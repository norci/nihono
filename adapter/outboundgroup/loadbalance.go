package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/callback"
	"github.com/metacubex/mihomo/common/lru"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"golang.org/x/net/publicsuffix"
)

const (
	maxRetryConsistentHashing = 5
	maxRetryStickySessions    = 5
	// maxRetryBatchSize controls how many proxies are attempted in parallel per batch.
	// Value 10 provides a balance between:
	//   - Latency reduction: Parallel execution avoids sequential waiting when many proxies are slow/unavailable
	//   - Resource usage: Limits concurrent connections to prevent overwhelming the system
	//   - Diminishing returns: Beyond ~10 parallel attempts, additional concurrency yields minimal latency improvement
	// This batch size ensures efficient retry behavior while maintaining system stability.
	maxRetryBatchSize = 10
)

type strategyFn = func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy

type LoadBalance struct {
	*GroupBase
	disableUDP     bool
	strategyFn     strategyFn
	testUrl        string
	expectedStatus string
}

var errStrategy = errors.New("unsupported strategy")

func parseStrategy(config map[string]any) string {
	if strategy, ok := config["strategy"].(string); ok {
		return strategy
	}
	return "consistent-hashing"
}

func getKey(metadata *C.Metadata) string {
	if metadata == nil {
		return ""
	}

	if metadata.Host != "" {
		// ip host
		if ip := net.ParseIP(metadata.Host); ip != nil {
			return metadata.Host
		}

		if etld, err := publicsuffix.EffectiveTLDPlusOne(metadata.Host); err == nil {
			return etld
		}
	}

	if !metadata.DstIP.IsValid() {
		return ""
	}

	return metadata.DstIP.String()
}

func getKeyWithSrcAndDst(metadata *C.Metadata) string {
	dst := getKey(metadata)
	src := ""
	if metadata != nil {
		src = metadata.SrcIP.String()
	}

	return fmt.Sprintf("%s%s", src, dst)
}

func jumpHash(key uint64, buckets int32) int32 {
	var b, j int64

	for j < int64(buckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int32(b)
}

// connectable represents types that can be appended to chains
type connectable interface {
	AppendToChains(lb C.ProxyAdapter)
}

// retryWithProxies attempts to establish a connection using the provided proxies,
// returning on the first successful attempt or after all proxies are exhausted.
//
// Batch Retry Strategy:
//   - Proxies are selected using the load balancer's strategy function (round-robin,
//     consistent-hashing, or sticky-sessions).
//   - Attempts are organized into batches of up to maxRetryBatchSize proxies.
//   - Each batch executes in parallel to minimize total wait time when many proxies
//     are slow or unavailable.
//
// Parallel Execution:
//   - All proxies in a batch are tried concurrently via goroutines.
//   - A cancellable context derived from the caller's context allows immediate
//     termination of all goroutines once any proxy succeeds.
//   - Results are collected via a buffered channel; the first successful connection
//     triggers cancellation and returns immediately.
//
// Error Reporting:
//   - On success: The successful connection is appended to chains and returned.
//   - On complete failure: After all proxies are exhausted, every failure is reported
//     to lb.onDialFailed to trigger appropriate health checks. The last error is
//     returned to the caller.
//
// Context Handling:
//   - The caller's context is respected (e.g., overall timeout/cancellation).
//   - An internal cancellation mechanism stops remaining attempts as soon as
//     one proxy succeeds, avoiding wasted resources.
//
// T must be a connectable type (C.Conn or C.PacketConn)
func retryWithProxies[T connectable](
	ctx context.Context,
	lb *LoadBalance,
	proxies []C.Proxy,
	metadata *C.Metadata,
	try func(proxy C.Proxy) (T, error),
) (T, error) {
	var zero T
	if len(proxies) == 0 {
		return zero, errors.New("no available proxies")
	}

	// resultItem holds the result of a single proxy connection attempt
	type resultItem struct {
		idx   int
		proxy C.Proxy
		conn  T
		err   error
	}

	tried := make(map[string]bool, len(proxies))
	var failedResults []resultItem // collect all failed attempts

	// Use a cancellable context derived from the caller's context
	// to respect external cancellation/timeout while also allowing
	// internal cancellation when one proxy succeeds
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		// Batch Collection: Select up to maxRetryBatchSize untried proxies.
		// The strategy function provides the primary selection; if it returns
		// an already-tried proxy, we fall back to scanning for any remaining
		// untried proxy to ensure progress.
		batch := make([]C.Proxy, 0, maxRetryBatchSize)
		for i := 0; i < maxRetryBatchSize; i++ {
			proxy := lb.strategyFn(proxies, metadata, true)
			if proxy == nil {
				break
			}
			if tried[proxy.Name()] {
				// Strategy returned an already-tried proxy; find any untried proxy
				found := false
				for _, p := range proxies {
					if !tried[p.Name()] {
						proxy = p
						found = true
						break
					}
				}
				if !found {
					// All proxies have been tried
					break
				}
			}
			tried[proxy.Name()] = true

			batch = append(batch, proxy)
		}

		if len(batch) == 0 {
			break
		}

		// Parallel Execution: Launch a goroutine for each proxy in the batch.
		// Each goroutine attempts the connection and sends its result to the channel.
		// The context is checked before attempting and when sending results to
		// avoid unnecessary work after cancellation.
		resultChan := make(chan resultItem, len(batch))
		var wg sync.WaitGroup

		for i, p := range batch {
			wg.Add(1)
			go func(idx int, proxy C.Proxy) {
				defer wg.Done()
				// Check if context is cancelled before attempting
				select {
				case <-ctx.Done():
					// Cancelled, skip this attempt
					return
				default:
					// Proceed with connection attempt
					conn, err := try(proxy)
					// Try to send result, but don't block if context cancelled
					select {
					case resultChan <- resultItem{idx: idx, proxy: proxy, conn: conn, err: err}:
					case <-ctx.Done():
						// Cancelled, discard result
					}
				}
			}(i, p)
		}

		// Close the channel when all goroutines are done
		go func() {
			wg.Wait()
			close(resultChan)
		}()

		// Result Collection: Process results as they arrive.
		// - First success triggers immediate cancellation of remaining attempts,
		//   appends the connection to chains, and returns.
		// - All failures are collected for later reporting to health checks.
		for res := range resultChan {
			if res.err == nil {
				// Success: append to chains, cancel others, and return
				cancel() // Signal other goroutines to stop
				res.conn.AppendToChains(lb)
				return res.conn, nil
			}
			// Capture all failures
			failedResults = append(failedResults, res)
		}

		// Batch failed; continue to next batch if there are untried proxies
		// Note: All goroutines from this batch have completed (or cancelled)
	}

	// All proxies failed - report each failure to onDialFailed
	if len(failedResults) > 0 {
		// Report all failures to trigger health checks appropriately
		for _, res := range failedResults {
			lb.onDialFailed(res.proxy.Type(), res.err, lb.healthCheck)
		}
		// Return the last error (most recent failure)
		return zero, failedResults[len(failedResults)-1].err
	}
	// Should not reach here if proxies existed, but return a generic error
	return zero, errors.New("all proxies failed")
}

// DialContext implements C.ProxyAdapter
func (lb *LoadBalance) DialContext(ctx context.Context, metadata *C.Metadata) (c C.Conn, err error) {
	proxies := lb.GetProxies(true)
	c, err = retryWithProxies[C.Conn](ctx, lb, proxies, metadata, func(proxy C.Proxy) (C.Conn, error) {
		conn, err := proxy.DialContext(ctx, metadata)
		if err == nil {
			if N.NeedHandshake(conn) {
				conn = callback.NewFirstWriteCallBackConn(conn, func(err error) {
					if err != nil {
						lb.onDialFailed(proxy.Type(), err, lb.healthCheck)
					} else {
						lb.onDialSuccess()
					}
				})
			}
			return conn, nil
		}
		return nil, err
	})
	return c, err
}

// ListenPacketContext implements C.ProxyAdapter
func (lb *LoadBalance) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	proxies := lb.GetProxies(true)
	pc, err = retryWithProxies[C.PacketConn](ctx, lb, proxies, metadata, func(proxy C.Proxy) (C.PacketConn, error) {
		return proxy.ListenPacketContext(ctx, metadata)
	})
	return pc, err
}

// SupportUDP implements C.ProxyAdapter
func (lb *LoadBalance) SupportUDP() bool {
	return !lb.disableUDP
}

// IsL3Protocol implements C.ProxyAdapter
func (lb *LoadBalance) IsL3Protocol(metadata *C.Metadata) bool {
	return lb.Unwrap(metadata, false).IsL3Protocol(metadata)
}

func strategyRoundRobin(url string) strategyFn {
	idx := 0
	idxMutex := sync.Mutex{}
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		idxMutex.Lock()
		defer idxMutex.Unlock()

		i := 0
		length := len(proxies)

		if touch {
			defer func() {
				idx = (idx + i) % length
			}()
		}

		for ; i < length; i++ {
			id := (idx + i) % length
			proxy := proxies[id]
			if proxy.AliveForTestUrl(url) {
				i++
				return proxy
			}
		}

		return proxies[0]
	}
}

func strategyConsistentHashing(url string) strategyFn {
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKey(metadata))
		buckets := int32(len(proxies))
		for i := 0; i < maxRetryConsistentHashing; i, key = i+1, key+1 {
			idx := jumpHash(key, buckets)
			proxy := proxies[idx]
			if proxy.AliveForTestUrl(url) {
				return proxy
			}
		}

		// when availability is poor, traverse the entire list to get the available nodes
		for _, proxy := range proxies {
			if proxy.AliveForTestUrl(url) {
				return proxy
			}
		}

		return proxies[0]
	}
}

func strategyStickySessions(url string) strategyFn {
	ttl := time.Minute * 10
	lruCache := lru.New[uint64, int](
		lru.WithAge[uint64, int](int64(ttl.Seconds())),
		lru.WithSize[uint64, int](1000))
	return func(proxies []C.Proxy, metadata *C.Metadata, touch bool) C.Proxy {
		key := utils.MapHash(getKeyWithSrcAndDst(metadata))
		length := len(proxies)
		idx, has := lruCache.Get(key)
		if !has || idx >= length {
			idx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
		}

		nowIdx := idx
		for i := 1; i < maxRetryStickySessions; i++ {
			proxy := proxies[nowIdx]
			if proxy.AliveForTestUrl(url) {
				if !has || nowIdx != idx {
					lruCache.Set(key, nowIdx)
				}

				return proxy
			} else {
				nowIdx = int(jumpHash(key+uint64(time.Now().UnixNano()), int32(length)))
			}
		}

		lruCache.Set(key, 0)
		return proxies[0]
	}
}

// Unwrap implements C.ProxyAdapter
func (lb *LoadBalance) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := lb.GetProxies(touch)
	return lb.strategyFn(proxies, metadata, touch)
}

// MarshalJSON implements C.ProxyAdapter
func (lb *LoadBalance) MarshalJSON() ([]byte, error) {
	var all []string
	for _, proxy := range lb.GetProxies(false) {
		all = append(all, proxy.Name())
	}
	return json.Marshal(map[string]any{
		"type":           lb.Type().String(),
		"all":            all,
		"testUrl":        lb.testUrl,
		"expectedStatus": lb.expectedStatus,
		"hidden":         lb.Hidden(),
		"icon":           lb.Icon(),
	})
}

func (lb *LoadBalance) Providers() []P.ProxyProvider {
	return lb.providers
}

func (lb *LoadBalance) Proxies() []C.Proxy {
	return lb.GetProxies(false)
}

func (lb *LoadBalance) Now() string {
	return ""
}

func NewLoadBalance(option *GroupCommonOption, providers []P.ProxyProvider, strategy string) (lb *LoadBalance, err error) {
	var strategyFn strategyFn
	switch strategy {
	case "consistent-hashing":
		strategyFn = strategyConsistentHashing(option.URL)
	case "round-robin":
		strategyFn = strategyRoundRobin(option.URL)
	case "sticky-sessions":
		strategyFn = strategyStickySessions(option.URL)
	default:
		return nil, fmt.Errorf("%w: %s", errStrategy, strategy)
	}
	return &LoadBalance{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:           option.Name,
			Type:           C.LoadBalance,
			Hidden:         option.Hidden,
			Icon:           option.Icon,
			Filter:         option.Filter,
			ExcludeFilter:  option.ExcludeFilter,
			ExcludeType:    option.ExcludeType,
			TestTimeout:    option.TestTimeout,
			MaxFailedTimes: option.MaxFailedTimes,
			Providers:      providers,
		}),
		strategyFn:     strategyFn,
		disableUDP:     option.DisableUDP,
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
	}, nil
}
