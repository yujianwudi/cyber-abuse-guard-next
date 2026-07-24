package plugin

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPendingCacheConcurrentPutGetAndClear(t *testing.T) {
	cache := newPendingCache(128, time.Minute)
	var wait sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 500; iteration++ {
				key := fmt.Sprintf("sha256:%064x", (worker+iteration)%256)
				cache.put(key, "credential_theft")
				_, _ = cache.get(key)
				if iteration%97 == 0 {
					cache.clear()
				}
			}
		}(worker)
	}
	wait.Wait()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if len(cache.items) > cache.limit || cache.order.Len() > cache.limit {
		t.Fatal("concurrent pending operations exceeded the configured bound")
	}
}

func TestPendingCacheRefreshExpiryAndBoundedEviction(t *testing.T) {
	clock := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	cache := newPendingCache(2, time.Minute)
	cache.now = func() time.Time { return clock }
	cache.put("one", "first")
	clock = clock.Add(time.Second)
	cache.put("two", "second")
	clock = clock.Add(time.Second)
	cache.put("one", "refreshed")
	cache.put("three", "third")

	if _, ok := cache.get("two"); ok {
		t.Fatal("oldest pending entry survived bounded eviction")
	}
	if got, ok := cache.get("one"); !ok || got.category != "refreshed" {
		t.Fatal("refreshing a pending entry evicted or lost it")
	}
	if _, ok := cache.get("three"); !ok {
		t.Fatal("new pending entry was not retained")
	}

	clock = clock.Add(2 * time.Minute)
	if _, ok := cache.get("one"); ok {
		t.Fatal("expired pending entry remained visible")
	}
	cache.clear()
	if len(cache.items) != 0 || cache.order.Len() != 0 {
		t.Fatal("pending clear left indexed entries behind")
	}
}

func BenchmarkPendingCacheParallelHit(b *testing.B) {
	cache := newPendingCache(4096, 2*time.Minute)
	for index := 0; index < 4096; index++ {
		cache.put(fmt.Sprintf("sha256:%064x", index), "credential_theft")
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = cache.get("sha256:0000000000000000000000000000000000000000000000000000000000000001")
		}
	})
}

func BenchmarkPendingCacheFullInsert(b *testing.B) {
	cache := newPendingCache(4096, 2*time.Minute)
	keys := make([]string, 8192)
	for index := range keys {
		keys[index] = fmt.Sprintf("sha256:%064x", index)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		cache.put(keys[iteration%len(keys)], "credential_theft")
	}
}

// BenchmarkPendingCacheFullInsertReferenceLinearScan preserves the previous
// full-map expiry/oldest scan as a development-only comparison. It is not used
// by production code and must not be treated as final performance evidence.
func BenchmarkPendingCacheFullInsertReferenceLinearScan(b *testing.B) {
	cache := &linearScanPendingCache{
		items: make(map[string]pendingDecision),
		limit: 4096,
		ttl:   2 * time.Minute,
		now:   time.Now,
	}
	keys := make([]string, 8192)
	for index := range keys {
		keys[index] = fmt.Sprintf("sha256:%064x", index)
	}
	for index := 0; index < cache.limit; index++ {
		cache.put(keys[index], "credential_theft")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		cache.put(keys[iteration%len(keys)], "credential_theft")
	}
}

type linearScanPendingCache struct {
	mu    sync.Mutex
	items map[string]pendingDecision
	limit int
	ttl   time.Duration
	now   func() time.Time
}

func (cache *linearScanPendingCache) put(hash, category string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.now()
	for key, item := range cache.items {
		if now.Sub(item.created) > cache.ttl {
			delete(cache.items, key)
		}
	}
	if len(cache.items) >= cache.limit {
		var oldestKey string
		var oldest time.Time
		for key, item := range cache.items {
			if oldestKey == "" || item.created.Before(oldest) {
				oldestKey = key
				oldest = item.created
			}
		}
		delete(cache.items, oldestKey)
	}
	cache.items[hash] = pendingDecision{category: category, created: now}
}
