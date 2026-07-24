package plugin

import (
	"container/list"
	"sync"
	"time"
)

type pendingDecision struct {
	category string
	created  time.Time
	element  *list.Element
}

// pendingCache carries only the coarse category across CPA's model.route ->
// executor callback split. It is bounded and time-limited, and never retains
// request text, headers, credentials, or other prompt-derived material.
type pendingCache struct {
	mu    sync.Mutex
	items map[string]pendingDecision
	order list.List
	limit int
	ttl   time.Duration
	now   func() time.Time
}

func newPendingCache(limit int, ttl time.Duration) pendingCache {
	return pendingCache{
		items: make(map[string]pendingDecision),
		limit: limit,
		ttl:   ttl,
		now:   time.Now,
	}
}

func (cache *pendingCache) put(hash, category string) {
	if cache == nil || hash == "" {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.now()
	cache.pruneExpiredLocked(now)
	if cache.limit <= 0 {
		return
	}
	if existing, ok := cache.items[hash]; ok {
		if existing.element != nil {
			cache.order.Remove(existing.element)
		}
		element := cache.order.PushBack(hash)
		cache.items[hash] = pendingDecision{category: category, created: now, element: element}
		return
	}
	if len(cache.items) >= cache.limit {
		cache.removeOldestLocked()
	}
	element := cache.order.PushBack(hash)
	cache.items[hash] = pendingDecision{category: category, created: now, element: element}
}

func (cache *pendingCache) get(hash string) (pendingDecision, bool) {
	if cache == nil || hash == "" {
		return pendingDecision{}, false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	item, ok := cache.items[hash]
	if !ok {
		return pendingDecision{}, false
	}
	if cache.ttl > 0 && cache.now().Sub(item.created) > cache.ttl {
		cache.removeLocked(hash, item)
		return pendingDecision{}, false
	}
	return item, true
}

func (cache *pendingCache) clear() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	clear(cache.items)
	cache.order.Init()
	cache.mu.Unlock()
}

func (cache *pendingCache) pruneExpiredLocked(now time.Time) {
	if cache.ttl <= 0 {
		return
	}
	for element := cache.order.Front(); element != nil; element = cache.order.Front() {
		key, ok := element.Value.(string)
		if !ok {
			cache.order.Remove(element)
			continue
		}
		item, ok := cache.items[key]
		if !ok || item.element != element {
			cache.order.Remove(element)
			continue
		}
		if now.Sub(item.created) <= cache.ttl {
			return
		}
		cache.removeLocked(key, item)
	}
}

func (cache *pendingCache) removeOldestLocked() {
	for element := cache.order.Front(); element != nil; element = cache.order.Front() {
		key, ok := element.Value.(string)
		if !ok {
			cache.order.Remove(element)
			continue
		}
		item, ok := cache.items[key]
		if !ok || item.element != element {
			cache.order.Remove(element)
			continue
		}
		cache.removeLocked(key, item)
		return
	}

	// Preserve bounded behavior for white-box tests or older in-memory values
	// that predate the order index.
	for key, item := range cache.items {
		cache.removeLocked(key, item)
		return
	}
}

func (cache *pendingCache) removeLocked(key string, item pendingDecision) {
	if item.element != nil {
		cache.order.Remove(item.element)
	}
	delete(cache.items, key)
}
