package sign

import (
	"sync"

	"golang.org/x/sync/singleflight"
)

// Window caches a signed value per key until shortly before it expires. A
// value is made again within refresh seconds of its expiry; if that fails,
// the cached value is still served until it expires, and after that the
// error is returned. Times are Unix seconds.
type Window[V any] struct {
	refresh int64

	mu        sync.Mutex
	entries   map[string]windowEntry[V]
	lastSweep int64
	group     singleflight.Group
}

type windowEntry[V any] struct {
	v       V
	expires int64
}

// NewWindow returns a Window that makes a value again refresh seconds before
// it expires.
func NewWindow[V any](refresh int64) *Window[V] {
	return &Window[V]{refresh: refresh, entries: map[string]windowEntry[V]{}}
}

// Get returns key's value at now. mint returns a new value and when it
// expires; concurrent calls for one key share one call to mint.
func (w *Window[V]) Get(key string, now int64, mint func() (V, int64, error)) (V, error) {
	w.mu.Lock()
	if now != w.lastSweep {
		w.lastSweep = now
		for k, e := range w.entries {
			if now >= e.expires {
				delete(w.entries, k)
			}
		}
	}
	e, ok := w.entries[key]
	w.mu.Unlock()

	if ok && now >= e.expires {
		ok = false
	}
	if ok && now < e.expires-w.refresh {
		return e.v, nil
	}

	v, err, _ := w.group.Do(key, func() (any, error) {
		v, expires, err := mint()
		if err != nil {
			return nil, err
		}
		ne := windowEntry[V]{v: v, expires: expires}
		w.mu.Lock()
		w.entries[key] = ne
		w.mu.Unlock()
		return ne, nil
	})
	if err != nil {
		if ok {
			return e.v, nil
		}
		var zero V
		return zero, err
	}
	ne, _ := v.(windowEntry[V])

	return ne.v, nil
}
