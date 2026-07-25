package adminweb

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const maxLoginGuardEntries = 1024

type loginFailure struct {
	count       int
	lockedUntil time.Time
	updatedAt   time.Time
}

type loginGuard struct {
	mu          sync.Mutex
	maxFailures int
	lockout     time.Duration
	entries     map[string]loginFailure
}

func newLoginGuard(maxFailures int, lockout time.Duration) *loginGuard {
	if maxFailures < 1 {
		maxFailures = 5
	}
	if lockout <= 0 {
		lockout = 15 * time.Minute
	}
	return &loginGuard{maxFailures: maxFailures, lockout: lockout, entries: make(map[string]loginFailure)}
}

func (g *loginGuard) Allow(username string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(username))
	failure, ok := g.entries[key]
	if !ok {
		return true
	}
	if !failure.lockedUntil.IsZero() && now.Before(failure.lockedUntil) {
		return false
	}
	if !failure.lockedUntil.IsZero() {
		delete(g.entries, key)
	}
	return true
}

func (g *loginGuard) Failure(username string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(username))
	failure := g.entries[key]
	failure.count++
	failure.updatedAt = now
	if failure.count >= g.maxFailures {
		failure.lockedUntil = now.Add(g.lockout)
	}
	g.entries[key] = failure
	if len(g.entries) > maxLoginGuardEntries {
		g.evictOldest()
	}
}

func (g *loginGuard) Success(username string) {
	g.mu.Lock()
	delete(g.entries, strings.ToLower(strings.TrimSpace(username)))
	g.mu.Unlock()
}

func (g *loginGuard) evictOldest() {
	type entry struct {
		key string
		at  time.Time
	}
	entries := make([]entry, 0, len(g.entries))
	for key, failure := range g.entries {
		entries = append(entries, entry{key: key, at: failure.updatedAt})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].at.Before(entries[j].at) })
	for len(g.entries) > maxLoginGuardEntries && len(entries) > 0 {
		delete(g.entries, entries[0].key)
		entries = entries[1:]
	}
}

func loginLockout(value string) time.Duration {
	duration, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || duration <= 0 {
		return 15 * time.Minute
	}
	return duration
}
