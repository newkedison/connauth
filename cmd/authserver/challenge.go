package main

import (
	"sync"
	"time"
)

type pendingChallengeKey struct {
	IP          string
	KeyID       string
	ServerID    string
	ClientID    string
	Port        uint16
	ClientNonce string
	ServerNonce string
}

type pendingChallenge struct {
	ExpiresAt time.Time
}

type pendingChallengeStore struct {
	mux       sync.Mutex
	items     map[pendingChallengeKey]pendingChallenge
	countByIP map[string]int
	maxGlobal int
	maxPerIP  int
}

func newPendingChallengeStore(maxGlobal int, maxPerIP int) *pendingChallengeStore {
	return &pendingChallengeStore{
		items:     make(map[pendingChallengeKey]pendingChallenge),
		countByIP: make(map[string]int),
		maxGlobal: maxGlobal,
		maxPerIP:  maxPerIP,
	}
}

func (s *pendingChallengeStore) add(key pendingChallengeKey, expiresAt time.Time) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.maxGlobal > 0 && len(s.items) >= s.maxGlobal {
		return false
	}
	if s.maxPerIP > 0 && s.countByIP[key.IP] >= s.maxPerIP {
		return false
	}
	if _, exists := s.items[key]; exists {
		return true
	}
	s.items[key] = pendingChallenge{ExpiresAt: expiresAt}
	s.countByIP[key.IP]++
	return true
}

func (s *pendingChallengeStore) consume(key pendingChallengeKey, now time.Time) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	item, exists := s.items[key]
	if !exists {
		return false
	}
	delete(s.items, key)
	s.countByIP[key.IP]--
	if s.countByIP[key.IP] <= 0 {
		delete(s.countByIP, key.IP)
	}
	return item.ExpiresAt.After(now)
}

func (s *pendingChallengeStore) cleanup(now time.Time) int {
	s.mux.Lock()
	defer s.mux.Unlock()
	deleted := 0
	for key, item := range s.items {
		if item.ExpiresAt.After(now) {
			continue
		}
		delete(s.items, key)
		s.countByIP[key.IP]--
		if s.countByIP[key.IP] <= 0 {
			delete(s.countByIP, key.IP)
		}
		deleted++
	}
	return deleted
}
