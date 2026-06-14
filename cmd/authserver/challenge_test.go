package main

import (
	"net"
	"testing"
	"time"
)

func TestPendingChallengeConsumeRequiresExactBinding(t *testing.T) {
	store := newPendingChallengeStore(10, 4)
	now := time.Unix(1700000000, 0)
	ip := net.ParseIP("192.0.2.10")
	store.add(pendingChallengeKey{
		IP:           ip.String(),
		KeyID:        "primary-2026-06",
		ServerID:     "connauth-server",
		ClientID:     "workstation",
		Port:         40022,
		ClientNonce:  "client",
		ServerNonce:  "server",
	}, now.Add(time.Minute))

	if store.consume(pendingChallengeKey{IP: "192.0.2.11", KeyID: "primary-2026-06", ServerID: "connauth-server", ClientID: "workstation", Port: 40022, ClientNonce: "client", ServerNonce: "server"}, now) {
		t.Fatal("expected different IP to be rejected")
	}
	if !store.consume(pendingChallengeKey{IP: ip.String(), KeyID: "primary-2026-06", ServerID: "connauth-server", ClientID: "workstation", Port: 40022, ClientNonce: "client", ServerNonce: "server"}, now) {
		t.Fatal("expected exact challenge binding to be consumed")
	}
	if store.consume(pendingChallengeKey{IP: ip.String(), KeyID: "primary-2026-06", ServerID: "connauth-server", ClientID: "workstation", Port: 40022, ClientNonce: "client", ServerNonce: "server"}, now) {
		t.Fatal("expected replay to be rejected")
	}
}

func TestPendingChallengeRejectsExpiredChallenge(t *testing.T) {
	store := newPendingChallengeStore(10, 4)
	now := time.Unix(1700000000, 0)
	key := pendingChallengeKey{IP: "192.0.2.10", KeyID: "primary-2026-06", ServerID: "connauth-server", ClientID: "workstation", Port: 40022, ClientNonce: "client", ServerNonce: "server"}
	store.add(key, now.Add(time.Second))
	if store.consume(key, now.Add(2*time.Second)) {
		t.Fatal("expected expired challenge to be rejected")
	}
}

func TestPendingChallengeLimitsCapacity(t *testing.T) {
	store := newPendingChallengeStore(2, 1)
	now := time.Unix(1700000000, 0)
	first := pendingChallengeKey{IP: "192.0.2.10", KeyID: "primary-2026-06", ServerID: "connauth-server", ClientID: "workstation", Port: 40022, ClientNonce: "client-1", ServerNonce: "server-1"}
	secondSameIP := pendingChallengeKey{IP: "192.0.2.10", KeyID: "primary-2026-06", ServerID: "connauth-server", ClientID: "workstation", Port: 40022, ClientNonce: "client-2", ServerNonce: "server-2"}
	secondOtherIP := pendingChallengeKey{IP: "192.0.2.11", KeyID: "primary-2026-06", ServerID: "connauth-server", ClientID: "workstation", Port: 40022, ClientNonce: "client-3", ServerNonce: "server-3"}
	thirdOtherIP := pendingChallengeKey{IP: "192.0.2.12", KeyID: "primary-2026-06", ServerID: "connauth-server", ClientID: "workstation", Port: 40022, ClientNonce: "client-4", ServerNonce: "server-4"}

	if !store.add(first, now.Add(time.Minute)) {
		t.Fatal("expected first challenge to be added")
	}
	if store.add(secondSameIP, now.Add(time.Minute)) {
		t.Fatal("expected per-IP limit to reject second challenge")
	}
	if !store.add(secondOtherIP, now.Add(time.Minute)) {
		t.Fatal("expected second IP challenge to be added")
	}
	if store.add(thirdOtherIP, now.Add(time.Minute)) {
		t.Fatal("expected global limit to reject third challenge")
	}
}
