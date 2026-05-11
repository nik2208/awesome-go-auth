package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	secret := "my-webhook-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if err := VerifyWebhookSignature(secret, body, sig); err != nil {
		t.Fatalf("expected valid signature to pass: %v", err)
	}
}

func TestVerifyWebhookSignature_Mismatch(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	err := VerifyWebhookSignature("secret1", body, "sha256="+hex.EncodeToString(make([]byte, 32)))
	if err == nil {
		t.Fatal("expected error for mismatched signature")
	}
}

func TestVerifyWebhookSignature_InvalidFormat(t *testing.T) {
	err := VerifyWebhookSignature("secret", []byte("body"), "invalid-header")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestVerifyWebhookSignature_InvalidHex(t *testing.T) {
	err := VerifyWebhookSignature("secret", []byte("body"), "sha256=notvalidhex!")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestVerifyWebhookSignature_TooShort(t *testing.T) {
	err := VerifyWebhookSignature("secret", []byte("body"), "sha2")
	if err == nil {
		t.Fatal("expected error for too-short header")
	}
}

func TestVerifyWebhookSignature_EmptyHeader(t *testing.T) {
	err := VerifyWebhookSignature("secret", []byte("body"), "")
	if err == nil {
		t.Fatal("expected error for empty header")
	}
}

func TestWebhookMatches_EmptyEvents(t *testing.T) {
	ep := WebhookEndpoint{Events: nil}
	if !webhookMatches(ep, "anything") {
		t.Fatal("empty events list should match any event")
	}
}

func TestWebhookMatches_Specific(t *testing.T) {
	ep := WebhookEndpoint{Events: []string{"user.login"}}
	if !webhookMatches(ep, "user.login") {
		t.Fatal("should match configured event")
	}
}

func TestWebhookMatches_NoMatch(t *testing.T) {
	ep := WebhookEndpoint{Events: []string{"user.login"}}
	if webhookMatches(ep, "user.register") {
		t.Fatal("should not match unconfigured event")
	}
}

func TestWebhookMatches_Wildcard(t *testing.T) {
	ep := WebhookEndpoint{Events: []string{"*"}}
	if !webhookMatches(ep, "anything.at.all") {
		t.Fatal("wildcard should match any event")
	}
}

func TestWebhookMatches_MultipleEvents(t *testing.T) {
	ep := WebhookEndpoint{Events: []string{"user.login", "user.logout"}}
	if !webhookMatches(ep, "user.login") {
		t.Fatal("should match first event")
	}
	if !webhookMatches(ep, "user.logout") {
		t.Fatal("should match second event")
	}
	if webhookMatches(ep, "user.register") {
		t.Fatal("should not match unconfigured event")
	}
}

func TestWebhookDispatcher_Dispatch(t *testing.T) {
	received := make(chan WebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p WebhookPayload
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		received <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewWebhookDispatcher(WebhookEndpoint{
		ID:  "ep1",
		URL: server.URL,
	})
	dispatcher.Dispatch(context.Background(), Event{
		Name:      "user.registered",
		UserID:    "u1",
		TenantID:  "t1",
		Timestamp: time.Now(),
	})

	select {
	case p := <-received:
		if p.Event != "user.registered" {
			t.Fatalf("unexpected event: %s", p.Event)
		}
		if p.ID == "" {
			t.Fatal("payload ID should not be empty")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not received within timeout")
	}
}

func TestWebhookDispatcher_Dispatch_WithSignature(t *testing.T) {
	secret := "test-secret"
	sigOK := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get("X-Signature-SHA256")
		err := VerifyWebhookSignature(secret, body, sig)
		sigOK <- (err == nil)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewWebhookDispatcher(WebhookEndpoint{
		ID:     "ep2",
		URL:    server.URL,
		Secret: secret,
	})
	dispatcher.Dispatch(context.Background(), Event{Name: "signed.event", Timestamp: time.Now()})

	select {
	case ok := <-sigOK:
		if !ok {
			t.Fatal("signature should be valid")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not received within timeout")
	}
}

func TestWebhookDispatcher_Dispatch_Filtered(t *testing.T) {
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewWebhookDispatcher(WebhookEndpoint{
		ID:     "ep3",
		URL:    server.URL,
		Events: []string{"user.login"},
	})
	dispatcher.Dispatch(context.Background(), Event{Name: "user.register", Timestamp: time.Now()})
	time.Sleep(200 * time.Millisecond)
	if count != 0 {
		t.Fatalf("filtered-out event should not trigger dispatch, got %d calls", count)
	}
}

func TestWebhookDispatcher_Dispatch_DefaultData(t *testing.T) {
	received := make(chan WebhookPayload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p WebhookPayload
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		received <- p
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dispatcher := NewWebhookDispatcher(WebhookEndpoint{ID: "ep4", URL: server.URL})
	dispatcher.Dispatch(context.Background(), Event{
		Name:      "test.event",
		UserID:    "u123",
		TenantID:  "t456",
		Timestamp: time.Now(),
	})

	select {
	case p := <-received:
		if p.Data["userID"] != "u123" || p.Data["tenantID"] != "t456" {
			t.Fatalf("unexpected data: %+v", p.Data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not received")
	}
}

func TestWebhookDispatcher_Dispatch_MultipleEndpoints(t *testing.T) {
	count := 0
	var mu sync.Mutex
	newServer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			count++
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
	}
	s1 := newServer()
	s2 := newServer()
	defer s1.Close()
	defer s2.Close()

	dispatcher := NewWebhookDispatcher(
		WebhookEndpoint{ID: "e1", URL: s1.URL},
		WebhookEndpoint{ID: "e2", URL: s2.URL},
	)
	dispatcher.Dispatch(context.Background(), Event{Name: "multi", Timestamp: time.Now()})
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if count != 2 {
		t.Fatalf("expected both endpoints to receive the event, got %d", count)
	}
}
