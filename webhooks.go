package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookEndpoint configures a single outbound webhook target.
type WebhookEndpoint struct {
	ID     string
	URL    string
	Secret string
	Events []string // event names to forward; empty = all
}

// WebhookDispatcher delivers signed webhook payloads.
type WebhookDispatcher struct {
	endpoints []WebhookEndpoint
	client    *http.Client
}

// NewWebhookDispatcher creates a dispatcher for the given endpoints.
func NewWebhookDispatcher(endpoints ...WebhookEndpoint) *WebhookDispatcher {
	return &WebhookDispatcher{
		endpoints: endpoints,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// WebhookPayload is the envelope sent to webhook targets.
type WebhookPayload struct {
	ID        string         `json:"id"`
	Event     string         `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// Dispatch delivers the event to all matching endpoints.
func (d *WebhookDispatcher) Dispatch(ctx context.Context, event Event) {
	id, _ := newID("whk")
	payload := WebhookPayload{
		ID:        id,
		Event:     event.Name,
		Timestamp: event.Timestamp,
		Data:      event.Data,
	}
	if payload.Data == nil {
		payload.Data = map[string]any{"userID": event.UserID, "tenantID": event.TenantID}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	for _, ep := range d.endpoints {
		if !webhookMatches(ep, event.Name) {
			continue
		}
		go d.send(ctx, ep, body)
	}
}

func (d *WebhookDispatcher) send(ctx context.Context, ep WebhookEndpoint, body []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if ep.Secret != "" {
		mac := hmac.New(sha256.New, []byte(ep.Secret))
		mac.Write(body)
		req.Header.Set("X-Signature-SHA256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// VerifyWebhookSignature validates an inbound webhook signature.
func VerifyWebhookSignature(secret string, body []byte, sigHeader string) error {
	if len(sigHeader) < 7 || sigHeader[:7] != "sha256=" {
		return fmt.Errorf("auth: invalid signature header format")
	}
	got, err := hex.DecodeString(sigHeader[7:])
	if err != nil {
		return fmt.Errorf("auth: invalid signature hex: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)
	if !hmac.Equal(got, expected) {
		return fmt.Errorf("auth: signature mismatch")
	}
	return nil
}

func webhookMatches(ep WebhookEndpoint, event string) bool {
	if len(ep.Events) == 0 {
		return true
	}
	for _, e := range ep.Events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}
