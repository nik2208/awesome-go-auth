package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SseDistributor broadcasts SSE messages to all connected clients.
// Implement this interface for Redis/Kafka-based multi-instance scaling.
type SseDistributor interface {
	Publish(ctx context.Context, channel string, msg SseMessage) error
	Subscribe(ctx context.Context, channel string) (<-chan SseMessage, error)
}

// SseMessage is a single SSE payload.
type SseMessage struct {
	ID    string
	Event string
	Data  map[string]any
}

// SseHub manages in-process SSE subscriptions.
type SseHub struct {
	mu      sync.RWMutex
	clients map[string][]chan SseMessage
}

// NewSseHub creates an in-process SSE hub.
func NewSseHub() *SseHub {
	return &SseHub{clients: make(map[string][]chan SseMessage)}
}

// Subscribe registers a new client channel for the given user/channel key.
func (h *SseHub) Subscribe(_ context.Context, channel string) (<-chan SseMessage, error) {
	ch := make(chan SseMessage, 32)
	h.mu.Lock()
	h.clients[channel] = append(h.clients[channel], ch)
	h.mu.Unlock()
	return ch, nil
}

// Publish sends a message to all subscribers of channel.
func (h *SseHub) Publish(_ context.Context, channel string, msg SseMessage) error {
	h.mu.RLock()
	subs := append([]chan SseMessage{}, h.clients[channel]...)
	h.mu.RUnlock()
	for _, ch := range subs {
		select {
		case ch <- msg:
		default:
		}
	}
	return nil
}

// Unsubscribe removes a client channel from the hub.
func (h *SseHub) Unsubscribe(channel string, ch <-chan SseMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	subs := h.clients[channel]
	out := subs[:0]
	for _, c := range subs {
		if c != ch {
			out = append(out, c)
		}
	}
	h.clients[channel] = out
}

// ServeSSE is an http.HandlerFunc that streams SSE to a connected client.
// channel is typically the authenticated user's ID.
func ServeSSE(hub *SseHub, channel string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		ch, err := hub.Subscribe(r.Context(), channel)
		if err != nil {
			http.Error(w, "sse error", http.StatusInternalServerError)
			return
		}
		defer hub.Unsubscribe(channel, ch)

		flusher, ok := w.(http.Flusher)
		for {
			select {
			case <-r.Context().Done():
				return
			case msg, open := <-ch:
				if !open {
					return
				}
				data, _ := json.Marshal(msg.Data)
				if msg.ID != "" {
					fmt.Fprintf(w, "id: %s\n", msg.ID)
				}
				if msg.Event != "" {
					fmt.Fprintf(w, "event: %s\n", msg.Event)
				}
				fmt.Fprintf(w, "data: %s\n\n", data)
				if ok {
					flusher.Flush()
				}
			case <-time.After(30 * time.Second):
				fmt.Fprintf(w, ": ping\n\n")
				if ok {
					flusher.Flush()
				}
			}
		}
	}
}
