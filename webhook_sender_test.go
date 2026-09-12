package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The wire is the whole point of this file, so the assertions are on bytes and
// counts rather than on behaviour in the abstract: the four headers by name, the
// envelope by its JSON keys, the attempt count against `while (attempt <=
// maxRetries)`, and the back-off against `baseDelayMs * 2^(attempt-1)`.
//
// Two seams make that possible without a test that waits seven seconds:
// WebhookDeliverer, which is the product's seam and is therefore worth
// exercising anyway, and WebhookSender.sleep, which is unexported precisely
// because the schedule is not a knob.

// testWebhookEvent is a fixed envelope, so that every expectation below can be
// written out rather than recomputed.
func testWebhookEvent() OutgoingWebhookEvent {
	return Event{
		Name:          EventAuthLoginSuccess,
		UserID:        "usr_1",
		TenantID:      "acme",
		SessionID:     "ses_1",
		CorrelationID: "cor_1",
		Timestamp:     time.Date(2026, 9, 12, 10, 0, 0, 123456789, time.UTC),
		Data:          map[string]any{"provider": "local"},
	}.OutgoingWebhook("")
}

// recordedAttempt is one call at the deliverer seam.
type recordedAttempt struct {
	attempt WebhookAttempt
	ctxErr  error
}

// recordingDeliverer answers each call from results in order, repeating the last
// one once it runs out, and records what it was handed.
type recordingDeliverer struct {
	mu      sync.Mutex
	results []error
	calls   []recordedAttempt
}

func (d *recordingDeliverer) DeliverWebhook(ctx context.Context, attempt WebhookAttempt) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, recordedAttempt{attempt: attempt, ctxErr: ctx.Err()})
	if len(d.results) == 0 {
		return nil
	}
	if len(d.calls) <= len(d.results) {
		return d.results[len(d.calls)-1]
	}
	return d.results[len(d.results)-1]
}

func (d *recordingDeliverer) recorded() []recordedAttempt {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]recordedAttempt(nil), d.calls...)
}

// waitRecorder captures the back-off schedule without waiting it out.
type waitRecorder struct {
	mu    sync.Mutex
	waits []time.Duration
}

func (w *waitRecorder) sleep(_ context.Context, d time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.waits = append(w.waits, d)
	return nil
}

func (w *waitRecorder) recorded() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Duration(nil), w.waits...)
}

// The four headers and the body, as a receiver written against the reference
// sees them (webhook-sender.ts:24-33). This is the test that fails if anything
// about the wire moves.
func TestWebhookSenderSendsTheReferenceWireFormat(t *testing.T) {
	const secret = "s3cr3t"
	type capture struct {
		headers http.Header
		body    []byte
	}
	got := make(chan capture, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- capture{headers: r.Header.Clone(), body: body}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	event := testWebhookEvent()
	sender := &WebhookSender{}
	err := sender.Send(context.Background(), WebhookConfig{
		ID: "whk_1", URL: server.URL, Secret: secret,
		Events: []string{WebhookEventWildcard}, MaxRetries: intPtr(0),
	}, event)
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	var c capture
	select {
	case c = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("webhook never arrived")
	}

	if want := "application/json"; c.headers.Get("Content-Type") != want {
		t.Errorf("Content-Type = %q, want %q", c.headers.Get("Content-Type"), want)
	}
	if c.headers.Get(webhookEventHeader) != EventAuthLoginSuccess {
		t.Errorf("X-Webhook-Event = %q, want %q", c.headers.Get(webhookEventHeader), EventAuthLoginSuccess)
	}
	// The header carries the envelope's timestamp, not the moment of the
	// request (webhook-sender.ts:28).
	if want := "2026-09-12T10:00:00.123Z"; c.headers.Get(webhookTimestampHeader) != want {
		t.Errorf("X-Webhook-Timestamp = %q, want %q", c.headers.Get(webhookTimestampHeader), want)
	}
	if id := c.headers.Get(webhookDeliveryHeader); len(id) != 36 || strings.Count(id, "-") != 4 {
		t.Errorf("X-Webhook-Delivery = %q, want a canonical UUID", id)
	}
	// sha256=<hex>, over the raw body and nothing else (webhook-sender.ts:55).
	sig := c.headers.Get(webhookSignatureHeader)
	if err := VerifyWebhookSignature(secret, c.body, sig); err != nil {
		t.Errorf("the sender's own signature %q did not verify: %v", sig, err)
	}
	if err := VerifyWebhookSignature(secret, append([]byte(nil), c.body[1:]...), sig); err == nil {
		t.Error("signature verified against a truncated body")
	}
	// Nothing else X-Webhook-*, and above all not the header the removed
	// WebhookDispatcher sent.
	if legacy := c.headers.Get("X-Signature-SHA256"); legacy != "" {
		t.Errorf("X-Signature-SHA256 was sent (%q); it was removed in v0.11.0", legacy)
	}

	// The body is OutgoingWebhookEvent, with the reference's key names.
	var decoded map[string]any
	if err := json.Unmarshal(c.body, &decoded); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if decoded["event"] != EventAuthLoginSuccess {
		t.Errorf("event = %v", decoded["event"])
	}
	if decoded["version"] != OutgoingWebhookVersion {
		t.Errorf("version = %v, want %q", decoded["version"], OutgoingWebhookVersion)
	}
	if decoded["timestamp"] != "2026-09-12T10:00:00.123Z" {
		t.Errorf("timestamp = %v", decoded["timestamp"])
	}
	data, ok := decoded["data"].(map[string]any)
	if !ok || data["provider"] != "local" {
		t.Errorf("data = %v", decoded["data"])
	}
	meta, ok := decoded["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata = %v", decoded["metadata"])
	}
	for key, want := range map[string]string{
		"userId": "usr_1", "tenantId": "acme", "sessionId": "ses_1", "correlationId": "cor_1",
	} {
		if meta[key] != want {
			t.Errorf("metadata[%q] = %v, want %q", key, meta[key], want)
		}
	}
	// The privacy line Event.WebhookMetadata draws: telemetry keeps these two,
	// a third party does not get them.
	if _, present := meta["ip"]; present {
		t.Error("metadata carried ip; the reference's four keys do not include it")
	}
	if _, present := meta["userAgent"]; present {
		t.Error("metadata carried userAgent; the reference's four keys do not include it")
	}
}

// No secret, no signature header at all (webhook-sender.ts:31-33) — not an
// empty one, and not one keyed on "".
func TestWebhookSenderOmitsTheSignatureWithoutASecret(t *testing.T) {
	deliverer := &recordingDeliverer{}
	sender := &WebhookSender{Deliverer: deliverer}
	if err := sender.Send(context.Background(), WebhookConfig{URL: "https://example.test/hook", MaxRetries: intPtr(0)}, testWebhookEvent()); err != nil {
		t.Fatalf("send: %v", err)
	}
	calls := deliverer.recorded()
	if len(calls) != 1 {
		t.Fatalf("attempts = %d, want 1", len(calls))
	}
	if _, present := calls[0].attempt.Headers[http.CanonicalHeaderKey(webhookSignatureHeader)]; present {
		t.Error("X-Webhook-Signature was set without a secret")
	}
}

// `while (attempt <= maxRetries)` with the default 3 is four requests, and the
// waits between them are baseDelayMs doubling from 1s (webhook-sender.ts:23,
// :45-46). The last failure is not followed by a wait (:39, :42).
func TestWebhookSenderRetryScheduleIsTheReferences(t *testing.T) {
	deliverer := &recordingDeliverer{results: []error{errors.New("refused")}}
	waits := &waitRecorder{}
	sender := &WebhookSender{Deliverer: deliverer, sleep: waits.sleep}

	err := sender.Send(context.Background(), WebhookConfig{ID: "whk_1", URL: "https://example.test/hook"}, testWebhookEvent())
	if err == nil {
		t.Fatal("an exhausted send returned nil")
	}
	if !strings.Contains(err.Error(), "4 attempt") {
		t.Errorf("error does not name the attempt count: %v", err)
	}

	calls := deliverer.recorded()
	if len(calls) != DefaultWebhookMaxRetries+1 {
		t.Fatalf("attempts = %d, want %d", len(calls), DefaultWebhookMaxRetries+1)
	}
	for i, call := range calls {
		if call.attempt.Attempt != i {
			t.Errorf("attempt %d reported Attempt = %d", i, call.attempt.Attempt)
		}
		if want := DefaultWebhookMaxRetries - i; call.attempt.Remaining != want {
			t.Errorf("attempt %d reported Remaining = %d, want %d", i, call.attempt.Remaining, want)
		}
	}

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	got := waits.recorded()
	if len(got) != len(want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("wait %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// The reference mints randomUUID() inside the loop (webhook-sender.ts:27), so
// the header identifies an attempt and not an event — which is exactly why it
// cannot be used to deduplicate. The timestamp, by contrast, does not move.
func TestWebhookDeliveryIDIsFreshPerAttemptAndTheTimestampIsNot(t *testing.T) {
	deliverer := &recordingDeliverer{results: []error{errors.New("refused")}}
	sender := &WebhookSender{Deliverer: deliverer, sleep: func(context.Context, time.Duration) error { return nil }}
	event := testWebhookEvent()
	_ = sender.Send(context.Background(), WebhookConfig{URL: "https://example.test/hook"}, event)

	calls := deliverer.recorded()
	seen := make(map[string]bool, len(calls))
	var firstBody string
	for i, call := range calls {
		id := call.attempt.DeliveryID
		if id == "" {
			t.Fatalf("attempt %d carried no delivery id", i)
		}
		if seen[id] {
			t.Errorf("attempt %d reused delivery id %q; the reference mints one per attempt", i, id)
		}
		seen[id] = true
		if call.attempt.Headers.Get(webhookDeliveryHeader) != id {
			t.Errorf("attempt %d: header and DeliveryID disagree", i)
		}
		if got := call.attempt.Headers.Get(webhookTimestampHeader); got != event.Timestamp {
			t.Errorf("attempt %d: X-Webhook-Timestamp = %q, want the envelope's %q", i, got, event.Timestamp)
		}
		// Serialised once, before the first attempt (webhook-sender.ts:20).
		if i == 0 {
			firstBody = string(call.attempt.Body)
		} else if string(call.attempt.Body) != firstBody {
			t.Errorf("attempt %d carried different bytes; every attempt has to sign the same body", i)
		}
	}
}

// A non-2xx and a transport failure take the same branch there
// (webhook-sender.ts:37-43) and take the same branch here.
func TestWebhookSenderRetriesRefusalsAndTransportFailuresAlike(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail error
	}{
		{"non-2xx", &WebhookStatusError{StatusCode: http.StatusInternalServerError}},
		{"transport failure", errors.New("dial tcp: connection refused")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deliverer := &recordingDeliverer{results: []error{tc.fail, tc.fail, nil}}
			sender := &WebhookSender{Deliverer: deliverer, sleep: func(context.Context, time.Duration) error { return nil }}
			if err := sender.Send(context.Background(), WebhookConfig{URL: "https://example.test/hook"}, testWebhookEvent()); err != nil {
				t.Fatalf("a send that eventually succeeded returned %v", err)
			}
			// Three attempts, then it stops: a success returns out of the loop
			// (webhook-sender.ts:37).
			if calls := deliverer.recorded(); len(calls) != 3 {
				t.Fatalf("attempts = %d, want 3", len(calls))
			}
		})
	}
}

// maxRetries: 0 is "deliver once, never retry", which is the whole reason
// WebhookConfig.MaxRetries is a *int; a negative one never enters the loop at
// all and sends nothing.
func TestWebhookSenderHonoursTheStoredRetryCount(t *testing.T) {
	for _, tc := range []struct {
		name        string
		maxRetries  int
		wantCalls   int
		wantErrored bool
	}{
		{"zero retries is one attempt", 0, 1, true},
		{"one retry is two attempts", 1, 2, true},
		{"a negative count sends nothing", -1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deliverer := &recordingDeliverer{results: []error{errors.New("refused")}}
			sender := &WebhookSender{Deliverer: deliverer, sleep: func(context.Context, time.Duration) error { return nil }}
			err := sender.Send(context.Background(), WebhookConfig{
				URL: "https://example.test/hook", MaxRetries: intPtr(tc.maxRetries),
			}, testWebhookEvent())
			if got := err != nil; got != tc.wantErrored {
				t.Errorf("error = %v, want errored = %v", err, tc.wantErrored)
			}
			if calls := deliverer.recorded(); len(calls) != tc.wantCalls {
				t.Fatalf("attempts = %d, want %d", len(calls), tc.wantCalls)
			}
		})
	}
}

// A stored retryDelayMs of 0 is honoured as 0, for MaxRetries' reason.
func TestWebhookSenderHonoursAStoredZeroRetryDelay(t *testing.T) {
	deliverer := &recordingDeliverer{results: []error{errors.New("refused")}}
	waits := &waitRecorder{}
	sender := &WebhookSender{Deliverer: deliverer, sleep: waits.sleep}
	_ = sender.Send(context.Background(), WebhookConfig{
		URL: "https://example.test/hook", MaxRetries: intPtr(2), RetryDelayMs: intPtr(0),
	}, testWebhookEvent())
	for i, d := range waits.recorded() {
		if d != 0 {
			t.Errorf("wait %d = %v, want 0", i, d)
		}
	}
}

// The seam is below the format: what crosses it is a request that is already
// built and already signed, and the subscription's secret is not part of it.
func TestWebhookAttemptIsSelfContainedAndCarriesNoSecret(t *testing.T) {
	const secret = "s3cr3t"
	deliverer := &recordingDeliverer{}
	sender := &WebhookSender{Deliverer: deliverer}
	config := WebhookConfig{ID: "whk_1", URL: "https://example.test/hook", Secret: secret, MaxRetries: intPtr(0)}
	if err := sender.Send(context.Background(), config, testWebhookEvent()); err != nil {
		t.Fatalf("send: %v", err)
	}
	call := deliverer.recorded()[0].attempt
	if call.ConfigID != "whk_1" || call.URL != config.URL || call.Event != EventAuthLoginSuccess {
		t.Errorf("attempt did not carry the routing fields: %+v", call)
	}
	if err := VerifyWebhookSignature(secret, call.Body, call.Headers.Get(webhookSignatureHeader)); err != nil {
		t.Errorf("the attempt's own signature did not verify: %v", err)
	}
	for name, values := range call.Headers {
		for _, value := range values {
			if strings.Contains(value, secret) {
				t.Errorf("header %s leaked the signing secret", name)
			}
		}
	}
	if strings.Contains(string(call.Body), secret) {
		t.Error("the body leaked the signing secret")
	}
	// And it is a complete request: a host that is still on HTTP builds it
	// without knowing anything else.
	req, err := call.NewRequest(context.Background())
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if req.Method != http.MethodPost || req.URL.String() != config.URL {
		t.Errorf("NewRequest built %s %s", req.Method, req.URL)
	}
	if req.Header.Get(webhookSignatureHeader) != call.Headers.Get(webhookSignatureHeader) {
		t.Error("NewRequest dropped the signature")
	}
}

// The whole reason the seam exists: a deployment that queues instead of POSTing
// replaces one interface and reimplements neither the envelope nor the policy.
func TestWebhookDelivererSeamReplacesTheTransportOnly(t *testing.T) {
	var queued []WebhookAttempt
	sender := &WebhookSender{Deliverer: WebhookDelivererFunc(func(_ context.Context, a WebhookAttempt) error {
		queued = append(queued, a)
		return nil // durably enqueued
	})}
	if err := sender.Send(context.Background(), WebhookConfig{ID: "whk_1", URL: "https://example.test/hook", Secret: "s3cr3t"}, testWebhookEvent()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(queued) != 1 {
		t.Fatalf("enqueues = %d, want 1: a deliverer that reports success is not retried", len(queued))
	}
	// What the host has in hand is the request, not the subscription: it can be
	// serialised and replayed elsewhere without this package.
	round, err := json.Marshal(queued[0])
	if err != nil {
		t.Fatalf("a WebhookAttempt has to survive a queue: %v", err)
	}
	var back WebhookAttempt
	if err := json.Unmarshal(round, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.URL != queued[0].URL || string(back.Body) != string(queued[0].Body) ||
		back.Headers.Get(webhookSignatureHeader) != queued[0].Headers.Get(webhookSignatureHeader) {
		t.Error("a WebhookAttempt did not survive a JSON round trip intact")
	}
}

func TestHTTPWebhookDelivererReportsRefusalsAsAStatusError(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent, http.StatusMovedPermanently, http.StatusBadRequest, http.StatusInternalServerError} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		err := (&HTTPWebhookDeliverer{}).DeliverWebhook(context.Background(), WebhookAttempt{
			URL: server.URL, Body: []byte(`{}`), Headers: http.Header{},
		})
		server.Close()
		// res.ok is 200-299 and nothing else (webhook-sender.ts:37): a 301 is
		// a refusal, not a success.
		wantOK := status >= 200 && status < 300
		if wantOK && err != nil {
			t.Errorf("status %d: %v", status, err)
			continue
		}
		if wantOK {
			continue
		}
		var statusErr *WebhookStatusError
		if !errors.As(err, &statusErr) {
			t.Errorf("status %d: error = %v, want a *WebhookStatusError", status, err)
			continue
		}
		if statusErr.StatusCode != status {
			t.Errorf("WebhookStatusError.StatusCode = %d, want %d", statusErr.StatusCode, status)
		}
	}
}

// The envelope is derived from the Event rather than assembled beside it, which
// is what Event.WebhookMetadata was written for.
func TestEventOutgoingWebhookIsTheReferenceEnvelope(t *testing.T) {
	stamp := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	t.Run("defaults", func(t *testing.T) {
		got := Event{Name: EventUserCreated, UserID: "usr_1", Timestamp: stamp}.OutgoingWebhook("")
		if got.Version != OutgoingWebhookVersion {
			t.Errorf("Version = %q, want %q", got.Version, OutgoingWebhookVersion)
		}
		if got.Timestamp != "2026-09-12T10:00:00.000Z" {
			t.Errorf("Timestamp = %q; toISOString always writes three fractional digits", got.Timestamp)
		}
		// `data ?? null` (auth-tools.ts:269): a key that is present and null,
		// not an absent key and not {}.
		body, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(body), `"data":null`) {
			t.Errorf("an event with no data serialised as %s, want a null data member", body)
		}
	})
	t.Run("host version", func(t *testing.T) {
		if got := (Event{Name: EventUserCreated, Timestamp: stamp}).OutgoingWebhook("2"); got.Version != "2" {
			t.Errorf("Version = %q, want %q", got.Version, "2")
		}
	})
	t.Run("metadata comes from the event", func(t *testing.T) {
		ev := Event{Name: EventUserCreated, UserID: "usr_1", SessionID: "ses_1", Timestamp: stamp}
		got := ev.OutgoingWebhook("")
		want := ev.WebhookMetadata()
		if len(got.Metadata) != len(want) || got.Metadata["userId"] != "usr_1" || got.Metadata["sessionId"] != "ses_1" {
			t.Errorf("Metadata = %v, want %v", got.Metadata, want)
		}
	})
	t.Run("a zero timestamp is filled", func(t *testing.T) {
		got := Event{Name: EventUserCreated}.OutgoingWebhook("")
		if got.Timestamp == "" || strings.HasPrefix(got.Timestamp, "0001-") {
			t.Errorf("Timestamp = %q, want the current instant", got.Timestamp)
		}
	})
}

func TestWebhookTimestampIsToISOStringShaped(t *testing.T) {
	for _, tc := range []struct {
		in   time.Time
		want string
	}{
		{time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC), "2026-09-12T10:00:00.000Z"},
		{time.Date(2026, 9, 12, 10, 0, 0, 123456789, time.UTC), "2026-09-12T10:00:00.123Z"},
		// A non-UTC zone is converted, never carried as an offset: toISOString
		// always writes Z.
		{time.Date(2026, 9, 12, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60)), "2026-09-12T10:00:00.000Z"},
	} {
		if got := WebhookTimestamp(tc.in); got != tc.want {
			t.Errorf("WebhookTimestamp(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWebhookBackoffDoublesAndSaturates(t *testing.T) {
	for attempt, want := range map[int]time.Duration{0: time.Second, 1: 2 * time.Second, 2: 4 * time.Second, 3: 8 * time.Second} {
		if got := webhookBackoff(time.Second, attempt); got != want {
			t.Errorf("webhookBackoff(1s, %d) = %v, want %v", attempt, got, want)
		}
	}
	if got := webhookBackoff(0, 3); got != 0 {
		t.Errorf("webhookBackoff(0, 3) = %v, want 0", got)
	}
	// An absurd retry count saturates rather than wrapping to a negative
	// Duration, which time.NewTimer would fire immediately on.
	if got := webhookBackoff(time.Second, 200); got <= 0 {
		t.Errorf("webhookBackoff(1s, 200) = %v, want a positive saturated value", got)
	}
}

// failingWebhookStore is a store that is down.
type failingWebhookStore struct{}

func (failingWebhookStore) FindByEvent(context.Context, string, string) ([]WebhookConfig, error) {
	return nil, errors.New("store is down")
}

// The emitter is step 4 of track and the three decisions in it are the
// reference's: the store is the only filter, a store failure is an empty result
// rather than a failed emit, and one envelope is shared by every delivery.
func TestWebhookEmitterFansOutWhatTheStoreReturns(t *testing.T) {
	store := NewMemoryWebhookStore()
	ctx := context.Background()
	for _, config := range []WebhookConfig{
		{URL: "https://one.test/hook", Events: []string{EventAuthLoginSuccess}, MaxRetries: intPtr(0)},
		{URL: "https://two.test/hook", Events: []string{WebhookEventWildcard}, MaxRetries: intPtr(0)},
		{URL: "https://off.test/hook", Events: []string{WebhookEventWildcard}, IsActive: boolPtr(false), MaxRetries: intPtr(0)},
		{URL: "https://other.test/hook", Events: []string{EventUserDeleted}, MaxRetries: intPtr(0)},
	} {
		if _, err := store.AddWebhook(ctx, config); err != nil {
			t.Fatalf("add webhook: %v", err)
		}
	}

	var mu sync.Mutex
	bodies := make(map[string]string)
	done := make(chan struct{}, 2)
	emitter := &WebhookEmitter{
		Store: store,
		Sender: &WebhookSender{Deliverer: WebhookDelivererFunc(func(_ context.Context, a WebhookAttempt) error {
			mu.Lock()
			bodies[a.URL] = string(a.Body)
			mu.Unlock()
			done <- struct{}{}
			return nil
		})},
	}
	emitter.Emit(ctx, Event{Name: EventAuthLoginSuccess, UserID: "usr_1", Timestamp: time.Now()})
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("not every matching subscription was delivered to")
		}
	}
	// Give a fourth delivery, if the filter leaked, time to show up.
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("delivered to %d endpoints, want 2: %v", len(bodies), bodies)
	}
	if bodies["https://one.test/hook"] != bodies["https://two.test/hook"] {
		t.Error("two subscriptions got different bytes; the envelope is built once per event")
	}
}

// `.catch(() => [])` (auth-tools.ts:265): a store failure is no webhooks, and it
// is silent unless a host asks to hear about it.
func TestWebhookEmitterSwallowsAStoreFailure(t *testing.T) {
	var mu sync.Mutex
	var seen []error
	emitter := &WebhookEmitter{
		Store: failingWebhookStore{},
		Sender: &WebhookSender{Deliverer: WebhookDelivererFunc(func(context.Context, WebhookAttempt) error {
			t.Error("a failing store delivered a webhook")
			return nil
		})},
		OnError: func(config WebhookConfig, err error) {
			mu.Lock()
			defer mu.Unlock()
			if config.ID != "" {
				t.Errorf("a store failure was reported against config %q", config.ID)
			}
			seen = append(seen, err)
		},
	}
	// The whole point: Emit returns normally. There is no error to propagate.
	emitter.Emit(context.Background(), Event{Name: EventAuthLoginSuccess, Timestamp: time.Now()})
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("OnError calls = %d, want 1", len(seen))
	}

	// And with no hook, nothing at all happens.
	(&WebhookEmitter{Store: failingWebhookStore{}}).Emit(context.Background(), Event{Name: EventAuthLoginSuccess})
	// A nil Store is "no outgoing webhooks", not a panic.
	(&WebhookEmitter{}).Emit(context.Background(), Event{Name: EventAuthLoginSuccess})
}

// A delivery must not die with the request that caused it: the reference does
// not await send (auth-tools.ts:280), so a retry schedule outlives the
// response.
func TestWebhookEmitterDetachesTheDeliveryFromTheCallersContext(t *testing.T) {
	store := NewMemoryWebhookStore()
	if _, err := store.AddWebhook(context.Background(), WebhookConfig{
		URL: "https://example.test/hook", Events: []string{WebhookEventWildcard}, MaxRetries: intPtr(0),
	}); err != nil {
		t.Fatalf("add webhook: %v", err)
	}

	type key struct{}
	cancelled := make(chan struct{})
	seen := make(chan recordedAttempt, 1)
	emitter := &WebhookEmitter{
		Store: store,
		Sender: &WebhookSender{Deliverer: WebhookDelivererFunc(func(ctx context.Context, a WebhookAttempt) error {
			<-cancelled
			if ctx.Value(key{}) != "kept" {
				t.Error("the delivery context lost the caller's values")
			}
			seen <- recordedAttempt{attempt: a, ctxErr: ctx.Err()}
			return nil
		})},
	}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "kept"))
	emitter.Emit(ctx, Event{Name: EventAuthLoginSuccess, Timestamp: time.Now()})
	cancel()
	close(cancelled)

	select {
	case got := <-seen:
		if got.ctxErr != nil {
			t.Fatalf("the delivery context ended with the caller's: %v", got.ctxErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the delivery never ran")
	}
}

// End to end over the pieces a host actually wires: a store, the bus U18 gave
// callers, the emitter's one-line bridge, and a real HTTP endpoint. This is the
// path that proves the wire format is reachable from a published event, and it
// is the shape the example uses.
func TestWebhookEmitterDeliversAPublishedEventOverTheBus(t *testing.T) {
	const secret = "s3cr3t"
	type capture struct {
		event string
		body  []byte
		sig   string
	}
	got := make(chan capture, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- capture{event: r.Header.Get(webhookEventHeader), body: body, sig: r.Header.Get(webhookSignatureHeader)}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := NewMemoryWebhookStore()
	if _, err := store.AddWebhook(context.Background(), WebhookConfig{
		URL: server.URL, Secret: secret,
		Events: []string{EventAuthLoginSuccess}, MaxRetries: intPtr(0),
	}); err != nil {
		t.Fatalf("add webhook: %v", err)
	}

	bus := NewEventBus()
	(&WebhookEmitter{Store: store}).Subscribe(bus)

	// Published the way U18 publishes, request context and all.
	ctx := ContextWithEventContext(context.Background(), EventContext{
		CorrelationID: "cor_1", IP: "203.0.113.7", UserAgent: "curl/8",
	})
	bus.PublishContext(ctx, Event{Name: EventAuthLoginSuccess, UserID: "usr_1", SessionID: "ses_1"})

	select {
	case c := <-got:
		if c.event != EventAuthLoginSuccess {
			t.Errorf("X-Webhook-Event = %q", c.event)
		}
		if err := VerifyWebhookSignature(secret, c.body, c.sig); err != nil {
			t.Errorf("signature: %v", err)
		}
		var decoded OutgoingWebhookEvent
		if err := json.Unmarshal(c.body, &decoded); err != nil {
			t.Fatalf("body: %v", err)
		}
		// The correlation id the adapter put on the context reaches the
		// receiver; the address and the user agent deliberately do not.
		if decoded.Metadata["correlationId"] != "cor_1" {
			t.Errorf("metadata.correlationId = %v", decoded.Metadata["correlationId"])
		}
		if _, present := decoded.Metadata["ip"]; present {
			t.Error("the client address left the deployment")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the published event never reached the endpoint")
	}
}

// A bus subscription is a host's call, not something this package makes for it:
// nothing wires an emitter on its own, so U21 inherits an unclaimed seat rather
// than a default to unpick.
func TestNothingSubscribesAWebhookEmitterByItself(t *testing.T) {
	bus := NewEventBus()
	delivered := make(chan struct{}, 1)
	store := NewMemoryWebhookStore()
	if _, err := store.AddWebhook(context.Background(), WebhookConfig{
		URL: "https://example.test/hook", Events: []string{WebhookEventWildcard},
	}); err != nil {
		t.Fatalf("add webhook: %v", err)
	}
	emitter := &WebhookEmitter{
		Store: store,
		Sender: &WebhookSender{Deliverer: WebhookDelivererFunc(func(context.Context, WebhookAttempt) error {
			delivered <- struct{}{}
			return nil
		})},
	}
	bus.Publish(Event{Name: EventAuthLoginSuccess})
	select {
	case <-delivered:
		t.Fatal("an unsubscribed emitter received a published event")
	case <-time.After(100 * time.Millisecond):
	}

	emitter.Subscribe(bus)
	bus.Publish(Event{Name: EventAuthLoginSuccess})
	select {
	case <-delivered:
	case <-time.After(5 * time.Second):
		t.Fatal("a subscribed emitter did not receive a published event")
	}
}

// VerifyWebhookSignature is the reference's verify (webhook-sender.ts:65-74)
// and the receiver-side half of the format. It moved out of the removed
// webhooks.go unchanged, and these are the cases it has always had to answer.
func TestVerifyWebhookSignature(t *testing.T) {
	body := []byte(`{"event":"test"}`)
	const secret = "my-webhook-secret"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	valid := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if err := VerifyWebhookSignature(secret, body, valid); err != nil {
		t.Fatalf("expected valid signature to pass: %v", err)
	}
	if signWebhookBody(secret, body) != valid {
		t.Error("signWebhookBody and the reference's sign disagree")
	}
	for _, tc := range []struct {
		name   string
		secret string
		body   []byte
		header string
	}{
		{"mismatched signature", "secret1", body, "sha256=" + hex.EncodeToString(make([]byte, 32))},
		{"wrong secret", "not-the-secret", body, valid},
		{"altered body", secret, []byte(`{"event":"tset"}`), valid},
		{"invalid format", secret, body, "invalid-header"},
		{"invalid hex", secret, body, "sha256=notvalidhex!"},
		{"too short", secret, body, "sha2"},
		{"empty header", secret, body, ""},
		{"unprefixed hex", secret, body, strings.TrimPrefix(valid, "sha256=")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyWebhookSignature(tc.secret, tc.body, tc.header); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
