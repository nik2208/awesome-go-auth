package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// This file is the port of the reference's WebhookSender
// (src/tools/webhook-sender.ts): the wire an outgoing webhook is delivered on,
// the retry policy around it, and the one seam a deployment replaces when
// delivery does not belong on the goroutine that raised the event.
//
// It replaces WebhookDispatcher, which webhooks.go held until this release.
// That type was this port's own invention — its own endpoint list, its own
// envelope, and an X-Signature-SHA256 header the reference has never sent — and
// webhook_store.go named this change as the one that would remove it. The
// removal is breaking and deliberate; CHANGELOG.md says what a host does about
// it.
//
// Three pieces, and the split between them is the whole design:
//
//   - WebhookSender owns the envelope, the four headers, the signature and the
//     retry loop. It is a transcription of webhook-sender.ts:17-48 and nothing
//     in it is negotiable, because a receiver written against the reference has
//     to verify a signature this package computed.
//   - WebhookDeliverer is the transport, and only the transport. The sender
//     hands it a request that is already built, already signed and already
//     numbered; a host that replaces it is replacing net/http with SQS, not
//     reimplementing the format. That is the seam the Lambda deployment needs.
//   - WebhookEmitter is step 4 of the reference's AuthTools.track
//     (auth-tools.ts:263-281) and no more of it: find the subscriptions, build
//     one envelope, fan out. The other three steps of track — telemetry, the
//     bus, SSE — and the order they run in are U21's, and nothing here assumes
//     an order.
//
// What this file deliberately does not do is subscribe anything. Neither tree
// bridges the event bus to the sender: in both, AuthTools.track is the only
// caller of WebhookSender.send, and the routers' own publications go to the bus
// and stop there (auth-tools.ts:263-281 against node-auth
// auth.router.ts:418-433). So no constructor in this package wires a
// WebhookEmitter to an EventBus. WebhookEmitter.Subscribe exists for a host
// that wants the bridge today — this port raises its events from the service
// layer onto the bus, so the bridge is the only path that reaches a webhook
// before U21 — and it is one line a host writes, not a default it has to
// discover and undo.

// The envelope headers, named as the reference names them
// (webhook-sender.ts:24-33). They are shared with the two senders that borrowed
// the convention before this file existed — DeliveryWebhook and ClaimsWebhook —
// so that one receiver verifies all three the same way.
const (
	webhookEventHeader     = "X-Webhook-Event"
	webhookDeliveryHeader  = "X-Webhook-Delivery"
	webhookTimestampHeader = "X-Webhook-Timestamp"
	webhookSignatureHeader = "X-Webhook-Signature"
)

// webhookTimestampLayout is Date.prototype.toISOString's output — UTC, always
// three fractional digits, a literal Z.
//
// It is the format of OutgoingWebhookEvent.Timestamp and therefore of the
// X-Webhook-Timestamp header, and the reason that field is a string rather than
// a time.Time is written on the field itself: RFC 3339 in Go emits as many
// fractional digits as the value happens to have, so the same instant would
// serialise differently here and there, and the signature is over the bytes.
const webhookTimestampLayout = "2006-01-02T15:04:05.000Z07:00"

// DefaultWebhookTimeout bounds one HTTPWebhookDeliverer request whose Timeout is
// unset.
//
// The reference sets none: its fetch is bounded only by whatever its runtime
// does. Go's zero value is "wait forever", which for a delivery on a detached
// goroutine means a leaked goroutine per hung endpoint rather than a slow
// webhook, so this package picks a bound and makes it a field. Ten seconds is
// what the removed WebhookDispatcher used, and a receiver that cannot
// acknowledge in ten seconds should acknowledge and do the work afterwards.
const DefaultWebhookTimeout = 10 * time.Second

// WebhookTimestamp formats t the way the reference's toISOString() does, which
// is the only spelling OutgoingWebhookEvent.Timestamp and X-Webhook-Timestamp
// may carry: UTC, exactly three fractional digits, a literal Z.
//
// It is exported because a host building an OutgoingWebhookEvent by hand — a
// replay tool, a test fixture, the far side of a queueing WebhookDeliverer —
// has to produce the same bytes, and time.RFC3339Nano does not.
func WebhookTimestamp(t time.Time) string {
	return t.UTC().Format(webhookTimestampLayout)
}

// OutgoingWebhook returns the envelope an outgoing webhook carries for this
// event: the object the reference's track builds once per event and sends to
// every matching subscription (auth-tools.ts:266-273).
//
// version is OutgoingWebhookEvent.Version, the reference's
// AuthToolsOptions.webhookVersion; empty means OutgoingWebhookVersion.
//
// The four members are the reference's four. Data is the event's data or JSON
// null — the reference writes `data ?? null` (:269), and a nil Event.Data
// reaches the wire as null rather than as {} or as an absent key, which is what
// leaving the `any` nil does. Metadata is Event.WebhookMetadata(), which is
// where the four-key object and the decision to leave IP and UserAgent out of
// it already live; building it here a second time is exactly what that method
// exists to prevent.
//
// A zero Timestamp is filled with the current instant, for the reason
// EventBus.Publish fills one: an envelope with a zero time would put year 1 on
// the wire, and every event the reference sends is stamped at the moment track
// ran.
func (e Event) OutgoingWebhook(version string) OutgoingWebhookEvent {
	if version == "" {
		version = OutgoingWebhookVersion
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	envelope := OutgoingWebhookEvent{
		Event:     e.Name,
		Version:   version,
		Timestamp: WebhookTimestamp(e.Timestamp),
		Metadata:  e.WebhookMetadata(),
	}
	// Left nil — and so encoded as null — when the event carried no data.
	if e.Data != nil {
		envelope.Data = e.Data
	}
	return envelope
}

// WebhookAttempt is one prepared delivery: everything a transport needs and
// nothing it has to decide.
//
// The sender fills every field before calling WebhookDeliverer, so an
// implementation neither serialises the envelope nor signs it nor chooses a
// delivery id. It is safe to serialise this value onto a queue as it stands —
// it is the request, not the subscription, and it deliberately carries no
// secret.
type WebhookAttempt struct {
	// ConfigID is WebhookConfig.ID: which subscription this delivery belongs
	// to. It is here for a host's logs, metrics and dead-letter routing, and it
	// is the only part of the configuration that crosses the seam — the URL
	// below is the request's, and the secret never crosses at all.
	ConfigID string
	// URL is where to POST Body.
	URL string
	// Event is the event name, the same string as the X-Webhook-Event header.
	Event string
	// DeliveryID is the X-Webhook-Delivery value for this attempt.
	//
	// Fresh on every attempt, not once per event: the reference mints it inside
	// the retry loop (webhook-sender.ts:27), so two attempts at the same
	// envelope carry two different ids and a receiver cannot use it to
	// deduplicate. See WebhookDeliverer for what that means for a host that
	// redelivers.
	DeliveryID string
	// Attempt is zero for the first try and increments by one per retry.
	Attempt int
	// Remaining is how many further attempts the sender will make if this one
	// returns an error. Zero means this is the last one, and a host that
	// dead-letters wants to know that before it returns.
	Remaining int
	// Headers are the request headers, complete: Content-Type and the four
	// X-Webhook-* the reference sends, with X-Webhook-Signature present only
	// when the subscription carries a secret. Send them as given. The signature
	// covers Body exactly, so an added, dropped or rewritten header is
	// survivable and a changed body is not.
	Headers http.Header
	// Body is the serialised OutgoingWebhookEvent: the bytes the signature was
	// computed over, and the bytes that have to arrive.
	Body []byte
}

// NewRequest builds the POST this attempt describes. It is what
// HTTPWebhookDeliverer calls, and it is exported for a host whose deliverer is
// still HTTP — one that adds a proxy, a client certificate or its own
// instrumentation — so that the header set stays in one place.
//
// The returned request owns a copy of Headers and reads Body from memory, so it
// is safe to retry.
func (a WebhookAttempt) NewRequest(ctx context.Context) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(a.Body))
	if err != nil {
		return nil, err
	}
	if a.Headers != nil {
		req.Header = a.Headers.Clone()
	}
	req.ContentLength = int64(len(a.Body))
	return req, nil
}

// WebhookDeliverer is the transport an outgoing webhook leaves by: the seam
// that replaces the reference's bare fetch (webhook-sender.ts:36).
//
// It exists because delivering on the goroutine that served the request is a
// deployment decision and not a library one. The in-process default,
// HTTPWebhookDeliverer, is the reference's behaviour; a Lambda deployment puts
// the attempt on a queue with a dead-letter queue behind it and returns as soon
// as the enqueue is durable, so that the request goroutine never waits on a
// third party it does not control.
//
// The seam is deliberately below the format and below the policy. The sender
// has already built the envelope, signed it, numbered the attempt and decided
// how many more there will be; an implementation POSTs Body to URL with Headers
// and reports what happened. Nothing here is a place to re-derive a signature
// or re-read a WebhookConfig.
//
// # The contract
//
// Return nil when the delivery succeeded — for HTTP, a 2xx answer; for a queue,
// a durable enqueue. Return an error for anything else. The sender treats every
// error alike, because the reference does: a non-2xx and a network failure take
// the same branch (webhook-sender.ts:37-43).
//
// An error is retryable. The sender waits the subscription's back-off and calls
// again with a fresh WebhookAttempt — a new DeliveryID, Attempt one higher,
// Remaining one lower — until Remaining reaches zero, then gives up.
//
// # What a host owes
//
// Ordering: nothing. Two events for the same endpoint are delivered on separate
// goroutines and may arrive in any order, exactly as the reference's unawaited
// sends may; an implementation need not preserve order either, and a receiver
// that cares orders by the envelope's timestamp. A queue that happens to be
// FIFO is a bonus nobody may depend on.
//
// Delivery: this package promises at-most-once and nothing more. It persists
// nothing, so a process that exits mid-flight drops whatever was in the air,
// and a host that needs at-least-once is the one that buys it — by making
// DeliverWebhook durable before it returns nil, and by delivering from that
// durable record afterwards.
//
// Retry: once DeliverWebhook returns nil, this package is finished with the
// delivery and will never hear about it again. So the back-off implemented here
// covers only failures to hand the attempt over — for a queueing deliverer,
// failures to enqueue. The retry policy for the real request becomes the host's
// the moment it accepts one, and a host that wants a receiver to see the
// reference's behaviour reproduces it on the far side: at most
// WebhookConfig.Retries() further attempts, the first after
// WebhookConfig.RetryDelay() and each subsequent wait twice the last. Those two
// helpers apply the reference's defaults, so read the policy off the
// configuration rather than hard-coding 3 and one second. A dead-letter queue
// is likewise the host's, and this package will never learn that a delivery
// reached one.
//
// Idempotency: do not mint a DeliveryID of your own. It is per attempt rather
// than per event, so it is not a deduplication key and a receiver that treats
// it as one is already wrong against the reference; but a host that redelivers
// from a queue should resend the header it was handed, so that the identifiers
// a receiver sees are the ones this package actually issued.
//
// Concurrency: DeliverWebhook is called from one goroutine per delivery and
// must be safe for concurrent use.
//
// Blocking: the call owns its goroutine and the sender applies no timeout
// around it. Honour ctx, or bound the work some other way —
// HTTPWebhookDeliverer does the latter with its own Timeout. On the
// WebhookEmitter path ctx carries the caller's values but no deadline and no
// cancellation, because a fire-and-forget delivery must not die with the
// request that caused it.
type WebhookDeliverer interface {
	DeliverWebhook(ctx context.Context, attempt WebhookAttempt) error
}

// WebhookDelivererFunc adapts a plain function to WebhookDeliverer.
type WebhookDelivererFunc func(ctx context.Context, attempt WebhookAttempt) error

// DeliverWebhook calls f.
func (f WebhookDelivererFunc) DeliverWebhook(ctx context.Context, attempt WebhookAttempt) error {
	return f(ctx, attempt)
}

// WebhookStatusError is what HTTPWebhookDeliverer returns when the endpoint
// answered but refused: a status outside 2xx.
//
// The sender does not look at it — the reference retries a refusal and a
// transport failure identically (webhook-sender.ts:37-43) and so does this port
// — but a host's telemetry, and a host deliverer deciding whether a dead-letter
// is worth writing, want the two apart. The body is deliberately not carried: a
// receiver that echoes the request would put the payload back into an error
// string that is logged further than the request ever travelled.
type WebhookStatusError struct {
	// StatusCode is the status the endpoint answered with.
	StatusCode int
}

func (e *WebhookStatusError) Error() string {
	return fmt.Sprintf("auth: webhook endpoint answered status %d", e.StatusCode)
}

// HTTPWebhookDeliverer POSTs the attempt over HTTP, in process, on the calling
// goroutine. It is the default WebhookDeliverer and it is the reference's own
// behaviour — the fetch at webhook-sender.ts:36, with a timeout Go needs and
// the reference does without.
//
// The zero value is usable.
type HTTPWebhookDeliverer struct {
	// Client issues the request. Nil means http.DefaultClient. A Client with a
	// Timeout of its own is bounded by both.
	Client *http.Client
	// Timeout bounds one request, connect to last byte, through the request
	// context — a shorter deadline already on ctx wins. Zero or negative means
	// DefaultWebhookTimeout.
	Timeout time.Duration
}

// DeliverWebhook posts the attempt. A 2xx is nil; anything else is a
// *WebhookStatusError, and a transport failure or a timeout is whatever the
// client returned.
func (d *HTTPWebhookDeliverer) DeliverWebhook(ctx context.Context, attempt WebhookAttempt) error {
	timeout := DefaultWebhookTimeout
	if d != nil && d.Timeout > 0 {
		timeout = d.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := attempt.NewRequest(ctx)
	if err != nil {
		return err
	}
	client := http.DefaultClient
	if d != nil && d.Client != nil {
		client = d.Client
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain a little so a kept-alive connection can be reused; the bytes go
	// nowhere, for the reason WebhookStatusError carries no body.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	// res.ok, which is 200-299 and nothing else (webhook-sender.ts:37).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &WebhookStatusError{StatusCode: resp.StatusCode}
	}
	return nil
}

// WebhookSender delivers one OutgoingWebhookEvent to one subscription, with the
// reference's headers, the reference's signature and the reference's retry
// policy: WebhookSender.send (webhook-sender.ts:17-48).
//
// The zero value is usable and delivers over HTTP.
type WebhookSender struct {
	// Deliverer is the transport. Nil means an HTTPWebhookDeliverer with the
	// default client and DefaultWebhookTimeout — the reference's behaviour.
	Deliverer WebhookDeliverer

	// sleep waits out one back-off. It is a field so that the retry schedule can
	// be asserted without a test waiting seconds for it; nothing outside this
	// package can replace it, because the schedule is the reference's and is not
	// a knob.
	sleep func(ctx context.Context, d time.Duration) error
}

// Send delivers event to config, retrying on failure, and reports what
// happened.
//
// The wire, in full. One POST to config.URL with the serialised event as the
// body and
//
//	Content-Type:        application/json
//	X-Webhook-Event:     <event.Event>
//	X-Webhook-Delivery:  <a fresh UUID, per attempt rather than per event>
//	X-Webhook-Timestamp: <event.Timestamp, the envelope's own string>
//	X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the body>  (only with a secret)
//
// Three of those repay a second look, because each is a place a reasonable
// implementation would differ and a receiver would notice:
//
//   - X-Webhook-Delivery changes on every attempt. The reference mints it
//     inside the retry loop (webhook-sender.ts:27), so a receiver that saw the
//     same event twice sees two identifiers and cannot deduplicate on this
//     header. It is reproduced rather than corrected.
//   - X-Webhook-Timestamp is the envelope's timestamp, not the attempt's (:28).
//     A retry an hour later still carries the instant the event happened, which
//     is what makes the header and the body agree.
//   - The signature covers the serialised body and the body only — not the
//     headers, not the URL, not the timestamp as a separate input. The body is
//     serialised once, before the first attempt (:20), so every attempt at an
//     event carries identical bytes and an identical signature.
//
// The retry policy is likewise the reference's, and it is worth stating in
// attempts rather than in retries because the two are off by one:
// `while (attempt <= maxRetries)` runs config.Retries()+1 times, so the default
// 3 is four requests, not three. A non-2xx and a transport failure are the same
// failure here; both retry while attempts remain. Between them the sender waits
// config.RetryDelay() doubled once per retry already made — with the defaults
// 1s, 2s, 4s — which is `baseDelayMs * 2^(attempt-1)` evaluated after the
// increment at :45-46. The last attempt is not followed by a wait: the
// reference returns out of the loop before the delay (:39, :42), and so does
// this.
//
// Two edge cases fall out of that loop and both are the reference's.
// config.Retries() of 0 is one attempt and no retry, which is why
// WebhookConfig.MaxRetries is a *int — a stored 0 that decayed into the default
// would turn "deliver once" into four deliveries. A negative one sends nothing
// at all: `while (attempt <= -1)` never runs, no request is made, and Send
// reports no error because nothing failed.
//
// What Send returns is where this is not a transcription, and the difference is
// off the wire. The reference's send resolves void whether it delivered or gave
// up: its one caller discards the promise (auth-tools.ts:280), so the failure is
// silent by construction. Here the exhausted case returns an error wrapping the
// last failure, because a Go caller has no other way to learn it and because the
// host implementing a queueing WebhookDeliverer needs one. The silence is
// reproduced where the reference is actually silent — one level up, in
// WebhookEmitter, which discards this error exactly as `.catch(() => {})` does
// and logs nothing unless a host asks it to.
//
// Send does not consult config beyond URL, Secret, MaxRetries and RetryDelayMs.
// It checks neither IsActive nor Events, because the reference's sender checks
// neither: the store is the only filter in the chain and a store that
// over-returns delivers. That is stated on WebhookStore.FindByEvent, and this
// method is what makes it true.
func (s *WebhookSender) Send(ctx context.Context, config WebhookConfig, event OutgoingWebhookEvent) error {
	if s == nil {
		return fmt.Errorf("auth: webhook sender is nil")
	}
	where := event.Event
	if config.ID != "" {
		where += " to " + config.ID
	}

	// Serialised once, outside the loop, as the reference serialises it
	// (webhook-sender.ts:20): every attempt has to carry the same bytes, or the
	// signature a receiver checks would only match the attempt that produced
	// it. encoding/json escapes <, > and & where JSON.stringify does not, which
	// is this package's convention everywhere it writes JSON and is invisible
	// here in any case — the signature is over what is sent, and a receiver
	// parses the escapes back to the same string.
	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("auth: webhook %s: encode: %w", where, err)
	}

	retries := config.Retries()
	delay := config.RetryDelay()
	deliverer := s.Deliverer
	if deliverer == nil {
		deliverer = &HTTPWebhookDeliverer{}
	}
	sleep := s.sleep
	if sleep == nil {
		sleep = webhookSleep
	}

	for attempt := 0; attempt <= retries; attempt++ {
		deliveryID, err := newUUIDv4()
		if err != nil {
			return fmt.Errorf("auth: webhook %s: %w", where, err)
		}
		headers := make(http.Header, 5)
		headers.Set("Content-Type", "application/json")
		headers.Set(webhookEventHeader, event.Event)
		headers.Set(webhookDeliveryHeader, deliveryID)
		headers.Set(webhookTimestampHeader, event.Timestamp)
		if config.Secret != "" {
			headers.Set(webhookSignatureHeader, signWebhookBody(config.Secret, body))
		}

		sendErr := deliverer.DeliverWebhook(ctx, WebhookAttempt{
			ConfigID:   config.ID,
			URL:        config.URL,
			Event:      event.Event,
			DeliveryID: deliveryID,
			Attempt:    attempt,
			Remaining:  retries - attempt,
			Headers:    headers,
			Body:       body,
		})
		if sendErr == nil {
			return nil
		}
		// The reference returns before the delay on the last attempt
		// (webhook-sender.ts:39, :42), so nobody waits out a back-off that
		// nothing follows.
		if attempt >= retries {
			return fmt.Errorf("auth: webhook %s: gave up after %d attempt(s): %w", where, attempt+1, sendErr)
		}
		if err := sleep(ctx, webhookBackoff(delay, attempt)); err != nil {
			return fmt.Errorf("auth: webhook %s: %w", where, err)
		}
	}
	// Only reachable with a negative Retries(), whose loop the reference
	// likewise declines to enter. Nothing was sent and nothing failed.
	return nil
}

// webhookBackoff is the wait after the attempt-th failure, counting from zero:
// `baseDelayMs * Math.pow(2, attempt - 1)` evaluated after the reference's
// increment (webhook-sender.ts:45-46), which for attempt 0 is base, for 1 is
// twice base, and so on.
//
// It doubles rather than shifting so that an absurd MaxRetries saturates
// instead of wrapping to a negative Duration. The reference overflows to
// Infinity there and its runtime then clamps a non-finite delay to a single
// millisecond, firing immediately — the opposite of saturating. That is not
// reproduced: reaching either behaviour needs a MaxRetries above thirty, which
// is four billion attempts and no deployment's configuration.
func webhookBackoff(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	const ceiling = time.Duration(1) << 62
	d := base
	for i := 0; i < attempt; i++ {
		if d > ceiling/2 {
			return ceiling
		}
		d *= 2
	}
	return d
}

// webhookSleep waits out one back-off, or stops early if ctx ends.
//
// The reference's delay is a bare setTimeout and cannot be cancelled
// (webhook-sender.ts:76-78). Honouring ctx is the Go caller's expectation, and
// it is unreachable on the WebhookEmitter path, which detaches from the request
// precisely so that a retry schedule outlives the response.
func webhookSleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// WebhookEmitter fans one Event out to the subscriptions a WebhookStore holds:
// step 4 of the reference's AuthTools.track (auth-tools.ts:263-281), and
// exactly that step.
//
// The zero value does nothing. A Store is what turns it on, which is the
// reference's rule too — `if (this.webhookStore)` (:263); without one, outgoing
// webhooks are off.
//
// # Where the line to U21 is drawn
//
// track does four things per event: persists a telemetry record, publishes on
// the bus, broadcasts over SSE and fires webhooks. This type is the fourth, on
// its own, with no opinion about the other three or about the order they run
// in. That order is observable — a subscriber that reads the telemetry store
// sees a different world depending on whether the save has happened — so it is
// one decision, made once, by the facade that owns all four. Implementing a
// second, partial ordering here and asking U21 to unpick it would be the worse
// inheritance.
//
// So U21 may call Emit from wherever in track's sequence it decides webhooks
// belong, and will find that this type has already settled the parts that are
// local to webhooks: the store failure is swallowed, the envelope is built once
// per event rather than once per subscription, and every delivery is
// fire-and-forget.
type WebhookEmitter struct {
	// Store is where the subscriptions live. Nil is "no outgoing webhooks", not
	// an error.
	Store WebhookStore
	// Sender delivers. Nil means a zero WebhookSender, which delivers over HTTP
	// in process.
	Sender *WebhookSender
	// Version is OutgoingWebhookEvent.Version, the reference's
	// AuthToolsOptions.webhookVersion. Empty means OutgoingWebhookVersion.
	Version string
	// OnError, when set, is called once per subscription whose delivery failed
	// after every attempt, and once with a zero WebhookConfig when the store
	// itself failed.
	//
	// Nil is the default and nil is the reference: track discards the store
	// error with `.catch(() => [])` (:265) and each send with `.catch(() => {})`
	// (:280), and logging where the reference stays silent would be a difference
	// this package would then have to register. So the default is silence and
	// the hook is how a deployment buys observability back. It is called on the
	// delivery goroutine and must be safe for concurrent use; it must not block,
	// because nothing is waiting on it and a slow hook only accumulates
	// goroutines.
	OnError func(config WebhookConfig, err error)
}

// Emit delivers ev to every subscription the store returns for it.
//
// The shape is the reference's, and each part of it is a decision the reference
// already made:
//
//   - The lookup is synchronous, on the calling goroutine. track awaits
//     findByEvent before it sends anything (auth-tools.ts:265), so a slow store
//     delays whatever published — in this port, the service call and therefore
//     the HTTP response. That is reproduced rather than improved: moving the
//     lookup onto a goroutine would reorder it against the caller's own work
//     for no gain a deployment asked for.
//   - A store error is not an error. It becomes an empty result, so a failing
//     store means "no webhooks for this event" and never a failed publish —
//     `.catch(() => [])` (:265). OnError hears about it; nothing else does.
//   - The envelope is built once and shared by every delivery (:266-273). Two
//     subscriptions receive byte-identical bodies and therefore comparable
//     signatures, which is what a receiver fronting several endpoints expects.
//   - Every delivery is fire-and-forget, on its own goroutine, and Emit returns
//     without waiting: the reference does not await send (:280). Nothing is
//     ordered against anything, and a webhook that will retry for seven seconds
//     does not hold the response open for seven seconds.
//
// ctx is used for the store lookup as given. The deliveries get
// context.WithoutCancel(ctx): they keep the caller's values, for a host whose
// deliverer reads a trace from them, and lose its deadline and cancellation,
// because a delivery that died when the response was written would be a retry
// policy that never retried. Nothing is waited on and nothing is persisted, so
// a process that exits drops whatever is in flight — see WebhookDeliverer for
// which half of that a host can buy back.
func (e *WebhookEmitter) Emit(ctx context.Context, ev Event) {
	if e == nil || e.Store == nil {
		return
	}
	configs, err := e.Store.FindByEvent(ctx, ev.Name, ev.TenantID)
	if err != nil {
		// The reference's .catch(() => []): a store failure is no webhooks, not
		// a failed emit.
		if e.OnError != nil {
			e.OnError(WebhookConfig{}, fmt.Errorf("auth: webhook store lookup for %q: %w", ev.Name, err))
		}
		return
	}
	if len(configs) == 0 {
		return
	}
	envelope := ev.OutgoingWebhook(e.Version)
	sender := e.Sender
	if sender == nil {
		sender = &WebhookSender{}
	}
	onError := e.OnError
	detached := context.WithoutCancel(ctx)
	for _, config := range configs {
		go func(config WebhookConfig) {
			if err := sender.Send(detached, config, envelope); err != nil && onError != nil {
				onError(config, err)
			}
		}(config)
	}
}

// Subscribe wires this emitter to every event a bus carries, so that publishing
// an event delivers it to the subscriptions a store holds.
//
// It is one line, and the line is written out here rather than hidden because
// it is the whole of the bridge:
//
//	bus.Subscribe(auth.EventBusWildcard, func(ev auth.Event) {
//		emitter.Emit(context.Background(), ev)
//	})
//
// Neither tree ships this bridge. There, AuthTools.track is the only caller of
// the sender and the routers' own publications reach the bus and stop
// (auth-tools.ts:263-281 against node-auth auth.router.ts:418-433). Here the
// service layer publishes onto the bus, so until U21 brings the facade across
// this is how a deployment gets an outgoing webhook at all — and it stays a
// call a host makes rather than something New() does, so that a host who wants
// U21's ordering later has nothing to switch off.
//
// The context is Background: a bus handler is handed an Event and no context,
// and a delivery is fire-and-forget in any case. There is no way to
// unsubscribe, because EventBus has none; that arrives with the first consumer
// that needs it.
func (e *WebhookEmitter) Subscribe(bus *EventBus) {
	if e == nil || bus == nil {
		return
	}
	bus.Subscribe(EventBusWildcard, func(ev Event) {
		e.Emit(context.Background(), ev)
	})
}

// signWebhookBody is the reference's WebhookSender.sign
// (webhook-sender.ts:54-56): "sha256=" + hex(HMAC-SHA256(secret, body)). It is
// the form VerifyWebhookSignature checks, and the value of the
// X-Webhook-Signature header on every outbound request this package makes.
func signWebhookBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature validates an X-Webhook-Signature header against the raw
// body it should cover: the reference's WebhookSender.verify
// (webhook-sender.ts:65-74), which a receiver calls rather than a sender.
//
// sigHeader is the header value whole, "sha256=" prefix included. A nil error
// means the body was signed with secret and has not been altered since.
//
// It answers an error where the reference answers false, because a Go caller
// gating on a webhook wants to know which of the three refusals it hit while it
// is writing the check, and because false is the one return value that is easy
// to ignore. The comparison is constant-time either way — the reference
// hand-rolls one over char codes (:68-73) and this uses hmac.Equal — and the
// length check that precedes it leaks nothing on either side: the length of a
// hex-encoded SHA-256 is not a secret.
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

// newUUIDv4 is what the reference's randomUUID() gives X-Webhook-Delivery: a
// random (version 4, variant 1) UUID in its canonical 8-4-4-4-12 spelling.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: random uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
