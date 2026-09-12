package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// SSE is the one surface in this package whose tests are about time, and a
// suite that waits out a duration is a suite that flakes on a loaded machine.
// So nothing here sleeps for an interval it expects something to happen in.
// Every wait is a deadline that only a failure reaches, every ordering claim is
// made by arranging the order rather than by pausing between steps, and the two
// negative claims — that a disabled heartbeat sends nothing and that a
// cancelled subscription delivers nothing — are made by proving that the *next*
// frame is a different, deliberately provoked one.
const sseTestDeadline = 10 * time.Second

// sseRecorder is a ResponseWriter that records what was written and lets a test
// hold a write open.
//
// gate, when non-nil, is a token bucket: each Write takes one and blocks when
// there are none, which is how a test parks the connection's pump inside a
// write and lets its queue fill.
type sseRecorder struct {
	hdr    http.Header
	writes chan []byte
	gate   chan struct{}

	mu      sync.Mutex
	body    bytes.Buffer
	flushes int
}

func newSseRecorder() *sseRecorder {
	return &sseRecorder{hdr: make(http.Header), writes: make(chan []byte, 64)}
}

func (w *sseRecorder) Header() http.Header { return w.hdr }

func (w *sseRecorder) Write(p []byte) (int, error) {
	if w.gate != nil {
		<-w.gate
	}
	w.mu.Lock()
	w.body.Write(p)
	w.mu.Unlock()
	frame := append([]byte(nil), p...)
	select {
	case w.writes <- frame:
	default:
	}
	return len(p), nil
}

func (w *sseRecorder) WriteHeader(int) {}

func (w *sseRecorder) Flush() {
	w.mu.Lock()
	w.flushes++
	w.mu.Unlock()
}

// next returns the next frame written, failing the test on a deadline.
func (w *sseRecorder) next(t *testing.T) string {
	t.Helper()
	select {
	case frame := <-w.writes:
		return string(frame)
	case <-time.After(sseTestDeadline):
		t.Fatal("timed out waiting for an SSE frame")
		return ""
	}
}

// sseUnflushableRecorder implements http.ResponseWriter and nothing else, so
// http.ResponseController cannot flush it.
type sseUnflushableRecorder struct{ hdr http.Header }

func (w *sseUnflushableRecorder) Header() http.Header         { return w.hdr }
func (w *sseUnflushableRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (w *sseUnflushableRecorder) WriteHeader(int)             {}

// sseStream is one connection served by a test.
type sseStream struct {
	rec    *sseRecorder
	cancel context.CancelFunc
	err    <-chan error
}

// serveSseStream starts Serve on a goroutine and waits until the manager has
// registered the connection, so a following Broadcast cannot race registration.
func serveSseStream(t *testing.T, m *SseManager, rec *sseRecorder, topics []string, meta SseConnectionMeta) *sseStream {
	t.Helper()
	before := m.ConnectionCount()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	errCh := make(chan error, 1)
	go func() { errCh <- m.Serve(rec, req, topics, meta) }()
	waitForSse(t, func() bool { return m.ConnectionCount() > before }, "the connection to be registered")
	t.Cleanup(cancel)
	return &sseStream{rec: rec, cancel: cancel, err: errCh}
}

// waitForSse polls a condition up to the failure deadline. The poll interval is
// a millisecond and is not derived from anything the code under test does, so
// it neither tracks a heartbeat nor grows with load.
func waitForSse(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(sseTestDeadline)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func newTestSseManager(t *testing.T, opts ...SseOption) *SseManager {
	t.Helper()
	m, err := NewSseManager(context.Background(), opts...)
	if err != nil {
		t.Fatalf("NewSseManager: %v", err)
	}
	return m
}

// eventType pulls the value of the `event:` line out of a frame.
func sseEventType(t *testing.T, frame string) string {
	t.Helper()
	for _, line := range strings.Split(frame, "\n") {
		if strings.HasPrefix(line, "event: ") {
			return strings.TrimPrefix(line, "event: ")
		}
	}
	t.Fatalf("frame has no event line: %q", frame)
	return ""
}

// ---------------------------------------------------------------------------
// The frame, byte for byte
// ---------------------------------------------------------------------------

func TestSseFrameIsTheReferencesThreeLines(t *testing.T) {
	// sse-manager.ts:250-252. Three lines and the blank line that ends them;
	// the payload under rawData with no `data` key; userId present because it
	// was set and tenantId and metadata absent because they were not; and no
	// HTML escaping, because JSON.stringify does none.
	got, err := sseFrameBytes("evt-1", "identity.auth.login.success", sseFrame{
		ID:        "evt-1",
		Timestamp: "2026-09-12T10:11:12.345Z",
		Topic:     "user:u1",
		Type:      "identity.auth.login.success",
		UserID:    "u1",
		RawData:   map[string]any{"message": "<b>hi</b> & bye"},
	})
	if err != nil {
		t.Fatalf("sseFrameBytes: %v", err)
	}
	want := "id: evt-1\n" +
		"event: identity.auth.login.success\n" +
		`data: {"id":"evt-1","timestamp":"2026-09-12T10:11:12.345Z","topic":"user:u1",` +
		`"type":"identity.auth.login.success","userId":"u1","rawData":{"message":"<b>hi</b> & bye"}}` +
		"\n\n"
	if string(got) != want {
		t.Errorf("frame bytes differ\n got: %q\nwant: %q", got, want)
	}
}

func TestSseFrameOmitsAnAbsentOptionalAndKeepsAnEmptyOne(t *testing.T) {
	// omitzero, not omitempty: JSON.stringify drops an undefined key and keeps
	// an empty object, and the two cases have to stay distinguishable.
	absent, err := sseFrameBytes("e", "t", sseFrame{ID: "e", Type: "t", RawData: nil})
	if err != nil {
		t.Fatalf("sseFrameBytes: %v", err)
	}
	if strings.Contains(string(absent), "metadata") {
		t.Errorf("a nil Metadata should write no key: %q", absent)
	}
	if !strings.Contains(string(absent), `"rawData":null`) {
		t.Errorf("rawData is required and must be written even when null: %q", absent)
	}
	empty, err := sseFrameBytes("e", "t", sseFrame{ID: "e", Type: "t", Metadata: map[string]any{}})
	if err != nil {
		t.Fatalf("sseFrameBytes: %v", err)
	}
	if !strings.Contains(string(empty), `"metadata":{}`) {
		t.Errorf("an empty Metadata should write an empty object: %q", empty)
	}
}

func TestSseFrameIsAlwaysOneDataLine(t *testing.T) {
	// A pre-encoded, indented json.RawMessage is the only way a raw newline can
	// reach the payload, and the frame must still be three lines.
	raw := json.RawMessage("{\n  \"a\": 1\n}")
	frame, err := sseFrameBytes("e", "t", sseFrame{ID: "e", Type: "t", RawData: raw})
	if err != nil {
		t.Fatalf("sseFrameBytes: %v", err)
	}
	if n := strings.Count(string(frame), "\n"); n != 4 {
		t.Errorf("want exactly four newlines (three lines and the blank one), got %d in %q", n, frame)
	}
	if !strings.Contains(string(frame), `"rawData":{"a":1}`) {
		t.Errorf("the compacted payload should be unchanged as a value: %q", frame)
	}
}

func TestSseHeartbeatIsTheReferencesComment(t *testing.T) {
	// sse-manager.ts:159 writes ': heartbeat\n\n' although the documentation
	// beside it spells the comment without the space. The code is the contract.
	if sseHeartbeatFrame != ": heartbeat\n\n" {
		t.Errorf("heartbeat frame is %q", sseHeartbeatFrame)
	}
}

func TestStreamEventIsTheDistributorsShape(t *testing.T) {
	// A distributor serialises StreamEvent itself, so its JSON is a wire shape
	// of its own and is not the frame's.
	b, err := json.Marshal(StreamEvent{
		ID:        "e1",
		Type:      "t",
		Timestamp: "2026-09-12T10:11:12.345Z",
		Topic:     "global",
		Data:      map[string]any{"n": 1},
		UserID:    "u1",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"id":"e1","type":"t","timestamp":"2026-09-12T10:11:12.345Z","topic":"global","data":{"n":1},"userId":"u1"}`
	if string(b) != want {
		t.Errorf("StreamEvent JSON differs\n got: %s\nwant: %s", b, want)
	}
}

// ---------------------------------------------------------------------------
// Serve
// ---------------------------------------------------------------------------

func TestSseServeWritesTheReferencesHeadersAndFirstFrame(t *testing.T) {
	m := newTestSseManager(t, WithSseHeartbeat(0))
	rec := newSseRecorder()
	stream := serveSseStream(t, m, rec, []string{"user:u1", "global"}, SseConnectionMeta{UserID: "u1"})

	for header, want := range map[string]string{
		"Content-Type":      "text/event-stream",
		"Cache-Control":     "no-cache",
		"Connection":        "keep-alive",
		"X-Accel-Buffering": "no",
	} {
		if got := rec.hdr.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	frame := rec.next(t)
	if got := sseEventType(t, frame); got != "connected" {
		t.Fatalf("first frame is %q, want connected", got)
	}
	// The literal's own key order (sse-manager.ts:140-146): type precedes
	// timestamp here, unlike in a broadcast frame.
	data := strings.TrimSuffix(strings.SplitN(frame, "data: ", 2)[1], "\n\n")
	if !strings.Contains(data, `"type":"connected"`) ||
		strings.Index(data, `"type"`) > strings.Index(data, `"timestamp"`) {
		t.Errorf("connected frame key order differs from the reference's literal: %s", data)
	}
	if !strings.Contains(data, `"topic":"meta"`) {
		t.Errorf("connected frame topic should be meta: %s", data)
	}
	if !strings.Contains(data, `"topics":["user:u1","global"]`) {
		t.Errorf("connected frame should echo the server-chosen topics: %s", data)
	}
	var payload struct {
		ID      string `json:"id"`
		RawData struct {
			ConnectionID string `json:"connectionId"`
		} `json:"rawData"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		t.Fatalf("connected frame is not JSON: %v", err)
	}
	if payload.RawData.ConnectionID == "" {
		t.Error("connected frame carries no connectionId")
	}
	if payload.ID == payload.RawData.ConnectionID {
		t.Error("the connected event's id and the connection id are two different UUIDs in the reference")
	}

	stream.cancel()
	if err := <-stream.err; err != nil {
		t.Errorf("Serve after cancellation: %v", err)
	}
	waitForSse(t, func() bool { return m.ConnectionCount() == 0 }, "the connection to be forgotten")
}

func TestSseServeWritesAnEmptyTopicArrayForNoTopics(t *testing.T) {
	m := newTestSseManager(t, WithSseHeartbeat(0))
	rec := newSseRecorder()
	serveSseStream(t, m, rec, nil, SseConnectionMeta{})
	if frame := rec.next(t); !strings.Contains(frame, `"topics":[]`) {
		t.Errorf("a nil topics slice must write [] and not null: %q", frame)
	}
}

func TestSseServeRefusesAWriterItCannotFlush(t *testing.T) {
	m := newTestSseManager(t)
	w := &sseUnflushableRecorder{hdr: make(http.Header)}
	err := m.Serve(w, httptest.NewRequest(http.MethodGet, "/events", nil), []string{"global"}, SseConnectionMeta{})
	if !errors.Is(err, ErrSseStreamingUnsupported) {
		t.Fatalf("Serve = %v, want ErrSseStreamingUnsupported", err)
	}
	if got := w.hdr.Get("Content-Type"); got != "" {
		t.Errorf("the response must be left alone for the caller to answer, got Content-Type %q", got)
	}
	if m.ConnectionCount() != 0 {
		t.Error("a refused stream must not leave a registration behind")
	}
}

func TestSseHeartbeatArrivesWhenEnabled(t *testing.T) {
	// The interval is short so the test is fast, and the wait for the frame is
	// a failure deadline rather than a pause proportional to it.
	m := newTestSseManager(t, WithSseHeartbeat(time.Millisecond))
	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"global"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}
	if frame := rec.next(t); frame != sseHeartbeatFrame {
		t.Errorf("second frame = %q, want the heartbeat comment", frame)
	}
}

func TestSseHeartbeatZeroDisablesIt(t *testing.T) {
	m := newTestSseManager(t, WithSseHeartbeat(0))
	if m.HeartbeatInterval() != 0 {
		t.Fatalf("HeartbeatInterval = %v, want 0", m.HeartbeatInterval())
	}
	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"global"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}
	// No pause: the next frame is whatever arrives next, and with heartbeats
	// off the only thing that can arrive is the event provoked here.
	m.Broadcast(context.Background(), "global", StreamEvent{Type: "provoked"})
	if got := sseEventType(t, rec.next(t)); got != "provoked" {
		t.Errorf("second frame is %q, want the broadcast event — a heartbeat means 0 did not disable them", got)
	}
}

func TestSseDefaultsAreTheReferences(t *testing.T) {
	m := newTestSseManager(t)
	if m.HeartbeatInterval() != DefaultSseHeartbeatInterval {
		t.Errorf("default heartbeat = %v, want %v", m.HeartbeatInterval(), DefaultSseHeartbeatInterval)
	}
	if !m.Deduplicate() {
		t.Error("deduplication is on by default in the reference")
	}
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

func TestSseTopicMatchingIsExact(t *testing.T) {
	// The hierarchical scheme is a naming convention: no prefix or ancestor
	// matching exists (sse-manager.ts:206).
	m := newTestSseManager(t, WithSseHeartbeat(0))
	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"tenant:acme"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}
	m.Broadcast(context.Background(), "tenant:acme:role:admin", StreamEvent{Type: "descendant"})
	m.Broadcast(context.Background(), "tenant", StreamEvent{Type: "ancestor"})
	m.Broadcast(context.Background(), "tenant:acme", StreamEvent{Type: "exact"})
	if got := sseEventType(t, rec.next(t)); got != "exact" {
		t.Errorf("delivered %q; only the exact topic matches", got)
	}
}

func TestSseTenantIsolation(t *testing.T) {
	// sse-manager.ts:211: the check bites only when both sides are set.
	m := newTestSseManager(t, WithSseHeartbeat(0))
	acme := newSseRecorder()
	serveSseStream(t, m, acme, []string{"global"}, SseConnectionMeta{TenantID: "acme"})
	operator := newSseRecorder()
	serveSseStream(t, m, operator, []string{"global"}, SseConnectionMeta{})
	for _, rec := range []*sseRecorder{acme, operator} {
		if got := sseEventType(t, rec.next(t)); got != "connected" {
			t.Fatalf("first frame is %q", got)
		}
	}

	ctx := context.Background()
	m.Broadcast(ctx, "global", StreamEvent{Type: "other-tenant", TenantID: "globex"})
	m.Broadcast(ctx, "global", StreamEvent{Type: "no-tenant"})

	if got := sseEventType(t, acme.next(t)); got != "no-tenant" {
		t.Errorf("the acme connection received %q; an event for another tenant must be withheld", got)
	}
	// The connection with no tenant id receives everything, which is the
	// reference's rule and the reason an empty TenantID is a privilege.
	if got := sseEventType(t, operator.next(t)); got != "other-tenant" {
		t.Errorf("the tenant-less connection received %q first, want other-tenant", got)
	}
	if got := sseEventType(t, operator.next(t)); got != "no-tenant" {
		t.Errorf("the tenant-less connection received %q second, want no-tenant", got)
	}
}

func TestSseDeduplicationIsConsecutiveOnly(t *testing.T) {
	// The reference compares against the previous event's id and nothing older
	// (sse-manager.ts:214), so a repeat with something in between is delivered.
	m := newTestSseManager(t, WithSseHeartbeat(0))
	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"a", "b"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}

	ctx := context.Background()
	fanned := StreamEvent{ID: "same", Type: "fanned-out"}
	// One event, two topics the connection holds: the second is suppressed,
	// which is the case deduplication exists for.
	m.Broadcast(ctx, "a", fanned)
	m.Broadcast(ctx, "b", fanned)
	m.Broadcast(ctx, "a", StreamEvent{ID: "other", Type: "in-between"})
	m.Broadcast(ctx, "a", fanned)

	want := []string{"fanned-out", "in-between", "fanned-out"}
	for i, w := range want {
		if got := sseEventType(t, rec.next(t)); got != w {
			t.Fatalf("frame %d is %q, want %q", i, got, w)
		}
	}
}

func TestSseDeduplicationOffDeliversTheRepeat(t *testing.T) {
	m := newTestSseManager(t, WithSseHeartbeat(0), WithSseDeduplicate(false))
	if m.Deduplicate() {
		t.Fatal("WithSseDeduplicate(false) did not take")
	}
	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"a", "b"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}
	ev := StreamEvent{ID: "same", Type: "twice"}
	m.Broadcast(context.Background(), "a", ev)
	m.Broadcast(context.Background(), "b", ev)
	for i := range 2 {
		if got := sseEventType(t, rec.next(t)); got != "twice" {
			t.Fatalf("frame %d is %q, want twice", i, got)
		}
	}
}

func TestSseNoResumeFromLastEventID(t *testing.T) {
	// Neither implementation reads the header a browser sends on reconnect, and
	// neither retains an event to replay. The whole of the resume story is that
	// there is none, and a consumer has to be able to check that.
	m := newTestSseManager(t, WithSseHeartbeat(0))
	gone := newSseRecorder()
	first := serveSseStream(t, m, gone, []string{"global"}, SseConnectionMeta{})
	if got := sseEventType(t, gone.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}
	m.Broadcast(context.Background(), "global", StreamEvent{ID: "missed", Type: "while-connected"})
	if got := sseEventType(t, gone.next(t)); got != "while-connected" {
		t.Fatalf("frame is %q", got)
	}
	first.cancel()
	waitForSse(t, func() bool { return m.ConnectionCount() == 0 }, "the first connection to end")

	m.Broadcast(context.Background(), "global", StreamEvent{ID: "gap", Type: "while-away"})

	rec := newSseRecorder()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/events", nil).WithContext(ctx)
	req.Header.Set("Last-Event-ID", "missed")
	errCh := make(chan error, 1)
	go func() { errCh <- m.Serve(rec, req, []string{"global"}, SseConnectionMeta{}) }()
	waitForSse(t, func() bool { return m.ConnectionCount() == 1 }, "the second connection")

	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("the reconnect's first frame is %q, want connected", got)
	}
	m.Broadcast(context.Background(), "global", StreamEvent{ID: "after", Type: "after-reconnect"})
	if got := sseEventType(t, rec.next(t)); got != "after-reconnect" {
		t.Errorf("the frame after the connected one is %q; nothing may be replayed for Last-Event-ID", got)
	}
}

// ---------------------------------------------------------------------------
// The slow consumer
// ---------------------------------------------------------------------------

func TestSseSlowConsumerIsDisconnectedAndThePublisherIsNotBlocked(t *testing.T) {
	m := newTestSseManager(t, WithSseHeartbeat(0), WithSseSendBuffer(1))
	rec := newSseRecorder()
	// One token: the connected frame is written, and the next write parks.
	rec.gate = make(chan struct{}, 8)
	rec.gate <- struct{}{}
	stream := serveSseStream(t, m, rec, []string{"global"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}

	// Each Broadcast returns; none of them waits for the parked writer. The
	// queue fills within a couple of events and the connection is dropped.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 64 {
			m.Broadcast(context.Background(), "global", StreamEvent{Type: "flood"})
			if m.ConnectionCount() == 0 {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(sseTestDeadline):
		t.Fatal("Broadcast blocked on a consumer that stopped reading")
	}
	if m.ConnectionCount() != 0 {
		t.Fatal("a consumer that cannot keep up must be disconnected, not buffered without limit")
	}

	// Releasing the parked write lets the handler observe the close and return.
	for range cap(rec.gate) {
		rec.gate <- struct{}{}
	}
	select {
	case err := <-stream.err:
		if err != nil {
			t.Errorf("Serve after a disconnect: %v", err)
		}
	case <-time.After(sseTestDeadline):
		t.Fatal("Serve did not return after its connection was disconnected")
	}
}

func TestSseDisconnectIsIdempotent(t *testing.T) {
	m := newTestSseManager(t, WithSseHeartbeat(0))
	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"global"}, SseConnectionMeta{})
	frame := rec.next(t)
	data := strings.TrimSuffix(strings.SplitN(frame, "data: ", 2)[1], "\n\n")
	var payload struct {
		RawData struct {
			ConnectionID string `json:"connectionId"`
		} `json:"rawData"`
	}
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		t.Fatalf("connected frame: %v", err)
	}
	m.Disconnect(payload.RawData.ConnectionID)
	m.Disconnect(payload.RawData.ConnectionID)
	m.Disconnect("never-existed")
	waitForSse(t, func() bool { return m.ConnectionCount() == 0 }, "the connection to be forgotten")
}

// ---------------------------------------------------------------------------
// The distributor seam
// ---------------------------------------------------------------------------

type fakeSseDistributor struct {
	subscribeErr error
	publishErr   error

	mu        sync.Mutex
	published []StreamEvent
	fn        func(string, StreamEvent)
}

func (d *fakeSseDistributor) Publish(_ context.Context, _ string, ev StreamEvent) error {
	d.mu.Lock()
	d.published = append(d.published, ev)
	d.mu.Unlock()
	return d.publishErr
}

func (d *fakeSseDistributor) Subscribe(_ context.Context, fn func(string, StreamEvent)) error {
	if d.subscribeErr != nil {
		return d.subscribeErr
	}
	d.mu.Lock()
	d.fn = fn
	d.mu.Unlock()
	return nil
}

// echo is another instance's event arriving on the bus.
func (d *fakeSseDistributor) echo(topic string, ev StreamEvent) {
	d.mu.Lock()
	fn := d.fn
	d.mu.Unlock()
	fn(topic, ev)
}

func (d *fakeSseDistributor) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.published)
}

func TestSseDistributorReplacesLocalDelivery(t *testing.T) {
	// With a distributor the local connections are served only by the echo
	// (sse-manager.ts:190-197). Arranging the order is what proves it: if
	// Broadcast delivered locally as well, its frame would already be queued
	// when the echo is made, and it would arrive first.
	d := &fakeSseDistributor{}
	m := newTestSseManager(t, WithSseHeartbeat(0), WithSseDistributor(d))
	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"global"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}

	m.Broadcast(context.Background(), "global", StreamEvent{ID: "p", Type: "published"})
	if d.count() != 1 {
		t.Fatalf("the distributor received %d events, want 1", d.count())
	}
	d.echo("global", StreamEvent{ID: "e", Type: "echoed"})
	if got := sseEventType(t, rec.next(t)); got != "echoed" {
		t.Errorf("first frame after connecting is %q; a distributor-backed manager must not deliver its own broadcast locally", got)
	}
}

func TestSseDistributorFailureFallsBackToLocalDelivery(t *testing.T) {
	// sse-manager.ts:191-194.
	d := &fakeSseDistributor{publishErr: errors.New("bus down")}
	m := newTestSseManager(t, WithSseHeartbeat(0), WithSseDistributor(d))
	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"global"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}
	m.Broadcast(context.Background(), "global", StreamEvent{Type: "fallback"})
	if got := sseEventType(t, rec.next(t)); got != "fallback" {
		t.Errorf("frame is %q; a failed publish must still reach this instance's connections", got)
	}
}

func TestSseDistributorSubscribeFailureFailsConstruction(t *testing.T) {
	// The reference drops this error on the floor (sse-manager.ts:110-112) and
	// ends up with a manager that silently receives nothing from the fleet.
	want := errors.New("no bus")
	_, err := NewSseManager(context.Background(), WithSseDistributor(&fakeSseDistributor{subscribeErr: want}))
	if !errors.Is(err, want) {
		t.Fatalf("NewSseManager = %v, want it to wrap %v", err, want)
	}
}

// ---------------------------------------------------------------------------
// The bus seam
// ---------------------------------------------------------------------------

func TestSseBridgeEventBusDeliversAndCancels(t *testing.T) {
	m := newTestSseManager(t, WithSseHeartbeat(0))
	bus := NewEventBus()
	cancel := m.BridgeEventBus(context.Background(), bus, func(ev Event) []string {
		return []string{"user:" + ev.UserID}
	})

	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"user:u1"}, SseConnectionMeta{UserID: "u1"})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}

	bus.Publish(Event{Name: EventAuthLoginSuccess, UserID: "u1", Data: map[string]any{"k": "v"}})
	frame := rec.next(t)
	if got := sseEventType(t, frame); got != EventAuthLoginSuccess {
		t.Fatalf("frame is %q, want %q", got, EventAuthLoginSuccess)
	}
	if !strings.Contains(frame, `"rawData":{"k":"v"}`) {
		t.Errorf("the bus event's data should reach the frame under rawData: %q", frame)
	}

	cancel()
	cancel() // idempotent
	bus.Publish(Event{Name: EventAuthLoginSuccess, UserID: "u1"})
	// No pause: the probe is broadcast after the publish that must not arrive,
	// and delivery is synchronous, so an uncancelled bridge would have queued
	// its frame first.
	m.Broadcast(context.Background(), "user:u1", StreamEvent{Type: "probe"})
	if got := sseEventType(t, rec.next(t)); got != "probe" {
		t.Errorf("frame after cancelling the bridge is %q, want probe", got)
	}
}

func TestSseBridgeEventBusFansOutWithOneEventID(t *testing.T) {
	// One bus event, two topics the connection holds: the deduplication must
	// absorb the second, which only works if the id is generated once.
	m := newTestSseManager(t, WithSseHeartbeat(0))
	bus := NewEventBus()
	cancel := m.BridgeEventBus(context.Background(), bus, func(Event) []string {
		return []string{"a", "b"}
	})
	defer cancel()

	rec := newSseRecorder()
	serveSseStream(t, m, rec, []string{"a", "b"}, SseConnectionMeta{})
	if got := sseEventType(t, rec.next(t)); got != "connected" {
		t.Fatalf("first frame is %q", got)
	}
	bus.Publish(Event{Name: EventAuthLoginSuccess, UserID: "u1"})
	if got := sseEventType(t, rec.next(t)); got != EventAuthLoginSuccess {
		t.Fatalf("frame is %q", got)
	}
	m.Broadcast(context.Background(), "a", StreamEvent{Type: "probe"})
	if got := sseEventType(t, rec.next(t)); got != "probe" {
		t.Errorf("the fanned-out event was delivered twice; the frame after it is %q", got)
	}
}

func TestSseBridgeEventBusToleratesANilResolver(t *testing.T) {
	m := newTestSseManager(t, WithSseHeartbeat(0))
	bus := NewEventBus()
	cancel := m.BridgeEventBus(context.Background(), bus, nil)
	defer cancel()
	bus.Publish(Event{Name: EventAuthLoginSuccess, UserID: "u1"})
}
