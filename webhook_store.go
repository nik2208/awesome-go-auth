package auth

import (
	"context"
	"sync"
	"time"
)

// This file is the webhook store seam: the reference's WebhookConfig,
// OutgoingWebhookEvent and IWebhookStore
// (awesome-node-auth src/interfaces/webhook-store.interface.ts:4-150), plus an
// in-memory implementation.
//
// It landed in v0.8.0 as the seam alone, with nothing in the package reading a
// WebhookStore. Two of the three readers it was waiting for have since arrived,
// and one has not:
//
//   - The sender is here. webhook_sender.go is the port of the reference's
//     WebhookSender, and WebhookEmitter is what turns FindByEvent's result into
//     deliveries. The duplication this file used to describe — an events list
//     matched twice, a secret twice, an id prefixed whk_ twice — is gone with
//     WebhookDispatcher, which carried its own envelope and its own
//     X-Signature-SHA256 header and was removed in v0.11.0 as a deliberate
//     BREAKING change. There is one wire now and it is the reference's.
//
//   - The inbound route is here. POST <tools>/webhook/{provider} is what calls
//     FindByProvider (tools.router.ts:250-259), and tools_webhook.go is what it
//     does with the answer. The admin Webhooks screens, which are what call
//     ListWebhooks, AddWebhook, UpdateWebhook and RemoveWebhook
//     (admin.router.ts:1362-1440), are U14 (M8).
//
//   - No script runs *here*. The inbound route reads JSScript and hands it to
//     an InboundScriptRunner, which executes it out of process; nothing in this
//     package interprets it. See WebhookConfig's inbound-webhook fields.
//
// The one behaviour worth stating up front, because it decides how strict a
// store has to be: the reference's caller adds no filtering of its own. The
// emit path calls findByEvent and hands every returned config straight to
// WebhookSender.send (auth-tools.ts:250-267), and the sender POSTs whatever it
// is handed — it re-checks neither isActive nor events
// (webhook-sender.ts:17-46). The store is the only filter in the chain, and a
// store that over-returns delivers. The same caller swallows a store failure
// with .catch(() => []) (auth-tools.ts:251), so a FindByEvent error means "no
// webhooks for this event", never a failed emit.

// WebhookEventWildcard is the events entry that subscribes a configuration to
// every event (webhook-store.interface.ts:11). It is the only pattern the
// reference understands: matching is literal otherwise, so "identity.auth.*"
// is an event name nothing emits rather than a prefix subscription — the
// example query matches with whereJsonContains (:106).
const WebhookEventWildcard = "*"

// The defaults the reference documents on WebhookConfig and resolves in the
// sender rather than in the store (webhook-sender.ts:18-19,
// webhook-store.interface.ts:27, :32). They are exported because
// WebhookSender applies exactly these numbers and a host reproducing its retry
// policy on the far side of a WebhookDeliverer needs the same two, and because
// a store round-tripping a config has to be able to tell an unset field from a
// field set to the same value.
const (
	DefaultWebhookMaxRetries = 3
	DefaultWebhookRetryDelay = time.Second
)

// OutgoingWebhookVersion is the default OutgoingWebhookEvent.Version, the
// reference's AuthToolsOptions.webhookVersion ?? "1" (auth-tools.ts:175).
const OutgoingWebhookVersion = "1"

// WebhookConfig is one webhook subscription as a store holds it
// (webhook-store.interface.ts:4-73). The JSON tags are the reference's key
// names, so a stored document round-trips between this port and a node-auth
// deployment unchanged.
//
// IsActive, MaxRetries and RetryDelayMs are pointers for the same reason every
// optional field of AuthSettings is (settings_store.go): nil means the key is
// absent, and absent is not the zero value. IsActive defaults to true, so a nil
// decoded as false would silence a webhook; MaxRetries and RetryDelayMs are
// resolved with ?? in the sender, which keeps 0 as 0 — maxRetries: 0 is
// "deliver once, never retry" and must not decay into "retry three times".
// Active, Retries and RetryDelay are those resolutions, in one place.
//
// Secret, TenantID, Provider and JSScript stay plain strings: the reference
// tests each of them for truthiness, so "" and absent are the same value there
// and nothing is lost by collapsing them here.
type WebhookConfig struct {
	// ID is assigned by the store, not by the caller: the reference's add takes
	// an Omit<WebhookConfig, "id"> (:129). See WebhookAdminStore.AddWebhook.
	ID string `json:"id"`
	// URL is the endpoint events are POSTed to (:8). The store does not
	// validate it; the admin route refuses an empty one before it ever reaches
	// add (admin.router.ts:1397), and that check is U14's.
	URL string `json:"url"`
	// Events are the event names this configuration subscribes to (:14), or the
	// single entry WebhookEventWildcard for all of them.
	//
	// An empty or nil Events matches nothing, and that is the reference's rule
	// rather than a convenience: its matching is a positive containment test,
	// so a row with no events is subscribed to none (:106). The removed
	// WebhookDispatcher read an empty list the other way round, as every event,
	// which is one more reason it could not simply be pointed at a store. The
	// reference's admin route defaults a create with no events to ["*"]
	// (admin.router.ts:1403), which is where that convenience lives there.
	Events []string `json:"events"`
	// Secret is the HMAC-SHA256 signing key (:16); empty means the delivery is
	// unsigned. It is held in the clear, because the signature has to be
	// reproducible and the reference holds it in the clear too — the admin
	// listing is what masks it to "***" (admin.router.ts:1381), not the store.
	Secret string `json:"secret,omitempty"`
	// IsActive gates delivery (:18) and defaults to true when nil — see Active,
	// which is the only place that default is applied.
	IsActive *bool `json:"isActive,omitempty"`
	// TenantID scopes the configuration to one tenant (:23); empty is a global
	// webhook, which fires for every tenant. See WebhookStore.FindByEvent.
	TenantID string `json:"tenantId,omitempty"`
	// MaxRetries and RetryDelayMs are the delivery retry policy (:28, :33),
	// resolved and acted on by WebhookSender.Send. Retries() and RetryDelay()
	// below are how to read them: never dereference these pointers directly,
	// because nil is the reference's default and a stored 0 is not.
	MaxRetries   *int `json:"maxRetries,omitempty"`
	RetryDelayMs *int `json:"retryDelayMs,omitempty"`

	// Provider, AllowedActions and JSScript are the inbound half of the
	// reference's WebhookConfig (:35-72). In the reference they are executed:
	// POST /tools/webhook/:provider looks the config up by Provider, intersects
	// AllowedActions with AuthSettings.EnabledWebhookActions, and runs JSScript
	// in a node vm sandbox with the request body and the surviving actions in
	// scope (tools.router.ts:250-300).
	//
	// Here they are data, and they will stay data. This package's dependency
	// rule is stdlib plus golang.org/x/crypto, and a JavaScript engine is not
	// going to be the exception: an in-process interpreter would put
	// administrator-authored script in the same address space as the signing
	// keys and the password hashes, with a sandbox as the only boundary. The
	// decision taken on 2026-09-12 is that the core exposes an
	// InboundScriptRunner seam and the product implements it out of process,
	// where an IAM role is the real sandbox.
	//
	// That seam landed with the route. Provider selects the configuration,
	// AllowedActions is intersected with AuthSettings.EnabledWebhookActions to
	// produce the allowlist that crosses, and JSScript is handed over verbatim
	// — read, never interpreted, by anything in this package. A store must
	// round-trip all three unchanged and must never interpret them either.
	Provider       string   `json:"provider,omitempty"`
	AllowedActions []string `json:"allowedActions,omitempty"`
	JSScript       string   `json:"jsScript,omitempty"`
}

// Active is IsActive with the reference's default applied: a configuration that
// never set the field is active (webhook-store.interface.ts:17).
//
// The reference's own example store reads the rule the other way — its query is
// .where("isActive", true) (:104), which in SQL excludes a NULL row — but the
// prose is what a store implementor is told, and the admin route writes the
// field explicitly on every create (isActive ?? true, admin.router.ts:1404), so
// a nil in real data is a hand-written row rather than anything the reference
// produces. The prose wins.
func (c WebhookConfig) Active() bool {
	if c.IsActive == nil {
		return true
	}
	return *c.IsActive
}

// Retries is MaxRetries with the reference's default of 3 applied
// (webhook-sender.ts:18). A stored 0 is returned as 0.
func (c WebhookConfig) Retries() int {
	if c.MaxRetries == nil {
		return DefaultWebhookMaxRetries
	}
	return *c.MaxRetries
}

// RetryDelay is RetryDelayMs with the reference's default of 1000 ms applied
// (webhook-sender.ts:19), as a Duration. A stored 0 is returned as 0.
func (c WebhookConfig) RetryDelay() time.Duration {
	if c.RetryDelayMs == nil {
		return DefaultWebhookRetryDelay
	}
	return time.Duration(*c.RetryDelayMs) * time.Millisecond
}

// Matches reports whether c should receive event on behalf of tenantID: the
// three rules WebhookStore.FindByEvent is defined by, in one place.
//
// It is exported for the stores that cannot express all three in a query. A
// DynamoDB implementation that fetches a tenant partition and filters in memory
// should finish with this rather than re-derive the rules, so that the
// wildcard, the empty-events case and the global-webhook case cannot drift per
// backend.
func (c WebhookConfig) Matches(event, tenantID string) bool {
	if !c.Active() {
		return false
	}
	if c.TenantID != "" && c.TenantID != tenantID {
		return false
	}
	for _, subscribed := range c.Events {
		if subscribed == WebhookEventWildcard || subscribed == event {
			return true
		}
	}
	return false
}

// OutgoingWebhookEvent is the JSON body POSTed to a webhook endpoint
// (webhook-store.interface.ts:75-89). Event.OutgoingWebhook builds it and
// WebhookSender.Send serialises it; the bytes it produces are what the
// X-Webhook-Signature header signs.
//
// Timestamp is a string, not a time.Time, because the reference's is a string
// (:84) and the two do not encode alike: JavaScript's toISOString() emits
// exactly three fractional digits and a Z, where time.Time's RFC 3339 encoding
// emits as many digits as the value has — none for a whole second, nine for a
// monotonic-clock reading — and a receiver that signature-checks the raw body
// sees a different string for the same instant. Keeping it a string forces the
// producer to choose the format deliberately.
type OutgoingWebhookEvent struct {
	Event string `json:"event"`
	// Version is the event schema version, OutgoingWebhookVersion unless the
	// host overrides it (auth-tools.ts:175).
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
	// Data is the event payload, and the key is always present: the reference
	// writes data ?? null, so an event with nothing to say sends null rather
	// than omitting the field (auth-tools.ts:256). No omitempty, for that
	// reason.
	Data any `json:"data"`
	// Metadata carries userId, tenantId, sessionId and correlationId
	// (auth-tools.ts:257-262). The reference always builds the object and lets
	// JSON.stringify drop the undefined members, so the key is present whenever
	// any one of the four is known and the absent ones simply are not there —
	// which is what omitempty over a map reproduces.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// WebhookStore holds outgoing webhook subscriptions: the reference's
// IWebhookStore (webhook-store.interface.ts:111-150). It is optional in the
// sense the reference's is — without one, outgoing webhooks are off.
//
// Only FindByEvent is required, because only FindByEvent is on a hot path. The
// reference's five other methods are optional (`?`), and optional here means
// what it means everywhere else in this package: a narrow interface the caller
// type-asserts the configured store to, answering ErrFeatureNotSupported when
// the assertion fails, as Service.ListSessions does with SessionAdminStore.
// They are WebhookAdminStore and InboundWebhookStore below.
type WebhookStore interface {
	// FindByEvent returns every configuration that should receive event on
	// behalf of tenantID (webhook-store.interface.ts:112-117).
	//
	// Three rules, all of them the reference's, all of them in
	// WebhookConfig.Matches:
	//
	//   - Active only. A configuration whose IsActive is false is not returned.
	//     Nothing downstream re-checks it — the sender delivers to whatever it
	//     is handed — so this filter existing in the store is the whole of the
	//     feature.
	//   - Tenant scope. A non-empty tenantID returns both the configurations
	//     scoped to it and the global ones, which is what the interface says
	//     (:114-115). An empty tenantID returns the global ones only, which is
	//     what the interface's example query does: tenantId ?? null makes the
	//     first branch unsatisfiable and leaves orWhereNull (:105).
	//   - Event match. An Events entry equal to the event name, or to
	//     WebhookEventWildcard, subscribes; nothing else does. An empty Events
	//     matches nothing.
	//
	// Order is part of the contract. The normative order is the one
	// MemoryWebhookStore guarantees — the order the configurations were added —
	// and a store that cannot reproduce it states its own, here and in the
	// deviation register if it is a published one. The order is not observable
	// on the wire, because WebhookEmitter starts a goroutine per configuration
	// and nothing sequences them; it is observable in ListWebhooks' pagination
	// (U14) and in the order the deliveries are started in, which a host's
	// queueing WebhookDeliverer may well preserve.
	//
	// An error means the store failed, and the caller is expected to treat it
	// as an empty result rather than as a failed emit — the reference's
	// .catch(() => []) (auth-tools.ts:251). Returning an error is therefore
	// never a way to refuse an event; return an empty slice for that.
	FindByEvent(ctx context.Context, event, tenantID string) ([]WebhookConfig, error)
}

// WebhookAdminStore is the management half of the reference's IWebhookStore —
// listAll?, add?, remove? and update? (webhook-store.interface.ts:119-141) — as
// one optional capability. A store that does not implement it can still serve
// events; only the admin Webhooks screens need it, and those are U14 (M8).
//
// The four are separately optional in the reference, which guards each call
// site and answers its own 501 per method ("IWebhookStore.listAll is not
// implemented", admin.router.ts:1368-1371, and the three that follow). They are
// bundled here because they exist for one screen over one store, the way
// SessionAdminStore bundles the reference's equally-separate getAllSessions?
// and deleteExpiredSessions? (session-store.interface.ts:91, :100), and because
// bundling costs nothing on the wire: a store that can list but not write
// implements all four and returns ErrFeatureNotSupported from the writers,
// which HTTPErrorFor already maps to the same 501 as a failed type assertion
// (wire.go:187). U14 reaches the reference's per-method answer either way.
type WebhookAdminStore interface {
	// ListWebhooks returns one page of every configuration the store holds,
	// active or not, in the store's documented order (:119-123).
	//
	// offset is zero-based. A limit of zero or less returns no rows, as LIMIT 0
	// does; an offset past the end returns an empty slice, not an error. The
	// reference clamps limit to 100 and defaults it to 20 in the route rather
	// than in the store (admin.router.ts:1366-1367), so the store honours what
	// it is given.
	ListWebhooks(ctx context.Context, limit, offset int) ([]WebhookConfig, error)
	// AddWebhook stores a new configuration and returns it with the ID the
	// store assigned (:125-129).
	//
	// The reference's add takes an Omit<WebhookConfig, "id">, which Go has no
	// spelling for; the shape this package already uses for the same thing is
	// CreateTenant and CreateUser in store.go — take the value, return what was
	// stored — so that is the shape here. The difference from those two is that
	// the store owns the identifier: config.ID is ignored, and reading the
	// assigned one off the returned value is the only way to get it.
	//
	// The configuration is stored as given otherwise. No field is defaulted on
	// the way in: Active, Retries and RetryDelay resolve nil at the point of
	// use, and the reference's own defaulting of events to ["*"] and isActive
	// to true happens in the admin route (admin.router.ts:1403-1404), which is
	// U14's to reproduce.
	AddWebhook(ctx context.Context, config WebhookConfig) (WebhookConfig, error)
	// UpdateWebhook applies a partial update (:137-141). An id the store does
	// not hold is not an error — see WebhookPatch.
	UpdateWebhook(ctx context.Context, id string, patch WebhookPatch) error
	// RemoveWebhook permanently deletes a configuration (:131-135). An id the
	// store does not hold is not an error: the reference's remove returns void
	// and its route answers {"success": true} without asking whether anything
	// was deleted (admin.router.ts:1429-1440), so a second DELETE of the same
	// id succeeds.
	RemoveWebhook(ctx context.Context, id string) error
}

// InboundWebhookStore is the reference's findByProvider?
// (webhook-store.interface.ts:143-149): the lookup POST
// /tools/webhook/:provider does to find the script it should run. It is its own
// capability rather than a method of WebhookAdminStore because it answers a
// different question for a different caller, and because a deployment that
// never accepts inbound webhooks should be able to say so by not implementing
// it.
//
// The tools router calls it from POST <tools>/webhook/{provider}, and what it
// does with the result — running JSScript — it does through
// InboundScriptRunner, out of process. See tools_webhook.go.
type InboundWebhookStore interface {
	// FindByProvider returns the inbound configuration registered for provider,
	// and false when there is none — the reference's WebhookConfig | null, in
	// the (value, ok, error) shape TemplateStore already uses for the same
	// thing.
	//
	// Note what it does not filter on: IsActive. FindByEvent's contract is
	// "active configurations only" and this one's is not, because the only
	// caller tests the result for a jsScript and nothing else
	// (tools.router.ts:257-259). Deactivating a webhook stops outgoing
	// deliveries; it does not stop an inbound script from running. That is the
	// reference's behaviour and it is reproduced rather than corrected, but it
	// is a trap worth knowing before M9 wires the route, and a store must not
	// quietly fix it by filtering here.
	FindByProvider(ctx context.Context, provider string) (WebhookConfig, bool, error)
}

// WebhookPatch is what WebhookAdminStore.UpdateWebhook applies: the reference's
// Partial<Omit<WebhookConfig, "id">> (webhook-store.interface.ts:141), where a
// field that is present replaces the stored one and a field that is absent
// leaves it alone. It is MailTemplatePatch's shape, for MailTemplatePatch's
// reasons (template_store.go).
//
// A nil pointer leaves the stored field alone; a pointer to a zero value sets
// it to that zero — *IsActive = false is how the admin UI's toggle turns a
// webhook off, and it has to be distinguishable from "not in this patch". The
// two slices follow MailTemplatePatch.Translations: nil leaves the stored slice
// alone, and a non-nil one replaces it whole rather than appending to it, so a
// caller changing one event sends the list back complete. A non-nil empty slice
// clears.
//
// What a patch cannot do is put an optional field back to absent: nil is
// already spent on "leave alone". Neither can the reference's, without sending
// an explicit null through a spread, and no route of its own does. A store that
// needs to clear MaxRetries reads the config, removes it and adds it back.
type WebhookPatch struct {
	URL            *string
	Events         []string
	Secret         *string
	IsActive       *bool
	TenantID       *string
	MaxRetries     *int
	RetryDelayMs   *int
	Provider       *string
	AllowedActions []string
	JSScript       *string
}

// applyTo returns config with the patch applied. It works on a copy, so the
// caller decides what to do with the result.
func (p WebhookPatch) applyTo(config WebhookConfig) WebhookConfig {
	if p.URL != nil {
		config.URL = *p.URL
	}
	if p.Events != nil {
		config.Events = copySlice(p.Events)
	}
	if p.Secret != nil {
		config.Secret = *p.Secret
	}
	if p.IsActive != nil {
		config.IsActive = copyBool(p.IsActive)
	}
	if p.TenantID != nil {
		config.TenantID = *p.TenantID
	}
	if p.MaxRetries != nil {
		config.MaxRetries = copyInt(p.MaxRetries)
	}
	if p.RetryDelayMs != nil {
		config.RetryDelayMs = copyInt(p.RetryDelayMs)
	}
	if p.Provider != nil {
		config.Provider = *p.Provider
	}
	if p.AllowedActions != nil {
		config.AllowedActions = copySlice(p.AllowedActions)
	}
	if p.JSScript != nil {
		config.JSScript = *p.JSScript
	}
	return config
}

// MemoryWebhookStore is the in-memory WebhookStore, and implements
// WebhookAdminStore and InboundWebhookStore as well. It is safe for concurrent
// use, and everything it hands out is a deep copy: mutating a returned
// configuration, its Events slice or its IsActive pointer does not reach the
// store.
//
// The reference ships no in-memory webhook store to port — src/stores holds
// only memory-template.store.ts — so the ordering below is this port's to
// choose, and having chosen it, this package is where it is normative.
//
// The order is first-insertion, everywhere: FindByEvent, ListWebhooks and
// FindByProvider all walk the configurations in the order AddWebhook saw them.
// Updating one does not move it; removing one closes the gap, and re-adding it
// puts it at the end. This is MemoryTemplateStore's rule (template_store.go)
// and the Map iteration order of the one store the reference does ship, it is
// the only order that makes ListWebhooks' limit/offset pagination stable across
// calls, and unlike sorting by ID it stays meaningful with ids that are random
// (newID).
type MemoryWebhookStore struct {
	mu    sync.RWMutex
	byID  map[string]WebhookConfig
	order []string
}

// NewMemoryWebhookStore returns an empty MemoryWebhookStore.
func NewMemoryWebhookStore() *MemoryWebhookStore {
	return &MemoryWebhookStore{byID: make(map[string]WebhookConfig)}
}

// FindByEvent applies WebhookConfig.Matches to every stored configuration, in
// insertion order.
func (s *MemoryWebhookStore) FindByEvent(_ context.Context, event, tenantID string) ([]WebhookConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]WebhookConfig, 0, len(s.order))
	for _, id := range s.order {
		config := s.byID[id]
		if config.Matches(event, tenantID) {
			out = append(out, copyWebhookConfig(config))
		}
	}
	return out, nil
}

// ListWebhooks returns one page of every stored configuration, active or not,
// in insertion order.
func (s *MemoryWebhookStore) ListWebhooks(_ context.Context, limit, offset int) ([]WebhookConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || offset >= len(s.order) {
		return []WebhookConfig{}, nil
	}
	if offset < 0 {
		offset = 0
	}
	end := offset + limit
	if end > len(s.order) {
		end = len(s.order)
	}
	page := s.order[offset:end]
	out := make([]WebhookConfig, 0, len(page))
	for _, id := range page {
		out = append(out, copyWebhookConfig(s.byID[id]))
	}
	return out, nil
}

// AddWebhook assigns an id and appends the configuration to the insertion
// order. The ID of the argument is ignored.
func (s *MemoryWebhookStore) AddWebhook(_ context.Context, config WebhookConfig) (WebhookConfig, error) {
	id, err := newID("whk")
	if err != nil {
		return WebhookConfig{}, err
	}
	stored := copyWebhookConfig(config)
	stored.ID = id
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = stored
	s.order = append(s.order, id)
	return copyWebhookConfig(stored), nil
}

// UpdateWebhook applies the patch in place, keeping the configuration where it
// is in the insertion order. An unknown id is a no-op and not an error.
func (s *MemoryWebhookStore) UpdateWebhook(_ context.Context, id string, patch WebhookPatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byID[id]
	if !ok {
		return nil
	}
	updated := patch.applyTo(current)
	updated.ID = id
	s.byID[id] = updated
	return nil
}

// RemoveWebhook deletes the configuration and closes the gap it leaves in the
// insertion order. An unknown id is a no-op and not an error.
func (s *MemoryWebhookStore) RemoveWebhook(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return nil
	}
	delete(s.byID, id)
	for i, stored := range s.order {
		if stored == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}

// FindByProvider returns the first configuration registered for provider in
// insertion order, active or not. An empty provider never matches: every
// outgoing-only configuration leaves the field unset
// (webhook-store.interface.ts:41), so matching on "" would hand the router one
// of those.
func (s *MemoryWebhookStore) FindByProvider(_ context.Context, provider string) (WebhookConfig, bool, error) {
	if provider == "" {
		return WebhookConfig{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, id := range s.order {
		if config := s.byID[id]; config.Provider == provider {
			return copyWebhookConfig(config), true, nil
		}
	}
	return WebhookConfig{}, false, nil
}

// copyWebhookConfig deep-copies the two slices and three pointers a
// WebhookConfig owns, preserving the nil/empty distinction on every one of them
// — nil is "absent" in this type, and an empty slice is not.
func copyWebhookConfig(config WebhookConfig) WebhookConfig {
	config.Events = copySlice(config.Events)
	config.AllowedActions = copySlice(config.AllowedActions)
	config.IsActive = copyBool(config.IsActive)
	config.MaxRetries = copyInt(config.MaxRetries)
	config.RetryDelayMs = copyInt(config.RetryDelayMs)
	return config
}
