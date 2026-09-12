package auth

import (
	"context"
	"encoding/json"
	"sync"
)

// This file is the runtime-settings seam: the reference's ISettingsStore
// (awesome-node-auth src/interfaces/settings-store.interface.ts:28-40), the
// global switches an administrator flips through the admin Control panel at run
// time rather than at deploy time, plus the in-memory implementation.
//
// Exactly one of those switches is consulted by this library, and by exactly one
// route: require2FA, which POST <prefix>/2fa/disable refuses on with 403
// 2FA_REQUIRED (auth.router.ts:890-896). It is the only one the reference reads
// on any route that decides a login either: no other route in
// src/router/auth.router.ts reads the store, and the strategy that decides a
// login reads the static AuthConfig and never the store
// (src/strategies/local/local.strategy.ts:32-35).
//
// The reference has two further readers, both outside the login path and neither
// ported yet: GET <prefix>/ui/config reads the ui block for branding
// (src/router/ui.router.ts:99 and :126-133, mounted by createAuthRouter itself
// when config.ui.enabled, auth.router.ts:1639-1648), and the tools router reads
// enabledWebhookActions for the inbound-webhook sandbox — swallowing a store
// failure rather than failing closed, which is the opposite of what this port
// does on /2fa/disable (src/router/tools.router.ts:261-262).
//
// So requireEmailVerification, emailVerificationMode and
// lazyEmailVerificationGracePeriodDays are stored and handed back and change
// nothing about who may log in. That is the reference's behaviour, not an
// oversight of this port (reference-issues N36), and it is reproduced rather
// than fixed because the admin UI writes those keys and the family clients read
// them back; a port that silently enforced them would refuse logins the
// reference allows. Config.EmailVerificationMode is the knob that does decide a
// login here, as config.emailVerificationMode is there. enabledWebhookActions is
// likewise stored for the inbound-webhook sandbox that arrives with the tools
// router, and ui for the UI config route; neither is read yet.
//
// No wire deviation is registered for any of this: every route this port serves
// answers exactly what the reference answers for the same stored settings. The
// one deviation on the route that reads them is about the other term —
// Config.Require2FA, which the reference has no equivalent of — and it is
// registered as config-require2fa-is-a-system-policy-term in compatibility.go.

// UISettings is the reference's AuthSettings.ui
// (settings-store.interface.ts:79-91): the branding the admin UI customization
// panel writes, which the UI config route will serve once it lands.
//
// The fields are pointers so that a patch can carry one of them without
// blanking the other seven, and omitempty so that a key nobody ever set is
// absent rather than null — the reference stores whatever object the admin
// router last merged (admin.router.ts:979-981) and JSON.stringify emits only the
// keys it holds. The reference types every field as required inside the optional
// ui object; in practice its own PATCH route writes partial objects, so required
// is the type rather than the data.
type UISettings struct {
	PrimaryColor   *string `json:"primaryColor,omitempty"`
	SecondaryColor *string `json:"secondaryColor,omitempty"`
	LogoURL        *string `json:"logoUrl,omitempty"`
	SiteName       *string `json:"siteName,omitempty"`
	LogoPath       *string `json:"logoPath,omitempty"`
	BgColor        *string `json:"bgColor,omitempty"`
	BgImage        *string `json:"bgImage,omitempty"`
	CardBg         *string `json:"cardBg,omitempty"`
}

// AuthSettings is the reference's AuthSettings
// (settings-store.interface.ts:45-92), in both roles it plays there: the whole
// stored value that GetSettings returns, and the Partial<AuthSettings> patch
// that UpdateSettings applies. Every field is optional in the reference, so
// every field here is a pointer or a slice, and a nil one means absent — which
// on the way in means keep what is stored, and on the way out means the store
// never held it.
//
// The JSON names are the reference's, so a stored document round-trips between
// this port and a node-auth deployment unchanged. Round-tripping the *cleared*
// state of enabledWebhookActions needs one correction that struct tags cannot
// express on their own: see MarshalJSON.
type AuthSettings struct {
	// RequireEmailVerification is the legacy boolean form of
	// EmailVerificationMode (settings-store.interface.ts:47). Stored only: see
	// the file comment, and Config.EmailVerificationMode for the knob that does
	// decide a login.
	RequireEmailVerification *bool `json:"requireEmailVerification,omitempty"`
	// EmailVerificationMode is none, lazy or strict
	// (settings-store.interface.ts:55), and overrides
	// RequireEmailVerification when both are set. Stored only.
	EmailVerificationMode *string `json:"emailVerificationMode,omitempty"`
	// LazyEmailVerificationGracePeriodDays is the lazy-mode grace period in days
	// (settings-store.interface.ts:62), 7 when unset. Stored only; the reference
	// admin UI displays it and nothing enforces it. Note the naming drift in the
	// reference itself: its admin OpenAPI calls the same key
	// emailVerificationGracePeriodDays (openapi.ts:1278). The interface name is
	// the one used here, because it is the one the admin UI writes.
	LazyEmailVerificationGracePeriodDays *int `json:"lazyEmailVerificationGracePeriodDays,omitempty"`
	// Require2FA is the one setting this library acts on: when true,
	// POST <prefix>/2fa/disable answers 403 2FA_REQUIRED
	// (auth.router.ts:890-896). Auth.TwoFactorPolicy is where it is read.
	Require2FA *bool `json:"require2FA,omitempty"`
	// EnabledWebhookActions is the global allowlist of inbound-webhook action
	// ids (settings-store.interface.ts:74), the circuit breaker above each
	// webhook own allowedActions list. It is read by
	// POST <tools>/webhook/{provider}, which intersects it with the webhook's
	// own AllowedActions to decide what an inbound script may call — so an empty
	// list, or no settings store at all, means no script can call anything.
	//
	// nil and empty are different values here, as they are everywhere else in
	// this type: nil is absent and keeps what is stored, an empty non-nil slice
	// is the administrator switching every action off. MarshalJSON is what keeps
	// that difference alive through an encoder.
	EnabledWebhookActions []string `json:"enabledWebhookActions,omitempty"`
	// UI is the branding block. It is one field of the patch, so a patch that
	// carries it replaces the stored block whole rather than merging into it:
	// see MergeSettings.
	UI *UISettings `json:"ui,omitempty"`
}

// wireSettings is the shape AuthSettings is actually encoded as. It differs in
// one field and in nothing else: EnabledWebhookActions is a *[]string, where
// omitempty drops a nil pointer and keeps a pointer to an empty slice.
//
// Field order is the encoded key order, so it is AuthSettings' order and the
// reference's.
type wireSettings struct {
	RequireEmailVerification             *bool       `json:"requireEmailVerification,omitempty"`
	EmailVerificationMode                *string     `json:"emailVerificationMode,omitempty"`
	LazyEmailVerificationGracePeriodDays *int        `json:"lazyEmailVerificationGracePeriodDays,omitempty"`
	Require2FA                           *bool       `json:"require2FA,omitempty"`
	EnabledWebhookActions                *[]string   `json:"enabledWebhookActions,omitempty"`
	UI                                   *UISettings `json:"ui,omitempty"`
}

// MarshalJSON encodes the settings under the reference's names, with one
// correction encoding/json cannot make from a struct tag.
//
// omitempty on a []string drops an empty slice as well as a nil one, so a plain
// tag would encode AuthSettings{EnabledWebhookActions: []string{}} as {} — and
// the cleared list, which is how an administrator switches every inbound-webhook
// action off, would come back from a store that persists JSON as absent, which
// MergeSettings reads as keep. The list would quietly come back on. The
// reference has no such hole: JSON.stringify({enabledWebhookActions: []}) emits
// [].
//
// So the field is encoded through a pointer, where omitempty means nil and
// nothing else: nil stays absent, and a non-nil empty slice is written as [].
// Decoding needs no counterpart, because encoding/json already decodes [] into a
// non-nil empty slice.
func (s AuthSettings) MarshalJSON() ([]byte, error) {
	wire := wireSettings{
		RequireEmailVerification:             s.RequireEmailVerification,
		EmailVerificationMode:                s.EmailVerificationMode,
		LazyEmailVerificationGracePeriodDays: s.LazyEmailVerificationGracePeriodDays,
		Require2FA:                           s.Require2FA,
		UI:                                   s.UI,
	}
	if s.EnabledWebhookActions != nil {
		actions := s.EnabledWebhookActions
		wire.EnabledWebhookActions = &actions
	}
	return json.Marshal(wire)
}

// SettingsStore keeps the global runtime settings
// (settings-store.interface.ts:28-40). It is optional: without one nothing
// changes, exactly as in the reference, where the settings check on
// /2fa/disable is skipped altogether when no store is configured
// (auth.router.ts:890).
//
// GetSettings returns the zero AuthSettings when nothing has been configured —
// the reference empty object (:31-32) — and reserves the error for the store
// itself failing. A failing GetSettings fails the route it was called from
// closed, with the reference generic 500: see Auth.TwoFactorPolicy.
//
// UpdateSettings applies patch as a shallow merge over what is stored: a field
// the patch does not carry is left untouched (:36-38), a field it does carry
// replaces the stored one outright. MergeSettings is that rule, and every
// implementation has to apply it. The reference method returns void and leaves
// the caller to read the result back; this one returns what is stored
// afterwards, as TemplateStore does.
//
// A store is wired once with WithSettingsStore (Config.Settings).
type SettingsStore interface {
	GetSettings(ctx context.Context) (AuthSettings, error)
	UpdateSettings(ctx context.Context, patch AuthSettings) (AuthSettings, error)
}

// MergeSettings applies patch over current and returns the result, the shallow
// spread the reference's ISettingsStore.updateSettings contract requires:
// merged = {...current, ...settings} (settings-store.interface.ts:20-24 is the
// JSDoc example, :36-38 the interface comment, "Settings not present in the
// input are left untouched").
//
// The contract is all the reference's src/ carries: it ships no ISettingsStore
// implementation there (src/stores/ holds only memory-template.store.ts). The
// implementations live beside it and all spread the same way — the closest to
// this one is examples/in-memory-user-store.ts:266-268,
// this.settings = { ...this.settings, ...updates }.
//
// Shallow is the operative word, and the one place it bites is UI. A patch whose
// UI is nil keeps the stored branding; a patch that carries a UI replaces the
// stored branding whole, so the seven fields it does not name are dropped, not
// preserved. That is what the spread does, and the reference depends on it: its
// admin PATCH route reads the current settings, merges the UI sub-object itself
// and sends the merged block back down (admin.router.ts:979-981), which it would
// have no reason to do if the store merged it. A caller that wants to change one
// colour does the same — read, merge, write.
//
// EnabledWebhookActions follows the same rule as a whole value: nil keeps, and
// a non-nil slice replaces, an empty one included. Everything the result points
// at is freshly allocated, so neither input can be mutated through it.
func MergeSettings(current, patch AuthSettings) AuthSettings {
	merged := copySettings(current)
	if patch.RequireEmailVerification != nil {
		merged.RequireEmailVerification = copyBool(patch.RequireEmailVerification)
	}
	if patch.EmailVerificationMode != nil {
		merged.EmailVerificationMode = copyString(patch.EmailVerificationMode)
	}
	if patch.LazyEmailVerificationGracePeriodDays != nil {
		merged.LazyEmailVerificationGracePeriodDays = copyInt(patch.LazyEmailVerificationGracePeriodDays)
	}
	if patch.Require2FA != nil {
		merged.Require2FA = copyBool(patch.Require2FA)
	}
	if patch.EnabledWebhookActions != nil {
		merged.EnabledWebhookActions = copySlice(patch.EnabledWebhookActions)
	}
	if patch.UI != nil {
		merged.UI = copyUISettings(patch.UI)
	}
	return merged
}

// MemorySettingsStore is the in-memory SettingsStore, safe for concurrent use.
// Everything handed out is a copy, so mutating a returned AuthSettings — or the
// UISettings behind it — does not reach the store.
type MemorySettingsStore struct {
	mu       sync.RWMutex
	settings AuthSettings
}

// NewMemorySettingsStore returns a MemorySettingsStore holding nothing, so that
// GetSettings answers the zero AuthSettings until something is written.
func NewMemorySettingsStore() *MemorySettingsStore {
	return &MemorySettingsStore{}
}

// GetSettings returns a copy of the stored settings.
func (s *MemorySettingsStore) GetSettings(_ context.Context) (AuthSettings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copySettings(s.settings), nil
}

// UpdateSettings applies patch with MergeSettings and returns a copy of what is
// stored afterwards.
func (s *MemorySettingsStore) UpdateSettings(_ context.Context, patch AuthSettings) (AuthSettings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings = MergeSettings(s.settings, patch)
	return copySettings(s.settings), nil
}

// copySettings deep-copies every pointer and slice an AuthSettings holds, so
// that the value crossing the store boundary shares nothing with the one behind
// it.
func copySettings(in AuthSettings) AuthSettings {
	return AuthSettings{
		RequireEmailVerification:             copyBool(in.RequireEmailVerification),
		EmailVerificationMode:                copyString(in.EmailVerificationMode),
		LazyEmailVerificationGracePeriodDays: copyInt(in.LazyEmailVerificationGracePeriodDays),
		Require2FA:                           copyBool(in.Require2FA),
		EnabledWebhookActions:                copySlice(in.EnabledWebhookActions),
		UI:                                   copyUISettings(in.UI),
	}
}

func copyUISettings(in *UISettings) *UISettings {
	if in == nil {
		return nil
	}
	return &UISettings{
		PrimaryColor:   copyString(in.PrimaryColor),
		SecondaryColor: copyString(in.SecondaryColor),
		LogoURL:        copyString(in.LogoURL),
		SiteName:       copyString(in.SiteName),
		LogoPath:       copyString(in.LogoPath),
		BgColor:        copyString(in.BgColor),
		BgImage:        copyString(in.BgImage),
		CardBg:         copyString(in.CardBg),
	}
}

func copyBool(in *bool) *bool {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func copyString(in *string) *string {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func copyInt(in *int) *int {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

// copySlice copies a string slice, preserving the nil/empty distinction that
// MergeSettings turns on.
func copySlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
