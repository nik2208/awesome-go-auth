package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// The credential half of the admin API: the eight routes of admin.router.ts
// that hold, mint or mask a secret (:1250-1440).
//
// M8 is split by class of risk rather than by route count, and the invariant
// this file carries is **secret redaction**. These eight are the only routes on
// the admin surface that touch key material, and they were separated from both
// the reads U13 ported and the ordinary writes U14 ported so that the masking
// rules and the writes that set the masked values are reviewed together:
// reviewing a mask apart from the write that fills the field it hides is how a
// mask gets missed.
//
// # The three secrets, and where each of them stops
//
//   - The bcrypt hash of an API key (APIKeyRecord.KeyHash). It exists on every
//     row the listing walks and it reaches the wire on none of them, because
//     the projection is a type that does not carry the field at all — see
//     adminAPIKeyRow. The reference hand-picks the same ten keys out of an
//     object that does carry keyHash (:1266-1277), which is the weaker form of
//     the same rule: there, one added key in the literal is a leak; here there
//     is no field to add.
//   - The raw API key. It exists exactly once, inside POST /api/api-keys,
//     between APIKeyService.Create minting it and the response being written.
//     Nothing stores it, nothing logs it, and no later route can produce it —
//     the store holds its bcrypt hash, and the listing holds neither the key nor
//     the hash. An operator who loses the value mints another and revokes this
//     one.
//   - A webhook's signing secret. Unlike the other two it is held in the clear,
//     because an HMAC has to be reproducible (see WebhookConfig.Secret), so the
//     two routes that echo a configuration mask it to "***" (:1381, :1406)
//     rather than omit it: the console shows *that* a webhook is signed without
//     showing what with. PATCH neither echoes it nor needs it, and a PATCH that
//     does not name it leaves the stored one alone.
//
// Rule 8 of this codebase — never let a secret reach a log — is the background
// everywhere else and the subject here. Nothing in this file writes to
// Config.Logger, and no error path carries a body: every failure below is the
// flat `Internal server error` the reference answers with, which is also the
// one shape that cannot accidentally quote what it was handed.
//
// # What these eight share with their neighbours
//
//   - All eight are mounted with AdminGuard.Protect, never ProtectShell. A
//     credential route reached through the reference's Accept: text/html marker
//     branch would hand an anonymous browser the key table and let it mint a
//     key; see the admin-unauthenticated-get-serves-only-the-login-form
//     deviation.
//   - Errors are {"error": "…"} — writeAdminError — and not the auth router's
//     HTTPError envelope.
//   - A body that will not decode leaves the zero value in every field and
//     falls into whichever validation branch that reaches, as it does on every
//     write in admin_write.go.
//   - None reads AdminUserFromContext: the principal is unavailable under
//     AdminPolicyOpen and under the legacy secret, and no handler in the
//     reference's admin router consults req.user. So a minted key records no
//     minter, on both sides.
//
// # Two absences, two statuses
//
// Every one of the eight answers 404 when no store is configured — "API key
// store not configured" (:1254), "Webhook store not configured" (:1364) — and
// 501 naming a single optional method when a store is configured but cannot do
// the thing. That split is the reason v0.8.0 spelled the optional API-key
// methods one to an interface: a type assertion tells the two apart, and a
// combined interface would fail for a store that has ListByServiceID and not
// ListAll and then answer 501 naming a method that is present. See
// APIKeyAdminStore and APIKeyDeleteStore.

// The credential routes, relative to the admin mount. Six of the eight are a
// parameter below one of these two.
const (
	AdminAPIKeysPath  = "/api/api-keys" // admin.router.ts:1253
	AdminWebhooksPath = "/api/webhooks" // admin.router.ts:1363
)

// adminWebhookMask is what the two echoing webhook routes write in place of a
// secret (:1381, :1406). It is a constant rather than a literal in two places
// because the listing and the create route have to agree: a console that showed
// "***" on one screen and something else on the other would teach an operator
// that one of them is the real value.
const adminWebhookMask = "***"

// adminCredentialRoute names one of the eight. It is matchAdminRead's and
// matchAdminWrite's third sibling rather than an extension of either, because
// these routes are one PR's and one class of risk's: the two GETs here are
// listings that redact, not ordinary reads, and keeping them beside the writes
// that fill what they redact is the whole arrangement of M8.
type adminCredentialRoute int

const (
	adminCredentialNone adminCredentialRoute = iota
	adminCredentialListAPIKeys
	adminCredentialCreateAPIKey
	adminCredentialRevokeAPIKey
	adminCredentialDeleteAPIKey
	adminCredentialListWebhooks
	adminCredentialCreateWebhook
	adminCredentialUpdateWebhook
	adminCredentialDeleteWebhook
)

// matchAdminCredential classifies a method and a path below the admin mount,
// returning the route and its decoded parameter.
//
// rel is the *escaped* path, for matchAdminRead's reason: Express matches its
// patterns against the raw pathname and decodes each captured parameter
// afterwards, so an id carrying %2F is one segment there and would be two here
// if this read r.URL.Path. The parameter is decoded once and not twice — none of
// these four parameterised routes calls decodeURIComponent on it the way the
// tenant family does (:1337, :1349, :1420, :1435).
//
// HEAD is folded into GET, which is Express's fallback to a router.get layer and
// what isAdminRead expresses for the read surface.
func matchAdminCredential(method, rel string) (adminCredentialRoute, string) {
	if method == http.MethodHead {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet:
		switch rel {
		case AdminAPIKeysPath:
			return adminCredentialListAPIKeys, ""
		case AdminWebhooksPath:
			return adminCredentialListWebhooks, ""
		}
	case http.MethodPost:
		switch rel {
		case AdminAPIKeysPath:
			return adminCredentialCreateAPIKey, ""
		case AdminWebhooksPath:
			return adminCredentialCreateWebhook, ""
		}
	case http.MethodPatch:
		if id, tail, ok := adminPathParam(rel, AdminWebhooksPath); ok && tail == "" {
			return adminCredentialUpdateWebhook, id
		}
	case http.MethodDelete:
		// The two API-key deletes are one pattern apart — ":id/revoke" and
		// ":id" — and mean different things; see adminDeleteAPIKey. Nothing is
		// registered below either, so a longer path is a miss.
		if id, tail, ok := adminPathParam(rel, AdminAPIKeysPath); ok {
			switch tail {
			case "":
				return adminCredentialDeleteAPIKey, id
			case "/revoke":
				return adminCredentialRevokeAPIKey, id
			}
			return adminCredentialNone, ""
		}
		if id, tail, ok := adminPathParam(rel, AdminWebhooksPath); ok && tail == "" {
			return adminCredentialDeleteWebhook, id
		}
	}
	return adminCredentialNone, ""
}

// serveAdminCredential dispatches one classified credential route. It runs
// behind Protect, so everything below may assume an authorised caller and
// nothing below may assume an identified one.
//
// There is no adminCredentialRegistered beside it: all eight are registered
// unconditionally in the reference — outside the `if (featTemplates &&
// options.templateStore)` block that makes the template routes conditional — and
// each answers its own 404 for the store it was not given.
func (a *Auth) serveAdminCredential(w http.ResponseWriter, r *http.Request, route adminCredentialRoute, param string) {
	switch route {
	case adminCredentialListAPIKeys:
		a.adminListAPIKeys(w, r)
	case adminCredentialCreateAPIKey:
		a.adminCreateAPIKey(w, r)
	case adminCredentialRevokeAPIKey:
		a.adminRevokeAPIKey(w, r, param)
	case adminCredentialDeleteAPIKey:
		a.adminDeleteAPIKey(w, r, param)
	case adminCredentialListWebhooks:
		a.adminListWebhooks(w, r)
	case adminCredentialCreateWebhook:
		a.adminCreateWebhook(w, r)
	case adminCredentialUpdateWebhook:
		a.adminUpdateWebhook(w, r, param)
	case adminCredentialDeleteWebhook:
		a.adminDeleteWebhook(w, r, param)
	default:
		http.NotFound(w, r)
	}
}

// ── API keys ─────────────────────────────────────────────────────────────────

// adminAPIKeyRow is the projection GET <admin>/api/api-keys answers with
// (:1266-1277): ten hand-picked keys, and no key material of any kind.
//
// It is a type of its own rather than APIKeyRecord with a tag on KeyHash, and
// that is the point of this PR rather than a style choice. APIKeyRecord carries
// the bcrypt hash; a type that carries a field can leak it — through a `json:"-"`
// someone deletes, through a second serialiser that does not read struct tags,
// through a fmt.Sprintf("%+v") in a log line a future handler adds. This type
// has no field to leak, so the compiler is what enforces the redaction and not a
// reviewer. The same reasoning is why the listing builds rows rather than
// filtering a map built from the record.
//
// The reference's own list is the weaker form of this: it maps each record into
// an object literal naming ten fields (:1266-1277), out of a record that does
// carry keyHash. One key added to that literal in the wrong copy-paste is a
// disclosed hash; here it is a compile error.
//
// scopes is always an array. It is optional on the model (api-key.model.ts:43)
// but the reference's own service writes `scopes: options.scopes ?? []`
// (api-key.service.ts:60), so every record it made has one, and every client
// here iterates it. The other four optional members are omitted when this port
// has no value: the reference writes null for a record its service made and
// undefined for a store that never had the column, and Go cannot tell an absent
// column from an empty one — absent is the spelling U13 chose for the same
// question on the users table, and every reader of these fields tests them for
// truthiness.
type adminAPIKeyRow struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"keyPrefix"`
	ServiceID  string     `json:"serviceId,omitempty"`
	Scopes     []string   `json:"scopes"`
	AllowedIPs []string   `json:"allowedIps,omitempty"`
	IsActive   bool       `json:"isActive"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

func newAdminAPIKeyRow(record APIKeyRecord) adminAPIKeyRow {
	row := adminAPIKeyRow{
		ID:         record.ID,
		Name:       record.Name,
		KeyPrefix:  record.Prefix,
		ServiceID:  record.ServiceID,
		Scopes:     adminStrings(record.Scopes),
		AllowedIPs: record.AllowedIPs,
		IsActive:   record.IsActive,
		CreatedAt:  record.CreatedAt,
	}
	if record.ExpiresAt != nil {
		expiresAt := *record.ExpiresAt
		row.ExpiresAt = &expiresAt
	}
	if record.LastUsedAt != nil {
		lastUsedAt := *record.LastUsedAt
		row.LastUsedAt = &lastUsedAt
	}
	return row
}

// adminAPIKeyCreated is the record POST <admin>/api/api-keys echoes beside the
// raw key (:1316-1326), and it is nine keys where the listing is ten:
// lastUsedAt is not in it, because a key that was minted a microsecond ago has
// never been used.
//
// It is a second type rather than adminAPIKeyRow with a nil LastUsedAt for the
// reason adminUserDetail is a second type beside adminUserRow: the two
// projections answer different questions and the reference writes them as two
// literals. That they would serialise alike today is an accident of the record
// being fresh, and an accident is not what this file relies on.
type adminAPIKeyCreated struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"keyPrefix"`
	ServiceID  string     `json:"serviceId,omitempty"`
	Scopes     []string   `json:"scopes"`
	AllowedIPs []string   `json:"allowedIps,omitempty"`
	IsActive   bool       `json:"isActive"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

// adminListAPIKeys is GET <admin>/api/api-keys (:1253-1291).
//
// The paging and the filter are GET /api/users' arithmetic applied to a second
// table, quirk for quirk (:1256-1258, :1263-1288): limit defaults to 20 and is
// clamped to 100, a filter fetches a 500-row batch at offset 0 and matches in
// memory, the filtered page is that batch sliced [offset, offset+limit) with an
// exact total, and the unfiltered total is the best-effort
// `len(page) + offset + (len(page) == limit ? 1 : 0)` whose only job is the
// table's "next" button. adminListUsers carries the reasoning; it is not
// repeated here.
//
// The filter matches on name, serviceId and keyPrefix (:1280-1282) — never on
// the id and never on anything derived from the hash, so a caller cannot use it
// as an oracle over key material.
//
// The order is APIKeyAdminStore's: CreatedAt descending, ID ascending. See the
// admin-credential-listings-are-ordered deviation.
func (a *Auth) adminListAPIKeys(w http.ResponseWriter, r *http.Request) {
	if a.apiKeys == nil {
		writeAdminError(w, http.StatusNotFound, "API key store not configured")
		return
	}
	query := r.URL.Query()
	limit := adminQueryInt(query.Get("limit"), 20)
	if limit > 100 {
		limit = 100
	}
	offset := adminQueryInt(query.Get("offset"), 0)
	filter := strings.TrimSpace(strings.ToLower(query.Get("filter")))

	// The second of the two absences: a store is configured and cannot
	// enumerate. The 501 carries an empty page beside the message (:1260), so
	// the tab renders "0 keys" rather than breaking on an absent key — the same
	// shape GET /api/users' 501 has, and deliberately not the bare one the
	// 2FA-policy walk answers with.
	store, ok := a.apiKeys.(APIKeyAdminStore)
	if !ok {
		WriteJSON(w, http.StatusNotImplemented, map[string]any{
			"error": "IApiKeyStore.listAll is not implemented",
			"keys":  []adminAPIKeyRow{},
			"total": 0,
		})
		return
	}

	batchLimit, batchOffset := limit, offset
	if filter != "" {
		batchLimit, batchOffset = 500, 0
	}
	keys, err := store.ListAll(r.Context(), batchLimit, batchOffset)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rows := make([]adminAPIKeyRow, 0, len(keys))
	for _, key := range keys {
		rows = append(rows, newAdminAPIKeyRow(key))
	}

	if filter != "" {
		matched := make([]adminAPIKeyRow, 0, len(rows))
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row.Name), filter) ||
				strings.Contains(strings.ToLower(row.ServiceID), filter) ||
				strings.Contains(strings.ToLower(row.KeyPrefix), filter) {
				matched = append(matched, row)
			}
		}
		total := len(matched)
		low, high := adminSliceBounds(len(matched), offset, limit)
		WriteJSON(w, http.StatusOK, map[string]any{"keys": matched[low:high], "total": total})
		return
	}

	total := len(rows) + offset
	if len(rows) == limit {
		total++
	}
	WriteJSON(w, http.StatusOK, map[string]any{"keys": rows, "total": total})
}

// adminCreateAPIKey is POST <admin>/api/api-keys (:1295-1331), the one route in
// the whole package that puts a usable credential on the wire.
//
// It is there exactly once. APIKeyService.Create hashes the raw key with bcrypt
// before it returns, the store never sees the plaintext, and no other route can
// recover it: the listing projects ten fields that do not include the hash, and
// the hash would not yield the key if it did. An operator who loses the value
// mints a new key and revokes this one, which is the property the reference
// states at the top of its own model ("The plaintext key is returned exactly
// once at creation time", api-key.model.ts:4).
//
// What it answers beside the key is `record` — nine fields, no lastUsedAt and
// no keyHash (:1316-1326). So the whole body is {rawKey, record}, and `rawKey`
// is the only member of it that must never be logged, cached or echoed by
// anything downstream.
//
// # The two things it does not check
//
// There is no capability assertion. Creating needs Save, which is on APIKeyStore
// itself, so a configured store can always mint — the reference asks nothing
// here either (:1296-1312) and reaches `new ApiKeyService().createKey(store, …)`
// directly.
//
// There is no policy on name, scopes or allowedIps. `if (!name)` is the whole of
// the validation (:1305), so a key named by a single space is created on both
// sides, and a scope string means whatever the host's own middleware reads it
// as.
//
// # expiresAt
//
// The reference's `expiresAt ? new Date(expiresAt) : undefined` (:1312) builds
// an Invalid Date from an unparseable string, which serialises as null and
// compares false against every instant — so a garbage expiry there is a key
// that never expires, not a refusal. A failed time.Parse is therefore read as
// "no expiry" rather than as a 400, which is the same key in the same state, and
// the alternative would be a refusal the reference does not make.
func (a *Auth) adminCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	if a.apiKeys == nil {
		writeAdminError(w, http.StatusNotFound, "API key store not configured")
		return
	}
	var body struct {
		Name       string   `json:"name"`
		ServiceID  string   `json:"serviceId"`
		Scopes     []string `json:"scopes"`
		AllowedIPs []string `json:"allowedIps"`
		ExpiresAt  string   `json:"expiresAt"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Name == "" {
		writeAdminError(w, http.StatusBadRequest, "name is required")
		return
	}

	var expiresAt *time.Time
	if body.ExpiresAt != "" {
		if when, err := time.Parse(time.RFC3339, body.ExpiresAt); err == nil {
			expiresAt = &when
		}
	}

	// Config.BcryptCost, not the library default. The reference constructs
	// `new ApiKeyService()` with its own default of 10 salt rounds (:1306,
	// api-key.service.ts:40), deliberately below its password cost; this port
	// carries the cost on APIKeyService for the reason NewAPIKeyService gives —
	// an operator who raised the password cost would otherwise have no way to
	// reach the key hashes — and a zero Config.BcryptCost resolves to
	// bcrypt.DefaultCost, which is the reference's 10.
	rawKey, record, err := NewAPIKeyService(a.service.cfg.BcryptCost).Create(
		r.Context(), a.apiKeys, body.Name, body.ServiceID, body.Scopes, body.AllowedIPs, expiresAt)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"rawKey": rawKey,
		"record": adminAPIKeyCreated{
			ID:         record.ID,
			Name:       record.Name,
			KeyPrefix:  record.Prefix,
			ServiceID:  record.ServiceID,
			Scopes:     adminStrings(record.Scopes),
			AllowedIPs: record.AllowedIPs,
			IsActive:   record.IsActive,
			ExpiresAt:  record.ExpiresAt,
			CreatedAt:  record.CreatedAt,
		},
	})
}

// adminRevokeAPIKey is DELETE <admin>/api/api-keys/:id/revoke (:1334-1342): the
// soft delete, and the one the reference prefers — "prefer `revoke` for
// audit-trail preservation" (api-key-store.interface.ts:83).
//
// Revoke is on APIKeyStore itself, so there is no capability to assert and no
// 501 to answer. Nothing is looked up first and an id that matches nothing is
// still {"success": true}: the store contract says an unknown id is a no-op, and
// the route awaits the call and answers without asking what it did (:1337-1338).
func (a *Auth) adminRevokeAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if a.apiKeys == nil {
		writeAdminError(w, http.StatusNotFound, "API key store not configured")
		return
	}
	if err := a.apiKeys.Revoke(r.Context(), id); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// adminDeleteAPIKey is DELETE <admin>/api/api-keys/:id (:1345-1359): the hard
// delete, which falls back to the soft one and says so.
//
// The two routes are two meanings and not two spellings of one. Revoke keeps the
// row — the audit trail, the prefix an operator recognises, the last-used stamp —
// and Delete does not; the reference offers both and recommends the first, and
// it makes Delete the *optional* capability so that a store may decline to
// destroy evidence at all.
//
// Declining costs nothing, which is what the fallback is for: with no Delete the
// route revokes instead and answers 200 with a `note` saying which happened
// (:1350-1354). That note is the whole reason APIKeyDeleteStore is an interface
// of its own — the absence of this one method, on a store whose other four are
// present, has to be observable — and it is reproduced verbatim, because a
// console that quietly revoked where an operator asked to delete would be worse
// than one that refused.
func (a *Auth) adminDeleteAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	if a.apiKeys == nil {
		writeAdminError(w, http.StatusNotFound, "API key store not configured")
		return
	}
	if store, ok := a.apiKeys.(APIKeyDeleteStore); ok {
		if err := store.Delete(r.Context(), id); err != nil {
			writeAdminError(w, http.StatusInternalServerError, "Internal server error")
			return
		}
		writeAdminSuccess(w)
		return
	}
	if err := a.apiKeys.Revoke(r.Context(), id); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"note":    "IApiKeyStore.delete not implemented; key was revoked instead",
	})
}

// ── webhooks ─────────────────────────────────────────────────────────────────

// adminWebhookRow is the projection GET <admin>/api/webhooks answers with
// (:1373-1382): eight hand-picked keys, the last of which is the mask.
//
// secret is "***" when the stored configuration has one and absent when it does
// not, which is the reference's `w.secret ? '***' : undefined` (:1381) — so the
// field answers "is this webhook signed?" and nothing else. It is a string here
// rather than a bool named `signed` because the SPA reads exactly this shape
// (admin.js renders a "✓ signed" badge from the truthiness of `secret`), and
// because the reference's wire contract is what a client written against it
// expects to find.
//
// The three inbound fields of WebhookConfig — provider, allowedActions and
// jsScript — are not in the projection, because they are not in the reference's
// either. The listing is the outgoing-subscription screen.
type adminWebhookRow struct {
	ID           string   `json:"id"`
	URL          string   `json:"url"`
	Events       []string `json:"events"`
	IsActive     *bool    `json:"isActive,omitempty"`
	TenantID     string   `json:"tenantId,omitempty"`
	MaxRetries   *int     `json:"maxRetries,omitempty"`
	RetryDelayMs *int     `json:"retryDelayMs,omitempty"`
	Secret       string   `json:"secret,omitempty"`
}

func newAdminWebhookRow(config WebhookConfig) adminWebhookRow {
	row := adminWebhookRow{
		ID:           config.ID,
		URL:          config.URL,
		Events:       adminStrings(config.Events),
		TenantID:     config.TenantID,
		MaxRetries:   config.MaxRetries,
		RetryDelayMs: config.RetryDelayMs,
	}
	if config.IsActive != nil {
		isActive := *config.IsActive
		row.IsActive = &isActive
	}
	if config.Secret != "" {
		row.Secret = adminWebhookMask
	}
	return row
}

// adminMaskedWebhook is the masking POST <admin>/api/webhooks applies to the
// configuration it just stored: `{...webhook, secret: webhook.secret ? '***' :
// undefined}` (:1406).
//
// That route spreads the whole stored row where the listing hand-picks, so it is
// reproduced by serialising WebhookConfig itself rather than a projection — a
// field the store adds appears there and would appear here. The one field that
// must not is replaced *in the copy* this returns, so the value that reaches
// encoding/json has never held the secret; the parameter is a value and not a
// pointer for that reason, and the stored configuration is untouched.
func adminMaskedWebhook(config WebhookConfig) WebhookConfig {
	if config.Secret != "" {
		config.Secret = adminWebhookMask
	}
	return config
}

// adminListWebhooks is GET <admin>/api/webhooks (:1363-1387).
//
// It pages like the two listings beside it — limit defaulted to 20 and clamped
// to 100, the same best-effort total (:1366-1367, :1383) — and unlike them it
// has no filter, because the reference gives it none.
//
// The order is the one WebhookStore declares: first insertion. See the
// admin-credential-listings-are-ordered deviation.
func (a *Auth) adminListWebhooks(w http.ResponseWriter, r *http.Request) {
	if a.webhooks == nil {
		writeAdminError(w, http.StatusNotFound, "Webhook store not configured")
		return
	}
	query := r.URL.Query()
	limit := adminQueryInt(query.Get("limit"), 20)
	if limit > 100 {
		limit = 100
	}
	offset := adminQueryInt(query.Get("offset"), 0)

	store, ok := a.webhooks.(WebhookAdminStore)
	if !ok {
		adminWebhookListNotImplemented(w)
		return
	}
	configs, err := store.ListWebhooks(r.Context(), limit, offset)
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		// WebhookAdminStore bundles the reference's four separately-optional
		// methods, so a store that can serve one of them and not another says so
		// with this sentinel rather than by failing an assertion — the
		// arrangement WebhookStore's doc comment describes. Both spellings of
		// the absence answer the same 501 naming the same single method, which
		// is what the reference answers for either.
		adminWebhookListNotImplemented(w)
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rows := make([]adminWebhookRow, 0, len(configs))
	for _, config := range configs {
		rows = append(rows, newAdminWebhookRow(config))
	}
	total := len(rows) + offset
	if len(rows) == limit {
		total++
	}
	WriteJSON(w, http.StatusOK, map[string]any{"webhooks": rows, "total": total})
}

// adminWebhookListNotImplemented is the listing's 501 (:1369), which carries an
// empty page beside the message for the reason GET /api/api-keys' does.
func adminWebhookListNotImplemented(w http.ResponseWriter) {
	WriteJSON(w, http.StatusNotImplemented, map[string]any{
		"error":    "IWebhookStore.listAll is not implemented",
		"webhooks": []adminWebhookRow{},
		"total":    0,
	})
}

// adminCreateWebhook is POST <admin>/api/webhooks (:1390-1410).
//
// # The defaulting is the route's, not the store's
//
// `events ?? ['*']` and `isActive ?? true` (:1403-1404) happen here because they
// happen there, and WebhookAdminStore.AddWebhook is documented as storing what it
// is given. Both are nullish and not falsy tests, so `"events": []` is stored as
// an empty list — a subscription to nothing — and only an absent or null events
// becomes the wildcard. A nil slice and a nil *bool are what JSON decoding
// leaves for the absent form, which is the distinction Go can make and
// JavaScript's ?? makes.
//
// url is required by a falsy test (:1397) and is checked *before* the capability
// (:1398), so a body with no url is a 400 even on a store that could not have
// stored it.
//
// # What it answers
//
// The stored configuration with its secret masked — so a POST that set a secret
// gets "***" back and never the value it just sent. The response is therefore
// not a round-trip: a client that wants the secret it chose already has it.
func (a *Auth) adminCreateWebhook(w http.ResponseWriter, r *http.Request) {
	if a.webhooks == nil {
		writeAdminError(w, http.StatusNotFound, "Webhook store not configured")
		return
	}
	var body struct {
		URL          string   `json:"url"`
		Events       []string `json:"events"`
		Secret       string   `json:"secret"`
		TenantID     string   `json:"tenantId"`
		IsActive     *bool    `json:"isActive"`
		MaxRetries   *int     `json:"maxRetries"`
		RetryDelayMs *int     `json:"retryDelayMs"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.URL == "" {
		writeAdminError(w, http.StatusBadRequest, "url is required")
		return
	}
	store, ok := a.webhooks.(WebhookAdminStore)
	if !ok {
		writeAdminError(w, http.StatusNotImplemented, "IWebhookStore.add is not implemented")
		return
	}

	events := body.Events
	if events == nil {
		events = []string{WebhookEventWildcard}
	}
	isActive := body.IsActive
	if isActive == nil {
		active := true
		isActive = &active
	}

	config, err := store.AddWebhook(r.Context(), WebhookConfig{
		URL:          body.URL,
		Events:       events,
		Secret:       body.Secret,
		TenantID:     body.TenantID,
		IsActive:     isActive,
		MaxRetries:   body.MaxRetries,
		RetryDelayMs: body.RetryDelayMs,
	})
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		writeAdminError(w, http.StatusNotImplemented, "IWebhookStore.add is not implemented")
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"webhook": adminMaskedWebhook(config)})
}

// adminUpdateWebhook is PATCH <admin>/api/webhooks/:id (:1413-1425), and its
// secret semantics are the half of this PR that is easiest to get wrong.
//
// The reference passes the request body to update() as
// `Partial<Omit<WebhookConfig, 'id'>>` (:1420) and answers {"success": true}. So:
//
//   - A PATCH that does not name `secret` leaves the stored one alone. The
//     member is simply not in the patch, and a store applies what it was given.
//     That is what makes the console's isActive toggle safe — it sends one field
//     and the signing key survives it.
//   - A PATCH that names `secret` writes it, in the clear, because the clear
//     value is what an HMAC needs. `"secret": ""` clears it, which is how a
//     webhook stops being signed.
//   - Either way nothing is echoed. The response is the flat success body, so no
//     secret — old or new — is on the wire, and there is no read-back route that
//     would return one either: GET /api/webhooks masks.
//
// WebhookPatch is that Partial, field for field, and its nil-means-leave-alone
// rule is the same rule. It carries no ID, as the reference's Omit does not, so
// a body naming `id` changes nothing here — where a store implemented as a
// spread would have moved the row.
func (a *Auth) adminUpdateWebhook(w http.ResponseWriter, r *http.Request, id string) {
	if a.webhooks == nil {
		writeAdminError(w, http.StatusNotFound, "Webhook store not configured")
		return
	}
	store, ok := a.webhooks.(WebhookAdminStore)
	if !ok {
		writeAdminError(w, http.StatusNotImplemented, "IWebhookStore.update is not implemented")
		return
	}
	var body struct {
		URL            *string  `json:"url"`
		Events         []string `json:"events"`
		Secret         *string  `json:"secret"`
		IsActive       *bool    `json:"isActive"`
		TenantID       *string  `json:"tenantId"`
		MaxRetries     *int     `json:"maxRetries"`
		RetryDelayMs   *int     `json:"retryDelayMs"`
		Provider       *string  `json:"provider"`
		AllowedActions []string `json:"allowedActions"`
		JSScript       *string  `json:"jsScript"`
	}
	// No validation at all, as there: a PATCH with an empty body is a patch that
	// names nothing, and the store applies nothing.
	_ = json.NewDecoder(r.Body).Decode(&body)

	err := store.UpdateWebhook(r.Context(), id, WebhookPatch{
		URL:            body.URL,
		Events:         body.Events,
		Secret:         body.Secret,
		IsActive:       body.IsActive,
		TenantID:       body.TenantID,
		MaxRetries:     body.MaxRetries,
		RetryDelayMs:   body.RetryDelayMs,
		Provider:       body.Provider,
		AllowedActions: body.AllowedActions,
		JSScript:       body.JSScript,
	})
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		writeAdminError(w, http.StatusNotImplemented, "IWebhookStore.update is not implemented")
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}

// adminDeleteWebhook is DELETE <admin>/api/webhooks/:id (:1428-1440).
//
// It is a hard delete with no soft counterpart — the fallback DELETE
// /api/api-keys/:id exists because a key has an audit trail worth keeping,
// and a subscription's off switch is `{"isActive": false}` through the PATCH
// above. Nothing is looked up first and a second delete of the same id is still
// {"success": true}; see WebhookAdminStore.RemoveWebhook.
func (a *Auth) adminDeleteWebhook(w http.ResponseWriter, r *http.Request, id string) {
	if a.webhooks == nil {
		writeAdminError(w, http.StatusNotFound, "Webhook store not configured")
		return
	}
	store, ok := a.webhooks.(WebhookAdminStore)
	if !ok {
		writeAdminError(w, http.StatusNotImplemented, "IWebhookStore.remove is not implemented")
		return
	}
	err := store.RemoveWebhook(r.Context(), id)
	switch {
	case errors.Is(err, ErrFeatureNotSupported):
		writeAdminError(w, http.StatusNotImplemented, "IWebhookStore.remove is not implemented")
		return
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, "Internal server error")
		return
	}
	writeAdminSuccess(w)
}
