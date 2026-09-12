package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// APIKeyRecord stores hashed key material and policy constraints.
//
// CreatedAt is the minting instant, and it is not decoration. The admin listing
// projects it (`createdAt`, admin.router.ts:1275) and the create route echoes
// it back in the record beside the once-only raw key (:1325), so a store that
// drops it serves nulls to a screen built to show them. It is also the only
// field that can order that listing: newID mints `key_` plus random hex
// (security.go:20-26), so the IDs carry no time component and sorting by one is
// sorting by noise. APIKeyService.Create stamps it; a store must round-trip it
// unchanged.
//
// It is a value and not a pointer because the reference declares it
// non-optional — `createdAt: Date` (api-key.model.ts:59-60), where `expiresAt`
// and `lastUsedAt` are both nullable — and this type keeps that split. A zero
// CreatedAt therefore means a record that predates the field or a store that
// lost it, never "this key has no creation time".
type APIKeyRecord struct {
	ID         string
	Prefix     string
	Name       string
	ServiceID  string
	KeyHash    string
	Scopes     []string
	AllowedIPs []string
	IsActive   bool
	ExpiresAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// ErrAPIKeyNotFound is what an API key store answers when no record matches. It
// lives here rather than in errors.go for the reason ErrDeliveryFailed lives
// beside the senders: it is one feature's store contract and means nothing
// outside it.
//
// The reference's two finders return `ApiKey | null`
// (api-key-store.interface.ts:48, :54), which a two-value Go return has no room
// for, so absence is this error rather than a zero record with a nil error —
// the same shape the rest of this package uses. Verify collapses it, and every
// other store error, into ErrInvalidCredentials, so the distinction never
// reaches the wire.
var ErrAPIKeyNotFound = errors.New("auth: api key not found")

// APIKeyStore persists and resolves API keys.
//
// This is the mandatory half of the reference's IApiKeyStore, and the reference
// draws the line itself: "All methods are optional except for `findByPrefix`
// and `findById`" (api-key-store.interface.ts:7-9). The four it marks optional
// are not methods here at all. Each is a one-method companion interface below,
// which a caller reaches by type-asserting the configured store — the way
// SessionAdminStore and UserMetadataStore are reached — so a store that
// implements none of them still satisfies APIKeyStore and still authenticates.
//
// The optional four are split one to an interface, rather than gathered into a
// single admin interface, because the reference distinguishes them one at a
// time and answers differently for each. GET /admin/api/api-keys answers
// `404 {"error": "API key store not configured"}` when no store is configured
// (admin.router.ts:1254) and `501 {"error": "IApiKeyStore.listAll is not
// implemented", "keys": [], "total": 0}` when the configured store has no
// listAll (:1259-1262): two statuses for two different absences, and the 501
// names the single method. A combined interface would fail its assertion for a
// store that implements ListByServiceID and not ListAll, and answer 501 naming
// a method that is present. DELETE /admin/api/api-keys/:id makes the same
// distinction the other way round — with no delete it falls back to revoke and
// answers `200 {"success": true, "note": "IApiKeyStore.delete not implemented;
// key was revoked instead"}` (:1348-1354) — which it can only do if the absence
// of Delete alone is observable.
//
// FindByID sits on this interface and not among the companions because the
// reference makes it mandatory. Adding it breaks every existing implementor of
// the previous four-method interface, and that is taken deliberately: the admin
// surface addresses keys by id throughout, Revoke and UpdateLastUsed already
// take an id so any store that satisfies them already has an id index and the
// new method is one query it can already run, and leaving it optional would put
// an entry in the deviation register whose only argument is that this port
// shipped the interface incomplete first. v0.8.0 is the release the roadmap
// names as the one that completes APIKeyStore, so it is the release that pays
// for it.
type APIKeyStore interface {
	// Save persists a newly created record. APIKeyService.Create is its only
	// caller in this package and calls it once, with a record whose ID and
	// Prefix were minted a few lines earlier; the reference's own example is a
	// bare insert (api-key-store.interface.ts:16-18), with no collision rule,
	// and none is imposed here.
	Save(ctx context.Context, key APIKeyRecord) error

	// FindByPrefix returns the *active* candidate for a prefix. The reference is
	// explicit — "Only return records where `isActive = true`"
	// (api-key-store.interface.ts:46) — and its example implementation puts the
	// flag in the WHERE clause (:20). The prefix is a lookup index and not a
	// credential: the caller still verifies the raw key against KeyHash.
	//
	// Verify does not depend on the filter. It re-checks IsActive on whatever
	// comes back, exactly as the reference's strategy does
	// (api-key.strategy.ts:96), so a store that leaks revoked rows here is wrong
	// but not exploitable. Implement the filter anyway: it is the contract, and
	// a revoked key stays reachable for the admin screens through FindByID.
	//
	// Answer ErrAPIKeyNotFound when no active record has this prefix.
	FindByPrefix(ctx context.Context, prefix string) (APIKeyRecord, error)

	// FindByID returns the record with this id whatever its state — active,
	// revoked or expired. It is the deliberate opposite of FindByPrefix, and the
	// reference says why: it is "Used for revocation, rotation, and admin
	// management" (api-key-store.interface.ts:51-52), and a management screen
	// that could not open a revoked key could not show an operator the thing
	// they just revoked. Nothing on the authentication path calls it, so the
	// widening costs no strictness there.
	//
	// Answer ErrAPIKeyNotFound for an id that is absent.
	FindByID(ctx context.Context, id string) (APIKeyRecord, error)

	// Revoke marks the key inactive. It is a soft delete, and it is the one the
	// reference prefers — "prefer `revoke` for audit-trail preservation"
	// (api-key-store.interface.ts:83) — so the record stays readable through
	// FindByID afterwards.
	//
	// An id that matches nothing is not an error. The reference's example is an
	// unconditional update behind a `where({ id })`
	// (api-key-store.interface.ts:25-27), which no-ops on a miss, and the admin
	// route awaits it and answers `200 {"success": true}` with no lookup of its
	// own (admin.router.ts:1337-1338). A store that answered ErrAPIKeyNotFound
	// here would turn that 200 into a 500.
	Revoke(ctx context.Context, id string) error

	// UpdateLastUsed stamps the record after a successful authentication. Verify
	// calls it and discards the error, so a store may treat it as best-effort.
	//
	// The reference's signature is `updateLastUsed(id, at?)`
	// (api-key-store.interface.ts:66) with the instant optional and its example
	// defaulting to the store's own clock (:28-30); its one caller passes the
	// instant anyway (api-key.strategy.ts:132). Here it is required, so the
	// timestamp is always the caller's clock and a test can pin it.
	//
	// An unknown id is a no-op, for the reason it is on Revoke.
	UpdateLastUsed(ctx context.Context, id string, when time.Time) error
}

// APIKeyAdminStore is the reference's optional `listAll?`
// (api-key-store.interface.ts:74-78): the page of records an admin listing
// walks. A configured store that does not implement it is the case GET
// /admin/api/api-keys answers `501 {"error": "IApiKeyStore.listAll is not
// implemented", "keys": [], "total": 0}` for (admin.router.ts:1259-1262), which
// is the whole reason it is an interface of its own and not a method on
// APIKeyStore.
//
// Ordering. ListAll returns records newest first: CreatedAt descending, ties
// broken by ID ascending. That sentence is normative for this package. The
// reference ships the interface and no implementation of it, so there is
// nothing to reproduce and the choice has to be made somewhere; it is made
// here, MemoryAPIKeyStore is its executable statement, and a store that cannot
// hold to it — a DynamoDB table with no suitable index, say — registers its own
// order as a deviation against this paragraph rather than inventing one in
// silence.
//
// Newest first because that is what a key listing is read for: the key just
// minted is the one the operator came to look at. The ID tiebreak is what makes
// it a *total* order, and that is the load-bearing half. CreatedAt alone is not
// one — two keys can share an instant, and a backing column with second
// resolution will make them share it often — and limit/offset paging over a
// partial order silently repeats some rows and drops others. Records with a
// zero CreatedAt sort last, after every record that has one.
//
// The order is stable for a fixed set of records. It is not stable across a
// concurrent Save: a key created between two pages shifts every older record one
// place, so the second page repeats a row. The reference pages the same way
// (:1263-1265) and its `total` is openly a guess (:1288), so the property is
// reproduced rather than fixed.
//
// limit is the maximum number of records to return and offset how many to skip
// first. A limit of zero returns nothing, not everything; a negative limit or
// offset is read as zero. Returning fewer than limit records is how a caller
// learns the page is the last one — it is exactly what the reference's `total`
// heuristic reads (:1288) — so a store must not return a short page for any
// other reason.
type APIKeyAdminStore interface {
	ListAll(ctx context.Context, limit, offset int) ([]APIKeyRecord, error)
}

// APIKeyServiceIndexStore is the reference's optional `listByServiceId?`
// (api-key-store.interface.ts:68-72): every key issued to one service identity,
// active or not.
//
// Nothing in the reference calls it. It is declared on IApiKeyStore, described
// as needed "only if you expose a key-listing UI" (:70-71), and no route, no
// strategy and no service reaches for it — the admin UI lists with listAll
// instead. It is ported because the interface is the contract a host implements
// against, and a host that has already written the query should not discover
// later that this port dropped it; it is not ported because anything here needs
// it.
//
// Ordering is APIKeyAdminStore's: CreatedAt descending, ID ascending. There is
// no limit or offset because the reference declares none — the whole set comes
// back — so a service identity with a pathological number of keys is the
// caller's problem, as it is there.
type APIKeyServiceIndexStore interface {
	ListByServiceID(ctx context.Context, serviceID string) ([]APIKeyRecord, error)
}

// APIKeyDeleteStore is the reference's optional `delete?`
// (api-key-store.interface.ts:80-84): a hard delete, audit trail and all. The
// reference's own advice is not to implement it — "prefer `revoke` for
// audit-trail preservation" (:83) — and DELETE /admin/api/api-keys/:id is
// written so that declining costs nothing: with no delete it revokes instead and
// says so in the body, `200 {"success": true, "note": "IApiKeyStore.delete not
// implemented; key was revoked instead"}` (admin.router.ts:1348-1354).
//
// That fallback is why this is an interface of its own: the route has to be able
// to observe the absence of this one method, on a store whose other four are
// present, to choose between the two answers.
//
// An id that matches nothing is a no-op returning nil, as it is on Revoke and
// for the same reason: the route awaits the call and answers 200 without a
// lookup of its own (:1349-1350).
type APIKeyDeleteStore interface {
	Delete(ctx context.Context, id string) error
}

// APIKeyAuditEntry is one usage record for an API key, the reference's
// ApiKeyAuditEntry (api-key-store.interface.ts:93-103).
//
// The reference's optional fields are plain strings here rather than pointers:
// every one of them is a header value or a request component, where absent and
// empty are the same fact.
//
// Two of them the reference never populates. Path and Method are declared on the
// type (:99-100) and its only producer, the strategy's audit hook, writes keyId,
// timestamp, ip, userAgent, success and failureReason and nothing else
// (api-key.strategy.ts:214-223). They are carried anyway, because a store
// written against the reference will have columns for them.
type APIKeyAuditEntry struct {
	// KeyID is the record the attempt was made against. The reference writes the
	// literal `<unknown>` when the key did not resolve, so that an attempt
	// against a prefix nobody owns is still audited
	// (api-key.strategy.ts:215-217); a caller in this package must write the
	// same string rather than an empty one.
	KeyID string
	// Timestamp is when the attempt was made, from the caller's clock.
	Timestamp time.Time
	// IP is the remote address the attempt came from, empty when unknown.
	IP string
	// UserAgent is the request's User-Agent, empty when absent.
	UserAgent string
	// Path and Method describe the request. See the type comment: the reference
	// declares them and never fills them in.
	Path   string
	Method string
	// Success says whether the attempt authenticated. Both outcomes are logged.
	Success bool
	// FailureReason is the reference's own vocabulary on a failure —
	// INVALID_KEY, KEY_REVOKED, KEY_EXPIRED, IP_NOT_ALLOWED,
	// INSUFFICIENT_SCOPE (api-key.strategy.ts:91, :97, :103, :111, :122) — and
	// empty on success.
	FailureReason string
}

// APIKeyAuditStore is the reference's optional `logUsage?`
// (api-key-store.interface.ts:86-90): a per-key access log.
//
// This is a seam. Nothing in this package calls LogUsage today, and a store that
// implements it will not be asked for anything until something does. In the
// reference the caller is the API key strategy, and it is off by default: the
// hook returns immediately unless `ApiKeyStrategyOptions.auditLog` is set *and*
// the store implements the method (api-key.strategy.ts:31, :213), and it
// swallows whatever LogUsage throws, because "Audit log failures must never
// block the request" (:224-228). The caller arrives with the admin API key
// surface in M8 (v0.10.0), which is where APIKeyMiddleware grows the reference's
// auditLog option and where the entries this collects are read. It is defined
// now so that a host writing a store for M8 writes the table once.
//
// The seam is deliberately not wired early. Logging every authentication
// attempt — the failures above all, which is the point of it — turns an
// unauthenticated request into a write, and that is a decision for the milestone
// that also ships the switch to turn it off.
type APIKeyAuditStore interface {
	LogUsage(ctx context.Context, entry APIKeyAuditEntry) error
}

// APIKeyService issues and verifies API keys. Create stores a bcrypt hash of
// the key, so it carries the same cost knob as Config.BcryptCost — an operator
// who raises the password cost would otherwise still get key hashes pinned at
// the default, with no way to reach them.
type APIKeyService struct {
	bcryptCost int
}

// NewAPIKeyService returns a service that hashes new keys at bcryptCost.
//
// As with Config.BcryptCost, zero means unset and resolves to
// bcrypt.DefaultCost. Verify does not hash, so a service used only for
// verification may be built with 0 regardless of the cost its keys were created
// at: bcrypt reads the cost out of the stored hash.
func NewAPIKeyService(bcryptCost int) *APIKeyService {
	return &APIKeyService{bcryptCost: bcryptCost}
}

var apiKeyBodySanitizer = regexp.MustCompile(`[^a-zA-Z0-9]`)

// Create mints a key, hashes it and hands the raw value back exactly once.
//
// CreatedAt is stamped here, from time.Now(), which is where the reference
// stamps it too — the record literal in createKey carries `createdAt: new
// Date()` (api-key.service.ts:64) — rather than being left to the store. A store
// that filled it in itself would give two records created in one request
// different notions of "now", and would make the record this returns disagree
// with the row it just wrote; the admin create route echoes the returned record
// straight back to the caller (admin.router.ts:1314-1327), so the two have to
// be the same value.
//
// LastUsedAt stays nil, as the reference leaves it null (:65): a key that has
// never been presented has no last use, and zero would read as 1 January year 1.
func (s *APIKeyService) Create(ctx context.Context, store APIKeyStore, name, serviceID string, scopes, allowedIPs []string, expiresAt *time.Time) (rawKey string, record APIKeyRecord, err error) {
	if store == nil {
		return "", APIKeyRecord{}, errors.New("auth: api key store is required")
	}
	rawBody, err := randomToken(36)
	if err != nil {
		return "", APIKeyRecord{}, err
	}
	rawBody = apiKeyBodySanitizer.ReplaceAllString(rawBody, "")
	var b strings.Builder
	b.Grow(64)
	b.WriteString(rawBody)
	for i := 0; b.Len() < 48 && i < 4; i++ {
		fallback, ferr := randomToken(48)
		if ferr != nil {
			return "", APIKeyRecord{}, ferr
		}
		b.WriteString(apiKeyBodySanitizer.ReplaceAllString(fallback, ""))
	}
	rawBody = b.String()
	if len(rawBody) < 48 {
		return "", APIKeyRecord{}, errors.New("auth: api key entropy generation failed")
	}
	rawKey = "ak_" + rawBody[:48]
	keyID, err := newID("key")
	if err != nil {
		return "", APIKeyRecord{}, err
	}
	prefix := rawKey[:11]
	h, err := hashPassword(rawKey, s.bcryptCost)
	if err != nil {
		return "", APIKeyRecord{}, err
	}
	record = APIKeyRecord{
		ID:         keyID,
		Prefix:     prefix,
		Name:       name,
		ServiceID:  serviceID,
		KeyHash:    h,
		Scopes:     append([]string(nil), scopes...),
		AllowedIPs: append([]string(nil), allowedIPs...),
		IsActive:   true,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
	}
	if err := store.Save(ctx, record); err != nil {
		return "", APIKeyRecord{}, err
	}
	return rawKey, record, nil
}

func (s *APIKeyService) Verify(ctx context.Context, store APIKeyStore, rawKey string, ip string, requiredScopes []string) (APIKeyRecord, error) {
	if !strings.HasPrefix(rawKey, "ak_") || len(rawKey) < 11 {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	record, err := store.FindByPrefix(ctx, rawKey[:11])
	if err != nil || !verifyPassword(rawKey, record.KeyHash) {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	if !record.IsActive {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	if record.ExpiresAt != nil && time.Now().After(*record.ExpiresAt) {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	if !ipAllowed(ip, record.AllowedIPs) {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	if !hasScopes(record.Scopes, requiredScopes) {
		return APIKeyRecord{}, ErrInvalidCredentials
	}
	_ = store.UpdateLastUsed(ctx, record.ID, time.Now())
	return record, nil
}

func APIKeyMiddleware(store APIKeyStore, requiredScopes []string) func(http.Handler) http.Handler {
	// 0: this service only ever calls Verify, which reads the cost from the
	// stored hash and never produces one.
	svc := NewAPIKeyService(0)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractAPIKey(r.Header)
			if raw == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip == "" {
				ip = r.RemoteAddr
			}
			if _, err := svc.Verify(r.Context(), store, raw, ip, requiredScopes); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractAPIKey(h http.Header) string {
	if v := strings.TrimSpace(h.Get("X-Api-Key")); v != "" {
		return v
	}
	auth := strings.TrimSpace(h.Get("Authorization"))
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "ApiKey") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func hasScopes(got, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(got))
	for _, s := range got {
		set[s] = struct{}{}
	}
	for _, s := range required {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func ipAllowed(ip string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, v := range allowed {
		if strings.Contains(v, "/") {
			_, n, err := net.ParseCIDR(v)
			if err == nil && n.Contains(parsed) {
				return true
			}
			continue
		}
		if parsed.Equal(net.ParseIP(v)) {
			return true
		}
	}
	return false
}
