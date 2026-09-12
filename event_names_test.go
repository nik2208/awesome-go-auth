package auth

import (
	"strings"
	"testing"
)

// The vocabulary is the one thing in the event plane that a family client, a
// stored webhook subscription and a foreign consumer all see the same way: an
// event name is a wire string, and changing one silently retires every
// subscription filed against it. So the whole set is pinned here by value, not
// derived from the constants — a test that read the constants would pass any
// edit to them, which is exactly the edit worth catching.
//
// The list below is transcribed from awesome-node-auth's
// src/events/auth-event-names.ts. Twenty-five of the twenty-six are identical in
// the published reference (auth-event-names.ts:5-40) and in the private
// development line (node-auth auth-event-names.ts:5-41); the exception is
// identity.user.email.changed, which the dev line declares and the published
// reference does not. See event_names.go.
var wantEventNames = []string{
	"identity.user.created",
	"identity.user.deleted",
	"identity.user.email.changed",
	"identity.user.email.verified",
	"identity.user.password.changed",
	"identity.user.2fa.enabled",
	"identity.user.2fa.disabled",
	"identity.user.linked",
	"identity.user.unlinked",

	"identity.session.created",
	"identity.session.revoked",
	"identity.session.expired",
	"identity.session.rotated",

	"identity.auth.login.success",
	"identity.auth.login.failed",
	"identity.auth.logout",
	"identity.auth.oauth.success",
	"identity.auth.oauth.conflict",

	"identity.tenant.created",
	"identity.tenant.deleted",
	"identity.tenant.user.added",
	"identity.tenant.user.removed",

	"identity.role.assigned",
	"identity.role.revoked",
	"identity.permission.granted",
	"identity.permission.revoked",
}

// The exported constants are pinned separately from the list, because the list
// alone would let a constant be repointed at another declared name — an edit
// that keeps the set identical and silently moves every publisher.
var wantEventConstants = map[string]string{
	"EventUserCreated":         EventUserCreated,
	"EventUserDeleted":         EventUserDeleted,
	"EventUserEmailChanged":    EventUserEmailChanged,
	"EventUserEmailVerified":   EventUserEmailVerified,
	"EventUserPasswordChanged": EventUserPasswordChanged,
	"EventUser2FAEnabled":      EventUser2FAEnabled,
	"EventUser2FADisabled":     EventUser2FADisabled,
	"EventUserLinked":          EventUserLinked,
	"EventUserUnlinked":        EventUserUnlinked,
	"EventSessionCreated":      EventSessionCreated,
	"EventSessionRevoked":      EventSessionRevoked,
	"EventSessionExpired":      EventSessionExpired,
	"EventSessionRotated":      EventSessionRotated,
	"EventAuthLoginSuccess":    EventAuthLoginSuccess,
	"EventAuthLoginFailed":     EventAuthLoginFailed,
	"EventAuthLogout":          EventAuthLogout,
	"EventAuthOAuthSuccess":    EventAuthOAuthSuccess,
	"EventAuthOAuthConflict":   EventAuthOAuthConflict,
	"EventTenantCreated":       EventTenantCreated,
	"EventTenantDeleted":       EventTenantDeleted,
	"EventTenantUserAdded":     EventTenantUserAdded,
	"EventTenantUserRemoved":   EventTenantUserRemoved,
	"EventRoleAssigned":        EventRoleAssigned,
	"EventRoleRevoked":         EventRoleRevoked,
	"EventPermissionGranted":   EventPermissionGranted,
	"EventPermissionRevoked":   EventPermissionRevoked,
}

// wantEventConstantStrings is the same map inverted, written out so that a
// constant repointed at another declared name fails: the set stays the same and
// only the pairing changes.
var wantEventConstantStrings = map[string]string{
	"EventUserCreated":         "identity.user.created",
	"EventUserDeleted":         "identity.user.deleted",
	"EventUserEmailChanged":    "identity.user.email.changed",
	"EventUserEmailVerified":   "identity.user.email.verified",
	"EventUserPasswordChanged": "identity.user.password.changed",
	"EventUser2FAEnabled":      "identity.user.2fa.enabled",
	"EventUser2FADisabled":     "identity.user.2fa.disabled",
	"EventUserLinked":          "identity.user.linked",
	"EventUserUnlinked":        "identity.user.unlinked",
	"EventSessionCreated":      "identity.session.created",
	"EventSessionRevoked":      "identity.session.revoked",
	"EventSessionExpired":      "identity.session.expired",
	"EventSessionRotated":      "identity.session.rotated",
	"EventAuthLoginSuccess":    "identity.auth.login.success",
	"EventAuthLoginFailed":     "identity.auth.login.failed",
	"EventAuthLogout":          "identity.auth.logout",
	"EventAuthOAuthSuccess":    "identity.auth.oauth.success",
	"EventAuthOAuthConflict":   "identity.auth.oauth.conflict",
	"EventTenantCreated":       "identity.tenant.created",
	"EventTenantDeleted":       "identity.tenant.deleted",
	"EventTenantUserAdded":     "identity.tenant.user.added",
	"EventTenantUserRemoved":   "identity.tenant.user.removed",
	"EventRoleAssigned":        "identity.role.assigned",
	"EventRoleRevoked":         "identity.role.revoked",
	"EventPermissionGranted":   "identity.permission.granted",
	"EventPermissionRevoked":   "identity.permission.revoked",
}

func TestEventNamesMatchTheReference(t *testing.T) {
	got := EventNames()
	if len(got) != len(wantEventNames) {
		t.Fatalf("EventNames() has %d entries, want %d: the reference declares twenty-six "+
			"(node-auth auth-event-names.ts:5-41), and adding or dropping one is a vocabulary "+
			"change that every stored webhook subscription sees.\ngot:  %v\nwant: %v",
			len(got), len(wantEventNames), got, wantEventNames)
	}
	// Order is asserted, not just membership: EventNames documents that the
	// order is the reference's grouping because the admin UI and the OpenAPI
	// document show the list in it.
	for i := range wantEventNames {
		if got[i] != wantEventNames[i] {
			t.Errorf("EventNames()[%d] = %q, want %q", i, got[i], wantEventNames[i])
		}
	}
}

func TestEventNamesAreUniqueAndWellFormed(t *testing.T) {
	seen := make(map[string]bool, len(wantEventNames))
	for _, name := range EventNames() {
		if seen[name] {
			t.Errorf("%q is declared twice: two constants pointing at one wire name make a "+
				"subscription ambiguous", name)
		}
		seen[name] = true
		if !strings.HasPrefix(name, "identity.") {
			t.Errorf("%q does not start with the reference's `identity.` domain prefix", name)
		}
		if name == WebhookEventWildcard || name == EventBusWildcard {
			t.Errorf("%q collides with a wildcard term", name)
		}
	}
}

func TestEventConstantsArePinnedToTheirNames(t *testing.T) {
	for identifier, value := range wantEventConstants {
		want, ok := wantEventConstantStrings[identifier]
		if !ok {
			t.Errorf("%s has no pinned wire name", identifier)
			continue
		}
		if value != want {
			t.Errorf("%s = %q, want %q: repointing a constant at another declared name keeps "+
				"the vocabulary identical and silently moves every publisher that uses it",
				identifier, value, want)
		}
	}
	if len(wantEventConstants) != len(wantEventNames) {
		t.Errorf("%d constants pinned against %d names: every declared name needs an exported "+
			"constant, or a caller has to write the string",
			len(wantEventConstants), len(wantEventNames))
	}
}

func TestEventNamesReturnsAFreshSlice(t *testing.T) {
	first := EventNames()
	if len(first) == 0 {
		t.Fatal("no names to test against")
	}
	first[0] = "clobbered"
	if second := EventNames(); second[0] == "clobbered" {
		t.Error("EventNames shares its backing array between calls: a caller that sorts or " +
			"rewrites its own view changed the next caller's")
	}
}

func TestIsEventName(t *testing.T) {
	for _, name := range EventNames() {
		if !IsEventName(name) {
			t.Errorf("IsEventName(%q) = false for a declared name", name)
		}
	}
	for _, name := range []string{
		"",
		"identity.user.Created",
		"identity.user.create",
		"user.created",
		" identity.user.created",
		// The wildcard is a subscription term, not an event name. A store or an
		// admin route validating a subscription has to accept both, and this
		// function is the half that does not know about the other one.
		WebhookEventWildcard,
	} {
		if IsEventName(name) {
			t.Errorf("IsEventName(%q) = true, want false", name)
		}
	}
}

// The fifteen names the private development line actually raises, against the
// twenty-six it declares. This is not a behavioural assertion — nothing in this
// package publishes yet — but it is the fact U18 is measured against, and it
// belongs next to the vocabulary rather than in a commit message: the count of
// publication points (twenty-six) and the count of distinct names raised
// (fifteen) are different numbers, and conflating them would have U18 either
// inventing eleven publishers the reference does not have or missing eleven of
// the twenty-six sites.
var devLinePublishedEventNames = []string{
	EventUserCreated,
	EventUserDeleted,
	EventUserEmailChanged,
	EventUserEmailVerified,
	EventUserPasswordChanged,
	EventUser2FAEnabled,
	EventUser2FADisabled,
	EventSessionRotated,
	EventAuthLoginSuccess,
	EventAuthLoginFailed,
	EventAuthLogout,
	EventAuthOAuthSuccess,
	EventAuthOAuthConflict,
	EventRoleAssigned,
	EventRoleRevoked,
}

func TestPublishedEventNamesAreDeclared(t *testing.T) {
	if len(devLinePublishedEventNames) != 15 {
		t.Fatalf("the dev line raises %d distinct names, not %d: recount against "+
			"node-auth auth.router.ts, admin.router.ts and auth-configurator.ts before "+
			"changing this", 15, len(devLinePublishedEventNames))
	}
	for _, name := range devLinePublishedEventNames {
		if !IsEventName(name) {
			t.Errorf("%q is raised by the reference and not declared here", name)
		}
	}
}
