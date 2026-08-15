package auth

import (
	"encoding/json"
	"testing"
)

// The shipped clients parse the /me body directly, and two of the fields they
// read are non-nullable casts: a missing one does not degrade the client, it
// throws inside it. awesome-node-auth-flutter does
//
//	sub:   json['sub'] as String      (lib/src/auth_user.dart:76)
//	email: json['email'] as String    (:77)
//
// where every other field is `as String?` / `as bool?`, and ng-awesome-node-auth
// declares `sub: string` and `email: string` as required with `id?: string`
// optional (auth.service.ts:9-11). `sub` was absent until this test existed, so
// a Flutter client calling checkSession() against this port died on a Dart
// TypeError rather than showing a logged-out state.
//
// The list is deliberately the clients' hard requirements and not the
// reference's full field set: adding a field a client reads optionally is a
// compatible change, removing one it casts non-nullably is not.
func TestPublicUserCarriesTheFieldsClientsCastNonNullably(t *testing.T) {
	body, err := json.Marshal(NewPublicUser(User{ID: "usr_1", Email: "a@example.test"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"sub", "email"} {
		v, present := got[key]
		if !present {
			t.Errorf("%q is absent; the Flutter client casts it non-nullably and throws (body %s)", key, body)
			continue
		}
		if s, ok := v.(string); !ok || s == "" {
			t.Errorf("%q = %#v, want a non-empty string", key, v)
		}
	}

	if got["sub"] != "usr_1" {
		t.Errorf("sub = %v, want the user id %q", got["sub"], "usr_1")
	}
	// id shipped in 0.2.0 and both clients read it as optional, so it stays
	// alongside sub rather than being renamed out from under a consumer.
	if got["id"] != "usr_1" {
		t.Errorf("id = %v, want the user id %q", got["id"], "usr_1")
	}
}

// Role is the reference's single-role field. It is omitted while empty, which
// is every user today, so its presence must not be asserted unconditionally.
func TestPublicUserRoleIsOmittedWhenEmptyAndCarriedWhenSet(t *testing.T) {
	empty, err := json.Marshal(NewPublicUser(User{ID: "usr_1", Email: "a@example.test"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(empty, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := got["role"]; present {
		t.Errorf("role is present for a user without one: %s", empty)
	}

	set, err := json.Marshal(NewPublicUser(User{ID: "usr_1", Email: "a@example.test", Role: "admin"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(set, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["role"] != "admin" {
		t.Errorf("role = %v, want %q (body %s)", got["role"], "admin", set)
	}
}
