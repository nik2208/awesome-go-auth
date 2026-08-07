package auth

import (
	"context"
	"testing"
	"time"
)

// --- Metadata Store Tests ---

func TestMemoryMetadataStore_GetAndUpdate(t *testing.T) {
	store := NewMemoryMetadataStore()
	ctx := context.Background()
	if err := store.UpdateMetadata(ctx, "u1", map[string]any{"theme": "dark", "lang": "en"}); err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	meta, err := store.GetMetadata(ctx, "u1")
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if meta["theme"] != "dark" {
		t.Fatalf("unexpected theme: %v", meta["theme"])
	}
	if meta["lang"] != "en" {
		t.Fatalf("unexpected lang: %v", meta["lang"])
	}
}

func TestMemoryMetadataStore_MergesFields(t *testing.T) {
	store := NewMemoryMetadataStore()
	ctx := context.Background()
	_ = store.UpdateMetadata(ctx, "u1", map[string]any{"a": 1})
	_ = store.UpdateMetadata(ctx, "u1", map[string]any{"b": 2})
	meta, _ := store.GetMetadata(ctx, "u1")
	if meta["a"] != 1 || meta["b"] != 2 {
		t.Fatalf("metadata should be merged: %+v", meta)
	}
}

func TestMemoryMetadataStore_MissingUser_ReturnsEmpty(t *testing.T) {
	store := NewMemoryMetadataStore()
	meta, err := store.GetMetadata(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("GetMetadata for missing user should not error: %v", err)
	}
	if len(meta) != 0 {
		t.Fatalf("expected empty metadata, got %+v", meta)
	}
}

func TestMemoryMetadataStore_Clear(t *testing.T) {
	store := NewMemoryMetadataStore()
	ctx := context.Background()
	_ = store.UpdateMetadata(ctx, "u1", map[string]any{"x": 1})
	if err := store.ClearMetadata(ctx, "u1"); err != nil {
		t.Fatalf("ClearMetadata: %v", err)
	}
	meta, _ := store.GetMetadata(ctx, "u1")
	if len(meta) != 0 {
		t.Fatalf("expected empty metadata after clear, got %+v", meta)
	}
}

func TestMemoryMetadataStore_ReturnsCopy(t *testing.T) {
	store := NewMemoryMetadataStore()
	ctx := context.Background()
	_ = store.UpdateMetadata(ctx, "u1", map[string]any{"k": "v"})
	meta, _ := store.GetMetadata(ctx, "u1")
	meta["k"] = "modified"
	// Original should be unaffected
	meta2, _ := store.GetMetadata(ctx, "u1")
	if meta2["k"] != "v" {
		t.Fatalf("GetMetadata should return a copy, got %v", meta2["k"])
	}
}

func TestMemoryMetadataStore_OverwriteField(t *testing.T) {
	store := NewMemoryMetadataStore()
	ctx := context.Background()
	_ = store.UpdateMetadata(ctx, "u1", map[string]any{"color": "red"})
	_ = store.UpdateMetadata(ctx, "u1", map[string]any{"color": "blue"})
	meta, _ := store.GetMetadata(ctx, "u1")
	if meta["color"] != "blue" {
		t.Fatalf("expected overwritten value: %v", meta["color"])
	}
}

// --- RBAC Store Tests ---

func TestMemoryRBACStore_CreateRole(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	if err := store.CreateRole(ctx, "admin", []string{"read", "write", "delete"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	perms, err := store.GetPermissionsForRole(ctx, "admin")
	if err != nil {
		t.Fatalf("GetPermissionsForRole: %v", err)
	}
	if len(perms) != 3 {
		t.Fatalf("expected 3 permissions, got %d", len(perms))
	}
}

func TestMemoryRBACStore_CreateRole_NoPermissions(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	if err := store.CreateRole(ctx, "readonly", nil); err != nil {
		t.Fatalf("CreateRole with nil permissions: %v", err)
	}
	perms, _ := store.GetPermissionsForRole(ctx, "readonly")
	if len(perms) != 0 {
		t.Fatalf("expected 0 permissions, got %d", len(perms))
	}
}

func TestMemoryRBACStore_AddRoleToUser(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "editor", []string{"posts:write"})
	if err := store.AddRoleToUser(ctx, "u1", "editor", "t1"); err != nil {
		t.Fatalf("AddRoleToUser: %v", err)
	}
	roles, err := store.GetRolesForUser(ctx, "u1", "t1")
	if err != nil {
		t.Fatalf("GetRolesForUser: %v", err)
	}
	if len(roles) != 1 || roles[0] != "editor" {
		t.Fatalf("unexpected roles: %v", roles)
	}
}

func TestMemoryRBACStore_AddRoleToUser_UnknownRole(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	err := store.AddRoleToUser(ctx, "u1", "nonexistent", "t1")
	if err != ErrRoleNotFound {
		t.Fatalf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestMemoryRBACStore_RemoveRoleFromUser(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "viewer", nil)
	_ = store.AddRoleToUser(ctx, "u1", "viewer", "t1")
	if err := store.RemoveRoleFromUser(ctx, "u1", "viewer", "t1"); err != nil {
		t.Fatalf("RemoveRoleFromUser: %v", err)
	}
	roles, _ := store.GetRolesForUser(ctx, "u1", "t1")
	if len(roles) != 0 {
		t.Fatalf("expected no roles after removal, got %v", roles)
	}
}

func TestMemoryRBACStore_DeleteRole_RemovesFromUsers(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "temp", []string{"x"})
	_ = store.AddRoleToUser(ctx, "u1", "temp", "t1")
	if err := store.DeleteRole(ctx, "temp"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	roles, _ := store.GetRolesForUser(ctx, "u1", "t1")
	for _, r := range roles {
		if r == "temp" {
			t.Fatal("deleted role should be removed from users")
		}
	}
}

func TestMemoryRBACStore_AddPermissionToRole(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "writer", nil)
	if err := store.AddPermissionToRole(ctx, "writer", "posts:create"); err != nil {
		t.Fatalf("AddPermissionToRole: %v", err)
	}
	perms, _ := store.GetPermissionsForRole(ctx, "writer")
	if len(perms) != 1 || perms[0] != "posts:create" {
		t.Fatalf("unexpected permissions: %v", perms)
	}
}

func TestMemoryRBACStore_RemovePermissionFromRole(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "r", []string{"p1", "p2"})
	if err := store.RemovePermissionFromRole(ctx, "r", "p1"); err != nil {
		t.Fatalf("RemovePermissionFromRole: %v", err)
	}
	perms, _ := store.GetPermissionsForRole(ctx, "r")
	for _, p := range perms {
		if p == "p1" {
			t.Fatal("removed permission should not be present")
		}
	}
	if len(perms) != 1 || perms[0] != "p2" {
		t.Fatalf("expected only p2, got %v", perms)
	}
}

func TestMemoryRBACStore_GetPermissionsForUser(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "r1", []string{"p1", "p2"})
	_ = store.CreateRole(ctx, "r2", []string{"p3"})
	_ = store.AddRoleToUser(ctx, "u1", "r1", "t1")
	_ = store.AddRoleToUser(ctx, "u1", "r2", "t1")
	perms, err := store.GetPermissionsForUser(ctx, "u1", "t1")
	if err != nil {
		t.Fatalf("GetPermissionsForUser: %v", err)
	}
	if len(perms) != 3 {
		t.Fatalf("expected 3 permissions, got %d: %v", len(perms), perms)
	}
}

func TestMemoryRBACStore_GetPermissionsForUser_DeduplicatesAcrossRoles(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "r1", []string{"shared"})
	_ = store.CreateRole(ctx, "r2", []string{"shared", "extra"})
	_ = store.AddRoleToUser(ctx, "u1", "r1", "t1")
	_ = store.AddRoleToUser(ctx, "u1", "r2", "t1")
	perms, _ := store.GetPermissionsForUser(ctx, "u1", "t1")
	count := 0
	for _, p := range perms {
		if p == "shared" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("permission should be deduplicated, but 'shared' appears %d times", count)
	}
}

func TestMemoryRBACStore_UserHasPermission_True(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "r", []string{"allowed:action"})
	_ = store.AddRoleToUser(ctx, "u1", "r", "t1")
	ok, err := store.UserHasPermission(ctx, "u1", "allowed:action", "t1")
	if err != nil {
		t.Fatalf("UserHasPermission: %v", err)
	}
	if !ok {
		t.Fatal("user should have permission")
	}
}

func TestMemoryRBACStore_UserHasPermission_False(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "r", []string{"read"})
	_ = store.AddRoleToUser(ctx, "u1", "r", "t1")
	ok, err := store.UserHasPermission(ctx, "u1", "delete", "t1")
	if err != nil {
		t.Fatalf("UserHasPermission: %v", err)
	}
	if ok {
		t.Fatal("user should not have delete permission")
	}
}

func TestMemoryRBACStore_GetRolesForUser_Empty(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	roles, err := store.GetRolesForUser(context.Background(), "u_nobody", "t1")
	if err != nil {
		t.Fatalf("GetRolesForUser: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected empty roles, got %v", roles)
	}
}

func TestMemoryRBACStore_RoleIsolatedByTenant(t *testing.T) {
	store := NewMemoryRolesPermissionsStore()
	ctx := context.Background()
	_ = store.CreateRole(ctx, "admin", []string{"x"})
	_ = store.AddRoleToUser(ctx, "u1", "admin", "t1")
	roles, _ := store.GetRolesForUser(ctx, "u1", "t2")
	for _, r := range roles {
		if r == "admin" {
			t.Fatal("roles should be isolated by tenant")
		}
	}
}

// --- Tenant Store Tests ---

func TestMemoryTenantStore_CreateAndGet(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	tenant, err := store.CreateTenant(ctx, Tenant{ID: "tnt_001", Name: "Acme", IsActive: true})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if tenant.ID != "tnt_001" {
		t.Fatalf("unexpected ID: %s", tenant.ID)
	}
	found, err := store.GetTenantByID(ctx, "tnt_001")
	if err != nil {
		t.Fatalf("GetTenantByID: %v", err)
	}
	if found.Name != "Acme" {
		t.Fatalf("unexpected name: %s", found.Name)
	}
}

func TestMemoryTenantStore_GetTenantByID_NotFound(t *testing.T) {
	store := NewMemoryTenantStore()
	_, err := store.GetTenantByID(context.Background(), "nonexistent")
	if err != ErrTenantNotFound {
		t.Fatalf("expected ErrTenantNotFound, got %v", err)
	}
}

func TestMemoryTenantStore_DuplicateCreate(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	_, _ = store.CreateTenant(ctx, Tenant{ID: "tnt_dup"})
	_, err := store.CreateTenant(ctx, Tenant{ID: "tnt_dup"})
	if err != ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestMemoryTenantStore_GetAllTenants(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	_, _ = store.CreateTenant(ctx, Tenant{ID: "t1", Name: "T1"})
	_, _ = store.CreateTenant(ctx, Tenant{ID: "t2", Name: "T2"})
	all, err := store.GetAllTenants(ctx)
	if err != nil {
		t.Fatalf("GetAllTenants: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(all))
	}
}

func TestMemoryTenantStore_UpdateTenant(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	_, _ = store.CreateTenant(ctx, Tenant{ID: "tnt_upd", Name: "Old", IsActive: true})
	if err := store.UpdateTenant(ctx, "tnt_upd", Tenant{Name: "New", IsActive: false}); err != nil {
		t.Fatalf("UpdateTenant: %v", err)
	}
	updated, _ := store.GetTenantByID(ctx, "tnt_upd")
	if updated.Name != "New" {
		t.Fatalf("expected updated name, got %s", updated.Name)
	}
	if updated.IsActive {
		t.Fatal("expected inactive tenant")
	}
}

func TestMemoryTenantStore_UpdateTenant_NotFound(t *testing.T) {
	store := NewMemoryTenantStore()
	err := store.UpdateTenant(context.Background(), "nonexistent", Tenant{Name: "X"})
	if err != ErrTenantNotFound {
		t.Fatalf("expected ErrTenantNotFound, got %v", err)
	}
}

func TestMemoryTenantStore_DeleteTenant(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	_, _ = store.CreateTenant(ctx, Tenant{ID: "tnt_del"})
	if err := store.DeleteTenant(ctx, "tnt_del"); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	_, err := store.GetTenantByID(ctx, "tnt_del")
	if err != ErrTenantNotFound {
		t.Fatalf("expected ErrTenantNotFound after delete, got %v", err)
	}
}

func TestMemoryTenantStore_AssociateAndDisassociateUser(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	_, _ = store.CreateTenant(ctx, Tenant{ID: "tnt_assoc"})
	if err := store.AssociateUserWithTenant(ctx, "u1", "tnt_assoc"); err != nil {
		t.Fatalf("AssociateUserWithTenant: %v", err)
	}
	tenants, err := store.GetTenantsForUser(ctx, "u1")
	if err != nil {
		t.Fatalf("GetTenantsForUser: %v", err)
	}
	if len(tenants) != 1 || tenants[0].ID != "tnt_assoc" {
		t.Fatalf("unexpected tenants: %v", tenants)
	}
	if err := store.DisassociateUserFromTenant(ctx, "u1", "tnt_assoc"); err != nil {
		t.Fatalf("DisassociateUserFromTenant: %v", err)
	}
	tenants, _ = store.GetTenantsForUser(ctx, "u1")
	if len(tenants) != 0 {
		t.Fatalf("expected no tenants after disassociation, got %v", tenants)
	}
}

func TestMemoryTenantStore_AssociateUser_TenantNotFound(t *testing.T) {
	store := NewMemoryTenantStore()
	err := store.AssociateUserWithTenant(context.Background(), "u1", "nonexistent")
	if err != ErrTenantNotFound {
		t.Fatalf("expected ErrTenantNotFound, got %v", err)
	}
}

func TestMemoryTenantStore_GetUsersForTenant(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	_, _ = store.CreateTenant(ctx, Tenant{ID: "tnt_users"})
	_ = store.AssociateUserWithTenant(ctx, "u1", "tnt_users")
	_ = store.AssociateUserWithTenant(ctx, "u2", "tnt_users")
	users, err := store.GetUsersForTenant(ctx, "tnt_users")
	if err != nil {
		t.Fatalf("GetUsersForTenant: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestMemoryTenantStore_GetTenantsForUser_Empty(t *testing.T) {
	store := NewMemoryTenantStore()
	tenants, err := store.GetTenantsForUser(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("GetTenantsForUser: %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("expected empty list, got %v", tenants)
	}
}

func TestMemoryTenantStore_UserBelongsToMultipleTenants(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	_, _ = store.CreateTenant(ctx, Tenant{ID: "ta"})
	_, _ = store.CreateTenant(ctx, Tenant{ID: "tb"})
	_ = store.AssociateUserWithTenant(ctx, "u1", "ta")
	_ = store.AssociateUserWithTenant(ctx, "u1", "tb")
	tenants, _ := store.GetTenantsForUser(ctx, "u1")
	if len(tenants) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(tenants))
	}
}

func TestMemoryTenantStore_DeleteTenant_RemovesUserAssociations(t *testing.T) {
	store := NewMemoryTenantStore()
	ctx := context.Background()
	_, _ = store.CreateTenant(ctx, Tenant{ID: "tnt_cleanup"})
	_ = store.AssociateUserWithTenant(ctx, "u1", "tnt_cleanup")
	_ = store.DeleteTenant(ctx, "tnt_cleanup")
	tenants, _ := store.GetTenantsForUser(ctx, "u1")
	for _, t2 := range tenants {
		if t2.ID == "tnt_cleanup" {
			t.Fatal("deleted tenant should be removed from user associations")
		}
	}
}

// --- Service-level RBAC/Tenant helpers ---

func TestService_CreateRole_And_AssignRole(t *testing.T) {
	rbac := NewMemoryRolesPermissionsStore()
	cfg := testConfig("rbactest1234567890123456789012345")
	svc, _ := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore(), WithRolesPermissionsStore(rbac))
	ctx := context.Background()
	if err := svc.CreateRole(ctx, "moderator", []string{"posts:delete"}); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	user, _, _ := svc.Register(ctx, RegisterInput{Email: "mod@example.com", Password: "password1", TenantID: "t1"})
	if err := svc.AssignRole(ctx, user.ID, "moderator", "t1"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	ok, err := svc.UserHasPermission(ctx, user.ID, "posts:delete", "t1")
	if err != nil {
		t.Fatalf("UserHasPermission: %v", err)
	}
	if !ok {
		t.Fatal("user should have posts:delete permission")
	}
}

func TestService_CreateTenant_And_AddUserToTenant(t *testing.T) {
	tenantStore := NewMemoryTenantStore()
	cfg := testConfig("tenanttest1234567890123456789012")
	svc, _ := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore(), WithTenantStore(tenantStore))
	ctx := context.Background()
	tenant, err := svc.CreateTenant(ctx, "Acme Corp", nil)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	user, _, _ := svc.Register(ctx, RegisterInput{Email: "worker@example.com", Password: "password1", TenantID: "t1"})
	if err := svc.AddUserToTenant(ctx, user.ID, tenant.ID); err != nil {
		t.Fatalf("AddUserToTenant: %v", err)
	}
	tenants, _ := tenantStore.GetTenantsForUser(ctx, user.ID)
	if len(tenants) == 0 {
		t.Fatal("user should be associated with the new tenant")
	}
}

func TestService_UpdateMetadata_And_GetMetadata(t *testing.T) {
	meta := NewMemoryMetadataStore()
	cfg := testConfig("metatest1234567890123456789012345")
	svc, _ := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore(), WithMetadataStore(meta))
	ctx := context.Background()
	user, _, _ := svc.Register(ctx, RegisterInput{Email: "meta@example.com", Password: "password1", TenantID: "t1"})
	if err := svc.UpdateMetadata(ctx, user.ID, map[string]any{"plan": "pro"}); err != nil {
		t.Fatalf("UpdateMetadata: %v", err)
	}
	m, err := svc.GetMetadata(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetMetadata: %v", err)
	}
	if m["plan"] != "pro" {
		t.Fatalf("unexpected plan: %v", m["plan"])
	}
}

func TestService_GetMetadata_FeatureNotSupported(t *testing.T) {
	cfg := testConfig("metanosupport1234567890123456789")
	svc, _ := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	ctx := context.Background()
	_, err := svc.GetMetadata(ctx, "u1")
	if err != ErrFeatureNotSupported {
		t.Fatalf("expected ErrFeatureNotSupported, got %v", err)
	}
}

func TestService_CreateRole_FeatureNotSupported(t *testing.T) {
	cfg := testConfig("rbacnosupport1234567890123456789")
	svc, _ := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	ctx := context.Background()
	err := svc.CreateRole(ctx, "admin", nil)
	if err != ErrFeatureNotSupported {
		t.Fatalf("expected ErrFeatureNotSupported, got %v", err)
	}
}

func TestService_CreateTenant_FeatureNotSupported(t *testing.T) {
	cfg := testConfig("tenantnosupport123456789012345678")
	svc, _ := NewService(cfg, NewMemoryUserStore(), NewMemorySessionStore())
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, "X", nil)
	if err != ErrFeatureNotSupported {
		t.Fatalf("expected ErrFeatureNotSupported, got %v", err)
	}
}

// --- Telemetry store (basic smoke test) ---

func TestMemoryTelemetryStore_Record(t *testing.T) {
	store := NewMemoryTelemetryStore()
	ctx := context.Background()
	_ = store.Record(ctx, TelemetryEvent{
		EventName: "login",
		UserID:    "u1",
		TenantID:  "t1",
		Timestamp: time.Now(),
	})
	events, err := store.Query(ctx, TelemetryFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected at least 1 event")
	}
}

func TestMemoryTelemetryStore_FilterByUserID(t *testing.T) {
	store := NewMemoryTelemetryStore()
	ctx := context.Background()
	_ = store.Record(ctx, TelemetryEvent{EventName: "login", UserID: "u1", Timestamp: time.Now()})
	_ = store.Record(ctx, TelemetryEvent{EventName: "login", UserID: "u2", Timestamp: time.Now()})
	events, err := store.Query(ctx, TelemetryFilter{UserID: "u1"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, e := range events {
		if e.UserID != "u1" {
			t.Fatalf("expected only u1 events, got %s", e.UserID)
		}
	}
}
