package auth

import (
	"context"
	"sort"
	"sync"
)

// MemoryMetadataStore is an in-memory implementation of UserMetadataStore.
type MemoryMetadataStore struct {
	mu   sync.RWMutex
	data map[string]map[string]any
}

func NewMemoryMetadataStore() *MemoryMetadataStore {
	return &MemoryMetadataStore{data: make(map[string]map[string]any)}
}

func (s *MemoryMetadataStore) GetMetadata(_ context.Context, userID string) (map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	current := s.data[userID]
	out := make(map[string]any, len(current))
	for k, v := range current {
		out[k] = v
	}
	return out, nil
}

func (s *MemoryMetadataStore) UpdateMetadata(_ context.Context, userID string, metadata map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.data[userID]
	if current == nil {
		current = make(map[string]any)
	}
	for k, v := range metadata {
		current[k] = v
	}
	s.data[userID] = current
	return nil
}

func (s *MemoryMetadataStore) ClearMetadata(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, userID)
	return nil
}

// MemoryRolesPermissionsStore is an in-memory RBAC store.
type MemoryRolesPermissionsStore struct {
	mu              sync.RWMutex
	rolePermissions map[string]map[string]struct{}
	userRoles       map[string]map[string]map[string]struct{}
}

func NewMemoryRolesPermissionsStore() *MemoryRolesPermissionsStore {
	return &MemoryRolesPermissionsStore{
		rolePermissions: make(map[string]map[string]struct{}),
		userRoles:       make(map[string]map[string]map[string]struct{}),
	}
}

func (s *MemoryRolesPermissionsStore) AddRoleToUser(_ context.Context, userID, role string, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rolePermissions[role]; !ok {
		return ErrRoleNotFound
	}
	if s.userRoles[userID] == nil {
		s.userRoles[userID] = make(map[string]map[string]struct{})
	}
	if s.userRoles[userID][tenantID] == nil {
		s.userRoles[userID][tenantID] = make(map[string]struct{})
	}
	s.userRoles[userID][tenantID][role] = struct{}{}
	return nil
}

func (s *MemoryRolesPermissionsStore) RemoveRoleFromUser(_ context.Context, userID, role string, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.userRoles[userID] != nil && s.userRoles[userID][tenantID] != nil {
		delete(s.userRoles[userID][tenantID], role)
	}
	return nil
}

func (s *MemoryRolesPermissionsStore) GetRolesForUser(_ context.Context, userID, tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userScoped := s.userRoles[userID]
	if userScoped == nil {
		return nil, nil
	}
	rolesMap := userScoped[tenantID]
	roles := make([]string, 0, len(rolesMap))
	for role := range rolesMap {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles, nil
}

func (s *MemoryRolesPermissionsStore) CreateRole(_ context.Context, role string, permissions []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	permSet := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		permSet[permission] = struct{}{}
	}
	s.rolePermissions[role] = permSet
	return nil
}

func (s *MemoryRolesPermissionsStore) DeleteRole(_ context.Context, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rolePermissions, role)
	for userID := range s.userRoles {
		for tenantID := range s.userRoles[userID] {
			delete(s.userRoles[userID][tenantID], role)
		}
	}
	return nil
}

func (s *MemoryRolesPermissionsStore) AddPermissionToRole(_ context.Context, role, permission string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rolePermissions[role] == nil {
		s.rolePermissions[role] = make(map[string]struct{})
	}
	s.rolePermissions[role][permission] = struct{}{}
	return nil
}

func (s *MemoryRolesPermissionsStore) RemovePermissionFromRole(_ context.Context, role, permission string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rolePermissions[role], permission)
	return nil
}

func (s *MemoryRolesPermissionsStore) GetPermissionsForRole(_ context.Context, role string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	perms := make([]string, 0, len(s.rolePermissions[role]))
	for permission := range s.rolePermissions[role] {
		perms = append(perms, permission)
	}
	sort.Strings(perms)
	return perms, nil
}

func (s *MemoryRolesPermissionsStore) GetPermissionsForUser(ctx context.Context, userID, tenantID string) ([]string, error) {
	roles, err := s.GetRolesForUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	permissions := make([]string, 0, len(roles)*2)
	for _, role := range roles {
		perms, err := s.GetPermissionsForRole(ctx, role)
		if err != nil {
			return nil, err
		}
		for _, permission := range perms {
			if _, ok := seen[permission]; ok {
				continue
			}
			seen[permission] = struct{}{}
			permissions = append(permissions, permission)
		}
	}
	sort.Strings(permissions)
	return permissions, nil
}

func (s *MemoryRolesPermissionsStore) UserHasPermission(ctx context.Context, userID, permission, tenantID string) (bool, error) {
	permissions, err := s.GetPermissionsForUser(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	for _, current := range permissions {
		if current == permission {
			return true, nil
		}
	}
	return false, nil
}

// MemoryTenantStore is an in-memory tenant/membership store.
type MemoryTenantStore struct {
	mu          sync.RWMutex
	byID        map[string]Tenant
	userTenants map[string]map[string]struct{}
	tenantUsers map[string]map[string]struct{}
}

func NewMemoryTenantStore() *MemoryTenantStore {
	return &MemoryTenantStore{
		byID:        make(map[string]Tenant),
		userTenants: make(map[string]map[string]struct{}),
		tenantUsers: make(map[string]map[string]struct{}),
	}
}

func (s *MemoryTenantStore) CreateTenant(_ context.Context, tenant Tenant) (Tenant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[tenant.ID]; exists {
		return Tenant{}, ErrAlreadyExists
	}
	s.byID[tenant.ID] = tenant
	return tenant, nil
}

func (s *MemoryTenantStore) GetTenantByID(_ context.Context, id string) (Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tenant, ok := s.byID[id]
	if !ok {
		return Tenant{}, ErrTenantNotFound
	}
	return tenant, nil
}

func (s *MemoryTenantStore) GetAllTenants(_ context.Context) ([]Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.byID))
	for _, tenant := range s.byID {
		out = append(out, tenant)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryTenantStore) UpdateTenant(_ context.Context, id string, update Tenant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.byID[id]
	if !ok {
		return ErrTenantNotFound
	}
	current.Name = update.Name
	current.IsActive = update.IsActive
	current.Config = update.Config
	s.byID[id] = current
	return nil
}

func (s *MemoryTenantStore) DeleteTenant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
	delete(s.tenantUsers, id)
	for userID := range s.userTenants {
		delete(s.userTenants[userID], id)
	}
	return nil
}

func (s *MemoryTenantStore) AssociateUserWithTenant(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[tenantID]; !ok {
		return ErrTenantNotFound
	}
	if s.userTenants[userID] == nil {
		s.userTenants[userID] = make(map[string]struct{})
	}
	if s.tenantUsers[tenantID] == nil {
		s.tenantUsers[tenantID] = make(map[string]struct{})
	}
	s.userTenants[userID][tenantID] = struct{}{}
	s.tenantUsers[tenantID][userID] = struct{}{}
	return nil
}

func (s *MemoryTenantStore) DisassociateUserFromTenant(_ context.Context, userID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.userTenants[userID] != nil {
		delete(s.userTenants[userID], tenantID)
	}
	if s.tenantUsers[tenantID] != nil {
		delete(s.tenantUsers[tenantID], userID)
	}
	return nil
}

func (s *MemoryTenantStore) GetTenantsForUser(_ context.Context, userID string) ([]Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.userTenants[userID]))
	for tenantID := range s.userTenants[userID] {
		if tenant, ok := s.byID[tenantID]; ok {
			out = append(out, tenant)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *MemoryTenantStore) GetUsersForTenant(_ context.Context, tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.tenantUsers[tenantID]))
	for userID := range s.tenantUsers[tenantID] {
		out = append(out, userID)
	}
	sort.Strings(out)
	return out, nil
}
