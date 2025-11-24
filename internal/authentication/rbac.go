package authentication

import (
	"context"
	"fmt"
	"strings"
)

// RBACManager implements role-based access control
type RBACManager struct {
	roleRepo       RoleRepository
	userRepo       UserRepository
	auditLogger    AuditLogger
	permissionCache map[string]map[string]bool
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(
	roleRepo RoleRepository,
	userRepo UserRepository,
	auditLogger AuditLogger,
) *RBACManager {
	return &RBACManager{
		roleRepo:       roleRepo,
		userRepo:       userRepo,
		auditLogger:    auditLogger,
		permissionCache: make(map[string]map[string]bool),
	}
}

// HasPermission checks if a user has a specific permission
func (rbac *RBACManager) HasPermission(user *User, permission string) bool {
	if user == nil {
		return false
	}

	// Super admin has all permissions
	if strings.EqualFold(user.Role.Name, RoleSuperAdmin) {
		return true
	}

	// Check cached permissions first
	cacheKey := fmt.Sprintf("user:%d:role:%d", user.ID, user.RoleID)
	if permissions, exists := rbac.permissionCache[cacheKey]; exists {
		if hasPermission, ok := permissions[permission]; ok {
			return hasPermission
		}
	}

	// Load role permissions
	role, err := rbac.roleRepo.GetRoleByID(context.Background(), user.RoleID)
	if err != nil {
		return false
	}

	// Build permission map
	permissionMap := make(map[string]bool)
	for _, perm := range role.Permissions {
		permissionMap[perm] = true
		// Add wildcard permissions
		if parts := strings.Split(perm, ":"); len(parts) == 2 {
			resource := parts[0]
			permissionMap[resource+":*"] = true
		}
	}

	// Cache the permissions
	rbac.permissionCache[cacheKey] = permissionMap

	// Check specific permission
	if hasPermission, ok := permissionMap[permission]; ok {
		return hasPermission
	}

	// Check wildcard permissions
	if parts := strings.Split(permission, ":"); len(parts) == 2 {
		resource := parts[0]
		if hasWildcard, ok := permissionMap[resource+":*"]; ok {
			return hasWildcard
		}
	}

	return false
}

// HasAnyPermission checks if a user has any of the specified permissions
func (rbac *RBACManager) HasAnyPermission(user *User, permissions []string) bool {
	for _, permission := range permissions {
		if rbac.HasPermission(user, permission) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if a user has all of the specified permissions
func (rbac *RBACManager) HasAllPermissions(user *User, permissions []string) bool {
	for _, permission := range permissions {
		if !rbac.HasPermission(user, permission) {
			return false
		}
	}
	return true
}

// GetUserPermissions returns all permissions for a user
func (rbac *RBACManager) GetUserPermissions(ctx context.Context, user *User) ([]string, error) {
	role, err := rbac.roleRepo.GetRoleByID(ctx, user.RoleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user role: %w", err)
	}

	permissions := make([]string, len(role.Permissions))
	copy(permissions, role.Permissions)

	return permissions, nil
}

// CanAccessResource checks if a user can access a specific resource with a given action
func (rbac *RBACManager) CanAccessResource(user *User, resource, action string) bool {
	permission := fmt.Sprintf("%s:%s", resource, action)
	return rbac.HasPermission(user, permission)
}

// AssignRoleToUser assigns a role to a user
func (rbac *RBACManager) AssignRoleToUser(ctx context.Context, userID, roleID int64, assignedBy int64) error {
	// Check if the assigning user has permission to assign roles
	assigner, err := rbac.userRepo.GetUserByID(ctx, assignedBy)
	if err != nil {
		return fmt.Errorf("failed to get assigning user: %w", err)
	}

	if !rbac.HasPermission(assigner, PermUserWrite) {
		rbac.auditLogger.LogUserAction(ctx, assignedBy, "role_assign_denied", "user", fmt.Sprintf("%d", userID), map[string]interface{}{
			"role_id":    roleID,
			"target_user_id": userID,
		}, false, "", "")
		return fmt.Errorf("insufficient permissions to assign roles")
	}

	// Get the role to assign
	role, err := rbac.roleRepo.GetRoleByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	// Cannot assign system roles unless you're a super admin
	if role.SystemRole && !strings.EqualFold(assigner.Role.Name, RoleSuperAdmin) {
		return fmt.Errorf("only super admin can assign system roles")
	}

	// Assign the role
	err = rbac.roleRepo.AssignRoleToUser(ctx, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	// Clear permission cache for the user
	cacheKey := fmt.Sprintf("user:%d:role:%d", userID, roleID)
	delete(rbac.permissionCache, cacheKey)

	rbac.auditLogger.LogUserAction(ctx, assignedBy, "role_assigned", "user", fmt.Sprintf("%d", userID), map[string]interface{}{
		"role_id":   roleID,
		"role_name": role.Name,
	}, true, "", "")

	return nil
}

// RemoveRoleFromUser removes a role from a user
func (rbac *RBACManager) RemoveRoleFromUser(ctx context.Context, userID, removedBy int64) error {
	// Check permissions
	remover, err := rbac.userRepo.GetUserByID(ctx, removedBy)
	if err != nil {
		return fmt.Errorf("failed to get removing user: %w", err)
	}

	if !rbac.HasPermission(remover, PermUserWrite) {
		return fmt.Errorf("insufficient permissions to remove roles")
	}

	// Get current role to clear cache
	user, err := rbac.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Remove the role
	err = rbac.roleRepo.RemoveRoleFromUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}

	// Clear permission cache
	cacheKey := fmt.Sprintf("user:%d:role:%d", userID, user.RoleID)
	delete(rbac.permissionCache, cacheKey)

	rbac.auditLogger.LogUserAction(ctx, removedBy, "role_removed", "user", fmt.Sprintf("%d", userID), map[string]interface{}{
		"previous_role_id":   user.RoleID,
	}, true, "", "")

	return nil
}

// CreateRole creates a new role
func (rbac *RBACManager) CreateRole(ctx context.Context, role *Role, createdBy int64) error {
	// Check permissions
	creator, err := rbac.userRepo.GetUserByID(ctx, createdBy)
	if err != nil {
		return fmt.Errorf("failed to get creating user: %w", err)
	}

	if !rbac.HasPermission(creator, PermUserWrite) {
		return fmt.Errorf("insufficient permissions to create roles")
	}

	// Cannot create system roles through API
	if role.SystemRole {
		return fmt.Errorf("cannot create system roles through API")
	}

	// Validate permissions
	if !rbac.validatePermissions(role.Permissions) {
		return fmt.Errorf("invalid permissions specified")
	}

	// Create the role
	err = rbac.roleRepo.CreateRole(ctx, role)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	rbac.auditLogger.LogUserAction(ctx, createdBy, "role_created", "role", fmt.Sprintf("%d", role.ID), map[string]interface{}{
		"role_name":    role.Name,
		"permissions":  role.Permissions,
	}, true, "", "")

	return nil
}

// UpdateRole updates an existing role
func (rbac *RBACManager) UpdateRole(ctx context.Context, role *Role, updatedBy int64) error {
	// Check permissions
	updater, err := rbac.userRepo.GetUserByID(ctx, updatedBy)
	if err != nil {
		return fmt.Errorf("failed to get updating user: %w", err)
	}

	if !rbac.HasPermission(updater, PermUserWrite) {
		return fmt.Errorf("insufficient permissions to update roles")
	}

	// Get existing role
	existingRole, err := rbac.roleRepo.GetRoleByID(ctx, role.ID)
	if err != nil {
		return fmt.Errorf("failed to get existing role: %w", err)
	}

	// Cannot modify system roles unless you're a super admin
	if existingRole.SystemRole && !strings.EqualFold(updater.Role.Name, RoleSuperAdmin) {
		return fmt.Errorf("only super admin can modify system roles")
	}

	// Validate permissions
	if !rbac.validatePermissions(role.Permissions) {
		return fmt.Errorf("invalid permissions specified")
	}

	// Update the role
	err = rbac.roleRepo.UpdateRole(ctx, role)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	// Clear all permission caches (since role permissions changed)
	rbac.permissionCache = make(map[string]map[string]bool)

	rbac.auditLogger.LogUserAction(ctx, updatedBy, "role_updated", "role", fmt.Sprintf("%d", role.ID), map[string]interface{}{
		"role_name":       role.Name,
		"old_permissions": existingRole.Permissions,
		"new_permissions": role.Permissions,
	}, true, "", "")

	return nil
}

// DeleteRole deletes a role
func (rbac *RBACManager) DeleteRole(ctx context.Context, roleID int64, deletedBy int64) error {
	// Check permissions
	deleter, err := rbac.userRepo.GetUserByID(ctx, deletedBy)
	if err != nil {
		return fmt.Errorf("failed to get deleting user: %w", err)
	}

	if !rbac.HasPermission(deleter, PermUserWrite) {
		return fmt.Errorf("insufficient permissions to delete roles")
	}

	// Get existing role
	role, err := rbac.roleRepo.GetRoleByID(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	// Cannot delete system roles
	if role.SystemRole {
		return fmt.Errorf("cannot delete system roles")
	}

	// Delete the role
	err = rbac.roleRepo.DeleteRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rbac.auditLogger.LogUserAction(ctx, deletedBy, "role_deleted", "role", fmt.Sprintf("%d", roleID), map[string]interface{}{
		"role_name": role.Name,
	}, true, "", "")

	return nil
}

// ListRoles lists all available roles
func (rbac *RBACManager) ListRoles(ctx context.Context) ([]*Role, error) {
	return rbac.roleRepo.ListRoles(ctx)
}

// GetRoleUsers returns all users with a specific role
func (rbac *RBACManager) GetRoleUsers(ctx context.Context, roleID int64) ([]*User, error) {
	// This would require implementing a method in the UserRepository
	// For now, we'll return all users and filter
	users, _, err := rbac.userRepo.ListUsers(ctx, &UserFilter{
		RoleID: &roleID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get role users: %w", err)
	}

	return users, nil
}

// validatePermissions validates that all permissions are recognized
func (rbac *RBACManager) validatePermissions(permissions []string) bool {
	validPermissions := map[string]bool{
		// System permissions
		PermSystemRead:  true,
		PermSystemWrite: true,
		PermSystemAdmin: true,

		// Provider permissions
		PermProviderRead:   true,
		PermProviderWrite:  true,
		PermProviderDelete: true,

		// Model permissions
		PermModelRead:    true,
		PermModelWrite:   true,
		PermModelDelete:  true,

		// Configuration permissions
		PermConfigRead:  true,
		PermConfigWrite: true,

		// User management permissions
		PermUserRead:   true,
		PermUserWrite:  true,
		PermUserDelete: true,

		// API key permissions
		PermAPIKeyRead:   true,
		PermAPIKeyWrite:  true,
		PermAPIKeyDelete: true,

		// Monitoring permissions
		PermMonitoringRead: true,
		PermMetricsRead:    true,

		// Audit permissions
		PermAuditRead:   true,
		PermAuditExport: true,

		// Health permissions
		PermHealthRead: true,

		// Wildcard permissions
		"system:*":    true,
		"provider:*":  true,
		"model:*":     true,
		"config:*":    true,
		"user:*":      true,
		"apikey:*":    true,
		"monitoring:*": true,
		"audit:*":     true,
		"health:*":    true,
	}

	for _, perm := range permissions {
		if !validPermissions[perm] {
			return false
		}
	}

	return true
}

// PermissionGroup represents a group of related permissions
type PermissionGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// GetPermissionGroups returns predefined permission groups
func (rbac *RBACManager) GetPermissionGroups() []PermissionGroup {
	return []PermissionGroup{
		{
			Name:        "System Management",
			Description: "Full system administration",
			Permissions: []string{PermSystemAdmin, PermSystemWrite, PermSystemRead},
		},
		{
			Name:        "Provider Management",
			Description: "Manage LLM providers",
			Permissions: []string{PermProviderWrite, PermProviderRead, PermProviderDelete},
		},
		{
			Name:        "Model Management",
			Description: "Manage AI models",
			Permissions: []string{PermModelWrite, PermModelRead, PermModelDelete},
		},
		{
			Name:        "Configuration",
			Description: "System configuration",
			Permissions: []string{PermConfigWrite, PermConfigRead},
		},
		{
			Name:        "User Management",
			Description: "Manage users and roles",
			Permissions: []string{PermUserWrite, PermUserRead, PermUserDelete},
		},
		{
			Name:        "API Key Management",
			Description: "Manage API keys",
			Permissions: []string{PermAPIKeyWrite, PermAPIKeyRead, PermAPIKeyDelete},
		},
		{
			Name:        "Monitoring",
			Description: "View system metrics and health",
			Permissions: []string{PermMonitoringRead, PermMetricsRead, PermHealthRead},
		},
		{
			Name:        "Auditing",
			Description: "Access audit logs and compliance data",
			Permissions: []string{PermAuditRead, PermAuditExport},
		},
	}
}

// CheckPermissionHierarchy checks if one permission implies another
func (rbac *RBACManager) CheckPermissionHierarchy(required string, has string) bool {
	// Admin permissions imply all others
	if has == PermSystemAdmin || has == "system:*" {
		return true
	}

	// Exact match
	if required == has {
		return true
	}

	// Check wildcard permissions
	if strings.HasSuffix(has, ":*") {
		resource := strings.TrimSuffix(has, ":*")
		if strings.HasPrefix(required, resource+":") {
			return true
		}
	}

	return false
}

// GetEffectivePermissions returns the effective permissions for a user (including inherited)
func (rbac *RBACManager) GetEffectivePermissions(ctx context.Context, user *User) (map[string]bool, error) {
	permissions, err := rbac.GetUserPermissions(ctx, user)
	if err != nil {
		return nil, err
	}

	effective := make(map[string]bool)

	for _, perm := range permissions {
		effective[perm] = true

		// Add implied permissions
		parts := strings.Split(perm, ":")
		if len(parts) == 2 && parts[1] == "*" {
			resource := parts[0]
			// Wildcard implies all actions for this resource
			effective[resource+":read"] = true
			effective[resource+":write"] = true
			effective[resource+":delete"] = true
		}
	}

	return effective, nil
}