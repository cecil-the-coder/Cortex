package authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// AdminAuthHandlers handles authentication-related admin endpoints
type AdminAuthHandlers struct {
	authManager  AuthenticationManager
	rbacManager  *RBACManager
	auditLogger  AuditLogger
	config       AuthenticationConfig
}

// NewAdminAuthHandlers creates new admin authentication handlers
func NewAdminAuthHandlers(
	authManager AuthenticationManager,
	rbacManager *RBACManager,
	auditLogger AuditLogger,
	config AuthenticationConfig,
) *AdminAuthHandlers {
	return &AdminAuthHandlers{
		authManager: authManager,
		rbacManager: rbacManager,
		auditLogger: auditLogger,
		config:      config,
	}
}

// Request/Response types

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TFACode  string `json:"tfa_code,omitempty"`
	Remember bool   `json:"remember,omitempty"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	User         *UserInfo    `json:"user"`
	SessionToken string       `json:"session_token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresAt    time.Time    `json:"expires_at"`
	Permissions  []string     `json:"permissions"`
	MFARequired  bool         `json:"mfa_required"`
	Message      string       `json:"message,omitempty"`
}

// UserInfo represents user information in responses
type UserInfo struct {
	ID           int64       `json:"id"`
	Username     string      `json:"username"`
	Email        string      `json:"email"`
	FullName     string      `json:"full_name"`
	Role         *RoleInfo   `json:"role"`
	Enabled      bool        `json:"enabled"`
	TFAEnabled   bool        `json:"tfa_enabled"`
	LastLogin    *time.Time  `json:"last_login,omitempty"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

// RoleInfo represents role information in responses
type RoleInfo struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name,omitempty"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	System      bool      `json:"system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserCreateRequest represents a user creation request
type UserCreateRequest struct {
	Username  string      `json:"username"`
	Email     string      `json:"email"`
	Password  string      `json:"password"`
	FullName  string      `json:"full_name"`
	RoleID    int64       `json:"role_id"`
	Enabled   bool        `json:"enabled"`
	TFAEnabled bool       `json:"tfa_enabled,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// UserUpdateRequest represents a user update request
type UserUpdateRequest struct {
	Email      *string    `json:"email,omitempty"`
	FullName   *string    `json:"full_name,omitempty"`
	RoleID     *int64     `json:"role_id,omitempty"`
	Enabled    *bool      `json:"enabled,omitempty"`
	TFAEnabled *bool      `json:"tfa_enabled,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// PasswordChangeRequest represents a password change request
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// PasswordResetConfirmRequest represents a password reset confirmation
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}


// TFASetupRequest represents TFA setup request
type TFASetupRequest struct {
	Method  string `json:"method"`
	Code    string `json:"code,omitempty"`
	Config  map[string]interface{} `json:"config,omitempty"`
}

// TFASetupResponse represents TFA setup response
type TFASetupResponse struct {
	Secret   string            `json:"secret,omitempty"`
	QRCode   string            `json:"qr_code,omitempty"`
	BackupCodes []string        `json:"backup_codes,omitempty"`
	Method   string            `json:"method"`
	Enabled  bool              `json:"enabled"`
}

// Authentication endpoints

// handleLogin handles user login
func (h *AdminAuthHandlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	if req.Username == "" || req.Password == "" {
		h.sendError(w, http.StatusBadRequest, "missing_credentials", "Username and password are required")
		return
	}

	ipAddress := h.getClientIP(r)
	userAgent := r.Header.Get("User-Agent")

	// Attempt authentication
	var user *User
	var session *UserSession
	var err error

	if req.TFACode != "" {
		user, session, err = h.authManager.AuthenticateUserWithTFB(r.Context(), req.Username, req.Password, req.TFACode, ipAddress, userAgent)
	} else {
		user, session, err = h.authManager.AuthenticateUser(r.Context(), req.Username, req.Password, ipAddress, userAgent)
	}

	if err != nil {
		// Log failed login
		h.auditLogger.LogLoginAttempt(r.Context(), req.Username, ipAddress, userAgent, false, err.Error(), nil)

		// Check if it's a TFA required error
		if err.Error() == "tfa_required" {
			response := LoginResponse{
				MFARequired: true,
				Message:     "Two-factor authentication code required",
			}
			h.sendResponse(w, http.StatusOK, response)
			return
		}

		h.sendError(w, http.StatusUnauthorized, "authentication_failed", "Invalid credentials")
		return
	}

	// Get user permissions
	permissions, err := h.rbacManager.GetUserPermissions(r.Context(), user)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "permission_error", "Failed to get user permissions")
		return
	}

	// Prepare response
	response := LoginResponse{
		User: &UserInfo{
			ID:         user.ID,
			Username:   user.Username,
			Email:      user.Email,
			FullName:   user.FullName,
			Role: &RoleInfo{
				ID:          user.Role.ID,
				Name:        user.Role.Name,
				Description: user.Role.Description,
				Permissions: user.Role.Permissions,
			},
			Enabled:    user.Enabled,
			TFAEnabled: user.TFAEnabled,
			LastLogin:  user.LastLogin,
			CreatedAt:  user.CreatedAt,
			UpdatedAt:  user.UpdatedAt,
		},
		SessionToken: session.SessionToken,
		RefreshToken: session.RefreshToken,
		ExpiresAt:    session.ExpiresAt,
		Permissions:  permissions,
		MFARequired:  false,
		Message:      "Login successful",
	}

	// Log successful login
	h.auditLogger.LogLoginAttempt(r.Context(), req.Username, ipAddress, userAgent, true, "success", &user.ID)

	h.sendResponse(w, http.StatusOK, response)
}

// handleLogout handles user logout
func (h *AdminAuthHandlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	token := h.getTokenFromContext(r.Context())
	if token != "" {
		err := h.authManager.LogoutUser(r.Context(), token)
		if err != nil {
			h.sendError(w, http.StatusInternalServerError, "logout_failed", "Failed to logout")
			return
		}
	}

	h.auditLogger.LogUserAction(r.Context(), user.ID, "logout", "session", "", map[string]interface{}{
		"ip_address": h.getClientIP(r),
	}, true, h.getClientIP(r), r.Header.Get("User-Agent"))

	response := map[string]interface{}{
		"message": "Logout successful",
	}

	h.sendResponse(w, http.StatusOK, response)
}

// handleRefreshToken handles token refresh
func (h *AdminAuthHandlers) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	if req.RefreshToken == "" {
		h.sendError(w, http.StatusBadRequest, "missing_token", "Refresh token is required")
		return
	}

	session, err := h.authManager.RefreshSession(r.Context(), req.RefreshToken)
	if err != nil {
		h.sendError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired refresh token")
		return
	}

	response := map[string]interface{}{
		"session_token": session.SessionToken,
		"refresh_token": session.RefreshToken,
		"expires_at":    session.ExpiresAt,
		"message":       "Token refreshed successfully",
	}

	h.sendResponse(w, http.StatusOK, response)
}

// handleMe returns current user information
func (h *AdminAuthHandlers) handleMe(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	permissions, err := h.rbacManager.GetUserPermissions(r.Context(), user)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "permission_error", "Failed to get user permissions")
		return
	}

	userInfo := &UserInfo{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		FullName:   user.FullName,
		Role: &RoleInfo{
			ID:          user.Role.ID,
			Name:        user.Role.Name,
			Description: user.Role.Description,
			Permissions: user.Role.Permissions,
		},
		Enabled:    user.Enabled,
		TFAEnabled: user.TFAEnabled,
		LastLogin:  user.LastLogin,
		CreatedAt:  user.CreatedAt,
		UpdatedAt:  user.UpdatedAt,
	}

	response := map[string]interface{}{
		"user":        userInfo,
		"permissions": permissions,
	}

	h.sendResponse(w, http.StatusOK, response)
}

// User management endpoints

// handleListUsers handles user listing
func (h *AdminAuthHandlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if !h.rbacManager.HasPermission(user, PermUserRead) {
		h.sendError(w, http.StatusForbidden, "insufficient_permissions", "Permission required to read users")
		return
	}

	filter := h.parseUserFilter(r)
	users, total, err := h.authManager.ListUsers(r.Context(), filter)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "list_failed", "Failed to list users")
		return
	}

	userInfos := make([]*UserInfo, len(users))
	for i, u := range users {
		userInfos[i] = &UserInfo{
			ID:         u.ID,
			Username:   u.Username,
			Email:      u.Email,
			FullName:   u.FullName,
			Role: &RoleInfo{
				ID:          u.Role.ID,
				Name:        u.Role.Name,
				Description: u.Role.Description,
			},
			Enabled:    u.Enabled,
			TFAEnabled: u.TFAEnabled,
			LastLogin:  u.LastLogin,
			CreatedAt:  u.CreatedAt,
			UpdatedAt:  u.UpdatedAt,
		}
	}

	response := map[string]interface{}{
		"users": userInfos,
		"total": total,
	}

	h.sendResponse(w, http.StatusOK, response)
}

// handleCreateUser handles user creation
func (h *AdminAuthHandlers) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if !h.rbacManager.HasPermission(user, PermUserWrite) {
		h.sendError(w, http.StatusForbidden, "insufficient_permissions", "Permission required to create users")
		return
	}

	var req UserCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Validate request
	if err := h.validateUserCreateRequest(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	// Create user
	newUser := &User{
		Username:   req.Username,
		Email:      req.Email,
		FullName:   req.FullName,
		RoleID:     req.RoleID,
		Enabled:    req.Enabled,
		TFAEnabled: req.TFAEnabled,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	err := h.authManager.CreateUser(r.Context(), newUser, req.Password)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "creation_failed", "Failed to create user: "+err.Error())
		return
	}

	h.auditLogger.LogUserAction(r.Context(), user.ID, "user_created", "user", fmt.Sprintf("%d", newUser.ID), map[string]interface{}{
		"username":   req.Username,
		"email":      req.Email,
		"role_id":    req.RoleID,
		"created_by": user.ID,
	}, true, h.getClientIP(r), r.Header.Get("User-Agent"))

	// Return created user info (without sensitive data)
	userInfo := &UserInfo{
		ID:        newUser.ID,
		Username:  newUser.Username,
		Email:     newUser.Email,
		FullName:  newUser.FullName,
		Role:      nil, // Will be populated by database
		Enabled:   newUser.Enabled,
		TFAEnabled: newUser.TFAEnabled,
		CreatedAt: newUser.CreatedAt,
		UpdatedAt: newUser.UpdatedAt,
	}

	response := map[string]interface{}{
		"user":    userInfo,
		"message": "User created successfully",
	}

	h.sendResponse(w, http.StatusCreated, response)
}

// handleUpdateUser handles user updates
func (h *AdminAuthHandlers) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if !h.rbacManager.HasPermission(user, PermUserWrite) {
		h.sendError(w, http.StatusForbidden, "insufficient_permissions", "Permission required to update users")
		return
	}

	vars := mux.Vars(r)
	userIDStr := vars["id"]
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_user_id", "Invalid user ID")
		return
	}

	var req UserUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Get existing user
	targetUser, err := h.authManager.GetUserByID(r.Context(), userID)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "user_not_found", "User not found")
		return
	}

	// Apply updates
	oldValues := make(map[string]interface{})
	if req.Email != nil {
		oldValues["email"] = targetUser.Email
		targetUser.Email = *req.Email
	}
	if req.FullName != nil {
		oldValues["full_name"] = targetUser.FullName
		targetUser.FullName = *req.FullName
	}
	if req.RoleID != nil {
		oldValues["role_id"] = targetUser.RoleID
		targetUser.RoleID = *req.RoleID
	}
	if req.Enabled != nil {
		oldValues["enabled"] = targetUser.Enabled
		targetUser.Enabled = *req.Enabled
	}
	if req.TFAEnabled != nil {
		oldValues["tfa_enabled"] = targetUser.TFAEnabled
		targetUser.TFAEnabled = *req.TFAEnabled
	}

	targetUser.UpdatedAt = time.Now()

	// Update user
	err = h.authManager.UpdateUser(r.Context(), targetUser)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "update_failed", "Failed to update user: "+err.Error())
		return
	}

	h.auditLogger.LogUserAction(r.Context(), user.ID, "user_updated", "user", fmt.Sprintf("%d", userID), map[string]interface{}{
		"target_user_id": userID,
		"old_values":     oldValues,
		"new_values":     req,
	}, true, h.getClientIP(r), r.Header.Get("User-Agent"))

	// Return updated user info
	userInfo := &UserInfo{
		ID:         targetUser.ID,
		Username:   targetUser.Username,
		Email:      targetUser.Email,
		FullName:   targetUser.FullName,
		Role:       h.convertRoleToRoleInfo(targetUser.Role),
		Enabled:    targetUser.Enabled,
		TFAEnabled: targetUser.TFAEnabled,
		UpdatedAt:  targetUser.UpdatedAt,
	}

	response := map[string]interface{}{
		"user":    userInfo,
		"message": "User updated successfully",
	}

	h.sendResponse(w, http.StatusOK, response)
}

// handleDeleteUser handles user deletion
func (h *AdminAuthHandlers) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	if !h.rbacManager.HasPermission(user, PermUserDelete) {
		h.sendError(w, http.StatusForbidden, "insufficient_permissions", "Permission required to delete users")
		return
	}

	vars := mux.Vars(r)
	userIDStr := vars["id"]
	userID, err := strconv.ParseInt(userIDStr, 10, 64)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_user_id", "Invalid user ID")
		return
	}

	// Prevent self-deletion
	if userID == user.ID {
		h.sendError(w, http.StatusBadRequest, "self_deletion", "Cannot delete your own account")
		return
	}

	// Get user to delete for logging
	targetUser, err := h.authManager.GetUserByID(r.Context(), userID)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "user_not_found", "User not found")
		return
	}

	// Delete user
	err = h.authManager.DeleteUser(r.Context(), userID)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "deletion_failed", "Failed to delete user: "+err.Error())
		return
	}

	h.auditLogger.LogUserAction(r.Context(), user.ID, "user_deleted", "user", fmt.Sprintf("%d", userID), map[string]interface{}{
		"deleted_username": targetUser.Username,
		"deleted_email":    targetUser.Email,
	}, true, h.getClientIP(r), r.Header.Get("User-Agent"))

	response := map[string]interface{}{
		"message": "User deleted successfully",
	}

	h.sendResponse(w, http.StatusOK, response)
}

// Password management endpoints

// handleChangePassword handles password changes
func (h *AdminAuthHandlers) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req PasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Validate request
	if req.CurrentPassword == "" || req.NewPassword == "" || req.ConfirmPassword == "" {
		h.sendError(w, http.StatusBadRequest, "missing_fields", "All password fields are required")
		return
	}

	if req.NewPassword != req.ConfirmPassword {
		h.sendError(w, http.StatusBadRequest, "password_mismatch", "New password and confirmation do not match")
		return
	}

	// Change password
	err := h.authManager.ChangePassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "password_change_failed", "Failed to change password: "+err.Error())
		return
	}

	h.auditLogger.LogUserAction(r.Context(), user.ID, "password_changed", "user", fmt.Sprintf("%d", user.ID), map[string]interface{}{
		"ip_address": h.getClientIP(r),
	}, true, h.getClientIP(r), r.Header.Get("User-Agent"))

	response := map[string]interface{}{
		"message": "Password changed successfully",
	}

	h.sendResponse(w, http.StatusOK, response)
}

// TFA endpoints

// handleSetupTFA handles TFA setup
func (h *AdminAuthHandlers) handleSetupTFA(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req TFASetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	if req.Method != "totp" {
		h.sendError(w, http.StatusBadRequest, "unsupported_method", "Only TOTP method is currently supported")
		return
	}

	// Generate TFA secret
	secret, qrCode, err := h.authManager.GenerateTFASecret(user.ID)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "setup_failed", "Failed to setup TFA: "+err.Error())
		return
	}

	response := TFASetupResponse{
		Secret:  secret,
		QRCode:  qrCode,
		Method:  req.Method,
		Enabled: false,
	}

	h.sendResponse(w, http.StatusOK, response)
}

// handleEnableTFA handles enabling TFA
func (h *AdminAuthHandlers) handleEnableTFA(w http.ResponseWriter, r *http.Request) {
	user := h.getUserFromContext(r.Context())
	if user == nil {
		h.sendError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON format")
		return
	}

	// Verify TFA code
	if !h.authManager.ValidateTFA(user.ID, req.Code) {
		h.sendError(w, http.StatusBadRequest, "invalid_code", "Invalid TFA code")
		return
	}

	// Enable TFA
	err := h.authManager.EnableTFA(r.Context(), user.ID, req.Secret)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "enable_failed", "Failed to enable TFA: "+err.Error())
		return
	}

	h.auditLogger.LogUserAction(r.Context(), user.ID, "tfa_enabled", "user", fmt.Sprintf("%d", user.ID), map[string]interface{}{
		"method": "totp",
	}, true, h.getClientIP(r), r.Header.Get("User-Agent"))

	response := map[string]interface{}{
		"message": "Two-factor authentication enabled successfully",
		"enabled": true,
	}

	h.sendResponse(w, http.StatusOK, response)
}

// Helper methods

func (h *AdminAuthHandlers) sendResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"data":      data,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	_ = json.NewEncoder(w).Encode(response)
}

func (h *AdminAuthHandlers) sendError(w http.ResponseWriter, statusCode int, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"error":     errorType,
		"message":   message,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	_ = json.NewEncoder(w).Encode(response)
}

func (h *AdminAuthHandlers) getUserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(UserContextKey).(*User); ok {
		return user
	}
	return nil
}

func (h *AdminAuthHandlers) getTokenFromContext(ctx context.Context) string {
	if token, ok := ctx.Value(TokenContextKey).(string); ok {
		return token
	}
	return ""
}

func (h *AdminAuthHandlers) getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func (h *AdminAuthHandlers) parseUserFilter(r *http.Request) *UserFilter {
	filter := &UserFilter{
		Limit:    50,
		Offset:   0,
		SortBy:   "created_at",
		SortDesc: true,
	}

	// Parse query parameters
	if q := r.URL.Query().Get("username"); q != "" {
		filter.Username = q
	}
	if q := r.URL.Query().Get("email"); q != "" {
		filter.Email = q
	}
	if q := r.URL.Query().Get("enabled"); q != "" {
		enabled := q == "true"
		filter.Enabled = &enabled
	}
	if q := r.URL.Query().Get("tfa_enabled"); q != "" {
		tfaEnabled := q == "true"
		filter.TFAEnabled = &tfaEnabled
	}
	if q := r.URL.Query().Get("limit"); q != "" {
		if limit, err := strconv.Atoi(q); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}
	if q := r.URL.Query().Get("offset"); q != "" {
		if offset, err := strconv.Atoi(q); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}
	if q := r.URL.Query().Get("sort"); q != "" {
		filter.SortBy = q
	}
	if q := r.URL.Query().Get("order"); q == "asc" {
		filter.SortDesc = false
	}

	return filter
}

// Helper function to convert Role to RoleInfo
func (h *AdminAuthHandlers) convertRoleToRoleInfo(role *Role) *RoleInfo {
	if role == nil {
		return nil
	}
	return &RoleInfo{
		ID:          role.ID,
		Name:        role.Name,
		DisplayName: role.Name, // Use Name as DisplayName since it doesn't exist
		Description: role.Description,
		Permissions: role.Permissions,
		System:      role.SystemRole,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	}
}

func (h *AdminAuthHandlers) validateUserCreateRequest(req *UserCreateRequest) error {
	if req.Username == "" {
		return fmt.Errorf("username is required")
	}
	if req.Email == "" {
		return fmt.Errorf("email is required")
	}
	if req.Password == "" {
		return fmt.Errorf("password is required")
	}
	if req.RoleID == 0 {
		return fmt.Errorf("role_id is required")
	}

	// Validate password strength
	pm := NewPasswordManager(h.config.GetPasswordPolicy())
	if err := pm.ValidatePasswordStrength(req.Password); err != nil {
		return err
	}

	return nil
}