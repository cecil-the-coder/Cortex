package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/cecil-the-coder/Cortex/internal/config"
)

// OAuthHandler manages OAuth token operations for providers
type OAuthHandler struct {
	mu                 sync.RWMutex
	registry           *SDKProviderRegistry
	config             *config.Config
	configPath         string
	httpClient         *http.Client
	refreshCallbacks   map[string]func(*config.OAuthCredentialSet) error
	refreshInProgress  map[string]bool
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(registry *SDKProviderRegistry, cfg *config.Config, configPath string) *OAuthHandler {
	return &OAuthHandler{
		registry:   registry,
		config:     cfg,
		configPath: configPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		refreshCallbacks:  make(map[string]func(*config.OAuthCredentialSet) error),
		refreshInProgress: make(map[string]bool),
	}
}

// TokenResponse represents OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Error        string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// RefreshToken refreshes an OAuth token for a provider
func (h *OAuthHandler) RefreshToken(providerName string) error {
	h.mu.Lock()
	if h.refreshInProgress[providerName] {
		h.mu.Unlock()
		return fmt.Errorf("token refresh already in progress for provider: %s", providerName)
	}
	h.refreshInProgress[providerName] = true
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.refreshInProgress, providerName)
		h.mu.Unlock()
	}()

	// Get provider OAuth configuration
	oauth, err := h.config.GetProviderOAuthCredentials(providerName)
	if err != nil {
		return fmt.Errorf("failed to get OAuth credentials for provider %s: %w", providerName, err)
	}

	if oauth.RefreshToken == "" {
		return fmt.Errorf("no refresh token available for provider: %s", providerName)
	}

	// Prepare token refresh request
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", oauth.RefreshToken)
	data.Set("client_id", oauth.ClientID)
	data.Set("client_secret", oauth.ClientSecret)

	// Make refresh request
	resp, err := h.httpClient.PostForm(oauth.TokenURL, data)
	if err != nil {
		return fmt.Errorf("failed to make refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token refresh failed with status: %d", resp.StatusCode)
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read refresh response: %w", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Error != "" {
		return fmt.Errorf("token refresh error: %s - %s", tokenResp.Error, tokenResp.ErrorDescription)
	}

	// Update OAuth credentials with new tokens
	oauth.UpdateTokens(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.TokenType, tokenResp.ExpiresIn)

	// Update in-memory config
	if err := h.config.UpdateProviderOAuthCredentials(providerName, oauth, true, h.configPath); err != nil {
		log.Printf("Warning: Failed to persist OAuth tokens for provider %s: %v", providerName, err)
	}

	// Update provider registry with new token
	if err := h.registry.RefreshProviderAPIKey(providerName, tokenResp.AccessToken); err != nil {
		log.Printf("Warning: Failed to update provider API key for %s: %v", providerName, err)
	}

	// Call refresh callback if set
	h.mu.RLock()
	if callback, exists := h.refreshCallbacks[providerName]; exists {
		if err := callback(oauth); err != nil {
			log.Printf("Warning: OAuth refresh callback failed for provider %s: %v", providerName, err)
		}
	}
	h.mu.RUnlock()

	log.Printf("Successfully refreshed OAuth token for provider: %s", providerName)
	return nil
}

// ValidateAndRefreshIfNeeded checks if a token is valid and refreshes if needed
func (h *OAuthHandler) ValidateAndRefreshIfNeeded(providerName string) error {
	oauth, err := h.config.GetProviderOAuthCredentials(providerName)
	if err != nil {
		return fmt.Errorf("failed to get OAuth credentials for provider %s: %w", providerName, err)
	}

	// If token is still valid, no refresh needed
	if oauth.IsValid() {
		return nil
	}

	// Token expired or invalid, attempt refresh
	log.Printf("OAuth token expired for provider %s, attempting refresh", providerName)
	return h.RefreshToken(providerName)
}

// ExchangeCodeForToken exchanges authorization code for access token
func (h *OAuthHandler) ExchangeCodeForToken(providerName string, authorizationCode string) error {
	// Get provider OAuth configuration
	oauth, err := h.config.GetProviderOAuthCredentials(providerName)
	if err != nil {
		return fmt.Errorf("failed to get OAuth credentials for provider %s: %w", providerName, err)
	}

	// Prepare token exchange request
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authorizationCode)
	data.Set("client_id", oauth.ClientID)
	data.Set("client_secret", oauth.ClientSecret)
	if oauth.RedirectURL != "" {
		data.Set("redirect_uri", oauth.RedirectURL)
	}

	// Make token request
	resp, err := h.httpClient.PostForm(oauth.TokenURL, data)
	if err != nil {
		return fmt.Errorf("failed to make token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read token response: %w", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Error != "" {
		return fmt.Errorf("token exchange error: %s - %s", tokenResp.Error, tokenResp.ErrorDescription)
	}

	// Update OAuth credentials with new tokens
	oauth.UpdateTokens(tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.TokenType, tokenResp.ExpiresIn)

	// Update config and registry
	if err := h.config.UpdateProviderOAuthCredentials(providerName, oauth, true, h.configPath); err != nil {
		log.Printf("Warning: Failed to persist OAuth tokens for provider %s: %v", providerName, err)
	}

	if err := h.registry.RefreshProviderAPIKey(providerName, tokenResp.AccessToken); err != nil {
		log.Printf("Warning: Failed to update provider API key for %s: %v", providerName, err)
	}

	log.Printf("Successfully exchanged authorization code for tokens for provider: %s", providerName)
	return nil
}

// GetAuthorizationURL generates the OAuth authorization URL for a provider
func (h *OAuthHandler) GetAuthorizationURL(providerName string, state string) (string, error) {
	oauth, err := h.config.GetProviderOAuthCredentials(providerName)
	if err != nil {
		return "", fmt.Errorf("failed to get OAuth credentials for provider %s: %w", providerName, err)
	}

	if oauth.AuthURL == "" {
		return "", fmt.Errorf("authorization URL not configured for provider: %s", providerName)
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", oauth.ClientID)
	if oauth.RedirectURL != "" {
		params.Set("redirect_uri", oauth.RedirectURL)
	}
	if oauth.Scopes != "" {
		params.Set("scope", oauth.Scopes)
	}
	if state != "" {
		params.Set("state", state)
	}

	authURL := fmt.Sprintf("%s?%s", oauth.AuthURL, params.Encode())
	return authURL, nil
}

// SetRefreshCallback sets a callback function for token refresh events
func (h *OAuthHandler) SetRefreshCallback(providerName string, callback func(*config.OAuthCredentialSet) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refreshCallbacks[providerName] = callback
}

// SetConfigPath updates the configuration file path for OAuth persistence
func (h *OAuthHandler) SetConfigPath(configPath string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.configPath = configPath
}

// GetTokenStatus returns the current status of OAuth tokens for a provider
func (h *OAuthHandler) GetTokenStatus(providerName string) (*TokenStatus, error) {
	oauth, err := h.config.GetProviderOAuthCredentials(providerName)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, tokenType, expiresAt := oauth.GetTokens()
	isValid := oauth.IsValid()

	return &TokenStatus{
		ProviderName:  providerName,
		AccessToken:   maskToken(accessToken),
		RefreshToken:  maskToken(refreshToken),
		TokenType:     tokenType,
		ExpiresAt:     expiresAt,
		IsValid:       isValid,
		TimeUntilExpiry: time.Until(expiresAt),
	}, nil
}

// TokenStatus represents the status of OAuth tokens
type TokenStatus struct {
	ProviderName   string        `json:"provider_name"`
	AccessToken    string        `json:"access_token"`
	RefreshToken   string        `json:"refresh_token,omitempty"`
	TokenType      string        `json:"token_type"`
	ExpiresAt      time.Time     `json:"expires_at"`
	IsValid        bool          `json:"is_valid"`
	TimeUntilExpiry time.Duration `json:"time_until_expiry"`
}

// RefreshAllExpiredTokens checks all OAuth providers and refreshes expired tokens
func (h *OAuthHandler) RefreshAllExpiredTokens() {
	h.mu.RLock()
	providerConfigs := h.registry.GetAllProviderConfigs()
	h.mu.RUnlock()

	for _, provider := range providerConfigs {
		if provider.AuthMethod == config.AuthMethodOAuth || provider.AuthMethod == config.AuthMethodHybrid {
			if provider.OAuth != nil && provider.OAuth.RefreshToken != "" {
				if !provider.OAuth.IsValid() {
					if err := h.ValidateAndRefreshIfNeeded(provider.Name); err != nil {
						log.Printf("Failed to refresh token for provider %s: %v", provider.Name, err)
					}
				}
			}
		}
	}
}

// StartTokenRefreshScheduler starts a background goroutine to periodically refresh tokens
func (h *OAuthHandler) StartTokenRefreshScheduler(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Printf("Token refresh scheduler stopped")
				return
			case <-ticker.C:
				h.RefreshAllExpiredTokens()
			}
		}
	}()

	log.Printf("Token refresh scheduler started with interval: %v", interval)
}

// maskToken masks sensitive token information for logging
func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "****" + token[len(token)-4:]
}

// RevokeTokens revokes OAuth tokens for a provider (if supported)
func (h *OAuthHandler) RevokeTokens(providerName string) error {
	oauth, err := h.config.GetProviderOAuthCredentials(providerName)
	if err != nil {
		return fmt.Errorf("failed to get OAuth credentials for provider %s: %w", providerName, err)
	}

	// Most OAuth providers don't have a standard revocation endpoint
	// This would need to be implemented per-provider if needed
	log.Printf("Token revocation not implemented for provider: %s", providerName)

	// For now, just clear the in-memory tokens
	oauth.UpdateTokens("", "", "", 0)

	// Update config and registry
	if err := h.config.UpdateProviderOAuthCredentials(providerName, oauth, true, h.configPath); err != nil {
		return fmt.Errorf("failed to clear OAuth tokens: %w", err)
	}

	return h.registry.RefreshProviderAPIKey(providerName, "")
}