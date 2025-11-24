package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ConfigChangeType represents the type of configuration change
type ConfigChangeType string

const (
	ConfigChangeAll         ConfigChangeType = "all"
	ConfigChangeOAuth       ConfigChangeType = "oauth"
	ConfigChangeProvider    ConfigChangeType = "provider"
	ConfigChangeRouter      ConfigChangeType = "router"
)

// ConfigChange represents details about what changed in the configuration
type ConfigChange struct {
	Type        ConfigChangeType
	ProviderName string // For provider-specific changes
	Description  string
}

// ReloadCallback is called when configuration changes are detected
type ReloadCallback func(*Config, error, *ConfigChange)

// ConfigWatcher monitors configuration files for changes
type ConfigWatcher struct {
	configPath   string
	watcher      *fsnotify.Watcher
	callback     ReloadCallback
	debounceTime time.Duration
	stopChan     chan struct{}
	mu           sync.RWMutex
	isRunning    bool
	lastReload   time.Time
	lastConfig   *Config // For change detection
}

// NewConfigWatcher creates a new configuration file watcher
func NewConfigWatcher(configPath string, callback ReloadCallback, debounceTime time.Duration) (*ConfigWatcher, error) {
	if debounceTime <= 0 {
		debounceTime = 500 * time.Millisecond // Default debounce time
	}

	// Create filesystem watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		watcher.Close()
		return nil, err
	}

	cw := &ConfigWatcher{
		configPath:   absPath,
		watcher:      watcher,
		callback:     callback,
		debounceTime: debounceTime,
		stopChan:     make(chan struct{}),
		isRunning:    false,
	}

	return cw, nil
}

// Start begins watching the configuration file
func (cw *ConfigWatcher) Start() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cw.isRunning {
		return nil // Already running
	}

	// Watch the config file directory
	configDir := filepath.Dir(cw.configPath)
	err := cw.watcher.Add(configDir)
	if err != nil {
		return err
	}

	// Also watch the file specifically if it exists
	if _, err := os.Stat(cw.configPath); err == nil {
		if err := cw.watcher.Add(cw.configPath); err != nil {
			log.Printf("Warning: Could not watch config file %s: %v", cw.configPath, err)
		}
	}

	cw.isRunning = true

	// Start the watch goroutine
	go cw.watchLoop()

	log.Printf("Config watcher started for: %s", cw.configPath)
	return nil
}

// Stop stops watching the configuration file
func (cw *ConfigWatcher) Stop() {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if !cw.isRunning {
		return
	}

	close(cw.stopChan)
	cw.isRunning = false

	if cw.watcher != nil {
		cw.watcher.Close()
	}

	log.Printf("Config watcher stopped for: %s", cw.configPath)
}

// IsRunning returns whether the watcher is currently active
func (cw *ConfigWatcher) IsRunning() bool {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.isRunning
}

// ForceReload forces an immediate reload of the configuration
func (cw *ConfigWatcher) ForceReload() {
	cw.loadConfig()
}

// ForceReloadWithChange forces an immediate reload with a specific change type
func (cw *ConfigWatcher) ForceReloadWithChange(changeType ConfigChangeType, providerName string, description string) {
	cw.mu.Lock()
	now := time.Time{} // Reset to force reload
	cw.lastReload = now
	cw.mu.Unlock()

	// Force the reload
	cw.loadConfig()

	// If there's a callback, we might want to call it with a specific change
	// Note: This is additional functionality, the main change handling is in the callback itself
}

// watchLoop is the main watch loop that monitors file system events
func (cw *ConfigWatcher) watchLoop() {
	var (
		debounceTimer *time.Timer
		pendingReload = false
	)

	for {
		select {
		case <-cw.stopChan:
			return

		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}

			// Only handle events related to our config file
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				// Check if this is our config file or if it might be our config file
				if cw.isConfigEvent(event.Name) {
					if !pendingReload {
						log.Printf("Config file change detected: %s", event.Name)
						pendingReload = true
					}

					// Reset debounce timer
					if debounceTimer != nil {
						debounceTimer.Stop()
					}
					debounceTimer = time.AfterFunc(cw.debounceTime, func() {
						cw.loadConfig()
						pendingReload = false
					})
				}
			}

			// If file is removed, stop watching it (it might be recreated)
			if event.Has(fsnotify.Remove) && cw.isConfigEvent(event.Name) {
				if debounceTimer != nil {
					debounceTimer.Stop()
					debounceTimer = nil
				}
				pendingReload = false
				log.Printf("Config file removed: %s", event.Name)
			}

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Config watcher error: %v", err)
		}
	}
}

// isConfigEvent checks if an event is related to our config file
func (cw *ConfigWatcher) isConfigEvent(filename string) bool {
	absFilename, err := filepath.Abs(filename)
	if err != nil {
		return false
	}
	return absFilename == cw.configPath
}

// detectChanges identifies what changed between the last and current configuration
func (cw *ConfigWatcher) detectChanges(newConfig *Config) *ConfigChange {
	// If this is the first load, treat it as an all change
	if cw.lastConfig == nil {
		cw.lastConfig = newConfig
		return &ConfigChange{
			Type:        ConfigChangeAll,
			Description: "Initial configuration load",
		}
	}

	// Compare provider configurations
	if len(cw.lastConfig.Providers) != len(newConfig.Providers) {
		cw.lastConfig = newConfig
		return &ConfigChange{
			Type:        ConfigChangeAll,
			Description: "Provider count changed",
		}
	}

	// Look for OAuth credential changes
	for _, newProvider := range newConfig.Providers {
		// Find matching provider in old config
		var oldProvider *Provider
		for _, oldProv := range cw.lastConfig.Providers {
			if oldProv.Name == newProvider.Name {
				oldProvider = &oldProv
				break
			}
		}

		if oldProvider == nil {
			// New provider added
			cw.lastConfig = newConfig
			return &ConfigChange{
				Type:         ConfigChangeProvider,
				ProviderName: newProvider.Name,
				Description:  fmt.Sprintf("New provider added: %s", newProvider.Name),
			}
		}

		// Check for OAuth credential changes
		if newProvider.OAuth != nil && oldProvider.OAuth != nil {
			if !oauthCredentialsEqual(newProvider.OAuth, oldProvider.OAuth) {
				cw.lastConfig = newConfig
				return &ConfigChange{
					Type:         ConfigChangeOAuth,
					ProviderName: newProvider.Name,
					Description:  fmt.Sprintf("OAuth credentials changed for provider: %s", newProvider.Name),
				}
			}
		} else if (newProvider.OAuth == nil && oldProvider.OAuth != nil) || (newProvider.OAuth != nil && oldProvider.OAuth == nil) {
			// OAuth configuration added or removed
			cw.lastConfig = newConfig
			return &ConfigChange{
				Type:         ConfigChangeOAuth,
				ProviderName: newProvider.Name,
				Description:  fmt.Sprintf("OAuth configuration %s for provider: %s",
					map[bool]string{true: "added", false: "removed"}[newProvider.OAuth != nil], newProvider.Name),
			}
		}

		// Check for API key changes
		if newProvider.APIKEY != oldProvider.APIKEY {
			cw.lastConfig = newConfig
			return &ConfigChange{
				Type:         ConfigChangeProvider,
				ProviderName: newProvider.Name,
				Description:  fmt.Sprintf("API key changed for provider: %s", newProvider.Name),
			}
		}

		// Check for auth method changes
		if newProvider.AuthMethod != oldProvider.AuthMethod {
			cw.lastConfig = newConfig
			return &ConfigChange{
				Type:         ConfigChangeProvider,
				ProviderName: newProvider.Name,
				Description:  fmt.Sprintf("Auth method changed for provider: %s", newProvider.Name),
			}
		}
	}

	// Check router configuration changes
	if !routerConfigEqual(&cw.lastConfig.Router, &newConfig.Router) {
		cw.lastConfig = newConfig
		return &ConfigChange{
			Type:        ConfigChangeRouter,
			Description: "Router configuration changed",
		}
	}

	// No significant changes detected
	cw.lastConfig = newConfig
	return nil
}

// oauthCredentialsEqual compares two OAuth credential sets for equality
func oauthCredentialsEqual(a, b *OAuthCredentialSet) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return a.ClientID == b.ClientID &&
		   a.ClientSecret == b.ClientSecret &&
		   a.Scopes == b.Scopes &&
		   a.RedirectURL == b.RedirectURL &&
		   a.TokenURL == b.TokenURL &&
		   a.AuthURL == b.AuthURL
	// Note: We don't compare access tokens, refresh tokens, or expiry times
	// as they are runtime fields that can change without config file changes
}

// routerConfigEqual compares two router configurations for equality
func routerConfigEqual(a, b *RouterConfig) bool {
	return a.Default == b.Default &&
		   a.Background == b.Background &&
		   a.Think == b.Think &&
		   a.LongContext == b.LongContext &&
		   a.WebSearch == b.WebSearch &&
		   a.LongContextThreshold == b.LongContextThreshold
}

// loadConfig loads the current configuration and calls the callback
func (cw *ConfigWatcher) loadConfig() {
	cw.mu.Lock()
	now := time.Now()

	// Prevent too frequent reloads (minimum 1 second apart)
	if now.Sub(cw.lastReload) < time.Second {
		cw.mu.Unlock()
		log.Printf("Config reload skipped (too frequent recent reload)")
		return
	}
	cw.lastReload = now
	cw.mu.Unlock()

	log.Printf("Reloading configuration from: %s", cw.configPath)

	// Load the configuration
	cfg, err := Load(cw.configPath)

	// If the file doesn't exist, try to load default config
	if os.IsNotExist(err) {
		log.Printf("Config file not found, loading default configuration")
		cfg = DefaultConfig()
		err = nil
	}

	// Detect changes
	var change *ConfigChange
	if err == nil {
		change = cw.detectChanges(cfg)
	}

	// Call the callback
	if cw.callback != nil {
		go cw.callback(cfg, err, change)
	}

	if err != nil {
		log.Printf("Configuration reload failed: %v", err)
	} else {
		if change != nil {
			log.Printf("Configuration reloaded successfully - change detected: %s", change.Description)
		} else {
			log.Printf("Configuration reloaded successfully - no significant changes")
		}
	}
}

// GetConfigPath returns the current config file path
func (cw *ConfigWatcher) GetConfigPath() string {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.configPath
}