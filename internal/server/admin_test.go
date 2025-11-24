package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cecil-the-coder/Cortex/internal/config"
	"github.com/cecil-the-coder/Cortex/internal/access"
)

// TestAdminAPIKeyManagement tests the basic API key management endpoints
func TestAdminAPIKeyManagement(t *testing.T) {
	// Create test configuration with minimal required fields
	cfg := &config.Config{
		APIKEY: "test-admin-key",
		ClientAPIKeys: &config.ClientAPIKeys{
			"test-key": {
				APIKey:      "sk-test123456789",
				Description: "Test API key",
				ModelGroups: []string{"test-group"},
				Enabled:     true,
			},
		},
		ModelGroups: &config.ModelGroups{
			"test-group": {
				Description: "Test model group",
				Models: []config.ModelReference{
					{
						Provider: "test-provider",
						Model:    "test-model",
						Alias:    "test-alias",
					},
				},
			},
		},
		Providers: []config.Provider{
			{
				Name:       "test-provider",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "test-provider-key",
				BaseURL:    "https://api.test.com/v1",
				Models:     []string{"test-model"},
			},
		},
		Router: config.RouterConfig{
			Default: "test-provider",
		},
	}

	// Create access manager
	am := access.NewAccessManager(cfg)

	// Create test server
	srv := &Server{
		accessManager: am,
		configFunc:    func() *config.Config { return cfg },
		config: &Config{
			ConfigPath: "/tmp/test-config.yaml", // Dummy path for tests
		},
	}

	tests := []struct {
		name           string
		method         string
		path           string
		body           interface{}
		headers        map[string]string
		expectedStatus int
		checkFunc      func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:   "List API keys without auth",
			method: "GET",
			path:   "/admin/api-keys",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:   "List API keys with valid auth",
			method: "GET",
			path:   "/admin/api-keys",
			headers: map[string]string{
				"Authorization": "Bearer test-admin-key",
			},
			expectedStatus: http.StatusOK,
			checkFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
				var response APIKeyListResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				if err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if !response.Success {
					t.Error("Expected success=true")
				}
				if response.Count != 1 {
					t.Errorf("Expected 1 API key, got %d", response.Count)
				}
			},
		},
		{
			name:   "Create new API key",
			method: "POST",
			path:   "/admin/api-keys",
			headers: map[string]string{
				"Authorization": "Bearer test-admin-key",
				"Content-Type": "application/json",
			},
			body: APIKeyCreateRequest{
				ID:          "new-key",
				Description: "New test key",
				ModelGroups: []string{"test-group"},
				Enabled:     true,
			},
			expectedStatus: http.StatusCreated,
			checkFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
				if rr.Code != http.StatusCreated {
					t.Logf("Create API key response body: %s", rr.Body.String())
				}
			},
		},
		{
			name:   "Validate API key format",
			method: "POST",
			path:   "/admin/api-keys/validate",
			headers: map[string]string{
				"Authorization": "Bearer test-admin-key",
				"Content-Type":  "application/json",
			},
			body: map[string]string{
				"api_key": "sk-test123456789",
			},
			expectedStatus: http.StatusOK,
			checkFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
				var response map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				if err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if !response["success"].(bool) {
					t.Error("Expected success=true")
				}
				if !response["exists"].(bool) {
					t.Error("Expected exists=true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.body != nil {
				var err error
				body, err = json.Marshal(tt.body)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			var bodyReader *bytes.Reader
			if body != nil {
				bodyReader = bytes.NewReader(body)
			} else {
				bodyReader = bytes.NewReader(nil)
			}

			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			if body != nil {
				req.ContentLength = int64(len(body))
			}

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			rr := httptest.NewRecorder()

			// Route to appropriate handler
			switch {
			case tt.method == "GET" && tt.path == "/admin/api-keys":
				srv.ServeAdminAPIKeys(rr, req)
			case tt.method == "POST" && tt.path == "/admin/api-keys":
				srv.ServeAdminAPIKeyCreate(rr, req)
			case tt.method == "POST" && tt.path == "/admin/api-keys/validate":
				srv.ServeAdminAPIKeyValidate(rr, req)
			default:
				t.Errorf("Unsupported test case: %s %s", tt.method, tt.path)
				return
			}

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, rr)
			}
		})
	}
}

// TestAdminModelGroupManagement tests the basic model group management endpoints
func TestAdminModelGroupManagement(t *testing.T) {
	// Create test configuration with model groups and required router config
	cfg := &config.Config{
		APIKEY: "test-admin-key",
		ModelGroups: &config.ModelGroups{
			"test-group": {
				Description: "Test model group",
				Models: []config.ModelReference{
					{
						Provider: "test-provider",
						Model:    "test-model",
						Alias:    "test-alias",
					},
				},
			},
		},
		Providers: []config.Provider{
			{
				Name:       "test-provider",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "test-provider-key",
				BaseURL:    "https://api.test.com/v1",
				Models:     []string{"test-model", "new-model"},
			},
		},
		Router: config.RouterConfig{
			Default: "test-provider",
		},
	}

	// Create access manager
	am := access.NewAccessManager(cfg)

	// Create test server
	srv := &Server{
		accessManager: am,
		configFunc:    func() *config.Config { return cfg },
		config: &Config{
			ConfigPath: "/tmp/test-config.yaml", // Dummy path for tests
		},
	}

	tests := []struct {
		name           string
		method         string
		path           string
		body           interface{}
		headers        map[string]string
		expectedStatus int
		checkFunc      func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:   "List model groups with valid auth",
			method: "GET",
			path:   "/admin/model-groups",
			headers: map[string]string{
				"Authorization": "Bearer test-admin-key",
			},
			expectedStatus: http.StatusOK,
			checkFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
				var response ModelGroupListResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				if err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if !response.Success {
					t.Error("Expected success=true")
				}
				if response.Count != 1 {
					t.Errorf("Expected 1 model group, got %d", response.Count)
				}
			},
		},
		{
			name:   "Get model group details",
			method: "GET",
			path:   "/admin/model-groups/test-group",
			headers: map[string]string{
				"Authorization": "Bearer test-admin-key",
			},
			expectedStatus: http.StatusOK,
			checkFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
				if rr.Code != http.StatusOK {
					t.Logf("Get model group details response body: %s", rr.Body.String())
				}
				var response struct {
					Success   bool           `json:"success"`
					GroupInfo ModelGroupInfo `json:"group_info"`
					Timestamp string         `json:"timestamp"`
				}
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				if err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if !response.Success {
					t.Error("Expected success=true")
				}
				if response.GroupInfo.Name != "test-group" {
					t.Errorf("Expected group name 'test-group', got '%s'", response.GroupInfo.Name)
				}
			},
		},
		{
			name:   "Create new model group",
			method: "POST",
			path:   "/admin/model-groups",
			headers: map[string]string{
				"Authorization": "Bearer test-admin-key",
				"Content-Type": "application/json",
			},
			body: ModelGroupCreateRequest{
				Name:        "new-group",
				Description: "New test group",
				Models: []config.ModelReference{
					{
						Provider: "test-provider",
						Model:    "new-model",
						Alias:    "new-alias",
					},
				},
			},
			expectedStatus: http.StatusCreated,
			checkFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
				if rr.Code != http.StatusCreated {
					t.Logf("Create model group response body: %s", rr.Body.String())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.body != nil {
				var err error
				body, err = json.Marshal(tt.body)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			var bodyReader *bytes.Reader
			if body != nil {
				bodyReader = bytes.NewReader(body)
			} else {
				bodyReader = bytes.NewReader(nil)
			}

			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			if body != nil {
				req.ContentLength = int64(len(body))
			}

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			rr := httptest.NewRecorder()

			// Route to appropriate handler
			switch {
			case tt.method == "GET" && tt.path == "/admin/model-groups":
				srv.ServeAdminModelGroups(rr, req)
			case tt.method == "GET" && tt.path == "/admin/model-groups/test-group":
				srv.ServeAdminModelGroupDetails(rr, req)
			case tt.method == "POST" && tt.path == "/admin/model-groups":
				srv.ServeAdminModelGroupsCreate(rr, req)
			default:
				t.Errorf("Unsupported test case: %s %s", tt.method, tt.path)
				return
			}

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, rr)
			}
		})
	}
}

// TestAdminAccessControl tests the access control endpoints
func TestAdminAccessControl(t *testing.T) {
	// Create test configuration with all required components
	cfg := &config.Config{
		APIKEY: "test-admin-key",
		ModelGroups: &config.ModelGroups{
			"test-group": {
				Description: "Test model group",
				Models: []config.ModelReference{
					{
						Provider: "test-provider",
						Model:    "test-model",
						Alias:    "test-alias",
					},
				},
			},
		},
		ClientAPIKeys: &config.ClientAPIKeys{
			"test-key": {
				APIKey:      "sk-test123456789",
				Description: "Test API key",
				ModelGroups: []string{"test-group"},
				Enabled:     true,
			},
		},
		Providers: []config.Provider{
			{
				Name:       "test-provider",
				AuthMethod: config.AuthMethodAPIKey,
				APIKEY:     "test-provider-key",
				BaseURL:    "https://api.test.com/v1",
				Models:     []string{"test-model"},
			},
		},
		Router: config.RouterConfig{
			Default: "test-provider",
		},
	}

	// Create access manager
	am := access.NewAccessManager(cfg)

	// Create test server
	srv := &Server{
		accessManager: am,
		configFunc:    func() *config.Config { return cfg },
		config: &Config{
			ConfigPath: "/tmp/test-config.yaml", // Dummy path for tests
		},
	}

	tests := []struct {
		name           string
		method         string
		path           string
		body           interface{}
		headers        map[string]string
		expectedStatus int
		checkFunc      func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name:   "Check model access",
			method: "POST",
			path:   "/admin/access/check",
			headers: map[string]string{
				"Authorization": "Bearer test-admin-key",
				"Content-Type":  "application/json",
			},
			body: AccessCheckRequest{
				APIKey: "sk-test123456789",
				Model:  "test-alias",
			},
			expectedStatus: http.StatusOK,
			checkFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
				var response AccessCheckResponse
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				if err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if !response.Success {
					t.Error("Expected success=true")
				}
				if !response.HasAccess {
					t.Error("Expected has_access=true")
				}
				if response.ResolvedModel != "test-model" {
					t.Errorf("Expected resolved model 'test-model', got '%s'", response.ResolvedModel)
				}
			},
		},
		{
			name:   "Get available models for API key",
			method: "GET",
			path:   "/admin/access/models/sk-test123456789",
			headers: map[string]string{
				"Authorization": "Bearer test-admin-key",
			},
			expectedStatus: http.StatusOK,
			checkFunc: func(t *testing.T, rr *httptest.ResponseRecorder) {
				if rr.Code != http.StatusOK {
					t.Logf("Get available models response body: %s", rr.Body.String())
				}
				var response struct {
					Success        bool              `json:"success"`
					APIKey         string            `json:"api_key"`
					AvailableModels []string          `json:"available_models"`
					ModelCount     int               `json:"model_count"`
					Timestamp      string            `json:"timestamp"`
				}
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				if err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if !response.Success {
					t.Error("Expected success=true")
				}
				if response.ModelCount == 0 {
					t.Error("Expected models to be available")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.body != nil {
				var err error
				body, err = json.Marshal(tt.body)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
			}

			var bodyReader *bytes.Reader
			if body != nil {
				bodyReader = bytes.NewReader(body)
			} else {
				bodyReader = bytes.NewReader(nil)
			}

			req := httptest.NewRequest(tt.method, tt.path, bodyReader)
			if body != nil {
				req.ContentLength = int64(len(body))
			}

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			rr := httptest.NewRecorder()

			// Route to appropriate handler
			switch {
			case tt.method == "POST" && tt.path == "/admin/access/check":
				srv.ServeAdminAccessCheck(rr, req)
			case tt.method == "GET" && tt.path == "/admin/access/models/sk-test123456789":
				srv.ServeAdminAvailableModels(rr, req)
			default:
				t.Errorf("Unsupported test case: %s %s", tt.method, tt.path)
				return
			}

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, rr)
			}
		})
	}
}

// TestHelperFunctions tests internal helper functions
func TestHelperFunctions(t *testing.T) {
	srv := &Server{}

	// Test API key validation
	validKeys := []string{
		"sk-A1b2C3d4E5f6",
		"test-key-123",
		"abcdefghijklmnopqrstuvwxyz123456",
	}

	for _, key := range validKeys {
		if !srv.validateAPIKeyFormat(key) {
			t.Errorf("Expected valid key format: %s", key)
		}
	}

	invalidKeys := []string{
		"short",
		"key with spaces",
		"key@with#symbols",
		"", // empty
	}

	for _, key := range invalidKeys {
		if srv.validateAPIKeyFormat(key) {
			t.Errorf("Expected invalid key format: %s", key)
		}
	}

	// Test key validation
	validIDs := []string{
		"test-key",
		"api-key-123",
		"client_ABC",
	}

	for _, id := range validIDs {
		if !srv.isValidKeyID(id) {
			t.Errorf("Expected valid ID: %s", id)
		}
	}

	invalidIDs := []string{
		"id-with spaces",
		"id@with#symbols",
		"", // empty
		"a-very-long-id-that-exceeds-the-maximum-allowed-length-of-sixty-four-characters",
	}

	for _, id := range invalidIDs {
		if srv.isValidKeyID(id) {
			t.Errorf("Expected invalid ID: %s", id)
		}
	}

	// Test key masking
	testKey := "sk-a1b2c3d4e5f67890"
	masked := srv.maskAPIKey(testKey)
	expected := "sk-a***********7890"
	if masked != expected {
		t.Errorf("Expected masked key '%s', got '%s'", expected, masked)
	}

	// Test API key generation
	if generatedKey, err := srv.generateAPIKey(); err != nil {
		t.Errorf("Failed to generate API key: %v", err)
	} else {
		if len(generatedKey) < 12 { // "sk-" + at least 24 hex chars
			t.Errorf("Generated key too short: %s", generatedKey)
		}
		if generatedKey[:3] != "sk-" {
			t.Errorf("Generated key should start with 'sk-': %s", generatedKey)
		}
	}

	// Test auth extraction
	// Test Authorization header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	if srv.extractAPIKey(req) != "test-key" {
		t.Error("Failed to extract API key from Authorization header")
	}

	// Test x-api-key header
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("x-api-key", "test-key-2")
	if srv.extractAPIKey(req) != "test-key-2" {
		t.Error("Failed to extract API key from x-api-key header")
	}

	// Test query parameter
	req = httptest.NewRequest("GET", "/?api_key=test-key-3", nil)
	if srv.extractAPIKey(req) != "test-key-3" {
		t.Error("Failed to extract API key from query parameter")
	}
}