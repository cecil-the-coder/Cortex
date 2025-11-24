package database

import (
	"context"
	"database/sql"
	"time"

	goconfig "github.com/cecil-the-coder/Cortex/internal/config"
)

// Database provides abstraction for different database backends
type Database interface {
	// Connection management
	Connect(ctx context.Context) error
	Close() error
	Ping(ctx context.Context) error

	// Transaction support
	BeginTx(ctx context.Context, opts *sql.TxOptions) (Transaction, error)

	// Configuration operations
	ConfigRepository
	MetricsRepository

	// Migration support
	Migrate(ctx context.Context) error
	GetVersion() (string, error)

	// Health check
	HealthCheck(ctx context.Context) error
}

// Transaction interface for database transactions
type Transaction interface {
	Commit() error
	Rollback() error
	ConfigRepository
	MetricsRepository
}

// DatabaseConfig holds configuration for database connections
type DatabaseConfig struct {
	Type     string `yaml:"type" json:"type"`         // "sqlite" or "mysql"
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	Database string `yaml:"database" json:"database"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`

	// Connection pooling
	MaxOpenConns    int           `yaml:"max_open_conns" json:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" json:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" json:"conn_max_idle_time"`

	// Performance tuning
	BatchSize     int           `yaml:"batch_size" json:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval" json:"flush_interval"`

	// SQLite specific
	SQLitePath     string `yaml:"sqlite_path" json:"sqlite_path"`
	SQLiteWALMode  bool   `yaml:"sqlite_wal_mode" json:"sqlite_wal_mode"`
	SQLiteCacheSize int   `yaml:"sqlite_cache_size" json:"sqlite_cache_size"`

	// MySQL specific
	MySQLCharset   string `yaml:"mysql_charset" json:"mysql_charset"`
	MySQLCollation string `yaml:"mysql_collation" json:"mysql_collation"`
	MySQLParseTime bool   `yaml:"mysql_parse_time" json:"mysql_parse_time"`
}

// OAuthCredentialSet holds OAuth credentials for providers
type OAuthCredentialSet struct {
	ClientID     string     `json:"client_id"`
	ClientSecret string     `json:"client_secret"`
	AccessToken  string     `json:"access_token,omitempty"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	TokenURL     string     `json:"token_url,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// Configuration models for database storage
type Provider struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`
	AuthMethod      string    `json:"auth_method"`
	APIKey          string    `json:"api_key,omitempty"`
	BaseURL         string    `json:"base_url"`
	UseCoreAPI      bool      `json:"use_core_api"`
	CoreAPIFeatures []string  `json:"core_api_features,omitempty"`
	OAuth           *OAuthCredentialSet `json:"oauth,omitempty"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type Model struct {
	ID                int64      `json:"id"`
	ProviderID        int64      `json:"provider_id"`
	ModelName         string     `json:"model_name"`
	DisplayName       string     `json:"display_name,omitempty"`
	MaxContextTokens  int        `json:"max_context_tokens"`
	SupportsVision    bool       `json:"supports_vision"`
	SupportsTools     bool       `json:"supports_tools"`
	InputCostPer1k    float64    `json:"input_cost_per_1k"`
	OutputCostPer1k   float64    `json:"output_cost_per_1k"`
	Enabled           bool       `json:"enabled"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type ModelGroup struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type GroupMember struct {
	ID                      int64 `json:"id"`
	GroupID                 int64 `json:"group_id"`
	ProviderID              int64 `json:"provider_id"`
	ModelID                 int64 `json:"model_id"`
	Alias                   string `json:"alias,omitempty"`
	MaxContextTokensOverride *int  `json:"max_context_tokens_override,omitempty"`
	CreatedAt               time.Time `json:"created_at"`
}

type ClientAPIKey struct {
	ID          int64      `json:"id"`
	KeyID       string     `json:"key_id"`
	APIKeyHash  string     `json:"api_key_hash"`
	Description string     `json:"description,omitempty"`
	RateLimit   int        `json:"rate_limit"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type RouterConfig struct {
	ID                    int64     `json:"id"`
	DefaultProvider       string    `json:"default_provider"`
	BackgroundProvider    string    `json:"background_provider,omitempty"`
	ThinkProvider         string    `json:"think_provider,omitempty"`
	LongContextProvider   string    `json:"long_context_provider,omitempty"`
	WebSearchProvider     string    `json:"web_search_provider,omitempty"`
	VisionProvider        string    `json:"vision_provider,omitempty"`
	LongContextThreshold  int       `json:"long_context_threshold"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// Metrics models
type RequestMetrics struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	RequestID    string    `json:"request_id"`
	APIKeyID     *int64    `json:"api_key_id,omitempty"`
	ProviderID   int64     `json:"provider_id"`
	ModelID      int64     `json:"model_id"`
	ModelGroupID *int64    `json:"model_group_id,omitempty"`
	RequestType  string    `json:"request_type"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	TotalTokens  int       `json:"total_tokens"`
	LatencyMs    int       `json:"latency_ms"`
	StatusCode   int       `json:"status_code"`
	ErrorMessage string    `json:"error_message,omitempty"`
	RequestSize  int       `json:"request_size_bytes"`
	ResponseSize int       `json:"response_size_bytes"`
	Streaming    bool      `json:"streaming"`
	VisionContent bool     `json:"vision_content"`
	ToolUse      bool      `json:"tool_use"`
	ThinkingMode bool      `json:"thinking_mode"`
	Cost         float64   `json:"cost"`
	CreatedAt    time.Time `json:"created_at"`
}

// Filter types
type ProviderFilter struct {
	Name    string
	Enabled *bool
	Limit   int
	Offset  int
}

type ModelFilter struct {
	ProviderID *int64
	ModelName  string
	Enabled    *bool
	Limit      int
	Offset     int
}

type APIKeyFilter struct {
	KeyID   string
	Enabled *bool
	Limit   int
	Offset  int
}

// Time range for metrics queries
type TimeRange struct {
	From time.Time
	To   time.Time
}

// Metrics query types
type MetricsQuery struct {
	ProviderID   *int64
	ModelID      *int64
	ModelGroupID *int64
	APIKeyID     *int64
	StatusCode   *int
	TimeRange    TimeRange
	Limit        int
	Offset       int
	OrderBy      string
}

type AggregatedQuery struct {
	TimeRange    TimeRange
	GroupBy      string // "hour", "day", "provider", "model"
	Metrics      []string // "count", "tokens", "cost", "latency"
	TimeInterval string   // "1h", "1d", "1w"
}

type AggregatedMetrics struct {
	Labels map[string]string `json:"labels"`
	Values map[string]interface{} `json:"values"`
	Timestamp time.Time       `json:"timestamp"`
}

// Repository interfaces for database operations

// ConfigRepository provides configuration management operations
type ConfigRepository interface {
	// Provider operations
	CreateProvider(ctx context.Context, provider *Provider) error
	GetProvider(ctx context.Context, id int64) (*Provider, error)
	GetProviderByName(ctx context.Context, name string) (*Provider, error)
	UpdateProvider(ctx context.Context, provider *Provider) error
	DeleteProvider(ctx context.Context, id int64) error
	ListProviders(ctx context.Context, filter *ProviderFilter) ([]*Provider, error)

	// Model operations
	CreateModel(ctx context.Context, model *Model) error
	GetModel(ctx context.Context, id int64) (*Model, error)
	GetModelByName(ctx context.Context, providerID int64, modelName string) (*Model, error)
	UpdateModel(ctx context.Context, model *Model) error
	DeleteModel(ctx context.Context, id int64) error
	ListModels(ctx context.Context, filter *ModelFilter) ([]*Model, error)

	// Model group operations
	CreateModelGroup(ctx context.Context, group *ModelGroup) error
	GetModelGroup(ctx context.Context, id int64) (*ModelGroup, error)
	GetModelGroupByName(ctx context.Context, name string) (*ModelGroup, error)
	UpdateModelGroup(ctx context.Context, group *ModelGroup) error
	DeleteModelGroup(ctx context.Context, id int64) error
	ListModelGroups(ctx context.Context) ([]*ModelGroup, error)

	// Group member operations
	AddGroupMember(ctx context.Context, member *GroupMember) error
	RemoveGroupMember(ctx context.Context, id int64) error
	GetGroupMembers(ctx context.Context, groupID int64) ([]*GroupMember, error)

	// API key operations
	CreateAPIKey(ctx context.Context, apiKey *ClientAPIKey) error
	GetAPIKey(ctx context.Context, id int64) (*ClientAPIKey, error)
	GetAPIKeyByKeyID(ctx context.Context, keyID string) (*ClientAPIKey, error)
	UpdateAPIKey(ctx context.Context, apiKey *ClientAPIKey) error
	DeleteAPIKey(ctx context.Context, id int64) error
	ListAPIKeys(ctx context.Context, filter *APIKeyFilter) ([]*ClientAPIKey, error)

	// Router configuration operations
	GetRouterConfig(ctx context.Context) (*RouterConfig, error)
	UpdateRouterConfig(ctx context.Context, config *RouterConfig) error

	// Configuration export/import
	ExportConfig(ctx context.Context) (*goconfig.Config, error)
	ImportConfig(ctx context.Context, cfg *goconfig.Config) error
}

// MetricsRepository provides metrics storage and retrieval operations
type MetricsRepository interface {
	// Request metrics operations
	StoreRequestMetrics(ctx context.Context, metrics *RequestMetrics) error
	StoreBatchRequestMetrics(ctx context.Context, metrics []*RequestMetrics) error
	GetRequestMetrics(ctx context.Context, query *MetricsQuery) ([]*RequestMetrics, error)
	GetAggregatedMetrics(ctx context.Context, query *AggregatedQuery) ([]*AggregatedMetrics, error)

	// Metrics cleanup
	CleanupOldMetrics(ctx context.Context, olderThan time.Time) error
	GetMetricsRetention(ctx context.Context) (time.Duration, error)

	// Health metrics
	GetProviderHealthStats(ctx context.Context, providerID int64, timeRange TimeRange) (map[string]interface{}, error)
	GetSystemMetrics(ctx context.Context, timeRange TimeRange) (map[string]interface{}, error)

	// Batch operations
	BatchRecordRequests(ctx context.Context, metrics []*RequestMetrics) error
	RecordProviderHealth(ctx context.Context, health interface{}) error
	AggregateMetrics(ctx context.Context) error
}