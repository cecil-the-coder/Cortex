package authentication

import (
	"context"
	"database/sql"
	"fmt"
)

// Migrations represents all authentication-related database migrations
var Migrations = []string{
	// Users table
	`CREATE TABLE IF NOT EXISTS auth_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		full_name VARCHAR(255),
		role_id INTEGER NOT NULL,
		enabled BOOLEAN DEFAULT TRUE,
		tfa_enabled BOOLEAN DEFAULT FALSE,
		tfa_secret VARCHAR(255),
		last_login TIMESTAMP,
		login_attempts INTEGER DEFAULT 0,
		locked_until TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (role_id) REFERENCES auth_roles(id)
	);`,

	// Roles table
	`CREATE TABLE IF NOT EXISTS auth_roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) UNIQUE NOT NULL,
		description TEXT,
		permissions TEXT NOT NULL, -- JSON array
		system_role BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`,

	// User sessions table
	`CREATE TABLE IF NOT EXISTS auth_user_sessions (
		id TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		session_token_hash VARCHAR(255) NOT NULL,
		refresh_token_hash VARCHAR(255) NOT NULL,
		ip_address VARCHAR(45) NOT NULL,
		user_agent TEXT,
		expires_at TIMESTAMP NOT NULL,
		last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		active BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
	);`,

	// Admin API keys table
	`CREATE TABLE IF NOT EXISTS auth_admin_api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		key_id VARCHAR(50) UNIQUE NOT NULL,
		key_hash VARCHAR(255) NOT NULL,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		user_id INTEGER, -- Optional user association
		permissions TEXT NOT NULL, -- JSON array
		expires_at TIMESTAMP,
		last_used TIMESTAMP,
		usage_count INTEGER DEFAULT 0,
		enabled BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE SET NULL
	);`,

	// Audit logs table
	`CREATE TABLE IF NOT EXISTS auth_audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		api_key_id INTEGER,
		session_id TEXT,
		action VARCHAR(100) NOT NULL,
		resource VARCHAR(100) NOT NULL,
		resource_id VARCHAR(255),
		details TEXT, -- JSON object
		ip_address VARCHAR(45) NOT NULL,
		user_agent TEXT,
		success BOOLEAN NOT NULL,
		error_message TEXT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE SET NULL,
		FOREIGN KEY (api_key_id) REFERENCES auth_admin_api_keys(id) ON DELETE SET NULL
	);`,

	// Password reset tokens table
	`CREATE TABLE IF NOT EXISTS auth_password_reset_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token_hash VARCHAR(255) NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		used BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
	);`,

	// Failed logins table
	`CREATE TABLE IF NOT EXISTS auth_failed_logins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address VARCHAR(45) NOT NULL,
		username VARCHAR(255) NOT NULL,
		reason VARCHAR(100) NOT NULL, -- "invalid_credentials", "account_locked", "tfa_required"
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`,

	// Login attempts table
	`CREATE TABLE IF NOT EXISTS auth_login_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(255) NOT NULL,
		ip_address VARCHAR(45) NOT NULL,
		user_agent TEXT,
		success BOOLEAN NOT NULL,
		reason VARCHAR(255),
		user_id INTEGER,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE SET NULL
	);`,

	// Security events table
	`CREATE TABLE IF NOT EXISTS auth_security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		type VARCHAR(100) NOT NULL, -- "brute_force", "suspicious_activity", "privilege_escalation"
		severity VARCHAR(20) NOT NULL, -- "low", "medium", "high", "critical"
		title VARCHAR(255) NOT NULL,
		description TEXT NOT NULL,
		details TEXT, -- JSON object
		ip_address VARCHAR(45),
		user_id INTEGER,
		resolved BOOLEAN DEFAULT FALSE,
		resolved_at TIMESTAMP,
		resolved_by INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE SET NULL,
		FOREIGN KEY (resolved_by) REFERENCES auth_users(id) ON DELETE SET NULL
	);`,

	// TFA backup codes table
	`CREATE TABLE IF NOT EXISTS auth_tfa_backup_codes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		code_hash VARCHAR(255) NOT NULL,
		used BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
	);`,

	// TFA methods table
	`CREATE TABLE IF NOT EXISTS auth_tfa_methods (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		method VARCHAR(50) NOT NULL, -- "totp", "sms", "email"
		config TEXT, -- JSON object for method-specific config
		verified BOOLEAN DEFAULT FALSE,
		enabled BOOLEAN DEFAULT FALSE,
		last_used TIMESTAMP,
		failure_count INTEGER DEFAULT 0,
		locked_until TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
	);`,

	// Indexes for performance
	`CREATE INDEX IF NOT EXISTS idx_auth_users_username ON auth_users(username);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_users_email ON auth_users(email);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_users_role_id ON auth_users(role_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_users_enabled ON auth_users(enabled);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_user_sessions_user_id ON auth_user_sessions(user_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_user_sessions_expires_at ON auth_user_sessions(expires_at);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_user_sessions_active ON auth_user_sessions(active);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_admin_api_keys_key_id ON auth_admin_api_keys(key_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_admin_api_keys_user_id ON auth_admin_api_keys(user_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_admin_api_keys_enabled ON auth_admin_api_keys(enabled);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_admin_api_keys_expires_at ON auth_admin_api_keys(expires_at);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_user_id ON auth_audit_logs(user_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_api_key_id ON auth_audit_logs(api_key_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_timestamp ON auth_audit_logs(timestamp);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_action ON auth_audit_logs(action);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_audit_logs_resource ON auth_audit_logs(resource);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_failed_logins_ip_address ON auth_failed_logins(ip_address);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_failed_logins_timestamp ON auth_failed_logins(timestamp);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_user_id ON auth_login_attempts(user_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_timestamp ON auth_login_attempts(timestamp);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_security_events_type ON auth_security_events(type);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_security_events_severity ON auth_security_events(severity);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_security_events_resolved ON auth_security_events(resolved);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_security_events_created_at ON auth_security_events(created_at);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_password_reset_tokens_user_id ON auth_password_reset_tokens(user_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_password_reset_tokens_expires_at ON auth_password_reset_tokens(expires_at);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_tfa_backup_codes_user_id ON auth_tfa_backup_codes(user_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_tfa_backup_codes_used ON auth_tfa_backup_codes(used);`,

	`CREATE INDEX IF NOT EXISTS idx_auth_tfa_methods_user_id ON auth_tfa_methods(user_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_tfa_methods_method ON auth_tfa_methods(method);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_tfa_methods_enabled ON auth_tfa_methods(enabled);`,
}

// MySQL specific migrations
var MySQLMigrations = []string{
	// Users table
	`CREATE TABLE IF NOT EXISTS auth_users (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		full_name VARCHAR(255),
		role_id BIGINT NOT NULL,
		enabled BOOLEAN DEFAULT TRUE,
		tfa_enabled BOOLEAN DEFAULT FALSE,
		tfa_secret VARCHAR(255),
		last_login TIMESTAMP NULL,
		login_attempts INT DEFAULT 0,
		locked_until TIMESTAMP NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		FOREIGN KEY (role_id) REFERENCES auth_roles(id)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

	// Roles table
	`CREATE TABLE IF NOT EXISTS auth_roles (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(100) UNIQUE NOT NULL,
		description TEXT,
		permissions JSON NOT NULL,
		system_role BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

	// User sessions table
	`CREATE TABLE IF NOT EXISTS auth_user_sessions (
		id VARCHAR(255) PRIMARY KEY,
		user_id BIGINT NOT NULL,
		session_token_hash VARCHAR(255) NOT NULL,
		refresh_token_hash VARCHAR(255) NOT NULL,
		ip_address VARCHAR(45) NOT NULL,
		user_agent TEXT,
		expires_at TIMESTAMP NOT NULL,
		last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		active BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE CASCADE
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

	// Admin API keys table
	`CREATE TABLE IF NOT EXISTS auth_admin_api_keys (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		key_id VARCHAR(50) UNIQUE NOT NULL,
		key_hash VARCHAR(255) NOT NULL,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		user_id BIGINT,
		permissions JSON NOT NULL,
		expires_at TIMESTAMP NULL,
		last_used TIMESTAMP NULL,
		usage_count BIGINT DEFAULT 0,
		enabled BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE SET NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

	// Audit logs table
	`CREATE TABLE IF NOT EXISTS auth_audit_logs (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		user_id BIGINT,
		api_key_id BIGINT,
		session_id VARCHAR(255),
		action VARCHAR(100) NOT NULL,
		resource VARCHAR(100) NOT NULL,
		resource_id VARCHAR(255),
		details JSON,
		ip_address VARCHAR(45) NOT NULL,
		user_agent TEXT,
		success BOOLEAN NOT NULL,
		error_message TEXT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES auth_users(id) ON DELETE SET NULL,
		FOREIGN KEY (api_key_id) REFERENCES auth_admin_api_keys(id) ON DELETE SET NULL
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,

	// Remaining tables would be similar with MySQL syntax adjustments
}

// MigrationRunner handles database migrations
type MigrationRunner struct {
	db *sql.DB
}

// NewMigrationRunner creates a new migration runner
func NewMigrationRunner(db *sql.DB) *MigrationRunner {
	return &MigrationRunner{db: db}
}

// RunMigrations runs all authentication migrations
func (mr *MigrationRunner) RunMigrations(ctx context.Context, dbType string) error {
	var migrations []string

	switch dbType {
	case "mysql":
		migrations = MySQLMigrations
	default:
		migrations = Migrations
	}

	for _, migration := range migrations {
		if err := mr.runMigration(ctx, migration); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	// Insert default data
	return mr.insertDefaultData(ctx)
}

// runMigration runs a single migration
func (mr *MigrationRunner) runMigration(ctx context.Context, migration string) error {
	_, err := mr.db.ExecContext(ctx, migration)
	return err
}

// insertDefaultData inserts default roles and admin user
func (mr *MigrationRunner) insertDefaultData(ctx context.Context) error {
	// Insert default roles
	defaultRoles := DefaultRoles()
	for _, role := range defaultRoles {
		// Check if role already exists
		var count int
		err := mr.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_roles WHERE name = ?", role.Name).Scan(&count)
		if err != nil {
			return fmt.Errorf("failed to check role existence: %w", err)
		}

		if count == 0 {
			// Insert role
			_, err = mr.db.ExecContext(ctx,
				"INSERT INTO auth_roles (name, description, permissions, system_role) VALUES (?, ?, ?, ?)",
				role.Name, role.Description, toJSONString(role.Permissions), role.SystemRole)
			if err != nil {
				return fmt.Errorf("failed to insert role %s: %w", role.Name, err)
			}
		}
	}

	// Create default super admin user if no users exist
	var userCount int
	err := mr.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_users").Scan(&userCount)
	if err != nil {
		return fmt.Errorf("failed to check user count: %w", err)
	}

	if userCount == 0 {
		// Generate default admin password (in production, this should be set via environment variable)
		defaultPassword := "admin123!@#ChangeMe"
		passwordManager := NewPasswordManager(nil)
		passwordHash, err := passwordManager.HashPassword(defaultPassword)
		if err != nil {
			return fmt.Errorf("failed to hash default password: %w", err)
		}

		// Get super admin role ID
		var roleID int64
		err = mr.db.QueryRowContext(ctx, "SELECT id FROM auth_roles WHERE name = ?", RoleSuperAdmin).Scan(&roleID)
		if err != nil {
			return fmt.Errorf("failed to get super admin role ID: %w", err)
		}

		// Insert default admin user
		_, err = mr.db.ExecContext(ctx,
			`INSERT INTO auth_users (username, email, password_hash, full_name, role_id, enabled, tfa_enabled)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"admin", "admin@localhost", passwordHash, "Default Administrator", roleID, true, false)
		if err != nil {
			return fmt.Errorf("failed to create default admin user: %w", err)
		}
	}

	return nil
}

// Helper function to convert slice to JSON string
func toJSONString(data interface{}) string {
	// In a real implementation, you'd use json.Marshal
	// For now, return a placeholder
	return "[]"
}

// CreateMigrationTable creates the migration tracking table
func (mr *MigrationRunner) CreateMigrationTable(ctx context.Context, dbType string) error {
	var query string

	if dbType == "mysql" {
		query = `CREATE TABLE IF NOT EXISTS auth_migrations (
			id INT AUTO_INCREMENT PRIMARY KEY,
			version VARCHAR(255) NOT NULL UNIQUE,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`
	} else {
		query = `CREATE TABLE IF NOT EXISTS auth_migrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			version TEXT UNIQUE NOT NULL,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`
	}

	_, err := mr.db.ExecContext(ctx, query)
	return err
}

// IsMigrationApplied checks if a migration has been applied
func (mr *MigrationRunner) IsMigrationApplied(ctx context.Context, version string) (bool, error) {
	var count int
	err := mr.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM auth_migrations WHERE version = ?", version).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// MarkMigrationApplied marks a migration as applied
func (mr *MigrationRunner) MarkMigrationApplied(ctx context.Context, version string) error {
	_, err := mr.db.ExecContext(ctx, "INSERT INTO auth_migrations (version) VALUES (?)", version)
	return err
}