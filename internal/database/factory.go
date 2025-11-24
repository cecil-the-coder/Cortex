package database

import (
	"database/sql"
	"fmt"
	"log/slog"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"

	// "github.com/cecil-the-coder/Cortex/internal/cache" // TODO: implement cache module
)

// NewDatabase creates a database instance based on configuration
func NewDatabase(config *DatabaseConfig, logger *slog.Logger) (Database, error) {
	var db Database
	var err error

	switch config.Type {
	case "sqlite":
		db, err = NewSQLiteDatabase(config, logger)
	case "mysql":
		db, err = NewMySQLDatabase(config, logger)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", config.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	return db, nil
}

// Cache factory - TODO: implement cache module
// func NewCache(config *cache.Config, logger *slog.Logger) (cache.Cache, error) {
// 	if !config.Enabled {
// 		return cache.NewNoOpCache(), nil
// 	}
//
// 	switch config.Type {
// 	case "memory":
// 		return cache.NewMemoryCache(config.MaxSize, config.TTL), nil
// 	case "redis":
// 		return cache.NewRedisCache(config.Redis, logger)
// 	default:
// 		return nil, fmt.Errorf("unsupported cache type: %s", config.Type)
// 	}
// }

// Helper function to setup connection pool
func SetupConnectionPool(db *sql.DB, config *DatabaseConfig, dbType string) error {
	// Set default values based on database type
	switch dbType {
	case "sqlite":
		// SQLite works best with a single connection
		if config.MaxOpenConns == 0 {
			config.MaxOpenConns = 1
		}
		if config.MaxIdleConns == 0 {
			config.MaxIdleConns = 1
		}
	case "mysql":
		// MySQL can handle more connections
		if config.MaxOpenConns == 0 {
			config.MaxOpenConns = 25
		}
		if config.MaxIdleConns == 0 {
			config.MaxIdleConns = 5
		}
	}

	db.SetMaxOpenConns(config.MaxOpenConns)
	db.SetMaxIdleConns(config.MaxIdleConns)

	if config.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(config.ConnMaxLifetime)
	}

	if config.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(config.ConnMaxIdleTime)
	}

	return nil
}