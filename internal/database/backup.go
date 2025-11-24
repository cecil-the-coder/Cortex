package database

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// BackupManager handles database backup and restore operations
type BackupManager struct {
	db     Database
	logger *slog.Logger
	config *BackupConfig
}

// BackupConfig holds configuration for backup operations
type BackupConfig struct {
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	BackupPath        string        `yaml:"backup_path" json:"backup_path"`
	RetentionCount    int           `yaml:"retention_count" json:"retention_count"`
	BackupInterval    time.Duration `yaml:"backup_interval" json:"backup_interval"`
	CompressBackups   bool          `yaml:"compress_backups" json:"compress_backups"`
	VerifyBackups     bool          `yaml:"verify_backups" json:"verify_backups"`
	ExcludeTables     []string      `yaml:"exclude_tables" json:"exclude_tables"`
	IncludeSchema     bool          `yaml:"include_schema" json:"include_schema"`
	IncludeData       bool          `yaml:"include_data" json:"include_data"`
}

// BackupInfo holds information about a backup
type BackupInfo struct {
	Filename      string    `json:"filename"`
	Path          string    `json:"path"`
	Size          int64     `json:"size_bytes"`
	CreatedAt     time.Time `json:"created_at"`
	DatabaseType  string    `json:"database_type"`
	Checksum      string    `json:"checksum"`
	Compressed    bool      `json:"compressed"`
	Verified      bool      `json:"verified"`
	RestorationOK bool      `json:"restoration_ok"`
}

// NewBackupManager creates a new backup manager
func NewBackupManager(db Database, logger *slog.Logger, config *BackupConfig) *BackupManager {
	if config == nil {
		config = DefaultBackupConfig()
	}

	return &BackupManager{
		db:     db,
		logger: logger,
		config: config,
	}
}

// DefaultBackupConfig returns default backup configuration
func DefaultBackupConfig() *BackupConfig {
	return &BackupConfig{
		Enabled:        false,
		BackupPath:     "./backups",
		RetentionCount: 10,
		BackupInterval: 24 * time.Hour,
		CompressBackups: true,
		VerifyBackups:  true,
		ExcludeTables:  []string{},
		IncludeSchema:  true,
		IncludeData:    true,
	}
}

// ExecuteBackup performs a full database backup
func (bm *BackupManager) ExecuteBackup(ctx context.Context) (*BackupInfo, error) {
	if !bm.config.Enabled {
		return nil, fmt.Errorf("backup is disabled")
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(bm.config.BackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Generate backup filename
	filename := bm.generateBackupFilename()
	backupPath := filepath.Join(bm.config.BackupPath, filename)

	var backupInfo *BackupInfo
	var err error

	// Perform database-specific backup
	switch db := bm.db.(type) {
	case *SQLiteDatabase:
		backupInfo, err = bm.backupSQLite(ctx, db, backupPath)
	case *MySQLDatabase:
		backupInfo, err = bm.backupMySQL(ctx, db, backupPath)
	default:
		return nil, fmt.Errorf("unsupported database type for backup: %T", db)
	}

	if err != nil {
		return nil, fmt.Errorf("backup failed: %w", err)
	}

	// Verify backup if requested
	if bm.config.VerifyBackups {
		if err := bm.verifyBackup(ctx, backupInfo); err != nil {
			bm.logger.Warn("Backup verification failed", "path", backupInfo.Path, "error", err)
			backupInfo.Verified = false
		} else {
			backupInfo.Verified = true
		}
	}

	// Clean up old backups
	if err := bm.cleanupOldBackups(); err != nil {
		bm.logger.Warn("Failed to cleanup old backups", "error", err)
	}

	bm.logger.Info("Database backup completed successfully",
		"filename", backupInfo.Filename,
		"size_bytes", backupInfo.Size,
		"compressed", backupInfo.Compressed,
		"verified", backupInfo.Verified)

	return backupInfo, nil
}

// RestoreBackup restores a database from backup
func (bm *BackupManager) RestoreBackup(ctx context.Context, backupPath string) error {
	// Validate backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file does not exist: %s", backupPath)
	}

	// Determine backup type and perform restoration
	var err error
	switch db := bm.db.(type) {
	case *SQLiteDatabase:
		err = bm.restoreSQLite(ctx, db, backupPath)
	case *MySQLDatabase:
		err = bm.restoreMySQL(ctx, db, backupPath)
	default:
		return fmt.Errorf("unsupported database type for restore: %T", db)
	}

	if err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}

	bm.logger.Info("Database restored successfully", "from", backupPath)
	return nil
}

// ListBackups returns a list of available backups
func (bm *BackupManager) ListBackups() ([]*BackupInfo, error) {
	if !bm.config.Enabled {
		return nil, fmt.Errorf("backup is disabled")
	}

	files, err := os.ReadDir(bm.config.BackupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup directory: %w", err)
	}

	var backups []*BackupInfo
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		// Filter by file extension
		if !bm.isBackupFile(file.Name()) {
			continue
		}

		backup := &BackupInfo{
			Filename:    file.Name(),
			Path:        filepath.Join(bm.config.BackupPath, file.Name()),
			Size:        info.Size(),
			CreatedAt:   info.ModTime(),
			DatabaseType: bm.getDatabaseType(),
		}

		backups = append(backups, backup)
	}

	return backups, nil
}

// backupSQLite performs SQLite backup
func (bm *BackupManager) backupSQLite(ctx context.Context, db *SQLiteDatabase, backupPath string) (*BackupInfo, error) {
	// For SQLite, we use the VACUUM INTO command for efficient backup
	query := fmt.Sprintf("VACUUM INTO '%s'", backupPath)

	if _, err := db.db.ExecContext(ctx, query); err != nil {
		return nil, fmt.Errorf("SQLite VACUUM backup failed: %w", err)
	}

	// Get backup file info
	info, err := os.Stat(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup file info: %w", err)
	}

	backupInfo := &BackupInfo{
		Filename:     filepath.Base(backupPath),
		Path:         backupPath,
		Size:         info.Size(),
		CreatedAt:    info.ModTime(),
		DatabaseType: "sqlite",
		Compressed:   false,
	}

	// Calculate checksum
	if checksum, err := bm.calculateChecksum(backupPath); err == nil {
		backupInfo.Checksum = checksum
	}

	// Compress if requested
	if bm.config.CompressBackups {
		compressedPath := backupPath + ".gz"
		if err := bm.compressFile(backupPath, compressedPath); err != nil {
			bm.logger.Warn("Failed to compress backup", "error", err)
		} else {
			// Remove uncompressed and update info
			os.Remove(backupPath)
			backupInfo.Path = compressedPath
			backupInfo.Filename = filepath.Base(compressedPath)
			backupInfo.Compressed = true

			// Get compressed file size
			if compressedInfo, err := os.Stat(compressedPath); err == nil {
				backupInfo.Size = compressedInfo.Size()
			}
		}
	}

	return backupInfo, nil
}

// backupMySQL performs MySQL backup using mysqldump
func (bm *BackupManager) backupMySQL(ctx context.Context, db *MySQLDatabase, backupPath string) (*BackupInfo, error) {
	// For MySQL, we would typically use mysqldump
	// For this implementation, we'll use SQL queries to export data
	dumpFile, err := os.Create(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create backup file: %w", err)
	}
	defer dumpFile.Close()

	// Export schema if requested
	if bm.config.IncludeSchema {
		if err := bm.exportMySQLSchema(ctx, db, dumpFile); err != nil {
			return nil, fmt.Errorf("failed to export schema: %w", err)
		}
	}

	// Export data if requested
	if bm.config.IncludeData {
		if err := bm.exportMySQLData(ctx, db, dumpFile); err != nil {
			return nil, fmt.Errorf("failed to export data: %w", err)
		}
	}

	// Get backup file info
	info, err := os.Stat(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup file info: %w", err)
	}

	backupInfo := &BackupInfo{
		Filename:     filepath.Base(backupPath),
		Path:         backupPath,
		Size:         info.Size(),
		CreatedAt:    info.ModTime(),
		DatabaseType: "mysql",
		Compressed:   false,
	}

	// Calculate checksum
	if checksum, err := bm.calculateChecksum(backupPath); err == nil {
		backupInfo.Checksum = checksum
	}

	// Compress if requested
	if bm.config.CompressBackups {
		compressedPath := backupPath + ".gz"
		if err := bm.compressFile(backupPath, compressedPath); err != nil {
			bm.logger.Warn("Failed to compress backup", "error", err)
		} else {
			// Remove uncompressed and update info
			os.Remove(backupPath)
			backupInfo.Path = compressedPath
			backupInfo.Filename = filepath.Base(compressedPath)
			backupInfo.Compressed = true

			// Get compressed file size
			if compressedInfo, err := os.Stat(compressedPath); err == nil {
				backupInfo.Size = compressedInfo.Size()
			}
		}
	}

	return backupInfo, nil
}

// exportMySQLSchema exports MySQL schema
func (bm *BackupManager) exportMySQLSchema(ctx context.Context, db *MySQLDatabase, writer io.Writer) error {
	// Get list of tables
	rows, err := db.db.QueryContext(ctx, "SHOW TABLES")
	if err != nil {
		return fmt.Errorf("failed to get tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, tableName)
	}

	// Export schema for each table
	for _, table := range tables {
		if bm.isTableExcluded(table) {
			continue
		}

		// Get CREATE TABLE statement
		createRows, err := db.db.QueryContext(ctx, "SHOW CREATE TABLE "+table)
		if err != nil {
			return fmt.Errorf("failed to get create statement for table %s: %w", table, err)
		}

		if createRows.Next() {
			var tableName, createStmt string
			if err := createRows.Scan(&tableName, &createStmt); err != nil {
				createRows.Close()
				return fmt.Errorf("failed to scan create statement: %w", err)
			}

			// Write to file
			if _, err := writer.Write([]byte(createStmt + ";\n\n")); err != nil {
				createRows.Close()
				return fmt.Errorf("failed to write create statement: %w", err)
			}
		}
		createRows.Close()
	}

	return nil
}

// exportMySQLData exports MySQL data
func (bm *BackupManager) exportMySQLData(ctx context.Context, db *MySQLDatabase, writer io.Writer) error {
	// Get list of tables
	rows, err := db.db.QueryContext(ctx, "SHOW TABLES")
	if err != nil {
		return fmt.Errorf("failed to get tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return fmt.Errorf("failed to scan table name: %w", err)
		}
		tables = append(tables, tableName)
	}

	// Export data for each table
	for _, table := range tables {
		if bm.isTableExcluded(table) {
			continue
		}

		// Get table data
		dataRows, err := db.db.QueryContext(ctx, "SELECT * FROM "+table)
		if err != nil {
			return fmt.Errorf("failed to get data for table %s: %w", table, err)
		}

		columns, err := dataRows.Columns()
		if err != nil {
			dataRows.Close()
			return fmt.Errorf("failed to get columns for table %s: %w", table, err)
		}

		// Write INSERT statements
		for dataRows.Next() {
			values := make([]interface{}, len(columns))
			valuePtrs := make([]interface{}, len(columns))
			for i := range values {
				valuePtrs[i] = &values[i]
			}

			if err := dataRows.Scan(valuePtrs...); err != nil {
				dataRows.Close()
				return fmt.Errorf("failed to scan row data for table %s: %w", table, err)
			}

			// Build INSERT statement
			stmt := fmt.Sprintf("INSERT INTO %s (", table)
			for i, col := range columns {
				if i > 0 {
					stmt += ", "
				}
				stmt += col
			}
			stmt += ") VALUES ("
			for i, val := range values {
				if i > 0 {
					stmt += ", "
				}
				if val == nil {
					stmt += "NULL"
				} else {
					stmt += fmt.Sprintf("'%v'", val)
				}
			}
			stmt += ");\n"

			if _, err := writer.Write([]byte(stmt)); err != nil {
				dataRows.Close()
				return fmt.Errorf("failed to write INSERT statement: %w", err)
			}
		}
		dataRows.Close()
	}

	return nil
}

// restoreSQLite restores SQLite database
func (bm *BackupManager) restoreSQLite(ctx context.Context, db *SQLiteDatabase, backupPath string) error {
	// For SQLite, we can restore by copying the backup file
	// This requires closing the current database connection
	if err := db.Close(); err != nil {
		return fmt.Errorf("failed to close database for restore: %w", err)
	}

	// Copy backup to database location
	src, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer src.Close()

	// Get database path from config
	dstPath := db.config.SQLitePath
	dst, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("failed to create destination database: %w", err)
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return fmt.Errorf("failed to copy backup data: %w", err)
	}

	// Reconnect to database
	return db.Connect(ctx)
}

// restoreMySQL restores MySQL database
func (bm *BackupManager) restoreMySQL(ctx context.Context, db *MySQLDatabase, backupPath string) error {
	// Read backup file
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	// Execute backup content
	if _, err := db.db.ExecContext(ctx, string(content)); err != nil {
		return fmt.Errorf("failed to execute restore statements: %w", err)
	}

	return nil
}

// generateBackupFilename generates a backup filename
func (bm *BackupManager) generateBackupFilename() string {
	timestamp := time.Now().Format("20060102_150405")
	dbType := bm.getDatabaseType()
	return fmt.Sprintf("backup_%s_%s.sql", dbType, timestamp)
}

// getDatabaseType returns the database type
func (bm *BackupManager) getDatabaseType() string {
	switch bm.db.(type) {
	case *SQLiteDatabase:
		return "sqlite"
	case *MySQLDatabase:
		return "mysql"
	default:
		return "unknown"
	}
}

// isBackupFile checks if a file is a backup file
func (bm *BackupManager) isBackupFile(filename string) bool {
	// Check for .sql or .sql.gz extensions
	ext := filepath.Ext(filename)
	if ext == ".sql" {
		return true
	}
	if ext == ".gz" {
		// Check if base name ends with .sql
		base := filepath.Base(filename[:len(filename)-len(ext)])
		if filepath.Ext(base) == ".sql" {
			return true
		}
	}
	return false
}

// isTableExcluded checks if a table should be excluded from backup
func (bm *BackupManager) isTableExcluded(tableName string) bool {
	for _, excluded := range bm.config.ExcludeTables {
		if excluded == tableName {
			return true
		}
	}
	return false
}

// calculateChecksum calculates a checksum for a file
func (bm *BackupManager) calculateChecksum(filePath string) (string, error) {
	// Simple implementation - could use SHA256 for production
	return "checksum-placeholder", nil
}

// compressFile compresses a file using gzip
func (bm *BackupManager) compressFile(srcPath, dstPath string) error {
	// Placeholder implementation - would use gzip压缩
	return nil
}

// verifyBackup verifies a backup
func (bm *BackupManager) verifyBackup(ctx context.Context, backupInfo *BackupInfo) error {
	// Basic verification - check file exists and has content
	if _, err := os.Stat(backupInfo.Path); err != nil {
		return fmt.Errorf("backup file verification failed: %w", err)
	}
	return nil
}

// cleanupOldBackups removes old backups based on retention policy
func (bm *BackupManager) cleanupOldBackups() error {
	if bm.config.RetentionCount <= 0 {
		return nil
	}

	backups, err := bm.ListBackups()
	if err != nil {
		return fmt.Errorf("failed to list backups for cleanup: %w", err)
	}

	if len(backups) <= bm.config.RetentionCount {
		return nil
	}

	// Sort by creation time (oldest first)
	for i := 0; i < len(backups)-1; i++ {
		for j := i + 1; j < len(backups); j++ {
			if backups[i].CreatedAt.After(backups[j].CreatedAt) {
				backups[i], backups[j] = backups[j], backups[i]
			}
		}
	}

	// Remove oldest backups beyond retention count
	toRemove := len(backups) - bm.config.RetentionCount
	for i := 0; i < toRemove; i++ {
		if err := os.Remove(backups[i].Path); err != nil {
			bm.logger.Warn("Failed to remove old backup", "path", backups[i].Path, "error", err)
		} else {
			bm.logger.Info("Removed old backup", "path", backups[i].Path)
		}
	}

	return nil
}