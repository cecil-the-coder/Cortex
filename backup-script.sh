#!/bin/bash

# Database backup script for Cortex
# This script backs up the PostgreSQL database with authentication data

set -e

# Configuration
BACKUP_DIR="/backups"
DB_NAME="go_llm_router"
DB_USER="router_user"
DB_HOST="postgres"
RETENTION_DAYS=30
DATE_FORMAT=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/router_backup_${DATE_FORMAT}.sql.gz"
PASSWORD_FILE="/run/secrets/db-password"

# Check if password file exists and is readable
if [[ ! -f "$PASSWORD_FILE" ]]; then
    echo "Error: Database password file not found at $PASSWORD_FILE"
    exit 1
fi

# Read database password
export PGPASSWORD=$(cat "$PASSWORD_FILE")

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo "Starting database backup for ${DB_NAME}..."

# Create database backup
pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" --no-owner --no-privileges --compress=9 > "$BACKUP_FILE"

if [[ $? -eq 0 ]]; then
    echo "Backup completed successfully: $BACKUP_FILE"

    # Get backup size
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "Backup size: $BACKUP_SIZE"

    # Clean up old backups (keep only the last RETENTION_DAYS days)
    echo "Cleaning up backups older than $RETENTION_DAYS days..."
    find "$BACKUP_DIR" -name "router_backup_*.sql.gz" -type f -mtime +$RETENTION_DAYS -delete

    if [[ $? -eq 0 ]]; then
        echo "Cleanup completed successfully"
    else
        echo "Warning: Cleanup failed"
    fi

    # List remaining backups
    echo "Available backups:"
    ls -lh "$BACKUP_DIR"/router_backup_*.sql.gz 2>/dev/null || echo "No backup files found"

else
    echo "Error: Backup failed"
    exit 1
fi

# Verify backup integrity
echo "Verifying backup integrity..."
if gunzip -t "$BACKUP_FILE"; then
    echo "Backup integrity verified successfully"
else
    echo "Error: Backup integrity check failed"
    exit 1
fi

echo "Database backup process completed successfully"