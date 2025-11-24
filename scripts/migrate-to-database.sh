#!/bin/bash

# Migration Script: File-based Configuration to Database Backend
# This script helps migrate existing Cortex deployments from file-based config to database backend

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CURRENT_CONFIG_FILE="${CONFIG_FILE:-config.json}"
DB_TYPE="${DB_TYPE:-sqlite}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_NAME="${DB_NAME:-go_llm_router}"
DB_USER="${DB_USER:-router_user}"
DB_PASSWORD="${DB_PASSWORD}"
SQLITE_PATH="${SQLITE_PATH:-./data/router.db}"

print_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE       Database type (sqlite, mysql, postgres) [default: sqlite]"
    echo "  -h, --host HOST       Database host [default: localhost]"
    echo "  -p, --port PORT       Database port [default: 3306/5432]"
    echo "  -d, --database NAME   Database name [default: go_llm_router]"
    echo "  -u, --user USER       Database user [default: router_user]"
    echo "  -P, --password PASS   Database password [required for mysql/postgres]"
    echo "  -s, --sqlite PATH     SQLite database path [default: ./data/router.db]"
    echo "  -c, --config FILE     Current config file path [default: config.json]"
    echo "  --dry-run             Show what would be done without making changes"
    echo "  -v, --verbose         Verbose output"
    echo "  --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  # SQLite migration"
    echo "  $0 -t sqlite"
    echo ""
    echo "  # MySQL migration with environment variables"
    echo "  DB_HOST=localhost DB_PASSWORD=secret $0 -t mysql"
    echo ""
    echo "  # PostgreSQL migration"
    echo "  $0 -t postgres -h db.example.com -p 5432 -d router_prod -u router_user -P secret"
}

# Parse command line arguments
DRY_RUN=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            DB_TYPE="$2"
            shift 2
            ;;
        -h|--host)
            DB_HOST="$2"
            shift 2
            ;;
        -p|--port)
            DB_PORT="$2"
            shift 2
            ;;
        -d|--database)
            DB_NAME="$2"
            shift 2
            ;;
        -u|--user)
            DB_USER="$2"
            shift 2
            ;;
        -P|--password)
            DB_PASSWORD="$2"
            shift 2
            ;;
        -s|--sqlite)
            SQLITE_PATH="$2"
            shift 2
            ;;
        -c|--config)
            CURRENT_CONFIG_FILE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            print_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_help
            exit 1
            ;;
    esac
done

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${NC}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    fi
}

# Validate inputs
validate_inputs() {
    log "Validating migration configuration..."

    if [ ! -f "$CURRENT_CONFIG_FILE" ]; then
        error "Configuration file not found: $CURRENT_CONFIG_FILE"
        exit 1
    fi

    case "$DB_TYPE" in
        sqlite)
            # Create directory for SQLite database if it doesn't exist
            SQLITE_DIR=$(dirname "$SQLITE_PATH")
            if [ ! -d "$SQLITE_DIR" ]; then
                if [ "$DRY_RUN" = false ]; then
                    mkdir -p "$SQLITE_DIR"
                    log "Created SQLite directory: $SQLITE_DIR"
                else
                    log "[DRY RUN] Would create SQLite directory: $SQLITE_DIR"
                fi
            fi
            ;;
        mysql|postgres)
            if [ -z "$DB_PASSWORD" ]; then
                error "Database password is required for $DB_TYPE"
                exit 1
            fi
            ;;
        *)
            error "Unsupported database type: $DB_TYPE"
            exit 1
            ;;
    esac

    verbose "Configuration validated successfully"
}

# Create new database configuration
create_db_config() {
    log "Creating database-backed configuration..."

    local new_config_file="config-${DB_TYPE}-$(date +%Y%m%d-%H%M%S).json"

    # Database configuration based on type
    local db_config=""
    case "$DB_TYPE" in
        sqlite)
            db_config=$(cat <<EOF
    "Database": {
      "enabled": true,
      "primary": {
        "type": "sqlite",
        "sqlite_path": "$(realpath "$SQLITE_PATH")",
        "sqlite_wal_mode": true,
        "sqlite_cache_size": 2000,
        "max_open_conns": 25,
        "max_idle_conns": 5,
        "conn_max_lifetime": "5m",
        "conn_max_idle_time": "1m",
        "batch_size": 100,
        "flush_interval": "5s"
      },
      "fallback": {
        "use_file_on_failure": true,
        "config_path": "$CURRENT_CONFIG_FILE",
        "retry_delay": "30s",
        "sync_on_recovery": true
      },
      "cache": {
        "enabled": true,
        "ttl": "5m",
        "max_entries": 1000,
        "cleanup_interval": "10m"
      }
    }
EOF
)
            ;;
        mysql)
            db_config=$(cat <<EOF
    "Database": {
      "enabled": true,
      "primary": {
        "type": "mysql",
        "host": "$DB_HOST",
        "port": $DB_PORT,
        "database": "$DB_NAME",
        "username": "$DB_USER",
        "password": "$DB_PASSWORD",
        "mysql_charset": "utf8mb4",
        "mysql_collation": "utf8mb4_unicode_ci",
        "mysql_parse_time": true,
        "max_open_conns": 50,
        "max_idle_conns": 10,
        "conn_max_lifetime": "10m",
        "conn_max_idle_time": "2m",
        "batch_size": 200,
        "flush_interval": "3s"
      },
      "fallback": {
        "use_file_on_failure": true,
        "config_path": "$CURRENT_CONFIG_FILE",
        "retry_delay": "60s",
        "sync_on_recovery": true
      },
      "cache": {
        "enabled": true,
        "ttl": "10m",
        "max_entries": 2000,
        "cleanup_interval": "5m"
      }
    }
EOF
)
            ;;
        postgres)
            db_config=$(cat <<EOF
    "Database": {
      "enabled": true,
      "primary": {
        "type": "postgres",
        "host": "$DB_HOST",
        "port": $DB_PORT,
        "database": "$DB_NAME",
        "username": "$DB_USER",
        "password": "$DB_PASSWORD",
        "max_open_conns": 100,
        "max_idle_conns": 20,
        "conn_max_lifetime": "15m",
        "conn_max_idle_time": "5m",
        "batch_size": 500,
        "flush_interval": "1s"
      },
      "fallback": {
        "use_file_on_failure": true,
        "config_path": "$CURRENT_CONFIG_FILE",
        "retry_delay": "45s",
        "sync_on_recovery": true
      },
      "cache": {
        "enabled": true,
        "ttl": "15m",
        "max_entries": 5000,
        "cleanup_interval": "3m"
      }
    }
EOF
)
            ;;
    esac

    # Create new config file by merging existing config with database config
    if [ "$DRY_RUN" = true ]; then
        log "[DRY RUN] Would create new configuration file: $new_config_file"
        log "[DRY RUN] Database configuration would be added to existing configuration"
        return
    fi

    # Use jq to merge JSON configurations
    if command -v jq &> /dev/null; then
        jq --arg dbconfig "$db_config" '. + ($dbconfig | fromjson)' "$CURRENT_CONFIG_FILE" > "$new_config_file"
        log "Created new database-backed configuration: $new_config_file"
    else
        error "jq is required for JSON manipulation. Please install jq."
        exit 1
    fi
}

# Backup existing configuration
backup_config() {
    log "Creating backup of existing configuration..."

    local backup_file="${CURRENT_CONFIG_FILE}.backup.$(date +%Y%m%d-%H%M%S)"

    if [ "$DRY_RUN" = true ]; then
        log "[DRY RUN] Would create backup: $backup_file"
        return
    fi

    cp "$CURRENT_CONFIG_FILE" "$backup_file"
    log "Configuration backed up to: $backup_file"
}

# Setup database (for MySQL/PostgreSQL)
setup_database() {
    if [ "$DB_TYPE" = "sqlite" ]; then
        verbose "SQLite setup not required (database will be created on first run)"
        return
    fi

    log "Setting up $DB_TYPE database..."

    if [ "$DRY_RUN" = true ]; then
        log "[DRY RUN] Would create database: $DB_NAME"
        log "[DRY RUN] Would grant access to user: $DB_USER"
        return
    fi

    case "$DB_TYPE" in
        mysql)
            # MySQL setup commands
            mysql -h "$DB_HOST" -P "$DB_PORT" -u root -p <<EOF
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'%';
FLUSH PRIVILEGES;
EOF
            ;;
        postgres)
            # PostgreSQL setup commands
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U postgres <<EOF
CREATE DATABASE "$DB_NAME";
CREATE USER "$DB_USER" WITH PASSWORD '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE "$DB_NAME" TO "$DB_USER";
\q
EOF
            ;;
    esac

    log "Database setup completed"
}

# Validate new configuration
validate_new_config() {
    log "Validating new configuration..."

    local new_config_file
    new_config_file=$(ls -t config-${DB_TYPE}-*.json | head -n 1)

    if [ "$DRY_RUN" = true ]; then
        log "[DRY RUN] Would validate configuration file: $new_config_file"
        return
    fi

    # Try to validate by starting the router with the new configuration
    if timeout 10s ./router -config "$new_config_file" -version &> /dev/null; then
        log "Configuration validation passed"
    else
        error "Configuration validation failed"
        warn "Please check the new configuration file: $new_config_file"
        exit 1
    fi
}

# Print next steps
print_next_steps() {
    local new_config_file
    new_config_file=$(ls -t config-${DB_TYPE}-*.json | head -n 1)

    log "Migration preparation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Review the new configuration file: $new_config_file"
    echo "2. Test with the new configuration:"
    echo "   ./router -config $new_config_file -enable-admin"
    echo "3. If everything works, replace the old configuration:"
    echo "   mv $CURRENT_CONFIG_FILE ${CURRENT_CONFIG_FILE}.old"
    echo "   mv $new_config_file $CURRENT_CONFIG_FILE"
    echo "4. Verify the database is working by checking:"
    echo "   curl http://localhost:8081/admin/v1/system/database/status"
    echo ""
    echo "Database configuration details:"
    verbose "Type: $DB_TYPE"
    verbose "Configuration file: $new_config_file"
    verbose "Fallback file: $CURRENT_CONFIG_FILE"
}

# Main execution
main() {
    log "Starting migration from file-based to database-backed configuration"
    log "Current config: $CURRENT_CONFIG_FILE"
    log "Target database: $DB_TYPE"

    validate_inputs
    backup_config
    setup_database
    create_db_config
    validate_new_config
    print_next_steps
}

# Run main function
main "$@"