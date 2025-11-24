#!/bin/bash

# Cortex Authentication Setup Script
# This script helps set up authentication configuration and initial users

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONFIG_DIR="./config"
SECRETS_DIR="./secrets"
SSL_DIR="./ssl"
LOGS_DIR="./logs"

# Helper functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

print_step() {
    echo -e "\n${YELLOW}→ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to generate secure random string
generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -d "=+/" | cut -c1-32
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c "import secrets; print(secrets.token_urlsafe(32))"
    else
        # Fallback method
        LC_CTYPE=C tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 32
    fi
}

# Function to prompt for user input with default
prompt_input() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"

    if [ -n "$default" ]; then
        read -p "$prompt [$default]: " input
        input="${input:-$default}"
    else
        read -p "$prompt: " input
    fi

    if [ -n "$var_name" ]; then
        eval "$var_name='$input'"
    fi
}

# Function to prompt for password
prompt_password() {
    local prompt="$1"
    local var_name="$2"
    local password

    while true; do
        read -s -p "$prompt: " password
        echo
        read -s -p "Confirm password: " confirm
        echo

        if [ "$password" = "$confirm" ]; then
            if [ -n "$var_name" ]; then
                eval "$var_name='$password'"
            fi
            break
        else
            print_error "Passwords do not match, please try again"
        fi
    done
}

# Main setup function
main() {
    print_header "Cortex Authentication Setup"
    echo "This script will help you set up authentication for Cortex"
    echo "It will create configuration files, secrets, and initial users"
    echo

    # Check if running as root (not recommended for setup)
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root is not recommended for this setup"
        print_warning "Consider creating a dedicated user for Cortex"
        read -p "Continue anyway? (y/N): " continue_as_root
        if [[ ! "$continue_as_root" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    # Create necessary directories
    print_step "Creating directory structure"
    mkdir -p "$CONFIG_DIR" "$SECRETS_DIR" "$SSL_DIR" "$LOGS_DIR"
    print_success "Directory structure created"

    # Generate secrets
    print_step "Generating secure secrets"

    JWT_SECRET=$(generate_secret)
    echo "$JWT_SECRET" > "$SECRETS_DIR/jwt-secret"
    chmod 600 "$SECRETS_DIR/jwt-secret"
    print_success "JWT secret generated"

    DB_PASSWORD=$(generate_secret)
    echo "$DB_PASSWORD" > "$SECRETS_DIR/db-password"
    chmod 600 "$SECRETS_DIR/db-password"
    print_success "Database password generated"

    REDIS_PASSWORD=$(generate_secret)
    echo "$REDIS_PASSWORD" > "$SECRETS_DIR/redis-password"
    chmod 600 "$SECRETS_DIR/redis-password"
    print_success "Redis password generated"

    # Create environment file
    print_step "Creating environment configuration"
    if [ ! -f ".env" ]; then
        cp .env.auth.template .env
        print_success "Environment file created from template"

        # Update environment file with generated secrets
        sed -i "s|your-very-secure-random-secret-key-change-this-in-production|$JWT_SECRET|g" .env
        sed -i "s|secure_password|$DB_PASSWORD|g" .env
        echo "" >> .env
        echo "# Generated secrets (added by setup script)" >> .env
        echo "DB_DSN=postgres://router_user:$DB_PASSWORD@localhost/go_llm_router?sslmode=disable" >> .env
        echo "REDIS_PASSWORD=$REDIS_PASSWORD" >> .env
        print_success "Environment file updated with generated secrets"
    else
        print_warning ".env file already exists, skipping creation"
    fi

    # Create configuration files
    print_step "Creating configuration files"

    if [ ! -f "$CONFIG_DIR/config.json" ]; then
        cp config-with-admin-auth.json "$CONFIG_DIR/config.json"
        # Update config with actual generated secrets
        sed -i "s|your-very-secure-random-secret-key-change-this-in-production|$JWT_SECRET|g" "$CONFIG_DIR/config.json"
        sed -i "s|postgres://router_user:secure_password@localhost/go_llm_router?sslmode=require|postgres://router_user:$DB_PASSWORD@localhost/go_llm_router?sslmode=disable|g" "$CONFIG_DIR/config.json"
        print_success "Production configuration file created"
    fi

    if [ ! -f "$CONFIG_DIR/config-dev.json" ]; then
        cp config-dev-auth.json "$CONFIG_DIR/config-dev.json"
        print_success "Development configuration file created"
    fi

    # Setup initial admin user
    print_step "Initial admin user setup"

    echo "The initial admin user will have super_admin privileges"
    prompt_input "Admin username" "admin" ADMIN_USERNAME
    prompt_password "Admin password" ADMIN_PASSWORD
    prompt_input "Admin email" "admin@example.com" ADMIN_EMAIL

    # Create admin user setup script
    cat > "$SECRETS_DIR/admin-user-setup.sql" << EOF
-- Initial admin user setup
-- This file contains hashed password for the admin user

-- Update the existing admin user or insert a new one
INSERT INTO users (username, email, password_hash, role, tfa_enabled)
VALUES ('$ADMIN_USERNAME', '$ADMIN_EMAIL', '$(echo -n "$ADMIN_PASSWORD" | openssl passwd -6 -stdin 2>/dev/null || echo "HASH_FAILED")', 'super_admin', false)
ON CONFLICT (username)
DO UPDATE SET
    email = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    role = EXCLUDED.role,
    updated_at = NOW();
EOF

    chmod 600 "$SECRETS_DIR/admin-user-setup.sql"
    print_success "Admin user setup created"

    # SSL Certificate setup
    print_step "SSL Certificate setup"

    if [ ! -f "$SSL_DIR/router.crt" ] || [ ! -f "$SSL_DIR/router.key" ]; then
        read -p "Generate self-signed SSL certificate for development? (y/N): " generate_ssl
        if [[ "$generate_ssl" =~ ^[Yy]$ ]]; then
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout "$SSL_DIR/router.key" \
                -out "$SSL_DIR/router.crt" \
                -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null || {
                print_error "Failed to generate SSL certificate"
                print_error "Please install OpenSSL and try again"
            }

            if [ -f "$SSL_DIR/router.crt" ]; then
                chmod 600 "$SSL_DIR/router.key"
                chmod 644 "$SSL_DIR/router.crt"
                print_success "Self-signed SSL certificate generated"
            fi
        else
            print_warning "SSL certificate not generated"
            print_warning "You'll need to provide your own certificates for HTTPS"
        fi
    else
        print_warning "SSL certificates already exist, skipping generation"
    fi

    # Docker setup
    print_step "Docker Compose setup"

    if command -v docker >/dev/null 2>&1 && command -v docker-compose >/dev/null 2>&1; then
        read -p "Create docker-compose.override.yml for local development? (y/N): " create_docker_override
        if [[ "$create_docker_override" =~ ^[Yy]$ ]]; then
            cat > docker-compose.override.yml << EOF
version: '3.8'

services:
  router:
    volumes:
      - ./config:/config:ro
      - ./secrets:/run/secrets:ro
      - ./ssl:/ssl:ro
      - ./logs:/var/log/Cortex:rw
    environment:
      - ADMIN_DEFAULT_USER=$ADMIN_USERNAME
      - ADMIN_DEFAULT_PASSWORD=$ADMIN_PASSWORD

  postgres:
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./secrets/db-password:/run/secrets/db-password:ro
EOF
            print_success "Docker override file created"
        fi

        read -p "Pull required Docker images? (y/N): " pull_images
        if [[ "$pull_images" =~ ^[Yy]$ ]]; then
            docker-compose -f docker-compose-with-auth.yml pull
            print_success "Docker images pulled"
        fi
    else
        print_warning "Docker not found, skipping Docker setup"
    fi

    # Create startup script
    print_step "Creating startup script"

    cat > start-auth.sh << 'EOF'
#!/bin/bash

# Cortex Startup Script with Authentication
# This script starts the router with authentication enabled

# Configuration
CONFIG_FILE="./config/config.json"
LOG_FILE="./logs/router.log"
PID_FILE="./logs/router.pid"

# Function to check if process is running
is_running() {
    [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null
}

# Function to start the router
start_router() {
    if is_running; then
        echo "Router is already running (PID: $(cat $PID_FILE))"
        return 1
    fi

    echo "Starting Cortex with authentication..."

    # Create logs directory if it doesn't exist
    mkdir -p "$(dirname "$LOG_FILE")"

    # Start the router
    nohup ./Cortex --config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"

    # Wait a moment and check if it started successfully
    sleep 2
    if is_running; then
        echo "Router started successfully (PID: $(cat $PID_FILE))"
        echo "Log file: $LOG_FILE"
        echo "Admin UI: http://localhost:8081"
        echo "API: http://localhost:8080"
    else
        echo "Failed to start router"
        rm -f "$PID_FILE"
        return 1
    fi
}

# Function to stop the router
stop_router() {
    if ! is_running; then
        echo "Router is not running"
        return 1
    fi

    echo "Stopping router..."
    kill "$(cat "$PID_FILE")"

    # Wait for graceful shutdown
    for i in {1..10}; do
        if ! is_running; then
            echo "Router stopped successfully"
            rm -f "$PID_FILE"
            return 0
        fi
        sleep 1
    done

    # Force kill if still running
    echo "Force killing router..."
    kill -9 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null || true
    rm -f "$PID_FILE"
    echo "Router stopped"
}

# Function to show status
show_status() {
    if is_running; then
        echo "Router is running (PID: $(cat $PID_FILE))"
        echo "Uptime: $(ps -o etime= -p "$(cat $PID_FILE)" | tr -d ' ')"
    else
        echo "Router is not running"
    fi
}

# Main logic
case "${1:-}" in
    start)
        start_router
        ;;
    stop)
        stop_router
        ;;
    restart)
        stop_router
        sleep 1
        start_router
        ;;
    status)
        show_status
        ;;
    logs)
        if [ -f "$LOG_FILE" ]; then
            tail -f "$LOG_FILE"
        else
            echo "Log file not found: $LOG_FILE"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOF

    chmod +x start-auth.sh
    print_success "Startup script created"

    # Final summary
    print_header "Setup Complete!"
    echo "Authentication setup has been completed successfully."
    echo ""
    echo "Files created:"
    echo "  • Configuration: $CONFIG_DIR/"
    echo "  • Secrets: $SECRETS_DIR/"
    echo "  • SSL: $SSL_DIR/"
    echo "  • Logs: $LOGS_DIR/"
    echo "  • Scripts: start-auth.sh"
    echo ""
    echo "Admin user created:"
    echo "  • Username: $ADMIN_USERNAME"
    echo "  • Email: $ADMIN_EMAIL"
    echo "  • Password: [hidden for security]"
    echo ""
    echo "Next steps:"
    echo "1. Start the router: ./start-auth.sh start"
    echo "2. Access admin UI: http://localhost:8081"
    echo "3. Login with admin credentials"
    echo "4. Configure additional users and API keys"
    echo ""
    echo "Security notes:"
    echo "• Store the secrets directory securely"
    echo "• Change passwords before production deployment"
    echo "• Use proper SSL certificates in production"
    echo "• Enable rate limiting and audit logging"
    echo ""
    echo "For production deployment:"
    echo "• Use docker-compose-with-auth.yml"
    echo "• Set up proper database backups"
    echo "• Configure monitoring and alerting"
    echo "• Review security settings in configuration"
}

# Check if user wants to proceed
echo "This setup will create authentication configuration for Cortex."
echo "It will generate secure secrets and initial user accounts."
echo ""
read -p "Continue with setup? (y/N): " proceed

if [[ "$proceed" =~ ^[Yy]$ ]]; then
    main "$@"
else
    echo "Setup cancelled"
    exit 0
fi