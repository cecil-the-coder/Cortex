#!/bin/bash

# Admin API Examples for Cortex
# This script demonstrates how to use the admin API endpoints with authentication
#
# Usage: ./admin-api-examples.sh [base_url] [username] [password]
#
# Example: ./admin-api-examples.sh http://localhost:8080 admin secure-password
#
# Environment Variables:
#   SKIP_TFA: Set to 'true' to skip TFA setup (default: false)
#   SKIP_CLEANUP: Set to 'true' to skip cleanup (default: false)
#   ADMIN_API_KEY: Use API key instead of username/password authentication

set -e

# Configuration
BASE_URL="${1:-http://localhost:8080}"
USERNAME="${2:-admin}"
PASSWORD="${3:-secure-password}"
API_BASE="$BASE_URL/admin/v1"

# Authentication tokens (will be set after login)
ACCESS_TOKEN=""
REFRESH_TOKEN=""

# API Key override (if provided via environment)
if [ -n "$ADMIN_API_KEY" ]; then
    AUTH_METHOD="api_key"
    API_KEY_HEADER="X-API-Key: $ADMIN_API_KEY"
    echo -e "\n${YELLOW}Using API Key authentication${NC}"
else
    AUTH_METHOD="jwt"
    API_KEY_HEADER=""
    echo -e "\n${YELLOW}Using JWT authentication for user: $USERNAME${NC}"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
echo_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

echo_step() {
    echo -e "\n${YELLOW}→ $1${NC}"
}

echo_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

echo_error() {
    echo -e "${RED}✗ $1${NC}"
}

echo_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Authentication functions
perform_login() {
    echo_step "Performing authentication login"

    local login_data='{
        "username": "'"$USERNAME"'",
        "password": "'"$PASSWORD"'",
        "remember_me": true
    }'

    local response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$login_data" \
        "$API_BASE/auth/login")

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n -1)

    if [ "$http_code" -eq 200 ]; then
        if command -v jq >/dev/null 2>&1; then
            ACCESS_TOKEN=$(echo "$body" | jq -r '.access_token')
            REFRESH_TOKEN=$(echo "$body" | jq -r '.refresh_token')
            USER_INFO=$(echo "$body" | jq -r '.user')
        else
            ACCESS_TOKEN=$(echo "$body" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
            REFRESH_TOKEN=$(echo "$body" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
            USER_INFO=$(echo "$body" | grep -o '"user":{[^}]*}')
        fi

        echo_success "Login successful!"
        echo "User info: $USER_INFO"
        return 0
    elif [ "$http_code" -eq 206 ]; then
        # TFA required
        echo_warning "Two-Factor Authentication required"
        if command -v jq >/dev/null 2>&1; then
            TFA_SESSION=$(echo "$body" | jq -r '.tfa_session')
        else
            TFA_SESSION=$(echo "$body" | grep -o '"tfa_session":"[^"]*"' | cut -d'"' -f4)
        fi
        return 2
    else
        echo_error "Login failed (HTTP $http_code)"
        echo "Response: $body"
        return 1
    fi
}

perform_tfa_login() {
    echo_step "Please enter your TFA code:"
    read -p "TFA Code: " tfa_code

    local tfa_data='{
        "tfa_session": "'"$TFA_SESSION"'",
        "tfa_code": "'"$tfa_code"'"
    }'

    local response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$tfa_data" \
        "$API_BASE/auth/tfa/complete")

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n -1)

    if [ "$http_code" -eq 200 ]; then
        if command -v jq >/dev/null 2>&1; then
            ACCESS_TOKEN=$(echo "$body" | jq -r '.access_token')
            REFRESH_TOKEN=$(echo "$body" | jq -r '.refresh_token')
            USER_INFO=$(echo "$body" | jq -r '.user')
        else
            ACCESS_TOKEN=$(echo "$body" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
            REFRESH_TOKEN=$(echo "$body" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
            USER_INFO=$(echo "$body" | grep -o '"user":{[^}]*}')
        fi

        echo_success "TFA login successful!"
        echo "User info: $USER_INFO"
        return 0
    else
        echo_error "TFA login failed (HTTP $http_code)"
        echo "Response: $body"
        return 1
    fi
}

refresh_access_token() {
    if [ -z "$REFRESH_TOKEN" ]; then
        echo_error "No refresh token available"
        return 1
    fi

    local response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        "$API_BASE/auth/refresh")

    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n -1)

    if [ "$http_code" -eq 200 ]; then
        if command -v jq >/dev/null 2>&1; then
            ACCESS_TOKEN=$(echo "$body" | jq -r '.access_token')
            REFRESH_TOKEN=$(echo "$body" | jq -r '.refresh_token')
        else
            ACCESS_TOKEN=$(echo "$body" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
            REFRESH_TOKEN=$(echo "$body" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
        fi
        return 0
    else
        echo_error "Token refresh failed (HTTP $http_code)"
        return 1
    fi
}

perform_logout() {
    echo_step "Performing logout"

    if [ "$AUTH_METHOD" = "jwt" ] && [ -n "$ACCESS_TOKEN" ]; then
        local response=$(curl -s -w "\n%{http_code}" \
            -X POST \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            "$API_BASE/auth/logout")

        local http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" -eq 200 ]; then
            echo_success "Logout successful"
        else
            echo_warning "Logout completed client-side only"
        fi
    fi

    ACCESS_TOKEN=""
    REFRESH_TOKEN=""
}

# API call helper
make_api_call() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    local curl_opts=(-s -w "\n%{http_code}")

    # Set authentication header
    if [ "$AUTH_METHOD" = "api_key" ]; then
        curl_opts+=(-H "$API_KEY_HEADER")
    elif [ "$AUTH_METHOD" = "jwt" ]; then
        if [ -z "$ACCESS_TOKEN" ]; then
            echo_error "No access token available"
            echo "null"
            return 401
        fi
        curl_opts+=(-H "Authorization: Bearer $ACCESS_TOKEN")
    fi

    if [ -n "$data" ]; then
        curl_opts+=(-X "$method" -H "Content-Type: application/json" -d "$data" "$API_BASE$endpoint")
    else
        curl_opts+=(-X "$method" "$API_BASE$endpoint")
    fi

    local response=$(curl "${curl_opts[@]}")
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n -1)

    # Handle token refresh for JWT authentication
    if [ "$AUTH_METHOD" = "jwt" ] && [ "$http_code" -eq 401 ]; then
        echo_warning "Access token expired, attempting refresh..."
        if refresh_access_token; then
            # Retry request with new token
            set -- "$1" "$2" "$3"  # Reset arguments
            curl_opts=()

            curl_opts+=(-s -w "\n%{http_code}" -H "Authorization: Bearer $ACCESS_TOKEN")

            if [ -n "$data" ]; then
                curl_opts+=(-X "$method" -H "Content-Type: application/json" -d "$data" "$API_BASE$endpoint")
            else
                curl_opts+=(-X "$method" "$API_BASE$endpoint")
            fi

            response=$(curl "${curl_opts[@]}")
            http_code=$(echo "$response" | tail -n1)
            body=$(echo "$response" | head -n -1)
        else
            echo_error "Failed to refresh token, please re-authenticate"
            echo "null"
            return 401
        fi
    fi

    echo "$body"
    return "$http_code"
}

# Pretty print JSON
pretty_print() {
    if command -v jq >/dev/null 2>&1; then
        echo "$1" | jq .
    else
        echo "$1"
    fi
}

# Check if server is running
check_server() {
    echo_header "Checking Server Connection"

    echo_step "Pinging server at $BASE_URL"

    if curl -s "$API_BASE/health" > /dev/null 2>&1; then
        echo_success "Server is running at $BASE_URL"
    else
        echo_error "Server is not running at $BASE_URL"
        echo_error "Please start the server first"
        exit 1
    fi
}

# Authentication demo functions
demo_authentication() {
    echo_header " Authentication Demo "

    if [ "$AUTH_METHOD" = "jwt" ]; then
        echo_step "Testing JWT authentication flow"

        # Get current user info
        echo_step "Getting current user information"
        response=$(make_api_call "GET" "/me")
        http_code=$?
        if [ $http_code -eq 200 ]; then
            echo_success "Current user info:"
            pretty_print "$response"
        else
            echo_error "Failed to get user info (HTTP $http_code)"
            pretty_print "$response"
        fi

        # Test token refresh
        echo_step "Testing token refresh mechanism"
        if refresh_access_token; then
            echo_success "Token refresh completed successfully"
        else
            echo_error "Token refresh failed"
        fi

        # Test rate limiting info (if available in user endpoint response)
        echo_step "Checking rate limiting information"
        response=$(make_api_call "GET" "/me")
        if [ $? -eq 200 ]; then
            if command -v jq >/dev/null 2>&1; then
                rate_limits=$(echo "$response" | jq '.rate_limits // {}')
                echo_success "Rate limits: $rate_limits"
            fi
        fi
    fi

    # Test API key authentication if API key was used
    if [ "$AUTH_METHOD" = "api_key" ]; then
        echo_step "Testing API key authentication"

        response=$(make_api_call "GET" "/me")
        http_code=$?
        if [ $http_code -eq 200 ]; then
            echo_success "API key authentication successful:"
            pretty_print "$response"
        else
            echo_error "API key authentication failed (HTTP $http_code)"
            pretty_print "$response"
        fi
    fi
}

demo_user_management() {
    echo_header " User Management Demo "

    # Only admin and super_admin users can manage other users
    if [ "$AUTH_METHOD" = "jwt" ]; then
        echo_step "Getting current user role"
        response=$(make_api_call "GET" "/me")
        if command -v jq >/dev/null 2>&1; then
            USER_ROLE=$(echo "$response" | jq -r '.role // "unknown"')
            echo "Current user role: $USER_ROLE"
        fi

        # Only proceed if user has management permissions
        if [ "$USER_ROLE" = "super_admin" ] || [ "$USER_ROLE" = "admin" ]; then
            echo_step "Creating a new user (operator role)"

            new_user_data='{
                "username": "demo-operator",
                "password": "demo-password-123",
                "email": "operator@example.com",
                "role": "operator",
                "tfa_enabled": false
            }'

            response=$(make_api_call "POST" "/users" "$new_user_data")
            http_code=$?
            if [ $http_code -eq 201 ]; then
                echo_success "Created new user:"
                pretty_print "$response"

                # Extract user ID for later use
                if command -v jq >/dev/null 2>&1; then
                    DEMO_USER_ID=$(echo "$response" | jq -r '.id')
                fi
            else
                echo_error "Failed to create user (HTTP $http_code)"
                pretty_print "$response"

                # User might already exist, try to get existing user
                echo_step "Attempting to get existing demo user"
                response=$(make_api_call "GET" "/users/demo-operator")
                if [ $? -eq 200 ]; then
                    echo_success "Found existing user:"
                    if command -v jq >/dev/null 2>&1; then
                        DEMO_USER_ID=$(echo "$response" | jq -r '.id')
                    fi
                fi
            fi

            # List users
            if [ -n "$DEMO_USER_ID" ]; then
                echo_step "Listing all users"
                response=$(make_api_call "GET" "/users")
                http_code=$?
                if [ $http_code -eq 200 ]; then
                    echo_success "User list:"
                    pretty_print "$response"
                else
                    echo_error "Failed to list users (HTTP $http_code)"
                    pretty_print "$response"
                fi

                # Update user role
                echo_step "Updating demo user role to 'viewer'"
                update_data='{"role": "viewer"}'

                response=$(make_api_call "PATCH" "/users/$DEMO_USER_ID" "$update_data")
                http_code=$?
                if [ $http_code -eq 200 ]; then
                    echo_success "Updated user role:"
                    pretty_print "$response"
                else
                    echo_error "Failed to update user role (HTTP $http_code)"
                    pretty_print "$response"
                fi
            fi
        else
            echo_warning "Current user role ($USER_ROLE) does not have user management permissions"
        fi
    else
        echo_warning "User management requires JWT authentication with admin privileges"
    fi
}

demo_tfa_setup() {
    echo_header " Two-Factor Authentication Demo "

    if [ "$AUTH_METHOD" != "jwt" ]; then
        echo_warning "TFA setup requires JWT authentication"
        return
    fi

    if [ "${SKIP_TFA:-false}" = "true" ]; then
        echo_warning "Skipping TFA setup (SKIP_TFA=true)"
        return
    fi

    # Check if TFA is already enabled
    response=$(make_api_call "GET" "/me")
    if [ $? -eq 200 ]; then
        if command -v jq >/dev/null 2>&1; then
            TFA_ENABLED=$(echo "$response" | jq -r '.tfa_enabled // false')
        else
            TFA_ENABLED=$(echo "$response" | grep -o '"tfa_enabled":[^,}]*' | cut -d':' -f2)
        fi

        if [ "$TFA_ENABLED" = "true" ]; then
            echo_success "TFA is already enabled for current user"
            return
        fi
    fi

    echo_step "Initiating TFA setup"
    response=$(make_api_call "POST" "/auth/tfa/setup")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "TFA setup initiated successfully!"
        echo "Response includes QR code and backup codes for demonstration"
        pretty_print "$response"

        if command -v jq >/dev/null 2>&1; then
            TFA_SECRET=$(echo "$response" | jq -r '.secret')
            echo -e "\n${YELLOW}TFA Secret for demo: $TFA_SECRET${NC}"
        fi

        echo_warning "In a real setup, you would:"
        echo "1. Scan the QR code with your authenticator app"
        echo "2. Save the backup codes in a secure location"
        echo "3. Verify the setup by entering a TOT P code"

        # For demo purposes, we'll skip the actual verification
        echo_step "Skipping TFA verification (demo mode)"
    else
        echo_error "Failed to initiate TFA setup (HTTP $http_code)"
        pretty_print "$response"
    fi
}

# API Key Management Examples
demo_api_keys() {
    echo_header "API Key Management"

    # List existing API keys (user-specific)
    echo_step "Listing existing API keys"
    response=$(make_api_call "GET" "/users/api-keys")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Retrieved API keys:"
        pretty_print "$response"
    else
        echo_error "Failed to list API keys (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Create a new API key with role-based permissions
    echo_step "Creating a new API key"
    new_key_data='{
        "name": "Demo Client Key",
        "description": "Demo client API key for testing",
        "role": "viewer",
        "expires_in": 86400,
        "allowed_ips": ["127.0.0.1", "::1"],
        "metadata": {
            "client": "demo-script",
            "environment": "testing"
        }
    }'

    response=$(make_api_call "POST" "/users/api-keys" "$new_key_data")
    http_code=$?
    if [ $http_code -eq 201 ]; then
        echo_success "Created new API key:"
        pretty_print "$response"
        # Extract the API key for later use
        if command -v jq >/dev/null 2>&1; then
            CLIENT_API_KEY=$(echo "$response" | jq -r '.api_key')
            CLIENT_KEY_ID=$(echo "$response" | jq -r '.id')
        else
            CLIENT_API_KEY=$(echo "$response" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)
            CLIENT_KEY_ID=$(echo "$response" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
        fi
        echo_success "Client API key for testing: $CLIENT_API_KEY"
    else
        echo_error "Failed to create API key (HTTP $http_code)"
        pretty_print "$response"
        CLIENT_API_KEY="sk-test-key-1-123456"  # fallback key
        CLIENT_KEY_ID="demo-key-id"
    fi

    # Update the API key
    echo_step "Updating the API key"
    update_data='{
        "description": "Updated demo client API key with more permissions",
        "role": "operator",
        "metadata": {
            "client": "demo-script",
            "environment": "testing",
            "updated": "true"
        }
    }'

    response=$(make_api_call "PUT" "/users/api-keys/$CLIENT_KEY_ID" "$update_data")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Updated API key:"
        pretty_print "$response"
    else
        echo_error "Failed to update API key (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Revoke the API key
    echo_step "Revoking the API key"
    response=$(make_api_call "DELETE" "/users/api-keys/$CLIENT_KEY_ID")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Revoked API key:"
        pretty_print "$response"
    else
        echo_error "Failed to revoke API key (HTTP $http_code)"
        pretty_print "$response"
    fi

    # List API keys again to see the change
    echo_step "Listing API keys after updates"
    response=$(make_api_call "GET" "/users/api-keys")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Updated API keys list:"
        pretty_print "$response"
    else
        echo_error "Failed to list API keys (HTTP $http_code)"
        pretty_print "$response"
    fi
}

# Model Group Management Examples
demo_model_groups() {
    echo_header "Model Group Management"

    # List existing model groups
    echo_step "Listing existing model groups"
    response=$(make_api_call "GET" "/model-groups")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Retrieved model groups:"
        pretty_print "$response"
    else
        echo_error "Failed to list model groups (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Create a new model group
    echo_step "Creating a new model group"
    model_group_data='{
        "name": "demo-production",
        "description": "Demo production models with aliases",
        "models": [
            {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "alias": "claude-latest"
            },
            {
                "provider": "openai",
                "model": "gpt-4-turbo-preview",
                "alias": "gpt4-turbo"
            }
        ]
    }'

    response=$(make_api_call "POST" "/model-groups" "$model_group_data")
    http_code=$?
    if [ $http_code -eq 201 ]; then
        echo_success "Created new model group:"
        pretty_print "$response"
    else
        echo_error "Failed to create model group (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Get model group details
    echo_step "Getting model group details"
    response=$(make_api_call "GET" "/model-groups/demo-production")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Model group details:"
        pretty_print "$response"
    else
        echo_error "Failed to get model group details (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Update the model group
    echo_step "Updating model group"
    update_group_data='{
        "description": "Updated demo production models",
        "models": [
            {
                "provider": "anthropic",
                "model": "claude-3-5-sonnet-20241022",
                "alias": "claude-latest"
            },
            {
                "provider": "openai",
                "model": "gpt-4-turbo-preview",
                "alias": "gpt4-turbo"
            },
            {
                "provider": "openai",
                "model": "gpt-4-vision-preview",
                "alias": "gpt4-vision"
            }
        ]
    }'

    response=$(make_api_call "PUT" "/model-groups/demo-production" "$update_group_data")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Updated model group:"
        pretty_print "$response"
    else
        echo_error "Failed to update model group (HTTP $http_code)"
        pretty_print "$response"
    fi
}

# Access Control Examples
demo_access_control() {
    echo_header "Access Control"

    # Check model access
    echo_step "Checking model access for different API keys and models"

    # Test 1: Valid access
    echo_step "Test 1: Valid API key with authorized model"
    access_data='{
        "api_key": "sk-test-key-1-123456",
        "model": "claude-sonnet"
    }'

    response=$(make_api_call "POST" "/access/check" "$access_data")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Access check result (should be granted):"
        pretty_print "$response"
    else
        echo_error "Failed to check access (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Test 2: Invalid API key
    echo_step "Test 2: Invalid API key"
    access_data='{
        "api_key": "sk-invalid-key",
        "model": "claude-sonnet"
    }'

    response=$(make_api_call "POST" "/access/check" "$access_data")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Access check result (should be denied):"
        pretty_print "$response"
    else
        echo_error "Failed to check access (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Test 3: Wrong model group
    echo_step "Test 3: API key with unauthorized model"
    access_data='{
        "api_key": "sk-test-key-2-123456",
        "model": "claude-sonnet"
    }'

    response=$(make_api_call "POST" "/access/check" "$access_data")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Access check result (should be denied):"
        pretty_print "$response"
    else
        echo_error "Failed to check access (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Get available models for API key
    echo_step "Getting available models for API key"
    response=$(make_api_call "GET" "/access/models/sk-test-key-1-123456")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Available models for API key:"
        pretty_print "$response"
    else
        echo_error "Failed to get available models (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Get available aliases for API key
    echo_step "Getting available aliases for API key"
    response=$(make_api_call "GET" "/access/aliases/sk-test-key-1-123456")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Available aliases for API key:"
        pretty_print "$response"
    else
        echo_error "Failed to get available aliases (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Get model group membership
    echo_step "Getting model group membership for a specific model"
    response=$(make_api_call "GET" "/access/groups/claude-sonnet")
    http_code=$?
    if [ $http_code -eq 200 ]; then
        echo_success "Model group membership:"
        pretty_print "$response"
    else
        echo_error "Failed to get model group membership (HTTP $http_code)"
        pretty_print "$response"
    fi
}

# Workflow Examples
demo_workflows() {
    echo_header "Real-World Workflows"

    # Workflow 1: Onboard a new client
    echo_step "Workflow 1: Onboarding a new client"
    echo "Creating client account, assigning to production models, setting rate limits..."

    # Create client API key
    client_data='{
        "id": "new-client-acme",
        "description": "ACME Corp - Production access",
        "model_groups": ["demo-production"],
        "enabled": true,
        "rate_limit": 500,
        "expires_at": "2024-12-31T23:59:59Z"
    }'

    response=$(make_api_call "POST" "/api-keys" "$client_data")
    http_code=$?
    if [ $http_code -eq 201 ]; then
        echo_success "Created client account:"
        pretty_print "$response"

        # Extract and save client key
        if command -v jq >/dev/null 2>&1; then
            ACME_API_KEY=$(echo "$response" | jq -r '.api_key')
        else
            ACME_API_KEY=$(echo "$response" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)
        fi
        echo_success "ACME Client API key: $ACME_API_KEY"

        # Verify access
        echo_step "Verifying client access to production models"
        verify_data="{\"api_key\": \"$ACME_API_KEY\", \"model\": \"claude-latest\"}"
        response=$(make_api_call "POST" "/access/check" "$verify_data")
        pretty_print "$response"
    else
        echo_error "Failed to create client account (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Workflow 2: Model maintenance
    echo_step "Workflow 2: Model group maintenance"
    echo "Creating a maintenance group, rotating models, updating client access..."

    # Create maintenance model group
    maintenance_data='{
        "name": "maintenance-backup",
        "description": "Backup models for maintenance",
        "models": [
            {
                "provider": "anthropic",
                "model": "claude-3-haiku-20240307",
                "alias": "claude-backup"
            }
        ]
    }'

    response=$(make_api_call "POST" "/model-groups" "$maintenance_data")
    http_code=$?
    if [ $http_code -eq 201 ]; then
        echo_success "Created maintenance model group"

        # Update some clients to use maintenance group
        update_data='{"model_groups": ["maintenance-backup"]}'
        response=$(make_api_call "PUT" "/api-keys/demo-client-1" "$update_data")
        if [ $? -eq 200 ]; then
            echo_success "Updated client to use maintenance models"
        fi
    else
        echo_error "Failed to create maintenance group (HTTP $http_code)"
        pretty_print "$response"
    fi

    # Workflow 3: Rate limiting
    echo_step "Workflow 3: Implementing rate limiting"
    echo "Applying different rate limits based on client tiers..."

    # Premium client (higher rate limit)
    premium_data='{"rate_limit": 1000}'
    response=$(make_api_call "PUT" "/api-keys/new-client-acme" "$premium_data")
    pretty_print "$response"

    # Basic client (lower rate limit)
    basic_data='{"rate_limit": 50}'
    response=$(make_api_call "PUT" "/api-keys/demo-client-1" "$basic_data")
    pretty_print "$response"
}

# Cleanup function
cleanup() {
    echo_header "Cleanup Demo Resources"

    # Remove demo resources
    echo_step "Removing demo API keys"
    make_api_call "DELETE" "/api-keys/demo-client-1" > /dev/null 2>&1 || true
    make_api_call "DELETE" "/api-keys/new-client-acme" > /dev/null 2>&1 || true

    echo_step "Removing demo model groups"
    make_api_call "DELETE" "/model-groups/demo-production" > /dev/null 2>&1 || true
    make_api_call "DELETE" "/model-groups/maintenance-backup" > /dev/null 2>&1 || true

    echo_success "Cleanup completed"
}

# Error handling and advanced examples
demo_error_handling() {
    echo_header "Error Handling Examples"

    echo_step "Test 1: Invalid authentication"
    response=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer invalid-key" "$API_BASE/api-keys" 2>/dev/null)
    echo "Response (should be 401):"
    echo "$response" | head -n -1 | pretty_print

    echo_step "Test 2: Invalid request data"
    invalid_data='{"id": "", "description": ""}'
    response=$(make_api_call "POST" "/api-keys" "$invalid_data")
    echo "Response (should be validation error):"
    pretty_print "$response"

    echo_step "Test 3: Resource not found"
    response=$(make_api_call "GET" "/api-keys/nonexistent-key")
    echo "Response (should be 404):"
    pretty_print "$response"

    echo_step "Test 4: Duplicate resource creation"
    duplicate_data='{"id": "test-key-1", "description": "duplicate"}'
    response=$(make_api_call "POST" "/api-keys" "$duplicate_data")
    echo "Response (should be conflict error):"
    pretty_print "$response"
}

# Performance testing
demo_performance() {
    echo_header "Basic Performance Testing"

    echo_step "Testing API response times..."

    # Test list API keys performance
    echo "Testing /admin/api-keys endpoint:"
    start_time=$(date +%s%N)
    response=$(make_api_call "GET" "/api-keys")
    end_time=$(date +%s%N)
    duration=$((($end_time - $start_time) / 1000000))
    echo "Response time: ${duration}ms"
    echo "Response size: $(echo "$response" | wc -c) bytes"

    # Test model groups performance
    echo "Testing /admin/model-groups endpoint:"
    start_time=$(date +%s%N)
    response=$(make_api_call "GET" "/model-groups")
    end_time=$(date +%s%N)
    duration=$((($end_time - $start_time) / 1000000))
    echo "Response time: ${duration}ms"
    echo "Response size: $(echo "$response" | wc -c) bytes"
}

# Main execution
main() {
    echo_header "Cortex Admin API Examples"
    echo "Base URL: $BASE_URL"
    echo "Authentication method: $AUTH_METHOD"

    if [ "$AUTH_METHOD" = "jwt" ]; then
        echo "User: $USERNAME"
    else
        echo "API Key: ${ADMIN_API_KEY:0:10}..."
    fi

    # Check prerequisites
    if ! command -v curl >/dev/null 2>&1; then
        echo_error "curl is required but not installed"
        exit 1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        echo_warning "Warning: jq is not installed, JSON output will not be pretty-printed"
    fi

    check_server

    # Authenticate first if using JWT
    if [ "$AUTH_METHOD" = "jwt" ]; then
        echo_step "Authenticating user"
        perform_login
        login_result=$?

        if [ $login_result -eq 1 ]; then
            echo_error "Authentication failed"
            exit 1
        elif [ $login_result -eq 2 ]; then
            # TFA required
            perform_tfa_login
            tfa_result=$?
            if [ $tfa_result -ne 0 ]; then
                echo_error "TFA authentication failed"
                exit 1
            fi
        fi
    fi

    # Run all demos
    demo_authentication
    demo_user_management
    demo_api_keys
    demo_model_groups

    # Run TFA setup demo if enabled
    if [ "${SKIP_TFA:-false}" != "true" ] && [ "$AUTH_METHOD" = "jwt" ]; then
        demo_tfa_setup
    fi

    demo_error_handling

    # Cleanup
    if [ "${SKIP_CLEANUP:-}" != "true" ]; then
        cleanup
    fi

    # Logout if using JWT
    if [ "$AUTH_METHOD" = "jwt" ]; then
        perform_logout
    fi

    echo_header "Demo Completed Successfully!"
    echo "You can now:"
    echo "1. Use the created API keys in your applications"
    echo "2. Monitor API usage and audit logs"
    echo "3. Extend these examples for your specific use cases"
    echo "4. Set up TFA for enhanced security"
    echo ""
    echo "Authentication methods demonstrated:"
    echo "- JWT token authentication with automatic refresh"
    echo "- User role-based permissions"
    echo "- API key authentication and management"
    echo "- Two-Factor Authentication setup (optional)"
    echo ""
    echo "To skip TFA setup: SKIP_TFA=true $0"
    echo "To skip cleanup: SKIP_CLEANUP=true $0"
    echo "To use API key auth: ADMIN_API_KEY=your-key $0"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Admin API Examples for Cortex with Authentication"
        echo ""
        echo "Usage: $0 [BASE_URL] [USERNAME] [PASSWORD]"
        echo "       $0 [BASE_URL]           (with ADMIN_API_KEY env var)"
        echo ""
        echo "Arguments:"
        echo "  BASE_URL     Base URL of the router (default: http://localhost:8080)"
        echo "  USERNAME     Admin username for JWT authentication (default: admin)"
        echo "  PASSWORD     Admin password for JWT authentication (default: secure-password)"
        echo ""
        echo "Environment variables:"
        echo "  ADMIN_API_KEY Use API key authentication instead of username/password"
        echo "  SKIP_TFA     Skip TFA setup demo (set to 'true' to skip)"
        echo "  SKIP_CLEANUP Skip cleanup of demo resources (set to 'true' to skip)"
        echo ""
        echo "Authentication Methods:"
        echo "  1. JWT Token: ./admin-api-examples.sh http://localhost:8080 admin password"
        echo "  2. API Key: ADMIN_API_KEY=sk-admin-123 ./admin-api-examples.sh localhost:8080"
        echo ""
        echo "Examples:"
        echo "  # JWT authentication with credentials"
        echo "  $0 http://localhost:8080 admin my-secure-password"
        echo ""
        echo "  # JWT with TFA demo disabled"
        echo "  SKIP_TFA=true $0 http://localhost:8080 admin my-secure-password"
        echo ""
        echo "  # API key authentication"
        echo "  ADMIN_API_KEY=sk-admin-12345 $0 http://localhost:8080"
        echo ""
        echo "  # Skip resource cleanup"
        echo "  SKIP_CLEANUP=true $0 http://localhost:8080 admin my-secure-password"
        echo ""
        echo "Features demonstrated:"
        echo "  • JWT token authentication with automatic refresh"
        echo "  • Role-based access control (RBAC)"
        echo "  • Two-Factor Authentication (TFA) with TOTP"
        echo "  • User management and API key creation"
        echo "  • Rate limiting and security headers"
        echo "  • Comprehensive error handling"
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac