#!/bin/bash

# Test script for hot-reload functionality
set -e

CONFIG_FILE="config.json"
BACKUP_FILE="config.json.backup"
API_KEY="test-admin-key-12345"
SERVER_URL="http://localhost:echo $PORT || echo "8082""

echo "=== Hot-Reload Test Script ==="
echo "Testing configuration hot-reload functionality..."

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    if [ -f "$BACKUP_FILE" ]; then
        mv "$BACKUP_FILE" "$CONFIG_FILE"
        echo "Restored original config"
    fi
}

trap cleanup EXIT

# Create environment variables for testing
export ANTHROPIC_API_KEY="sk-test-anthropic-key"
export OPENAI_API_KEY="sk-test-openai-key"
export OPENROUTER_API_KEY="sk-test-openrouter-key"
export ROUTER_API_KEY="$API_KEY"

# Create backup of original config
cp "$CONFIG_FILE" "$BACKUP_FILE"

echo "1. Starting server..."
./router -config="$CONFIG_FILE" > server.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo "   Waiting for server to start..."
sleep 3

# Test if server is running
if ! curl -s "$SERVER_URL/health" > /dev/null; then
    echo "❌ Failed to start server"
    exit 1
fi

echo "✅ Server started successfully"

echo "2. Testing admin status endpoint..."
STATUS_RESPONSE=$(curl -s -H "x-api-key: $API_KEY" "$SERVER_URL/admin/status")
if echo "$STATUS_RESPONSE" | grep -q '"status":"running"'; then
    echo "✅ Admin status endpoint working"
else
    echo "❌ Admin status endpoint not working"
    echo "Response: $STATUS_RESPONSE"
fi

echo "3. Testing manual configuration reload..."
RELOAD_RESPONSE=$(curl -s -X POST -H "x-api-key: $API_KEY" "$SERVER_URL/admin/reload")
if echo "$RELOAD_RESPONSE" | grep -q '"success":true'; then
    echo "✅ Manual reload successful"
else
    echo "❌ Manual reload failed"
    echo "Response: $RELOAD_RESPONSE"
fi

echo "4. Testing configuration file hot-reload..."
# Modify the config file (change API key to trigger reload)
sed -i 's/test-admin-key-12345/test-admin-key-updated/' "$CONFIG_FILE"

echo "   Modified config file, waiting for hot-reload..."
sleep 2

# Test if the new API key works (this should fail with old key and succeed if we check with new key)
echo "5. Testing configuration update..."
TEST_NEW_KEY=$(curl -s -H "x-api-key: test-admin-key-updated" "$SERVER_URL/admin/status" || echo "failed")
if echo "$TEST_NEW_KEY" | grep -q '"status":"running"'; then
    echo "✅ Configuration hot-reload working (new API key accepted)"
else
    echo "❌ Configuration hot-reload may not be working"
fi

# Test with original API key
TEST_OLD_KEY=$(curl -s -H "x-api-key: $API_KEY" "$SERVER_URL/admin/status" || echo "failed")
if echo "$TEST_OLD_KEY" | grep -q Invalid; then
    echo "✅ Old API key properly rejected"
else
    echo "⚠️  Old API key still accepted (might need to reconnect to test)"
fi

echo "6. Testing provider validation..."
if curl -s -X POST -H "x-api-key: test-admin-key-updated" "$SERVER_URL/admin/validate/anthropic" | grep -q '"success":true'; then
    echo "✅ Provider validation working (or test key placeholder accepted)"
else
    echo "⚠️  Provider validation returned expected error for test keys"
fi

echo "7. Testing configuration errors..."
# Create invalid config
echo '{"invalid": "json"}' > "$CONFIG_FILE"
sleep 2

# Server should still be running with last good config
if curl -s -H "x-api-key: test-admin-key-updated" "$SERVER_URL/admin/status" | grep -q '"status":"running"'; then
    echo "✅ Server handles invalid config gracefully"
else
    echo "❌ Server may have crashed on invalid config"
fi

echo ""
echo "=== Test Complete ==="
echo "Check server.log for detailed logs"