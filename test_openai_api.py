#!/usr/bin/env python3
"""
Comprehensive test script for OpenAI-compatible API implementation
Tests all major endpoints and validates response_formats
"""

import os
import json
import requests
import time
from typing import Dict, Any, List
import argparse
import sys
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8080"
API_KEY = "test-key"  # Default test key
TIMEOUT = 30

class Colors:
    """Terminal colors for output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log(message: str, color: str = Colors.ENDC):
    """Print colored log message"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"{color}[{timestamp}] {message}{Colors.ENDC}")

def log_test(test_name: str, status: str, message: str = ""):
    """Log test result with color"""
    if status == "PASS":
        log(f"✓ {test_name} {message}", Colors.GREEN)
    elif status == "FAIL":
        log(f"✗ {test_name} {message}", Colors.RED)
    elif status == "SKIP":
        log(f"- {test_name} {message}", Colors.YELLOW)
    else:
        log(f"? {test_name} {message}", Colors.BLUE)

def make_request(method: str, endpoint: str, data: Any = None, stream: bool = False) -> requests.Response:
    """Make HTTP request to the API"""
    url = f"{BASE_URL}{endpoint}"
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        if method.upper() == "GET":
            response = requests.get(url, headers=headers, timeout=TIMEOUT, stream=stream)
        elif method.upper() == "POST":
            response = requests.post(url, headers=headers, json=data, timeout=TIMEOUT, stream=stream)
        else:
            raise ValueError(f"Unsupported method: {method}")
        return response
    except requests.exceptions.RequestException as e:
        log(f"Request failed: {e}", Colors.RED)
        return None

def test_health_endpoint():
    """Test health check endpoint"""
    log("\n=== Testing Health Endpoint ===", Colors.BOLD)

    response = make_request("GET", "/health")
    if response and response.status_code == 200:
        log_test("Health check", "PASS", f"Status: {response.status_code}")
        log(f"Response: {response.text[:100]}...", Colors.BLUE)
        return True
    else:
        log_test("Health check", "FAIL", f"Status: {response.status_code if response else 'No response'}")
        return False

def test_models_endpoint():
    """Test /v1/models endpoint"""
    log("\n=== Testing Models Endpoint ===", Colors.BOLD)

    response = make_request("GET", "/v1/models")
    if response is None:
        log_test("Models endpoint", "FAIL", "No response")
        return False

    try:
        data = response.json()
        log_test("Models endpoint", "PASS", f"Status: {response.status_code}")

        # Validate response structure
        if "object" in data and data["object"] == "list":
            log_test("Response structure", "PASS", "Correct object type")
        else:
            log_test("Response structure", "FAIL", "Missing or incorrect object field")

        if "data" in data and isinstance(data["data"], list):
            models = data["data"]
            log_test("Models list", "PASS", f"Found {len(models)} models")

            # Validate model structure
            for i, model in enumerate(models[:3]):  # Check first 3 models
                if all(key in model for key in ["id", "object", "created", "owned_by"]):
                    log_test(f"Model {i+1} structure", "PASS", f"ID: {model['id']}")
                else:
                    log_test(f"Model {i+1} structure", "FAIL", "Missing required fields")

            # Check for virtual router model
            router_model = next((m for m in models if m["id"] == "router"), None)
            if router_model:
                log_test("Virtual router model", "PASS", "Found 'router' model")
            else:
                log_test("Virtual router model", "FAIL", "Missing 'router' model")
        else:
            log_test("Models list", "FAIL", "Missing or invalid data array")

        return True

    except json.JSONDecodeError as e:
        log_test("Models endpoint", "FAIL", f"Invalid JSON: {e}")
        return False

def test_chat_completions_non_streaming():
    """Test /v1/chat/completions endpoint (non-streaming)"""
    log("\n=== Testing Chat Completions (Non-Streaming) ===", Colors.BOLD)

    request_data = {
        "model": "router",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say 'Hello from OpenAI API!'"}
        ],
        "max_tokens": 50,
        "temperature": 0.7
    }

    response = make_request("POST", "/v1/chat/completions", data=request_data)
    if response is None:
        log_test("Chat completions (non-streaming)", "FAIL", "No response")
        return False

    try:
        if response.status_code == 200:
            data = response.json()
            log_test("Chat completions (non-streaming)", "PASS", f"Status: {response.status_code}")

            # Validate response structure
            required_fields = ["id", "object", "created", "model", "choices", "usage"]
            if all(field in data for field in required_fields):
                log_test("Response structure", "PASS", "All required fields present")
            else:
                missing = [f for f in required_fields if f not in data]
                log_test("Response structure", "FAIL", f"Missing fields: {missing}")

            # Validate object type
            if data.get("object") == "chat.completion":
                log_test("Object type", "PASS", "Correct object type")
            else:
                log_test("Object type", "FAIL", f"Got: {data.get('object')}")

            # Validate choices
            if "choices" in data and len(data["choices"]) > 0:
                choice = data["choices"][0]
                if "message" in choice and choice["message"].get("role") == "assistant":
                    content = choice["message"].get("content", "")
                    if content:
                        log_test("Response content", "PASS", f"Content: {content[:50]}...")
                    else:
                        log_test("Response content", "FAIL", "Empty content")
                else:
                    log_test("Message structure", "FAIL", "Invalid message structure")
            else:
                log_test("Choices array", "FAIL", "Empty or missing choices")

            # Validate usage
            if "usage" in data:
                usage = data["usage"]
                if all(k in usage for k in ["prompt_tokens", "completion_tokens", "total_tokens"]):
                    log_test("Token usage", "PASS", f"Total: {usage['total_tokens']}")
                else:
                    log_test("Token usage", "FAIL", "Missing usage fields")

            return True

        else:
            log_test("Chat completions (non-streaming)", "FAIL", f"Status: {response.status_code}")
            try:
                error_data = response.json()
                log(f"Error response: {json.dumps(error_data, indent=2)}", Colors.RED)
            except:
                log(f"Error text: {response.text}", Colors.RED)
            return False

    except json.JSONDecodeError as e:
        log_test("Chat completions (non-streaming)", "FAIL", f"Invalid JSON: {e}")
        return False

def test_chat_completions_streaming():
    """Test /v1/chat/completions endpoint (streaming)"""
    log("\n=== Testing Chat Completions (Streaming) ===", Colors.BOLD)

    request_data = {
        "model": "router",
        "messages": [
            {"role": "user", "content": "Count from 1 to 5"}
        ],
        "max_tokens": 50,
        "stream": True
    }

    response = make_request("POST", "/v1/chat/completions", data=request_data, stream=True)
    if response is None:
        log_test("Chat completions (streaming)", "FAIL", "No response")
        return False

    try:
        if response.status_code == 200:
            log_test("Chat completions (streaming)", "PASS", f"Status: {response.status_code}")

            # Process streaming response
            chunks = []
            role_received = False
            content_received = False
            finish_received = False

            for line in response.iter_lines():
                if line:
                    line_str = line.decode('utf-8')
                    if line_str.startswith('data: '):
                        data_str = line_str[6:]  # Remove 'data: ' prefix

                        if data_str == '[DONE]':
                            finish_received = True
                            break

                        try:
                            chunk_data = json.loads(data_str)
                            chunks.append(chunk_data)

                            # Validate chunk structure
                            if "choices" in chunk_data and len(chunk_data["choices"]) > 0:
                                delta = chunk_data["choices"][0].get("delta", {})

                                if delta.get("role") == "assistant":
                                    role_received = True
                                if delta.get("content"):
                                    content_received = True
                        except json.JSONDecodeError:
                            continue

            # Validate streaming response
            if len(chunks) > 0:
                log_test("Streaming chunks", "PASS", f"Received {len(chunks)} chunks")
            else:
                log_test("Streaming chunks", "FAIL", "No valid chunks received")

            if role_received:
                log_test("Role delta", "PASS", "Assistant role received")
            else:
                log_test("Role delta", "FAIL", "No role delta found")

            if content_received:
                log_test("Content delta", "PASS", "Content deltas received")
            else:
                log_test("Content delta", "FAIL", "No content deltas found")

            if finish_received:
                log_test("Stream completion", "PASS", "[DONE] marker received")
            else:
                log_test("Stream completion", "FAIL", "No [DONE] marker")

            return True

        else:
            log_test("Chat completions (streaming)", "FAIL", f"Status: {response.status_code}")
            log(f"Error text: {response.text}", Colors.RED)
            return False

    except Exception as e:
        log_test("Chat completions (streaming)", "FAIL", f"Exception: {e}")
        return False

def test_error_handling():
    """Test error handling with invalid requests"""
    log("\n=== Testing Error Handling ===", Colors.BOLD)

    # Test missing model
    request_data = {
        "messages": [
            {"role": "user", "content": "Hello"}
        ]
    }

    response = make_request("POST", "/v1/chat/completions", data=request_data)
    if response and response.status_code == 400:
        try:
            error_data = response.json()
            if "error" in error_data:
                log_test("Missing model error", "PASS", "Proper error response")
            else:
                log_test("Missing model error", "FAIL", "Missing error field")
        except:
            log_test("Missing model error", "FAIL", "Invalid error JSON")
    else:
        log_test("Missing model error", "FAIL", f"Expected 400, got {response.status_code if response else 'No response'}")

    # Test empty messages
    request_data = {
        "model": "router",
        "messages": []
    }

    response = make_request("POST", "/v1/chat/completions", data=request_data)
    if response and response.status_code == 400:
        log_test("Empty messages error", "PASS", "Proper error response")
    else:
        log_test("Empty messages error", "FAIL", f"Expected 400, got {response.status_code if response else 'No response'}")

def test_routing_logic():
    """Test that routing works correctly"""
    log("\n=== Testing Routing Logic ===", Colors.BOLD)

    # Test with web search tool (should route to OpenAI based on config)
    request_data = {
        "model": "router",
        "messages": [
            {"role": "user", "content": "Search for recent news about AI"}
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "web_search",
                    "description": "Search the web"
                }
            }
        ],
        "max_tokens": 50
    }

    response = make_request("POST", "/v1/chat/completions", data=request_data)
    if response and response.status_code == 200:
        log_test("Web search routing", "PASS", "Request routed successfully")
        # We could check logs to verify it went to OpenAI, but for now just ensure it works
    else:
        log_test("Web search routing", "FAIL", f"Status: {response.status_code if response else 'No response'}")

def main():
    """Main test function"""
    parser = argparse.ArgumentParser(description="Test OpenAI-compatible API implementation")
    parser.add_argument("--url", default=BASE_URL, help="Base URL for the API")
    parser.add_argument("--key", default=API_KEY, help="API key for authentication")
    parser.add_argument("--test", choices=["health", "models", "chat", "stream", "errors", "routing"],
                       help="Run specific test only")

    args = parser.parse_args()

    global BASE_URL, API_KEY
    BASE_URL = args.url
    API_KEY = args.key

    log(f"Starting API tests for {BASE_URL}", Colors.BOLD)
    log(f"Using API key: {API_KEY[:10]}..." if len(API_KEY) > 10 else API_KEY, Colors.BLUE)

    results = []

    if not args.test or args.test == "health":
        results.append(test_health_endpoint())

    if not args.test or args.test == "models":
        results.append(test_models_endpoint())

    if not args.test or args.test == "chat":
        results.append(test_chat_completions_non_streaming())

    if not args.test or args.test == "stream":
        results.append(test_chat_completions_streaming())

    if not args.test or args.test == "errors":
        results.append(test_error_handling())

    if not args.test or args.test == "routing":
        results.append(test_routing_logic())

    # Summary
    log(f"\n=== Test Summary ===", Colors.BOLD)
    passed = sum(results)
    total = len(results)

    if passed == total:
        log(f"All tests passed! ({passed}/{total})", Colors.GREEN)
        sys.exit(0)
    else:
        log(f"Some tests failed ({passed}/{total})", Colors.RED)
        sys.exit(1)

if __name__ == "__main__":
    main()