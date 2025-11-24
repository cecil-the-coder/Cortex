#!/usr/bin/env python3
"""
Admin API Examples for Cortex with Authentication
This script demonstrates how to use the admin API endpoints with comprehensive authentication support

Usage:
    python admin-api-python.py --base-url BASE_URL --username USER --password PASS
    python admin-api-python.py --base-url BASE_URL --api-key KEY
    python admin-api-python.py --demo  # Run demo with automated cleanup

Examples:
    python admin-api-python.py --base-url http://localhost:8080 --username admin --password secure-password
    python admin-api-python.py --api-key sk-admin-12345 --demo
    python admin-api-python.py --demo --skip-tfa  # Run demo without TFA setup
"""

import argparse
import base64
import json
import sys
import time
import getpass
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
import requests
from requests import Response


class AuthenticationError(Exception):
    """Raised when authentication fails"""
    pass


class RateLimitError(Exception):
    """Raised when rate limit is exceeded"""
    pass


class AdminAPIClient:
    """Client for interacting with the Cortex admin API with authentication"""

    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip("/")
        self.api_base = f"{self.base_url}/admin/v1"
        self.session = requests.Session()

        # Authentication state
        self.auth_method = None
        self.access_token = None
        self.refresh_token = None
        self.user_info = None

        # Rate limiting info
        self.rate_limit_info = {}

    def authenticate_with_password(self, username: str, password: str, tfa_code: Optional[str] = None) -> Dict[str, Any]:
        """Authenticate using username and password (JWT)"""
        self.auth_method = "jwt"

        login_data = {
            "username": username,
            "password": password,
            "remember_me": True
        }

        if tfa_code:
            login_data["tfa_code"] = tfa_code

        response = requests.post(
            f"{self.api_base}/auth/login",
            json=login_data,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.user_info = data["user"]

            # Set authorization header
            self.session.headers.update({
                "Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json"
            })

            return data
        elif response.status_code == 206:
            # TFA required
            tfa_data = response.json()
            raise AuthenticationError(f"TFA required. Session: {tfa_data.get('tfa_session')}")
        else:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            raise AuthenticationError(f"Authentication failed: {error_data.get('error', {}).get('message', response.text)}")

    def authenticate_with_api_key(self, api_key: str) -> None:
        """Authenticate using API key"""
        self.auth_method = "api_key"

        self.session.headers.update({
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        })

    def complete_tfa_login(self, tfa_session: str, tfa_code: str) -> Dict[str, Any]:
        """Complete TFA login"""
        tfa_data = {
            "tfa_session": tfa_session,
            "tfa_code": tfa_code
        }

        response = requests.post(
            f"{self.api_base}/auth/tfa/complete",
            json=tfa_data,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data["refresh_token"]
            self.user_info = data["user"]

            # Update authorization header
            self.session.headers.update({
                "Authorization": f"Bearer {self.access_token}"
            })

            return data
        else:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            raise AuthenticationError(f"TFA verification failed: {error_data.get('error', {}).get('message', response.text)}")

    def refresh_access_token(self) -> bool:
        """Refresh access token"""
        if not self.refresh_token or self.auth_method != "jwt":
            return False

        try:
            response = requests.post(
                f"{self.api_base}/auth/refresh",
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json"
                },
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                self.access_token = data["access_token"]
                self.refresh_token = data["refresh_token"]

                # Update authorization header
                self.session.headers.update({
                    "Authorization": f"Bearer {self.access_token}"
                })

                return True
        except Exception:
            pass

        return False

    def logout(self) -> None:
        """Logout and invalidate session"""
        if self.auth_method == "jwt" and self.access_token:
            try:
                requests.post(
                    f"{self.api_base}/auth/logout",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json"
                    },
                    timeout=10
                )
            except Exception:
                pass  # Best effort logout

        # Clear authentication state
        self.access_token = None
        self.refresh_token = None
        self.user_info = None
        self.auth_method = None
        self.session.headers.clear()

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None,
                     expected_status: int = 200) -> Response:
        """Make HTTP request to admin API with automatic token refresh"""
        url = f"{self.api_base}{endpoint}"

        # Prepare request
        kwargs = {}
        if data is not None:
            kwargs["json"] = data

        response = self.session.request(method, url, timeout=30, **kwargs)

        # Handle token refresh for JWT authentication
        if (self.auth_method == "jwt" and response.status_code == 401 and
            self.refresh_token and endpoint != "/auth/login"):

            if self.refresh_access_token():
                # Retry request with new token
                response = self.session.request(method, url, timeout=30, **kwargs)

        return response

    def _handle_response(self, response: Response, expected_status: int = 200) -> Dict[str, Any]:
        """Handle API response and return JSON data"""
        # Store rate limit info if available
        if "X-RateLimit-Limit" in response.headers:
            self.rate_limit_info = {
                "limit": response.headers.get("X-RateLimit-Limit"),
                "remaining": response.headers.get("X-RateLimit-Remaining"),
                "reset": response.headers.get("X-RateLimit-Reset"),
                "retry_after": response.headers.get("X-RateLimit-Retry-After")
            }

        if response.status_code == expected_status:
            try:
                return response.json()
            except ValueError:
                return {"message": response.text}
        elif response.status_code == 429:
            raise RateLimitError(f"Rate limit exceeded. Retry after: {response.headers.get('X-RateLimit-Retry-After', 'unknown')}")
        else:
            print(f"Error: HTTP {response.status_code}")
            try:
                error_data = response.json()
                print("Error details:")
                print(json.dumps(error_data, indent=2))
            except:
                print("Response:", response.text)
            response.raise_for_status()

    # Authentication Methods
    def get_current_user(self) -> Dict[str, Any]:
        """Get current user information"""
        response = self._make_request("GET", "/me")
        return self._handle_response(response)

    def setup_tfa(self) -> Dict[str, Any]:
        """Setup Two-Factor Authentication"""
        response = self._make_request("POST", "/auth/tfa/setup")
        return self._handle_response(response)

    def verify_tfa_setup(self, code: str, remember_device: bool = False) -> Dict[str, Any]:
        """Verify TFA setup"""
        data = {"code": code, "remember_device": remember_device}
        response = self._make_request("POST", "/auth/tfa/verify", data)
        return self._handle_response(response)

    def disable_tfa(self) -> Dict[str, Any]:
        """Disable Two-Factor Authentication"""
        response = self._make_request("DELETE", "/auth/tfa")
        return self._handle_response(response)

    def regenerate_backup_codes(self) -> Dict[str, Any]:
        """Regenerate TFA backup codes"""
        response = self._make_request("POST", "/auth/tfa/backup-codes")
        return self._handle_response(response)

    # User Management Methods
    def list_users(self) -> Dict[str, Any]:
        """List all users (admin/super_admin only)"""
        response = self._make_request("GET", "/users")
        return self._handle_response(response)

    def get_user(self, user_id: str) -> Dict[str, Any]:
        """Get specific user information"""
        response = self._make_request("GET", f"/users/{user_id}")
        return self._handle_response(response)

    def create_user(self, username: str, password: str, email: str, role: str = "viewer",
                   tfa_enabled: bool = False) -> Dict[str, Any]:
        """Create a new user"""
        data = {
            "username": username,
            "password": password,
            "email": email,
            "role": role,
            "tfa_enabled": tfa_enabled
        }
        response = self._make_request("POST", "/users", data, expected_status=201)
        return self._handle_response(response)

    def update_user(self, user_id: str, **kwargs) -> Dict[str, Any]:
        """Update user information"""
        response = self._make_request("PATCH", f"/users/{user_id}", kwargs)
        return self._handle_response(response)

    def delete_user(self, user_id: str) -> Dict[str, Any]:
        """Delete a user"""
        response = self._make_request("DELETE", f"/users/{user_id}")
        return self._handle_response(response)

    # API Key Management Methods
    def list_api_keys(self) -> Dict[str, Any]:
        """List current user's API keys"""
        response = self._make_request("GET", "/users/api-keys")
        return self._handle_response(response)

    def create_api_key(self, name: str, description: str, role: str = "viewer",
                      expires_in: Optional[int] = None, allowed_ips: Optional[List[str]] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a new API key"""
        data = {
            "name": name,
            "description": description,
            "role": role
        }

        if expires_in:
            data["expires_in"] = expires_in
        if allowed_ips:
            data["allowed_ips"] = allowed_ips
        if metadata:
            data["metadata"] = metadata

        response = self._make_request("POST", "/users/api-keys", data, expected_status=201)
        return self._handle_response(response)

    def get_api_key(self, key_id: str) -> Dict[str, Any]:
        """Get API key details"""
        response = self._make_request("GET", f"/users/api-keys/{key_id}")
        return self._handle_response(response)

    def update_api_key(self, key_id: str, **kwargs) -> Dict[str, Any]:
        """Update an API key"""
        response = self._make_request("PUT", f"/users/api-keys/{key_id}", kwargs)
        return self._handle_response(response)

    def delete_api_key(self, key_id: str) -> Dict[str, Any]:
        """Delete an API key"""
        response = self._make_request("DELETE", f"/users/api-keys/{key_id}")
        return self._handle_response(response)

    # Model Group Management Methods (updated for v1 API)
    def list_model_groups(self) -> Dict[str, Any]:
        """List all model groups"""
        response = self._make_request("GET", "/model-groups")
        return self._handle_response(response)

    def create_model_group(self, name: str, description: str,
                          models: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a new model group"""
        data = {
            "name": name,
            "description": description,
            "models": models
        }
        response = self._make_request("POST", "/model-groups", data, expected_status=201)
        return self._handle_response(response)

    def get_model_group(self, name: str) -> Dict[str, Any]:
        """Get details of a specific model group"""
        response = self._make_request("GET", f"/model-groups/{name}")
        return self._handle_response(response)

    def update_model_group(self, name: str, **kwargs) -> Dict[str, Any]:
        """Update a model group"""
        response = self._make_request("PUT", f"/model-groups/{name}", kwargs)
        return self._handle_response(response)

    def delete_model_group(self, name: str) -> Dict[str, Any]:
        """Delete a model group"""
        response = self._make_request("DELETE", f"/model-groups/{name}")
        return self._handle_response(response)

    # Health and Status Methods
    def check_health(self) -> Dict[str, Any]:
        """Check API health status"""
        response = self._make_request("GET", "/health")
        return self._handle_response(response)

    def get_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        response = self._make_request("GET", "/status")
        return self._handle_response(response)

    def check_server_connectivity(self) -> bool:
        """Check if the server is running"""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False


def print_section(title: str):
    """Print a section header"""
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def print_subsection(title: str):
    """Print a subsection header"""
    print(f"\n--- {title} ---")
    print()


def print_json(data: Union[Dict[str, Any], List], title: str = ""):
    """Pretty print JSON data"""
    if title:
        print(f"{title}:")
    print(json.dumps(data, indent=2))
    print()


def demo_authentication(client: AdminAPIClient):
    """Demonstrate authentication features"""
    print_section("Authentication Demo")

    if client.auth_method == "jwt":
        print("🔐 JWT Authentication Mode")

        # Get current user info
        print_subsection("Current User Information")
        try:
            user_info = client.get_current_user()
            print_json(user_info, "User Profile")

            print(f"Username: {user_info.get('username')}")
            print(f"Role: {user_info.get('role')}")
            print(f"Email: {user_info.get('email')}")
            print(f"TFA Enabled: {user_info.get('tfa_enabled', False)}")
            print(f"API Keys Count: {user_info.get('api_keys_count', 0)}")

            if 'rate_limits' in user_info:
                print_json(user_info['rate_limits'], "Rate Limits")

        except Exception as e:
            print(f"Error getting user info: {e}")

        # Test token refresh if JWT
        print_subsection("Token Refresh Test")
        if client.refresh_access_token():
            print("✓ Token refresh successful")
        else:
            print("⚠ Token refresh failed or not available")

    elif client.auth_method == "api_key":
        print("🔑 API Key Authentication Mode")

        print_subsection("API Key Information")
        try:
            user_info = client.get_current_user()
            print_json(user_info, "API Key User Info")
            print(f"User Role: {user_info.get('role')}")
            print(f"Permissions: {user_info.get('permissions', [])}")
        except Exception as e:
            print(f"Error with API key: {e}")


def demo_user_management(client: AdminAPIClient):
    """Demonstrate user management"""
    print_section("User Management Demo")

    if client.auth_method != "jwt":
        print("⚠ User management requires JWT authentication")
        return

    # Check if user has admin privileges
    try:
        user_info = client.get_current_user()
        user_role = user_info.get('role', '')

        if user_role not in ['super_admin', 'admin']:
            print(f"⚠ User role '{user_role}' does not have user management permissions")
            return

        # List users
        print_subsection("Listing Existing Users")
        users = client.list_users()
        print_json(users, "Users List")

        # Create a demo user
        print_subsection("Creating Demo User")
        try:
            demo_user = client.create_user(
                username="demo-operator-py",
                password="demo-password-123",
                email="operator-py@example.com",
                role="operator",
                tfa_enabled=False
            )
            print_json(demo_user, "Created User")
            demo_user_id = demo_user.get('id')
        except Exception as e:
            print(f"Error creating user (might already exist): {e}")
            # Try to get existing user
            try:
                existing_user = client.get_user("demo-operator-py")
                demo_user_id = existing_user.get('id')
                print_json(existing_user, "Existing Demo User")
            except:
                demo_user_id = None

        if demo_user_id:
            # Update user role
            print_subsection("Updating User Role to Viewer")
            try:
                updated_user = client.update_user(demo_user_id, role="viewer")
                print_json(updated_user, "Updated User")
            except Exception as e:
                print(f"Error updating user: {e}")

    except Exception as e:
        print(f"Error in user management demo: {e}")


def demo_tfa_setup(client: AdminAPIClient):
    """Demonstrate TFA setup"""
    print_section("Two-Factor Authentication Demo")

    if client.auth_method != "jwt":
        print("⚠ TFA setup requires JWT authentication")
        return

    # Check current TFA status
    try:
        user_info = client.get_current_user()
        if user_info.get('tfa_enabled', False):
            print("✓ TFA is already enabled for current user")
            return
    except Exception:
        pass

    print_subsection("Initiating TFA Setup")
    try:
        tfa_setup = client.setup_tfa()
        print_json(tfa_setup, "TFA Setup Response")

        if 'secret' in tfa_setup:
            print(f"\n📱 TFA Secret: {tfa_setup['secret']}")
            print("🔐 Backup Codes (save these!):")
            for i, code in enumerate(tfa_setup.get('backup_codes', []), 1):
                print(f"  {i}. {code}")

        if 'qr_code_url' in tfa_setup:
            # For demo purposes, we'll just show the size of the QR code
            qr_data = tfa_setup['qr_code_url']
            if qr_data.startswith('data:image/png;base64,'):
                qr_bytes = base64.b64decode(qr_data.split(',')[1])
                print(f"\n📷 QR Code generated ({len(qr_bytes)} bytes)")
                print("(In a real application, display this for scanning)")

        print("\n⚠ Demo Note: Skipping actual TFA verification")
        print("In a real setup, you would:")
        print("1. Scan the QR code with your authenticator app")
        print("2. Enter the 6-digit code to verify")
        print("3. Save backup codes securely")

    except Exception as e:
        print(f"Error setting up TFA: {e}")


def demo_api_key_management(client: AdminAPIClient):
    """Demonstrate API key management"""
    print_section("API Key Management Demo")

    # List existing keys
    print_subsection("Listing Existing API Keys")
    try:
        keys = client.list_api_keys()
        print_json(keys, "Existing API Keys")
        key_count = keys.get('count', 0)
        print(f"Total API keys: {key_count}")
    except Exception as e:
        print(f"Error listing keys: {e}")

    # Create a new API key
    print_subsection("Creating New API Key")
    try:
        new_key = client.create_api_key(
            name="Python Demo Client",
            description="Demo API key for Python examples",
            role="viewer",
            expires_in=86400 * 7,  # 7 days
            allowed_ips=["127.0.0.1", "::1"],
            metadata={
                "client": "python-demo",
                "environment": "testing",
                "created_by": "demo-script"
            }
        )
        print_json(new_key, "Created API Key")

        # Store key info for later use
        api_key_id = new_key.get('id')
        actual_key = new_key.get('api_key', '')
        if actual_key:
            print(f"🔑 Generated API Key: {actual_key[:20]}...")

    except Exception as e:
        print(f"Error creating API key: {e}")
        api_key_id = None

    if api_key_id:
        # Update the API key
        print_subsection("Updating API Key")
        try:
            updated_key = client.update_api_key(
                api_key_id,
                description="Updated Python demo client",
                role="operator",  # Upgrade permissions
                metadata={
                    "client": "python-demo",
                    "environment": "testing",
                    "updated": True
                }
            )
            print_json(updated_key, "Updated API Key")
        except Exception as e:
            print(f"Error updating API key: {e}")

        # Delete the API key
        print_subsection("Cleaning Up Demo API Key")
        try:
            delete_result = client.delete_api_key(api_key_id)
            print_json(delete_result, "Deleted API Key")
        except Exception as e:
            print(f"Error deleting API key: {e}")


def demo_error_handling(client: AdminAPIClient):
    """Demonstrate comprehensive error handling"""
    print_section("Error Handling Demo")

    error_scenarios = [
        ("Rate Limiting", lambda: client.check_health(), "Testing rate limit handling"),
        ("Invalid Authentication", lambda: client._make_request("GET", "/me"), "Invalid auth scenario"),
        ("Invalid Request Data", lambda: client.create_user("", "", "", ""), "Empty user data"),
        ("Resource Not Found", lambda: client.get_user("nonexistent-user-123"), "User doesn't exist"),
        ("API Key Not Found", lambda: client.get_api_key("nonexistent-key"), "API key doesn't exist"),
    ]

    for scenario_name, action, description in error_scenarios:
        print_subsection(f"Error Scenario: {scenario_name}")
        print(f"Description: {description}")

        if scenario_name == "Invalid Authentication":
            # Temporarily break authentication
            original_auth = client.session.headers.get("Authorization")
            client.session.headers["Authorization"] = "Bearer invalid-token"

        try:
            if scenario_name == "Rate Limiting":
                # Make multiple rapid requests to trigger rate limiting
                for i in range(10):
                    try:
                        action()
                    except RateLimitError as e:
                        print(f"✓ Rate limit triggered: {e}")
                        break
                    except Exception:
                        pass
            else:
                action()
                print("⚠ Unexpected success (should have failed)")

        except RateLimitError as e:
            print(f"✓ Rate limit error handled: {e}")
        except requests.exceptions.HTTPError as e:
            print(f"✓ Expected HTTP error: {e.response.status_code}")
            try:
                error_data = e.response.json()
                print("Error details:")
                print_json(error_data.get('error', error_data))
            except:
                print(f"Error text: {e.response.text}")
        except AuthenticationError as e:
            print(f"✓ Authentication error: {e}")
        except Exception as e:
            print(f"✓ Other error handled: {e}")

        # Restore authentication
        if scenario_name == "Invalid Authentication" and original_auth:
            client.session.headers["Authorization"] = original_auth


def demo_performance_testing(client: AdminAPIClient):
    """Demonstrate performance testing"""
    print_section("Performance Testing Demo")

    test_endpoints = [
        ("User Info", client.get_current_user),
        ("API Keys List", client.list_api_keys),
        ("Health Check", client.check_health),
        ("System Status", client.get_status),
    ]

    results = {}

    for name, endpoint_func in test_endpoints:
        print_subsection(f"Testing: {name}")

        response_times = []
        success_count = 0

        for i in range(5):  # Test 5 times
            start_time = time.time()
            try:
                result = endpoint_func()
                end_time = time.time()
                response_times.append(end_time - start_time)
                success_count += 1
            except Exception as e:
                print(f"  Request {i+1} failed: {e}")

            # Small delay between requests
            time.sleep(0.2)

        if response_times:
            avg_time = sum(response_times) / len(response_times)
            min_time = min(response_times)
            max_time = max(response_times)

            results[name] = {
                "avg_ms": avg_time * 1000,
                "min_ms": min_time * 1000,
                "max_ms": max_time * 1000,
                "success_rate": f"{success_count}/5"
            }

            print(f"Average response time: {avg_time*1000:.2f}ms")
            print(f"Min response time: {min_time*1000:.2f}ms")
            print(f"Max response time: {max_time*1000:.2f}ms")
            print(f"Success rate: {success_count}/5")

            # Show rate limit info if available
            if client.rate_limit_info:
                print(f"Rate limit info: {client.rate_limit_info}")

    # Summary
    print_subsection("Performance Summary")
    print_json(results, "Performance Test Results")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Admin API Examples for Cortex with Authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authentication Examples:
  %(prog)s --username admin --password mypass        # JWT auth with username/password
  %(prog)s --api-key sk-admin-12345                  # API key auth
  %(prog)s --demo --username admin --password pass   # Full demo with JWT

Environment Variables:
  SKIP_TFA        Skip TFA setup demo (set to 'true')
  SKIP_CLEANUP    Skip cleanup of demo resources

Examples:
  %(prog)s --base-url http://localhost:8080 --username admin --password secure-password
  ADMIN_API_KEY=sk-admin-123 %(prog)s --demo
  %(prog)s --demo --skip-tfa  # Run demo without TFA setup
        """
    )

    # Authentication options
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("--username", help="Username for JWT authentication")
    auth_group.add_argument("--api-key", help="API key for authentication")

    # General options
    parser.add_argument("--password", help="Password for JWT authentication (will prompt if not provided)")
    parser.add_argument("--base-url", default="http://localhost:8080",
                       help="Base URL of the router (default: http://localhost:8080)")
    parser.add_argument("--demo", action="store_true",
                       help="Run full demo with all examples")
    parser.add_argument("--skip-tfa", action="store_true",
                       help="Skip TFA setup demo")
    parser.add_argument("--skip-cleanup", action="store_true",
                       help="Skip cleanup of demo resources")

    args = parser.parse_args()

    # Create API client
    client = AdminAPIClient(args.base_url)

    # Check server connectivity
    print_section("Checking Server Connectivity")
    if not client.check_server_connectivity():
        print(f"✗ Server is not running at {args.base_url}")
        print("Please start the Cortex server first")
        sys.exit(1)
    else:
        print(f"✓ Server is running at {args.base_url}")

    # Authenticate
    print_section("Authentication")

    try:
        if args.username:
            # JWT authentication
            password = args.password
            if not password:
                password = getpass.getpass(f"Enter password for {args.username}: ")

            print(f"Attempting JWT authentication for user: {args.username}")
            try:
                auth_result = client.authenticate_with_password(args.username, password)
                print("✓ JWT authentication successful!")
                print(f"User: {auth_result.get('user', {}).get('username')}")
                print(f"Role: {auth_result.get('user', {}).get('role')}")
                print(f"Token expires in: {auth_result.get('expires_in', 'unknown')} seconds")
            except AuthenticationError as e:
                if "TFA required" in str(e):
                    print("⚠ Two-Factor Authentication required")
                    tfa_code = input("Enter TFA code: ")

                    # Extract TFA session from error message
                    tfa_session = str(e).split("Session: ")[-1]
                    client.complete_tfa_login(tfa_session, tfa_code)
                    print("✓ TFA authentication successful!")
                else:
                    raise

        elif args.api_key:
            # API key authentication
            print("Using API key authentication")
            client.authenticate_with_api_key(args.api_key)
            print("✓ API key authentication successful!")

            # Test the key by getting user info
            user_info = client.get_current_user()
            print(f"User: {user_info.get('username', 'API Key User')}")
            print(f"Role: {user_info.get('role', 'unknown')}")

    except Exception as e:
        print(f"✗ Authentication failed: {e}")
        sys.exit(1)

    if args.demo:
        # Run full demo
        print_section("Full Demo Mode")

        try:
            demo_authentication(client)
            demo_user_management(client)
            demo_api_key_management(client)

            if not args.skip_tfa:
                demo_tfa_setup(client)

            demo_error_handling(client)
            demo_performance_testing(client)

        except KeyboardInterrupt:
            print("\n\nDemo interrupted by user")
        except Exception as e:
            print(f"\nDemo failed with error: {e}")
            import traceback
            traceback.print_exc()
    else:
        # Interactive mode
        print_section("Basic Functionality Test")

        try:
            # Test basic endpoints
            print("Testing user information...")
            user_info = client.get_current_user()
            print(f"✓ Retrieved user info for: {user_info.get('username')}")

            print("\nTesting API key management...")
            keys = client.list_api_keys()
            print(f"✓ Retrieved {keys.get('count', 0)} API keys")

            print("\nTesting system status...")
            status = client.get_status()
            print("✓ Retrieved system status")

            print("\n✓ All basic API endpoints are working correctly!")

        except Exception as e:
            print(f"✗ Basic test failed: {e}")
            sys.exit(1)

    # Logout if using JWT
    if client.auth_method == "jwt":
        print_section("Cleanup")
        client.logout()
        print("✓ Logged out successfully")

    print_section("Demo Complete")
    print("\nNext steps:")
    print("1. Review the authentication methods demonstrated above")
    print("2. Use the AdminAPIClient class in your Python applications")
    print("3. Implement proper error handling and retry logic")
    print("4. Add logging and monitoring for production use")
    print("5. Consider implementing TFA for enhanced security")
    print("\nAuthentication Features Demonstrated:")
    print("• JWT token authentication with automatic refresh")
    print("• API key authentication with role-based permissions")
    print("• Two-Factor Authentication (TOTP) setup")
    print("• User management and role assignment")
    print("• Comprehensive error handling and rate limiting")
    print("• Performance testing with response time analysis")


if __name__ == "__main__":
    main()