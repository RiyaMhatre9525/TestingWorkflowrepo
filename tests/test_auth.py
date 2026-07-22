"""
Security unit tests for authentication and authorization components.
"""

import pytest


class TestAuthentication:
    def test_valid_login(self):
        """Test that valid credentials allow authentication."""
        token = authenticate(username="user", password="correct_password")
        assert token is not None

    def test_invalid_password(self):
        """Test that invalid password is rejected."""
        token = authenticate(username="user", password="wrong_password")
        assert token is None

    def test_token_validation(self):
        """Test that JWT token validation works correctly."""
        valid_token = generate_token(user_id=1)
        assert validate_token(valid_token) is True

    def test_expired_token_rejected(self):
        """Test that expired tokens are rejected."""
        expired_token = generate_expired_token()
        assert validate_token(expired_token) is False


class TestAuthorization:
    def test_admin_access_control(self):
        """Test that admin role has correct permissions."""
        user = create_user(role="admin")
        assert has_permission(user, "delete_resource") is True

    def test_regular_user_access_control(self):
        """Test that regular user cannot access admin resources."""
        user = create_user(role="user")
        assert has_permission(user, "delete_resource") is False

    def test_permission_logic(self):
        """Test permission logic for security filters."""
        security_filter = SecurityFilter(required_role="admin")
        assert security_filter.allows(role="admin") is True
        assert security_filter.allows(role="guest") is False


class TestPasswordValidation:
    def test_weak_password_rejected(self):
        """Test that weak passwords are rejected."""
        assert validate_password("123") is False

    def test_strong_password_accepted(self):
        """Test that strong passwords are accepted."""
        assert validate_password("Str0ng!Pass#2024") is True
