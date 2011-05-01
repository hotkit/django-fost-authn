from unittest2 import TestCase

from fost_authn import FostBackend


class BackendTests(TestCase):
    """Test that the backend does the right sorts of things."""
    def setUp(self):
        self.backend = FostBackend()

    def test_unsigned(self):
        self.backend.authenticate()

    def test_get_user_no_user(self):
        self.backend.get_user(None)
