from app.schemas.user_schema import UserCreate
from app.services.auth_service import auth_service


class FakeCursor:
    def __init__(self):
        self._last_query = ""
        self.closed = False
        self.insert_params = None

    def execute(self, query, params=None):
        self._last_query = query
        if query.startswith("INSERT INTO users"):
            self.insert_params = params

    def fetchone(self):
        if "SELECT id FROM users" in self._last_query:
            return None
        if "SELECT id FROM organizations" in self._last_query:
            return {"id": "org-1"}
        return None

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self):
        self.cursor_instance = FakeCursor()
        self.committed = False

    def cursor(self, dictionary=True):
        return self.cursor_instance

    def commit(self):
        self.committed = True


def test_create_user_returns_persisted_viewer_role():
    conn = FakeConnection()
    user = UserCreate(
        username="alice",
        email="alice@example.com",
        password="secret123",
        confirm_password="secret123",
    )

    created = auth_service.create_user(conn, user)

    assert created["username"] == "alice"
    assert created["email"] == "alice@example.com"
    assert created["role"] == "viewer"
    assert created["organization_id"] == "org-1"
    assert conn.committed is True
    assert conn.cursor_instance.insert_params[4] == "viewer"
    assert conn.cursor_instance.closed is True


class AuthCursor:
    def __init__(self, user):
        self.user = user
        self.calls = []
        self.closed = False

    def execute(self, query, params=None):
        self.calls.append((" ".join(query.split()), params))

    def fetchone(self):
        return self.user

    def close(self):
        self.closed = True


class AuthConnection:
    def __init__(self, user):
        self.cursor_instance = AuthCursor(user)
        self.committed = False
        self.rolled_back = False

    def cursor(self, dictionary=True):
        return self.cursor_instance

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def test_authenticate_accepts_email_identifier(monkeypatch):
    user = {
        "id": "user-1",
        "username": "alice",
        "email": "alice@example.com",
        "password": "hash",
        "role": "viewer",
        "status": "active",
        "locked_until": None,
    }
    conn = AuthConnection(user)
    monkeypatch.setattr("app.services.auth_service.verify_password", lambda password, hashed: password == "secret123")

    authenticated = auth_service.authenticate(conn, "alice@example.com", "secret123")

    assert authenticated["username"] == "alice"
    query, params = conn.cursor_instance.calls[0]
    assert "WHERE username = %s OR email = %s" in query
    assert params == ("alice@example.com", "alice@example.com")
    assert conn.committed is True

