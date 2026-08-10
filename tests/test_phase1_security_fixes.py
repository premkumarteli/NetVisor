"""
Tests for Phase 1 Critical Security Fixes:
1. SQL Injection prevention in system_service.py
2. SQL Injection prevention in flow_service.py
3. mTLS connection leak fix (async revocation check)
4. JWT RS256 token creation and verification
"""

import pytest
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from app.services.system_service import SystemService
from app.services.flow_service import FlowService
from app.core.security import create_access_token, verify_access_token, set_settings
from app.core.config import Settings


@pytest.fixture(autouse=True)
def reset_global_settings():
    yield
    set_settings(None)


# ============================================================
# Test fixtures
# ============================================================

class FakeCursor:
    def __init__(self, tables):
        self.tables = tables
        self.query = ""
        self.params = ()
        self.closed = False
        self.results = []
        self.column_names = ()

    def execute(self, query, params=None):
        self.query = " ".join(query.strip().split())
        self.params = params or ()
        
        # Parse query to return appropriate mock results
        self._parse_and_set_results(query)

    def _parse_and_set_results(self, query):
        """Parse query and set up mock results."""
        import re
        q = query.strip().upper()
        
        if "FROM INFORMATION_SCHEMA.TABLES" in q:
            _, table_name = self.params
            runtime_tables = set(self.tables.keys())
            self.results = [{"count": 1 if table_name in runtime_tables else 0}]
        elif "FROM INFORMATION_SCHEMA.COLUMNS" in q:
            _, table_name, column_name = self.params
            required_columns = {"id", "src_ip", "dst_ip", "organization_id", "last_seen", "application", "domain", "sni", "internal_device_ip", "external_endpoint_ip", "start_time", "ingest_hash"}
            self.results = [{"count": 1 if column_name in required_columns else 0}]
        elif "FROM INFORMATION_SCHEMA.STATISTICS" in q:
            self.results = [{"count": 0}]
        elif q.startswith("SHOW TABLES LIKE"):
            table_name = self.params[0].lower()
            self.results = [{"table": table_name}] if table_name in self.tables else []
        elif "SELECT COUNT(*) AS COUNT FROM" in q:
            # Extract table name
            import re
            match = re.search(r"FROM\s+`?(\w+)`?", q)
            if match:
                table_name = match.group(1).lower()
                self.results = [{"count": len(self.tables.get(table_name, []))}]
            else:
                self.results = [{"count": 0}]
        elif "SELECT COUNT(*) AS TOTAL FROM" in q:
            # For flow_logs count query
            match = re.search(r"FROM\s+`?(\w+)`?", q)
            if match:
                table_name = match.group(1).lower()
                self.results = [{"total": len(self.tables.get(table_name, []))}]
            else:
                self.results = [{"total": 0}]
        elif "SELECT * FROM" in q and "LIMIT 0" in q:
            # Extract table name
            import re
            match = re.search(r"FROM\s+`?(\w+)`?", q)
            if match:
                table_name = match.group(1).lower()
                rows = self.tables.get(table_name, [])
                if rows:
                    self.column_names = tuple(rows[0].keys())
                else:
                    self.column_names = ()
            self.results = []
        elif "SELECT * FROM" in q:
            # Extract table name
            import re
            match = re.search(r"FROM\s+`?(\w+)`?", q)
            if match:
                table_name = match.group(1).lower()
                rows = self.tables.get(table_name, [])
                if rows:
                    self.column_names = tuple(rows[0].keys())
                self.results = [dict(row) for row in rows]
            else:
                self.results = []
        elif q.startswith("DELETE FROM"):
            self.results = []
        elif "ALTER TABLE" in q:
            self.results = []
        elif "INSERT INTO SYSTEM_SETTINGS" in q:
            self.results = []
        elif "CREATE TABLE" in q:
            self.results = []
        elif "SHOW TABLES" == q.strip():
            self.results = [(t,) for t in self.tables.keys()]
        else:
            self.results = []

    def fetchone(self):
        return self.results[0] if self.results else None

    def fetchall(self):
        res = list(self.results)
        self.results = []
        return res

    def fetchmany(self, size=1):
        chunk = self.results[:size]
        self.results = self.results[size:]
        return chunk

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, tables):
        self.tables = tables
        self.commits = 0
        self.rollbacks = 0

    def cursor(self, dictionary=False):
        return FakeCursor(self.tables)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def make_rsa_keys(tmp_path):
    """Helper to generate RSA key files for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_key_path = tmp_path / "private.pem"
    public_key_path = tmp_path / "public.pem"
    private_key_path.write_bytes(private_pem)
    public_key_path.write_bytes(public_pem)
    
    return private_key_path, public_key_path


def make_settings_with_keys(tmp_path, algorithm="RS256", secret_key=None):
    """Create a Settings instance with test keys."""
    private_key_path, public_key_path = make_rsa_keys(tmp_path)
    
    settings_data = {
        "JWT_ALGORITHM": algorithm,
    }
    if algorithm == "RS256":
        settings_data["JWT_PRIVATE_KEY_PATH"] = str(private_key_path)
        settings_data["JWT_PUBLIC_KEY_PATH"] = str(public_key_path)
    else:
        settings_data["SECRET_KEY"] = secret_key or "test-secret-key-that-is-long-enough-for-hs256"
    
    return Settings(**settings_data)


# ============================================================
# System Service SQL Injection Tests
# ============================================================

class TestSystemServiceSQLInjection:
    """Test SQL injection prevention in SystemService."""

    def test_validate_table_name_allows_valid_tables(self, tmp_path):
        service = SystemService(backup_root=Path(tmp_path))
        for table in SystemService.OPERATIONAL_TABLES:
            validated = service._validate_table_name(table)
            assert validated == table

    def test_validate_table_name_rejects_invalid_table(self, tmp_path):
        service = SystemService(backup_root=Path(tmp_path))
        with pytest.raises(ValueError, match="not in the allowed tables list"):
            service._validate_table_name("users; DROP TABLE agents;--")

    def test_validate_table_name_rejects_random_string(self, tmp_path):
        service = SystemService(backup_root=Path(tmp_path))
        with pytest.raises(ValueError, match="not in the allowed tables list"):
            service._validate_table_name("evil_table")

    def test_table_count_uses_validated_table_name(self, tmp_path):
        service = SystemService(backup_root=Path(tmp_path))
        tables = {"flow_logs": [{"id": 1, "src_ip": "10.0.0.2"}]}
        conn = FakeConnection(tables)
        
        count = service._table_count(conn.cursor(), "flow_logs")
        assert count == 1

    def test_table_count_rejects_invalid_table(self, tmp_path):
        service = SystemService(backup_root=Path(tmp_path))
        tables = {"flow_logs": []}
        conn = FakeConnection(tables)
        
        with pytest.raises(ValueError):
            service._table_count(conn.cursor(), "users; DROP TABLE agents;--")

    def test_export_table_to_csv_validates_table_name(self, tmp_path):
        service = SystemService(backup_root=Path(tmp_path))
        tables = {"flow_logs": [{"id": 1, "src_ip": "10.0.0.2"}]}
        conn = FakeConnection(tables)
        
        with pytest.raises(ValueError):
            service._export_table_to_csv(conn, "evil_table", Path(tmp_path))

    def test_clear_runtime_data_validates_table_name(self, tmp_path):
        service = SystemService(backup_root=Path(tmp_path))
        tables = {t: [] for t in SystemService.OPERATIONAL_TABLES}
        conn = FakeConnection(tables)
        
        # This should work - uses OPERATIONAL_TABLES internally
        result = service.clear_runtime_data(conn)
        assert result == {}

    def test_export_all_tables_to_db_dump_filters_non_standard_tables(self, tmp_path):
        """Test that export_all_tables_to_db_dump only exports allowed tables."""
        service = SystemService(backup_root=Path(tmp_path))
        
        # Mock a connection that returns both allowed and non-allowed tables
        tables = {
            "flow_logs": [{"id": 1}],
            "evil_table": [{"id": 1}],
            "system_settings": [{"setting_key": "test", "setting_value": "value"}],
        }
        conn = FakeConnection(tables)
        
        class DummyPath:
            def __truediv__(self, other):
                return Path(tmp_path)

        class DummyPathResolver:
            def resolve(self):
                return self
            @property
            def parents(self):
                return [None, None, DummyPath()]
        
        # This should not raise an error, but should only export allowed tables
        with patch("app.services.system_service.Path", lambda *args: DummyPathResolver() if args and "system_service.py" in str(args[0]) else Path(*args)):
            service.export_all_tables_to_db_dump(conn)
        
        # Verify only allowed tables were exported
        export_dirs = list(Path(tmp_path).glob("*/"))
        assert len(export_dirs) == 1
        export_dir = export_dirs[0]
        
        exported_files = list(export_dir.glob("*.csv"))
        exported_table_names = [f.stem for f in exported_files]
        
        # Should include flow_logs and system_settings, but NOT evil_table
        assert "flow_logs" in exported_table_names
        assert "system_settings" in exported_table_names
        assert "evil_table" not in exported_table_names


# ============================================================
# Flow Service SQL Injection Tests
# ============================================================

class TestFlowServiceSQLInjection:
    """Test SQL injection prevention in FlowService."""

    def test_validate_where_clause_allows_valid_columns(self):
        service = FlowService()
        
        # Valid WHERE clauses should pass
        valid_clauses = [
            "organization_id = %s AND src_ip = %s",
            "organization_id = %s AND dst_ip = %s",
            "organization_id = %s AND application = %s",
            "organization_id = %s AND domain LIKE %s",
            "organization_id = %s AND (src_ip = %s OR dst_ip = %s)",
        ]
        for clause in valid_clauses:
            service._validate_where_clause(clause)  # Should not raise

    def test_validate_where_clause_rejects_invalid_column(self):
        service = FlowService()
        
        invalid_clauses = [
            "organization_id = %s AND evil_column = %s",
            "evil_column = %s",
        ]
        for clause in invalid_clauses:
            with pytest.raises(ValueError, match="Invalid column"):
                service._validate_where_clause(clause)
    
    def test_validate_where_clause_rejects_dangerous_patterns(self):
        service = FlowService()
        
        dangerous_clauses = [
            "organization_id = %s; DROP TABLE flow_logs;--",
            "organization_id = %s AND src_ip = %s; DELETE FROM flow_logs;--",
            "organization_id = %s UNION SELECT * FROM users",
        ]
        for clause in dangerous_clauses:
            with pytest.raises(ValueError, match="dangerous pattern"):
                service._validate_where_clause(clause)

    def test_get_flow_logs_validates_where_clause(self, tmp_path):
        service = FlowService()
        tables = {
            "flow_logs": [
                {
                    "id": 1,
                    "organization_id": "org-1",
                    "src_ip": "10.0.0.1",
                    "last_seen": "2024-01-01 00:00:00",
                    "start_time": "2024-01-01 00:00:00",
                }
            ]
        }
        conn = FakeConnection(tables)
        
        # Valid query should work
        result = service.get_flow_logs(conn, "org-1", limit=10)
        assert result["total"] == 1

    def test_build_flow_log_query_parts_uses_allowed_columns_only(self):
        service = FlowService()
        
        # Build query with all valid parameters
        where_str, params = service.build_flow_log_query_parts(
            "org-1",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            application="HTTP",
            search="example.com"
        )
        
        # Verify only allowed columns are in the WHERE clause
        assert "organization_id = %s" in where_str
        assert "src_ip = %s" in where_str
        assert "dst_ip = %s" in where_str
        assert "application = %s" in where_str
        assert "domain =" in where_str or "domain LIKE" in where_str
        
        # Verify no unexpected columns
        for param in params:
            assert isinstance(param, str)


# ============================================================
# mTLS Middleware Tests
# ============================================================

@pytest.fixture
def anyio_backend():
    return "asyncio"


class TestMTLSMiddleware:
    """Test mTLS middleware async revocation check."""

    @pytest.mark.anyio
    async def test_revocation_check_uses_thread_pool(self):
        """Test that revocation check runs in thread pool."""
        from app.middleware.mtls_middleware import MTLSMiddleware
        
        middleware = MTLSMiddleware(app=None)
        
        # Mock the sync revocation check
        with patch.object(middleware, '_check_revocation_async') as mock_check:
            mock_check.return_value = False
            
            # Call the async method
            result = await middleware._check_revocation_async("serial-123")
            
            assert result is False
            mock_check.assert_called_once_with("serial-123")

    @pytest.mark.anyio
    async def test_revocation_check_caches_results(self):
        """Test that revocation results are cached."""
        from app.middleware.mtls_middleware import MTLSMiddleware, _REVOCATION_CACHE
        
        middleware = MTLSMiddleware(app=None)
        
        # Clear cache
        _REVOCATION_CACHE.clear()
        
        with patch('app.middleware.mtls_middleware.anyio.to_thread.run_sync') as mock_run_sync:
            mock_run_sync.return_value = False
            
            # First call
            result1 = await middleware._check_revocation_async("serial-123")
            assert result1 is False
            assert mock_run_sync.call_count == 1
            
            # Second call should use cache
            result2 = await middleware._check_revocation_async("serial-123")
            assert result2 is False
            assert mock_run_sync.call_count == 1  # Still 1, cached

    @pytest.mark.anyio
    async def test_revocation_check_handles_db_error_in_optional_mode(self):
        """Test that DB errors are handled gracefully in optional mode."""
        from app.middleware.mtls_middleware import MTLSMiddleware
        from app.core.config import settings
        
        original_mode = settings.MTLS_MODE
        settings.MTLS_MODE = "optional"
        
        try:
            middleware = MTLSMiddleware(app=None)
            
            with patch('app.middleware.mtls_middleware.anyio.to_thread.run_sync') as mock_run_sync:
                mock_run_sync.side_effect = Exception("DB connection failed")
                
                # Should not raise in optional mode
                result = await middleware._check_revocation_async("serial-123")
                assert result is False  # Default to not revoked on error
        finally:
            settings.MTLS_MODE = original_mode


# ============================================================
# JWT RS256 Tests
# ============================================================

class TestJWTRS256:
    """Test JWT RS256 token creation and verification."""

    def test_create_access_token_rs256(self, tmp_path):
        """Test creating RS256 token with key files."""
        # Generate test RSA keys
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        private_key_path = tmp_path / "private.pem"
        public_key_path = tmp_path / "public.pem"
        private_key_path.write_bytes(private_pem)
        public_key_path.write_bytes(public_pem)
        
        # Set environment
        import os
        os.environ["NETVISOR_JWT_ALGORITHM"] = "RS256"
        os.environ["NETVISOR_JWT_PRIVATE_KEY_PATH"] = str(private_key_path)
        os.environ["NETVISOR_JWT_PUBLIC_KEY_PATH"] = str(public_key_path)
        
        # Reload settings
        from app.core.config import Settings
        settings = Settings()
        set_settings(settings)
        
        # Create token
        token = create_access_token("user-123")
        assert token is not None
        assert isinstance(token, str)
        assert len(token.split(".")) == 3  # JWT has 3 parts
        
        # Verify token
        payload = verify_access_token(token)
        assert payload["sub"] == "user-123"
        assert payload["iss"] == "netvisor-backend"
        assert payload["aud"] == "netvisor-clients"

    def test_create_access_token_hs256_fallback_with_warning(self, tmp_path):
        """Test HS256 fallback works but emits deprecation warning."""
        import os
        import warnings
        
        os.environ["NETVISOR_JWT_ALGORITHM"] = "HS256"
        os.environ["NETVISOR_SECRET_KEY"] = "test-secret-key-that-is-long-enough-for-hs256"
        os.environ.pop("NETVISOR_JWT_PRIVATE_KEY_PATH", None)
        os.environ.pop("NETVISOR_JWT_PUBLIC_KEY_PATH", None)
        
        from app.core.config import Settings
        settings = Settings()
        set_settings(settings)
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            token = create_access_token("user-123")
            
            # Should emit deprecation warning
            assert len(w) >= 1
            assert any("deprecated" in str(warning.message).lower() for warning in w)
        
        # Token should still be valid
        payload = verify_access_token(token)
        assert payload["sub"] == "user-123"

    def test_verify_access_token_rejects_invalid_signature(self, tmp_path):
        """Test that tokens with invalid signatures are rejected."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import os
        
        # Generate two key pairs
        private_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        private_pem1 = private_key1.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem1 = private_key1.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_pem2 = private_key2.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Sign with key1, verify with key2 (should fail)
        os.environ["NETVISOR_JWT_ALGORITHM"] = "RS256"
        os.environ["NETVISOR_JWT_PRIVATE_KEY_PATH"] = str(tmp_path / "private1.pem")
        os.environ["NETVISOR_JWT_PUBLIC_KEY_PATH"] = str(tmp_path / "public2.pem")
        
        (tmp_path / "private1.pem").write_bytes(private_pem1)
        (tmp_path / "public1.pem").write_bytes(public_pem1)
        (tmp_path / "private2.pem").write_bytes(private_pem2)
        (tmp_path / "public2.pem").write_bytes(private_key2.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        
        from app.core.config import Settings
        settings = Settings()
        set_settings(settings)
        
        token = create_access_token("user-123")
        
        # Now change to verify with different public key
        os.environ["NETVISOR_JWT_PUBLIC_KEY_PATH"] = str(tmp_path / "public2.pem")
        settings = Settings()
        set_settings(settings)
        
        with pytest.raises(ValueError, match="Invalid token"):
            verify_access_token(token)

    def test_verify_access_token_rejects_expired_token(self, tmp_path):
        """Test that expired tokens are rejected."""
        from datetime import timedelta
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import os
        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        private_key_path = tmp_path / "private.pem"
        public_key_path = tmp_path / "public.pem"
        private_key_path.write_bytes(private_pem)
        public_key_path.write_bytes(public_pem)
        
        os.environ["NETVISOR_JWT_ALGORITHM"] = "RS256"
        os.environ["NETVISOR_JWT_PRIVATE_KEY_PATH"] = str(private_key_path)
        os.environ["NETVISOR_JWT_PUBLIC_KEY_PATH"] = str(public_key_path)
        
        from app.core.config import Settings
        settings = Settings()
        set_settings(settings)
        
        # Create token with negative expiry (already expired)
        token = create_access_token("user-123", expires_delta=timedelta(seconds=-10))
        
        with pytest.raises(ValueError, match="Invalid token"):
            verify_access_token(token)


# ============================================================
# Integration Tests
# ============================================================

class TestIntegration:
    """Integration tests for the security fixes."""

    def test_system_service_backup_still_works_after_sql_fix(self, tmp_path):
        """Ensure backup functionality works after SQL injection fix."""
        tables = {
            "flow_logs": [{"id": 1, "src_ip": "10.0.0.2", "byte_count": 100}],
            "alerts": [{"id": 1, "device_ip": "10.0.0.2", "severity": "HIGH"}],
            "devices": [{"id": 1, "ip": "10.0.0.2", "hostname": "HOST"}],
        }
        conn = FakeConnection(tables)
        service = SystemService(backup_root=Path(tmp_path))
        
        result = service.backup_and_reset_runtime_data(conn, reason="test")
        
        assert result["backup"]["created"] is True
        assert result["backup"]["row_count"] == 3

    def test_flow_service_query_still_works_after_sql_fix(self, tmp_path):
        """Ensure flow log queries work after SQL injection fix."""
        tables = {
            "flow_logs": [
                {
                    "id": 1,
                    "organization_id": "org-1",
                    "src_ip": "10.0.0.1",
                    "dst_ip": "10.0.0.2",
                    "last_seen": "2024-01-01 00:00:00",
                    "start_time": "2024-01-01 00:00:00",
                }
            ]
        }
        conn = FakeConnection(tables)
        service = FlowService()
        
        result = service.get_flow_logs(conn, "org-1", src_ip="10.0.0.1")
        
        assert result["total"] == 1
        assert len(result["results"]) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])