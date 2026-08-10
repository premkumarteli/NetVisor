# Phase 1 Implementation Plan: Critical Security & Performance Fixes

## Overview
Address the three critical vulnerabilities identified in the code review:
1. **SQL Injection** via f-string table/column interpolation
2. **mTLS Connection Leak** - synchronous DB connection per request in middleware
3. **JWT Algorithm Confusion** - hardcoded HS256 instead of RS256

---

## Fix 1: SQL Injection in `system_service.py`

### Files & Lines
- `app/services/system_service.py:95` - `_table_count()`
- `app/services/system_service.py:105` - `_export_table_to_csv()` schema query
- `app/services/system_service.py:116` - `_export_table_to_csv()` data query
- `app/services/system_service.py:411` - `backup_and_reset_runtime_data()` DELETE

### Current Vulnerable Code
```python
cursor.execute(f"SELECT COUNT(*) AS count FROM {table_name} WHERE organization_id = %s", (organization_id,))
cursor.execute(f"SELECT * FROM {table_name} LIMIT 0")
cursor.execute(f"SELECT * FROM {table_name} WHERE organization_id = %s{order_clause}", (organization_id,))
cursor.execute(f"DELETE FROM {table_name} WHERE organization_id = %s", (organization_id,))
```

### Fix Strategy
1. Define `ALLOWED_TABLES` as a class constant (whitelist)
2. Validate `table_name` against whitelist before any query
3. Use parameterized queries for all values (already done for `organization_id`)
4. Add `_validate_table_name()` helper method

### Test Cases
- `test_system_service_sql_injection_prevention.py`
  - Valid table from `OPERATIONAL_TABLES` → succeeds
  - Invalid table `"users; DROP TABLE agents;--"` → raises `ValueError`
  - Table not in whitelist → raises `ValueError`

---

## Fix 2: SQL Injection in `flow_service.py`

### Files & Lines
- `app/services/flow_service.py:1297` - `ingest_hash` IN clause construction
- `app/services/flow_service.py:1806` - `where_str` dynamic filter interpolation
- `app/services/flow_service.py:1811` - `data_sql` with same `where_str`

### Current Vulnerable Code
```python
# Line 1297
format_strings = ",".join(["%s"] * len(ingest_hashes))
cursor.execute(f"SELECT ingest_hash FROM flow_logs WHERE ingest_hash IN ({format_strings})", tuple(ingest_hashes))

# Line 1806-1811
where_str = " AND ".join(where_clauses)  # Built from user input
count_sql = f"SELECT COUNT(*) as total FROM flow_logs WHERE {where_str}"
data_sql = f"SELECT ... FROM flow_logs WHERE {where_str} ORDER BY ..."
```

### Fix Strategy
1. **Line 1297**: Already uses parameterized values correctly - just validate `ingest_hashes` length
2. **Lines 1806/1811**: 
   - Build `where_clauses` with validated column names only
   - Use a column whitelist: `ALLOWED_FILTER_COLUMNS = {"organization_id", "src_ip", "dst_ip", "application", "network_scope", "flow_direction", "last_seen", "analysis_confidence"}`
   - Reject any column not in whitelist
   - Keep values parameterized

### Test Cases
- `test_flow_service_sql_injection_prevention.py`
  - Valid filters → returns results
  - Malicious filter `{"src_ip": "1.1.1.1; DROP TABLE flow_logs"}` → parameterized safely
  - Invalid column `{"evil_column": "x"}` → raises `ValueError`

---

## Fix 3: mTLS Connection Leak in `mtls_middleware.py`

### Files & Lines
- `app/middleware/mtls_middleware.py:100-118` - Revocation check opens new connection per request

### Current Vulnerable Code
```python
conn = get_db_connection()  # New connection every request!
try:
    ca = CertificateAuthority(settings.MTLS_CA_DIR)
    if ca.is_revoked(conn, cert_serial):
        ...
finally:
    conn.close()
```

### Fix Strategy
1. Use `anyio.to_thread.run_sync()` to run sync DB call in thread pool (non-blocking)
2. Reuse connection from request state if available, or use a lightweight pooled connection
3. Better: Move revocation check to a cached service with TTL (certificates don't change often)
4. Add connection timeout and circuit breaker

### Implementation
```python
import anyio
from ..db.session import get_db_connection
from ..services.ca import CertificateAuthority

async def _check_revocation(self, cert_serial: str) -> bool:
    """Run revocation check in thread pool to avoid blocking event loop."""
    def _sync_check():
        conn = get_db_connection()
        try:
            ca = CertificateAuthority(settings.MTLS_CA_DIR)
            return ca.is_revoked(conn, cert_serial)
        finally:
            conn.close()
    
    return await anyio.to_thread.run_sync(_sync_check)
```

### Test Cases
- `test_mtls_middleware_connection_leak.py`
  - Load test: 100 concurrent requests → no connection pool exhaustion
  - Revoked cert → returns 403
  - Valid cert → passes through
  - DB timeout → returns 500 in required mode, allows in optional mode

---

## Fix 4: JWT RS256 Migration in `security.py`

### Files & Lines
- `app/core/security.py:8` - `ALGORITHM = "HS256"`
- `app/core/security.py:10-28` - `create_access_token()`
- `app/core/security.py` - Need new `verify_access_token()` function

### Current Vulnerable Code
```python
ALGORITHM = "HS256"

def create_access_token(subject, expires_delta=None, extra_claims=None):
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
```

### Fix Strategy
1. Add new settings: `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`, `JWT_ALGORITHM` (default RS256)
2. Load keys from files or environment (PEM format)
3. Keep HS256 as fallback with deprecation warning
4. New `verify_access_token()` that uses public key for RS256
5. Update all token verification sites (middleware, Socket.IO auth, API dependencies)

### Settings Additions (config.py)
```python
JWT_ALGORITHM: str = Field(default="RS256", validation_alias="NETVISOR_JWT_ALGORITHM")
JWT_PRIVATE_KEY_PATH: str = Field(default="", validation_alias="NETVISOR_JWT_PRIVATE_KEY_PATH")
JWT_PUBLIC_KEY_PATH: str = Field(default="", validation_alias="NETVISOR_JWT_PUBLIC_KEY_PATH")
JWT_PRIVATE_KEY: str = Field(default="", validation_alias="NETVISOR_JWT_PRIVATE_KEY")
JWT_PUBLIC_KEY: str = Field(default="", validation_alias="NETVISOR_JWT_PUBLIC_KEY")
```

### Implementation
```python
# security.py
from cryptography.hazmat.primitives import serialization

def _load_private_key() -> bytes:
    if settings.JWT_PRIVATE_KEY:
        return settings.JWT_PRIVATE_KEY.encode()
    if settings.JWT_PRIVATE_KEY_PATH:
        with open(settings.JWT_PRIVATE_KEY_PATH, "rb") as f:
            return f.read()
    raise RuntimeError("No JWT private key configured")

def _load_public_key() -> bytes:
    if settings.JWT_PUBLIC_KEY:
        return settings.JWT_PUBLIC_KEY.encode()
    if settings.JWT_PUBLIC_KEY_PATH:
        with open(settings.JWT_PUBLIC_KEY_PATH, "rb") as f:
            return f.read()
    raise RuntimeError("No JWT public key configured")

def create_access_token(...):
    private_key = _load_private_key()
    encoded_jwt = jwt.encode(to_encode, private_key, algorithm=settings.JWT_ALGORITHM)

def verify_access_token(token: str) -> dict:
    public_key = _load_public_key()
    return jwt.decode(token, public_key, algorithms=[settings.JWT_ALGORITHM], ...)
```

### Test Cases
- `test_jwt_rs256.py`
  - RS256 token creation → valid signature
  - RS256 token verification → returns payload
  - HS256 fallback with warning → works but logs deprecation
  - Invalid signature → raises JWTError
  - Expired token → raises JWTError
  - Wrong audience/issuer → raises JWTError

---

## Execution Order

| Step | Task | Depends On |
|------|------|------------|
| 1 | Fix `system_service.py` SQL injection | None |
| 2 | Fix `flow_service.py` SQL injection | None |
| 3 | Fix `mtls_middleware.py` connection leak | None |
| 4 | Add JWT key settings to `config.py` | None |
| 5 | Migrate `security.py` to RS256 | Step 4 |
| 6 | Update token verification in `realtime.py`, `dependencies.py` | Step 5 |
| 7 | Write tests for all fixes | Steps 1-6 |

---

## Rollback Plan
- Each fix is isolated to single file/module
- Feature flags: `NETVISOR_JWT_ALGORITHM=HS256` to revert
- Git commits per fix for easy revert

---

## Acceptance Criteria
- [ ] All SQL queries use whitelisted identifiers + parameterized values
- [ ] mTLS middleware handles 1000 req/s without connection exhaustion
- [ ] JWT tokens use RS256 by default, HS256 only with explicit config
- [ ] All existing tests pass + new security tests pass
- [ ] No deprecation warnings in production logs