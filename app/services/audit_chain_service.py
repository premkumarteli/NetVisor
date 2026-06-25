import hashlib
from typing import Optional, Dict, Any, List
from ..core.config import settings

class AuditChainService:
    def verify_chain(self, db_conn, organization_id: str, limit: int = 1000) -> dict:
        cursor = db_conn.cursor(dictionary=True)
        try:
            # We want to retrieve all rows for this org, ordered by ID ascending.
            cursor.execute(
                """
                SELECT id, organization_id, username, action, ip_address, resource, details, created_at, entry_hash, chain_hash, prev_id
                FROM audit_logs
                WHERE organization_id = %s
                ORDER BY id ASC
                LIMIT %s
                """,
                (organization_id, limit),
            )
            rows = cursor.fetchall()
            
            total_checked = 0
            first_broken_id = None
            status = "ok"
            chain_tip = None
            
            # Map of row ID -> chain_hash to verify that prev_id points to the correct hash
            hashes_by_id = {}
            null_hash_ids = set()
            
            for row in rows:
                row_id = row["id"]
                row_entry_hash = row["entry_hash"]
                row_chain_hash = row["chain_hash"]
                row_prev_id = row["prev_id"]
                
                # Check if hashes are NULL (legacy or disabled chain)
                if not row_entry_hash or not row_chain_hash:
                    status = "partial"
                    null_hash_ids.add(row_id)
                    continue
                
                # Verify prev_id and determine prev_chain_hash
                if row_prev_id is None or row_prev_id in null_hash_ids:
                    # Genesis or first signed row after a legacy block
                    prev_chain_hash = settings.AUDIT_CHAIN_GENESIS
                else:
                    # Should match the chain_hash of the row with row_prev_id
                    if row_prev_id not in hashes_by_id:
                        # Gap detected or referencing a row outside the check window/deleted
                        status = "broken"
                        first_broken_id = row_id
                        break
                    prev_chain_hash = hashes_by_id[row_prev_id]
                
                # Re-compute entry hash
                created_at = row["created_at"]
                if hasattr(created_at, "strftime"):
                    created_at_str = created_at.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    created_at_str = str(created_at or "")
                
                payload_str = f"{row_id}|{row['organization_id']}|{row['username']}|{row['action']}|{row['ip_address'] or ''}|{row['resource'] or ''}|{row['details'] or ''}|{created_at_str}"
                computed_entry_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
                
                if computed_entry_hash != row_entry_hash:
                    status = "broken"
                    first_broken_id = row_id
                    break
                
                # Re-compute chain hash
                chain_input = f"{computed_entry_hash}|{prev_chain_hash}"
                computed_chain_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
                
                if computed_chain_hash != row_chain_hash:
                    status = "broken"
                    first_broken_id = row_id
                    break
                
                hashes_by_id[row_id] = row_chain_hash
                chain_tip = row_chain_hash
                total_checked += 1
            
            verified_through = None
            if rows and status == "ok":
                last_row_time = rows[-1]["created_at"]
                if hasattr(last_row_time, "strftime"):
                    verified_through = last_row_time.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    verified_through = str(last_row_time or "")
            
            return {
                "status": status,
                "total_checked": total_checked,
                "first_broken_id": first_broken_id,
                "chain_tip": chain_tip,
                "verified_through": verified_through
            }
        finally:
            cursor.close()

    def get_chain_tip(self, db_conn, organization_id: str) -> Optional[str]:
        cursor = db_conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT chain_hash
                FROM audit_logs
                WHERE organization_id = %s AND chain_hash IS NOT NULL
                ORDER BY id DESC
                LIMIT 1
                """,
                (organization_id,),
            )
            row = cursor.fetchone()
            return row["chain_hash"] if row else None
        finally:
            cursor.close()

audit_chain_service = AuditChainService()
