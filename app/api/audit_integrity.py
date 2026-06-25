from fastapi import APIRouter, Depends, HTTPException, Request, Query
from ..core.dependencies import require_org_admin
from ..db.session import get_db
from ..services.audit_chain_service import audit_chain_service

router = APIRouter()

@router.get("/verify")
def verify_audit_chain(
    request: Request,
    limit: int = 1000,
    db=Depends(get_db),
    user=Depends(require_org_admin),
):
    org_id = user.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=400, detail="User organization ID not found")
    
    return audit_chain_service.verify_chain(db, organization_id=org_id, limit=limit)

@router.get("/tip")
def get_chain_tip(
    request: Request,
    db=Depends(get_db),
    user=Depends(require_org_admin),
):
    org_id = user.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=400, detail="User organization ID not found")
        
    tip = audit_chain_service.get_chain_tip(db, organization_id=org_id)
    return {"chain_tip": tip}

@router.get("/logs")
def get_audit_logs(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
    user=Depends(require_org_admin),
):
    org_id = user.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=400, detail="User organization ID not found")
    
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT id, username, action, ip_address, resource, details, created_at, entry_hash, chain_hash, prev_id
            FROM audit_logs
            WHERE organization_id = %s
            ORDER BY id DESC
            LIMIT %s OFFSET %s
            """,
            (org_id, limit, offset),
        )
        rows = cursor.fetchall()
        
        # Convert datetime to string
        for row in rows:
            created_at = row["created_at"]
            if hasattr(created_at, "strftime"):
                row["created_at"] = created_at.strftime("%Y-%m-%d %H:%M:%S")
            else:
                row["created_at"] = str(created_at or "")
                
        # Get total count
        cursor.execute(
            "SELECT COUNT(*) as count FROM audit_logs WHERE organization_id = %s",
            (org_id,),
        )
        total = cursor.fetchone()["count"]
        
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "logs": rows,
        }
    finally:
        cursor.close()
