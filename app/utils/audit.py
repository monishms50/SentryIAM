def log_event(db, event_type: str, success: bool, user_id=None, request = None):
    try:
        ip = request.client.host if request else None
        user_agent = request.headers.get("user-agent") if request else None
        db.add(AuditLog(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip,
            user_agent=user_agent,
            success=success
        ))
        db.commit()
    except Exception:
        pass  # so that logging never crash the main flow
