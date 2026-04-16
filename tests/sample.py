from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from contextlib import contextmanager
import psycopg2
from datetime import datetime
import os

app = FastAPI()

# --- DB connection ---

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "database": os.environ.get("DB_NAME", "security_log"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD")
}

@contextmanager
def get_db():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# --- Data model ---

class LoginEvent(BaseModel):
    username: str
    password_hash: str
    ip_address: str
    success: bool = True


# --- Routes ---


# GET landing page
@app.get("/")
def get_landing_page():
    return [
        {
            "Landing_Page": "Successful"
        }
    ]

# GET all login events
@app.get("/login-events")
def get_login_events():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, ip_address, logged_in_at, success FROM login_event ORDER BY id"
        )
        rows = cursor.fetchall()

    return [
        {
            "id": row[0],
            "username": row[1],
            "ip_address": row[2],
            "logged_in_at": row[3],
            "success": row[4]
        }
        for row in rows
    ]


# GET a single user's events
@app.get("/login-events/{username}")
def get_user_events(username: str):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, ip_address, logged_in_at, success FROM login_event WHERE username = %s ORDER BY logged_in_at DESC",
            (username,)
        )
        rows = cursor.fetchall()

    if not rows:
        raise HTTPException(status_code=404, detail="No events found for this user")

    return [
        {
            "id": row[0],
            "username": row[1],
            "ip_address": row[2],
            "logged_in_at": row[3],
            "success": row[4]
        }
        for row in rows
    ]


# POST a new login event
@app.post("/login-events", status_code=201)
def create_login_event(event: LoginEvent):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO login_event (username, password_hash, ip_address, success)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (event.username, event.password_hash, event.ip_address, event.success)
        )
        new_id = cursor.fetchone()[0]

    return {"id": new_id, "message": "Login event recorded"}
