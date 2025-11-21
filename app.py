import sqlite3
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

# Ruta del archivo SQLite dentro de /server
DB_PATH = os.path.join("server", "chat.db")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inicializar la DB
def init_db():
    os.makedirs("server", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.get("/messages")
def get_messages():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM messages ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()

    return [{"id": r[0], "username": r[1], "message": r[2]} for r in rows]

@app.post("/messages")
def save_message(username: str, message: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("INSERT INTO messages (username, message) VALUES (?, ?)",
                (username, message))

    conn.commit()
    conn.close()

    return {"status": "ok"}
