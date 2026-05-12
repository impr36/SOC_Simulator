import sqlite3

DB_NAME="soc_simulator.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def initialize_database():
    conn=get_connection()
    cursor=conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS raw_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source TEXT,
        event_id INTEGER,
        computer TEXT,
        user TEXT,
        process_name TEXT,
        severity TEXT,
        description TEXT,
        raw_data TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        type TEXT,
        severity TEXT,
        log_source TEXT,
        category TEXT,          
        event_id INTEGER,
        description TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS forensic_cases(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_name TEXT,
        created_at TEXT,
        file_path TEXT,
        hash TEXT
    )
    """)

    cursor.execute("""
CREATE TABLE IF NOT EXISTS file_snapshots(

    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT,
    file_hash TEXT,
    extension TEXT,
    scan_time TEXT,                              
    last_modified TEXT,
    file_size INTEGER,
    created_at TEXT
)
""")

    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_raw_timestamp
    ON raw_logs(timestamp)
    """)

    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_alert_timestamp
    ON alerts(timestamp)
    """)

    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_alert_severity
    ON alerts(severity)
    """)

    conn.commit()
    conn.close()