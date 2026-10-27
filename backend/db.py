import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "cornell-course-sphere-data", "roster_reviews.sqlite.db")


def create_connection():
    return sqlite3.connect(DB_PATH)


def execute_query(query, params=()):
    conn = create_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()
