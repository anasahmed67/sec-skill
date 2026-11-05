import sqlite3
def get_user(db, username):
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    return cursor.execute(query, (username,)).fetchall()
