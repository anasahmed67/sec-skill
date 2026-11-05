import sqlite3
def get_user(db, username):
    cursor = db.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return cursor.execute(query).fetchall()
