import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

username = input("Username: ")
password = input("Password: ")

query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)

result = cursor.fetchone()

if result:
    print("Login success")
else:
    print("Invalid login")