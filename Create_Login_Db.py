'''
Create a database with a table to store the user's information, including the hashed password
'''
import sqlite3
import bcrypt
import os

# Create a connection to the SQLite database
conn = sqlite3.connect('login.db')
c = conn.cursor()

# Set the file permissions to only allow read and write access to the owner
os.chmod('login.db', 0o600)

# Create a table to store the user's information, including the hashed password
c.execute('''CREATE TABLE users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')

# Securely hash the password for the first user and store it in the database
hashed_password = bcrypt.hashpw(b"qwerty", bcrypt.gensalt())
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', hashed_password))

# Securely hash the password for the second user and store it in the database
hashed_password = bcrypt.hashpw(b"asdfg", bcrypt.gensalt())
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('user1', hashed_password))

# Securely hash the password for the third user and store it in the database
hashed_password = bcrypt.hashpw(b"zxcvb", bcrypt.gensalt())
c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('user2', hashed_password))

# Commit the changes to the database
conn.commit()

