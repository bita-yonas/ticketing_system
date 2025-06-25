import sqlite3
from werkzeug.security import generate_password_hash

# Connect to the database
conn = sqlite3.connect('tickets.db')
cursor = conn.cursor()

# New passwords for each user
password_updates = [
    ('admin', 'Admin@2024!'),
    ('regular_user', 'User@2024!'),
    ('test_user', 'Test@2024!')
]

# Update passwords
for username, new_password in password_updates:
    hashed_password = generate_password_hash(new_password)
    cursor.execute(
        'UPDATE users SET password = ? WHERE username = ?',
        (hashed_password, username)
    )

# Commit changes and close connection
conn.commit()
conn.close()

print("Passwords have been reset successfully!")
print("\nNew credentials:")
print("-----------------")
for username, password in password_updates:
    print(f"Username: {username}")
    print(f"Password: {password}")
    print("-----------------") 