import mysql.connector
import pyotp
import re


host = 'localhost'
user = 'root'
password = 'tiger'
port = 3306

conn = mysql.connector.connect(
    host=host,
    user=user,
    password=password,
    port=port
)
cursor = conn.cursor()

DB_NAME = 'user_2fa'  

def ensure_2fa_db(cursor):
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME}")
    cursor.execute(f"USE {DB_NAME}")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS twofa(
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE,
            pin CHAR(4),
            secret_key VARCHAR(64),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

def valid_pin(pin: str) -> bool:
    return bool(re.fullmatch(r'\d{4}', pin))

def register_user(cursor, conn):
    ensure_2fa_db(cursor)

    username = input("Enter username for 2FA (must match your password-manager username): ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    pin = input("Enter a 4-digit PIN to attach to 2FA: ").strip()
    if not valid_pin(pin):
        print("Invalid PIN. It must be exactly 4 digits.")
        return

    try:
        # check for existing user
        cursor.execute("SELECT secret_key, pin FROM twofa WHERE username = %s", (username,))
        row = cursor.fetchone()
        if row:
            existing_secret, existing_pin = row
            print("User already registered for 2FA.")
            print(f"Stored PIN: {existing_pin}")
            print(f"Stored secret key: {existing_secret}")
            print("If you lost your secret key, delete the user and re-register.")
            return

        secret_key = pyotp.random_base32()  # single generation
        cursor.execute("INSERT INTO twofa (username, pin, secret_key) VALUES (%s, %s, %s)",
                       (username, pin, secret_key))
        conn.commit()
        print("User registered for 2FA.")
        print("Secret key (store this safely):", secret_key)
        print("Current OTP (4 digits):", pyotp.TOTP(secret_key, digits=4).now())

    except mysql.connector.Error as err:
        print("Database error:", err)

def main():
    try:
        register_user(cursor, conn)
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()
