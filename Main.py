import mysql.connector
import pyotp
import math
import string
import time
import re


DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASS = 'tiger'
DB_PORT = 3306

PW_DB = 'password_manager'
TWOFA_DB = 'user_2fa'  



#Entropy
def get_charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += len(string.punctuation)
    if any(ord(c) > 127 for c in password):
        size += 100
    return size

def calculate_entropy(password: str) -> float:
    charset_size = get_charset_size(password)
    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)

COMMON = {
    "password", "123456", "qwerty", "admin", "abc123",
    "letmein", "welcome", "pass@123", "iloveyou"
}

def is_common(password: str) -> bool:
    return password.lower() in COMMON

def strength_rating(entropy: float, password: str) -> str:
    if is_common(password):
        return "Very Weak (Common Password)"
    if entropy < 28:
        return "Weak"
    elif entropy < 36:
        return "Moderate"
    elif entropy < 60:
        return "Strong"
    else:
        return "Very Strong"

def analyze_password(password: str) -> dict:
    entropy = calculate_entropy(password)
    rating = strength_rating(entropy, password)
    return {"entropy": round(entropy, 2), "rating": rating}


def connect_to_database():
    conn = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        port=DB_PORT
    )
    cursor = conn.cursor()
    return conn, cursor

def create_database_and_tables(cursor):
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {PW_DB}")
    cursor.execute(f"USE {PW_DB}")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE,
            pin CHAR(4)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            website VARCHAR(200),
            password VARCHAR(200),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')


def fetch_2fa_row(cursor_2fa, username: str):
    cursor_2fa.execute(
        "SELECT pin, secret_key FROM user_2fa.twofa WHERE username = %s",
        (username,)
    )
    return cursor_2fa.fetchone()

def verify_otp_for_user(cursor_2fa, username: str, pin_input: str) -> bool:
    row = fetch_2fa_row(cursor_2fa, username)
    if not row:
        print("2FA record not found for this username. Register in the 2FA app first.")
        return False

    stored_pin, secret_key = row

    if stored_pin != pin_input:
        print("Incorrect 2FA PIN.")
        return False

    otp_input = input("Enter your OTP code: ").strip()

    totp = pyotp.TOTP(secret_key, digits=4)

    if totp.verify(otp_input):
        print("✅ OTP verified successfully!")
        return True
    else:
        print("❌ Invalid OTP.")
        return False


def valid_pin(pin: str) -> bool:
    return bool(re.fullmatch(r'\d{4}', pin))

def store_user(cursor, conn):
    username = input("Enter the username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return

    pin = input("Set a 4-digit PIN for this user: ").strip()
    if not valid_pin(pin):
        print("PIN must be 4 digits.")
        return

    try:
        cursor.execute('INSERT INTO users (username, pin) VALUES (%s, %s)', (username, pin))
        conn.commit()
        print("User added successfully.")
    except mysql.connector.Error as err:
        print("Error adding user:", err)

def store_password(cursor, conn):
    username = input("Enter the username: ").strip()
    website = input("Enter website: ").strip()
    password_input = input("Enter the password: ").strip()

    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()

    if user:
        user_id = user[0]
        cursor.execute(
            'INSERT INTO passwords (user_id, website, password) VALUES (%s, %s, %s)',
            (user_id, website, password_input)
        )
        conn.commit()
        print("Password stored.")
    else:
        print("User not found.")

def view_password(cursor, conn):
    username = input("Enter your username: ").strip()

    cursor.execute('SELECT id, pin FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()

    if not user:
        print("User not found.")
        return

    user_id, stored_pin = user
    pin_input = input("Enter your 4-digit PIN: ").strip()

    if stored_pin != pin_input:
        print("Incorrect PIN.")
        return

    # OTP verify
    conn2, cursor2 = connect_to_database()
    try:
        if not verify_otp_for_user(cursor2, username, pin_input):
            return
    finally:
        cursor2.close()
        conn2.close()

    website = input("Enter the website to view password: ").strip()

    cursor.execute(
        'SELECT password FROM passwords WHERE user_id = %s AND website = %s',
        (user_id, website)
    )
    result = cursor.fetchone()

    if result:
        print(f"Password for {username} at {website}: {result[0]}")
    else:
        print("No password found.")

def update_password(cursor, conn):
    username = input("Enter your username: ").strip()
    cursor.execute('SELECT id, pin FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()

    if not user:
        print("User not found.")
        return

    user_id, stored_pin = user
    pin_input = input("Enter your PIN: ").strip()

    if stored_pin != pin_input:
        print("Incorrect PIN.")
        return

    website = input("Website to update: ").strip()
    new_pw = input("New password: ").strip()

    cursor.execute(
        'UPDATE passwords SET password = %s WHERE user_id = %s AND website = %s',
        (new_pw, user_id, website)
    )
    conn.commit()

    if cursor.rowcount:
        print("Password updated.")
    else:
        print("No matching record.")

def delete_password(cursor, conn):
    username = input("Enter your username: ").strip()
    cursor.execute('SELECT id, pin FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()

    if not user:
        print("User not found.")
        return

    user_id, stored_pin = user
    pin_input = input("Enter your PIN: ").strip()

    if stored_pin != pin_input:
        print("Incorrect PIN.")
        return

    website = input("Website to delete: ").strip()

    cursor.execute(
        'DELETE FROM passwords WHERE user_id = %s AND website = %s',
        (user_id, website)
    )
    conn.commit()

    if cursor.rowcount:
        print("Password deleted.")
    else:
        print("No record found.")

def psc(cursor):
    username = input("Enter your username: ").strip()

    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()

    if not user:
        print("User not found.")
        return

    user_id = user[0]

    pin_input = input("Enter your 4-digit PIN: ").strip()

    conn2, cursor2 = connect_to_database()
    try:
        if not verify_otp_for_user(cursor2, username, pin_input):
            return
    finally:
        cursor2.close()
        conn2.close()

    website = input("Enter website: ").strip()

    cursor.execute(
        'SELECT password FROM passwords WHERE user_id = %s AND website = %s',
        (user_id, website)
    )
    row = cursor.fetchone()

    if not row:
        print("No password found.")
        return

    password = row[0]
    analysis = analyze_password(password)

    print("\n=== Password Strength Analysis ===")
    print(f"Password: {password}")
    print(f"Entropy: {analysis['entropy']} bits")
    print(f"Strength: {analysis['rating']}")



def main():
    conn, cursor = connect_to_database()
    create_database_and_tables(cursor)

    print("Password Manager".center(60))

    while True:
        print("\n1. Add user\n2. Add password\n3. View password\n4. Update password\n5. Delete password\n6. View strength\n7. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            store_user(cursor, conn)
        elif choice == "2":
            store_password(cursor, conn)
        elif choice == "3":
            view_password(cursor, conn)
        elif choice == "4":
            update_password(cursor, conn)
        elif choice == "5":
            delete_password(cursor, conn)
        elif choice == "6":
            psc(cursor)
        elif choice == "7":
            print("Exiting...")
            break
        else:
            print("Invalid input.")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()
