import mysql.connector
import pyotp
import time

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

def TOTP(cursor):
    db_name = 'User_2fa'
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
    cursor.execute(f"USE {db_name}")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS twofa(
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE,
            pin VARCHAR(4),
            secret_key VARCHAR(32),
            time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

def main(cursor):
    uinput = input("Enter your username. \n ***SAME AS THAT OF PASSWORD MANAGER***\n")
    pininput = input("Enter your pin\n")
    try:
        TOTP(cursor)
        secret_key = pyotp.random_base32()  # Generate a unique base32 secret key
        cursor.execute("INSERT INTO twofa(username, pin, secret_key) VALUES (%s, %s, %s);",
                       (uinput, pininput, secret_key))
        conn.commit()
        print("User registered for 2FA.")
        print("Your secret key is:", secret_key)
        
        print("Your current OTP is:", pyotp.TOTP(secret_key, digits=4).now())
    except mysql.connector.Error as err:
        print(f"ERROR: {err}")

main(cursor)
conn.close()
