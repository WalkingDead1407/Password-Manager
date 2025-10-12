import mysql.connector
import pyotp
import time
# Database configuration
host = 'localhost'
user = 'root'
password = 'tiger'
port = 3306

def connect_to_database():
    conn = mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        port=port
    )
    cursor = conn.cursor()
    return conn, cursor

def create_database_and_tables(cursor): 
    database_name = 'password_manager'
    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name}")
    cursor.execute(f"USE {database_name}")
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE,
            pin VARCHAR(4)  
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            website VARCHAR(100),
            password VARCHAR(100),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

def verify_otp(cursor):
    global username_input
    global pin_input
    otp_input = input("Enter your OTP code: ")

    try:
        cursor.execute("SELECT pin, key FROM twofa WHERE username = %s", (username_input,))
        result = cursor.fetchone()

        if result is None:
            print("Username not found.")
            return False

        stored_pin, secret_key = result

        if pin_input != stored_pin:
            print("Incorrect PIN.")
            return False

        totp = pyotp.TOTP(secret_key, digits=4)
        if totp.verify(otp_input):
            print("✅ OTP verified successfully!")
            return True
        else:
            print("❌ Invalid OTP. Please try again.")
            return False
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")


def store_user(cursor, conn):
    """Prompt for user information and store it in the database."""
    global username_input
    global pin_input
    username_input = input("Enter the username: ")
    print("****PLEASE MAKE YOUR USER IN OUR OTP APP TO CONTINUE****")
    
    try:
        # Insert the new user
        cursor.execute('INSERT INTO users (username) VALUES (%s)', (username_input,))
        conn.commit() 
        print("User added successfully.")
        redirecting_animation()

    except mysql.connector.Error as err:
        print(f"Error: {err}")

def store_password(cursor, conn):
    global username_input
    username_input = input("Enter the username for the password: ")
    website = input("Enter the website: ")
    password_input = input("Enter the password: ")
    
    cursor.execute('SELECT id FROM users WHERE username = %s', (username_input,))
    user = cursor.fetchone()
    
    if user:
        user_id = user[0]
        cursor.execute('INSERT INTO passwords (user_id, website, password) VALUES (%s, %s, %s)', 
                       (user_id, website, password_input))
        conn.commit()
        print("Password record inserted successfully.")
        redirecting_animation()
    else:
        print("User not found. Please add the user first.")
        redirecting_animation()
        main()

        
def view_password(cursor):
    global username_input
    global pin_input

    website_to_view = input("Enter the website for which you want to view the password: ")

    # Fetch user data
    cursor.execute('SELECT id, pin FROM users WHERE username = %s', (username_input,))
    user = cursor.fetchone()

    if user:
        user_id = user
        verify_otp(cursor)  # This uses global username_input and pin_input
        if not verify_otp(cursor):
            print("OTP verification failed.")
            redirecting_animation()
            return

        # If OTP is verified, fetch password
        cursor.execute('SELECT password FROM passwords WHERE user_id = %s AND website = %s', 
                       (user_id, website_to_view))
        result = cursor.fetchone()

        if result:
            print(f"Password for {username_input} on {website_to_view} is: {result[0]}")
        else:
            print("No records found for the specified username and website.")

    else:
        print("User not found.")
        
    redirecting_animation()

        
def update_password(cursor, conn):
    global username_input,pin
    username_input = input("Enter your username for the website: ")
    website_to_update = input("Enter the website for which you want to update the password: ")
    pin_input = input("Enter your 4-digit PIN: ")
    new_password = input("Enter the new password: ")
    
    cursor.execute('SELECT id, pin FROM users WHERE username = %s', (username_input,))
    user = cursor.fetchone()
    
    if user:
        user_id, stored_pin = user
        if stored_pin == pin_input:
            cursor.execute('UPDATE passwords SET password = %s WHERE user_id = %s AND website = %s',
                           (new_password, user_id, website_to_update))
            conn.commit()
            
            if cursor.rowcount > 0:
                print("Password updated successfully.")
                redirecting_animation()

            else:
                print("No records found to update.")
                redirecting_animation()

        else:
            print("Incorrect PIN.")
            print("Exiting the programme")
            redirecting_animation()

    else:
        print("User not found.")
        redirecting_animation()

def delete_password(cursor, conn):
    global username_input
    global pin_input
    username_input = input("Enter your username for the website: ")
    website_to_delete = input("Enter the website for which you want to delete the password: ")
    pin_input = input("Enter your 4-digit PIN: ")
    
    cursor.execute('SELECT id, pin FROM users WHERE username = %s', (username_input,))
    user = cursor.fetchone()
    
    if user:
        user_id, stored_pin = user
        if stored_pin == pin_input:
            cursor.execute('DELETE FROM passwords WHERE user_id = %s AND website = %s', (user_id, website_to_delete))
            conn.commit()
            
            if cursor.rowcount > 0:
                print("Password deleted successfully.")
            else:
                print("No records found to delete.")
        else:
            print("Incorrect PIN.")
    else:
        print("User not found.")

def admin(cursor):  # Pass cursor as parameter
    u = input("Enter your username: ")
    if u == "admin":
        admp = input("Enter your password: ")
        if admp == "admin123":
            ad2fa = int(input("Enter your 2FA: "))
            if ad2fa == 1111:
                a = input("What task would you like to perform: \n1. Analyze password strengths\n2. Access logs\n3. Visualize passwords\n")
                if a == "1":
                    psc(cursor)
                # Add other options here

def psc(cursor):
    special = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~"
    try:
        username_view = input("Enter your username for the website: ")
        website_to_view = input("Enter the website for which you want to view the password: ")
        pin_input = input("Enter your 4-digit PIN: ")
        
        cursor.execute('SELECT id, pin FROM users WHERE username = %s', (username_view,))
        user = cursor.fetchone()
        
        if user:
            user_id, stored_pin = user
            if stored_pin == pin_input:
                cursor.execute('SELECT password FROM passwords WHERE user_id = %s AND website = %s', 
                               (user_id, website_to_view))
                result = cursor.fetchone()
                if result:
                    password = result[0]
                    length_score = 2.0 if len(password) >= 8 else 0
                    c1 = c2 = c3 = c4 = 0
                    
                    for char in password:
                        if char.isupper():
                            c1 += 1
                        elif char.islower():
                            c2 += 1
                        elif char.isdigit():
                            c3 += 1
                        elif char in special:
                            c4 += 1
                    
                    score = (c1 > 0)*2.0 + (c2 > 0)*2.0 + (c3 > 0)*2.0 + (c4 > 0)*2.0 + length_score
                    print(f"Password strength score (max 10): {score}")
                    
                    # Provide feedback
                    if score >= 8:
                        print("This is a strong password!")
                        redirecting_animation()

                    elif score >= 5:
                        print("This password could be stronger.")
                        redirecting_animation()

                    else:
                        print("This is a weak password. Consider changing it.")
                        redirecting_animation()

                else:
                    print("No records found for the specified username and website.")
                    redirecting_animation()

            else:
                print("Incorrect PIN.")
                redirecting_animation()

        else:
            print("User not found.")
            redirecting_animation()

    except mysql.connector.Error as err:
        print(f"Error: {err}")

def redirecting_animation(cycles=4):
    states = [
        "redirecting   ",
        "redirecting.  ",
        "redirecting.. ",
        "redirecting...",
        "redirecting.. ",
        "redirecting.  ",
    ]

    for _ in range(cycles):
        for state in states:
            print(f"\r{state}", end="")
            for _ in range(10000000):
                pass

    

def main():
    conn, cursor = connect_to_database()
    create_database_and_tables(cursor)
    print("Password Manager".center(100))

    while True:
        print("\n1. Add user\n2. Add password\n3. View password\n4. Update password\n5. Delete password\n6. View Password Strength\n7. Admin \n8. Exit")
        print("***If you haven't created a user yet MAKE SURE TO DO SO***")
        choice = input("\nChoose an option: ")
        
        if choice == "1":
            store_user(cursor, conn)
            redirecting_animation()
        elif choice == "2":
            store_password(cursor, conn)
        elif choice == "3":
            view_password(cursor)
        elif choice == "4":
            update_password(cursor, conn)
        elif choice == "5":
            delete_password(cursor, conn)
        elif choice == "6":
            admin(cursor)
        elif choice == "7":
            states = [
        "Exiting the program   ",
        "Exiting the program.  ",
        "Exiting the program.. ",
        "Exiting the program...",
        "Exiting the program.. ",
        "Exiting the program.  ",
        ]

            for _ in range(4):
                for state in states:
                    print(f"\r{state}", end="")
                for _ in range(1000):
                    pass

            break
        else:
            print("Invalid input! Please try again.")

    cursor.close()
    conn.close()


username_input=""
if __name__ == "__main__":
    main()

