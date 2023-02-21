import bcrypt
import random
import pwinput
import sqlite3

def create_db():
    # Create Database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL)''')

    conn.commit()
    conn.close()


# Login Fn
def login():
    # Call db function
    create_db()

    print("\n---------------| Login |---------------")

    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")


    # Fetch the user's hashed password from the database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute("SELECT password FROM users WHERE username=?", (username,))

    row = c.fetchone()

    conn.close()

    if row is None:
        print("\nInvalid username or password")
        print("-----------------------------------------\n")
        return

    hashed_password = row[0]

    # Check if the password is correct
    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        print("\nLogin successful!")
        
        return True
    else:
        print("\nInvalid username or password")
        return False

# Signup Fn
def signup():
    # Call db function
    create_db()

    print("\n---------------| Signup |---------------")

    
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    password_check(password)

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Insert the new user into the database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))

    conn.commit()
    conn.close()

    print("User created successfully!")
    return True

# Generate random password
def random_pass(length):
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
    password = ''
    for i in range(length):
        password += random.choice(chars)
    signup()
    return password


# Password checker
def password_check(password):
    # Generate a captcha code
    def generate_captcha():
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'
        captcha = ''
        for i in range(6):
            captcha += random.choice(chars)
        return captcha

    # Check the strength of a password
    def check_password_strength():
        strength = 0
        if len(password) >= 8:
            strength += 1
        if any(c.isupper() for c in password) and any(c.islower() for c in password):
            strength += 1
        if any(c.isdigit() for c in password):
            strength += 1
        if any(c in '!@#$%^&*()_-+={}[]|\:;"<>,.?/' for c in password):
            strength += 1
        return strength

    # User password validation
    def pass_validation():
        captcha = generate_captcha()
        print("\nPlease enter the following captcha to complete your registration:", captcha,"\n")
        captcha_input = input("\nEnter the captcha: ")
        if captcha_input == captcha:
            password_strength = check_password_strength()
            if password_strength == 4:
                print("Your password is very strong!\n")
            elif password_strength == 3:
                print("Your password is strong.\n")
            elif password_strength == 2:
                print("* Your password is weak. Please consider adding more complexity.\n")
            else:
                print("* Your password is very weak. Please choose a stronger password.\n")
                Yn = input("Generate a password? (y/n): ")
                if(Yn == "y"):
                    length = input("Enter the password length you want: ")
                    random_pass(length)
                signup()
        else:
            print("Captcha verification failed. Please try again.")
            print("Signup again")
            signup()
        
    pass_validation()
