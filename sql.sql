import sqlite3

# ឈ្មោះឯកសារមូលដ្ឋានទិន្នន័យ SQLite
# SQLite database file name
DATABASE_NAME = 'my_application_data.db'

def connect_db():
    """
    ភ្ជាប់ទៅមូលដ្ឋានទិន្នន័យ SQLite ។
    ប្រសិនបើឯកសារមូលដ្ឋានទិន្នន័យមិនមានទេ វានឹងត្រូវបានបង្កើត។
    Returns a connection object.
    """
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        conn.row_factory = sqlite3.Row # អនុញ្ញាតឱ្យចូលប្រើជួរឈរដោយឈ្មោះ
        print(f"Successfully connected to {DATABASE_NAME}")
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def create_table(conn):
    """
    បង្កើតតារាង 'users' ប្រសិនបើវាមិនទាន់មាន។
    Creates the 'users' table if it doesn't already exist.
    """
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                age INTEGER
            )
        ''')
        conn.commit() # រក្សាទុកការផ្លាស់ប្តូរ
        print("Table 'users' created or already exists.")
    except sqlite3.Error as e:
        print(f"Error creating table: {e}")

def insert_user(conn, name, email, age):
    """
    បញ្ចូលអ្នកប្រើប្រាស់ថ្មីទៅក្នុងតារាង 'users' ។
    Inserts a new user into the 'users' table.
    """
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, age) VALUES (?, ?, ?)", (name, email, age))
        conn.commit()
        print(f"User '{name}' inserted successfully.")
        return cursor.lastrowid # ត្រឡប់ ID នៃជួរដេកដែលបានបញ្ចូល
    except sqlite3.Error as e:
        print(f"Error inserting user: {e}")
        return None

def get_all_users(conn):
    """
    ទាញយកអ្នកប្រើប្រាស់ទាំងអស់ពីតារាង 'users' ។
    Fetches all users from the 'users' table.
    """
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall() # យកជួរដេកទាំងអស់
        if users:
            print("\n--- All Users ---")
            for user in users:
                # ចូលប្រើជួរឈរដោយឈ្មោះដោយសារ row_factory
                print(f"ID: {user['id']}, Name: {user['name']}, Email: {user['email']}, Age: {user['age']}")
        else:
            print("No users found.")
        return users
    except sqlite3.Error as e:
        print(f"Error fetching users: {e}")
        return []

def get_user_by_email(conn, email):
    """
    ទាញយកអ្នកប្រើប្រាស់ដោយអ៊ីមែល។
    Fetches a user by email.
    """
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone() # យកជួរដេកមួយ
        if user:
            print(f"\n--- User found by email '{email}' ---")
            print(f"ID: {user['id']}, Name: {user['name']}, Email: {user['email']}, Age: {user['age']}")
        else:
            print(f"No user found with email: {email}")
        return user
    except sqlite3.Error as e:
        print(f"Error fetching user by email: {e}")
        return None

def update_user_age(conn, user_id, new_age):
    """
    ធ្វើបច្ចុប្បន្នភាពអាយុរបស់អ្នកប្រើប្រាស់ដោយ ID ។
    Updates a user's age by ID.
    """
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET age = ? WHERE id = ?", (new_age, user_id))
        conn.commit()
        if cursor.rowcount > 0:
            print(f"User with ID {user_id} updated. New age: {new_age}")
        else:
            print(f"No user found with ID {user_id} to update.")
    except sqlite3.Error as e:
        print(f"Error updating user: {e}")

def delete_user(conn, user_id):
    """
    លុបអ្នកប្រើប្រាស់ដោយ ID ។
    Deletes a user by ID.
    """
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        if cursor.rowcount > 0:
            print(f"User with ID {user_id} deleted successfully.")
        else:
            print(f"No user found with ID {user_id} to delete.")
    except sqlite3.Error as e:
        print(f"Error deleting user: {e}")

# មុខងារសំខាន់ដើម្បីដំណើរការកម្មវិធី
# Main function to run the application
def main():
    conn = connect_db()
    if conn:
        create_table(conn)

        # បញ្ចូលទិន្នន័យគំរូ
        # Insert sample data
        insert_user(conn, "Sok Srey", "sok.srey@example.com", 30)
        insert_user(conn, "Vann Rithy", "vann.rithy@example.com", 25)
        insert_user(conn, "Chhay Sokha", "chhay.sokha@example.com", 35)

        # ព្យាយាមបញ្ចូលអ្នកប្រើប្រាស់ដែលមានអ៊ីមែលដូចគ្នា (នឹងបរាជ័យដោយសារ UNIQUE constraint)
        # Try to insert a user with the same email (will fail due to UNIQUE constraint)
        insert_user(conn, "Sok Srey Duplicate", "sok.srey@example.com", 31)

        # យកអ្នកប្រើប្រាស់ទាំងអស់
        # Get all users
        get_all_users(conn)

        # យកអ្នកប្រើប្រាស់ម្នាក់ដោយអ៊ីមែល
        # Get a single user by email
        get_user_by_email(conn, "vann.rithy@example.com")
        get_user_by_email(conn, "nonexistent@example.com")

        # ធ្វើបច្ចុប្បន្នភាពអាយុរបស់អ្នកប្រើប្រាស់
        # Update a user's age
        update_user_age(conn, 1, 31) # ធ្វើបច្ចុប្បន្នភាព Sok Srey
        get_all_users(conn)

        # លុបអ្នកប្រើប្រាស់
        # Delete a user
        delete_user(conn, 3) # លុប Chhay Sokha
        get_all_users(conn)

        # បិទការតភ្ជាប់
        # Close the connection
        conn.close()
        print(f"\nDatabase connection to {DATABASE_NAME} closed.")

if __name__ == "__main__":
    main()
