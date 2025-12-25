import sqlite3

def add_columns():
    try:
        conn = sqlite3.connect('chat.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute("ALTER TABLE public_messages ADD COLUMN file_data TEXT")
            print("Added file_data column")
        except Exception as e:
            print(f"file_data error (maybe exists): {e}")
            
        try:
            cursor.execute("ALTER TABLE public_messages ADD COLUMN file_type TEXT")
            print("Added file_type column")
        except Exception as e:
            print(f"file_type error (maybe exists): {e}")
            
        conn.commit()
        conn.close()
        print("Migration complete.")
    except Exception as e:
        print(f"Migration failed: {e}")

if __name__ == "__main__":
    add_columns()
