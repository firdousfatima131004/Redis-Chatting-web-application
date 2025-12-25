import os
import sys
from sqlalchemy import inspect

# Add current dir to path
sys.path.append(os.getcwd())

try:
    print("Importing models...")
    from models import User, SessionLocal, engine, Base
    print("Models imported successfully.")
    
    print(f"Database URL: {engine.url}")
    
    # Check if file exists
    db_path = "chat.db"
    if os.path.exists(db_path):
        print(f"'{db_path}' exists.")
    else:
        print(f"'{db_path}' does NOT exist.")
        
    # Check tables
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"Tables found: {tables}")
    
    if "users" in tables:
        print("Table 'users' exists. Checking columns...")
        columns = [c['name'] for c in inspector.get_columns("users")]
        print(f"Columns: {columns}")
        
        required = ['age', 'interests', 'account_duration', 'expires_at']
        missing = [c for c in required if c not in columns]
        if missing:
            print(f"MISSING COLUMNS: {missing}")
        else:
            print("All new columns present.")
            
    # Try to create a session
    session = SessionLocal()
    print("Session created.")
    session.close()

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()
