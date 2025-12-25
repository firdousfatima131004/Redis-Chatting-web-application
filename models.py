from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class User(Base):
    """User model - stores username, hashed password, and profile details"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Profile fields
    age = Column(Integer, nullable=True)
    interests = Column(String(500), nullable=True)  # Comma-separated
    total_friends = Column(Integer, default=0)
    
    # Account lifecycle
    created_at = Column(DateTime, default=datetime.utcnow)
    account_duration = Column(String(20), nullable=True) # e.g. "1 hour"
    expires_at = Column(DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"


class PublicMessage(Base):
    """Stores permanent public messages"""
    __tablename__ = "public_messages"

    id = Column(String(32), primary_key=True)
    sender = Column(String(50), nullable=False)
    message = Column(String(500), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    file_data = Column(String(5000000), nullable=True) # Approx 5MB limit for Base64
    file_type = Column(String(50), nullable=True) # MIME type
    
    def to_dict(self):
        return {
            "id": self.id,
            "sender": self.sender,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() + "Z", # Append Z for UTC
            "type": "permanent",
            "file_data": self.file_data,
            "file_type": self.file_type
        }


# Database setup
# ✅ check_same_thread=False helps when app uses threads (Flask-SocketIO threading mode).
engine = create_engine(
    "sqlite:///chat.db",
    echo=False,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Create tables
Base.metadata.create_all(engine)
