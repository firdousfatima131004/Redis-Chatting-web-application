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



from sqlalchemy import ForeignKey, Table
from sqlalchemy.orm import relationship

class Group(Base):
    """Group model for persistent group metadata"""
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    description = Column(String(200), nullable=True)
    type = Column(String(20), default="public") # public, private
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    members = relationship("GroupMember", back_populates="group", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "type": self.type,
            "created_at": self.created_at.isoformat() + "Z"
        }

class GroupMember(Base):
    """Association table for User-Group membership"""
    __tablename__ = "group_members"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), default="member") # admin, member
    joined_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    group = relationship("Group", back_populates="members")
    user = relationship("User")


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
