# Real-Time Chat Application with Auto-Expiring Messages

A production-ready real-time chat application built with Flask, WebSockets (Flask-SocketIO), and Redis. Features secure authentication, user search, real-time messaging, and auto-expiring messages using Redis TTL.

## 🎯 Features

### Core Features
- ✅ **User Authentication**: Register and login with unique usernames
- ✅ **Redis Session Management**: Secure session handling with Redis
- ✅ **User Search**: Search for registered users by username
- ✅ **Real-Time Messaging**: WebSocket-based instant messaging
- ✅ **Auto-Expiring Messages**: Messages automatically disappear after user-defined time (10s to 24h)
- ✅ **Online/Offline Status**: Real-time user status indicators
- ✅ **Dark/Light Mode**: Toggle between themes with persistent preference

### Technical Highlights
- **Flask-SocketIO**: Real-time bidirectional communication
- **Redis TTL**: Automatic message expiration
- **bcrypt**: Secure password hashing
- **SQLAlchemy**: User data persistence
- **Modern UI**: Minimal, clean, responsive design

## 🏗️ Architecture

### Project Structure
```
redis_practice/
├── app.py               # Main Flask app with WebSocket handlers
├── models.py            # SQLAlchemy User model
├── requirements.txt     # Python dependencies
├── templates/           # Jinja2 HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   └── chat.html
└── static/
    └── css/
        └── style.css    # Modern CSS with dark/light mode
```

### Redis Key Patterns
```
session:{session_id}              → username (TTL: 24 hours)
online:{username}                 → "1" (TTL: 60 seconds)
message:{room}:{message_id}       → message JSON (TTL: user-defined)
chat:{room}:messages              → list of message IDs (TTL: matches message)
```

### How It Works

1. **Authentication Flow**
   - User registers with username and password (hashed with bcrypt)
   - Login creates Redis session with 24-hour TTL
   - Session verified on each request

2. **Real-Time Messaging**
   - Users search for other users
   - Chat rooms created using sorted usernames (consistent room IDs)
   - Messages sent via WebSocket and stored in Redis with TTL
   - Messages automatically expire based on user-selected duration

3. **Online Status**
   - Users ping server every 30 seconds
   - Online status stored in Redis with 60-second TTL
   - Status updates broadcast to all connected clients

4. **Message Expiration**
   - User selects expiration time (10s, 1m, 1h, etc.)
   - Message stored in Redis with matching TTL
   - Frontend displays countdown timer
   - Redis automatically deletes expired messages

## 🚀 Setup Instructions

### Prerequisites
- Python 3.8+
- Redis server running locally

### Installation

1. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start Redis server**
   ```bash
   # macOS (using Homebrew)
   brew services start redis
   
   # Linux
   sudo systemctl start redis
   
   # Or run directly
   redis-server
   ```

3. **Run the Flask application**
   ```bash
   python app.py
   ```

4. **Access the application**
   - Open browser: `http://localhost:5000`
   - Register two accounts in different browser windows/tabs
   - Search for users and start chatting!

## 📋 Usage Guide

### Registration & Login
1. Register with a unique username (3+ characters, alphanumeric + underscore)
2. Login with your credentials
3. Session persists for 24 hours

### Starting a Chat
1. Use the search box to find users by username
2. Click on a user to start a chat
3. Online/offline status shown next to usernames

### Sending Messages
1. Type your message in the input box
2. Select expiration time (10 seconds to 24 hours)
3. Click Send or press Enter
4. Message appears with countdown timer
5. Message automatically expires after selected time

### Features
- **Real-Time Updates**: Messages appear instantly for both users
- **Message Timer**: See how long until message expires
- **Theme Toggle**: Switch between light and dark mode
- **Online Status**: See when other users are online
- **Auto-Expiry**: Messages disappear automatically (no manual cleanup needed)

## 🔐 Security Features

- ✅ bcrypt password hashing
- ✅ Redis session management with expiry
- ✅ Input validation and sanitization
- ✅ XSS protection (Jinja2 auto-escaping)
- ✅ SQL injection protection (SQLAlchemy)
- ✅ WebSocket authentication verification

## 🎨 UI/UX Design

### Design Principles
- **Minimal**: Clean, uncluttered interface
- **Modern**: Smooth animations, professional styling
- **Accessible**: High contrast, clear typography
- **Responsive**: Works on desktop and mobile

### Color Scheme
- **Light Mode**: White backgrounds, dark text, blue accents
- **Dark Mode**: Dark backgrounds, light text, bright blue accents
- **Status Colors**: Green (online), Gray (offline)
- **Message Colors**: Blue gradient (own), White (others)

### Features
- Smooth transitions and hover effects
- Real-time status indicators
- Message countdown timers
- Notification system
- Theme persistence (saved in localStorage)

## 💡 Technical Details

### WebSocket Events

**Client → Server:**
- `connect`: Establish connection
- `ping`: Maintain online status
- `start_chat`: Begin chat with user
- `send_message`: Send new message
- `leave_chat`: Leave chat room

**Server → Client:**
- `connected`: Connection confirmed
- `user_status`: User online/offline update
- `chat_started`: Chat room initialized
- `new_message`: New message received
- `message_sent`: Message sent confirmation
- `error`: Error occurred

### Message Expiration Options
- 10 seconds
- 30 seconds
- 1 minute
- 5 minutes
- 15 minutes
- 1 hour (default)
- 24 hours

### Redis Usage

**Why Redis?**
- **Speed**: Sub-millisecond access for real-time features
- **TTL**: Built-in expiration (perfect for temporary messages)
- **Atomic Operations**: Thread-safe counters and lists
- **Memory Efficiency**: Automatic cleanup of expired data

**What's Stored:**
- Sessions (24h TTL)
- Online status (60s TTL)
- Messages (user-defined TTL)
- Message lists (matching message TTL)

## 🐛 Troubleshooting

### Redis Connection Error
```
✗ Redis connection failed. Please ensure Redis is running on localhost:6379
```
**Solution**: Start Redis server (`redis-server` or `brew services start redis`)

### WebSocket Connection Issues
- Ensure Flask-SocketIO is installed: `pip install flask-socketio eventlet`
- Check browser console for WebSocket errors
- Verify Redis is running

### Messages Not Appearing
- Check browser console for errors
- Verify both users are connected via WebSocket
- Check Redis connection status

### Port Already in Use
Change port in `app.py`: `socketio.run(app, port=5001)`

## 📚 Technologies Used

- **Flask 3.0.0**: Web framework
- **Flask-SocketIO 5.3.6**: WebSocket support
- **Redis 5.0.1**: In-memory data store with TTL
- **SQLAlchemy 2.0.23**: ORM for database
- **bcrypt 4.1.1**: Password hashing
- **Bootstrap 5.3.2**: UI framework
- **Socket.IO 4.5.4**: Client-side WebSocket library
- **SQLite**: Database (via SQLAlchemy)

## 🎓 Learning Outcomes

This project demonstrates:

1. **Real-Time Communication**: WebSocket implementation with Flask-SocketIO
2. **Redis TTL**: Using expiration for temporary data
3. **Session Management**: Secure Redis-based sessions
4. **User Search**: Efficient database queries
5. **Message Expiration**: Automatic cleanup with Redis
6. **Modern UI**: Dark/light mode, responsive design
7. **Online Status**: Real-time presence indicators

## 🔄 Future Enhancements

Potential improvements:
- Message encryption
- File/image sharing
- Group chats
- Message history persistence
- Read receipts
- Typing indicators
- User profiles
- Message reactions

## 📄 License

This project is for educational and demonstration purposes.

---

**Built with ❤️ for real-time communication and Redis expertise**

