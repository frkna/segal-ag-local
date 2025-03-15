from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

# Kullanıcı rolleri için enum değerleri
class UserRole:
    ADMIN = 'idare'
    TEACHER = 'öğretmen'
    STUDENT = 'sınıf'

# Oda üyeliği tablosu (Many-to-Many ilişki için)
room_members = db.Table('room_members',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('room_id', db.Integer, db.ForeignKey('rooms.id'), primary_key=True),
    db.Column('joined_at', db.DateTime, default=datetime.utcnow)
)

seen_messages = db.Table('seen_messages',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('message_id', db.Integer, db.ForeignKey('messages.id'))
)

class ScheduleFile(db.Model):
    __tablename__ = 'schedules'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<ScheduleFile {self.filename}>'
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(120), nullable=True) 
    full_name = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(20), nullable=False) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, nullable=True, default=None)
    
    
    # İlişkiler
    messages = db.relationship('Message', backref='author', lazy=True)
    rooms = db.relationship('Room', secondary=room_members, backref=db.backref('members', lazy='dynamic'))
    created_rooms = db.relationship('Room', backref='creator', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def can_send_message(self, room):
        return self.role in [UserRole.ADMIN, UserRole.TEACHER]

    def can_read_message(self, room):
        return True  # Tüm roller okuyabilir

    def can_manage_rooms(self):
        return self.role == UserRole.ADMIN

    def can_manage_users(self):
        return self.role == UserRole.ADMIN
    
    def update_last_seen(self):
        self.last_seen = datetime.utcnow()
        db.session.commit()

class Room(db.Model):
    __tablename__ = 'rooms'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # İlişkiler
    messages = db.relationship('Message', backref='room', lazy=True)
    schedules = db.relationship('ScheduleFile', backref='room', cascade='all, delete-orphan')

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('rooms.id'))
    
    def __repr__(self):
        return f'<Message {self.id}>'
