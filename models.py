import time
import uuid
from database import db
from sqlalchemy.dialects.postgresql import UUID

class User(db.Model):
    __tablename__ = 'users'
    
    # Core User Info
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    
    # Security
    mpin_hash = db.Column(db.String(256)) # Storing MPIN as plain text (as before)
    login_attempts = db.Column(db.Integer, default=0)
    locked = db.Column(db.Boolean, default=False)

    # Profile Details
    full_name = db.Column(db.String(100))
    dob = db.Column(db.String(20)) # Storing as string, e.g., "YYYY-MM-DD"
    phone_number = db.Column(db.String(20))
    address = db.Column(db.Text)
    profile_picture_url = db.Column(db.String(255), default="/static/images/default_avatar.png")

    # OTP Storage (using JSON for flexibility)
    otps = db.Column(db.JSON, default=dict)
    transfer_otp = db.Column(db.JSON, default=dict)
    
    # --- NEW: Password Reset ---
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiry = db.Column(db.Float, nullable=True)
    
    # Relationships
    account = db.relationship('Account', back_populates='user', uselist=False, cascade="all, delete-orphan") # One-to-One
    login_history = db.relationship('LoginHistory', back_populates='user', lazy=True, cascade="all, delete-orphan") # One-to-Many

class Account(db.Model):
    __tablename__ = 'accounts'
    
    # Using a string for account number "SB1234..."
    account_number = db.Column(db.String(12), primary_key=True)
    balance = db.Column(db.Float, nullable=False, default=0.0)
    emergency_mode = db.Column(db.Boolean, default=False)
    
    # Foreign Key to link to User
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), unique=True, nullable=False)
    
    # Relationships
    user = db.relationship('User', back_populates='account')
    sent_transactions = db.relationship('Transaction', foreign_keys='Transaction.sender_account', back_populates='sender', lazy=True)
    received_transactions = db.relationship('Transaction', foreign_keys='Transaction.recipient_account', back_populates='recipient', lazy=True)

class LoginHistory(db.Model):
    __tablename__ = 'login_history'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.Float, default=time.time)
    ip_address = db.Column(db.String(45))
    device_info = db.Column(db.String(255))
    location = db.Column(db.String(255))
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    
    # Foreign Key to link to User
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    
    # Relationship
    user = db.relationship('User', back_populates='login_history')

class Transaction(db.Model):
    __tablename__ = 'transactions'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp = db.Column(db.Float, default=time.time)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Completed')
    type = db.Column(db.String(50), nullable=False, default='Transfer') # e.g., 'Transfer', 'Admin Credit'
    recipient_name = db.Column(db.String(100), nullable=True)
    
    # Foreign Keys
    sender_account = db.Column(db.String(12), db.ForeignKey('accounts.account_number'), nullable=True)
    recipient_account = db.Column(db.String(12), db.ForeignKey('accounts.account_number'), nullable=True)
    
    # Relationships
    sender = db.relationship('Account', foreign_keys=[sender_account], back_populates='sent_transactions')
    recipient = db.relationship('Account', foreign_keys=[recipient_account], back_populates='received_transactions')

class PendingAdmin(db.Model):
    __tablename__ = 'pending_admins'
    
    token = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.Float, default=time.time)