from flask_login import UserMixin
from extensions import db
from datetime import datetime, timedelta
import secrets
import string




class FamilyMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    dod = db.Column(db.Date)
    is_alive = db.Column(db.Boolean, default=True)
    biography = db.Column(db.Text)
    relationship = db.Column(db.String(100))
    photo_url = db.Column(db.String(200))

    parent_id = db.Column(db.Integer, db.ForeignKey('family_member.id'))

    parent = db.relationship(
        'FamilyMember',
        remote_side=[id],
        backref='children',
        foreign_keys=[parent_id]
    )

# Create User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    reset_code = db.Column(db.String(6))  # 6-digit code

    def __repr__(self):
        return f'<User {self.username}>'
    
    def generate_reset_token(self):
        """Generate a secure reset token and 6-digit code"""
        # Generate a secure token
        self.reset_token = secrets.token_urlsafe(32)
        # Generate a 6-digit code
        self.reset_code = ''.join(secrets.choice(string.digits) for _ in range(6))
        # Set expiry to 15 minutes from now
        self.reset_token_expiry = datetime.utcnow() + timedelta(minutes=15)
        return self.reset_code
    
    def is_reset_token_valid(self):
        """Check if reset token is valid and not expired"""
        if not self.reset_token or not self.reset_token_expiry:
            return False
        return datetime.utcnow() < self.reset_token_expiry
    
    def clear_reset_token(self):
        """Clear reset token and code after use"""
        self.reset_token = None
        self.reset_token_expiry = None
        self.reset_code = None

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    member_id = db.Column(db.Integer, db.ForeignKey('family_member.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    member = db.relationship('FamilyMember', backref='comments')

class MemorableMoment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(500), nullable=False)
    posted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    posted_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    user = db.relationship('User', backref='memorable_moments')