from flask_login import UserMixin
from extensions import db




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
    password_hash = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'