from flask import Flask, render_template, request, redirect, url_for, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os


from extensions import db
from models import FamilyMember

app = Flask(__name__)
app.secret_key = 'super-secret-key-1234'


# Configure the app
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from models import User
from flask_mail import Mail, Message


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # This is correct for Flask-Login

bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'apikey'  # This is literally the string 'apikey'
app.config['MAIL_PASSWORD'] = os.environ.get('SENDGRID_API_KEY')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# ✅ Ensure upload folder exists (even in production)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db.init_app(app)
mail = Mail(app)

# Ensure tables are created (production-safe)
with app.app_context():
    db.create_all()

@app.route('/init-db')
def init_db():
    with app.app_context():
        db.create_all()
    return "Database tables created successfully!"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from flask_login import login_user, login_required, logout_user, current_user


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password1 = request.form['password1']
        password2 = request.form['password2']

        user = User.query.filter_by(username=username).first()
        email_user = User.query.filter_by(email=email).first()
        if user:
            flash('Username already exists.', category='error')
        elif email_user:
            flash('Email already registered.', category='error')
        elif len(username) < 2:
            flash('Username must not be left blank and must be greater than or equal to 2 characters.', category='error')
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(username=username, email=email, password_hash=bcrypt.generate_password_hash(password1).decode('utf-8'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('login'))

    return render_template('register.html', user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            flash(f'Logged in successfully! Welcome to the Ogbonna\'s Family Website, {user.username}', category='success')
            login_user(user)
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))




@app.route('/')
def index():
    relationship = request.args.get('relationship', '')
    if relationship:
        members = FamilyMember.query.filter(
            FamilyMember.relationship.ilike(f"%{relationship}%")
        ).all()
    else:
        members = FamilyMember.query.all()

    # Birthday reminder logic
    today = datetime.today()
    birthday_members = [member for member in members if member.dob.month == today.month and member.dob.day == today.day]
    for member in birthday_members:
        flash(f"Today is {member.full_name}'s birthday! 🎉", category='success')

    # Email notification to all users if there is a birthday today
    if birthday_members:
        users = User.query.all()
        recipient_emails = [user.email for user in users if user.email]
        for member in birthday_members:
            msg = Message(
                subject=f"Birthday Reminder: {member.full_name}",
                recipients=recipient_emails,
                body=f"Today is {member.full_name}'s birthday! Wish them a happy birthday!"
            )
            mail.send(msg)

    return render_template('home.html', members=members, relationship=relationship)


# View a family member's profile
@app.route('/member/<int:member_id>')
def member_profile(member_id):
    member = FamilyMember.query.get_or_404(member_id)
    return render_template('member_profile.html', member=member)


# Add a new family member
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_member():
    if request.method == 'POST':
        full_name = request.form['full_name']
        dob = datetime.strptime(request.form['dob'], '%Y-%m-%d')
        dod = request.form['dod']
        is_alive = not bool(dod.strip())
        dod = datetime.strptime(dod, '%Y-%m-%d') if dod.strip() else None
        biography = request.form['biography']
        relationship = request.form['relationship']
        photo = request.files['photo']
        photo_filename = None

        parent_id = request.form.get('parent_id')
        parent_id = int(parent_id) if parent_id else None  # ✅ Convert to int if exists

        if photo and photo.filename != '':
            photo_filename = photo.filename
            if photo_filename:
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], str(photo_filename))
                photo.save(photo_path)
            # Set photo_url on new_member below

        new_member = FamilyMember(
            full_name=full_name,
            dob=dob,
            dod=dod,
            is_alive=is_alive,
            biography=biography,
            relationship=relationship,
            photo_url=photo_filename,
            parent_id=parent_id
        )

        db.session.add(new_member)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('add_member.html', FamilyMember=FamilyMember)


# Edit a family member
@app.route('/edit/<int:member_id>', methods=['GET', 'POST'])
@login_required
def edit_member(member_id):
    member = FamilyMember.query.get_or_404(member_id)

    if request.method == 'POST':
        member.full_name = request.form['full_name']
        member.dob = datetime.strptime(request.form['dob'], '%Y-%m-%d')
        dod = request.form['dod']
        member.is_alive = not bool(dod.strip())
        member.dod = datetime.strptime(dod, '%Y-%m-%d') if dod.strip() else None
        member.biography = request.form['biography']
        member.relationship = request.form['relationship']

        parent_id = request.form.get('parent_id')
        parent_id = int(parent_id) if parent_id else None


        photo = request.files['photo']
        if photo and photo.filename != '':
            photo_filename = photo.filename
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
            photo.save(photo_path)
            member.photo_url = photo_filename

        db.session.commit()
        return redirect(url_for('member_profile', member_id=member.id))

    return render_template('edit_member.html', FamilyMember=FamilyMember, member=member)


# Delete a family member
@app.route('/delete/<int:member_id>', methods=['POST'])
@login_required
def delete_member(member_id):
    member = FamilyMember.query.get_or_404(member_id)

    # Delete photo file if it exists
    if member.photo_url:
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], member.photo_url)
        if os.path.exists(photo_path):
            os.remove(photo_path)

    db.session.delete(member)
    db.session.commit()
    return redirect(url_for('index'))


# Generate family tree
@app.route('/family-tree')
def family_tree():
    members = FamilyMember.query.all()

    # Convert members to dict format for JS
    def build_tree(member):
        return {
            "name": member.full_name,
            "children": [build_tree(child) for child in member.children]
        }

    roots = [m for m in members if not m.parent_id]
    tree_data = [build_tree(root) for root in roots]

    return render_template('family_tree.html', tree_data=tree_data)



# Run the app
if __name__ == '__main__':
    
    app.run(debug=True)
