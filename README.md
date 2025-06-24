👨‍👩‍👧‍👦 Ogbonna Family Tree Web Application
This is a web-based family management and genealogy app built with Flask. It allows registered users to add, edit, view, and delete family members, and visualize family relationships through a family tree interface.

🚀 Features
✅ User authentication (Register/Login/Logout)

✅ Add and manage family member profiles

✅ Upload and display member photos

✅ Search by relationship type

✅ Visualize family tree hierarchy

✅ Secure password hashing using Flask-Bcrypt

✅ User session management using Flask-Login

🛠️ Tech Stack
Backend: Flask, SQLAlchemy, Flask-Bcrypt, Flask-Login

Frontend: HTML, Jinja2 Templates, Bootstrap (optional, based on your templates)

Database: SQLite

Others: Python, Jinja2, HTML Forms

📁 Project Structure

.
├── instance/               # Application instance directory
│   └── family.db  # SQLite database file (auto-created)
├── static/uploads/         # Uploaded member photos
├── templates/              # HTML templates
│   ├── add_member.html
│   ├── base.html
│   ├── edit_member.html
│   ├── family_tree.html
│   ├── home.html
│   ├── login.html
│   ├── member_profile.html
│   └── register.html
├── gitignore
├── extensions.py           # Flask extension initializers
├── app.py                  # Main application file
├── LICENSE
├── models.py               # SQLAlchemy models for User and FamilyMember
├── Procfile
├── README.md               
└── requirements.txt 

🧑‍💻 Installation & Setup
Clone the Repository

bash
CopyEdit
git clone https://github.com/Junate-World/family-website.git
cd family-website
Create Virtual Environment

bash
CopyEdit
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install Dependencies

bash
CopyEdit
pip install -r requirements.txt
If requirements.txt is missing, you can generate one:

bash
CopyEdit
pip freeze > requirements.txt
Run the App

bash
Copy Edit
python app.py
Visit http://localhost:5000 in your browser.

🧱 Models
User
id

username

password_hash

FamilyMember
id

full_name

dob / dod

biography

relationship

photo_url

parent_id (for hierarchy)

🔐 Authentication
/register: Create a new user

/login: Login page

/logout: Ends user session

Only authenticated users can add, edit, or delete family members.

🌳 Family Tree
The /family-tree route dynamically generates a JSON structure representing the family tree using the parent-child relationships stored in the database.

📌 Notes
All photos are uploaded to the static/uploads directory.

Passwords are securely hashed using Flask-Bcrypt.

Session management is handled via Flask-Login.

🧪 To Do / Improvements
Add pagination for large member lists

Implement admin roles

Export tree as image or PDF

Add search by name/date

Unit testing and CI/CD

📄 License
MIT License. Feel free to fork, improve, or adapt to your own family's needs.