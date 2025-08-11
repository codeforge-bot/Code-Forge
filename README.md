Code Forge - College Club Management Platform
Code Forge is a comprehensive web application designed to manage the activities of a college coding and innovation club. It provides a centralized platform for students, mentors, and administrators to organize events, collaborate on ideas, and track progress seamlessly.

✨ Key Features
Role-Based Access Control:

Student: Can register for events, submit work in stages, participate in brainstorming rooms, and view their profile.

Mentor: Can view all events, oversee progress, and participate in brainstorming rooms to guide students.

Admin: Has full control to create and manage events, view all users, track participant progress, and announce winners.

Complete Event Management:

Admins can create multi-stage events (like hackathons) with distinct deadlines.

Event pages display detailed descriptions, dates, and registration status.

Students can register for events and track their registered events in a dedicated dashboard.

Multi-Stage Submission System:

Students can submit text and upload files (.pdf, .ppt, .docx, etc.) for each stage of an event.

Submissions are securely uploaded to Cloudinary.

Admins and mentors can view submission progress for all participants.

Real-Time Collaborative Brainstorming:

Students and mentors can create and join real-time "brainstorm rooms."

Features a live chat powered by Flask-SocketIO.

Users can share files within the room, which are stored securely.

Secure Authentication & Profile Management:

Secure password hashing and session management.

Students can update their personal and academic information through a dedicated profile page.

OTP-based email verification for non-college email registrations.

Automated welcome emails upon successful registration.

🛠️ Technology Stack
Backend: Flask (Python)

Database: PostgreSQL

Real-Time Communication: Flask-SocketIO with Eventlet

Frontend: Tailwind CSS, Jinja2 Templating, JavaScript

Cloud Services: Cloudinary for file and image hosting

Email: smtplib for sending OTP and welcome emails

🚀 Getting Started
Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

Prerequisites
Python 3.8+

PostgreSQL database server

A Cloudinary account (for file uploads)

A Gmail account (for sending emails, preferably with an "App Password")

1. Clone the Repository
git clone [https://github.com/your-username/code-forge.git](https://github.com/your-username/code-forge.git)
cd code-forge

2. Set Up a Virtual Environment
It's highly recommended to use a virtual environment to manage project dependencies.

# For Windows
python -m venv venv
venv\Scripts\activate

# For macOS/Linux
python3 -m venv venv
source venv/bin/activate

3. Install Dependencies
Install all the required Python packages using pip.

pip install -r requirements.txt

4. Configure Environment Variables
Create a file named .env in the root directory of the project and add the following variables. Replace the placeholder values with your actual credentials.

# PostgreSQL Database URL
DATABASE_URL="postgresql://USERNAME:PASSWORD@HOST:PORT/DATABASE_NAME"

# Flask Secret Key (generate a random string)
FLASK_SECRET_KEY="your_super_secret_key"

# Cloudinary Credentials
CLOUD_NAME="your_cloud_name"
API_KEY="your_api_key"
API_SECRET="your_api_secret"

# Gmail Credentials for sending emails
EMAIL_USER="your_email@gmail.com"
EMAIL_PASS="your_gmail_app_password" 

5. Set Up the Database
Make sure your PostgreSQL server is running.

Create a new database (e.g., codeforge_db).

Execute the schema.sql file provided in the repository to create all the necessary tables.

psql -U your_username -d your_database_name -f schema.sql

6. Create an Admin User
To access the admin dashboard, you need to create an admin user manually.

Generate a Hashed Password:
Run the hash_password.py script to securely hash your desired admin password.

python hash_password.py

Copy the generated hash.

Insert the Admin User:
Connect to your PostgreSQL database and run the following SQL command, replacing the username and hashed password.

INSERT INTO admin (username, password) VALUES ('admin', 'paste_your_hashed_password_here');

7. Run the Application
You can now start the Flask application.

python app.py

The application will be running at http://127.0.0.1:5000.

🤝 Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are greatly appreciated.

Fork the Project

Create your Feature Branch (git checkout -b feature/AmazingFeature)

Commit your Changes (git commit -m 'Add some AmazingFeature')

Push to the Branch (git push origin feature/AmazingFeature)re

Open a Pull Request

📄 License
This project is licensed under the MIT License - see the `LICENSE
