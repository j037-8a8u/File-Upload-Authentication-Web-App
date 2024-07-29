import os
import random
import string
from flask import Flask, request, redirect, render_template, session, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import boto3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['AWS_S3_BUCKET'] = 'your_bucket_name'
app.config['AWS_ACCESS_KEY_ID'] = 'aws_access_key'
app.config['AWS_SECRET_ACCESS_KEY'] = 'aws_secret_key'
app.config['AWS_REGION'] = 'aws_region'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

s3 = boto3.client(
    's3',
    region_name=app.config['AWS_REGION'],
    aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
    aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY']
)

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    otp_secret = db.Column(db.String(20), nullable=True)  # Store OTP secret

    def __repr__(self):
        return f'<User {self.username}>'

    # Flask-Login requires these methods
    def is_active(self):
        # Return True to indicate that the user is active
        return True

    def is_authenticated(self):
        # Return True to indicate that the user is authenticated
        return True

    def is_anonymous(self):
        # Return False to indicate that the user is not anonymous
        return False

    def get_id(self):
        # Return the user ID as a string
        return str(self.id)

# UploadedFile model
class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('files', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/users')
@login_required
def list_users():
    users = User.query.all()
    return render_template('list_users.html', users=users)




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        otp_secret = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))  # Random secret
        new_user = User(username=username, password=password, otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/mfa')  # Redirect to MFA page
        return 'Invalid credentials'
    return render_template('login.html')



@app.route('/mfa', methods=['GET', 'POST'])
@login_required
def mfa():
    if request.method == 'POST':
        otp = request.form['otp']
        if otp == session.get('otp'):
            return redirect('/')
        return 'Invalid OTP'
    
    # Generate OTP
    otp = ''.join(random.choices(string.digits, k=6))
    session['otp'] = otp

    return render_template('mfa.html', otp=otp)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')



@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            s3.upload_fileobj(
                file,
                app.config['AWS_S3_BUCKET'],
                filename,
                ExtraArgs={"ServerSideEncryption": "AES256"}
            )

            new_file = UploadedFile(filename=filename, user=current_user)
            db.session.add(new_file)
            db.session.commit()

            return render_template('upload.html', filename=filename)
    return render_template('upload.html')



@app.route('/list_files')
@login_required
def list_files():
    files = UploadedFile.query.filter_by(user=current_user).all()
    return render_template('list_files.html', files=[file.filename for file in files])



@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file = UploadedFile.query.filter_by(filename=filename, user=current_user).first()
    if file:
        try:
            s3_url = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': app.config['AWS_S3_BUCKET'], 'Key': filename},
                ExpiresIn=3600
            )
            return redirect(s3_url)
        except Exception as e:
            print(e)
            abort(404)
    else:
        abort(404)




@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    file = UploadedFile.query.filter_by(filename=filename, user=current_user).first()
    if file:
        try:
            # Delete the file from S3
            s3.delete_object(Bucket=app.config['AWS_S3_BUCKET'], Key=filename)
            
            # Remove file reference from the database
            db.session.delete(file)
            db.session.commit()

            return redirect(url_for('list_files'))
        except Exception as e:
            print(e)
            abort(404)
    else:
        abort(404)




if __name__ == "__main__":
    app.run(debug=True)
