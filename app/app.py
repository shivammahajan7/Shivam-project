from flask import Flask, render_template, session, redirect, url_for, request
from flask_session import Session
from user import register, login, logout
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message  # Import the Mail and Message classes
import os
import boto3
from botocore.exceptions import NoCredentialsError
import datetime
import psycopg2
from database import get_db_connection
import random
import string
import datetime
import hashlib
from database import get_db_connection
import uuid
import secrets

# Function to generate a random token (password)
def generate_token():
    token_length = 12
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(token_length))

# Function to store a token associated with a file in the file_tokens table
def store_token(file_id, token, password):
    expiration_date = datetime.datetime.now() + datetime.timedelta(days=1)  # Set the expiration time
#    password_hash = hashlib.sha256(password.encode()).hexdigest()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO file_tokens (token, file_id, expiration_date, password_hash)
            VALUES (%s, %s, %s, %s)
        ''', (token, file_id, expiration_date, password))
        conn.commit()

        
# Insert file information into the files table
def insert_file_info(filename, file_url):
    file_id = uuid.uuid4()  # Generate a new UUID for the file
    upload_date = datetime.datetime.now()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO files (id, filename, file_url, upload_date)
            VALUES (%s, %s, %s, %s)
        ''', (str(file_id), filename, file_url, upload_date))
        conn.commit()


def delete_file_record(filename):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM files WHERE filename = %s', (filename,))
        conn.commit()
def get_file_id_by_file_url(file_url):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM files WHERE file_url = %s', (file_url,))
        result = cursor.fetchone()
        if result:
            return result[0]  # Return the first column value (file_id)
        return None  # File not found
# Create a Flask app instance
app = Flask(__name__)

# Set a secret key to secure the session
app.secret_key = 'my_super_secret_key'  # Replace with your actual secret key

# AWS S3 Configuration
AWS_ACCESS_KEY = ''
AWS_SECRET_KEY = ''
AWS_REGION = 'us-east-1'
BUCKET_NAME = ''


# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Replace with your SMTP server
app.config['MAIL_PORT'] = 587  # Replace with the appropriate port
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = ''  # Replace with your email address
app.config['MAIL_PASSWORD'] = ''  # Replace with your email password or app-specific password

mail = Mail(app)  # Initialize the Flask-Mail extension

# Use Flask-Session to handle the session (note: this is a client-side session, not recommended for production)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configure the database URI for PostgreSQL
# Replace 'ruegen', 'ruegen', and 'postgres-container' with appropriate values
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://ruegen:ruegen@postgres-container/secure_file_system"

# Register routes from the 'user' module
app.add_url_rule('/register', view_func=register, methods=['GET', 'POST'])
app.add_url_rule('/login', view_func=login, methods=['GET', 'POST'])
app.add_url_rule('/logout', view_func=logout)

# Define a route for the dashboard page (set it as the default route)
@app.route('/')
def default():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Define a route for the dashboard page
@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Render the dashboard template
    return render_template('dashboard.html', username=session['username'])

@app.route('/manage-files', methods=['GET', 'POST'])
def manage_files():
    # Check if the user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Check if the request is for deleting a file
        delete_filename = request.form.get('delete_filename')
        if delete_filename:
            try:
                # Delete the file from S3
                s3 = boto3.client(
                    's3',
                    aws_access_key_id=AWS_ACCESS_KEY,
                    aws_secret_access_key=AWS_SECRET_KEY,
                    region_name=AWS_REGION
                )
                bucket_name = BUCKET_NAME
                s3.delete_object(Bucket=bucket_name, Key=delete_filename)
                
                # Delete the record from the database
                delete_file_record(delete_filename)
            except NoCredentialsError:
                return "AWS credentials not available"
    
        # Check if the request is for uploading a file
        uploaded_file = request.files.get('file')
        if uploaded_file and uploaded_file.filename != '':
            try:
                # Upload the file to S3
                s3 = boto3.client(
                    's3',
                    aws_access_key_id=AWS_ACCESS_KEY,
                    aws_secret_access_key=AWS_SECRET_KEY,
                    region_name=AWS_REGION
                )
                bucket_name = BUCKET_NAME
                filename = secure_filename(uploaded_file.filename)
                s3.upload_fileobj(uploaded_file, bucket_name, filename)
                
                # Get the S3 file URL
                file_url = s3.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': bucket_name, 'Key': filename},
                    ExpiresIn=3600  # Set the expiration time in seconds (e.g., 1 hour)
                )
                
                # Insert file information into the files table
                insert_file_info(filename, file_url)
                token = generate_token()
                file_id=get_file_id_by_file_url(file_url)
                password_length = 12  # You can adjust the length of the password
                password = secrets.token_urlsafe(password_length)
                store_token(file_id, token, password)
                
                # Redirect to the manage-files page
                return redirect(url_for('manage_files'))
            except NoCredentialsError:
                return "AWS credentials not available"
    
    # Retrieve user-specific file information from S3 and render the template
    s3 = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION
    )
    bucket_name = BUCKET_NAME
    my_files = []
    response = s3.list_objects(Bucket=bucket_name)
    if 'Contents' in response:
        for file_info in response['Contents']:
            file_name = file_info['Key']
            file_size = file_info['Size']
            upload_date = file_info['LastModified'].strftime('%Y-%m-%d %H:%M:%S')
            
            # Generate a pre-signed URL for downloading the file
            file_link = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': bucket_name, 'Key': file_name},
                ExpiresIn=3600  # Set the expiration time in seconds (e.g., 1 hour)
            )
            
            my_files.append({'filename': file_name, 'filesize': file_size, 'upload_date': upload_date, 'file_link': file_link})
    
    # Render the manage-files template and pass the file information
    return render_template('manage-files.html', username=session['username'], my_files=my_files)



@app.route('/send-files', methods=['GET', 'POST'])
def send_files():
    # Check if the user is logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        recipient = request.form['recipient']
        subject = request.form['subject']
        message = request.form['message']
        attachment_filename = request.form['attachment']

        # Create an email message
        msg = Message(subject=subject, sender='your_email@gmail.com', recipients=[recipient])
        msg.body = message

        if attachment_filename:
            # Retrieve the associated token and password from the database
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT token, password_hash FROM file_tokens
                    WHERE file_id = (SELECT id FROM files WHERE filename = %s)
                ''', (attachment_filename,))
                result = cursor.fetchone()
                if result:
                    token, password_hash = result

                    # Generate a pre-signed URL for the selected file in S3
                    s3 = boto3.client(
                        's3',
                        aws_access_key_id=AWS_ACCESS_KEY,
                        aws_secret_access_key=AWS_SECRET_KEY,
                        region_name=AWS_REGION
                    )
                    bucket_name = BUCKET_NAME

                    attachment_url = s3.generate_presigned_url(
                        'get_object',
                        Params={'Bucket': bucket_name, 'Key': attachment_filename},
                        ExpiresIn=3600  # Set the expiration time in seconds (e.g., 1 hour)
                    )

                    # Attach the file link, token, and password to the email
                    protected_url = f"http://localhost:5000/download?token={token}"
                    #msg.body += f'\n\nAttachment: {attachment_url}'
                    msg.body += f'\nURL for Download: {protected_url}'
                    msg.body += f'\nPassword: {password_hash}'

        try:
            # Send the email
            mail.send(msg)
            return render_template('send_files.html', username=session['username'], message_sent=True)
        except Exception as e:
            return render_template('send_files.html', username=session['username'], message_sent=False, error_message=str(e))

    # Retrieve user-specific file information from S3
    s3 = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION
    )
    bucket_name = BUCKET_NAME
    my_files = []
    response = s3.list_objects(Bucket=bucket_name)
    if 'Contents' in response:
        for file_info in response['Contents']:
            file_name = file_info['Key']
            my_files.append({'filename': file_name})

    return render_template('send_files.html', username=session['username'], my_files=my_files)


@app.route('/download', methods=['GET', 'POST'])
def download_page():
    if request.method == 'GET':
        token = request.args.get('token')
        session['stored_token'] = token

    if request.method == 'POST':
        stored_token = session.get('stored_token')
        entered_password = request.form.get('password')
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT file_id, password_hash FROM file_tokens WHERE token = %s
                ''', (stored_token,))
                
                result = cursor.fetchone()
                if result:
                    password = result[1]
                    file_id = result[0]
                    if entered_password == password:
                        # Retrieve the file URL based on the file_id
                        cursor.execute('''
                            SELECT file_url FROM files WHERE id = %s
                        ''', (file_id,))
                        
                        file_result = cursor.fetchone()
                        if file_result:
                            presigned_url = file_result[0]
                            return redirect(presigned_url)
                        else:
                            return "File not found."
                    else:
                        return "Invalid password."
                else:
                    return "Invalid token."
        except psycopg2.Error as e:
            print("Error:", e)
    
    protected_url = f"http://localhost:5000/download?token={token}"
    return render_template('download.html', protected_url=protected_url)



if __name__ == '__main__':
    app.run(debug=True)
