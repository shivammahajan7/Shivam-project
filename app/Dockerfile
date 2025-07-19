# Use an official Python runtime as a parent image
FROM python:3.7

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install PostgreSQL development dependencies and build tools
RUN apt-get update && \
    apt-get install -y libpq-dev gcc

# Install required packages
RUN pip install --no-cache-dir \
    Flask==2.2.5 \
    Flask-Session==0.5.0 \
    Flask-Mail==0.9.1 \
    psycopg2==2.8.6 \
    bcrypt==4.0.1 \
    pyotp==2.9.0 \
    pyqrcode==1.2.1 \
    pypng==0.20220715.0 \
    boto3==1.28.27

# Expose the port the app runs on
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=app.py

# Run the application
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
