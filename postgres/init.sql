--create the 'users' table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    totp_secret TEXT NOT NULL
);

-- Create the 'login_attempts' table
CREATE TABLE login_attempts (
    ip_address inet PRIMARY KEY,
    attempts integer,
    blocked_until timestamp without time zone
);

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    filename TEXT NOT NULL,
    file_url TEXT NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE file_tokens (
    id SERIAL PRIMARY KEY,
    token TEXT NOT NULL,
    file_id UUID REFERENCES files(id),
    expiration_date TIMESTAMP NOT NULL,
    password_hash TEXT NOT NULL
);
