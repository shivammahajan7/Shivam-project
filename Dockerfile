# Use the official PostgreSQL image
FROM postgres:13

# Set environment variables for PostgreSQL
ENV POSTGRES_DB=secure_file_system
ENV POSTGRES_USER=ruegen
ENV POSTGRES_PASSWORD=ruegen

# Expose the PostgreSQL port
EXPOSE 5432

# Copy initialization script
COPY init.sql /docker-entrypoint-initdb.d/
