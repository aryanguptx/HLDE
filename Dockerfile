# Dockerfile for HLDE with Cron Setup
FROM python:3.11

# Set the working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install cron
RUN apt-get update && apt-get install -y cron

# Copy application files
COPY . /app

# Add the cron job
RUN echo "*/5 * * * * root python /app/main.py >> /app/logs/cron.log 2>&1" > /etc/cron.d/hlde-cron

# Set permissions for cron job
RUN chmod 0644 /etc/cron.d/hlde-cron

# Apply the cron job
RUN crontab /etc/cron.d/hlde-cron

# Create logs directory for cron logs
RUN mkdir -p /app/logs

# Run the cron daemon in the foreground
CMD ["cron", "-f"]
