# Use an Ubuntu base image
FROM ubuntu:latest

# Set the working directory
WORKDIR /app

# Install Python, cron, rsync, and any dependencies
RUN apt-get update && \
    apt-get install -y python3 python3-pip cron rsync && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the application files
COPY . /app

# Create a cron job to run main.py every 1 minute
RUN echo "* * * * * python3 /app/main.py >> /app/Data/Logs/cron.log 2>&1" > /etc/cron.d/hlde-cron

# Set permissions for the cron job file
RUN chmod 0644 /etc/cron.d/hlde-cron

# Apply the cron job
RUN crontab /etc/cron.d/hlde-cron

# Create a directory for logs
RUN mkdir -p /app/logs

# Run the cron daemon in the foreground
CMD ["cron", "-f"]