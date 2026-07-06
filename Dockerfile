# Use a lightweight official Python image
FROM python:3.10-slim

# Install basic network diagnostics tools for debugging purposes
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy dependency list and install required Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source code and the PCAP file
COPY analyzer.py .
COPY sample.pcap .

# Define the default command to execute the script
CMD ["python", "analyzer.py"]
