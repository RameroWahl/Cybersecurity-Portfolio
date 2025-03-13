# Use an official Python image
FROM python:3.13

# Set working directory
WORKDIR /app

# Copy project files into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the API port
EXPOSE 5000

# Command to run the API
CMD ["python", "forensic_api.py"]
