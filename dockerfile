# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy only requirements first for caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
