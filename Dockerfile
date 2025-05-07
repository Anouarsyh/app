FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p reports/incidents reports/exports

# Create empty config file with initial structure
RUN echo '{"username": "", "password": "", "server": "", "port": ""}' > config.json

# Expose port for Streamlit
EXPOSE 8501

# Run the application
CMD ["streamlit", "run", "streamlit.txt", "--server.port=8501", "--server.address=0.0.0.0"]
