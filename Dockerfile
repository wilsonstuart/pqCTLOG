# Development stage
FROM python:3.9-slim as development

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    REQUIREMENTS=requirements.txt

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements first to leverage Docker cache
COPY requirements*.txt .
COPY setup.py .
COPY pyproject.toml .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r ${REQUIREMENTS} && \
    pip install -e .

# Copy the rest of the application
COPY . .

# Create a non-root user and switch to it
RUN useradd -m appuser && \
    chown -R appuser:appuser /app
USER appuser

# Set the working directory to the app directory
WORKDIR /app/src

# Production stage
FROM python:3.9-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only the requirements first to leverage Docker cache
COPY requirements.txt .
COPY setup.py .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the rest of the application
COPY . .

# Install the package
RUN pip install .

# Create a non-root user and switch to it
RUN useradd -m appuser && \
    chown -R appuser:appuser /app
USER appuser

# Set the working directory to the app directory
WORKDIR /app/src

# Command to run the application
CMD ["python", "-m", "pqctlog"]
