FROM python:3.11-slim

WORKDIR /app

# Copy code and dependencies
COPY main.py .
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Optionally copy model (or mount as volume)
COPY runs ./runs

# Run Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8009"]
