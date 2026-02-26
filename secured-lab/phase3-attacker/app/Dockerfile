FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_hound.py /app/mcp_hound.py

# Keep container alive for exec usage
CMD ["sh", "-lc", "sleep infinity"]
