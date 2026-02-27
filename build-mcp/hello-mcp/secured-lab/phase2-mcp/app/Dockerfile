FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py /app/main.py

EXPOSE 7000

# Run with uvicorn using the ASGI app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7000"]
