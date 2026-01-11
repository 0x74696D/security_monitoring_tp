FROM python:3.9-slim

# Bad practice: install extra tools attackers love
RUN apt-get update && apt-get install -y curl netcat-traditional nmap && rm -rf /var/lib/apt/lists/*

# Bad practice: hardcoded secret
ENV DB_PASSWORD=SuperSecret123

WORKDIR /app
COPY app.py /app/app.py

# Simple HTTP server
RUN pip install flask

CMD ["python", "app.py"]
