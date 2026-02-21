# NoEyes - Secure Terminal Chat (server)
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir cryptography

COPY config.py encryption.py server.py utils.py ./
# Optional: copy noeyes.py to run as noeyes --server
COPY noeyes.py ./

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

# Run server on port 5000; override with docker run -e PORT=...
CMD ["python", "-c", "from server import run_server; from encryption import build_fernet; import os; run_server(port=int(os.environ.get('PORT', 5000)), fernet=build_fernet(os.environ.get('NOEYES_PASSPHRASE', 'change-me')))"]
