# Recruiter-facing agent status page: tiny FastAPI backend (holds IdP tokens server-side) + static UI.
# It only talks HTTP to the control-plane API and the IdP token endpoint. No DB, no Docker socket.
FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER nobody
EXPOSE 8400
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8400", "--no-access-log"]
