# Discovery feeds -> control-plane pending queue. One image, one process (govdisc.runner).
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY govdisc ./govdisc
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-m", "govdisc"]
