FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
WORKDIR /app
# No third-party dependencies: govagent is standard library only.
COPY govagent ./govagent
COPY samples ./samples
RUN useradd -r -u 10002 agent
USER agent
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 CMD ["python", "-m", "govagent.runtime"]
CMD ["python", "-m", "samples.hr_agent"]
