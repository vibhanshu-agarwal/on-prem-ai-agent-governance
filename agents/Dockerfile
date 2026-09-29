FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
WORKDIR /app
# No third-party dependencies: govagent is standard library only.
COPY govagent ./govagent
COPY samples ./samples
# /var/lib/agent-journal: the durable run journal (govagent.events.JournalSink). Compose mounts a named volume
# here; a new named volume copies this directory's owner, so the non-root agent can write to it.
RUN useradd -r -u 10002 agent && mkdir -p /var/lib/agent-journal && chown agent /var/lib/agent-journal
USER agent
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 CMD ["python", "-m", "govagent.runtime"]
CMD ["python", "-m", "samples.hr_agent"]
