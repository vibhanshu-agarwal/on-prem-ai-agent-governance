# One image, several entrypoints (selected by the compose `command`):
#   control-plane  uvicorn govcp.api.app:app
#   idp            uvicorn govcp.idp.app:app          (simulated corporate OIDC issuer)
#   authproxy      uvicorn govcp.authproxy.app:app    (JWT -> per-agent virtual key, in front of LiteLLM)
#   estop          uvicorn govcp.estop.app:app        (separate emergency-stop path)
#   cp-migrate     python -m govcp.migrate
# iproute2 + iptables are needed because this image is also the short-lived
# "quarantine helper" that joins an agent's network namespace to reset its
# established TCP connections (Docker stand-in for NetworkPolicy + conntrack flush).
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iptables \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY govcp ./govcp
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8100
CMD ["uvicorn", "govcp.api.app:app", "--host", "0.0.0.0", "--port", "8100"]
