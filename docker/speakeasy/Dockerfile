# Vanguard Fort Knox Speakeasy image.
# Run ONLY via: docker run --network=none ... (enforced by the Rust runner).
#
# Build:
#   docker build -t vanguard-speakeasy:latest ./docker/speakeasy

FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Pin Speakeasy; rebuild when intentionally upgrading.
RUN pip install --no-cache-dir "speakeasy-emulator==1.5.11"

WORKDIR /opt/vanguard
COPY entrypoint.py /opt/vanguard/entrypoint.py
RUN chmod 555 /opt/vanguard/entrypoint.py

# Non-root in image metadata; runner also passes --user 65534:65534.
USER nobody

# Sample is bind-mounted at /work/sample.bin by the host runner.
ENTRYPOINT ["python", "/opt/vanguard/entrypoint.py"]
