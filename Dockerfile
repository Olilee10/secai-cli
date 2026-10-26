# syntax=docker/dockerfile:1
#
# SecAI CLI container image.
#
#   docker build -t secai-cli .
#   docker run --rm -e DEEPSEEK_API_KEY=sk-xxx secai-cli cve CVE-2024-1234
#   docker run --rm secai-cli analyze-log /data/access.log --dry-run
#
FROM python:3.13-slim

LABEL org.opencontainers.image.title="secai-cli" \
      org.opencontainers.image.description="AI-powered cybersecurity assistant (DeepSeek)" \
      org.opencontainers.image.source="https://github.com/Olilee10/secai-cli"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SECAI_NO_COLOR=1

WORKDIR /app

# Install dependencies first, then copy the source so the dependency layer stays cached
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY secai.py ./
COPY secai/ ./secai/
COPY samples/ ./samples/

# Run as a non-root user: a scanning tool should never have more privileges than it needs
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin secai \
    && chown -R secai:secai /app
USER secai

HEALTHCHECK --interval=5m --timeout=10s CMD ["python", "secai.py", "--version"]

# Prints the help by default; append a command after the image name to use it
ENTRYPOINT ["python", "secai.py"]
CMD ["--help"]
CMD ["--help"]
