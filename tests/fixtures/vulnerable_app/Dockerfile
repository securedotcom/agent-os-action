# Vulnerable Dockerfile for testing Trivy/Checkov
# Contains intentional security issues for testing purposes

# Vulnerable: Using root user
FROM ubuntu:18.04

# Vulnerable: Outdated base image with known CVEs
# Trivy should detect CVE-2021-44228 (Log4Shell) and others

# Hardcoded secrets (TruffleHog should detect)
ENV DATABASE_PASSWORD="SuperSecretP@ssw0rd123"
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Vulnerable: Running as root (Checkov CKV_DOCKER_3)
USER root

# Vulnerable: Using latest tag (Checkov)
FROM python:latest

WORKDIR /app

# Vulnerable: pip install without pinned versions (Checkov)
RUN pip install flask requests

# Vulnerable: Exposing SSH port (Checkov CKV_DOCKER_1)
EXPOSE 22

# Vulnerable: Using ADD instead of COPY (Checkov CKV_DOCKER_2)
ADD . /app

# Vulnerable: Not using non-root user (Checkov CKV_DOCKER_3)
# USER nobody

# Vulnerable: HEALTHCHECK missing (Checkov CKV_DOCKER_4)
# HEALTHCHECK CMD curl --fail http://localhost:5000/health || exit 1

# Vulnerable: Package manager cache not cleaned (Checkov)
RUN apt-get update && apt-get install -y curl wget

CMD ["python", "app.py"]
