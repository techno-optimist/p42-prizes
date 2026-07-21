FROM python:3.14.2-slim@sha256:1a3c6dbfd2173971abba880c3cc2ec4643690901f6ad6742d0827bae6cefc925

# Candidate-only local image. Build from the repository root:
# docker build -f problems/erdos-szekeres-n7/Dockerfile .
ENV PYTHONHASHSEED=0 \
    PYTHONPATH=/repo/src
COPY src /repo/src
COPY problems/erdos-szekeres-n7 /repo/problems/erdos-szekeres-n7
WORKDIR /repo/problems/erdos-szekeres-n7

ENTRYPOINT ["python3", "verifier/verify.py"]
