FROM python:3.14-slim

WORKDIR /problem
COPY . /problem
COPY ../../src /src
ENV PYTHONPATH=/src

ENTRYPOINT ["python", "verifier/verify.py"]
