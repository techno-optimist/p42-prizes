FROM python:3.14-slim

WORKDIR /problem
COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir -r /tmp/requirements.lock
COPY . /problem
COPY ../../src /src
ENV PYTHONPATH=/src

ENTRYPOINT ["python", "verifier/verify.py"]
