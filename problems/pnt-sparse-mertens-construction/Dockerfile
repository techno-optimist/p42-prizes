FROM python:3.14-slim

WORKDIR /problem
COPY . /problem
COPY ../../src /src
RUN pip install --no-cache-dir -r requirements.lock
ENV PYTHONPATH=/src

ENTRYPOINT ["python", "verifier/verify.py"]
