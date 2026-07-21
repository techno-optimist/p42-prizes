FROM python:3.14.2-slim@sha256:1a3c6dbfd2173971abba880c3cc2ec4643690901f6ad6742d0827bae6cefc925

# Build from the repository root:
# docker build -f problems/minimum-autocorrelation-lower-bound/Dockerfile .
COPY requirements.runtime.lock /repo/requirements.runtime.lock
RUN pip install --no-cache-dir --require-hashes -r /repo/requirements.runtime.lock
COPY src /repo/src
COPY problems/minimum-autocorrelation-lower-bound /repo/problems/minimum-autocorrelation-lower-bound
WORKDIR /repo/problems/minimum-autocorrelation-lower-bound
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
ENV PYTHONHASHSEED=0 \
    OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    PYTHONPATH=/repo/src

ENTRYPOINT ["python", "verifier/verify.py"]
