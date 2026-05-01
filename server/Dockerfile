FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

# Install Python deps + pre-download the spaCy model used by mem0's
# fact-extraction + lemmatization pipelines. Without the [nlp] extra
# every request that hits get_nlp_full() / get_nlp_lemma() emits a
# WARNI and falls back to a degraded path; baking the model into the
# image avoids a runtime download (which is brittle in air-gapped
# envs and blocks first-request latency).
RUN pip install --no-cache-dir -r requirements.txt \
 && python -m spacy download en_core_web_sm

COPY . .

EXPOSE 8000

ENV PYTHONUNBUFFERED=1

# Production CMD — single uvicorn worker, no --reload.
#
# `--reload` is uvicorn's StatReload watcher: it polls every file under
# /app once a second and respawns the worker on any change. In a
# container that's wrong on three counts:
#   1. Wastes CPU polling a read-only filesystem.
#   2. Drops in-flight requests every time a tmpfile / log / pyc is
#      written next to the source.
#   3. PID 1 becomes the watcher — SIGTERM hits the reloader instead
#      of cleanly draining the worker.
#
# Use server/dev.Dockerfile (with the bind-mounted source volume) for
# the iterate-locally workflow. server/docker-compose.yaml already
# wires that up.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
