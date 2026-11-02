FROM python:3.13-slim
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV TZ=Etc/UTC
ENV PYTHONUNBUFFERED=1

ENV WEBMONITORING_HOME=/monitoring
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV POETRY_NO_INTERACTION=1
ENV PATH="/monitoring/.venv/bin:$PATH"

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN pip3 install --no-cache-dir poetry

WORKDIR /monitoring

# Install the dependencies first so they are cached between code changes
COPY pyproject.toml poetry.lock README.md LICENSE ./
RUN poetry install --only main --no-root

COPY webmonitoring webmonitoring/
COPY tools tools/
COPY bin bin/
COPY website website/
COPY config config/
COPY cache cache/

RUN mkdir -p logs
RUN poetry install --only main
RUN python tools/3rdparty.py
RUN python tools/generate_sri.py

EXPOSE 5200

# `start` launches the managers in the background and returns, so keep the
# container alive and shut the managers down cleanly when it is stopped.
CMD ["/bin/sh", "-c", "start || exit 1; trap 'shutdown; exit 0' TERM INT; sleep infinity & wait $!"]
