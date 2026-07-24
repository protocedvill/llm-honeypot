FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc musl-tools binutils upx-ucl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/app

COPY pyproject.toml ./
COPY app ./app

RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 1000 honeypot \
    && mkdir -p /srv/app/data/diag-cache \
    && chown -R honeypot:honeypot /srv/app
USER honeypot

EXPOSE 8000
EXPOSE 8001

CMD ["python", "-m", "app.run"]
