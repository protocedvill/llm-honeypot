FROM python:3.12-slim

WORKDIR /srv/app

COPY pyproject.toml ./
COPY app ./app

RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 1000 honeypot \
    && mkdir -p /srv/app/data \
    && chown -R honeypot:honeypot /srv/app
USER honeypot

EXPOSE 8000
EXPOSE 8001

CMD ["python", "-m", "app.run"]
