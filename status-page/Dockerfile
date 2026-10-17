FROM python:3.13-slim
WORKDIR /app
COPY status_server.py .
# Same UID as the crawler image, which writes the shared /status volume.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin pelican \
    && mkdir -p /status && chown pelican:pelican /status
# Shown on the page. Set by the publish workflow; a local build says "dev".
ARG VERSION=dev
ARG REVISION=
RUN printf '%s\n%s\n' "$VERSION" "$REVISION" > /app/version
USER pelican
ENTRYPOINT ["python", "-u", "status_server.py"]
