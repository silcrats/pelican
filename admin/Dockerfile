FROM python:3.13-slim
WORKDIR /app
# Pinned with hashes; regenerate from requirements.in with pip-compile
# --generate-hashes after changing it.
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY admin_server.py store.py ldap_auth.py storage.py ./
COPY static ./static
# /data holds the portal's database; /export the YAML files it writes for
# Frogmouth and the mailbox permission export. Created here so new named
# volumes come up owned by the portal's user.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin pelican \
    && mkdir -p /data /export && chown pelican:pelican /data /export
# Shown on the page. Set by the publish workflow; a local build says "dev".
ARG VERSION=dev
ARG REVISION=
RUN printf '%s\n%s\n' "$VERSION" "$REVISION" > /app/version
USER pelican
EXPOSE 8091
ENTRYPOINT ["python", "-u", "admin_server.py"]
