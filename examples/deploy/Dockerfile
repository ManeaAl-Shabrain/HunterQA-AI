ARG PYTHON_IMAGE=python:3.13-slim-bookworm
FROM ${PYTHON_IMAGE}
ARG HUNTERQA_UID=10001
ARG HUNTERQA_GID=10001
ARG HUNTERQA_RUNTIME_PREFIX=/opt/hunterqa-runtime
ENV HUNTERQA_RUNTIME_PREFIX=${HUNTERQA_RUNTIME_PREFIX} \
    PATH=${HUNTERQA_RUNTIME_PREFIX}/bin:${PATH} \
    PLAYWRIGHT_BROWSERS_PATH=${HUNTERQA_RUNTIME_PREFIX}/browsers \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 HOME=/nonexistent
COPY . /opt/hunterqa-build
RUN sh /opt/hunterqa-build/tools/install_linux_runtime.sh --system-deps "$HUNTERQA_RUNTIME_PREFIX"
RUN groupadd --gid "$HUNTERQA_GID" hunterqa && useradd --uid "$HUNTERQA_UID" --gid "$HUNTERQA_GID" --no-create-home --home-dir /nonexistent hunterqa
COPY examples/deploy/container-entrypoint.sh /usr/local/bin/hunterqa-runtime
COPY examples/deploy/container-health.sh /usr/local/bin/hunterqa-health
RUN chmod 755 /usr/local/bin/hunterqa-runtime /usr/local/bin/hunterqa-health
USER ${HUNTERQA_UID}:${HUNTERQA_GID}
ENTRYPOINT ["/usr/local/bin/hunterqa-runtime"]
CMD ["--help"]
