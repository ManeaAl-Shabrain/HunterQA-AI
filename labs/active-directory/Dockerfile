FROM python:3.13-slim-bookworm
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends samba samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind openssl util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin hunterqa-lab-reader
COPY . /opt/hunterqa-source
RUN python -m pip install --no-cache-dir '/opt/hunterqa-source[directory,identity]'
WORKDIR /opt/hunterqa-source
CMD ["python", "tools/verify_ad_lab.py"]
