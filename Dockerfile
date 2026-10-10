FROM php:8.3-fpm-bookworm
# sodium нужен защищённому каналу (протокол c1). В официальном образе он уже
# встроен, поэтому ниже он собирается только если его вдруг нет: вторая копия
# расширения дала бы «module already loaded» на каждом запросе.
ARG SUBMW_VERSION=dev
ENV SUBMW_DOCKER=1 SUBMW_VERSION=${SUBMW_VERSION}
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        nginx curl unzip libcurl4-openssl-dev libsqlite3-dev libonig-dev libxml2-dev python3 python3-yaml; \
    docker-php-ext-install -j"$(nproc)" pdo_sqlite pdo_mysql curl mbstring dom; \
    if ! php -m | grep -qi '^sodium$'; then \
        apt-get install -y --no-install-recommends libsodium-dev; \
        docker-php-ext-install -j"$(nproc)" sodium; \
    fi; \
    rm -rf /var/lib/apt/lists/*
# The pinned core is used only for isolated import checks; its YAML output is
# never connected to subscription delivery.
ARG TARGETARCH
RUN if [ "${TARGETARCH:-amd64}" = amd64 ]; then \
      curl -fsSL 'https://github.com/XTLS/Xray-core/releases/download/v26.9.9/Xray-linux-64.zip' -o /tmp/xray.zip; \
      echo '1eb9175d0f0a8f8149c9230a7fc5ae66ce332ed20a53155ce61fe62e3f58b7df  /tmp/xray.zip' | sha256sum -c -; \
      unzip -p /tmp/xray.zip xray > /usr/local/bin/xray; chmod 755 /usr/local/bin/xray; \
      rm /tmp/xray.zip; \
    fi
ENV GLOBALKEY_XRAY_BIN=/usr/local/bin/xray
COPY . /var/www/html
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN set -eux; \
    rm -rf /var/www/html/.git /var/www/html/.github /var/www/html/docker \
           /var/www/html/install.sh /var/www/html/Dockerfile /var/www/html/.dockerignore; \
    rm -f /etc/nginx/sites-enabled/default; \
    sed -i 's/^listen = .*/listen = 127.0.0.1:9000/' /usr/local/etc/php-fpm.d/zz-docker.conf; \
    { echo 'pm = ondemand'; echo 'pm.max_children = 8'; echo 'pm.process_idle_timeout = 10s'; echo 'pm.max_requests = 500'; } >> /usr/local/etc/php-fpm.d/zz-docker.conf; \
    mkdir -p /var/www/html/data; \
    chown -R www-data:www-data /var/www/html; \
    chmod +x /entrypoint.sh
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD php -r '$c=@fsockopen("127.0.0.1",9000,$e,$s,2); exit($c?0:1);' || exit 1
ENTRYPOINT ["/entrypoint.sh"]
