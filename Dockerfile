# ── Stage 1 : dépendances Composer ──────────────────────────────────────────
FROM composer:2.8 AS vendor

WORKDIR /app
COPY composer.json composer.lock symfony.lock* ./
RUN composer install \
    --no-dev \
    --no-scripts \
    --no-autoloader \
    --ignore-platform-reqs \
    --prefer-dist

COPY . .
RUN composer dump-autoload --optimize --no-dev

# ── Stage 2 : image runtime ───────────────────────────────────────────────────
FROM php:8.4-fpm-alpine AS app

LABEL maintainer="CyberSafe Solutions <dev@cybersafe.fr>"

# Dépendances système + extensions PHP
RUN apk add --no-cache \
        bash \
        git \
        unzip \
        curl \
        libzip-dev \
        icu-dev \
        oniguruma-dev \
        libxml2-dev \
        mysql-client \
        nodejs \
        npm \
        python3 \
        py3-pip \
    && apk add --no-cache --virtual .build-deps \
        autoconf \
        g++ \
        make \
    && docker-php-ext-install \
        pdo \
        pdo_mysql \
        mysqli \
        zip \
        intl \
        opcache \
        mbstring \
        xml \
    && pecl install apcu \
    && docker-php-ext-enable apcu \
    && apk del .build-deps


# Copier Composer depuis l'image officielle
COPY --from=composer:2.8 /usr/bin/composer /usr/bin/composer
# ── Semgrep (SAST) ────────────────────────────────────────────────────────────
RUN pip3 install semgrep --break-system-packages

# ── TruffleHog (secrets) ──────────────────────────────────────────────────────
RUN curl -sSfL \
    https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# Config PHP
COPY docker/php/php.ini     /usr/local/etc/php/conf.d/securescan.ini
COPY docker/php/opcache.ini /usr/local/etc/php/conf.d/opcache.ini

WORKDIR /var/www/html

COPY --from=vendor /app/vendor ./vendor
COPY . .

# AssetMapper
RUN php bin/console importmap:install --no-interaction || true

# Permissions
RUN mkdir -p var/cache var/log var/uploads \
    && chown -R www-data:www-data var \
    && chmod -R 775 var

EXPOSE 9000
CMD ["php-fpm"]
