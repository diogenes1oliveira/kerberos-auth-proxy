FROM python:3.9-bullseye

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_ROOT_USER_ACTION=ignore \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get install -y krb5-user && \
    rm -rf /var/lib/apt/lists/*

COPY ./requirements.txt ./
RUN pip3 install -r ./requirements.txt

ARG VERSION
COPY ./dist/kerberos_auth_proxy-$VERSION-py3-none-any.whl ./
RUN pip3 install ./kerberos_auth_proxy-$VERSION-py3-none-any.whl

COPY ./docker-entrypoint.sh /docker-entrypoint.sh
COPY ./docker-entrypoint-init.d/ /docker-entrypoint-init.d/

WORKDIR /app
COPY ./config.yaml ./

# libkrb5 settings
ENV KRB5_CONFIG=/etc/krb5.conf \
    KRB5CCNAME=DIR:/var/kerberos/cache

# kerberos-auth-proxy app settings
ENV KEYTABS_PATH=/etc/security/keytabs/ \
    KERBEROS_REALM=LOCALHOST \
    MITM_TLS_CA_CRT=/etc/security/tls/ca.crt \
    MITM_TLS_CA_KEY=/etc/security/tls/ca.key \
    CONFIG_FILE=/app/config.yaml

# MITM args and options
ENV MITM_SET_SSL_VERIFY_UPSTREAM_TRUSTED_CA=/etc/ssl/ca-bundle.pem \
    MITM_SET_TERMLOG_VERBOSITY=debug \
    MITM_SET_CONFDIR=/app/mitm \
    MITM_OPT_LISTEN_PORT=8081 \
    MITM_OPT_PROXYAUTH=@/etc/security/htpasswd

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "kerberos-auth-proxy", "mitmdump" ]
