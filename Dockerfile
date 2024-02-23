FROM python:3.9-bullseye

ARG VERSION
WORKDIR /app
COPY ./dist/kerberos_auth_proxy-$VERSION-py3-none-any.whl ./

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_ROOT_USER_ACTION=ignore \
    PIP_NO_CACHE_DIR=1

RUN pip3 install ./kerberos_auth_proxy-$VERSION-py3-none-any.whl

ENV MITM_TLS_CA_PEM=/etc/security/tls/ca.pem \
    MITM_TLS_CA_KEY=/etc/security/tls/ca.key \
    MITM_SET_CONFDIR=/etc/mitm \
    MITM_OPT_LISTEN_PORT=8081 \
    MITM_OPT_WEB_PORT=9047 \
    MITM_OPT_NO_WEB_OPEN_BROWSER=- \
    MITM_OPT_PROXYAUTH=any \
    MITM_SET_SSL_VERIFY_UPSTREAM_TRUSTED_CA=/etc/ssl/certs/ca-certificates.crt \
    MITM_SET_TERMLOG_VERBOSITY=debug \
    MITM_SET_KERBEROS_REALM=LOCALHOST \
    MITM_SET_KERBEROS_SPNEGO_CODES=401 \
    MITM_SET_KERBEROS_KNOX_URLS=http://localhost:8443/gateway/knoxsso/knoxauth \
    MITM_SET_KERBEROS_KNOX_CODES=302 \
    MITM_SET_KERBEROS_KNOX_USER_AGENT_OVERRIDE=curl/7 \
    MITM_SET_KERBEROS_KEYTABS_PATH=/etc/security/keytabs \
    MITM_SET_KERBEROS_CACHE_EXPIRATION=1m

COPY ./docker-entrypoint.sh /docker-entrypoint.sh
COPY ./docker-entrypoint-init.d/ /docker-entrypoint-init.d/

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "kerberos-auth-proxy" ]
