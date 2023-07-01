FROM debian:buster

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gettext-base \
        krb5-kdc \
        krb5-user \
        krb5-admin-server && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /var/log/kerberos
WORKDIR /var/kerberos/krb5kdc
WORKDIR /etc/krb5kdc
WORKDIR /var/lib/krb5kdc
WORKDIR /etc/kdc
EXPOSE 88

ENV USER_UID=1 \
    USER_GID=1 \
    KRB5_CONFIG=/etc/krb5.conf \
    KRB5_CONFIG_TEMPLATE=/etc/krb5.conf.template \
    KDC_MASTER_PASSWORD=password \
    KEYTABS_PATH=/etc/security/keytabs

COPY ./bin/ /bin/
COPY ./docker-entrypoint.sh /docker-entrypoint.sh
COPY ./docker-entrypoint-init.d/*.sh /docker-entrypoint-init.d/
COPY ./krb5.conf.template /etc/krb5.conf.template

ENTRYPOINT [ "/docker-entrypoint.sh" ]
CMD [ "/usr/sbin/krb5kdc", "-n" ]
