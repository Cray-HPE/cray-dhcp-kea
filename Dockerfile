# Pinned to alpine:3.13 because alpine:3.14+ requires Docker 20.10.0 or newer,
# see https://wiki.alpinelinux.org/wiki/Release_Notes_for_Alpine_3.14.0
FROM artifactory.algol60.net/csm-docker/stable/docker.io/library/alpine:3 as builder

ARG KEA_DHCP_VERSION=2.3.1
ARG LOG4_CPLUS_VERSION=2.0.6

RUN curl -sL https://sourceforge.net/projects/log4cplus/files/log4cplus-stable/${LOG4_CPLUS_VERSION}/log4cplus-${LOG4_CPLUS_VERSION}.tar.gz | tar -zx -C /tmp && \
RUN curl -sL https://ftp.isc.org/isc/kea/${KEA_DHCP_VERSION}/kea-${KEA_DHCP_VERSION}.tar.gz

RUN apk add --no-cache --virtual .build-deps \
        alpine-sdk \
        bash \
        boost-dev \
        bzip2-dev \
        file \
        openssl-dev \
        postgresql-dev \
        zlib-dev && \
    curl -sL https://sourceforge.net/projects/log4cplus/files/log4cplus-stable/${LOG4_CPLUS_VERSION}/log4cplus-${LOG4_CPLUS_VERSION}.tar.gz | tar -zx -C /tmp && \
    cd /tmp/log4cplus-${LOG4_CPLUS_VERSION} && \
    ./configure && \
    make -s -j$(nproc) && \
    make install && \
    curl -sL https://ftp.isc.org/isc/kea/${KEA_DHCP_VERSION}/kea-${KEA_DHCP_VERSION}.tar.gz | tar -zx -C /tmp && \
    cd /tmp/kea-${KEA_DHCP_VERSION} && \
    ./configure \
        --enable-shell \
        --enable-perfdhcp \
        --with-pgsql=/usr/bin/pg_config && \
    make -s -j$(nproc) && \
    make install-strip && \
    apk del --purge .build-deps && \
    rm -rf /tmp/*

FROM artifactory.algol60.net/csm-docker/stable/docker.io/library/alpine:3


RUN apk --no-cache add \
        bash \
        boost \
        bzip2 \
        openssl \
        postgresql-dev \
        postgresql-client \
        zlib \
        py-pip \
        curl \
        jq \
        tcpdump \
        python3 \
        py3-pip &&\
        pip3 install requests ipaddress nslookup kea-exporter hvac redfish python-ipmi manuf pyyaml


COPY --from=builder /usr/local /usr/local/


RUN addgroup -S kea && adduser -S kea -G kea

ENV DHCP_HELPER_DEBUG=false
ENV DHCP_HELPER_INTERVAL_SECONDS=180

RUN mkdir -p /srv/kea && \
    mkdir /cray-dhcp-kea-socket && \
    mkdir -p /usr/local/kea && \
    mkdir -p /usr/local/var/run/kea

RUN chown -R kea /srv/kea && \
    chown -R kea /usr/local/kea && \
    chown -R kea /cray-dhcp-kea-socket && \
    chown -R kea /usr/local/var/run/kea

COPY kubernetes/cray-dhcp-kea/files/* /srv/kea/

RUN chmod +x /srv/kea/startup-dhcp.sh && \
    chmod +x /srv/kea/startup-dhcp-ctrl-agent.sh

EXPOSE 6067/udp
EXPOSE 6067/tcp
EXPOSE 6068/udp
EXPOSE 6068/tcp
EXPOSE 8000/tcp
EXPOSE 9091/tcp

USER kea
