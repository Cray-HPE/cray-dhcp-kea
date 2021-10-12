FROM arti.dev.cray.com/baseos-docker-master-local/alpine:3.13.5 as builder

ARG KEA_DHCP_VERSION=1.8.2
ARG LOG4_CPLUS_VERSION=2.0.6

RUN apk add --no-cache --virtual .build-deps \
        alpine-sdk \
        bash \
        boost-dev \
        bzip2-dev \
        file \
        libressl-dev \
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

FROM arti.dev.cray.com/baseos-docker-master-local/alpine:3.13.5


RUN apk --no-cache add \
        bash \
        boost \
        bzip2 \
        libressl \
        postgresql-dev \
        postgresql-client \
        zlib \
        py-pip \
        curl \
        jq \
        tcpdump \
        python3 &&\
        pip3 install requests ipaddress nslookup kea-exporter

COPY --from=builder /usr/local /usr/local/

EXPOSE 67/udp
EXPOSE 67/tcp
EXPOSE 68/udp
EXPOSE 68/tcp
EXPOSE 8000/tcp
EXPOSE 9091/tcp

ENV DHCP_HELPER_DEBUG=false
ENV DHCP_HELPER_INTERVAL_SECONDS=180

# startup script for kea server
COPY startup-dhcp.sh /
# startup script for kea ctrl agent(api server)
COPY startup-dhcp-ctrl-agent.sh /
# copy network cidr script
COPY get_network_cidr.py /
# startup config for kea server
COPY startup-config-dhcp4.conf /

USER kea