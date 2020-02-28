from centos:7

RUN yum install -y epel-release && \
  curl -1sLf 'https://dl.cloudsmith.io/public/isc/kea-1-6/cfg/setup/bash.rpm.sh'| bash && \
  yum install -y isc-kea isc-kea-devel isc-kea-libs isc-kea-hooks net-tools iproute && \
  yum clean all

EXPOSE 67/udp
EXPOSE 67/tcp
EXPOSE 68/udp
EXPOSE 68/tcp

COPY startup.sh /
ENTRYPOINT ["sh", "-c", "/startup.sh"]

#CMD ["tail -f"]
