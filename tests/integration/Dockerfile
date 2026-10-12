FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update && apt-get install --yes --no-install-recommends \
    ca-certificates python3 systemd systemd-sysv dbus iproute2 ifupdown \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
