FROM debian:trixie AS base-target

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install --yes --no-install-recommends \
    ca-certificates python3 tzdata systemd iproute2 ifupdown \
    curl git rsync jq unzip htop mtr-tiny tcpdump ccze \
    && mkdir -p /opt/rzandal-package-repo

WORKDIR /opt/rzandal-package-repo
RUN apt-get download ccze
COPY tests/integration/build_package_repo.py /tmp/build-package-repo.py
RUN python3 -I /tmp/build-package-repo.py && rm /tmp/build-package-repo.py \
    && dpkg --remove ccze && apt-get clean && rm -rf /var/lib/apt/lists/*

FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker

RUN apt-get update && apt-get install --yes --no-install-recommends \
    ca-certificates python3 systemd systemd-sysv dbus iproute2 ifupdown \
    openssh-server openssh-client sudo nftables iputils-ping util-linux mount \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=base-target / /opt/rzandal-base-template/

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
