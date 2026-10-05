# Debian with systemd as PID 1, for `make test-systemd`. The reference files
# from deploy/ are installed unchanged.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus procps \
    && rm -rf /var/lib/apt/lists/* \
    && find /etc/systemd/system /lib/systemd/system -path '*.wants/*' \
       \( -name '*getty*' -o -name '*udev*' -o -name 'systemd-logind*' -o -name 'apt-*' \) -delete
COPY lan-sentinel capcheck /usr/local/bin/
COPY lan-sentinel.service /etc/systemd/system/lan-sentinel.service
COPY lan-sentinel.sysusers /etc/sysusers.d/lan-sentinel.conf
COPY lan-sentinel.tmpfiles /etc/tmpfiles.d/lan-sentinel.conf
COPY config.yaml /etc/lan-sentinel/config.yaml
RUN systemctl enable lan-sentinel.service
STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
