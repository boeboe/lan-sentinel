# Debian with systemd as PID 1, for `make test-systemd`, once per target
# release (BASE). The reference files from deploy/ are installed unchanged.
ARG BASE=debian:bookworm-slim
FROM ${BASE}
# Debian 11 left LTS in August 2026; its security pool no longer serves the
# files its index lists, so bullseye installs from the snapshot archive of
# the image's own date (the snapshot lines its sources.list carries).
RUN if grep -q bullseye /etc/os-release; then \
      sed -i -e 's|^deb http://deb.debian.org|# deb http://deb.debian.org|' -e 's|^# deb http://snapshot|deb http://snapshot|' /etc/apt/sources.list \
      && echo 'Acquire::Check-Valid-Until "false";' >/etc/apt/apt.conf.d/99snapshot; fi \
    && apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus procps \
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
