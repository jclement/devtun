# A dev box that behaves like a real one: sshd, an unprivileged user, and dev
# servers that appear on a delay so tunnels can be watched arriving rather than
# being present from the start.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server openssh-client python3 iproute2 lsof net-tools ca-certificates zsh \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd

# An ordinary user with an XDG runtime dir, because that is where the control
# socket belongs and a test that runs as root would never exercise it.
RUN useradd -m -s /bin/bash dev \
 && mkdir -p /run/user/1000 && chown dev:dev /run/user/1000 && chmod 700 /run/user/1000

# StreamLocalForwarding is the default, but a test that depends on it should
# say so rather than inherit it.
RUN printf 'AllowTcpForwarding yes\nAllowStreamLocalForwarding yes\nPermitRootLogin no\nPasswordAuthentication no\n' \
      >> /etc/ssh/sshd_config

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY devserver.py  /usr/local/bin/devserver.py
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
