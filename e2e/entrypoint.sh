#!/bin/sh
# Authorise the keys handed in, start sshd, then bring up dev servers on a
# delay. The delay is the point: a service that was already listening when
# devtun connected and one that appears afterwards must both be forwarded, and
# only a delay tests the second.
set -eu

install -d -m 700 -o dev -g dev /home/dev/.ssh
printf '%s\n' "${AUTHORIZED_KEYS:-}" > /home/dev/.ssh/authorized_keys
chown dev:dev /home/dev/.ssh/authorized_keys
chmod 600 /home/dev/.ssh/authorized_keys

ssh-keygen -A
/usr/sbin/sshd

# Already listening before devtun connects.
su dev -c 'XDG_RUNTIME_DIR=/run/user/1000 python3 /usr/local/bin/devserver.py 8080 &' 

# Appear later, as a dev server started by hand would.
su dev -c '(sleep 5;  XDG_RUNTIME_DIR=/run/user/1000 python3 /usr/local/bin/devserver.py 3000) &'
su dev -c '(sleep 10; XDG_RUNTIME_DIR=/run/user/1000 python3 /usr/local/bin/devserver.py 5173) &'

# A privileged port, which must never be forwarded by default.
python3 /usr/local/bin/devserver.py 80 &

tail -f /dev/null
