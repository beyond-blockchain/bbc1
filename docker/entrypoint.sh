#!/bin/bash
# generate host keys if not present
ssh-keygen -A

# for ubuntu
if [ ! -e /var/run/sshd ]; then
  mkdir /var/run/sshd
fi

# do not detach (-D), log to stderr (-e), passthrough other arguments
/usr/sbin/sshd -D -e &

source /root/.pythonenv/bin/activate
if [ -e /root/bbc1 ]; then
  cd /root/bbc1/bbc1/core
  exec python bbc_core.py -w /root/.bbc1
else
  pip install bbc1
  exec bbc_core.py -w /root/.bbc1
fi
