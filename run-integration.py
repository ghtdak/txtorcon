#!/usr/bin/env python

import atexit
import functools
import subprocess
import json
import time
import sys
from xml.dom import minidom

container = subprocess.check_output(['docker', 'run', '-d', 'txtorcon-tester'
                                    ]).strip()
print 'container:', container


def kill_container(container):
    print "killing", container
    subprocess.check_output(['docker', 'kill', container])


atexit.register(functools.partial(kill_container, container))

data = subprocess.check_output(['docker', 'inspect', container])
data = json.loads(data)[0]

ip = data['NetworkSettings']['IPAddress']
print "ip address", ip

print "awaiting launch",
while True:
    sys.stdout.write('.')
    sys.stdout.flush()
    logs = subprocess.check_output(['docker', 'logs', container])
    if 'liftoff' in logs:
        break
    time.sleep(1)
    continue

print "running nmap (scanning all 65535 TCP ports)..."
fname = 'txtorcon-nmap'
#print subprocess.check_output(['nmap', '-T5', '-PN', ip])
nmap = subprocess.check_output(['nmap', '-T5', '-p', '1-65535', '-oX', fname,
                                '--open', '-sS', ip])

dom = minidom.parse(open(fname, 'r'))
ports = dom.getElementsByTagName('port')
is_error = None
if len(ports):
    print "Open ports found:"
    for e in ports:
        state = e.getElementsByTagName('state')[0].getAttribute('state')
        port = e.getAttribute('portid')
        print port, state
    is_error = '%d open ports found' % len(ports)

if is_error:
    print "FAILED", is_error
    sys.exit(1)

else:
    print "OK."
    sys.exit(0)
