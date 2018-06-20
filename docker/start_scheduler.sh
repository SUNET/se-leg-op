#!/bin/bash

set -e

/sbin/start-stop-daemon --start -c seleg:seleg --exec \
     /op/env/bin/rqscheduler --pidfile /var/run/se-leg-op-scheduler.pid \
     -- \
     -H redis

