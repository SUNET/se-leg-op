#!/bin/bash

set -e
set -x

interval=${INTERVAL-'60.0'}

/sbin/start-stop-daemon --start -c seleg:seleg --exec \
     /op/env/bin/rqscheduler --pidfile /var/run/se-leg-op-scheduler.pid \
     -- \
     --interval $interval \
     --verbose

