#!/bin/bash

set -e

/sbin/start-stop-daemon --start -c seleg:seleg --exec \
     /op/env/bin/rq --pidfile /var/run/se-leg-op-worker.pid \
     -- \
     worker -c worker_config
