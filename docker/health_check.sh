#!/bin/bash

set -e

# Status views is only accessable in the app container
if ps -p 1 | grep gunicorn; then
  curl http://localhost:5000/status/healthy | grep -q STATUS_OK
fi
