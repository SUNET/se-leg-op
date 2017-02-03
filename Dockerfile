FROM debian

MAINTAINER se-leg developers <se-leg@lists.sunet.se>

ENV DEBIAN_FRONTEND=noninteractive \
    SE_LEG_PROVIDER_SETTINGS=/op/etc/app_config.py

WORKDIR /
EXPOSE 5000
VOLUME ["/op/etc"]

RUN apt-get update && apt-get -yu dist-upgrade
# for troubleshooting in the container
RUN apt-get -y install \
    vim \
    net-tools \
    netcat \
    telnet \
    traceroute
RUN apt-get -y install \
    python-virtualenv \
    git-core \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev
# insert additional apt-get installs here
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

RUN adduser --system --group seleg

# Add Dockerfile to the container as documentation
ADD Dockerfile /Dockerfile

# revision.txt is dynamically updated by the CI for every build,
# to ensure the statements below this point are executed every time
ADD revision.txt /revision.txt

RUN mkdir -p /op && virtualenv -p python3 /op/env
ADD . /op/src
RUN cd /op/src && \
    /op/env/bin/pip install -U pip && \
    /op/env/bin/pip install -r requirements.txt && \
    /op/env/bin/pip install gunicorn

CMD ["start-stop-daemon", "--start", "-c", "seleg:seleg", "--exec", \
     "/op/env/bin/gunicorn", "--pidfile", "/var/run/se-leg-op.pid", \
     "--", \
     "--bind", "0.0.0.0:5000", "--chdir", "/tmp", \
     "-w", "3", \
     "se_leg_op.service.run:app" \
     ]
