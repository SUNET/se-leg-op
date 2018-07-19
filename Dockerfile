FROM debian:stable

MAINTAINER se-leg developers <se-leg@lists.sunet.se>

ENV DEBIAN_FRONTEND=noninteractive \
    SE_LEG_PROVIDER_SETTINGS=/op/etc/app_config.py

WORKDIR /
EXPOSE 5000
VOLUME /op/etc

RUN /bin/sed -i s/deb.debian.org/ftp.se.debian.org/g /etc/apt/sources.list

RUN apt-get update && apt-get -y dist-upgrade
# for troubleshooting in the container
RUN apt-get -y install \
    vim \
    net-tools \
    netcat \
    telnet \
    traceroute \
    curl \
    procps
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
COPY Dockerfile /Dockerfile

# Add health check script for op
COPY docker/health_check.sh /health_check.sh

# Add start script for rq worker
COPY docker/start_worker.sh /start_worker.sh

# Add start script for delay worker
COPY docker/start_scheduler.sh /start_scheduler.sh

# revision.txt is dynamically updated by the CI for every build,
# to ensure the statements below this point are executed every time
COPY docker/revision.txt /revision.txt

RUN mkdir -p /op && virtualenv -p python3 /op/env
COPY . /op/src
RUN cd /op/src && \
    /op/env/bin/pip install -U pip && \
    /op/env/bin/pip install -r requirements.txt && \
    /op/env/bin/pip install gunicorn

# create log dirs
RUN mkdir -p /var/log/op/plugins && chown -R seleg:seleg /var/log/op
VOLUME /var/log/op

HEALTHCHECK --interval=10s CMD /health_check.sh

CMD ["start-stop-daemon", "--start", "-c", "seleg:seleg", "--exec", \
     "/op/env/bin/gunicorn", "--pidfile", "/var/run/se-leg-op.pid", \
     "--", \
     "--bind", "0.0.0.0:5000", "--chdir", "/tmp", \
     "-w", "3", \
     "se_leg_op.service.run:app" \
     ]
