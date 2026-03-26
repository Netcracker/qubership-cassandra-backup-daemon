FROM eclipse-temurin:11-jre AS java

FROM ghcr.io/netcracker/qubership-backup-daemon-go-debian:args_fix

RUN apt-get update && apt-get install -y \
        python3 \
        python3-dev \
        python3-pip \
        build-essential \
        libffi-dev \
        libssl-dev \
        libev-dev \
        wget \
        curl \
        unzip \
        bash \
        rsync \
        ansible \
        jq \
        net-tools \
        openssh-client \
        zip \
        grep \
        libarchive-tools \
    && pip3 install --no-cache-dir --break-system-packages \
        setuptools \
        cassandra-driver \
        boto3 \
        jq \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 999 cassandra

COPY --from=java /opt/java/openjdk /opt/java/openjdk

ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="$JAVA_HOME/bin:$PATH"

ENV CASSANDRA_HOME=/opt/cassandra
ENV CASSANDRA4_DIR=4.1.9

RUN mkdir -p /opt/downloads
RUN mkdir -p $CASSANDRA_HOME


RUN wget -qO- https://archive.apache.org/dist/cassandra/${CASSANDRA4_DIR}/apache-cassandra-${CASSANDRA4_DIR}-bin.tar.gz | tar xvfz - -C /opt/downloads/

RUN echo 'export PATH=$PATH:'"$CASSANDRA_HOME/bin" > $CASSANDRA_HOME/.profile 
RUN mkdir /var/lib/cassandra /var/log/cassandra

VOLUME /backup-storage

ADD files/ /opt/backup/
ADD main.py /opt/backup/
ADD src/ /opt/backup/src/
ADD config/ssh_config /etc/ssh/
ADD backup-daemon.conf /etc/backup-daemon.conf
ADD files/ansible.cfg /etc/ansible/
RUN chmod -R 777 /opt/backup  /opt/downloads  /opt/cassandra /etc/passwd


CMD ["/opt/backup/run.sh"]