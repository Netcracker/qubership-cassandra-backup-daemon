FROM eclipse-temurin:11-jre as java

FROM ghcr.io/netcracker/qubership-backup-daemon-go:main

RUN apk add --no-cache \
    wget net-tools openssh-client rsync ansible jq \
    python3 python3-dev py3-pip \
    libev-dev build-base linux-headers libffi-dev \
    zip unzip bash grep libarchive-tools \
    && sed -i "s/999/99/" /etc/group

COPY --from=java /opt/java/openjdk /opt/java/openjdk

ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="$JAVA_HOME/bin:$PATH"


RUN pip install --no-cache-dir --break-system-packages \
    setuptools==78.1.1 \
    wheel \
    cassandra-driver \
    boto3==1.40.69 \
    jq

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

