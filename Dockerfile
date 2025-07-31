FROM ghcr.io/netcracker/qubership-backup-daemon:main_alpine

RUN echo 'https://dl-cdn.alpinelinux.org/alpine/v3.20/main/' > /etc/apk/repositories \
    && echo 'https://dl-cdn.alpinelinux.org/alpine/v3.20/community' >> /etc/apk/repositories \
    && apk add --no-cache wget net-tools openssh-client rsync ansible openjdk8 jq zip unzip bash grep libarchive-tools curl \
    && apk update \
    && apk upgrade \
    # ping takes over 999 uid 
    && sed -i "s/999/99/" /etc/group 


RUN pip install "setuptools==70.0.0" && \
    pip install cassandra-driver boto3==1.35.27 jq

ENV CASSANDRA_HOME=/opt/cassandra
ENV CASSANDRA4_DIR=4.1.4

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

