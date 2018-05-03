FROM ubuntu

ENV container docker
ENV DEBIAN_FRONTEND noninteractive

RUN sed -i -E 's!archive.ubuntu.com!mirrors.aliyun.com!' /etc/apt/sources.list
RUN sed -i -E 's!security.ubuntu.com!mirrors.aliyun.com!' /etc/apt/sources.list

RUN apt-get update &&\
    DEBIAN_FRONTEND=noninteractive apt-get install -y apt-utils &&\
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -yy &&\
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-client git vim htop tmux bash-completion build-essential iputils-ping &&\
    rm -rf /var/lib/apt/lists/*

WORKDIR /root

ADD dummy-init.c /tmp
ADD etc/bash_completion.d/bunker_ssh_config /etc/bash_completion.d

RUN gcc /tmp/dummy-init.c -O3 -s -DNDEBUG -o /usr/bin/dummy-init && rm /tmp/dummy-init.c

CMD ["/usr/bin/dummy-init"]
