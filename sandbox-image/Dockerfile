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

ADD minit /usr/local/bin

ADD etc/bash_completion.d/bunker_ssh_config /etc/bash_completion.d

CMD ["/usr/local/bin/minit", "-L", "/root/.minit.sock"]
