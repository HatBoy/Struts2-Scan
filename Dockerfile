FROM python:3.6-slim-stretch

LABEL MAINTAINER "supj@gmail.com"

RUN echo "deb http://mirrors.ustc.edu.cn/debian/ stretch main  \
deb http://mirrors.ustc.edu.cn/debian-security stretch/updates main   \
deb http://mirrors.ustc.edu.cn/debian stretch-updates main"> /etc/apt/sources.list

RUN apt-get update && \
    apt-get install -y git

RUN /usr/local/bin/python -m pip install --upgrade pip && \
    pip install requests bs4 click

RUN git clone https://github.com/HatBoy/Struts2-Scan.git

RUN echo '#!/bin/bash \
sleep infinity' > start.sh

ENTRYPOINT ["/bin/bash", "start.sh"]
