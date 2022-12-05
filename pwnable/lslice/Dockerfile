FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update --fix-missing && apt-get -y upgrade
RUN apt-get -y install xinetd python3 hashcash
RUN groupadd -r pwn && useradd -r -g pwn pwn

ADD files/lslice/etc/pwn.xinetd /etc/xinetd.d/pwn
ADD files/lslice/etc/init.sh    /etc/init.sh
ADD files/lslice/etc/redir.sh   /home/pwn/.redir.sh
RUN chmod 550 /home/pwn/.redir.sh
RUN chmod 700 /etc/init.sh
RUN chmod 1733 /tmp /var/tmp /dev/shm

WORKDIR /home/pwn
ADD builds/flag.txt flag.txt
ADD files/lslice/bin/lua    lua
ADD files/lslice/bin/app.py app.py
RUN chmod 440 flag.txt
RUN chmod 550 lua
RUN chmod 550 app.py
RUN mv flag.txt flag-$(md5sum flag.txt | awk '{print $1}').txt

RUN chown -R root:pwn /home/pwn

RUN ls /home/pwn -lh

RUN service xinetd restart
