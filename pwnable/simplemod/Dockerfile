FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update --fix-missing
RUN apt-get -y upgrade
RUN apt-get -y install xinetd
RUN groupadd -r pwn && useradd -r -g pwn pwn

ADD build/pwn.xinetd /etc/xinetd.d/pwn
ADD build/init.sh /etc/init.sh
ADD build/run.sh /home/pwn/run.sh
RUN chmod 700 /etc/init.sh
RUN chmod 550 /home/pwn/run.sh
RUN chmod 1733 /tmp /var/tmp /dev/shm

WORKDIR /home/pwn
ADD build/flag.txt flag.txt
ADD build/ld.so ld.so
RUN chmod a+x ld.so && mv ld.so /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
ADD build/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
ADD files/simplemod/chall chall
ADD files/simplemod/libmod.so libmod.so
RUN chmod 440 flag.txt
RUN chmod 550 chall
RUN mv flag.txt flag-$(md5sum flag.txt | awk '{print $1}').txt

RUN chown -R root:pwn /home/pwn
