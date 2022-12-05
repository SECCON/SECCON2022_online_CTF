FROM ubuntu:22.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update --fix-missing
RUN apt-get -y upgrade
RUN apt-get -y install xinetd qemu-system hashcash
RUN groupadd -r pwn && useradd -r -g pwn pwn

ADD build/pwn.xinetd /etc/xinetd.d/pwn
ADD build/init.sh    /etc/init.sh
RUN chmod 700 /etc/init.sh
RUN chmod 1733 /tmp /var/tmp /dev/shm

WORKDIR /home/pwn
ADD build/run.sh .
ADD build/qemu/bzImage     ./qemu/bzImage
ADD build/qemu/rootfs.cpio ./qemu/rootfs.cpio
RUN chmod 550 run.sh
RUN chmod 440 qemu/bzImage
RUN chmod 440 qemu/rootfs.cpio

RUN chown -R root:pwn /home/pwn

RUN ls /home/pwn -lh

RUN service xinetd restart
