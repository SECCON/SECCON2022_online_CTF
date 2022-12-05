FROM ubuntu:20.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update --fix-missing && apt-get -y upgrade
RUN apt-get -y install socat python3.9
RUN groupadd -r ctf && useradd -r -g ctf ctf
RUN chmod 1733 /tmp /var/tmp /dev/shm

WORKDIR /home/ctf
ADD server.py .
RUN chmod 500 ./server.py
RUN chown ctf:root . -R

USER ctf
CMD socat TCP-L:10042,fork,reuseaddr EXEC:"./server.py"
