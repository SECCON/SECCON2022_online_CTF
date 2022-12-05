FROM python:3.10-buster

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -yqq socat
WORKDIR /app

COPY ./server.py /app/server.py
CMD ["socat", "TCP-L:8080,fork,reuseaddr", "EXEC:'python server.py'"]
