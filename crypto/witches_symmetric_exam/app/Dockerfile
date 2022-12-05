FROM python:3.8-buster

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

RUN apt update
RUN apt install socat -y

COPY ./problem.py /app/problem.py
COPY ./flag.py /app/flag.py

CMD socat TCP-L:8080,fork,reuseaddr EXEC:"python problem.py"
