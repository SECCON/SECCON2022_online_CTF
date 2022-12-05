FROM python:3.8-buster

RUN apt-get update && apt-get install -y socat
WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY ./app.py /app/app.py
COPY ./secret.py /app/secret.py
CMD ["socat", "tcp-listen:8080,reuseaddr,fork", "exec:'python3 app.py'"]
