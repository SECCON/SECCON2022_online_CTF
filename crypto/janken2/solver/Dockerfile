# (SECCON): Write this as you like

FROM python:3.10-buster

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app
ADD . /app

RUN apt-get update && apt-get install -yqq cmake make python3
RUN pip install -r requirements.txt

CMD ["python3", "/app/solver.py"]
