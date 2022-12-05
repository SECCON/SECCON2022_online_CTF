FROM python:3.10-buster

WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

COPY ./problem.py /app/problem.py
COPY ./flag.py /app/flag.py
CMD ["python", "problem.py"]
