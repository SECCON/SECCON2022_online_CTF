FROM python:3.10.7

WORKDIR /app
ADD . /app

RUN pip install -r requirements.txt

CMD ["python3", "/app/solver.py"]