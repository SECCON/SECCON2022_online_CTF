FROM python:3.9-alpine

RUN apk add gcc musl-dev
RUN pip install ptrlib

# キャッシュせんかい
WORKDIR /app
ADD . /app

CMD ["python3", "/app/solve.py"]
