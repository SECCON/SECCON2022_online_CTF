FROM python:3

MAINTAINER ShiftCrops <simiyu@shift-crops.net>

RUN pip3 install pwntools && \
	mkdir /opt/sc_expwn	

ADD https://raw.githubusercontent.com/shift-crops/sc_expwn/master/sc_expwn.py /opt/sc_expwn/ 

WORKDIR /app
ADD files/simplemod /app
ADD solver/exploit.py /app

ENV PYTHONPATH "${PYTHONPATH}:/opt/sc_expwn"
ENV TERM "linux"

CMD ["python3", "exploit.py"]
