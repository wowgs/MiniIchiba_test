FROM python:3.7.4

RUN mkdir -p /membership
RUN mkdir -p /logs
WORKDIR /membership
COPY requirements.txt /membership
RUN pip install -U pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . /membership