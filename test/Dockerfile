FROM ubuntu:xenial

RUN apt-get update
RUN apt-get install -y \
	gcc \
	hardening-includes

COPY build-binaries /usr/local/bin
COPY *.c /usr/local/share/mithril/

CMD build-binaries /usr/bin/gcc /out
