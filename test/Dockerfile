FROM ubuntu:xenial

RUN apt-get update && apt-get install -y \
	gcc \
	clang-3.8 \
	hardening-includes

COPY script/build-test-binaries /usr/local/share/mithril/script/
COPY test/*.c /usr/local/share/mithril/test/

WORKDIR /usr/local/share/mithril

CMD script/build-test-binaries /out /usr/bin/gcc /usr/bin/clang-3.8
