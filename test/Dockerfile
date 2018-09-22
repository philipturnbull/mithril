FROM ubuntu:xenial

RUN apt-get update && apt-get install -y \
	gcc-4.7 \
	gcc-4.8 \
	gcc-4.9 \
	gcc-5 \
	clang-3.5 \
	clang-3.6 \
	clang-3.7 \
	clang-3.8 \
	clang-3.9 \
	clang-4.0 \
	hardening-includes

COPY script/build-test-binaries /usr/local/share/mithril/script/
COPY test/*.c /usr/local/share/mithril/test/

WORKDIR /usr/local/share/mithril

CMD script/build-test-binaries /out /usr/bin/gcc-[0-9]* /usr/bin/clang-[0-9]*
