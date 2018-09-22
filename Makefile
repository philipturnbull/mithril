.PHONY: default
mithril:
	cargo build
default: mithril ;
	
.PHONY: travis
travis: mithril
	mkdir -p build
	script/build-test-binaries $(shell pwd)/build /usr/bin/gcc-4.8
	script/test

.PHONY: test
test: mithril
	docker build -f test/Dockerfile -t mithril/test .
	mkdir -p build
	docker run -v$(shell pwd)/build:/out mithril/test
	script/test

.PHONY: clean
clean:
	rm -rf build/
	rm -rf target/
