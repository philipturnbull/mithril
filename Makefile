.PHONY: default
mithril:
	cargo build
default: mithril ;
	
.PHONY: test
test: mithril
	mkdir -p build
	script/build-test-binaries build gcc
	script/compare-output

.PHONY: docker-test
docker-test: mithril
	docker build -f test/Dockerfile -t mithril/test .
	mkdir -p build
	docker run -v$(shell pwd)/build:/out mithril/test
	script/compare-output

.PHONY: clean
clean:
	rm -rf build/
	rm -rf target/
