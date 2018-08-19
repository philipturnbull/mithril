.PHONY: default
mitril:
	cargo build
default: mithril ;
	
.PHONY: test
test:
	docker build -t mithril/test test/
	docker run -v$(shell pwd)/build:/out mithril/test
	test/compare-output
