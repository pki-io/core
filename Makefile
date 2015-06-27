DIRS = config crypto document entity fs index node x509

default: get-deps test

get-deps:
	fdm

test:
	fdm test ./...

dev: clean get-deps
	mkdir -p _vendor/src/github.com/pki-io/core && \
	for d in $(DIRS); do (cd _vendor/src/github.com/pki-io/core && ln -s ../../../../../$$d .); done && \
	test ! -d _vendor/pkg || rm -rf _vendor/pkg
	fdm
	go get github.com/stretchr/testify

lint:
	fdm --exec gometalinter ./...

clean:
	test ! -d _vendor || rm -rf _vendor/*
