DIRS = config crypto document entity fs index node x509

default: get-deps test

get-deps:
	gom install
test:
	gom test ./...

dev: clean get-deps
	mkdir -p _vendor/src/github.com/pki-io/core && \
	for d in $(DIRS); do (cd _vendor/src/github.com/pki-io/core && ln -s ../../../../../$$d .); done && \
	test ! -d _vendor/pkg || rm -rf _vendor/pkg

clean:
	test ! -d _vendor || rm -rf _vendor/*
