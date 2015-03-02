DIRS = config crypto document entity fs index node x509

default: get-deps test

get-deps:
	gom install
test:
	for d in $(DIRS); do (cd $$d; gom test); done

dev:
	test -d _vendor && \
        mkdir -p _vendor/src/github.com/pki-io/core && \
        for d in $(DIRS); do (cd _vendor/src/github.com/pki-io/core && ln -s ../../../../../$$d .); done

clean:
	test ! -d _vendor || rm -rf _vendor/*
