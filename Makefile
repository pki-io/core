DIRS = config crypto document entity fs index node x509

default: get-deps test

get-deps::
	gom install
test:
	for d in $(DIRS); do (cd $$d; gom test); done

