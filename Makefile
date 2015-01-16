DIRS = config crypto document entity fs index node x509

test::
	gom install
test::
	-for d in $(DIRS); do (cd $$d; gom test); done
