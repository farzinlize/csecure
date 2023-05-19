SECURITY_LIB=-lgcrypt
MYPHONE=-march=armv8-a -mtune=cortex-a55
CPARTNER_SOURCES=cpartner.c security.c utility.c

# KEEP IN MIND "TEST" pre-processing value only applies to main functions

# security module 
security: security.c
	gcc -o build/security security.c $(SECURITY_LIB) -DSECURITY_MAIN -DMAKE_MAKE

# testing while develop
test-securty: security.c
	gcc -o build/test-security security.c $(SECURITY_LIB) -DTEST -DSECURITY_MAIN -DMAKE_MAKE

# inspecting mode in security module 
inspect-security: security.c
	gcc -o build/inspect-security security.c $(SECURITY_LIB) -DINSPECT -DSECURITY_MAIN -DMAKE_MAKE

cpartner: $(CPARTNER_SOURCES)
	gcc -o build/cpartner $(CPARTNER_SOURCES) $(SECURITY_LIB) -DMAKE_MAKE

test-cpartner: $(CPARTNER_SOURCES)
	gcc -o build/test-cpartner $(CPARTNER_SOURCES) $(SECURITY_LIB) -DMAKE_MAKE -DTEST -DINSPECT

clean:
	rm -rf build/*