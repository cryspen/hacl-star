HACL_HOME=$(realpath ../..)

# CUSTOMIZE HERE: determine what is the main target of this Makefile, e.g. a C
# test, a Low* test, or just a binary archive (like libcurve.a).
all: dist/Makefile.basic

test: all dist/sha3-test.exe
	dist/sha3-test.exe

# Defines rules for producing .checked, .krml, .depend, etc.
include $(HACL_HOME)/Makefile.local

# CUSTOMIZE HERE: how to produce binary objects
# An archive with all the compiled code in this directory.

SHA3_BUNDLE= -bundle Hacl.SHA3=Hacl.*

dist/Makefile.basic: $(filter-out %/prims.krml,$(ALL_KRML_FILES))
	$(KRML) $^  $(BASE_FLAGS) $(SHA3_BUNDLE) \
	  -funroll-loops 25 \
	  -fbuiltin-uint128 \
	  -tmpdir dist \
	  -skip-compilation \
	  -ccopts -std=gnu11,-g,-O3 \
	  -add-include '"krml/internal/target.h"' \
	  -add-include '"libintvector.h"'

dist/sha3-test.exe: dist/Makefile.basic sha3-test.c
	$(CC) -O3 -march=native -mtune=native -I ../../dist/gcc64-only -I dist -I digestif-src -I ../../lib/c -I ../../../karamel/include -I ../../../karamel/krmllib/c -I ../../../karamel/krmllib/dist/minimal -I ../../tests ../../dist/gcc64-only/Lib_Memzero0.c dist/Hacl_SHA3.c digestif-src/sha3.c sha3-test.c -o dist/sha3-test.exe

clean-c:
	$(MAKE) -C dist/ -f Makefile.basic clean
	rm -rf dist .output
