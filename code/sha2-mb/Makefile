HACL_HOME=$(realpath ../..)

# CUSTOMIZE HERE: determine what is the main target of this Makefile, e.g. a C
# test, a Low* test, or just a binary archive (like libcurve.a).
all: dist/sha2-mb-test.exe

test: all
	dist/sha2-mb-test.exe

# Defines rules for producing .checked, .krml, .depend, etc.
include $(HACL_HOME)/Makefile.local

#BASE_FLAGS+= -funroll-loops 4

CFLAGS += -I$(HACL_HOME)/lib/c -I dist -I ../../dist/gcc-compatible  -march=native -mtune=native -O3
export CFLAGS

SHA2MB_BUNDLE=-bundle Hacl.Impl.SHA2.Generic=Hacl.Impl.SHA2.*,Hacl.Hash.*[rename=Hacl_SHA2_Generic] -static-header Hacl.Impl.SHA2.Generic

# CUSTOMIZE HERE: how to produce binary objects
# An archive with all the compiled code in this directory.
dist/libsha2mb.a: dist/Makefile.basic
	$(MAKE) -C dist -f Makefile.basic

dist/Makefile.basic: $(filter-out %/prims.krml,$(ALL_KRML_FILES))
	$(KRML) $^ -o libsha2mb.a $(BASE_FLAGS) $(SHA2MB_BUNDLE) \
	  -funroll-loops 16 \
	  -add-include '"libintvector.h"' \
	  -tmpdir dist \
	  -skip-compilation

dist/sha2-mb-test.exe: dist/Makefile.basic sha2-mb-test.c
	$(CC) -O3 -march=native -mtune=native -I ../../dist/gcc64-only -I dist -I digestif-src -I ../../lib/c -I ../../../karamel/include -I ../../../karamel/krmllib/c -I ../../../karamel/krmllib/dist/minimal -I ../../tests ../../dist/gcc64-only/Lib_Memzero0.c 	../../dist/gcc64-only/cpuid-x86_64-linux.S ../../dist/gcc64-only/EverCrypt_AutoConfig2.c dist/*.c digestif-src/sha256.c sha2-mb-test.c -o dist/sha2-mb-test.exe


clean-c:
	$(MAKE) -C dist/ -f Makefile.basic clean
