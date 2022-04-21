#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>

#include "test_helpers.h"

#include "Hacl_SHA3.h"

#include "EverCrypt_AutoConfig2.h"

#include "sha3_vectors.h"

#include "sha3.h"

#define ROUNDS 16384
#define SIZE   16384


bool print_result(uint8_t* comp, uint8_t* exp, int len) {
  return compare_and_print(len, comp, exp);
}

bool print_test1(uint8_t* in, int in_len, uint8_t* exp256, uint8_t* exp512){
  uint8_t comp256[32] = {0};
  uint8_t comp512[64] = {0};

  Hacl_SHA3_sha3_256(in_len,in,comp256);
  printf("SHA3-256 (32-bit) Result:\n");
  printf("input:");
  for (size_t i = 0; i < in_len; i++)
    printf("%02x",in[i]);
  printf("\n");
  bool ok = print_result(comp256,exp256,32);

  Hacl_SHA3_sha3_512(in_len,in,comp512);
  printf("SHA3-512 (32-bit) Result:\n");
  printf("input:");
  for (size_t i = 0; i < in_len; i++)
    printf("%02x",in[i]);
  printf("\n");
  ok = print_result(comp512,exp512,64) && ok;


  struct sha3_ctx ctx;
  digestif_sha3_init(&ctx,256);
  digestif_sha3_update(&ctx,in,in_len);
  digestif_sha3_finalize(&ctx,comp256,0x06U);
  printf("Digestif SHA3-256 (32-bit) Result:\n");
  printf("input:");
  for (size_t i = 0; i < in_len; i++)
    printf("%02x",in[i]);
  printf("\n");
  ok = print_result(comp256,exp256,32) && ok;

return ok;
}

int main()
{

  bool ok = true;
  for (int i = 0; i < sizeof(vectors)/sizeof(sha3_test_vector); ++i) {
    ok &= print_test1(vectors[i].input,vectors[i].input_len,vectors[i].tag_256,vectors[i].tag_512);
  }


  uint64_t len = SIZE;
  uint8_t plain[SIZE];
  cycles a,b;
  clock_t t1,t2;
  memset(plain,'P',SIZE);

  for (int j = 0; j < ROUNDS; j++) {
    Hacl_SHA3_sha3_256(SIZE,plain,plain);
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_SHA3_sha3_256(SIZE,plain,plain);
  }
  b = cpucycles_end();
  t2 = clock();
  double cdiff2n = b - a;
  double tdiff2n = (double)(t2 - t1);

  for (int j = 0; j < ROUNDS; j++) {
    struct sha3_ctx ctx;
    digestif_sha3_init(&ctx,32);
    digestif_sha3_update(&ctx,plain,SIZE);
    digestif_sha3_finalize(&ctx,plain,0x06U);
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    struct sha3_ctx ctx;
    digestif_sha3_init(&ctx,32);
    digestif_sha3_update(&ctx,plain,SIZE);
    digestif_sha3_finalize(&ctx,plain,0x06U);
  }
  b = cpucycles_end();
  t2 = clock();
  double cdiff2d = b - a;
  double tdiff2d = (double)(t2 - t1);


  for (int j = 0; j < ROUNDS; j++) {
    Hacl_SHA3_sha3_512(SIZE,plain,plain);
  }

  t1 = clock();
  a = cpucycles_begin();
  for (int j = 0; j < ROUNDS; j++) {
    Hacl_SHA3_sha3_512(SIZE,plain,plain);
  }
  b = cpucycles_end();
  t2 = clock();
  double cdiff1 = b - a;
  double tdiff1 = (double)(t2 - t1);


  uint8_t res = plain[0];
  uint64_t count = ROUNDS * SIZE;
  printf ("\n\n");
  printf("SHA3-256 (32-bit) PERF: %d\n",(int)res); print_time(count,tdiff2n,cdiff2n);
  printf("DIGESTIF SHA3-256 (32-bit) PERF: %d\n",(int)res); print_time(count,tdiff2d,cdiff2d);

  printf("SHA3-512 (32-bit) PERF: %d\n",(int)res); print_time(count,tdiff1,cdiff1);

  if (ok) return EXIT_SUCCESS;
  else return EXIT_FAILURE;
}
