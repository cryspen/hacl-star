/* This file was auto-generated by KreMLin! */
#ifndef __Poly1305_64_H
#define __Poly1305_64_H



#include "kremlib.h"
#include "testlib.h"

typedef uint64_t Hacl_Bignum_Constants_limb;

typedef FStar_UInt128_t Hacl_Bignum_Constants_wide;

typedef FStar_UInt128_t Hacl_Bignum_Wide_t;

typedef uint64_t Hacl_Bignum_Limb_t;

typedef Prims_int Hacl_Spec_Bignum_Field_elem;

extern void
Hacl_Spec_Bignum_Field_lemma_addition_associativity(Prims_int x0, Prims_int x1, Prims_int x2);

extern void
Hacl_Spec_Bignum_Field_lemma_multiplication_associativity(
  Prims_int x0,
  Prims_int x1,
  Prims_int x2
);

extern void Hacl_Spec_Bignum_Field_lemma_addition_symmetry(Prims_int x0);

extern void Hacl_Spec_Bignum_Field_lemma_multiplication_symmetry(Prims_int x0);

typedef uint8_t Hacl_Spec_Poly1305_64_byte;

typedef void *Hacl_Spec_Poly1305_64_bytes;

typedef void *Hacl_Spec_Poly1305_64_word;

typedef void *Hacl_Spec_Poly1305_64_word_16;

typedef void *Hacl_Spec_Poly1305_64_tag;

typedef void *Hacl_Spec_Poly1305_64_word_;

typedef void *Hacl_Spec_Poly1305_64_text;

typedef void *Hacl_Spec_Poly1305_64_log_t;

typedef Prims_int Hacl_Spec_Poly1305_64_elem;

typedef struct {
  void *x00;
  void *x01;
  void *x02;
}
Hacl_Spec_Poly1305_64_poly1305_state_;

extern uint64_t Hacl_Spec_Poly1305_64_load64_le_spec(void *x0);

extern void *Hacl_Spec_Poly1305_64_store64_le_spec(uint64_t x0);

extern FStar_UInt128_t Hacl_Spec_Poly1305_64_load128_le_spec(void *x0);

extern void *Hacl_Spec_Poly1305_64_store128_le_spec(FStar_UInt128_t x0);

typedef void *Hacl_Impl_Poly1305_64_log_t;

typedef uint64_t *Hacl_Impl_Poly1305_64_bigint;

typedef uint8_t *Hacl_Impl_Poly1305_64_uint8_p;

typedef uint64_t *Hacl_Impl_Poly1305_64_elemB;

typedef uint8_t *Hacl_Impl_Poly1305_64_wordB;

typedef uint8_t *Hacl_Impl_Poly1305_64_wordB_16;

typedef struct {
  uint64_t *x00;
  uint64_t *x01;
}
Hacl_Impl_Poly1305_64_poly1305_state;

typedef uint8_t *Poly1305_64_uint8_p;

typedef uint8_t *Poly1305_64_key;

typedef Hacl_Impl_Poly1305_64_poly1305_state Poly1305_64_state;

void Poly1305_64_init(Hacl_Impl_Poly1305_64_poly1305_state st, uint8_t *k);

extern void *Poly1305_64_empty_log;

void Poly1305_64_update_block(Hacl_Impl_Poly1305_64_poly1305_state st, uint8_t *m);

void Poly1305_64_update(Hacl_Impl_Poly1305_64_poly1305_state st, uint8_t *m, uint32_t len);

void
Poly1305_64_update_last(Hacl_Impl_Poly1305_64_poly1305_state st, uint8_t *m, uint32_t len);

void Poly1305_64_finish(Hacl_Impl_Poly1305_64_poly1305_state st, uint8_t *mac, uint8_t *k);

void Poly1305_64_crypto_onetimeauth(uint8_t *output, uint8_t *input, uint64_t len, uint8_t *k);

void
Poly1305_64_poly1305_blocks_init(
  Hacl_Impl_Poly1305_64_poly1305_state st,
  uint8_t *input,
  uint32_t len,
  uint8_t *k
);

void
Poly1305_64_poly1305_blocks_continue(
  Hacl_Impl_Poly1305_64_poly1305_state st,
  uint8_t *input,
  uint32_t len
);

void
Poly1305_64_poly1305_blocks_finish(
  Hacl_Impl_Poly1305_64_poly1305_state st,
  uint8_t *input,
  uint8_t *mac,
  uint8_t *key_s
);
#endif
