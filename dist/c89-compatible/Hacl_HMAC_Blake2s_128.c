/* MIT License
 *
 * Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include "Hacl_HMAC_Blake2s_128.h"

#include "internal/Hacl_Hash_Blake2s_128.h"
#include "internal/Hacl_Hash_Blake2.h"

typedef struct ___Lib_IntVector_Intrinsics_vec128__uint64_t_s
{
  Lib_IntVector_Intrinsics_vec128 *fst;
  uint64_t snd;
}
___Lib_IntVector_Intrinsics_vec128__uint64_t;

void
Hacl_HMAC_Blake2s_128_compute_blake2s_128(
  uint8_t *dst,
  uint8_t *key,
  uint32_t key_len,
  uint8_t *data,
  uint32_t data_len
)
{
  uint32_t l = (uint32_t)64U;
  KRML_CHECK_SIZE(sizeof (uint8_t), l);
  {
    uint8_t key_block[l];
    memset(key_block, 0U, l * sizeof (uint8_t));
    {
      uint32_t i0;
      if (key_len <= (uint32_t)64U)
      {
        i0 = key_len;
      }
      else
      {
        i0 = (uint32_t)32U;
      }
      {
        uint8_t *nkey = key_block;
        if (key_len <= (uint32_t)64U)
        {
          memcpy(nkey, key, key_len * sizeof (uint8_t));
        }
        else
        {
          Hacl_Hash_Blake2s_128_hash_blake2s_128(key, key_len, nkey);
        }
        KRML_CHECK_SIZE(sizeof (uint8_t), l);
        {
          uint8_t ipad[l];
          memset(ipad, (uint8_t)0x36U, l * sizeof (uint8_t));
          {
            uint32_t i;
            for (i = (uint32_t)0U; i < l; i++)
            {
              uint8_t xi = ipad[i];
              uint8_t yi = key_block[i];
              ipad[i] = xi ^ yi;
            }
          }
          KRML_CHECK_SIZE(sizeof (uint8_t), l);
          {
            uint8_t opad[l];
            memset(opad, (uint8_t)0x5cU, l * sizeof (uint8_t));
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < l; i++)
              {
                uint8_t xi = opad[i];
                uint8_t yi = key_block[i];
                opad[i] = xi ^ yi;
              }
            }
            {
              KRML_PRE_ALIGN(16)
              Lib_IntVector_Intrinsics_vec128
              s0[4U] KRML_POST_ALIGN(16) = { 0U };
              Lib_IntVector_Intrinsics_vec128 *r0 = s0;
              Lib_IntVector_Intrinsics_vec128 *r1 = s0 + (uint32_t)1U;
              Lib_IntVector_Intrinsics_vec128 *r2 = s0 + (uint32_t)2U;
              Lib_IntVector_Intrinsics_vec128 *r3 = s0 + (uint32_t)3U;
              uint32_t iv0 = Hacl_Impl_Blake2_Constants_ivTable_S[0U];
              uint32_t iv1 = Hacl_Impl_Blake2_Constants_ivTable_S[1U];
              uint32_t iv2 = Hacl_Impl_Blake2_Constants_ivTable_S[2U];
              uint32_t iv3 = Hacl_Impl_Blake2_Constants_ivTable_S[3U];
              uint32_t iv4 = Hacl_Impl_Blake2_Constants_ivTable_S[4U];
              uint32_t iv5 = Hacl_Impl_Blake2_Constants_ivTable_S[5U];
              uint32_t iv6 = Hacl_Impl_Blake2_Constants_ivTable_S[6U];
              uint32_t iv7 = Hacl_Impl_Blake2_Constants_ivTable_S[7U];
              uint32_t kk_shift_8;
              uint32_t iv0_;
              uint64_t es;
              r2[0U] = Lib_IntVector_Intrinsics_vec128_load32s(iv0, iv1, iv2, iv3);
              r3[0U] = Lib_IntVector_Intrinsics_vec128_load32s(iv4, iv5, iv6, iv7);
              kk_shift_8 = (uint32_t)0U;
              iv0_ = iv0 ^ ((uint32_t)0x01010000U ^ (kk_shift_8 ^ (uint32_t)32U));
              r0[0U] = Lib_IntVector_Intrinsics_vec128_load32s(iv0_, iv1, iv2, iv3);
              r1[0U] = Lib_IntVector_Intrinsics_vec128_load32s(iv4, iv5, iv6, iv7);
              es = (uint64_t)0U;
              {
                ___Lib_IntVector_Intrinsics_vec128__uint64_t scrut0;
                Lib_IntVector_Intrinsics_vec128 *s;
                uint8_t *dst1;
                uint64_t ev0;
                uint64_t ev10;
                uint8_t *hash1;
                uint64_t ev;
                uint64_t ev11;
                uint32_t block_len0;
                uint32_t n_blocks0;
                uint32_t rem0;
                K___uint32_t_uint32_t scrut1;
                uint32_t n_blocks1;
                uint32_t rem_len0;
                uint32_t full_blocks_len0;
                uint8_t *full_blocks0;
                uint64_t ev2;
                uint8_t *rem1;
                uint64_t ev3;
                uint64_t ev1;
                scrut0.fst = s0;
                scrut0.snd = es;
                s = scrut0.fst;
                dst1 = ipad;
                ev0 = Hacl_Hash_Blake2s_128_init_blake2s_128(s);
                if (data_len == (uint32_t)0U)
                {
                  uint64_t
                  ev12 =
                    Hacl_Hash_Blake2s_128_update_last_blake2s_128(s,
                      ev0,
                      (uint64_t)0U,
                      ipad,
                      (uint32_t)64U);
                  ev10 = ev12;
                }
                else
                {
                  uint64_t
                  ev12 = Hacl_Hash_Blake2s_128_update_multi_blake2s_128(s, ev0, ipad, (uint32_t)1U);
                  uint32_t block_len = (uint32_t)64U;
                  uint32_t n_blocks2 = data_len / block_len;
                  uint32_t rem2 = data_len % block_len;
                  K___uint32_t_uint32_t scrut;
                  if (n_blocks2 > (uint32_t)0U && rem2 == (uint32_t)0U)
                  {
                    uint32_t n_blocks_ = n_blocks2 - (uint32_t)1U;
                    K___uint32_t_uint32_t lit;
                    lit.fst = n_blocks_;
                    lit.snd = data_len - n_blocks_ * block_len;
                    scrut = lit;
                  }
                  else
                  {
                    K___uint32_t_uint32_t lit;
                    lit.fst = n_blocks2;
                    lit.snd = rem2;
                    scrut = lit;
                  }
                  {
                    uint32_t n_blocks = scrut.fst;
                    uint32_t rem_len = scrut.snd;
                    uint32_t full_blocks_len = n_blocks * block_len;
                    uint8_t *full_blocks = data;
                    uint64_t
                    ev20 =
                      Hacl_Hash_Blake2s_128_update_multi_blake2s_128(s,
                        ev12,
                        full_blocks,
                        n_blocks);
                    uint8_t *rem = data + full_blocks_len;
                    uint64_t
                    ev30 =
                      Hacl_Hash_Blake2s_128_update_last_blake2s_128(s,
                        ev20,
                        (uint64_t)(uint32_t)64U + (uint64_t)full_blocks_len,
                        rem,
                        rem_len);
                    ev10 = ev30;
                  }
                }
                Hacl_Hash_Blake2s_128_finish_blake2s_128(s, ev10, dst1);
                hash1 = ipad;
                ev = Hacl_Hash_Blake2s_128_init_blake2s_128(s);
                ev11 = Hacl_Hash_Blake2s_128_update_multi_blake2s_128(s, ev, opad, (uint32_t)1U);
                block_len0 = (uint32_t)64U;
                n_blocks0 = (uint32_t)32U / block_len0;
                rem0 = (uint32_t)32U % block_len0;
                if (n_blocks0 > (uint32_t)0U && rem0 == (uint32_t)0U)
                {
                  uint32_t n_blocks_ = n_blocks0 - (uint32_t)1U;
                  K___uint32_t_uint32_t lit;
                  lit.fst = n_blocks_;
                  lit.snd = (uint32_t)32U - n_blocks_ * block_len0;
                  scrut1 = lit;
                }
                else
                {
                  K___uint32_t_uint32_t lit;
                  lit.fst = n_blocks0;
                  lit.snd = rem0;
                  scrut1 = lit;
                }
                n_blocks1 = scrut1.fst;
                rem_len0 = scrut1.snd;
                full_blocks_len0 = n_blocks1 * block_len0;
                full_blocks0 = hash1;
                ev2 =
                  Hacl_Hash_Blake2s_128_update_multi_blake2s_128(s,
                    ev11,
                    full_blocks0,
                    n_blocks1);
                rem1 = hash1 + full_blocks_len0;
                ev3 =
                  Hacl_Hash_Blake2s_128_update_last_blake2s_128(s,
                    ev2,
                    (uint64_t)(uint32_t)64U + (uint64_t)full_blocks_len0,
                    rem1,
                    rem_len0);
                ev1 = ev3;
                Hacl_Hash_Blake2s_128_finish_blake2s_128(s, ev1, dst);
              }
            }
          }
        }
      }
    }
  }
}

