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


#include "internal/Hacl_Hash_Base.h"



uint64_t Hacl_Hash_Core_Blake2_update_blake2s_32(uint32_t *s, uint64_t totlen, uint8_t *block)
{
  uint32_t wv[16U] = { 0U };
  uint64_t totlen1 = totlen + (uint64_t)(uint32_t)64U;
  uint32_t m_w[16U] = { 0U };
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < (uint32_t)16U; i++)
    {
      uint32_t *os = m_w;
      uint8_t *bj = block + i * (uint32_t)4U;
      uint32_t u = load32_le(bj);
      uint32_t r = u;
      uint32_t x = r;
      os[i] = x;
    }
  }
  {
    uint32_t mask[4U] = { 0U };
    uint32_t wv_14 = (uint32_t)0U;
    uint32_t wv_15 = (uint32_t)0U;
    uint32_t *wv3;
    uint32_t *s00;
    uint32_t *s16;
    uint32_t *r00;
    uint32_t *r10;
    uint32_t *r20;
    uint32_t *r30;
    mask[0U] = (uint32_t)totlen1;
    mask[1U] = (uint32_t)(totlen1 >> (uint32_t)32U);
    mask[2U] = wv_14;
    mask[3U] = wv_15;
    memcpy(wv, s, (uint32_t)4U * (uint32_t)4U * sizeof (uint32_t));
    wv3 = wv + (uint32_t)3U * (uint32_t)4U;
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint32_t *os = wv3;
        uint32_t x = wv3[i] ^ mask[i];
        os[i] = x;
      }
    }
    {
      uint32_t i0;
      for (i0 = (uint32_t)0U; i0 < (uint32_t)10U; i0++)
      {
        uint32_t start_idx = i0 % (uint32_t)10U * (uint32_t)16U;
        KRML_CHECK_SIZE(sizeof (uint32_t), (uint32_t)4U * (uint32_t)4U);
        {
          uint32_t m_st[(uint32_t)4U * (uint32_t)4U];
          memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (uint32_t));
          {
            uint32_t *r0 = m_st + (uint32_t)0U * (uint32_t)4U;
            uint32_t *r1 = m_st + (uint32_t)1U * (uint32_t)4U;
            uint32_t *r21 = m_st + (uint32_t)2U * (uint32_t)4U;
            uint32_t *r31 = m_st + (uint32_t)3U * (uint32_t)4U;
            uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
            uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
            uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
            uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
            uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
            uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
            uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
            uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
            uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
            uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
            uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
            uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
            uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
            uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
            uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
            uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
            uint32_t uu____0 = m_w[s2];
            uint32_t uu____1 = m_w[s4];
            uint32_t uu____2 = m_w[s6];
            r0[0U] = m_w[s0];
            r0[1U] = uu____0;
            r0[2U] = uu____1;
            r0[3U] = uu____2;
            {
              uint32_t uu____3 = m_w[s3];
              uint32_t uu____4 = m_w[s5];
              uint32_t uu____5 = m_w[s7];
              r1[0U] = m_w[s1];
              r1[1U] = uu____3;
              r1[2U] = uu____4;
              r1[3U] = uu____5;
              {
                uint32_t uu____6 = m_w[s10];
                uint32_t uu____7 = m_w[s12];
                uint32_t uu____8 = m_w[s14];
                r21[0U] = m_w[s8];
                r21[1U] = uu____6;
                r21[2U] = uu____7;
                r21[3U] = uu____8;
                {
                  uint32_t uu____9 = m_w[s11];
                  uint32_t uu____10 = m_w[s13];
                  uint32_t uu____11 = m_w[s15];
                  r31[0U] = m_w[s9];
                  r31[1U] = uu____9;
                  r31[2U] = uu____10;
                  r31[3U] = uu____11;
                  {
                    uint32_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
                    uint32_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
                    uint32_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
                    uint32_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
                    uint32_t a = (uint32_t)0U;
                    uint32_t b0 = (uint32_t)1U;
                    uint32_t c0 = (uint32_t)2U;
                    uint32_t d0 = (uint32_t)3U;
                    uint32_t *wv_a0 = wv + a * (uint32_t)4U;
                    uint32_t *wv_b0 = wv + b0 * (uint32_t)4U;
                    {
                      uint32_t i;
                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                      {
                        uint32_t *os = wv_a0;
                        uint32_t x1 = wv_a0[i] + wv_b0[i];
                        os[i] = x1;
                      }
                    }
                    {
                      uint32_t i;
                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                      {
                        uint32_t *os = wv_a0;
                        uint32_t x1 = wv_a0[i] + x[i];
                        os[i] = x1;
                      }
                    }
                    {
                      uint32_t *wv_a1 = wv + d0 * (uint32_t)4U;
                      uint32_t *wv_b1 = wv + a * (uint32_t)4U;
                      {
                        uint32_t i;
                        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                        {
                          uint32_t *os = wv_a1;
                          uint32_t x1 = wv_a1[i] ^ wv_b1[i];
                          os[i] = x1;
                        }
                      }
                      {
                        uint32_t *r12 = wv_a1;
                        {
                          uint32_t i;
                          for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                          {
                            uint32_t *os = r12;
                            uint32_t x1 = r12[i];
                            uint32_t x10 = x1 >> (uint32_t)16U | x1 << (uint32_t)16U;
                            os[i] = x10;
                          }
                        }
                        {
                          uint32_t *wv_a2 = wv + c0 * (uint32_t)4U;
                          uint32_t *wv_b2 = wv + d0 * (uint32_t)4U;
                          {
                            uint32_t i;
                            for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                            {
                              uint32_t *os = wv_a2;
                              uint32_t x1 = wv_a2[i] + wv_b2[i];
                              os[i] = x1;
                            }
                          }
                          {
                            uint32_t *wv_a3 = wv + b0 * (uint32_t)4U;
                            uint32_t *wv_b3 = wv + c0 * (uint32_t)4U;
                            {
                              uint32_t i;
                              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                              {
                                uint32_t *os = wv_a3;
                                uint32_t x1 = wv_a3[i] ^ wv_b3[i];
                                os[i] = x1;
                              }
                            }
                            {
                              uint32_t *r13 = wv_a3;
                              {
                                uint32_t i;
                                for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                {
                                  uint32_t *os = r13;
                                  uint32_t x1 = r13[i];
                                  uint32_t x10 = x1 >> (uint32_t)12U | x1 << (uint32_t)20U;
                                  os[i] = x10;
                                }
                              }
                              {
                                uint32_t *wv_a4 = wv + a * (uint32_t)4U;
                                uint32_t *wv_b4 = wv + b0 * (uint32_t)4U;
                                {
                                  uint32_t i;
                                  for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                  {
                                    uint32_t *os = wv_a4;
                                    uint32_t x1 = wv_a4[i] + wv_b4[i];
                                    os[i] = x1;
                                  }
                                }
                                {
                                  uint32_t i;
                                  for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                  {
                                    uint32_t *os = wv_a4;
                                    uint32_t x1 = wv_a4[i] + y[i];
                                    os[i] = x1;
                                  }
                                }
                                {
                                  uint32_t *wv_a5 = wv + d0 * (uint32_t)4U;
                                  uint32_t *wv_b5 = wv + a * (uint32_t)4U;
                                  {
                                    uint32_t i;
                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                    {
                                      uint32_t *os = wv_a5;
                                      uint32_t x1 = wv_a5[i] ^ wv_b5[i];
                                      os[i] = x1;
                                    }
                                  }
                                  {
                                    uint32_t *r14 = wv_a5;
                                    {
                                      uint32_t i;
                                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                      {
                                        uint32_t *os = r14;
                                        uint32_t x1 = r14[i];
                                        uint32_t x10 = x1 >> (uint32_t)8U | x1 << (uint32_t)24U;
                                        os[i] = x10;
                                      }
                                    }
                                    {
                                      uint32_t *wv_a6 = wv + c0 * (uint32_t)4U;
                                      uint32_t *wv_b6 = wv + d0 * (uint32_t)4U;
                                      {
                                        uint32_t i;
                                        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                        {
                                          uint32_t *os = wv_a6;
                                          uint32_t x1 = wv_a6[i] + wv_b6[i];
                                          os[i] = x1;
                                        }
                                      }
                                      {
                                        uint32_t *wv_a7 = wv + b0 * (uint32_t)4U;
                                        uint32_t *wv_b7 = wv + c0 * (uint32_t)4U;
                                        {
                                          uint32_t i;
                                          for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                          {
                                            uint32_t *os = wv_a7;
                                            uint32_t x1 = wv_a7[i] ^ wv_b7[i];
                                            os[i] = x1;
                                          }
                                        }
                                        {
                                          uint32_t *r15 = wv_a7;
                                          {
                                            uint32_t i;
                                            for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                            {
                                              uint32_t *os = r15;
                                              uint32_t x1 = r15[i];
                                              uint32_t
                                              x10 = x1 >> (uint32_t)7U | x1 << (uint32_t)25U;
                                              os[i] = x10;
                                            }
                                          }
                                          {
                                            uint32_t *r16 = wv + (uint32_t)1U * (uint32_t)4U;
                                            uint32_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
                                            uint32_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
                                            uint32_t *r110 = r16;
                                            uint32_t x00 = r110[1U];
                                            uint32_t
                                            x10 = r110[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
                                            uint32_t
                                            x20 = r110[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
                                            uint32_t
                                            x30 = r110[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
                                            r110[0U] = x00;
                                            r110[1U] = x10;
                                            r110[2U] = x20;
                                            r110[3U] = x30;
                                            {
                                              uint32_t *r111 = r22;
                                              uint32_t x01 = r111[2U];
                                              uint32_t
                                              x11 =
                                                r111[((uint32_t)2U + (uint32_t)1U)
                                                % (uint32_t)4U];
                                              uint32_t
                                              x21 =
                                                r111[((uint32_t)2U + (uint32_t)2U)
                                                % (uint32_t)4U];
                                              uint32_t
                                              x31 =
                                                r111[((uint32_t)2U + (uint32_t)3U)
                                                % (uint32_t)4U];
                                              r111[0U] = x01;
                                              r111[1U] = x11;
                                              r111[2U] = x21;
                                              r111[3U] = x31;
                                              {
                                                uint32_t *r112 = r32;
                                                uint32_t x02 = r112[3U];
                                                uint32_t
                                                x12 =
                                                  r112[((uint32_t)3U + (uint32_t)1U)
                                                  % (uint32_t)4U];
                                                uint32_t
                                                x22 =
                                                  r112[((uint32_t)3U + (uint32_t)2U)
                                                  % (uint32_t)4U];
                                                uint32_t
                                                x32 =
                                                  r112[((uint32_t)3U + (uint32_t)3U)
                                                  % (uint32_t)4U];
                                                r112[0U] = x02;
                                                r112[1U] = x12;
                                                r112[2U] = x22;
                                                r112[3U] = x32;
                                                {
                                                  uint32_t a0 = (uint32_t)0U;
                                                  uint32_t b = (uint32_t)1U;
                                                  uint32_t c = (uint32_t)2U;
                                                  uint32_t d = (uint32_t)3U;
                                                  uint32_t *wv_a = wv + a0 * (uint32_t)4U;
                                                  uint32_t *wv_b8 = wv + b * (uint32_t)4U;
                                                  {
                                                    uint32_t i;
                                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                    {
                                                      uint32_t *os = wv_a;
                                                      uint32_t x1 = wv_a[i] + wv_b8[i];
                                                      os[i] = x1;
                                                    }
                                                  }
                                                  {
                                                    uint32_t i;
                                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                    {
                                                      uint32_t *os = wv_a;
                                                      uint32_t x1 = wv_a[i] + z[i];
                                                      os[i] = x1;
                                                    }
                                                  }
                                                  {
                                                    uint32_t *wv_a8 = wv + d * (uint32_t)4U;
                                                    uint32_t *wv_b9 = wv + a0 * (uint32_t)4U;
                                                    {
                                                      uint32_t i;
                                                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                      {
                                                        uint32_t *os = wv_a8;
                                                        uint32_t x1 = wv_a8[i] ^ wv_b9[i];
                                                        os[i] = x1;
                                                      }
                                                    }
                                                    {
                                                      uint32_t *r17 = wv_a8;
                                                      {
                                                        uint32_t i;
                                                        for
                                                        (i
                                                          = (uint32_t)0U;
                                                          i
                                                          < (uint32_t)4U;
                                                          i++)
                                                        {
                                                          uint32_t *os = r17;
                                                          uint32_t x1 = r17[i];
                                                          uint32_t
                                                          x13 =
                                                            x1
                                                            >> (uint32_t)16U
                                                            | x1 << (uint32_t)16U;
                                                          os[i] = x13;
                                                        }
                                                      }
                                                      {
                                                        uint32_t *wv_a9 = wv + c * (uint32_t)4U;
                                                        uint32_t *wv_b10 = wv + d * (uint32_t)4U;
                                                        {
                                                          uint32_t i;
                                                          for
                                                          (i
                                                            = (uint32_t)0U;
                                                            i
                                                            < (uint32_t)4U;
                                                            i++)
                                                          {
                                                            uint32_t *os = wv_a9;
                                                            uint32_t x1 = wv_a9[i] + wv_b10[i];
                                                            os[i] = x1;
                                                          }
                                                        }
                                                        {
                                                          uint32_t *wv_a10 = wv + b * (uint32_t)4U;
                                                          uint32_t *wv_b11 = wv + c * (uint32_t)4U;
                                                          {
                                                            uint32_t i;
                                                            for
                                                            (i
                                                              = (uint32_t)0U;
                                                              i
                                                              < (uint32_t)4U;
                                                              i++)
                                                            {
                                                              uint32_t *os = wv_a10;
                                                              uint32_t x1 = wv_a10[i] ^ wv_b11[i];
                                                              os[i] = x1;
                                                            }
                                                          }
                                                          {
                                                            uint32_t *r18 = wv_a10;
                                                            {
                                                              uint32_t i;
                                                              for
                                                              (i
                                                                = (uint32_t)0U;
                                                                i
                                                                < (uint32_t)4U;
                                                                i++)
                                                              {
                                                                uint32_t *os = r18;
                                                                uint32_t x1 = r18[i];
                                                                uint32_t
                                                                x13 =
                                                                  x1
                                                                  >> (uint32_t)12U
                                                                  | x1 << (uint32_t)20U;
                                                                os[i] = x13;
                                                              }
                                                            }
                                                            {
                                                              uint32_t
                                                              *wv_a11 = wv + a0 * (uint32_t)4U;
                                                              uint32_t
                                                              *wv_b12 = wv + b * (uint32_t)4U;
                                                              {
                                                                uint32_t i;
                                                                for
                                                                (i
                                                                  = (uint32_t)0U;
                                                                  i
                                                                  < (uint32_t)4U;
                                                                  i++)
                                                                {
                                                                  uint32_t *os = wv_a11;
                                                                  uint32_t
                                                                  x1 = wv_a11[i] + wv_b12[i];
                                                                  os[i] = x1;
                                                                }
                                                              }
                                                              {
                                                                uint32_t i;
                                                                for
                                                                (i
                                                                  = (uint32_t)0U;
                                                                  i
                                                                  < (uint32_t)4U;
                                                                  i++)
                                                                {
                                                                  uint32_t *os = wv_a11;
                                                                  uint32_t x1 = wv_a11[i] + w[i];
                                                                  os[i] = x1;
                                                                }
                                                              }
                                                              {
                                                                uint32_t
                                                                *wv_a12 = wv + d * (uint32_t)4U;
                                                                uint32_t
                                                                *wv_b13 = wv + a0 * (uint32_t)4U;
                                                                {
                                                                  uint32_t i;
                                                                  for
                                                                  (i
                                                                    = (uint32_t)0U;
                                                                    i
                                                                    < (uint32_t)4U;
                                                                    i++)
                                                                  {
                                                                    uint32_t *os = wv_a12;
                                                                    uint32_t
                                                                    x1 = wv_a12[i] ^ wv_b13[i];
                                                                    os[i] = x1;
                                                                  }
                                                                }
                                                                {
                                                                  uint32_t *r19 = wv_a12;
                                                                  {
                                                                    uint32_t i;
                                                                    for
                                                                    (i
                                                                      = (uint32_t)0U;
                                                                      i
                                                                      < (uint32_t)4U;
                                                                      i++)
                                                                    {
                                                                      uint32_t *os = r19;
                                                                      uint32_t x1 = r19[i];
                                                                      uint32_t
                                                                      x13 =
                                                                        x1
                                                                        >> (uint32_t)8U
                                                                        | x1 << (uint32_t)24U;
                                                                      os[i] = x13;
                                                                    }
                                                                  }
                                                                  {
                                                                    uint32_t
                                                                    *wv_a13 = wv + c * (uint32_t)4U;
                                                                    uint32_t
                                                                    *wv_b14 = wv + d * (uint32_t)4U;
                                                                    {
                                                                      uint32_t i;
                                                                      for
                                                                      (i
                                                                        = (uint32_t)0U;
                                                                        i
                                                                        < (uint32_t)4U;
                                                                        i++)
                                                                      {
                                                                        uint32_t *os = wv_a13;
                                                                        uint32_t
                                                                        x1 = wv_a13[i] + wv_b14[i];
                                                                        os[i] = x1;
                                                                      }
                                                                    }
                                                                    {
                                                                      uint32_t
                                                                      *wv_a14 =
                                                                        wv
                                                                        + b * (uint32_t)4U;
                                                                      uint32_t
                                                                      *wv_b = wv + c * (uint32_t)4U;
                                                                      {
                                                                        uint32_t i;
                                                                        for
                                                                        (i
                                                                          = (uint32_t)0U;
                                                                          i
                                                                          < (uint32_t)4U;
                                                                          i++)
                                                                        {
                                                                          uint32_t *os = wv_a14;
                                                                          uint32_t
                                                                          x1 = wv_a14[i] ^ wv_b[i];
                                                                          os[i] = x1;
                                                                        }
                                                                      }
                                                                      {
                                                                        uint32_t *r113 = wv_a14;
                                                                        {
                                                                          uint32_t i;
                                                                          for
                                                                          (i
                                                                            = (uint32_t)0U;
                                                                            i
                                                                            < (uint32_t)4U;
                                                                            i++)
                                                                          {
                                                                            uint32_t *os = r113;
                                                                            uint32_t x1 = r113[i];
                                                                            uint32_t
                                                                            x13 =
                                                                              x1
                                                                              >> (uint32_t)7U
                                                                              | x1 << (uint32_t)25U;
                                                                            os[i] = x13;
                                                                          }
                                                                        }
                                                                        {
                                                                          uint32_t
                                                                          *r114 =
                                                                            wv
                                                                            +
                                                                              (uint32_t)1U
                                                                              * (uint32_t)4U;
                                                                          uint32_t
                                                                          *r2 =
                                                                            wv
                                                                            +
                                                                              (uint32_t)2U
                                                                              * (uint32_t)4U;
                                                                          uint32_t
                                                                          *r3 =
                                                                            wv
                                                                            +
                                                                              (uint32_t)3U
                                                                              * (uint32_t)4U;
                                                                          uint32_t *r11 = r114;
                                                                          uint32_t x03 = r11[3U];
                                                                          uint32_t
                                                                          x13 =
                                                                            r11[((uint32_t)3U
                                                                            + (uint32_t)1U)
                                                                            % (uint32_t)4U];
                                                                          uint32_t
                                                                          x23 =
                                                                            r11[((uint32_t)3U
                                                                            + (uint32_t)2U)
                                                                            % (uint32_t)4U];
                                                                          uint32_t
                                                                          x33 =
                                                                            r11[((uint32_t)3U
                                                                            + (uint32_t)3U)
                                                                            % (uint32_t)4U];
                                                                          r11[0U] = x03;
                                                                          r11[1U] = x13;
                                                                          r11[2U] = x23;
                                                                          r11[3U] = x33;
                                                                          {
                                                                            uint32_t *r115 = r2;
                                                                            uint32_t x04 = r115[2U];
                                                                            uint32_t
                                                                            x14 =
                                                                              r115[((uint32_t)2U
                                                                              + (uint32_t)1U)
                                                                              % (uint32_t)4U];
                                                                            uint32_t
                                                                            x24 =
                                                                              r115[((uint32_t)2U
                                                                              + (uint32_t)2U)
                                                                              % (uint32_t)4U];
                                                                            uint32_t
                                                                            x34 =
                                                                              r115[((uint32_t)2U
                                                                              + (uint32_t)3U)
                                                                              % (uint32_t)4U];
                                                                            r115[0U] = x04;
                                                                            r115[1U] = x14;
                                                                            r115[2U] = x24;
                                                                            r115[3U] = x34;
                                                                            {
                                                                              uint32_t *r116 = r3;
                                                                              uint32_t
                                                                              x0 = r116[1U];
                                                                              uint32_t
                                                                              x1 =
                                                                                r116[((uint32_t)1U
                                                                                + (uint32_t)1U)
                                                                                % (uint32_t)4U];
                                                                              uint32_t
                                                                              x2 =
                                                                                r116[((uint32_t)1U
                                                                                + (uint32_t)2U)
                                                                                % (uint32_t)4U];
                                                                              uint32_t
                                                                              x3 =
                                                                                r116[((uint32_t)1U
                                                                                + (uint32_t)3U)
                                                                                % (uint32_t)4U];
                                                                              r116[0U] = x0;
                                                                              r116[1U] = x1;
                                                                              r116[2U] = x2;
                                                                              r116[3U] = x3;
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    s00 = s + (uint32_t)0U * (uint32_t)4U;
    s16 = s + (uint32_t)1U * (uint32_t)4U;
    r00 = wv + (uint32_t)0U * (uint32_t)4U;
    r10 = wv + (uint32_t)1U * (uint32_t)4U;
    r20 = wv + (uint32_t)2U * (uint32_t)4U;
    r30 = wv + (uint32_t)3U * (uint32_t)4U;
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint32_t *os = s00;
        uint32_t x = s00[i] ^ r00[i];
        os[i] = x;
      }
    }
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint32_t *os = s00;
        uint32_t x = s00[i] ^ r20[i];
        os[i] = x;
      }
    }
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint32_t *os = s16;
        uint32_t x = s16[i] ^ r10[i];
        os[i] = x;
      }
    }
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint32_t *os = s16;
        uint32_t x = s16[i] ^ r30[i];
        os[i] = x;
      }
    }
    return totlen1;
  }
}

void Hacl_Hash_Core_Blake2_finish_blake2s_32(uint32_t *s, uint64_t ev, uint8_t *dst)
{
  uint32_t double_row = (uint32_t)2U * ((uint32_t)4U * (uint32_t)4U);
  KRML_CHECK_SIZE(sizeof (uint8_t), double_row);
  {
    uint8_t b[double_row];
    memset(b, 0U, double_row * sizeof (uint8_t));
    {
      uint8_t *first = b;
      uint8_t *second = b + (uint32_t)4U * (uint32_t)4U;
      uint32_t *row0 = s + (uint32_t)0U * (uint32_t)4U;
      uint32_t *row1 = s + (uint32_t)1U * (uint32_t)4U;
      uint8_t *final;
      {
        uint32_t i;
        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
        {
          store32_le(first + i * (uint32_t)4U, row0[i]);
        }
      }
      {
        uint32_t i;
        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
        {
          store32_le(second + i * (uint32_t)4U, row1[i]);
        }
      }
      final = b;
      memcpy(dst, final, (uint32_t)32U * sizeof (uint8_t));
      Lib_Memzero0_memzero(b, double_row * sizeof (b[0U]));
    }
  }
}

FStar_UInt128_uint128
Hacl_Hash_Core_Blake2_update_blake2b_32(
  uint64_t *s,
  FStar_UInt128_uint128 totlen,
  uint8_t *block
)
{
  uint64_t wv[16U] = { 0U };
  FStar_UInt128_uint128
  totlen1 =
    FStar_UInt128_add_mod(totlen,
      FStar_UInt128_uint64_to_uint128((uint64_t)(uint32_t)128U));
  uint64_t m_w[16U] = { 0U };
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < (uint32_t)16U; i++)
    {
      uint64_t *os = m_w;
      uint8_t *bj = block + i * (uint32_t)8U;
      uint64_t u = load64_le(bj);
      uint64_t r = u;
      uint64_t x = r;
      os[i] = x;
    }
  }
  {
    uint64_t mask[4U] = { 0U };
    uint64_t wv_14 = (uint64_t)0U;
    uint64_t wv_15 = (uint64_t)0U;
    uint64_t *wv3;
    uint64_t *s00;
    uint64_t *s16;
    uint64_t *r00;
    uint64_t *r10;
    uint64_t *r20;
    uint64_t *r30;
    mask[0U] = FStar_UInt128_uint128_to_uint64(totlen1);
    mask[1U] = FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(totlen1, (uint32_t)64U));
    mask[2U] = wv_14;
    mask[3U] = wv_15;
    memcpy(wv, s, (uint32_t)4U * (uint32_t)4U * sizeof (uint64_t));
    wv3 = wv + (uint32_t)3U * (uint32_t)4U;
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint64_t *os = wv3;
        uint64_t x = wv3[i] ^ mask[i];
        os[i] = x;
      }
    }
    {
      uint32_t i0;
      for (i0 = (uint32_t)0U; i0 < (uint32_t)12U; i0++)
      {
        uint32_t start_idx = i0 % (uint32_t)10U * (uint32_t)16U;
        KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
        {
          uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
          memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (uint64_t));
          {
            uint64_t *r0 = m_st + (uint32_t)0U * (uint32_t)4U;
            uint64_t *r1 = m_st + (uint32_t)1U * (uint32_t)4U;
            uint64_t *r21 = m_st + (uint32_t)2U * (uint32_t)4U;
            uint64_t *r31 = m_st + (uint32_t)3U * (uint32_t)4U;
            uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
            uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
            uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
            uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
            uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
            uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
            uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
            uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
            uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
            uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
            uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
            uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
            uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
            uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
            uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
            uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
            uint64_t uu____0 = m_w[s2];
            uint64_t uu____1 = m_w[s4];
            uint64_t uu____2 = m_w[s6];
            r0[0U] = m_w[s0];
            r0[1U] = uu____0;
            r0[2U] = uu____1;
            r0[3U] = uu____2;
            {
              uint64_t uu____3 = m_w[s3];
              uint64_t uu____4 = m_w[s5];
              uint64_t uu____5 = m_w[s7];
              r1[0U] = m_w[s1];
              r1[1U] = uu____3;
              r1[2U] = uu____4;
              r1[3U] = uu____5;
              {
                uint64_t uu____6 = m_w[s10];
                uint64_t uu____7 = m_w[s12];
                uint64_t uu____8 = m_w[s14];
                r21[0U] = m_w[s8];
                r21[1U] = uu____6;
                r21[2U] = uu____7;
                r21[3U] = uu____8;
                {
                  uint64_t uu____9 = m_w[s11];
                  uint64_t uu____10 = m_w[s13];
                  uint64_t uu____11 = m_w[s15];
                  r31[0U] = m_w[s9];
                  r31[1U] = uu____9;
                  r31[2U] = uu____10;
                  r31[3U] = uu____11;
                  {
                    uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
                    uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
                    uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
                    uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
                    uint32_t a = (uint32_t)0U;
                    uint32_t b0 = (uint32_t)1U;
                    uint32_t c0 = (uint32_t)2U;
                    uint32_t d0 = (uint32_t)3U;
                    uint64_t *wv_a0 = wv + a * (uint32_t)4U;
                    uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
                    {
                      uint32_t i;
                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                      {
                        uint64_t *os = wv_a0;
                        uint64_t x1 = wv_a0[i] + wv_b0[i];
                        os[i] = x1;
                      }
                    }
                    {
                      uint32_t i;
                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                      {
                        uint64_t *os = wv_a0;
                        uint64_t x1 = wv_a0[i] + x[i];
                        os[i] = x1;
                      }
                    }
                    {
                      uint64_t *wv_a1 = wv + d0 * (uint32_t)4U;
                      uint64_t *wv_b1 = wv + a * (uint32_t)4U;
                      {
                        uint32_t i;
                        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                        {
                          uint64_t *os = wv_a1;
                          uint64_t x1 = wv_a1[i] ^ wv_b1[i];
                          os[i] = x1;
                        }
                      }
                      {
                        uint64_t *r12 = wv_a1;
                        {
                          uint32_t i;
                          for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                          {
                            uint64_t *os = r12;
                            uint64_t x1 = r12[i];
                            uint64_t x10 = x1 >> (uint32_t)32U | x1 << (uint32_t)32U;
                            os[i] = x10;
                          }
                        }
                        {
                          uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
                          uint64_t *wv_b2 = wv + d0 * (uint32_t)4U;
                          {
                            uint32_t i;
                            for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                            {
                              uint64_t *os = wv_a2;
                              uint64_t x1 = wv_a2[i] + wv_b2[i];
                              os[i] = x1;
                            }
                          }
                          {
                            uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
                            uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
                            {
                              uint32_t i;
                              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                              {
                                uint64_t *os = wv_a3;
                                uint64_t x1 = wv_a3[i] ^ wv_b3[i];
                                os[i] = x1;
                              }
                            }
                            {
                              uint64_t *r13 = wv_a3;
                              {
                                uint32_t i;
                                for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                {
                                  uint64_t *os = r13;
                                  uint64_t x1 = r13[i];
                                  uint64_t x10 = x1 >> (uint32_t)24U | x1 << (uint32_t)40U;
                                  os[i] = x10;
                                }
                              }
                              {
                                uint64_t *wv_a4 = wv + a * (uint32_t)4U;
                                uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
                                {
                                  uint32_t i;
                                  for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                  {
                                    uint64_t *os = wv_a4;
                                    uint64_t x1 = wv_a4[i] + wv_b4[i];
                                    os[i] = x1;
                                  }
                                }
                                {
                                  uint32_t i;
                                  for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                  {
                                    uint64_t *os = wv_a4;
                                    uint64_t x1 = wv_a4[i] + y[i];
                                    os[i] = x1;
                                  }
                                }
                                {
                                  uint64_t *wv_a5 = wv + d0 * (uint32_t)4U;
                                  uint64_t *wv_b5 = wv + a * (uint32_t)4U;
                                  {
                                    uint32_t i;
                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                    {
                                      uint64_t *os = wv_a5;
                                      uint64_t x1 = wv_a5[i] ^ wv_b5[i];
                                      os[i] = x1;
                                    }
                                  }
                                  {
                                    uint64_t *r14 = wv_a5;
                                    {
                                      uint32_t i;
                                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                      {
                                        uint64_t *os = r14;
                                        uint64_t x1 = r14[i];
                                        uint64_t x10 = x1 >> (uint32_t)16U | x1 << (uint32_t)48U;
                                        os[i] = x10;
                                      }
                                    }
                                    {
                                      uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
                                      uint64_t *wv_b6 = wv + d0 * (uint32_t)4U;
                                      {
                                        uint32_t i;
                                        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                        {
                                          uint64_t *os = wv_a6;
                                          uint64_t x1 = wv_a6[i] + wv_b6[i];
                                          os[i] = x1;
                                        }
                                      }
                                      {
                                        uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
                                        uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
                                        {
                                          uint32_t i;
                                          for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                          {
                                            uint64_t *os = wv_a7;
                                            uint64_t x1 = wv_a7[i] ^ wv_b7[i];
                                            os[i] = x1;
                                          }
                                        }
                                        {
                                          uint64_t *r15 = wv_a7;
                                          {
                                            uint32_t i;
                                            for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                            {
                                              uint64_t *os = r15;
                                              uint64_t x1 = r15[i];
                                              uint64_t
                                              x10 = x1 >> (uint32_t)63U | x1 << (uint32_t)1U;
                                              os[i] = x10;
                                            }
                                          }
                                          {
                                            uint64_t *r16 = wv + (uint32_t)1U * (uint32_t)4U;
                                            uint64_t *r22 = wv + (uint32_t)2U * (uint32_t)4U;
                                            uint64_t *r32 = wv + (uint32_t)3U * (uint32_t)4U;
                                            uint64_t *r110 = r16;
                                            uint64_t x00 = r110[1U];
                                            uint64_t
                                            x10 = r110[((uint32_t)1U + (uint32_t)1U) % (uint32_t)4U];
                                            uint64_t
                                            x20 = r110[((uint32_t)1U + (uint32_t)2U) % (uint32_t)4U];
                                            uint64_t
                                            x30 = r110[((uint32_t)1U + (uint32_t)3U) % (uint32_t)4U];
                                            r110[0U] = x00;
                                            r110[1U] = x10;
                                            r110[2U] = x20;
                                            r110[3U] = x30;
                                            {
                                              uint64_t *r111 = r22;
                                              uint64_t x01 = r111[2U];
                                              uint64_t
                                              x11 =
                                                r111[((uint32_t)2U + (uint32_t)1U)
                                                % (uint32_t)4U];
                                              uint64_t
                                              x21 =
                                                r111[((uint32_t)2U + (uint32_t)2U)
                                                % (uint32_t)4U];
                                              uint64_t
                                              x31 =
                                                r111[((uint32_t)2U + (uint32_t)3U)
                                                % (uint32_t)4U];
                                              r111[0U] = x01;
                                              r111[1U] = x11;
                                              r111[2U] = x21;
                                              r111[3U] = x31;
                                              {
                                                uint64_t *r112 = r32;
                                                uint64_t x02 = r112[3U];
                                                uint64_t
                                                x12 =
                                                  r112[((uint32_t)3U + (uint32_t)1U)
                                                  % (uint32_t)4U];
                                                uint64_t
                                                x22 =
                                                  r112[((uint32_t)3U + (uint32_t)2U)
                                                  % (uint32_t)4U];
                                                uint64_t
                                                x32 =
                                                  r112[((uint32_t)3U + (uint32_t)3U)
                                                  % (uint32_t)4U];
                                                r112[0U] = x02;
                                                r112[1U] = x12;
                                                r112[2U] = x22;
                                                r112[3U] = x32;
                                                {
                                                  uint32_t a0 = (uint32_t)0U;
                                                  uint32_t b = (uint32_t)1U;
                                                  uint32_t c = (uint32_t)2U;
                                                  uint32_t d = (uint32_t)3U;
                                                  uint64_t *wv_a = wv + a0 * (uint32_t)4U;
                                                  uint64_t *wv_b8 = wv + b * (uint32_t)4U;
                                                  {
                                                    uint32_t i;
                                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                    {
                                                      uint64_t *os = wv_a;
                                                      uint64_t x1 = wv_a[i] + wv_b8[i];
                                                      os[i] = x1;
                                                    }
                                                  }
                                                  {
                                                    uint32_t i;
                                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                    {
                                                      uint64_t *os = wv_a;
                                                      uint64_t x1 = wv_a[i] + z[i];
                                                      os[i] = x1;
                                                    }
                                                  }
                                                  {
                                                    uint64_t *wv_a8 = wv + d * (uint32_t)4U;
                                                    uint64_t *wv_b9 = wv + a0 * (uint32_t)4U;
                                                    {
                                                      uint32_t i;
                                                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                      {
                                                        uint64_t *os = wv_a8;
                                                        uint64_t x1 = wv_a8[i] ^ wv_b9[i];
                                                        os[i] = x1;
                                                      }
                                                    }
                                                    {
                                                      uint64_t *r17 = wv_a8;
                                                      {
                                                        uint32_t i;
                                                        for
                                                        (i
                                                          = (uint32_t)0U;
                                                          i
                                                          < (uint32_t)4U;
                                                          i++)
                                                        {
                                                          uint64_t *os = r17;
                                                          uint64_t x1 = r17[i];
                                                          uint64_t
                                                          x13 =
                                                            x1
                                                            >> (uint32_t)32U
                                                            | x1 << (uint32_t)32U;
                                                          os[i] = x13;
                                                        }
                                                      }
                                                      {
                                                        uint64_t *wv_a9 = wv + c * (uint32_t)4U;
                                                        uint64_t *wv_b10 = wv + d * (uint32_t)4U;
                                                        {
                                                          uint32_t i;
                                                          for
                                                          (i
                                                            = (uint32_t)0U;
                                                            i
                                                            < (uint32_t)4U;
                                                            i++)
                                                          {
                                                            uint64_t *os = wv_a9;
                                                            uint64_t x1 = wv_a9[i] + wv_b10[i];
                                                            os[i] = x1;
                                                          }
                                                        }
                                                        {
                                                          uint64_t *wv_a10 = wv + b * (uint32_t)4U;
                                                          uint64_t *wv_b11 = wv + c * (uint32_t)4U;
                                                          {
                                                            uint32_t i;
                                                            for
                                                            (i
                                                              = (uint32_t)0U;
                                                              i
                                                              < (uint32_t)4U;
                                                              i++)
                                                            {
                                                              uint64_t *os = wv_a10;
                                                              uint64_t x1 = wv_a10[i] ^ wv_b11[i];
                                                              os[i] = x1;
                                                            }
                                                          }
                                                          {
                                                            uint64_t *r18 = wv_a10;
                                                            {
                                                              uint32_t i;
                                                              for
                                                              (i
                                                                = (uint32_t)0U;
                                                                i
                                                                < (uint32_t)4U;
                                                                i++)
                                                              {
                                                                uint64_t *os = r18;
                                                                uint64_t x1 = r18[i];
                                                                uint64_t
                                                                x13 =
                                                                  x1
                                                                  >> (uint32_t)24U
                                                                  | x1 << (uint32_t)40U;
                                                                os[i] = x13;
                                                              }
                                                            }
                                                            {
                                                              uint64_t
                                                              *wv_a11 = wv + a0 * (uint32_t)4U;
                                                              uint64_t
                                                              *wv_b12 = wv + b * (uint32_t)4U;
                                                              {
                                                                uint32_t i;
                                                                for
                                                                (i
                                                                  = (uint32_t)0U;
                                                                  i
                                                                  < (uint32_t)4U;
                                                                  i++)
                                                                {
                                                                  uint64_t *os = wv_a11;
                                                                  uint64_t
                                                                  x1 = wv_a11[i] + wv_b12[i];
                                                                  os[i] = x1;
                                                                }
                                                              }
                                                              {
                                                                uint32_t i;
                                                                for
                                                                (i
                                                                  = (uint32_t)0U;
                                                                  i
                                                                  < (uint32_t)4U;
                                                                  i++)
                                                                {
                                                                  uint64_t *os = wv_a11;
                                                                  uint64_t x1 = wv_a11[i] + w[i];
                                                                  os[i] = x1;
                                                                }
                                                              }
                                                              {
                                                                uint64_t
                                                                *wv_a12 = wv + d * (uint32_t)4U;
                                                                uint64_t
                                                                *wv_b13 = wv + a0 * (uint32_t)4U;
                                                                {
                                                                  uint32_t i;
                                                                  for
                                                                  (i
                                                                    = (uint32_t)0U;
                                                                    i
                                                                    < (uint32_t)4U;
                                                                    i++)
                                                                  {
                                                                    uint64_t *os = wv_a12;
                                                                    uint64_t
                                                                    x1 = wv_a12[i] ^ wv_b13[i];
                                                                    os[i] = x1;
                                                                  }
                                                                }
                                                                {
                                                                  uint64_t *r19 = wv_a12;
                                                                  {
                                                                    uint32_t i;
                                                                    for
                                                                    (i
                                                                      = (uint32_t)0U;
                                                                      i
                                                                      < (uint32_t)4U;
                                                                      i++)
                                                                    {
                                                                      uint64_t *os = r19;
                                                                      uint64_t x1 = r19[i];
                                                                      uint64_t
                                                                      x13 =
                                                                        x1
                                                                        >> (uint32_t)16U
                                                                        | x1 << (uint32_t)48U;
                                                                      os[i] = x13;
                                                                    }
                                                                  }
                                                                  {
                                                                    uint64_t
                                                                    *wv_a13 = wv + c * (uint32_t)4U;
                                                                    uint64_t
                                                                    *wv_b14 = wv + d * (uint32_t)4U;
                                                                    {
                                                                      uint32_t i;
                                                                      for
                                                                      (i
                                                                        = (uint32_t)0U;
                                                                        i
                                                                        < (uint32_t)4U;
                                                                        i++)
                                                                      {
                                                                        uint64_t *os = wv_a13;
                                                                        uint64_t
                                                                        x1 = wv_a13[i] + wv_b14[i];
                                                                        os[i] = x1;
                                                                      }
                                                                    }
                                                                    {
                                                                      uint64_t
                                                                      *wv_a14 =
                                                                        wv
                                                                        + b * (uint32_t)4U;
                                                                      uint64_t
                                                                      *wv_b = wv + c * (uint32_t)4U;
                                                                      {
                                                                        uint32_t i;
                                                                        for
                                                                        (i
                                                                          = (uint32_t)0U;
                                                                          i
                                                                          < (uint32_t)4U;
                                                                          i++)
                                                                        {
                                                                          uint64_t *os = wv_a14;
                                                                          uint64_t
                                                                          x1 = wv_a14[i] ^ wv_b[i];
                                                                          os[i] = x1;
                                                                        }
                                                                      }
                                                                      {
                                                                        uint64_t *r113 = wv_a14;
                                                                        {
                                                                          uint32_t i;
                                                                          for
                                                                          (i
                                                                            = (uint32_t)0U;
                                                                            i
                                                                            < (uint32_t)4U;
                                                                            i++)
                                                                          {
                                                                            uint64_t *os = r113;
                                                                            uint64_t x1 = r113[i];
                                                                            uint64_t
                                                                            x13 =
                                                                              x1
                                                                              >> (uint32_t)63U
                                                                              | x1 << (uint32_t)1U;
                                                                            os[i] = x13;
                                                                          }
                                                                        }
                                                                        {
                                                                          uint64_t
                                                                          *r114 =
                                                                            wv
                                                                            +
                                                                              (uint32_t)1U
                                                                              * (uint32_t)4U;
                                                                          uint64_t
                                                                          *r2 =
                                                                            wv
                                                                            +
                                                                              (uint32_t)2U
                                                                              * (uint32_t)4U;
                                                                          uint64_t
                                                                          *r3 =
                                                                            wv
                                                                            +
                                                                              (uint32_t)3U
                                                                              * (uint32_t)4U;
                                                                          uint64_t *r11 = r114;
                                                                          uint64_t x03 = r11[3U];
                                                                          uint64_t
                                                                          x13 =
                                                                            r11[((uint32_t)3U
                                                                            + (uint32_t)1U)
                                                                            % (uint32_t)4U];
                                                                          uint64_t
                                                                          x23 =
                                                                            r11[((uint32_t)3U
                                                                            + (uint32_t)2U)
                                                                            % (uint32_t)4U];
                                                                          uint64_t
                                                                          x33 =
                                                                            r11[((uint32_t)3U
                                                                            + (uint32_t)3U)
                                                                            % (uint32_t)4U];
                                                                          r11[0U] = x03;
                                                                          r11[1U] = x13;
                                                                          r11[2U] = x23;
                                                                          r11[3U] = x33;
                                                                          {
                                                                            uint64_t *r115 = r2;
                                                                            uint64_t x04 = r115[2U];
                                                                            uint64_t
                                                                            x14 =
                                                                              r115[((uint32_t)2U
                                                                              + (uint32_t)1U)
                                                                              % (uint32_t)4U];
                                                                            uint64_t
                                                                            x24 =
                                                                              r115[((uint32_t)2U
                                                                              + (uint32_t)2U)
                                                                              % (uint32_t)4U];
                                                                            uint64_t
                                                                            x34 =
                                                                              r115[((uint32_t)2U
                                                                              + (uint32_t)3U)
                                                                              % (uint32_t)4U];
                                                                            r115[0U] = x04;
                                                                            r115[1U] = x14;
                                                                            r115[2U] = x24;
                                                                            r115[3U] = x34;
                                                                            {
                                                                              uint64_t *r116 = r3;
                                                                              uint64_t
                                                                              x0 = r116[1U];
                                                                              uint64_t
                                                                              x1 =
                                                                                r116[((uint32_t)1U
                                                                                + (uint32_t)1U)
                                                                                % (uint32_t)4U];
                                                                              uint64_t
                                                                              x2 =
                                                                                r116[((uint32_t)1U
                                                                                + (uint32_t)2U)
                                                                                % (uint32_t)4U];
                                                                              uint64_t
                                                                              x3 =
                                                                                r116[((uint32_t)1U
                                                                                + (uint32_t)3U)
                                                                                % (uint32_t)4U];
                                                                              r116[0U] = x0;
                                                                              r116[1U] = x1;
                                                                              r116[2U] = x2;
                                                                              r116[3U] = x3;
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    s00 = s + (uint32_t)0U * (uint32_t)4U;
    s16 = s + (uint32_t)1U * (uint32_t)4U;
    r00 = wv + (uint32_t)0U * (uint32_t)4U;
    r10 = wv + (uint32_t)1U * (uint32_t)4U;
    r20 = wv + (uint32_t)2U * (uint32_t)4U;
    r30 = wv + (uint32_t)3U * (uint32_t)4U;
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint64_t *os = s00;
        uint64_t x = s00[i] ^ r00[i];
        os[i] = x;
      }
    }
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint64_t *os = s00;
        uint64_t x = s00[i] ^ r20[i];
        os[i] = x;
      }
    }
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint64_t *os = s16;
        uint64_t x = s16[i] ^ r10[i];
        os[i] = x;
      }
    }
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
      {
        uint64_t *os = s16;
        uint64_t x = s16[i] ^ r30[i];
        os[i] = x;
      }
    }
    return totlen1;
  }
}

void
Hacl_Hash_Core_Blake2_finish_blake2b_32(uint64_t *s, FStar_UInt128_uint128 ev, uint8_t *dst)
{
  uint32_t double_row = (uint32_t)2U * ((uint32_t)4U * (uint32_t)8U);
  KRML_CHECK_SIZE(sizeof (uint8_t), double_row);
  {
    uint8_t b[double_row];
    memset(b, 0U, double_row * sizeof (uint8_t));
    {
      uint8_t *first = b;
      uint8_t *second = b + (uint32_t)4U * (uint32_t)8U;
      uint64_t *row0 = s + (uint32_t)0U * (uint32_t)4U;
      uint64_t *row1 = s + (uint32_t)1U * (uint32_t)4U;
      uint8_t *final;
      {
        uint32_t i;
        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
        {
          store64_le(first + i * (uint32_t)8U, row0[i]);
        }
      }
      {
        uint32_t i;
        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
        {
          store64_le(second + i * (uint32_t)8U, row1[i]);
        }
      }
      final = b;
      memcpy(dst, final, (uint32_t)64U * sizeof (uint8_t));
      Lib_Memzero0_memzero(b, double_row * sizeof (b[0U]));
    }
  }
}

uint64_t
Hacl_Hash_Blake2_update_multi_blake2s_32(
  uint32_t *s,
  uint64_t ev,
  uint8_t *blocks,
  uint32_t n_blocks
)
{
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < n_blocks; i++)
    {
      uint32_t sz = (uint32_t)64U;
      uint8_t *block = blocks + sz * i;
      uint64_t
      v_ =
        Hacl_Hash_Core_Blake2_update_blake2s_32(s,
          ev + (uint64_t)i * (uint64_t)(uint32_t)64U,
          block);
    }
  }
  return ev + (uint64_t)n_blocks * (uint64_t)(uint32_t)64U;
}

FStar_UInt128_uint128
Hacl_Hash_Blake2_update_multi_blake2b_32(
  uint64_t *s,
  FStar_UInt128_uint128 ev,
  uint8_t *blocks,
  uint32_t n_blocks
)
{
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < n_blocks; i++)
    {
      uint32_t sz = (uint32_t)128U;
      uint8_t *block = blocks + sz * i;
      FStar_UInt128_uint128
      v_ =
        Hacl_Hash_Core_Blake2_update_blake2b_32(s,
          FStar_UInt128_add_mod(ev,
            FStar_UInt128_uint64_to_uint128((uint64_t)i * (uint64_t)(uint32_t)128U)),
          block);
    }
  }
  return
    FStar_UInt128_add_mod(ev,
      FStar_UInt128_uint64_to_uint128((uint64_t)n_blocks * (uint64_t)(uint32_t)128U));
}

typedef struct __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t__s
{
  uint32_t fst;
  uint32_t snd;
  uint32_t thd;
  uint8_t *f3;
  uint8_t *f4;
}
__uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_;

typedef struct __uint32_t_uint32_t_uint32_t_s
{
  uint32_t fst;
  uint32_t snd;
  uint32_t thd;
}
__uint32_t_uint32_t_uint32_t;

uint64_t
Hacl_Hash_Blake2_update_last_blake2s_32(
  uint32_t *s,
  uint64_t ev,
  uint64_t prev_len,
  uint8_t *input,
  uint32_t input_len
)
{
  uint32_t blocks_n = input_len / (uint32_t)64U;
  uint32_t blocks_len0 = blocks_n * (uint32_t)64U;
  uint32_t rest_len0 = input_len - blocks_len0;
  __uint32_t_uint32_t_uint32_t scrut0;
  if (rest_len0 == (uint32_t)0U && blocks_n > (uint32_t)0U)
  {
    uint32_t blocks_n1 = blocks_n - (uint32_t)1U;
    uint32_t blocks_len1 = blocks_len0 - (uint32_t)64U;
    uint32_t rest_len1 = (uint32_t)64U;
    __uint32_t_uint32_t_uint32_t lit;
    lit.fst = blocks_n1;
    lit.snd = blocks_len1;
    lit.thd = rest_len1;
    scrut0 = lit;
  }
  else
  {
    __uint32_t_uint32_t_uint32_t lit;
    lit.fst = blocks_n;
    lit.snd = blocks_len0;
    lit.thd = rest_len0;
    scrut0 = lit;
  }
  {
    uint32_t num_blocks0 = scrut0.fst;
    uint32_t blocks_len = scrut0.snd;
    uint32_t rest_len1 = scrut0.thd;
    uint8_t *blocks0 = input;
    uint8_t *rest0 = input + blocks_len;
    __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_ lit;
    __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_ scrut;
    uint32_t num_blocks;
    uint32_t rest_len;
    uint8_t *blocks;
    uint8_t *rest;
    uint64_t ev_;
    lit.fst = num_blocks0;
    lit.snd = blocks_len;
    lit.thd = rest_len1;
    lit.f3 = blocks0;
    lit.f4 = rest0;
    scrut = lit;
    num_blocks = scrut.fst;
    rest_len = scrut.thd;
    blocks = scrut.f3;
    rest = scrut.f4;
    ev_ = Hacl_Hash_Blake2_update_multi_blake2s_32(s, ev, blocks, num_blocks);
    KRML_CHECK_SIZE(sizeof (uint32_t), (uint32_t)4U * (uint32_t)4U);
    {
      uint32_t wv[(uint32_t)4U * (uint32_t)4U];
      memset(wv, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (uint32_t));
      {
        uint8_t tmp[64U] = { 0U };
        uint8_t *tmp_rest = tmp;
        uint64_t totlen;
        memcpy(tmp_rest, rest, rest_len * sizeof (uint8_t));
        totlen = ev_ + (uint64_t)rest_len;
        {
          uint32_t m_w[16U] = { 0U };
          {
            uint32_t i;
            for (i = (uint32_t)0U; i < (uint32_t)16U; i++)
            {
              uint32_t *os = m_w;
              uint8_t *bj = tmp + i * (uint32_t)4U;
              uint32_t u = load32_le(bj);
              uint32_t r = u;
              uint32_t x = r;
              os[i] = x;
            }
          }
          {
            uint32_t mask[4U] = { 0U };
            uint32_t wv_14 = (uint32_t)0xFFFFFFFFU;
            uint32_t wv_15 = (uint32_t)0U;
            uint32_t *wv3;
            uint32_t *s00;
            uint32_t *s16;
            uint32_t *r00;
            uint32_t *r10;
            uint32_t *r20;
            uint32_t *r30;
            mask[0U] = (uint32_t)totlen;
            mask[1U] = (uint32_t)(totlen >> (uint32_t)32U);
            mask[2U] = wv_14;
            mask[3U] = wv_15;
            memcpy(wv, s, (uint32_t)4U * (uint32_t)4U * sizeof (uint32_t));
            wv3 = wv + (uint32_t)3U * (uint32_t)4U;
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint32_t *os = wv3;
                uint32_t x = wv3[i] ^ mask[i];
                os[i] = x;
              }
            }
            {
              uint32_t i0;
              for (i0 = (uint32_t)0U; i0 < (uint32_t)10U; i0++)
              {
                uint32_t start_idx = i0 % (uint32_t)10U * (uint32_t)16U;
                KRML_CHECK_SIZE(sizeof (uint32_t), (uint32_t)4U * (uint32_t)4U);
                {
                  uint32_t m_st[(uint32_t)4U * (uint32_t)4U];
                  memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (uint32_t));
                  {
                    uint32_t *r0 = m_st + (uint32_t)0U * (uint32_t)4U;
                    uint32_t *r1 = m_st + (uint32_t)1U * (uint32_t)4U;
                    uint32_t *r21 = m_st + (uint32_t)2U * (uint32_t)4U;
                    uint32_t *r31 = m_st + (uint32_t)3U * (uint32_t)4U;
                    uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
                    uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
                    uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
                    uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
                    uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
                    uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
                    uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
                    uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
                    uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
                    uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
                    uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
                    uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
                    uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
                    uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
                    uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
                    uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
                    uint32_t uu____0 = m_w[s2];
                    uint32_t uu____1 = m_w[s4];
                    uint32_t uu____2 = m_w[s6];
                    r0[0U] = m_w[s0];
                    r0[1U] = uu____0;
                    r0[2U] = uu____1;
                    r0[3U] = uu____2;
                    {
                      uint32_t uu____3 = m_w[s3];
                      uint32_t uu____4 = m_w[s5];
                      uint32_t uu____5 = m_w[s7];
                      r1[0U] = m_w[s1];
                      r1[1U] = uu____3;
                      r1[2U] = uu____4;
                      r1[3U] = uu____5;
                      {
                        uint32_t uu____6 = m_w[s10];
                        uint32_t uu____7 = m_w[s12];
                        uint32_t uu____8 = m_w[s14];
                        r21[0U] = m_w[s8];
                        r21[1U] = uu____6;
                        r21[2U] = uu____7;
                        r21[3U] = uu____8;
                        {
                          uint32_t uu____9 = m_w[s11];
                          uint32_t uu____10 = m_w[s13];
                          uint32_t uu____11 = m_w[s15];
                          r31[0U] = m_w[s9];
                          r31[1U] = uu____9;
                          r31[2U] = uu____10;
                          r31[3U] = uu____11;
                          {
                            uint32_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
                            uint32_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
                            uint32_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
                            uint32_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
                            uint32_t a = (uint32_t)0U;
                            uint32_t b0 = (uint32_t)1U;
                            uint32_t c0 = (uint32_t)2U;
                            uint32_t d0 = (uint32_t)3U;
                            uint32_t *wv_a0 = wv + a * (uint32_t)4U;
                            uint32_t *wv_b0 = wv + b0 * (uint32_t)4U;
                            {
                              uint32_t i;
                              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                              {
                                uint32_t *os = wv_a0;
                                uint32_t x1 = wv_a0[i] + wv_b0[i];
                                os[i] = x1;
                              }
                            }
                            {
                              uint32_t i;
                              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                              {
                                uint32_t *os = wv_a0;
                                uint32_t x1 = wv_a0[i] + x[i];
                                os[i] = x1;
                              }
                            }
                            {
                              uint32_t *wv_a1 = wv + d0 * (uint32_t)4U;
                              uint32_t *wv_b1 = wv + a * (uint32_t)4U;
                              {
                                uint32_t i;
                                for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                {
                                  uint32_t *os = wv_a1;
                                  uint32_t x1 = wv_a1[i] ^ wv_b1[i];
                                  os[i] = x1;
                                }
                              }
                              {
                                uint32_t *r12 = wv_a1;
                                {
                                  uint32_t i;
                                  for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                  {
                                    uint32_t *os = r12;
                                    uint32_t x1 = r12[i];
                                    uint32_t x10 = x1 >> (uint32_t)16U | x1 << (uint32_t)16U;
                                    os[i] = x10;
                                  }
                                }
                                {
                                  uint32_t *wv_a2 = wv + c0 * (uint32_t)4U;
                                  uint32_t *wv_b2 = wv + d0 * (uint32_t)4U;
                                  {
                                    uint32_t i;
                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                    {
                                      uint32_t *os = wv_a2;
                                      uint32_t x1 = wv_a2[i] + wv_b2[i];
                                      os[i] = x1;
                                    }
                                  }
                                  {
                                    uint32_t *wv_a3 = wv + b0 * (uint32_t)4U;
                                    uint32_t *wv_b3 = wv + c0 * (uint32_t)4U;
                                    {
                                      uint32_t i;
                                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                      {
                                        uint32_t *os = wv_a3;
                                        uint32_t x1 = wv_a3[i] ^ wv_b3[i];
                                        os[i] = x1;
                                      }
                                    }
                                    {
                                      uint32_t *r13 = wv_a3;
                                      {
                                        uint32_t i;
                                        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                        {
                                          uint32_t *os = r13;
                                          uint32_t x1 = r13[i];
                                          uint32_t x10 = x1 >> (uint32_t)12U | x1 << (uint32_t)20U;
                                          os[i] = x10;
                                        }
                                      }
                                      {
                                        uint32_t *wv_a4 = wv + a * (uint32_t)4U;
                                        uint32_t *wv_b4 = wv + b0 * (uint32_t)4U;
                                        {
                                          uint32_t i;
                                          for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                          {
                                            uint32_t *os = wv_a4;
                                            uint32_t x1 = wv_a4[i] + wv_b4[i];
                                            os[i] = x1;
                                          }
                                        }
                                        {
                                          uint32_t i;
                                          for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                          {
                                            uint32_t *os = wv_a4;
                                            uint32_t x1 = wv_a4[i] + y[i];
                                            os[i] = x1;
                                          }
                                        }
                                        {
                                          uint32_t *wv_a5 = wv + d0 * (uint32_t)4U;
                                          uint32_t *wv_b5 = wv + a * (uint32_t)4U;
                                          {
                                            uint32_t i;
                                            for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                            {
                                              uint32_t *os = wv_a5;
                                              uint32_t x1 = wv_a5[i] ^ wv_b5[i];
                                              os[i] = x1;
                                            }
                                          }
                                          {
                                            uint32_t *r14 = wv_a5;
                                            {
                                              uint32_t i;
                                              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                              {
                                                uint32_t *os = r14;
                                                uint32_t x1 = r14[i];
                                                uint32_t
                                                x10 = x1 >> (uint32_t)8U | x1 << (uint32_t)24U;
                                                os[i] = x10;
                                              }
                                            }
                                            {
                                              uint32_t *wv_a6 = wv + c0 * (uint32_t)4U;
                                              uint32_t *wv_b6 = wv + d0 * (uint32_t)4U;
                                              {
                                                uint32_t i;
                                                for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                {
                                                  uint32_t *os = wv_a6;
                                                  uint32_t x1 = wv_a6[i] + wv_b6[i];
                                                  os[i] = x1;
                                                }
                                              }
                                              {
                                                uint32_t *wv_a7 = wv + b0 * (uint32_t)4U;
                                                uint32_t *wv_b7 = wv + c0 * (uint32_t)4U;
                                                {
                                                  uint32_t i;
                                                  for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                  {
                                                    uint32_t *os = wv_a7;
                                                    uint32_t x1 = wv_a7[i] ^ wv_b7[i];
                                                    os[i] = x1;
                                                  }
                                                }
                                                {
                                                  uint32_t *r15 = wv_a7;
                                                  {
                                                    uint32_t i;
                                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                    {
                                                      uint32_t *os = r15;
                                                      uint32_t x1 = r15[i];
                                                      uint32_t
                                                      x10 = x1 >> (uint32_t)7U | x1 << (uint32_t)25U;
                                                      os[i] = x10;
                                                    }
                                                  }
                                                  {
                                                    uint32_t
                                                    *r16 = wv + (uint32_t)1U * (uint32_t)4U;
                                                    uint32_t
                                                    *r22 = wv + (uint32_t)2U * (uint32_t)4U;
                                                    uint32_t
                                                    *r32 = wv + (uint32_t)3U * (uint32_t)4U;
                                                    uint32_t *r110 = r16;
                                                    uint32_t x00 = r110[1U];
                                                    uint32_t
                                                    x10 =
                                                      r110[((uint32_t)1U + (uint32_t)1U)
                                                      % (uint32_t)4U];
                                                    uint32_t
                                                    x20 =
                                                      r110[((uint32_t)1U + (uint32_t)2U)
                                                      % (uint32_t)4U];
                                                    uint32_t
                                                    x30 =
                                                      r110[((uint32_t)1U + (uint32_t)3U)
                                                      % (uint32_t)4U];
                                                    r110[0U] = x00;
                                                    r110[1U] = x10;
                                                    r110[2U] = x20;
                                                    r110[3U] = x30;
                                                    {
                                                      uint32_t *r111 = r22;
                                                      uint32_t x01 = r111[2U];
                                                      uint32_t
                                                      x11 =
                                                        r111[((uint32_t)2U + (uint32_t)1U)
                                                        % (uint32_t)4U];
                                                      uint32_t
                                                      x21 =
                                                        r111[((uint32_t)2U + (uint32_t)2U)
                                                        % (uint32_t)4U];
                                                      uint32_t
                                                      x31 =
                                                        r111[((uint32_t)2U + (uint32_t)3U)
                                                        % (uint32_t)4U];
                                                      r111[0U] = x01;
                                                      r111[1U] = x11;
                                                      r111[2U] = x21;
                                                      r111[3U] = x31;
                                                      {
                                                        uint32_t *r112 = r32;
                                                        uint32_t x02 = r112[3U];
                                                        uint32_t
                                                        x12 =
                                                          r112[((uint32_t)3U + (uint32_t)1U)
                                                          % (uint32_t)4U];
                                                        uint32_t
                                                        x22 =
                                                          r112[((uint32_t)3U + (uint32_t)2U)
                                                          % (uint32_t)4U];
                                                        uint32_t
                                                        x32 =
                                                          r112[((uint32_t)3U + (uint32_t)3U)
                                                          % (uint32_t)4U];
                                                        r112[0U] = x02;
                                                        r112[1U] = x12;
                                                        r112[2U] = x22;
                                                        r112[3U] = x32;
                                                        {
                                                          uint32_t a0 = (uint32_t)0U;
                                                          uint32_t b = (uint32_t)1U;
                                                          uint32_t c = (uint32_t)2U;
                                                          uint32_t d = (uint32_t)3U;
                                                          uint32_t *wv_a = wv + a0 * (uint32_t)4U;
                                                          uint32_t *wv_b8 = wv + b * (uint32_t)4U;
                                                          {
                                                            uint32_t i;
                                                            for
                                                            (i
                                                              = (uint32_t)0U;
                                                              i
                                                              < (uint32_t)4U;
                                                              i++)
                                                            {
                                                              uint32_t *os = wv_a;
                                                              uint32_t x1 = wv_a[i] + wv_b8[i];
                                                              os[i] = x1;
                                                            }
                                                          }
                                                          {
                                                            uint32_t i;
                                                            for
                                                            (i
                                                              = (uint32_t)0U;
                                                              i
                                                              < (uint32_t)4U;
                                                              i++)
                                                            {
                                                              uint32_t *os = wv_a;
                                                              uint32_t x1 = wv_a[i] + z[i];
                                                              os[i] = x1;
                                                            }
                                                          }
                                                          {
                                                            uint32_t *wv_a8 = wv + d * (uint32_t)4U;
                                                            uint32_t
                                                            *wv_b9 = wv + a0 * (uint32_t)4U;
                                                            {
                                                              uint32_t i;
                                                              for
                                                              (i
                                                                = (uint32_t)0U;
                                                                i
                                                                < (uint32_t)4U;
                                                                i++)
                                                              {
                                                                uint32_t *os = wv_a8;
                                                                uint32_t x1 = wv_a8[i] ^ wv_b9[i];
                                                                os[i] = x1;
                                                              }
                                                            }
                                                            {
                                                              uint32_t *r17 = wv_a8;
                                                              {
                                                                uint32_t i;
                                                                for
                                                                (i
                                                                  = (uint32_t)0U;
                                                                  i
                                                                  < (uint32_t)4U;
                                                                  i++)
                                                                {
                                                                  uint32_t *os = r17;
                                                                  uint32_t x1 = r17[i];
                                                                  uint32_t
                                                                  x13 =
                                                                    x1
                                                                    >> (uint32_t)16U
                                                                    | x1 << (uint32_t)16U;
                                                                  os[i] = x13;
                                                                }
                                                              }
                                                              {
                                                                uint32_t
                                                                *wv_a9 = wv + c * (uint32_t)4U;
                                                                uint32_t
                                                                *wv_b10 = wv + d * (uint32_t)4U;
                                                                {
                                                                  uint32_t i;
                                                                  for
                                                                  (i
                                                                    = (uint32_t)0U;
                                                                    i
                                                                    < (uint32_t)4U;
                                                                    i++)
                                                                  {
                                                                    uint32_t *os = wv_a9;
                                                                    uint32_t
                                                                    x1 = wv_a9[i] + wv_b10[i];
                                                                    os[i] = x1;
                                                                  }
                                                                }
                                                                {
                                                                  uint32_t
                                                                  *wv_a10 = wv + b * (uint32_t)4U;
                                                                  uint32_t
                                                                  *wv_b11 = wv + c * (uint32_t)4U;
                                                                  {
                                                                    uint32_t i;
                                                                    for
                                                                    (i
                                                                      = (uint32_t)0U;
                                                                      i
                                                                      < (uint32_t)4U;
                                                                      i++)
                                                                    {
                                                                      uint32_t *os = wv_a10;
                                                                      uint32_t
                                                                      x1 = wv_a10[i] ^ wv_b11[i];
                                                                      os[i] = x1;
                                                                    }
                                                                  }
                                                                  {
                                                                    uint32_t *r18 = wv_a10;
                                                                    {
                                                                      uint32_t i;
                                                                      for
                                                                      (i
                                                                        = (uint32_t)0U;
                                                                        i
                                                                        < (uint32_t)4U;
                                                                        i++)
                                                                      {
                                                                        uint32_t *os = r18;
                                                                        uint32_t x1 = r18[i];
                                                                        uint32_t
                                                                        x13 =
                                                                          x1
                                                                          >> (uint32_t)12U
                                                                          | x1 << (uint32_t)20U;
                                                                        os[i] = x13;
                                                                      }
                                                                    }
                                                                    {
                                                                      uint32_t
                                                                      *wv_a11 =
                                                                        wv
                                                                        + a0 * (uint32_t)4U;
                                                                      uint32_t
                                                                      *wv_b12 =
                                                                        wv
                                                                        + b * (uint32_t)4U;
                                                                      {
                                                                        uint32_t i;
                                                                        for
                                                                        (i
                                                                          = (uint32_t)0U;
                                                                          i
                                                                          < (uint32_t)4U;
                                                                          i++)
                                                                        {
                                                                          uint32_t *os = wv_a11;
                                                                          uint32_t
                                                                          x1 = wv_a11[i] + wv_b12[i];
                                                                          os[i] = x1;
                                                                        }
                                                                      }
                                                                      {
                                                                        uint32_t i;
                                                                        for
                                                                        (i
                                                                          = (uint32_t)0U;
                                                                          i
                                                                          < (uint32_t)4U;
                                                                          i++)
                                                                        {
                                                                          uint32_t *os = wv_a11;
                                                                          uint32_t
                                                                          x1 = wv_a11[i] + w[i];
                                                                          os[i] = x1;
                                                                        }
                                                                      }
                                                                      {
                                                                        uint32_t
                                                                        *wv_a12 =
                                                                          wv
                                                                          + d * (uint32_t)4U;
                                                                        uint32_t
                                                                        *wv_b13 =
                                                                          wv
                                                                          + a0 * (uint32_t)4U;
                                                                        {
                                                                          uint32_t i;
                                                                          for
                                                                          (i
                                                                            = (uint32_t)0U;
                                                                            i
                                                                            < (uint32_t)4U;
                                                                            i++)
                                                                          {
                                                                            uint32_t *os = wv_a12;
                                                                            uint32_t
                                                                            x1 =
                                                                              wv_a12[i]
                                                                              ^ wv_b13[i];
                                                                            os[i] = x1;
                                                                          }
                                                                        }
                                                                        {
                                                                          uint32_t *r19 = wv_a12;
                                                                          {
                                                                            uint32_t i;
                                                                            for
                                                                            (i
                                                                              = (uint32_t)0U;
                                                                              i
                                                                              < (uint32_t)4U;
                                                                              i++)
                                                                            {
                                                                              uint32_t *os = r19;
                                                                              uint32_t x1 = r19[i];
                                                                              uint32_t
                                                                              x13 =
                                                                                x1
                                                                                >> (uint32_t)8U
                                                                                |
                                                                                  x1
                                                                                  << (uint32_t)24U;
                                                                              os[i] = x13;
                                                                            }
                                                                          }
                                                                          {
                                                                            uint32_t
                                                                            *wv_a13 =
                                                                              wv
                                                                              + c * (uint32_t)4U;
                                                                            uint32_t
                                                                            *wv_b14 =
                                                                              wv
                                                                              + d * (uint32_t)4U;
                                                                            {
                                                                              uint32_t i;
                                                                              for
                                                                              (i
                                                                                = (uint32_t)0U;
                                                                                i
                                                                                < (uint32_t)4U;
                                                                                i++)
                                                                              {
                                                                                uint32_t
                                                                                *os = wv_a13;
                                                                                uint32_t
                                                                                x1 =
                                                                                  wv_a13[i]
                                                                                  + wv_b14[i];
                                                                                os[i] = x1;
                                                                              }
                                                                            }
                                                                            {
                                                                              uint32_t
                                                                              *wv_a14 =
                                                                                wv
                                                                                + b * (uint32_t)4U;
                                                                              uint32_t
                                                                              *wv_b =
                                                                                wv
                                                                                + c * (uint32_t)4U;
                                                                              {
                                                                                uint32_t i;
                                                                                for
                                                                                (i
                                                                                  = (uint32_t)0U;
                                                                                  i
                                                                                  < (uint32_t)4U;
                                                                                  i++)
                                                                                {
                                                                                  uint32_t
                                                                                  *os = wv_a14;
                                                                                  uint32_t
                                                                                  x1 =
                                                                                    wv_a14[i]
                                                                                    ^ wv_b[i];
                                                                                  os[i] = x1;
                                                                                }
                                                                              }
                                                                              {
                                                                                uint32_t
                                                                                *r113 = wv_a14;
                                                                                {
                                                                                  uint32_t i;
                                                                                  for
                                                                                  (i
                                                                                    = (uint32_t)0U;
                                                                                    i
                                                                                    < (uint32_t)4U;
                                                                                    i++)
                                                                                  {
                                                                                    uint32_t
                                                                                    *os = r113;
                                                                                    uint32_t
                                                                                    x1 = r113[i];
                                                                                    uint32_t
                                                                                    x13 =
                                                                                      x1
                                                                                      >>
                                                                                        (uint32_t)7U
                                                                                      |
                                                                                        x1
                                                                                        <<
                                                                                          (uint32_t)25U;
                                                                                    os[i] = x13;
                                                                                  }
                                                                                }
                                                                                {
                                                                                  uint32_t
                                                                                  *r114 =
                                                                                    wv
                                                                                    +
                                                                                      (uint32_t)1U
                                                                                      * (uint32_t)4U;
                                                                                  uint32_t
                                                                                  *r2 =
                                                                                    wv
                                                                                    +
                                                                                      (uint32_t)2U
                                                                                      * (uint32_t)4U;
                                                                                  uint32_t
                                                                                  *r3 =
                                                                                    wv
                                                                                    +
                                                                                      (uint32_t)3U
                                                                                      * (uint32_t)4U;
                                                                                  uint32_t
                                                                                  *r11 = r114;
                                                                                  uint32_t
                                                                                  x03 = r11[3U];
                                                                                  uint32_t
                                                                                  x13 =
                                                                                    r11[((uint32_t)3U
                                                                                    + (uint32_t)1U)
                                                                                    % (uint32_t)4U];
                                                                                  uint32_t
                                                                                  x23 =
                                                                                    r11[((uint32_t)3U
                                                                                    + (uint32_t)2U)
                                                                                    % (uint32_t)4U];
                                                                                  uint32_t
                                                                                  x33 =
                                                                                    r11[((uint32_t)3U
                                                                                    + (uint32_t)3U)
                                                                                    % (uint32_t)4U];
                                                                                  r11[0U] = x03;
                                                                                  r11[1U] = x13;
                                                                                  r11[2U] = x23;
                                                                                  r11[3U] = x33;
                                                                                  {
                                                                                    uint32_t
                                                                                    *r115 = r2;
                                                                                    uint32_t
                                                                                    x04 = r115[2U];
                                                                                    uint32_t
                                                                                    x14 =
                                                                                      r115[((uint32_t)2U
                                                                                      + (uint32_t)1U)
                                                                                      % (uint32_t)4U];
                                                                                    uint32_t
                                                                                    x24 =
                                                                                      r115[((uint32_t)2U
                                                                                      + (uint32_t)2U)
                                                                                      % (uint32_t)4U];
                                                                                    uint32_t
                                                                                    x34 =
                                                                                      r115[((uint32_t)2U
                                                                                      + (uint32_t)3U)
                                                                                      % (uint32_t)4U];
                                                                                    r115[0U] = x04;
                                                                                    r115[1U] = x14;
                                                                                    r115[2U] = x24;
                                                                                    r115[3U] = x34;
                                                                                    {
                                                                                      uint32_t
                                                                                      *r116 = r3;
                                                                                      uint32_t
                                                                                      x0 = r116[1U];
                                                                                      uint32_t
                                                                                      x1 =
                                                                                        r116[((uint32_t)1U
                                                                                        +
                                                                                          (uint32_t)1U)
                                                                                        %
                                                                                          (uint32_t)4U];
                                                                                      uint32_t
                                                                                      x2 =
                                                                                        r116[((uint32_t)1U
                                                                                        +
                                                                                          (uint32_t)2U)
                                                                                        %
                                                                                          (uint32_t)4U];
                                                                                      uint32_t
                                                                                      x3 =
                                                                                        r116[((uint32_t)1U
                                                                                        +
                                                                                          (uint32_t)3U)
                                                                                        %
                                                                                          (uint32_t)4U];
                                                                                      r116[0U] = x0;
                                                                                      r116[1U] = x1;
                                                                                      r116[2U] = x2;
                                                                                      r116[3U] = x3;
                                                                                    }
                                                                                  }
                                                                                }
                                                                              }
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            s00 = s + (uint32_t)0U * (uint32_t)4U;
            s16 = s + (uint32_t)1U * (uint32_t)4U;
            r00 = wv + (uint32_t)0U * (uint32_t)4U;
            r10 = wv + (uint32_t)1U * (uint32_t)4U;
            r20 = wv + (uint32_t)2U * (uint32_t)4U;
            r30 = wv + (uint32_t)3U * (uint32_t)4U;
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint32_t *os = s00;
                uint32_t x = s00[i] ^ r00[i];
                os[i] = x;
              }
            }
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint32_t *os = s00;
                uint32_t x = s00[i] ^ r20[i];
                os[i] = x;
              }
            }
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint32_t *os = s16;
                uint32_t x = s16[i] ^ r10[i];
                os[i] = x;
              }
            }
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint32_t *os = s16;
                uint32_t x = s16[i] ^ r30[i];
                os[i] = x;
              }
            }
            return (uint64_t)0U;
          }
        }
      }
    }
  }
}

FStar_UInt128_uint128
Hacl_Hash_Blake2_update_last_blake2b_32(
  uint64_t *s,
  FStar_UInt128_uint128 ev,
  FStar_UInt128_uint128 prev_len,
  uint8_t *input,
  uint32_t input_len
)
{
  uint32_t blocks_n = input_len / (uint32_t)128U;
  uint32_t blocks_len0 = blocks_n * (uint32_t)128U;
  uint32_t rest_len0 = input_len - blocks_len0;
  __uint32_t_uint32_t_uint32_t scrut0;
  if (rest_len0 == (uint32_t)0U && blocks_n > (uint32_t)0U)
  {
    uint32_t blocks_n1 = blocks_n - (uint32_t)1U;
    uint32_t blocks_len1 = blocks_len0 - (uint32_t)128U;
    uint32_t rest_len1 = (uint32_t)128U;
    __uint32_t_uint32_t_uint32_t lit;
    lit.fst = blocks_n1;
    lit.snd = blocks_len1;
    lit.thd = rest_len1;
    scrut0 = lit;
  }
  else
  {
    __uint32_t_uint32_t_uint32_t lit;
    lit.fst = blocks_n;
    lit.snd = blocks_len0;
    lit.thd = rest_len0;
    scrut0 = lit;
  }
  {
    uint32_t num_blocks0 = scrut0.fst;
    uint32_t blocks_len = scrut0.snd;
    uint32_t rest_len1 = scrut0.thd;
    uint8_t *blocks0 = input;
    uint8_t *rest0 = input + blocks_len;
    __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_ lit;
    __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_ scrut;
    uint32_t num_blocks;
    uint32_t rest_len;
    uint8_t *blocks;
    uint8_t *rest;
    FStar_UInt128_uint128 ev_;
    lit.fst = num_blocks0;
    lit.snd = blocks_len;
    lit.thd = rest_len1;
    lit.f3 = blocks0;
    lit.f4 = rest0;
    scrut = lit;
    num_blocks = scrut.fst;
    rest_len = scrut.thd;
    blocks = scrut.f3;
    rest = scrut.f4;
    ev_ = Hacl_Hash_Blake2_update_multi_blake2b_32(s, ev, blocks, num_blocks);
    KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
    {
      uint64_t wv[(uint32_t)4U * (uint32_t)4U];
      memset(wv, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (uint64_t));
      {
        uint8_t tmp[128U] = { 0U };
        uint8_t *tmp_rest = tmp;
        FStar_UInt128_uint128 totlen;
        memcpy(tmp_rest, rest, rest_len * sizeof (uint8_t));
        totlen = FStar_UInt128_add_mod(ev_, FStar_UInt128_uint64_to_uint128((uint64_t)rest_len));
        {
          uint64_t m_w[16U] = { 0U };
          {
            uint32_t i;
            for (i = (uint32_t)0U; i < (uint32_t)16U; i++)
            {
              uint64_t *os = m_w;
              uint8_t *bj = tmp + i * (uint32_t)8U;
              uint64_t u = load64_le(bj);
              uint64_t r = u;
              uint64_t x = r;
              os[i] = x;
            }
          }
          {
            uint64_t mask[4U] = { 0U };
            uint64_t wv_14 = (uint64_t)0xFFFFFFFFFFFFFFFFU;
            uint64_t wv_15 = (uint64_t)0U;
            uint64_t *wv3;
            uint64_t *s00;
            uint64_t *s16;
            uint64_t *r00;
            uint64_t *r10;
            uint64_t *r20;
            uint64_t *r30;
            mask[0U] = FStar_UInt128_uint128_to_uint64(totlen);
            mask[1U] =
              FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(totlen, (uint32_t)64U));
            mask[2U] = wv_14;
            mask[3U] = wv_15;
            memcpy(wv, s, (uint32_t)4U * (uint32_t)4U * sizeof (uint64_t));
            wv3 = wv + (uint32_t)3U * (uint32_t)4U;
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint64_t *os = wv3;
                uint64_t x = wv3[i] ^ mask[i];
                os[i] = x;
              }
            }
            {
              uint32_t i0;
              for (i0 = (uint32_t)0U; i0 < (uint32_t)12U; i0++)
              {
                uint32_t start_idx = i0 % (uint32_t)10U * (uint32_t)16U;
                KRML_CHECK_SIZE(sizeof (uint64_t), (uint32_t)4U * (uint32_t)4U);
                {
                  uint64_t m_st[(uint32_t)4U * (uint32_t)4U];
                  memset(m_st, 0U, (uint32_t)4U * (uint32_t)4U * sizeof (uint64_t));
                  {
                    uint64_t *r0 = m_st + (uint32_t)0U * (uint32_t)4U;
                    uint64_t *r1 = m_st + (uint32_t)1U * (uint32_t)4U;
                    uint64_t *r21 = m_st + (uint32_t)2U * (uint32_t)4U;
                    uint64_t *r31 = m_st + (uint32_t)3U * (uint32_t)4U;
                    uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
                    uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
                    uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
                    uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
                    uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
                    uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
                    uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
                    uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
                    uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
                    uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
                    uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
                    uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
                    uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
                    uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
                    uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
                    uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
                    uint64_t uu____0 = m_w[s2];
                    uint64_t uu____1 = m_w[s4];
                    uint64_t uu____2 = m_w[s6];
                    r0[0U] = m_w[s0];
                    r0[1U] = uu____0;
                    r0[2U] = uu____1;
                    r0[3U] = uu____2;
                    {
                      uint64_t uu____3 = m_w[s3];
                      uint64_t uu____4 = m_w[s5];
                      uint64_t uu____5 = m_w[s7];
                      r1[0U] = m_w[s1];
                      r1[1U] = uu____3;
                      r1[2U] = uu____4;
                      r1[3U] = uu____5;
                      {
                        uint64_t uu____6 = m_w[s10];
                        uint64_t uu____7 = m_w[s12];
                        uint64_t uu____8 = m_w[s14];
                        r21[0U] = m_w[s8];
                        r21[1U] = uu____6;
                        r21[2U] = uu____7;
                        r21[3U] = uu____8;
                        {
                          uint64_t uu____9 = m_w[s11];
                          uint64_t uu____10 = m_w[s13];
                          uint64_t uu____11 = m_w[s15];
                          r31[0U] = m_w[s9];
                          r31[1U] = uu____9;
                          r31[2U] = uu____10;
                          r31[3U] = uu____11;
                          {
                            uint64_t *x = m_st + (uint32_t)0U * (uint32_t)4U;
                            uint64_t *y = m_st + (uint32_t)1U * (uint32_t)4U;
                            uint64_t *z = m_st + (uint32_t)2U * (uint32_t)4U;
                            uint64_t *w = m_st + (uint32_t)3U * (uint32_t)4U;
                            uint32_t a = (uint32_t)0U;
                            uint32_t b0 = (uint32_t)1U;
                            uint32_t c0 = (uint32_t)2U;
                            uint32_t d0 = (uint32_t)3U;
                            uint64_t *wv_a0 = wv + a * (uint32_t)4U;
                            uint64_t *wv_b0 = wv + b0 * (uint32_t)4U;
                            {
                              uint32_t i;
                              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                              {
                                uint64_t *os = wv_a0;
                                uint64_t x1 = wv_a0[i] + wv_b0[i];
                                os[i] = x1;
                              }
                            }
                            {
                              uint32_t i;
                              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                              {
                                uint64_t *os = wv_a0;
                                uint64_t x1 = wv_a0[i] + x[i];
                                os[i] = x1;
                              }
                            }
                            {
                              uint64_t *wv_a1 = wv + d0 * (uint32_t)4U;
                              uint64_t *wv_b1 = wv + a * (uint32_t)4U;
                              {
                                uint32_t i;
                                for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                {
                                  uint64_t *os = wv_a1;
                                  uint64_t x1 = wv_a1[i] ^ wv_b1[i];
                                  os[i] = x1;
                                }
                              }
                              {
                                uint64_t *r12 = wv_a1;
                                {
                                  uint32_t i;
                                  for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                  {
                                    uint64_t *os = r12;
                                    uint64_t x1 = r12[i];
                                    uint64_t x10 = x1 >> (uint32_t)32U | x1 << (uint32_t)32U;
                                    os[i] = x10;
                                  }
                                }
                                {
                                  uint64_t *wv_a2 = wv + c0 * (uint32_t)4U;
                                  uint64_t *wv_b2 = wv + d0 * (uint32_t)4U;
                                  {
                                    uint32_t i;
                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                    {
                                      uint64_t *os = wv_a2;
                                      uint64_t x1 = wv_a2[i] + wv_b2[i];
                                      os[i] = x1;
                                    }
                                  }
                                  {
                                    uint64_t *wv_a3 = wv + b0 * (uint32_t)4U;
                                    uint64_t *wv_b3 = wv + c0 * (uint32_t)4U;
                                    {
                                      uint32_t i;
                                      for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                      {
                                        uint64_t *os = wv_a3;
                                        uint64_t x1 = wv_a3[i] ^ wv_b3[i];
                                        os[i] = x1;
                                      }
                                    }
                                    {
                                      uint64_t *r13 = wv_a3;
                                      {
                                        uint32_t i;
                                        for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                        {
                                          uint64_t *os = r13;
                                          uint64_t x1 = r13[i];
                                          uint64_t x10 = x1 >> (uint32_t)24U | x1 << (uint32_t)40U;
                                          os[i] = x10;
                                        }
                                      }
                                      {
                                        uint64_t *wv_a4 = wv + a * (uint32_t)4U;
                                        uint64_t *wv_b4 = wv + b0 * (uint32_t)4U;
                                        {
                                          uint32_t i;
                                          for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                          {
                                            uint64_t *os = wv_a4;
                                            uint64_t x1 = wv_a4[i] + wv_b4[i];
                                            os[i] = x1;
                                          }
                                        }
                                        {
                                          uint32_t i;
                                          for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                          {
                                            uint64_t *os = wv_a4;
                                            uint64_t x1 = wv_a4[i] + y[i];
                                            os[i] = x1;
                                          }
                                        }
                                        {
                                          uint64_t *wv_a5 = wv + d0 * (uint32_t)4U;
                                          uint64_t *wv_b5 = wv + a * (uint32_t)4U;
                                          {
                                            uint32_t i;
                                            for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                            {
                                              uint64_t *os = wv_a5;
                                              uint64_t x1 = wv_a5[i] ^ wv_b5[i];
                                              os[i] = x1;
                                            }
                                          }
                                          {
                                            uint64_t *r14 = wv_a5;
                                            {
                                              uint32_t i;
                                              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                              {
                                                uint64_t *os = r14;
                                                uint64_t x1 = r14[i];
                                                uint64_t
                                                x10 = x1 >> (uint32_t)16U | x1 << (uint32_t)48U;
                                                os[i] = x10;
                                              }
                                            }
                                            {
                                              uint64_t *wv_a6 = wv + c0 * (uint32_t)4U;
                                              uint64_t *wv_b6 = wv + d0 * (uint32_t)4U;
                                              {
                                                uint32_t i;
                                                for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                {
                                                  uint64_t *os = wv_a6;
                                                  uint64_t x1 = wv_a6[i] + wv_b6[i];
                                                  os[i] = x1;
                                                }
                                              }
                                              {
                                                uint64_t *wv_a7 = wv + b0 * (uint32_t)4U;
                                                uint64_t *wv_b7 = wv + c0 * (uint32_t)4U;
                                                {
                                                  uint32_t i;
                                                  for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                  {
                                                    uint64_t *os = wv_a7;
                                                    uint64_t x1 = wv_a7[i] ^ wv_b7[i];
                                                    os[i] = x1;
                                                  }
                                                }
                                                {
                                                  uint64_t *r15 = wv_a7;
                                                  {
                                                    uint32_t i;
                                                    for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
                                                    {
                                                      uint64_t *os = r15;
                                                      uint64_t x1 = r15[i];
                                                      uint64_t
                                                      x10 = x1 >> (uint32_t)63U | x1 << (uint32_t)1U;
                                                      os[i] = x10;
                                                    }
                                                  }
                                                  {
                                                    uint64_t
                                                    *r16 = wv + (uint32_t)1U * (uint32_t)4U;
                                                    uint64_t
                                                    *r22 = wv + (uint32_t)2U * (uint32_t)4U;
                                                    uint64_t
                                                    *r32 = wv + (uint32_t)3U * (uint32_t)4U;
                                                    uint64_t *r110 = r16;
                                                    uint64_t x00 = r110[1U];
                                                    uint64_t
                                                    x10 =
                                                      r110[((uint32_t)1U + (uint32_t)1U)
                                                      % (uint32_t)4U];
                                                    uint64_t
                                                    x20 =
                                                      r110[((uint32_t)1U + (uint32_t)2U)
                                                      % (uint32_t)4U];
                                                    uint64_t
                                                    x30 =
                                                      r110[((uint32_t)1U + (uint32_t)3U)
                                                      % (uint32_t)4U];
                                                    r110[0U] = x00;
                                                    r110[1U] = x10;
                                                    r110[2U] = x20;
                                                    r110[3U] = x30;
                                                    {
                                                      uint64_t *r111 = r22;
                                                      uint64_t x01 = r111[2U];
                                                      uint64_t
                                                      x11 =
                                                        r111[((uint32_t)2U + (uint32_t)1U)
                                                        % (uint32_t)4U];
                                                      uint64_t
                                                      x21 =
                                                        r111[((uint32_t)2U + (uint32_t)2U)
                                                        % (uint32_t)4U];
                                                      uint64_t
                                                      x31 =
                                                        r111[((uint32_t)2U + (uint32_t)3U)
                                                        % (uint32_t)4U];
                                                      r111[0U] = x01;
                                                      r111[1U] = x11;
                                                      r111[2U] = x21;
                                                      r111[3U] = x31;
                                                      {
                                                        uint64_t *r112 = r32;
                                                        uint64_t x02 = r112[3U];
                                                        uint64_t
                                                        x12 =
                                                          r112[((uint32_t)3U + (uint32_t)1U)
                                                          % (uint32_t)4U];
                                                        uint64_t
                                                        x22 =
                                                          r112[((uint32_t)3U + (uint32_t)2U)
                                                          % (uint32_t)4U];
                                                        uint64_t
                                                        x32 =
                                                          r112[((uint32_t)3U + (uint32_t)3U)
                                                          % (uint32_t)4U];
                                                        r112[0U] = x02;
                                                        r112[1U] = x12;
                                                        r112[2U] = x22;
                                                        r112[3U] = x32;
                                                        {
                                                          uint32_t a0 = (uint32_t)0U;
                                                          uint32_t b = (uint32_t)1U;
                                                          uint32_t c = (uint32_t)2U;
                                                          uint32_t d = (uint32_t)3U;
                                                          uint64_t *wv_a = wv + a0 * (uint32_t)4U;
                                                          uint64_t *wv_b8 = wv + b * (uint32_t)4U;
                                                          {
                                                            uint32_t i;
                                                            for
                                                            (i
                                                              = (uint32_t)0U;
                                                              i
                                                              < (uint32_t)4U;
                                                              i++)
                                                            {
                                                              uint64_t *os = wv_a;
                                                              uint64_t x1 = wv_a[i] + wv_b8[i];
                                                              os[i] = x1;
                                                            }
                                                          }
                                                          {
                                                            uint32_t i;
                                                            for
                                                            (i
                                                              = (uint32_t)0U;
                                                              i
                                                              < (uint32_t)4U;
                                                              i++)
                                                            {
                                                              uint64_t *os = wv_a;
                                                              uint64_t x1 = wv_a[i] + z[i];
                                                              os[i] = x1;
                                                            }
                                                          }
                                                          {
                                                            uint64_t *wv_a8 = wv + d * (uint32_t)4U;
                                                            uint64_t
                                                            *wv_b9 = wv + a0 * (uint32_t)4U;
                                                            {
                                                              uint32_t i;
                                                              for
                                                              (i
                                                                = (uint32_t)0U;
                                                                i
                                                                < (uint32_t)4U;
                                                                i++)
                                                              {
                                                                uint64_t *os = wv_a8;
                                                                uint64_t x1 = wv_a8[i] ^ wv_b9[i];
                                                                os[i] = x1;
                                                              }
                                                            }
                                                            {
                                                              uint64_t *r17 = wv_a8;
                                                              {
                                                                uint32_t i;
                                                                for
                                                                (i
                                                                  = (uint32_t)0U;
                                                                  i
                                                                  < (uint32_t)4U;
                                                                  i++)
                                                                {
                                                                  uint64_t *os = r17;
                                                                  uint64_t x1 = r17[i];
                                                                  uint64_t
                                                                  x13 =
                                                                    x1
                                                                    >> (uint32_t)32U
                                                                    | x1 << (uint32_t)32U;
                                                                  os[i] = x13;
                                                                }
                                                              }
                                                              {
                                                                uint64_t
                                                                *wv_a9 = wv + c * (uint32_t)4U;
                                                                uint64_t
                                                                *wv_b10 = wv + d * (uint32_t)4U;
                                                                {
                                                                  uint32_t i;
                                                                  for
                                                                  (i
                                                                    = (uint32_t)0U;
                                                                    i
                                                                    < (uint32_t)4U;
                                                                    i++)
                                                                  {
                                                                    uint64_t *os = wv_a9;
                                                                    uint64_t
                                                                    x1 = wv_a9[i] + wv_b10[i];
                                                                    os[i] = x1;
                                                                  }
                                                                }
                                                                {
                                                                  uint64_t
                                                                  *wv_a10 = wv + b * (uint32_t)4U;
                                                                  uint64_t
                                                                  *wv_b11 = wv + c * (uint32_t)4U;
                                                                  {
                                                                    uint32_t i;
                                                                    for
                                                                    (i
                                                                      = (uint32_t)0U;
                                                                      i
                                                                      < (uint32_t)4U;
                                                                      i++)
                                                                    {
                                                                      uint64_t *os = wv_a10;
                                                                      uint64_t
                                                                      x1 = wv_a10[i] ^ wv_b11[i];
                                                                      os[i] = x1;
                                                                    }
                                                                  }
                                                                  {
                                                                    uint64_t *r18 = wv_a10;
                                                                    {
                                                                      uint32_t i;
                                                                      for
                                                                      (i
                                                                        = (uint32_t)0U;
                                                                        i
                                                                        < (uint32_t)4U;
                                                                        i++)
                                                                      {
                                                                        uint64_t *os = r18;
                                                                        uint64_t x1 = r18[i];
                                                                        uint64_t
                                                                        x13 =
                                                                          x1
                                                                          >> (uint32_t)24U
                                                                          | x1 << (uint32_t)40U;
                                                                        os[i] = x13;
                                                                      }
                                                                    }
                                                                    {
                                                                      uint64_t
                                                                      *wv_a11 =
                                                                        wv
                                                                        + a0 * (uint32_t)4U;
                                                                      uint64_t
                                                                      *wv_b12 =
                                                                        wv
                                                                        + b * (uint32_t)4U;
                                                                      {
                                                                        uint32_t i;
                                                                        for
                                                                        (i
                                                                          = (uint32_t)0U;
                                                                          i
                                                                          < (uint32_t)4U;
                                                                          i++)
                                                                        {
                                                                          uint64_t *os = wv_a11;
                                                                          uint64_t
                                                                          x1 = wv_a11[i] + wv_b12[i];
                                                                          os[i] = x1;
                                                                        }
                                                                      }
                                                                      {
                                                                        uint32_t i;
                                                                        for
                                                                        (i
                                                                          = (uint32_t)0U;
                                                                          i
                                                                          < (uint32_t)4U;
                                                                          i++)
                                                                        {
                                                                          uint64_t *os = wv_a11;
                                                                          uint64_t
                                                                          x1 = wv_a11[i] + w[i];
                                                                          os[i] = x1;
                                                                        }
                                                                      }
                                                                      {
                                                                        uint64_t
                                                                        *wv_a12 =
                                                                          wv
                                                                          + d * (uint32_t)4U;
                                                                        uint64_t
                                                                        *wv_b13 =
                                                                          wv
                                                                          + a0 * (uint32_t)4U;
                                                                        {
                                                                          uint32_t i;
                                                                          for
                                                                          (i
                                                                            = (uint32_t)0U;
                                                                            i
                                                                            < (uint32_t)4U;
                                                                            i++)
                                                                          {
                                                                            uint64_t *os = wv_a12;
                                                                            uint64_t
                                                                            x1 =
                                                                              wv_a12[i]
                                                                              ^ wv_b13[i];
                                                                            os[i] = x1;
                                                                          }
                                                                        }
                                                                        {
                                                                          uint64_t *r19 = wv_a12;
                                                                          {
                                                                            uint32_t i;
                                                                            for
                                                                            (i
                                                                              = (uint32_t)0U;
                                                                              i
                                                                              < (uint32_t)4U;
                                                                              i++)
                                                                            {
                                                                              uint64_t *os = r19;
                                                                              uint64_t x1 = r19[i];
                                                                              uint64_t
                                                                              x13 =
                                                                                x1
                                                                                >> (uint32_t)16U
                                                                                |
                                                                                  x1
                                                                                  << (uint32_t)48U;
                                                                              os[i] = x13;
                                                                            }
                                                                          }
                                                                          {
                                                                            uint64_t
                                                                            *wv_a13 =
                                                                              wv
                                                                              + c * (uint32_t)4U;
                                                                            uint64_t
                                                                            *wv_b14 =
                                                                              wv
                                                                              + d * (uint32_t)4U;
                                                                            {
                                                                              uint32_t i;
                                                                              for
                                                                              (i
                                                                                = (uint32_t)0U;
                                                                                i
                                                                                < (uint32_t)4U;
                                                                                i++)
                                                                              {
                                                                                uint64_t
                                                                                *os = wv_a13;
                                                                                uint64_t
                                                                                x1 =
                                                                                  wv_a13[i]
                                                                                  + wv_b14[i];
                                                                                os[i] = x1;
                                                                              }
                                                                            }
                                                                            {
                                                                              uint64_t
                                                                              *wv_a14 =
                                                                                wv
                                                                                + b * (uint32_t)4U;
                                                                              uint64_t
                                                                              *wv_b =
                                                                                wv
                                                                                + c * (uint32_t)4U;
                                                                              {
                                                                                uint32_t i;
                                                                                for
                                                                                (i
                                                                                  = (uint32_t)0U;
                                                                                  i
                                                                                  < (uint32_t)4U;
                                                                                  i++)
                                                                                {
                                                                                  uint64_t
                                                                                  *os = wv_a14;
                                                                                  uint64_t
                                                                                  x1 =
                                                                                    wv_a14[i]
                                                                                    ^ wv_b[i];
                                                                                  os[i] = x1;
                                                                                }
                                                                              }
                                                                              {
                                                                                uint64_t
                                                                                *r113 = wv_a14;
                                                                                {
                                                                                  uint32_t i;
                                                                                  for
                                                                                  (i
                                                                                    = (uint32_t)0U;
                                                                                    i
                                                                                    < (uint32_t)4U;
                                                                                    i++)
                                                                                  {
                                                                                    uint64_t
                                                                                    *os = r113;
                                                                                    uint64_t
                                                                                    x1 = r113[i];
                                                                                    uint64_t
                                                                                    x13 =
                                                                                      x1
                                                                                      >>
                                                                                        (uint32_t)63U
                                                                                      |
                                                                                        x1
                                                                                        <<
                                                                                          (uint32_t)1U;
                                                                                    os[i] = x13;
                                                                                  }
                                                                                }
                                                                                {
                                                                                  uint64_t
                                                                                  *r114 =
                                                                                    wv
                                                                                    +
                                                                                      (uint32_t)1U
                                                                                      * (uint32_t)4U;
                                                                                  uint64_t
                                                                                  *r2 =
                                                                                    wv
                                                                                    +
                                                                                      (uint32_t)2U
                                                                                      * (uint32_t)4U;
                                                                                  uint64_t
                                                                                  *r3 =
                                                                                    wv
                                                                                    +
                                                                                      (uint32_t)3U
                                                                                      * (uint32_t)4U;
                                                                                  uint64_t
                                                                                  *r11 = r114;
                                                                                  uint64_t
                                                                                  x03 = r11[3U];
                                                                                  uint64_t
                                                                                  x13 =
                                                                                    r11[((uint32_t)3U
                                                                                    + (uint32_t)1U)
                                                                                    % (uint32_t)4U];
                                                                                  uint64_t
                                                                                  x23 =
                                                                                    r11[((uint32_t)3U
                                                                                    + (uint32_t)2U)
                                                                                    % (uint32_t)4U];
                                                                                  uint64_t
                                                                                  x33 =
                                                                                    r11[((uint32_t)3U
                                                                                    + (uint32_t)3U)
                                                                                    % (uint32_t)4U];
                                                                                  r11[0U] = x03;
                                                                                  r11[1U] = x13;
                                                                                  r11[2U] = x23;
                                                                                  r11[3U] = x33;
                                                                                  {
                                                                                    uint64_t
                                                                                    *r115 = r2;
                                                                                    uint64_t
                                                                                    x04 = r115[2U];
                                                                                    uint64_t
                                                                                    x14 =
                                                                                      r115[((uint32_t)2U
                                                                                      + (uint32_t)1U)
                                                                                      % (uint32_t)4U];
                                                                                    uint64_t
                                                                                    x24 =
                                                                                      r115[((uint32_t)2U
                                                                                      + (uint32_t)2U)
                                                                                      % (uint32_t)4U];
                                                                                    uint64_t
                                                                                    x34 =
                                                                                      r115[((uint32_t)2U
                                                                                      + (uint32_t)3U)
                                                                                      % (uint32_t)4U];
                                                                                    r115[0U] = x04;
                                                                                    r115[1U] = x14;
                                                                                    r115[2U] = x24;
                                                                                    r115[3U] = x34;
                                                                                    {
                                                                                      uint64_t
                                                                                      *r116 = r3;
                                                                                      uint64_t
                                                                                      x0 = r116[1U];
                                                                                      uint64_t
                                                                                      x1 =
                                                                                        r116[((uint32_t)1U
                                                                                        +
                                                                                          (uint32_t)1U)
                                                                                        %
                                                                                          (uint32_t)4U];
                                                                                      uint64_t
                                                                                      x2 =
                                                                                        r116[((uint32_t)1U
                                                                                        +
                                                                                          (uint32_t)2U)
                                                                                        %
                                                                                          (uint32_t)4U];
                                                                                      uint64_t
                                                                                      x3 =
                                                                                        r116[((uint32_t)1U
                                                                                        +
                                                                                          (uint32_t)3U)
                                                                                        %
                                                                                          (uint32_t)4U];
                                                                                      r116[0U] = x0;
                                                                                      r116[1U] = x1;
                                                                                      r116[2U] = x2;
                                                                                      r116[3U] = x3;
                                                                                    }
                                                                                  }
                                                                                }
                                                                              }
                                                                            }
                                                                          }
                                                                        }
                                                                      }
                                                                    }
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            s00 = s + (uint32_t)0U * (uint32_t)4U;
            s16 = s + (uint32_t)1U * (uint32_t)4U;
            r00 = wv + (uint32_t)0U * (uint32_t)4U;
            r10 = wv + (uint32_t)1U * (uint32_t)4U;
            r20 = wv + (uint32_t)2U * (uint32_t)4U;
            r30 = wv + (uint32_t)3U * (uint32_t)4U;
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint64_t *os = s00;
                uint64_t x = s00[i] ^ r00[i];
                os[i] = x;
              }
            }
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint64_t *os = s00;
                uint64_t x = s00[i] ^ r20[i];
                os[i] = x;
              }
            }
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint64_t *os = s16;
                uint64_t x = s16[i] ^ r10[i];
                os[i] = x;
              }
            }
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)4U; i++)
              {
                uint64_t *os = s16;
                uint64_t x = s16[i] ^ r30[i];
                os[i] = x;
              }
            }
            return FStar_UInt128_uint64_to_uint128((uint64_t)0U);
          }
        }
      }
    }
  }
}

void Hacl_Hash_Blake2_hash_blake2s_32(uint8_t *input, uint32_t input_len, uint8_t *dst)
{
  Hacl_Blake2s_32_blake2s((uint32_t)32U, dst, input_len, input, (uint32_t)0U, NULL);
}

void Hacl_Hash_Blake2_hash_blake2b_32(uint8_t *input, uint32_t input_len, uint8_t *dst)
{
  Hacl_Blake2b_32_blake2b((uint32_t)64U, dst, input_len, input, (uint32_t)0U, NULL);
}

static FStar_UInt128_uint128
update_blake2b_256(
  Lib_IntVector_Intrinsics_vec256 *s,
  FStar_UInt128_uint128 totlen,
  uint8_t *block
)
{
  Lib_IntVector_Intrinsics_vec256 wv[4U];
  {
    uint32_t _i;
    for (_i = 0U; _i < (uint32_t)4U; ++_i)
      wv[_i] = Lib_IntVector_Intrinsics_vec256_zero;
  }
  {
    FStar_UInt128_uint128
    totlen1 =
      FStar_UInt128_add_mod(totlen,
        FStar_UInt128_uint64_to_uint128((uint64_t)(uint32_t)128U));
    uint64_t m_w[16U] = { 0U };
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)16U; i++)
      {
        uint64_t *os = m_w;
        uint8_t *bj = block + i * (uint32_t)8U;
        uint64_t u = load64_le(bj);
        uint64_t r = u;
        uint64_t x = r;
        os[i] = x;
      }
    }
    {
      Lib_IntVector_Intrinsics_vec256 mask = Lib_IntVector_Intrinsics_vec256_zero;
      uint64_t wv_14 = (uint64_t)0U;
      uint64_t wv_15 = (uint64_t)0U;
      Lib_IntVector_Intrinsics_vec256 *wv3;
      Lib_IntVector_Intrinsics_vec256 *s00;
      Lib_IntVector_Intrinsics_vec256 *s16;
      Lib_IntVector_Intrinsics_vec256 *r00;
      Lib_IntVector_Intrinsics_vec256 *r10;
      Lib_IntVector_Intrinsics_vec256 *r20;
      Lib_IntVector_Intrinsics_vec256 *r30;
      mask =
        Lib_IntVector_Intrinsics_vec256_load64s(FStar_UInt128_uint128_to_uint64(totlen1),
          FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(totlen1, (uint32_t)64U)),
          wv_14,
          wv_15);
      memcpy(wv, s, (uint32_t)4U * (uint32_t)1U * sizeof (Lib_IntVector_Intrinsics_vec256));
      wv3 = wv + (uint32_t)3U * (uint32_t)1U;
      wv3[0U] = Lib_IntVector_Intrinsics_vec256_xor(wv3[0U], mask);
      {
        uint32_t i;
        for (i = (uint32_t)0U; i < (uint32_t)12U; i++)
        {
          uint32_t start_idx = i % (uint32_t)10U * (uint32_t)16U;
          KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec256), (uint32_t)4U * (uint32_t)1U);
          {
            Lib_IntVector_Intrinsics_vec256 m_st[(uint32_t)4U * (uint32_t)1U];
            {
              uint32_t _i;
              for (_i = 0U; _i < (uint32_t)4U * (uint32_t)1U; ++_i)
                m_st[_i] = Lib_IntVector_Intrinsics_vec256_zero;
            }
            {
              Lib_IntVector_Intrinsics_vec256 *r0 = m_st + (uint32_t)0U * (uint32_t)1U;
              Lib_IntVector_Intrinsics_vec256 *r1 = m_st + (uint32_t)1U * (uint32_t)1U;
              Lib_IntVector_Intrinsics_vec256 *r21 = m_st + (uint32_t)2U * (uint32_t)1U;
              Lib_IntVector_Intrinsics_vec256 *r31 = m_st + (uint32_t)3U * (uint32_t)1U;
              uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
              uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
              uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
              uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
              uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
              uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
              uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
              uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
              uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
              uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
              uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
              uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
              uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
              uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
              uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
              uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
              r0[0U] = Lib_IntVector_Intrinsics_vec256_load64s(m_w[s0], m_w[s2], m_w[s4], m_w[s6]);
              r1[0U] = Lib_IntVector_Intrinsics_vec256_load64s(m_w[s1], m_w[s3], m_w[s5], m_w[s7]);
              r21[0U] =
                Lib_IntVector_Intrinsics_vec256_load64s(m_w[s8],
                  m_w[s10],
                  m_w[s12],
                  m_w[s14]);
              r31[0U] =
                Lib_IntVector_Intrinsics_vec256_load64s(m_w[s9],
                  m_w[s11],
                  m_w[s13],
                  m_w[s15]);
              {
                Lib_IntVector_Intrinsics_vec256 *x = m_st + (uint32_t)0U * (uint32_t)1U;
                Lib_IntVector_Intrinsics_vec256 *y = m_st + (uint32_t)1U * (uint32_t)1U;
                Lib_IntVector_Intrinsics_vec256 *z = m_st + (uint32_t)2U * (uint32_t)1U;
                Lib_IntVector_Intrinsics_vec256 *w = m_st + (uint32_t)3U * (uint32_t)1U;
                uint32_t a = (uint32_t)0U;
                uint32_t b0 = (uint32_t)1U;
                uint32_t c0 = (uint32_t)2U;
                uint32_t d0 = (uint32_t)3U;
                Lib_IntVector_Intrinsics_vec256 *wv_a0 = wv + a * (uint32_t)1U;
                Lib_IntVector_Intrinsics_vec256 *wv_b0 = wv + b0 * (uint32_t)1U;
                wv_a0[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a0[0U], wv_b0[0U]);
                wv_a0[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a0[0U], x[0U]);
                {
                  Lib_IntVector_Intrinsics_vec256 *wv_a1 = wv + d0 * (uint32_t)1U;
                  Lib_IntVector_Intrinsics_vec256 *wv_b1 = wv + a * (uint32_t)1U;
                  wv_a1[0U] = Lib_IntVector_Intrinsics_vec256_xor(wv_a1[0U], wv_b1[0U]);
                  wv_a1[0U] =
                    Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a1[0U],
                      (uint32_t)32U);
                  {
                    Lib_IntVector_Intrinsics_vec256 *wv_a2 = wv + c0 * (uint32_t)1U;
                    Lib_IntVector_Intrinsics_vec256 *wv_b2 = wv + d0 * (uint32_t)1U;
                    wv_a2[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a2[0U], wv_b2[0U]);
                    {
                      Lib_IntVector_Intrinsics_vec256 *wv_a3 = wv + b0 * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec256 *wv_b3 = wv + c0 * (uint32_t)1U;
                      wv_a3[0U] = Lib_IntVector_Intrinsics_vec256_xor(wv_a3[0U], wv_b3[0U]);
                      wv_a3[0U] =
                        Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a3[0U],
                          (uint32_t)24U);
                      {
                        Lib_IntVector_Intrinsics_vec256 *wv_a4 = wv + a * (uint32_t)1U;
                        Lib_IntVector_Intrinsics_vec256 *wv_b4 = wv + b0 * (uint32_t)1U;
                        wv_a4[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a4[0U], wv_b4[0U]);
                        wv_a4[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a4[0U], y[0U]);
                        {
                          Lib_IntVector_Intrinsics_vec256 *wv_a5 = wv + d0 * (uint32_t)1U;
                          Lib_IntVector_Intrinsics_vec256 *wv_b5 = wv + a * (uint32_t)1U;
                          wv_a5[0U] = Lib_IntVector_Intrinsics_vec256_xor(wv_a5[0U], wv_b5[0U]);
                          wv_a5[0U] =
                            Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a5[0U],
                              (uint32_t)16U);
                          {
                            Lib_IntVector_Intrinsics_vec256 *wv_a6 = wv + c0 * (uint32_t)1U;
                            Lib_IntVector_Intrinsics_vec256 *wv_b6 = wv + d0 * (uint32_t)1U;
                            wv_a6[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a6[0U], wv_b6[0U]);
                            {
                              Lib_IntVector_Intrinsics_vec256 *wv_a7 = wv + b0 * (uint32_t)1U;
                              Lib_IntVector_Intrinsics_vec256 *wv_b7 = wv + c0 * (uint32_t)1U;
                              wv_a7[0U] = Lib_IntVector_Intrinsics_vec256_xor(wv_a7[0U], wv_b7[0U]);
                              wv_a7[0U] =
                                Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a7[0U],
                                  (uint32_t)63U);
                              {
                                Lib_IntVector_Intrinsics_vec256
                                *r11 = wv + (uint32_t)1U * (uint32_t)1U;
                                Lib_IntVector_Intrinsics_vec256
                                *r22 = wv + (uint32_t)2U * (uint32_t)1U;
                                Lib_IntVector_Intrinsics_vec256
                                *r32 = wv + (uint32_t)3U * (uint32_t)1U;
                                Lib_IntVector_Intrinsics_vec256 v00 = r11[0U];
                                Lib_IntVector_Intrinsics_vec256
                                v1 =
                                  Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v00,
                                    (uint32_t)1U);
                                r11[0U] = v1;
                                {
                                  Lib_IntVector_Intrinsics_vec256 v01 = r22[0U];
                                  Lib_IntVector_Intrinsics_vec256
                                  v10 =
                                    Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v01,
                                      (uint32_t)2U);
                                  r22[0U] = v10;
                                  {
                                    Lib_IntVector_Intrinsics_vec256 v02 = r32[0U];
                                    Lib_IntVector_Intrinsics_vec256
                                    v11 =
                                      Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v02,
                                        (uint32_t)3U);
                                    r32[0U] = v11;
                                    {
                                      uint32_t a0 = (uint32_t)0U;
                                      uint32_t b = (uint32_t)1U;
                                      uint32_t c = (uint32_t)2U;
                                      uint32_t d = (uint32_t)3U;
                                      Lib_IntVector_Intrinsics_vec256
                                      *wv_a = wv + a0 * (uint32_t)1U;
                                      Lib_IntVector_Intrinsics_vec256
                                      *wv_b8 = wv + b * (uint32_t)1U;
                                      wv_a[0U] =
                                        Lib_IntVector_Intrinsics_vec256_add64(wv_a[0U],
                                          wv_b8[0U]);
                                      wv_a[0U] =
                                        Lib_IntVector_Intrinsics_vec256_add64(wv_a[0U],
                                          z[0U]);
                                      {
                                        Lib_IntVector_Intrinsics_vec256
                                        *wv_a8 = wv + d * (uint32_t)1U;
                                        Lib_IntVector_Intrinsics_vec256
                                        *wv_b9 = wv + a0 * (uint32_t)1U;
                                        wv_a8[0U] =
                                          Lib_IntVector_Intrinsics_vec256_xor(wv_a8[0U],
                                            wv_b9[0U]);
                                        wv_a8[0U] =
                                          Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a8[0U],
                                            (uint32_t)32U);
                                        {
                                          Lib_IntVector_Intrinsics_vec256
                                          *wv_a9 = wv + c * (uint32_t)1U;
                                          Lib_IntVector_Intrinsics_vec256
                                          *wv_b10 = wv + d * (uint32_t)1U;
                                          wv_a9[0U] =
                                            Lib_IntVector_Intrinsics_vec256_add64(wv_a9[0U],
                                              wv_b10[0U]);
                                          {
                                            Lib_IntVector_Intrinsics_vec256
                                            *wv_a10 = wv + b * (uint32_t)1U;
                                            Lib_IntVector_Intrinsics_vec256
                                            *wv_b11 = wv + c * (uint32_t)1U;
                                            wv_a10[0U] =
                                              Lib_IntVector_Intrinsics_vec256_xor(wv_a10[0U],
                                                wv_b11[0U]);
                                            wv_a10[0U] =
                                              Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a10[0U],
                                                (uint32_t)24U);
                                            {
                                              Lib_IntVector_Intrinsics_vec256
                                              *wv_a11 = wv + a0 * (uint32_t)1U;
                                              Lib_IntVector_Intrinsics_vec256
                                              *wv_b12 = wv + b * (uint32_t)1U;
                                              wv_a11[0U] =
                                                Lib_IntVector_Intrinsics_vec256_add64(wv_a11[0U],
                                                  wv_b12[0U]);
                                              wv_a11[0U] =
                                                Lib_IntVector_Intrinsics_vec256_add64(wv_a11[0U],
                                                  w[0U]);
                                              {
                                                Lib_IntVector_Intrinsics_vec256
                                                *wv_a12 = wv + d * (uint32_t)1U;
                                                Lib_IntVector_Intrinsics_vec256
                                                *wv_b13 = wv + a0 * (uint32_t)1U;
                                                wv_a12[0U] =
                                                  Lib_IntVector_Intrinsics_vec256_xor(wv_a12[0U],
                                                    wv_b13[0U]);
                                                wv_a12[0U] =
                                                  Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a12[0U],
                                                    (uint32_t)16U);
                                                {
                                                  Lib_IntVector_Intrinsics_vec256
                                                  *wv_a13 = wv + c * (uint32_t)1U;
                                                  Lib_IntVector_Intrinsics_vec256
                                                  *wv_b14 = wv + d * (uint32_t)1U;
                                                  wv_a13[0U] =
                                                    Lib_IntVector_Intrinsics_vec256_add64(wv_a13[0U],
                                                      wv_b14[0U]);
                                                  {
                                                    Lib_IntVector_Intrinsics_vec256
                                                    *wv_a14 = wv + b * (uint32_t)1U;
                                                    Lib_IntVector_Intrinsics_vec256
                                                    *wv_b = wv + c * (uint32_t)1U;
                                                    wv_a14[0U] =
                                                      Lib_IntVector_Intrinsics_vec256_xor(wv_a14[0U],
                                                        wv_b[0U]);
                                                    wv_a14[0U] =
                                                      Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a14[0U],
                                                        (uint32_t)63U);
                                                    {
                                                      Lib_IntVector_Intrinsics_vec256
                                                      *r12 = wv + (uint32_t)1U * (uint32_t)1U;
                                                      Lib_IntVector_Intrinsics_vec256
                                                      *r2 = wv + (uint32_t)2U * (uint32_t)1U;
                                                      Lib_IntVector_Intrinsics_vec256
                                                      *r3 = wv + (uint32_t)3U * (uint32_t)1U;
                                                      Lib_IntVector_Intrinsics_vec256 v0 = r12[0U];
                                                      Lib_IntVector_Intrinsics_vec256
                                                      v12 =
                                                        Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v0,
                                                          (uint32_t)3U);
                                                      r12[0U] = v12;
                                                      {
                                                        Lib_IntVector_Intrinsics_vec256
                                                        v03 = r2[0U];
                                                        Lib_IntVector_Intrinsics_vec256
                                                        v13 =
                                                          Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v03,
                                                            (uint32_t)2U);
                                                        r2[0U] = v13;
                                                        {
                                                          Lib_IntVector_Intrinsics_vec256
                                                          v04 = r3[0U];
                                                          Lib_IntVector_Intrinsics_vec256
                                                          v14 =
                                                            Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v04,
                                                              (uint32_t)1U);
                                                          r3[0U] = v14;
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      s00 = s + (uint32_t)0U * (uint32_t)1U;
      s16 = s + (uint32_t)1U * (uint32_t)1U;
      r00 = wv + (uint32_t)0U * (uint32_t)1U;
      r10 = wv + (uint32_t)1U * (uint32_t)1U;
      r20 = wv + (uint32_t)2U * (uint32_t)1U;
      r30 = wv + (uint32_t)3U * (uint32_t)1U;
      s00[0U] = Lib_IntVector_Intrinsics_vec256_xor(s00[0U], r00[0U]);
      s00[0U] = Lib_IntVector_Intrinsics_vec256_xor(s00[0U], r20[0U]);
      s16[0U] = Lib_IntVector_Intrinsics_vec256_xor(s16[0U], r10[0U]);
      s16[0U] = Lib_IntVector_Intrinsics_vec256_xor(s16[0U], r30[0U]);
      return totlen1;
    }
  }
}

void
Hacl_Hash_Blake2b_256_finish_blake2b_256(
  Lib_IntVector_Intrinsics_vec256 *s,
  FStar_UInt128_uint128 ev,
  uint8_t *dst
)
{
  uint32_t double_row = (uint32_t)2U * ((uint32_t)4U * (uint32_t)8U);
  KRML_CHECK_SIZE(sizeof (uint8_t), double_row);
  {
    uint8_t b[double_row];
    memset(b, 0U, double_row * sizeof (uint8_t));
    {
      uint8_t *first = b;
      uint8_t *second = b + (uint32_t)4U * (uint32_t)8U;
      Lib_IntVector_Intrinsics_vec256 *row0 = s + (uint32_t)0U * (uint32_t)1U;
      Lib_IntVector_Intrinsics_vec256 *row1 = s + (uint32_t)1U * (uint32_t)1U;
      uint8_t *final;
      Lib_IntVector_Intrinsics_vec256_store64_le(first, row0[0U]);
      Lib_IntVector_Intrinsics_vec256_store64_le(second, row1[0U]);
      final = b;
      memcpy(dst, final, (uint32_t)64U * sizeof (uint8_t));
      Lib_Memzero0_memzero(b, double_row * sizeof (b[0U]));
    }
  }
}

FStar_UInt128_uint128
Hacl_Hash_Blake2b_256_update_multi_blake2b_256(
  Lib_IntVector_Intrinsics_vec256 *s,
  FStar_UInt128_uint128 ev,
  uint8_t *blocks,
  uint32_t n_blocks
)
{
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < n_blocks; i++)
    {
      uint32_t sz = (uint32_t)128U;
      uint8_t *block = blocks + sz * i;
      FStar_UInt128_uint128
      v_ =
        update_blake2b_256(s,
          FStar_UInt128_add_mod(ev,
            FStar_UInt128_uint64_to_uint128((uint64_t)i * (uint64_t)(uint32_t)128U)),
          block);
    }
  }
  return
    FStar_UInt128_add_mod(ev,
      FStar_UInt128_uint64_to_uint128((uint64_t)n_blocks * (uint64_t)(uint32_t)128U));
}

FStar_UInt128_uint128
Hacl_Hash_Blake2b_256_update_last_blake2b_256(
  Lib_IntVector_Intrinsics_vec256 *s,
  FStar_UInt128_uint128 ev,
  FStar_UInt128_uint128 prev_len,
  uint8_t *input,
  uint32_t input_len
)
{
  uint32_t blocks_n = input_len / (uint32_t)128U;
  uint32_t blocks_len0 = blocks_n * (uint32_t)128U;
  uint32_t rest_len0 = input_len - blocks_len0;
  __uint32_t_uint32_t_uint32_t scrut0;
  if (rest_len0 == (uint32_t)0U && blocks_n > (uint32_t)0U)
  {
    uint32_t blocks_n1 = blocks_n - (uint32_t)1U;
    uint32_t blocks_len1 = blocks_len0 - (uint32_t)128U;
    uint32_t rest_len1 = (uint32_t)128U;
    __uint32_t_uint32_t_uint32_t lit;
    lit.fst = blocks_n1;
    lit.snd = blocks_len1;
    lit.thd = rest_len1;
    scrut0 = lit;
  }
  else
  {
    __uint32_t_uint32_t_uint32_t lit;
    lit.fst = blocks_n;
    lit.snd = blocks_len0;
    lit.thd = rest_len0;
    scrut0 = lit;
  }
  {
    uint32_t num_blocks0 = scrut0.fst;
    uint32_t blocks_len = scrut0.snd;
    uint32_t rest_len1 = scrut0.thd;
    uint8_t *blocks0 = input;
    uint8_t *rest0 = input + blocks_len;
    __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_ lit;
    __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_ scrut;
    uint32_t num_blocks;
    uint32_t rest_len;
    uint8_t *blocks;
    uint8_t *rest;
    FStar_UInt128_uint128 ev_;
    lit.fst = num_blocks0;
    lit.snd = blocks_len;
    lit.thd = rest_len1;
    lit.f3 = blocks0;
    lit.f4 = rest0;
    scrut = lit;
    num_blocks = scrut.fst;
    rest_len = scrut.thd;
    blocks = scrut.f3;
    rest = scrut.f4;
    ev_ = Hacl_Hash_Blake2b_256_update_multi_blake2b_256(s, ev, blocks, num_blocks);
    KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec256), (uint32_t)4U * (uint32_t)1U);
    {
      Lib_IntVector_Intrinsics_vec256 wv[(uint32_t)4U * (uint32_t)1U];
      {
        uint32_t _i;
        for (_i = 0U; _i < (uint32_t)4U * (uint32_t)1U; ++_i)
          wv[_i] = Lib_IntVector_Intrinsics_vec256_zero;
      }
      {
        uint8_t tmp[128U] = { 0U };
        uint8_t *tmp_rest = tmp;
        FStar_UInt128_uint128 totlen;
        memcpy(tmp_rest, rest, rest_len * sizeof (uint8_t));
        totlen = FStar_UInt128_add_mod(ev_, FStar_UInt128_uint64_to_uint128((uint64_t)rest_len));
        {
          uint64_t m_w[16U] = { 0U };
          {
            uint32_t i;
            for (i = (uint32_t)0U; i < (uint32_t)16U; i++)
            {
              uint64_t *os = m_w;
              uint8_t *bj = tmp + i * (uint32_t)8U;
              uint64_t u = load64_le(bj);
              uint64_t r = u;
              uint64_t x = r;
              os[i] = x;
            }
          }
          {
            Lib_IntVector_Intrinsics_vec256 mask = Lib_IntVector_Intrinsics_vec256_zero;
            uint64_t wv_14 = (uint64_t)0xFFFFFFFFFFFFFFFFU;
            uint64_t wv_15 = (uint64_t)0U;
            Lib_IntVector_Intrinsics_vec256 *wv3;
            Lib_IntVector_Intrinsics_vec256 *s00;
            Lib_IntVector_Intrinsics_vec256 *s16;
            Lib_IntVector_Intrinsics_vec256 *r00;
            Lib_IntVector_Intrinsics_vec256 *r10;
            Lib_IntVector_Intrinsics_vec256 *r20;
            Lib_IntVector_Intrinsics_vec256 *r30;
            mask =
              Lib_IntVector_Intrinsics_vec256_load64s(FStar_UInt128_uint128_to_uint64(totlen),
                FStar_UInt128_uint128_to_uint64(FStar_UInt128_shift_right(totlen, (uint32_t)64U)),
                wv_14,
                wv_15);
            memcpy(wv, s, (uint32_t)4U * (uint32_t)1U * sizeof (Lib_IntVector_Intrinsics_vec256));
            wv3 = wv + (uint32_t)3U * (uint32_t)1U;
            wv3[0U] = Lib_IntVector_Intrinsics_vec256_xor(wv3[0U], mask);
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)12U; i++)
              {
                uint32_t start_idx = i % (uint32_t)10U * (uint32_t)16U;
                KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec256),
                  (uint32_t)4U * (uint32_t)1U);
                {
                  Lib_IntVector_Intrinsics_vec256 m_st[(uint32_t)4U * (uint32_t)1U];
                  {
                    uint32_t _i;
                    for (_i = 0U; _i < (uint32_t)4U * (uint32_t)1U; ++_i)
                      m_st[_i] = Lib_IntVector_Intrinsics_vec256_zero;
                  }
                  {
                    Lib_IntVector_Intrinsics_vec256 *r0 = m_st + (uint32_t)0U * (uint32_t)1U;
                    Lib_IntVector_Intrinsics_vec256 *r1 = m_st + (uint32_t)1U * (uint32_t)1U;
                    Lib_IntVector_Intrinsics_vec256 *r21 = m_st + (uint32_t)2U * (uint32_t)1U;
                    Lib_IntVector_Intrinsics_vec256 *r31 = m_st + (uint32_t)3U * (uint32_t)1U;
                    uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
                    uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
                    uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
                    uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
                    uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
                    uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
                    uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
                    uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
                    uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
                    uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
                    uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
                    uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
                    uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
                    uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
                    uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
                    uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
                    r0[0U] =
                      Lib_IntVector_Intrinsics_vec256_load64s(m_w[s0],
                        m_w[s2],
                        m_w[s4],
                        m_w[s6]);
                    r1[0U] =
                      Lib_IntVector_Intrinsics_vec256_load64s(m_w[s1],
                        m_w[s3],
                        m_w[s5],
                        m_w[s7]);
                    r21[0U] =
                      Lib_IntVector_Intrinsics_vec256_load64s(m_w[s8],
                        m_w[s10],
                        m_w[s12],
                        m_w[s14]);
                    r31[0U] =
                      Lib_IntVector_Intrinsics_vec256_load64s(m_w[s9],
                        m_w[s11],
                        m_w[s13],
                        m_w[s15]);
                    {
                      Lib_IntVector_Intrinsics_vec256 *x = m_st + (uint32_t)0U * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec256 *y = m_st + (uint32_t)1U * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec256 *z = m_st + (uint32_t)2U * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec256 *w = m_st + (uint32_t)3U * (uint32_t)1U;
                      uint32_t a = (uint32_t)0U;
                      uint32_t b0 = (uint32_t)1U;
                      uint32_t c0 = (uint32_t)2U;
                      uint32_t d0 = (uint32_t)3U;
                      Lib_IntVector_Intrinsics_vec256 *wv_a0 = wv + a * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec256 *wv_b0 = wv + b0 * (uint32_t)1U;
                      wv_a0[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a0[0U], wv_b0[0U]);
                      wv_a0[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a0[0U], x[0U]);
                      {
                        Lib_IntVector_Intrinsics_vec256 *wv_a1 = wv + d0 * (uint32_t)1U;
                        Lib_IntVector_Intrinsics_vec256 *wv_b1 = wv + a * (uint32_t)1U;
                        wv_a1[0U] = Lib_IntVector_Intrinsics_vec256_xor(wv_a1[0U], wv_b1[0U]);
                        wv_a1[0U] =
                          Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a1[0U],
                            (uint32_t)32U);
                        {
                          Lib_IntVector_Intrinsics_vec256 *wv_a2 = wv + c0 * (uint32_t)1U;
                          Lib_IntVector_Intrinsics_vec256 *wv_b2 = wv + d0 * (uint32_t)1U;
                          wv_a2[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a2[0U], wv_b2[0U]);
                          {
                            Lib_IntVector_Intrinsics_vec256 *wv_a3 = wv + b0 * (uint32_t)1U;
                            Lib_IntVector_Intrinsics_vec256 *wv_b3 = wv + c0 * (uint32_t)1U;
                            wv_a3[0U] = Lib_IntVector_Intrinsics_vec256_xor(wv_a3[0U], wv_b3[0U]);
                            wv_a3[0U] =
                              Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a3[0U],
                                (uint32_t)24U);
                            {
                              Lib_IntVector_Intrinsics_vec256 *wv_a4 = wv + a * (uint32_t)1U;
                              Lib_IntVector_Intrinsics_vec256 *wv_b4 = wv + b0 * (uint32_t)1U;
                              wv_a4[0U] =
                                Lib_IntVector_Intrinsics_vec256_add64(wv_a4[0U],
                                  wv_b4[0U]);
                              wv_a4[0U] = Lib_IntVector_Intrinsics_vec256_add64(wv_a4[0U], y[0U]);
                              {
                                Lib_IntVector_Intrinsics_vec256 *wv_a5 = wv + d0 * (uint32_t)1U;
                                Lib_IntVector_Intrinsics_vec256 *wv_b5 = wv + a * (uint32_t)1U;
                                wv_a5[0U] =
                                  Lib_IntVector_Intrinsics_vec256_xor(wv_a5[0U],
                                    wv_b5[0U]);
                                wv_a5[0U] =
                                  Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a5[0U],
                                    (uint32_t)16U);
                                {
                                  Lib_IntVector_Intrinsics_vec256 *wv_a6 = wv + c0 * (uint32_t)1U;
                                  Lib_IntVector_Intrinsics_vec256 *wv_b6 = wv + d0 * (uint32_t)1U;
                                  wv_a6[0U] =
                                    Lib_IntVector_Intrinsics_vec256_add64(wv_a6[0U],
                                      wv_b6[0U]);
                                  {
                                    Lib_IntVector_Intrinsics_vec256 *wv_a7 = wv + b0 * (uint32_t)1U;
                                    Lib_IntVector_Intrinsics_vec256 *wv_b7 = wv + c0 * (uint32_t)1U;
                                    wv_a7[0U] =
                                      Lib_IntVector_Intrinsics_vec256_xor(wv_a7[0U],
                                        wv_b7[0U]);
                                    wv_a7[0U] =
                                      Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a7[0U],
                                        (uint32_t)63U);
                                    {
                                      Lib_IntVector_Intrinsics_vec256
                                      *r11 = wv + (uint32_t)1U * (uint32_t)1U;
                                      Lib_IntVector_Intrinsics_vec256
                                      *r22 = wv + (uint32_t)2U * (uint32_t)1U;
                                      Lib_IntVector_Intrinsics_vec256
                                      *r32 = wv + (uint32_t)3U * (uint32_t)1U;
                                      Lib_IntVector_Intrinsics_vec256 v00 = r11[0U];
                                      Lib_IntVector_Intrinsics_vec256
                                      v1 =
                                        Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v00,
                                          (uint32_t)1U);
                                      r11[0U] = v1;
                                      {
                                        Lib_IntVector_Intrinsics_vec256 v01 = r22[0U];
                                        Lib_IntVector_Intrinsics_vec256
                                        v10 =
                                          Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v01,
                                            (uint32_t)2U);
                                        r22[0U] = v10;
                                        {
                                          Lib_IntVector_Intrinsics_vec256 v02 = r32[0U];
                                          Lib_IntVector_Intrinsics_vec256
                                          v11 =
                                            Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v02,
                                              (uint32_t)3U);
                                          r32[0U] = v11;
                                          {
                                            uint32_t a0 = (uint32_t)0U;
                                            uint32_t b = (uint32_t)1U;
                                            uint32_t c = (uint32_t)2U;
                                            uint32_t d = (uint32_t)3U;
                                            Lib_IntVector_Intrinsics_vec256
                                            *wv_a = wv + a0 * (uint32_t)1U;
                                            Lib_IntVector_Intrinsics_vec256
                                            *wv_b8 = wv + b * (uint32_t)1U;
                                            wv_a[0U] =
                                              Lib_IntVector_Intrinsics_vec256_add64(wv_a[0U],
                                                wv_b8[0U]);
                                            wv_a[0U] =
                                              Lib_IntVector_Intrinsics_vec256_add64(wv_a[0U],
                                                z[0U]);
                                            {
                                              Lib_IntVector_Intrinsics_vec256
                                              *wv_a8 = wv + d * (uint32_t)1U;
                                              Lib_IntVector_Intrinsics_vec256
                                              *wv_b9 = wv + a0 * (uint32_t)1U;
                                              wv_a8[0U] =
                                                Lib_IntVector_Intrinsics_vec256_xor(wv_a8[0U],
                                                  wv_b9[0U]);
                                              wv_a8[0U] =
                                                Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a8[0U],
                                                  (uint32_t)32U);
                                              {
                                                Lib_IntVector_Intrinsics_vec256
                                                *wv_a9 = wv + c * (uint32_t)1U;
                                                Lib_IntVector_Intrinsics_vec256
                                                *wv_b10 = wv + d * (uint32_t)1U;
                                                wv_a9[0U] =
                                                  Lib_IntVector_Intrinsics_vec256_add64(wv_a9[0U],
                                                    wv_b10[0U]);
                                                {
                                                  Lib_IntVector_Intrinsics_vec256
                                                  *wv_a10 = wv + b * (uint32_t)1U;
                                                  Lib_IntVector_Intrinsics_vec256
                                                  *wv_b11 = wv + c * (uint32_t)1U;
                                                  wv_a10[0U] =
                                                    Lib_IntVector_Intrinsics_vec256_xor(wv_a10[0U],
                                                      wv_b11[0U]);
                                                  wv_a10[0U] =
                                                    Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a10[0U],
                                                      (uint32_t)24U);
                                                  {
                                                    Lib_IntVector_Intrinsics_vec256
                                                    *wv_a11 = wv + a0 * (uint32_t)1U;
                                                    Lib_IntVector_Intrinsics_vec256
                                                    *wv_b12 = wv + b * (uint32_t)1U;
                                                    wv_a11[0U] =
                                                      Lib_IntVector_Intrinsics_vec256_add64(wv_a11[0U],
                                                        wv_b12[0U]);
                                                    wv_a11[0U] =
                                                      Lib_IntVector_Intrinsics_vec256_add64(wv_a11[0U],
                                                        w[0U]);
                                                    {
                                                      Lib_IntVector_Intrinsics_vec256
                                                      *wv_a12 = wv + d * (uint32_t)1U;
                                                      Lib_IntVector_Intrinsics_vec256
                                                      *wv_b13 = wv + a0 * (uint32_t)1U;
                                                      wv_a12[0U] =
                                                        Lib_IntVector_Intrinsics_vec256_xor(wv_a12[0U],
                                                          wv_b13[0U]);
                                                      wv_a12[0U] =
                                                        Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a12[0U],
                                                          (uint32_t)16U);
                                                      {
                                                        Lib_IntVector_Intrinsics_vec256
                                                        *wv_a13 = wv + c * (uint32_t)1U;
                                                        Lib_IntVector_Intrinsics_vec256
                                                        *wv_b14 = wv + d * (uint32_t)1U;
                                                        wv_a13[0U] =
                                                          Lib_IntVector_Intrinsics_vec256_add64(wv_a13[0U],
                                                            wv_b14[0U]);
                                                        {
                                                          Lib_IntVector_Intrinsics_vec256
                                                          *wv_a14 = wv + b * (uint32_t)1U;
                                                          Lib_IntVector_Intrinsics_vec256
                                                          *wv_b = wv + c * (uint32_t)1U;
                                                          wv_a14[0U] =
                                                            Lib_IntVector_Intrinsics_vec256_xor(wv_a14[0U],
                                                              wv_b[0U]);
                                                          wv_a14[0U] =
                                                            Lib_IntVector_Intrinsics_vec256_rotate_right64(wv_a14[0U],
                                                              (uint32_t)63U);
                                                          {
                                                            Lib_IntVector_Intrinsics_vec256
                                                            *r12 = wv + (uint32_t)1U * (uint32_t)1U;
                                                            Lib_IntVector_Intrinsics_vec256
                                                            *r2 = wv + (uint32_t)2U * (uint32_t)1U;
                                                            Lib_IntVector_Intrinsics_vec256
                                                            *r3 = wv + (uint32_t)3U * (uint32_t)1U;
                                                            Lib_IntVector_Intrinsics_vec256
                                                            v0 = r12[0U];
                                                            Lib_IntVector_Intrinsics_vec256
                                                            v12 =
                                                              Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v0,
                                                                (uint32_t)3U);
                                                            r12[0U] = v12;
                                                            {
                                                              Lib_IntVector_Intrinsics_vec256
                                                              v03 = r2[0U];
                                                              Lib_IntVector_Intrinsics_vec256
                                                              v13 =
                                                                Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v03,
                                                                  (uint32_t)2U);
                                                              r2[0U] = v13;
                                                              {
                                                                Lib_IntVector_Intrinsics_vec256
                                                                v04 = r3[0U];
                                                                Lib_IntVector_Intrinsics_vec256
                                                                v14 =
                                                                  Lib_IntVector_Intrinsics_vec256_rotate_right_lanes64(v04,
                                                                    (uint32_t)1U);
                                                                r3[0U] = v14;
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            s00 = s + (uint32_t)0U * (uint32_t)1U;
            s16 = s + (uint32_t)1U * (uint32_t)1U;
            r00 = wv + (uint32_t)0U * (uint32_t)1U;
            r10 = wv + (uint32_t)1U * (uint32_t)1U;
            r20 = wv + (uint32_t)2U * (uint32_t)1U;
            r30 = wv + (uint32_t)3U * (uint32_t)1U;
            s00[0U] = Lib_IntVector_Intrinsics_vec256_xor(s00[0U], r00[0U]);
            s00[0U] = Lib_IntVector_Intrinsics_vec256_xor(s00[0U], r20[0U]);
            s16[0U] = Lib_IntVector_Intrinsics_vec256_xor(s16[0U], r10[0U]);
            s16[0U] = Lib_IntVector_Intrinsics_vec256_xor(s16[0U], r30[0U]);
            return FStar_UInt128_uint64_to_uint128((uint64_t)0U);
          }
        }
      }
    }
  }
}

void Hacl_Hash_Blake2b_256_hash_blake2b_256(uint8_t *input, uint32_t input_len, uint8_t *dst)
{
  Hacl_Blake2b_256_blake2b((uint32_t)64U, dst, input_len, input, (uint32_t)0U, NULL);
}

static uint64_t
update_blake2s_128(Lib_IntVector_Intrinsics_vec128 *s, uint64_t totlen, uint8_t *block)
{
  Lib_IntVector_Intrinsics_vec128 wv[4U];
  {
    uint32_t _i;
    for (_i = 0U; _i < (uint32_t)4U; ++_i)
      wv[_i] = Lib_IntVector_Intrinsics_vec128_zero;
  }
  {
    uint64_t totlen1 = totlen + (uint64_t)(uint32_t)64U;
    uint32_t m_w[16U] = { 0U };
    {
      uint32_t i;
      for (i = (uint32_t)0U; i < (uint32_t)16U; i++)
      {
        uint32_t *os = m_w;
        uint8_t *bj = block + i * (uint32_t)4U;
        uint32_t u = load32_le(bj);
        uint32_t r = u;
        uint32_t x = r;
        os[i] = x;
      }
    }
    {
      Lib_IntVector_Intrinsics_vec128 mask = Lib_IntVector_Intrinsics_vec128_zero;
      uint32_t wv_14 = (uint32_t)0U;
      uint32_t wv_15 = (uint32_t)0U;
      Lib_IntVector_Intrinsics_vec128 *wv3;
      Lib_IntVector_Intrinsics_vec128 *s00;
      Lib_IntVector_Intrinsics_vec128 *s16;
      Lib_IntVector_Intrinsics_vec128 *r00;
      Lib_IntVector_Intrinsics_vec128 *r10;
      Lib_IntVector_Intrinsics_vec128 *r20;
      Lib_IntVector_Intrinsics_vec128 *r30;
      mask =
        Lib_IntVector_Intrinsics_vec128_load32s((uint32_t)totlen1,
          (uint32_t)(totlen1 >> (uint32_t)32U),
          wv_14,
          wv_15);
      memcpy(wv, s, (uint32_t)4U * (uint32_t)1U * sizeof (Lib_IntVector_Intrinsics_vec128));
      wv3 = wv + (uint32_t)3U * (uint32_t)1U;
      wv3[0U] = Lib_IntVector_Intrinsics_vec128_xor(wv3[0U], mask);
      {
        uint32_t i;
        for (i = (uint32_t)0U; i < (uint32_t)10U; i++)
        {
          uint32_t start_idx = i % (uint32_t)10U * (uint32_t)16U;
          KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec128), (uint32_t)4U * (uint32_t)1U);
          {
            Lib_IntVector_Intrinsics_vec128 m_st[(uint32_t)4U * (uint32_t)1U];
            {
              uint32_t _i;
              for (_i = 0U; _i < (uint32_t)4U * (uint32_t)1U; ++_i)
                m_st[_i] = Lib_IntVector_Intrinsics_vec128_zero;
            }
            {
              Lib_IntVector_Intrinsics_vec128 *r0 = m_st + (uint32_t)0U * (uint32_t)1U;
              Lib_IntVector_Intrinsics_vec128 *r1 = m_st + (uint32_t)1U * (uint32_t)1U;
              Lib_IntVector_Intrinsics_vec128 *r21 = m_st + (uint32_t)2U * (uint32_t)1U;
              Lib_IntVector_Intrinsics_vec128 *r31 = m_st + (uint32_t)3U * (uint32_t)1U;
              uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
              uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
              uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
              uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
              uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
              uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
              uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
              uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
              uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
              uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
              uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
              uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
              uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
              uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
              uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
              uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
              r0[0U] = Lib_IntVector_Intrinsics_vec128_load32s(m_w[s0], m_w[s2], m_w[s4], m_w[s6]);
              r1[0U] = Lib_IntVector_Intrinsics_vec128_load32s(m_w[s1], m_w[s3], m_w[s5], m_w[s7]);
              r21[0U] =
                Lib_IntVector_Intrinsics_vec128_load32s(m_w[s8],
                  m_w[s10],
                  m_w[s12],
                  m_w[s14]);
              r31[0U] =
                Lib_IntVector_Intrinsics_vec128_load32s(m_w[s9],
                  m_w[s11],
                  m_w[s13],
                  m_w[s15]);
              {
                Lib_IntVector_Intrinsics_vec128 *x = m_st + (uint32_t)0U * (uint32_t)1U;
                Lib_IntVector_Intrinsics_vec128 *y = m_st + (uint32_t)1U * (uint32_t)1U;
                Lib_IntVector_Intrinsics_vec128 *z = m_st + (uint32_t)2U * (uint32_t)1U;
                Lib_IntVector_Intrinsics_vec128 *w = m_st + (uint32_t)3U * (uint32_t)1U;
                uint32_t a = (uint32_t)0U;
                uint32_t b0 = (uint32_t)1U;
                uint32_t c0 = (uint32_t)2U;
                uint32_t d0 = (uint32_t)3U;
                Lib_IntVector_Intrinsics_vec128 *wv_a0 = wv + a * (uint32_t)1U;
                Lib_IntVector_Intrinsics_vec128 *wv_b0 = wv + b0 * (uint32_t)1U;
                wv_a0[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a0[0U], wv_b0[0U]);
                wv_a0[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a0[0U], x[0U]);
                {
                  Lib_IntVector_Intrinsics_vec128 *wv_a1 = wv + d0 * (uint32_t)1U;
                  Lib_IntVector_Intrinsics_vec128 *wv_b1 = wv + a * (uint32_t)1U;
                  wv_a1[0U] = Lib_IntVector_Intrinsics_vec128_xor(wv_a1[0U], wv_b1[0U]);
                  wv_a1[0U] =
                    Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a1[0U],
                      (uint32_t)16U);
                  {
                    Lib_IntVector_Intrinsics_vec128 *wv_a2 = wv + c0 * (uint32_t)1U;
                    Lib_IntVector_Intrinsics_vec128 *wv_b2 = wv + d0 * (uint32_t)1U;
                    wv_a2[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a2[0U], wv_b2[0U]);
                    {
                      Lib_IntVector_Intrinsics_vec128 *wv_a3 = wv + b0 * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec128 *wv_b3 = wv + c0 * (uint32_t)1U;
                      wv_a3[0U] = Lib_IntVector_Intrinsics_vec128_xor(wv_a3[0U], wv_b3[0U]);
                      wv_a3[0U] =
                        Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a3[0U],
                          (uint32_t)12U);
                      {
                        Lib_IntVector_Intrinsics_vec128 *wv_a4 = wv + a * (uint32_t)1U;
                        Lib_IntVector_Intrinsics_vec128 *wv_b4 = wv + b0 * (uint32_t)1U;
                        wv_a4[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a4[0U], wv_b4[0U]);
                        wv_a4[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a4[0U], y[0U]);
                        {
                          Lib_IntVector_Intrinsics_vec128 *wv_a5 = wv + d0 * (uint32_t)1U;
                          Lib_IntVector_Intrinsics_vec128 *wv_b5 = wv + a * (uint32_t)1U;
                          wv_a5[0U] = Lib_IntVector_Intrinsics_vec128_xor(wv_a5[0U], wv_b5[0U]);
                          wv_a5[0U] =
                            Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a5[0U],
                              (uint32_t)8U);
                          {
                            Lib_IntVector_Intrinsics_vec128 *wv_a6 = wv + c0 * (uint32_t)1U;
                            Lib_IntVector_Intrinsics_vec128 *wv_b6 = wv + d0 * (uint32_t)1U;
                            wv_a6[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a6[0U], wv_b6[0U]);
                            {
                              Lib_IntVector_Intrinsics_vec128 *wv_a7 = wv + b0 * (uint32_t)1U;
                              Lib_IntVector_Intrinsics_vec128 *wv_b7 = wv + c0 * (uint32_t)1U;
                              wv_a7[0U] = Lib_IntVector_Intrinsics_vec128_xor(wv_a7[0U], wv_b7[0U]);
                              wv_a7[0U] =
                                Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a7[0U],
                                  (uint32_t)7U);
                              {
                                Lib_IntVector_Intrinsics_vec128
                                *r11 = wv + (uint32_t)1U * (uint32_t)1U;
                                Lib_IntVector_Intrinsics_vec128
                                *r22 = wv + (uint32_t)2U * (uint32_t)1U;
                                Lib_IntVector_Intrinsics_vec128
                                *r32 = wv + (uint32_t)3U * (uint32_t)1U;
                                Lib_IntVector_Intrinsics_vec128 v00 = r11[0U];
                                Lib_IntVector_Intrinsics_vec128
                                v1 =
                                  Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v00,
                                    (uint32_t)1U);
                                r11[0U] = v1;
                                {
                                  Lib_IntVector_Intrinsics_vec128 v01 = r22[0U];
                                  Lib_IntVector_Intrinsics_vec128
                                  v10 =
                                    Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v01,
                                      (uint32_t)2U);
                                  r22[0U] = v10;
                                  {
                                    Lib_IntVector_Intrinsics_vec128 v02 = r32[0U];
                                    Lib_IntVector_Intrinsics_vec128
                                    v11 =
                                      Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v02,
                                        (uint32_t)3U);
                                    r32[0U] = v11;
                                    {
                                      uint32_t a0 = (uint32_t)0U;
                                      uint32_t b = (uint32_t)1U;
                                      uint32_t c = (uint32_t)2U;
                                      uint32_t d = (uint32_t)3U;
                                      Lib_IntVector_Intrinsics_vec128
                                      *wv_a = wv + a0 * (uint32_t)1U;
                                      Lib_IntVector_Intrinsics_vec128
                                      *wv_b8 = wv + b * (uint32_t)1U;
                                      wv_a[0U] =
                                        Lib_IntVector_Intrinsics_vec128_add32(wv_a[0U],
                                          wv_b8[0U]);
                                      wv_a[0U] =
                                        Lib_IntVector_Intrinsics_vec128_add32(wv_a[0U],
                                          z[0U]);
                                      {
                                        Lib_IntVector_Intrinsics_vec128
                                        *wv_a8 = wv + d * (uint32_t)1U;
                                        Lib_IntVector_Intrinsics_vec128
                                        *wv_b9 = wv + a0 * (uint32_t)1U;
                                        wv_a8[0U] =
                                          Lib_IntVector_Intrinsics_vec128_xor(wv_a8[0U],
                                            wv_b9[0U]);
                                        wv_a8[0U] =
                                          Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a8[0U],
                                            (uint32_t)16U);
                                        {
                                          Lib_IntVector_Intrinsics_vec128
                                          *wv_a9 = wv + c * (uint32_t)1U;
                                          Lib_IntVector_Intrinsics_vec128
                                          *wv_b10 = wv + d * (uint32_t)1U;
                                          wv_a9[0U] =
                                            Lib_IntVector_Intrinsics_vec128_add32(wv_a9[0U],
                                              wv_b10[0U]);
                                          {
                                            Lib_IntVector_Intrinsics_vec128
                                            *wv_a10 = wv + b * (uint32_t)1U;
                                            Lib_IntVector_Intrinsics_vec128
                                            *wv_b11 = wv + c * (uint32_t)1U;
                                            wv_a10[0U] =
                                              Lib_IntVector_Intrinsics_vec128_xor(wv_a10[0U],
                                                wv_b11[0U]);
                                            wv_a10[0U] =
                                              Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a10[0U],
                                                (uint32_t)12U);
                                            {
                                              Lib_IntVector_Intrinsics_vec128
                                              *wv_a11 = wv + a0 * (uint32_t)1U;
                                              Lib_IntVector_Intrinsics_vec128
                                              *wv_b12 = wv + b * (uint32_t)1U;
                                              wv_a11[0U] =
                                                Lib_IntVector_Intrinsics_vec128_add32(wv_a11[0U],
                                                  wv_b12[0U]);
                                              wv_a11[0U] =
                                                Lib_IntVector_Intrinsics_vec128_add32(wv_a11[0U],
                                                  w[0U]);
                                              {
                                                Lib_IntVector_Intrinsics_vec128
                                                *wv_a12 = wv + d * (uint32_t)1U;
                                                Lib_IntVector_Intrinsics_vec128
                                                *wv_b13 = wv + a0 * (uint32_t)1U;
                                                wv_a12[0U] =
                                                  Lib_IntVector_Intrinsics_vec128_xor(wv_a12[0U],
                                                    wv_b13[0U]);
                                                wv_a12[0U] =
                                                  Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a12[0U],
                                                    (uint32_t)8U);
                                                {
                                                  Lib_IntVector_Intrinsics_vec128
                                                  *wv_a13 = wv + c * (uint32_t)1U;
                                                  Lib_IntVector_Intrinsics_vec128
                                                  *wv_b14 = wv + d * (uint32_t)1U;
                                                  wv_a13[0U] =
                                                    Lib_IntVector_Intrinsics_vec128_add32(wv_a13[0U],
                                                      wv_b14[0U]);
                                                  {
                                                    Lib_IntVector_Intrinsics_vec128
                                                    *wv_a14 = wv + b * (uint32_t)1U;
                                                    Lib_IntVector_Intrinsics_vec128
                                                    *wv_b = wv + c * (uint32_t)1U;
                                                    wv_a14[0U] =
                                                      Lib_IntVector_Intrinsics_vec128_xor(wv_a14[0U],
                                                        wv_b[0U]);
                                                    wv_a14[0U] =
                                                      Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a14[0U],
                                                        (uint32_t)7U);
                                                    {
                                                      Lib_IntVector_Intrinsics_vec128
                                                      *r12 = wv + (uint32_t)1U * (uint32_t)1U;
                                                      Lib_IntVector_Intrinsics_vec128
                                                      *r2 = wv + (uint32_t)2U * (uint32_t)1U;
                                                      Lib_IntVector_Intrinsics_vec128
                                                      *r3 = wv + (uint32_t)3U * (uint32_t)1U;
                                                      Lib_IntVector_Intrinsics_vec128 v0 = r12[0U];
                                                      Lib_IntVector_Intrinsics_vec128
                                                      v12 =
                                                        Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v0,
                                                          (uint32_t)3U);
                                                      r12[0U] = v12;
                                                      {
                                                        Lib_IntVector_Intrinsics_vec128
                                                        v03 = r2[0U];
                                                        Lib_IntVector_Intrinsics_vec128
                                                        v13 =
                                                          Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v03,
                                                            (uint32_t)2U);
                                                        r2[0U] = v13;
                                                        {
                                                          Lib_IntVector_Intrinsics_vec128
                                                          v04 = r3[0U];
                                                          Lib_IntVector_Intrinsics_vec128
                                                          v14 =
                                                            Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v04,
                                                              (uint32_t)1U);
                                                          r3[0U] = v14;
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      s00 = s + (uint32_t)0U * (uint32_t)1U;
      s16 = s + (uint32_t)1U * (uint32_t)1U;
      r00 = wv + (uint32_t)0U * (uint32_t)1U;
      r10 = wv + (uint32_t)1U * (uint32_t)1U;
      r20 = wv + (uint32_t)2U * (uint32_t)1U;
      r30 = wv + (uint32_t)3U * (uint32_t)1U;
      s00[0U] = Lib_IntVector_Intrinsics_vec128_xor(s00[0U], r00[0U]);
      s00[0U] = Lib_IntVector_Intrinsics_vec128_xor(s00[0U], r20[0U]);
      s16[0U] = Lib_IntVector_Intrinsics_vec128_xor(s16[0U], r10[0U]);
      s16[0U] = Lib_IntVector_Intrinsics_vec128_xor(s16[0U], r30[0U]);
      return totlen1;
    }
  }
}

void
Hacl_Hash_Blake2s_128_finish_blake2s_128(
  Lib_IntVector_Intrinsics_vec128 *s,
  uint64_t ev,
  uint8_t *dst
)
{
  uint32_t double_row = (uint32_t)2U * ((uint32_t)4U * (uint32_t)4U);
  KRML_CHECK_SIZE(sizeof (uint8_t), double_row);
  {
    uint8_t b[double_row];
    memset(b, 0U, double_row * sizeof (uint8_t));
    {
      uint8_t *first = b;
      uint8_t *second = b + (uint32_t)4U * (uint32_t)4U;
      Lib_IntVector_Intrinsics_vec128 *row0 = s + (uint32_t)0U * (uint32_t)1U;
      Lib_IntVector_Intrinsics_vec128 *row1 = s + (uint32_t)1U * (uint32_t)1U;
      uint8_t *final;
      Lib_IntVector_Intrinsics_vec128_store32_le(first, row0[0U]);
      Lib_IntVector_Intrinsics_vec128_store32_le(second, row1[0U]);
      final = b;
      memcpy(dst, final, (uint32_t)32U * sizeof (uint8_t));
      Lib_Memzero0_memzero(b, double_row * sizeof (b[0U]));
    }
  }
}

uint64_t
Hacl_Hash_Blake2s_128_update_multi_blake2s_128(
  Lib_IntVector_Intrinsics_vec128 *s,
  uint64_t ev,
  uint8_t *blocks,
  uint32_t n_blocks
)
{
  {
    uint32_t i;
    for (i = (uint32_t)0U; i < n_blocks; i++)
    {
      uint32_t sz = (uint32_t)64U;
      uint8_t *block = blocks + sz * i;
      uint64_t v_ = update_blake2s_128(s, ev + (uint64_t)i * (uint64_t)(uint32_t)64U, block);
    }
  }
  return ev + (uint64_t)n_blocks * (uint64_t)(uint32_t)64U;
}

uint64_t
Hacl_Hash_Blake2s_128_update_last_blake2s_128(
  Lib_IntVector_Intrinsics_vec128 *s,
  uint64_t ev,
  uint64_t prev_len,
  uint8_t *input,
  uint32_t input_len
)
{
  uint32_t blocks_n = input_len / (uint32_t)64U;
  uint32_t blocks_len0 = blocks_n * (uint32_t)64U;
  uint32_t rest_len0 = input_len - blocks_len0;
  __uint32_t_uint32_t_uint32_t scrut0;
  if (rest_len0 == (uint32_t)0U && blocks_n > (uint32_t)0U)
  {
    uint32_t blocks_n1 = blocks_n - (uint32_t)1U;
    uint32_t blocks_len1 = blocks_len0 - (uint32_t)64U;
    uint32_t rest_len1 = (uint32_t)64U;
    __uint32_t_uint32_t_uint32_t lit;
    lit.fst = blocks_n1;
    lit.snd = blocks_len1;
    lit.thd = rest_len1;
    scrut0 = lit;
  }
  else
  {
    __uint32_t_uint32_t_uint32_t lit;
    lit.fst = blocks_n;
    lit.snd = blocks_len0;
    lit.thd = rest_len0;
    scrut0 = lit;
  }
  {
    uint32_t num_blocks0 = scrut0.fst;
    uint32_t blocks_len = scrut0.snd;
    uint32_t rest_len1 = scrut0.thd;
    uint8_t *blocks0 = input;
    uint8_t *rest0 = input + blocks_len;
    __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_ lit;
    __uint32_t_uint32_t_uint32_t__uint8_t___uint8_t_ scrut;
    uint32_t num_blocks;
    uint32_t rest_len;
    uint8_t *blocks;
    uint8_t *rest;
    uint64_t ev_;
    lit.fst = num_blocks0;
    lit.snd = blocks_len;
    lit.thd = rest_len1;
    lit.f3 = blocks0;
    lit.f4 = rest0;
    scrut = lit;
    num_blocks = scrut.fst;
    rest_len = scrut.thd;
    blocks = scrut.f3;
    rest = scrut.f4;
    ev_ = Hacl_Hash_Blake2s_128_update_multi_blake2s_128(s, ev, blocks, num_blocks);
    KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec128), (uint32_t)4U * (uint32_t)1U);
    {
      Lib_IntVector_Intrinsics_vec128 wv[(uint32_t)4U * (uint32_t)1U];
      {
        uint32_t _i;
        for (_i = 0U; _i < (uint32_t)4U * (uint32_t)1U; ++_i)
          wv[_i] = Lib_IntVector_Intrinsics_vec128_zero;
      }
      {
        uint8_t tmp[64U] = { 0U };
        uint8_t *tmp_rest = tmp;
        uint64_t totlen;
        memcpy(tmp_rest, rest, rest_len * sizeof (uint8_t));
        totlen = ev_ + (uint64_t)rest_len;
        {
          uint32_t m_w[16U] = { 0U };
          {
            uint32_t i;
            for (i = (uint32_t)0U; i < (uint32_t)16U; i++)
            {
              uint32_t *os = m_w;
              uint8_t *bj = tmp + i * (uint32_t)4U;
              uint32_t u = load32_le(bj);
              uint32_t r = u;
              uint32_t x = r;
              os[i] = x;
            }
          }
          {
            Lib_IntVector_Intrinsics_vec128 mask = Lib_IntVector_Intrinsics_vec128_zero;
            uint32_t wv_14 = (uint32_t)0xFFFFFFFFU;
            uint32_t wv_15 = (uint32_t)0U;
            Lib_IntVector_Intrinsics_vec128 *wv3;
            Lib_IntVector_Intrinsics_vec128 *s00;
            Lib_IntVector_Intrinsics_vec128 *s16;
            Lib_IntVector_Intrinsics_vec128 *r00;
            Lib_IntVector_Intrinsics_vec128 *r10;
            Lib_IntVector_Intrinsics_vec128 *r20;
            Lib_IntVector_Intrinsics_vec128 *r30;
            mask =
              Lib_IntVector_Intrinsics_vec128_load32s((uint32_t)totlen,
                (uint32_t)(totlen >> (uint32_t)32U),
                wv_14,
                wv_15);
            memcpy(wv, s, (uint32_t)4U * (uint32_t)1U * sizeof (Lib_IntVector_Intrinsics_vec128));
            wv3 = wv + (uint32_t)3U * (uint32_t)1U;
            wv3[0U] = Lib_IntVector_Intrinsics_vec128_xor(wv3[0U], mask);
            {
              uint32_t i;
              for (i = (uint32_t)0U; i < (uint32_t)10U; i++)
              {
                uint32_t start_idx = i % (uint32_t)10U * (uint32_t)16U;
                KRML_CHECK_SIZE(sizeof (Lib_IntVector_Intrinsics_vec128),
                  (uint32_t)4U * (uint32_t)1U);
                {
                  Lib_IntVector_Intrinsics_vec128 m_st[(uint32_t)4U * (uint32_t)1U];
                  {
                    uint32_t _i;
                    for (_i = 0U; _i < (uint32_t)4U * (uint32_t)1U; ++_i)
                      m_st[_i] = Lib_IntVector_Intrinsics_vec128_zero;
                  }
                  {
                    Lib_IntVector_Intrinsics_vec128 *r0 = m_st + (uint32_t)0U * (uint32_t)1U;
                    Lib_IntVector_Intrinsics_vec128 *r1 = m_st + (uint32_t)1U * (uint32_t)1U;
                    Lib_IntVector_Intrinsics_vec128 *r21 = m_st + (uint32_t)2U * (uint32_t)1U;
                    Lib_IntVector_Intrinsics_vec128 *r31 = m_st + (uint32_t)3U * (uint32_t)1U;
                    uint32_t s0 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx];
                    uint32_t s1 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)1U];
                    uint32_t s2 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)2U];
                    uint32_t s3 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)3U];
                    uint32_t s4 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)4U];
                    uint32_t s5 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)5U];
                    uint32_t s6 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)6U];
                    uint32_t s7 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)7U];
                    uint32_t s8 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)8U];
                    uint32_t s9 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)9U];
                    uint32_t s10 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)10U];
                    uint32_t s11 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)11U];
                    uint32_t s12 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)12U];
                    uint32_t s13 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)13U];
                    uint32_t s14 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)14U];
                    uint32_t s15 = Hacl_Impl_Blake2_Constants_sigmaTable[start_idx + (uint32_t)15U];
                    r0[0U] =
                      Lib_IntVector_Intrinsics_vec128_load32s(m_w[s0],
                        m_w[s2],
                        m_w[s4],
                        m_w[s6]);
                    r1[0U] =
                      Lib_IntVector_Intrinsics_vec128_load32s(m_w[s1],
                        m_w[s3],
                        m_w[s5],
                        m_w[s7]);
                    r21[0U] =
                      Lib_IntVector_Intrinsics_vec128_load32s(m_w[s8],
                        m_w[s10],
                        m_w[s12],
                        m_w[s14]);
                    r31[0U] =
                      Lib_IntVector_Intrinsics_vec128_load32s(m_w[s9],
                        m_w[s11],
                        m_w[s13],
                        m_w[s15]);
                    {
                      Lib_IntVector_Intrinsics_vec128 *x = m_st + (uint32_t)0U * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec128 *y = m_st + (uint32_t)1U * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec128 *z = m_st + (uint32_t)2U * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec128 *w = m_st + (uint32_t)3U * (uint32_t)1U;
                      uint32_t a = (uint32_t)0U;
                      uint32_t b0 = (uint32_t)1U;
                      uint32_t c0 = (uint32_t)2U;
                      uint32_t d0 = (uint32_t)3U;
                      Lib_IntVector_Intrinsics_vec128 *wv_a0 = wv + a * (uint32_t)1U;
                      Lib_IntVector_Intrinsics_vec128 *wv_b0 = wv + b0 * (uint32_t)1U;
                      wv_a0[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a0[0U], wv_b0[0U]);
                      wv_a0[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a0[0U], x[0U]);
                      {
                        Lib_IntVector_Intrinsics_vec128 *wv_a1 = wv + d0 * (uint32_t)1U;
                        Lib_IntVector_Intrinsics_vec128 *wv_b1 = wv + a * (uint32_t)1U;
                        wv_a1[0U] = Lib_IntVector_Intrinsics_vec128_xor(wv_a1[0U], wv_b1[0U]);
                        wv_a1[0U] =
                          Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a1[0U],
                            (uint32_t)16U);
                        {
                          Lib_IntVector_Intrinsics_vec128 *wv_a2 = wv + c0 * (uint32_t)1U;
                          Lib_IntVector_Intrinsics_vec128 *wv_b2 = wv + d0 * (uint32_t)1U;
                          wv_a2[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a2[0U], wv_b2[0U]);
                          {
                            Lib_IntVector_Intrinsics_vec128 *wv_a3 = wv + b0 * (uint32_t)1U;
                            Lib_IntVector_Intrinsics_vec128 *wv_b3 = wv + c0 * (uint32_t)1U;
                            wv_a3[0U] = Lib_IntVector_Intrinsics_vec128_xor(wv_a3[0U], wv_b3[0U]);
                            wv_a3[0U] =
                              Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a3[0U],
                                (uint32_t)12U);
                            {
                              Lib_IntVector_Intrinsics_vec128 *wv_a4 = wv + a * (uint32_t)1U;
                              Lib_IntVector_Intrinsics_vec128 *wv_b4 = wv + b0 * (uint32_t)1U;
                              wv_a4[0U] =
                                Lib_IntVector_Intrinsics_vec128_add32(wv_a4[0U],
                                  wv_b4[0U]);
                              wv_a4[0U] = Lib_IntVector_Intrinsics_vec128_add32(wv_a4[0U], y[0U]);
                              {
                                Lib_IntVector_Intrinsics_vec128 *wv_a5 = wv + d0 * (uint32_t)1U;
                                Lib_IntVector_Intrinsics_vec128 *wv_b5 = wv + a * (uint32_t)1U;
                                wv_a5[0U] =
                                  Lib_IntVector_Intrinsics_vec128_xor(wv_a5[0U],
                                    wv_b5[0U]);
                                wv_a5[0U] =
                                  Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a5[0U],
                                    (uint32_t)8U);
                                {
                                  Lib_IntVector_Intrinsics_vec128 *wv_a6 = wv + c0 * (uint32_t)1U;
                                  Lib_IntVector_Intrinsics_vec128 *wv_b6 = wv + d0 * (uint32_t)1U;
                                  wv_a6[0U] =
                                    Lib_IntVector_Intrinsics_vec128_add32(wv_a6[0U],
                                      wv_b6[0U]);
                                  {
                                    Lib_IntVector_Intrinsics_vec128 *wv_a7 = wv + b0 * (uint32_t)1U;
                                    Lib_IntVector_Intrinsics_vec128 *wv_b7 = wv + c0 * (uint32_t)1U;
                                    wv_a7[0U] =
                                      Lib_IntVector_Intrinsics_vec128_xor(wv_a7[0U],
                                        wv_b7[0U]);
                                    wv_a7[0U] =
                                      Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a7[0U],
                                        (uint32_t)7U);
                                    {
                                      Lib_IntVector_Intrinsics_vec128
                                      *r11 = wv + (uint32_t)1U * (uint32_t)1U;
                                      Lib_IntVector_Intrinsics_vec128
                                      *r22 = wv + (uint32_t)2U * (uint32_t)1U;
                                      Lib_IntVector_Intrinsics_vec128
                                      *r32 = wv + (uint32_t)3U * (uint32_t)1U;
                                      Lib_IntVector_Intrinsics_vec128 v00 = r11[0U];
                                      Lib_IntVector_Intrinsics_vec128
                                      v1 =
                                        Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v00,
                                          (uint32_t)1U);
                                      r11[0U] = v1;
                                      {
                                        Lib_IntVector_Intrinsics_vec128 v01 = r22[0U];
                                        Lib_IntVector_Intrinsics_vec128
                                        v10 =
                                          Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v01,
                                            (uint32_t)2U);
                                        r22[0U] = v10;
                                        {
                                          Lib_IntVector_Intrinsics_vec128 v02 = r32[0U];
                                          Lib_IntVector_Intrinsics_vec128
                                          v11 =
                                            Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v02,
                                              (uint32_t)3U);
                                          r32[0U] = v11;
                                          {
                                            uint32_t a0 = (uint32_t)0U;
                                            uint32_t b = (uint32_t)1U;
                                            uint32_t c = (uint32_t)2U;
                                            uint32_t d = (uint32_t)3U;
                                            Lib_IntVector_Intrinsics_vec128
                                            *wv_a = wv + a0 * (uint32_t)1U;
                                            Lib_IntVector_Intrinsics_vec128
                                            *wv_b8 = wv + b * (uint32_t)1U;
                                            wv_a[0U] =
                                              Lib_IntVector_Intrinsics_vec128_add32(wv_a[0U],
                                                wv_b8[0U]);
                                            wv_a[0U] =
                                              Lib_IntVector_Intrinsics_vec128_add32(wv_a[0U],
                                                z[0U]);
                                            {
                                              Lib_IntVector_Intrinsics_vec128
                                              *wv_a8 = wv + d * (uint32_t)1U;
                                              Lib_IntVector_Intrinsics_vec128
                                              *wv_b9 = wv + a0 * (uint32_t)1U;
                                              wv_a8[0U] =
                                                Lib_IntVector_Intrinsics_vec128_xor(wv_a8[0U],
                                                  wv_b9[0U]);
                                              wv_a8[0U] =
                                                Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a8[0U],
                                                  (uint32_t)16U);
                                              {
                                                Lib_IntVector_Intrinsics_vec128
                                                *wv_a9 = wv + c * (uint32_t)1U;
                                                Lib_IntVector_Intrinsics_vec128
                                                *wv_b10 = wv + d * (uint32_t)1U;
                                                wv_a9[0U] =
                                                  Lib_IntVector_Intrinsics_vec128_add32(wv_a9[0U],
                                                    wv_b10[0U]);
                                                {
                                                  Lib_IntVector_Intrinsics_vec128
                                                  *wv_a10 = wv + b * (uint32_t)1U;
                                                  Lib_IntVector_Intrinsics_vec128
                                                  *wv_b11 = wv + c * (uint32_t)1U;
                                                  wv_a10[0U] =
                                                    Lib_IntVector_Intrinsics_vec128_xor(wv_a10[0U],
                                                      wv_b11[0U]);
                                                  wv_a10[0U] =
                                                    Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a10[0U],
                                                      (uint32_t)12U);
                                                  {
                                                    Lib_IntVector_Intrinsics_vec128
                                                    *wv_a11 = wv + a0 * (uint32_t)1U;
                                                    Lib_IntVector_Intrinsics_vec128
                                                    *wv_b12 = wv + b * (uint32_t)1U;
                                                    wv_a11[0U] =
                                                      Lib_IntVector_Intrinsics_vec128_add32(wv_a11[0U],
                                                        wv_b12[0U]);
                                                    wv_a11[0U] =
                                                      Lib_IntVector_Intrinsics_vec128_add32(wv_a11[0U],
                                                        w[0U]);
                                                    {
                                                      Lib_IntVector_Intrinsics_vec128
                                                      *wv_a12 = wv + d * (uint32_t)1U;
                                                      Lib_IntVector_Intrinsics_vec128
                                                      *wv_b13 = wv + a0 * (uint32_t)1U;
                                                      wv_a12[0U] =
                                                        Lib_IntVector_Intrinsics_vec128_xor(wv_a12[0U],
                                                          wv_b13[0U]);
                                                      wv_a12[0U] =
                                                        Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a12[0U],
                                                          (uint32_t)8U);
                                                      {
                                                        Lib_IntVector_Intrinsics_vec128
                                                        *wv_a13 = wv + c * (uint32_t)1U;
                                                        Lib_IntVector_Intrinsics_vec128
                                                        *wv_b14 = wv + d * (uint32_t)1U;
                                                        wv_a13[0U] =
                                                          Lib_IntVector_Intrinsics_vec128_add32(wv_a13[0U],
                                                            wv_b14[0U]);
                                                        {
                                                          Lib_IntVector_Intrinsics_vec128
                                                          *wv_a14 = wv + b * (uint32_t)1U;
                                                          Lib_IntVector_Intrinsics_vec128
                                                          *wv_b = wv + c * (uint32_t)1U;
                                                          wv_a14[0U] =
                                                            Lib_IntVector_Intrinsics_vec128_xor(wv_a14[0U],
                                                              wv_b[0U]);
                                                          wv_a14[0U] =
                                                            Lib_IntVector_Intrinsics_vec128_rotate_right32(wv_a14[0U],
                                                              (uint32_t)7U);
                                                          {
                                                            Lib_IntVector_Intrinsics_vec128
                                                            *r12 = wv + (uint32_t)1U * (uint32_t)1U;
                                                            Lib_IntVector_Intrinsics_vec128
                                                            *r2 = wv + (uint32_t)2U * (uint32_t)1U;
                                                            Lib_IntVector_Intrinsics_vec128
                                                            *r3 = wv + (uint32_t)3U * (uint32_t)1U;
                                                            Lib_IntVector_Intrinsics_vec128
                                                            v0 = r12[0U];
                                                            Lib_IntVector_Intrinsics_vec128
                                                            v12 =
                                                              Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v0,
                                                                (uint32_t)3U);
                                                            r12[0U] = v12;
                                                            {
                                                              Lib_IntVector_Intrinsics_vec128
                                                              v03 = r2[0U];
                                                              Lib_IntVector_Intrinsics_vec128
                                                              v13 =
                                                                Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v03,
                                                                  (uint32_t)2U);
                                                              r2[0U] = v13;
                                                              {
                                                                Lib_IntVector_Intrinsics_vec128
                                                                v04 = r3[0U];
                                                                Lib_IntVector_Intrinsics_vec128
                                                                v14 =
                                                                  Lib_IntVector_Intrinsics_vec128_rotate_right_lanes32(v04,
                                                                    (uint32_t)1U);
                                                                r3[0U] = v14;
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            s00 = s + (uint32_t)0U * (uint32_t)1U;
            s16 = s + (uint32_t)1U * (uint32_t)1U;
            r00 = wv + (uint32_t)0U * (uint32_t)1U;
            r10 = wv + (uint32_t)1U * (uint32_t)1U;
            r20 = wv + (uint32_t)2U * (uint32_t)1U;
            r30 = wv + (uint32_t)3U * (uint32_t)1U;
            s00[0U] = Lib_IntVector_Intrinsics_vec128_xor(s00[0U], r00[0U]);
            s00[0U] = Lib_IntVector_Intrinsics_vec128_xor(s00[0U], r20[0U]);
            s16[0U] = Lib_IntVector_Intrinsics_vec128_xor(s16[0U], r10[0U]);
            s16[0U] = Lib_IntVector_Intrinsics_vec128_xor(s16[0U], r30[0U]);
            return (uint64_t)0U;
          }
        }
      }
    }
  }
}

void Hacl_Hash_Blake2s_128_hash_blake2s_128(uint8_t *input, uint32_t input_len, uint8_t *dst)
{
  Hacl_Blake2s_128_blake2s((uint32_t)32U, dst, input_len, input, (uint32_t)0U, NULL);
}

uint32_t Hacl_Hash_Definitions_word_len(Spec_Hash_Definitions_hash_alg a)
{
  switch (a)
  {
    case Spec_Hash_Definitions_MD5:
      {
        return (uint32_t)4U;
      }
    case Spec_Hash_Definitions_SHA1:
      {
        return (uint32_t)4U;
      }
    case Spec_Hash_Definitions_SHA2_224:
      {
        return (uint32_t)4U;
      }
    case Spec_Hash_Definitions_SHA2_256:
      {
        return (uint32_t)4U;
      }
    case Spec_Hash_Definitions_SHA2_384:
      {
        return (uint32_t)8U;
      }
    case Spec_Hash_Definitions_SHA2_512:
      {
        return (uint32_t)8U;
      }
    case Spec_Hash_Definitions_Blake2S:
      {
        return (uint32_t)4U;
      }
    case Spec_Hash_Definitions_Blake2B:
      {
        return (uint32_t)8U;
      }
    default:
      {
        KRML_HOST_PRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
}

uint32_t Hacl_Hash_Definitions_block_len(Spec_Hash_Definitions_hash_alg a)
{
  switch (a)
  {
    case Spec_Hash_Definitions_MD5:
      {
        return (uint32_t)64U;
      }
    case Spec_Hash_Definitions_SHA1:
      {
        return (uint32_t)64U;
      }
    case Spec_Hash_Definitions_SHA2_224:
      {
        return (uint32_t)64U;
      }
    case Spec_Hash_Definitions_SHA2_256:
      {
        return (uint32_t)64U;
      }
    case Spec_Hash_Definitions_SHA2_384:
      {
        return (uint32_t)128U;
      }
    case Spec_Hash_Definitions_SHA2_512:
      {
        return (uint32_t)128U;
      }
    case Spec_Hash_Definitions_Blake2S:
      {
        return (uint32_t)64U;
      }
    case Spec_Hash_Definitions_Blake2B:
      {
        return (uint32_t)128U;
      }
    default:
      {
        KRML_HOST_PRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
}

uint32_t Hacl_Hash_Definitions_hash_word_len(Spec_Hash_Definitions_hash_alg a)
{
  switch (a)
  {
    case Spec_Hash_Definitions_MD5:
      {
        return (uint32_t)4U;
      }
    case Spec_Hash_Definitions_SHA1:
      {
        return (uint32_t)5U;
      }
    case Spec_Hash_Definitions_SHA2_224:
      {
        return (uint32_t)7U;
      }
    case Spec_Hash_Definitions_SHA2_256:
      {
        return (uint32_t)8U;
      }
    case Spec_Hash_Definitions_SHA2_384:
      {
        return (uint32_t)6U;
      }
    case Spec_Hash_Definitions_SHA2_512:
      {
        return (uint32_t)8U;
      }
    case Spec_Hash_Definitions_Blake2S:
      {
        return (uint32_t)8U;
      }
    case Spec_Hash_Definitions_Blake2B:
      {
        return (uint32_t)8U;
      }
    default:
      {
        KRML_HOST_PRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
}

uint32_t Hacl_Hash_Definitions_hash_len(Spec_Hash_Definitions_hash_alg a)
{
  switch (a)
  {
    case Spec_Hash_Definitions_MD5:
      {
        return (uint32_t)16U;
      }
    case Spec_Hash_Definitions_SHA1:
      {
        return (uint32_t)20U;
      }
    case Spec_Hash_Definitions_SHA2_224:
      {
        return (uint32_t)28U;
      }
    case Spec_Hash_Definitions_SHA2_256:
      {
        return (uint32_t)32U;
      }
    case Spec_Hash_Definitions_SHA2_384:
      {
        return (uint32_t)48U;
      }
    case Spec_Hash_Definitions_SHA2_512:
      {
        return (uint32_t)64U;
      }
    case Spec_Hash_Definitions_Blake2S:
      {
        return (uint32_t)32U;
      }
    case Spec_Hash_Definitions_Blake2B:
      {
        return (uint32_t)64U;
      }
    default:
      {
        KRML_HOST_PRINTF("KaRaMeL incomplete match at %s:%d\n", __FILE__, __LINE__);
        KRML_HOST_EXIT(253U);
      }
  }
}

