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


#ifndef __internal_Hacl_K256_ECDSA_H
#define __internal_Hacl_K256_ECDSA_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <string.h>
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include "krml/internal/target.h"


#include "internal/Hacl_Krmllib.h"
#include "internal/Hacl_Bignum.h"
#include "../Hacl_K256_ECDSA.h"
#include "evercrypt_targetconfig.h"
#include "lib_intrinsics.h"
#include "libintvector.h"
/* SNIPPET_START: Hacl_Impl_K256_Point_aff_point_decompress_vartime */

bool Hacl_Impl_K256_Point_aff_point_decompress_vartime(uint64_t *x, uint64_t *y, uint8_t *s);

/* SNIPPET_END: Hacl_Impl_K256_Point_aff_point_decompress_vartime */

/* SNIPPET_START: Hacl_Impl_K256_Point_aff_point_compress_vartime */

void Hacl_Impl_K256_Point_aff_point_compress_vartime(uint8_t *s, uint64_t *x, uint64_t *y);

/* SNIPPET_END: Hacl_Impl_K256_Point_aff_point_compress_vartime */

/* SNIPPET_START: Hacl_Impl_K256_Point_point_negate */

void Hacl_Impl_K256_Point_point_negate(uint64_t *out, uint64_t *p);

/* SNIPPET_END: Hacl_Impl_K256_Point_point_negate */

/* SNIPPET_START: Hacl_Impl_K256_Point_point_eq */

bool Hacl_Impl_K256_Point_point_eq(uint64_t *p, uint64_t *q);

/* SNIPPET_END: Hacl_Impl_K256_Point_point_eq */

/* SNIPPET_START: Hacl_Impl_K256_PointDouble_point_double */

void Hacl_Impl_K256_PointDouble_point_double(uint64_t *out, uint64_t *p);

/* SNIPPET_END: Hacl_Impl_K256_PointDouble_point_double */

/* SNIPPET_START: Hacl_Impl_K256_PointAdd_point_add */

void Hacl_Impl_K256_PointAdd_point_add(uint64_t *out, uint64_t *p, uint64_t *q);

/* SNIPPET_END: Hacl_Impl_K256_PointAdd_point_add */

/* SNIPPET_START: Hacl_Impl_K256_PointMul_point_mul */

void Hacl_Impl_K256_PointMul_point_mul(uint64_t *out, uint64_t *scalar, uint64_t *q);

/* SNIPPET_END: Hacl_Impl_K256_PointMul_point_mul */

#if defined(__cplusplus)
}
#endif

#define __internal_Hacl_K256_ECDSA_H_DEFINED
#endif
