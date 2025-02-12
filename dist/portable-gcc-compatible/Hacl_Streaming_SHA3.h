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


#ifndef __Hacl_Streaming_SHA3_H
#define __Hacl_Streaming_SHA3_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <string.h>
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include "krml/internal/target.h"


#include "Lib_Memzero0.h"
#include "Hacl_Streaming_SHA2.h"
#include "Hacl_SHA3.h"
#include "evercrypt_targetconfig.h"
/* SNIPPET_START: Hacl_Streaming_SHA3_state_sha3_256 */

typedef Hacl_Streaming_SHA2_state_sha2_384 Hacl_Streaming_SHA3_state_sha3_256;

/* SNIPPET_END: Hacl_Streaming_SHA3_state_sha3_256 */

/* SNIPPET_START: Hacl_Streaming_SHA3_create_in_256 */

Hacl_Streaming_SHA2_state_sha2_384 *Hacl_Streaming_SHA3_create_in_256();

/* SNIPPET_END: Hacl_Streaming_SHA3_create_in_256 */

/* SNIPPET_START: Hacl_Streaming_SHA3_init_256 */

void Hacl_Streaming_SHA3_init_256(Hacl_Streaming_SHA2_state_sha2_384 *s);

/* SNIPPET_END: Hacl_Streaming_SHA3_init_256 */

/* SNIPPET_START: Hacl_Streaming_SHA3_update_256 */

void
Hacl_Streaming_SHA3_update_256(
  Hacl_Streaming_SHA2_state_sha2_384 *p,
  uint8_t *data,
  uint32_t len
);

/* SNIPPET_END: Hacl_Streaming_SHA3_update_256 */

/* SNIPPET_START: Hacl_Streaming_SHA3_finish_256 */

void Hacl_Streaming_SHA3_finish_256(Hacl_Streaming_SHA2_state_sha2_384 *p, uint8_t *dst);

/* SNIPPET_END: Hacl_Streaming_SHA3_finish_256 */

/* SNIPPET_START: Hacl_Streaming_SHA3_free_256 */

void Hacl_Streaming_SHA3_free_256(Hacl_Streaming_SHA2_state_sha2_384 *s);

/* SNIPPET_END: Hacl_Streaming_SHA3_free_256 */

#if defined(__cplusplus)
}
#endif

#define __Hacl_Streaming_SHA3_H_DEFINED
#endif
