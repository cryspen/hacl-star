module Hacl.Frodo.KEM

open FStar.HyperStack.All
open FStar.HyperStack
open FStar.HyperStack.ST
open FStar.Mul

open LowStar.Buffer
open LowStar.BufferOps

open Lib.IntTypes
open Lib.PQ.Buffer
open Hacl.Impl.Matrix
open Hacl.Impl.Frodo.Params
open Hacl.Impl.Frodo.KEM

#reset-options "--z3rlimit 50 --max_fuel 0 --max_ifuel 0 --using_facts_from '* -FStar.Seq'"

val crypto_kem_keypair:
    pk:lbytes crypto_publickeybytes
  -> sk:lbytes crypto_secretkeybytes
  -> Stack uint32
    (requires fun h -> live h pk /\ live h sk /\ disjoint pk sk)
    (ensures  fun h0 r h1 -> live h1 pk /\ live h1 sk /\
      modifies (loc_union (loc_buffer pk) (loc_buffer sk)) h0 h1)
let crypto_kem_keypair pk sk = Hacl.Impl.Frodo.KEM.KeyGen.crypto_kem_keypair pk sk

val crypto_kem_enc:
    ct:lbytes crypto_ciphertextbytes
  -> ss:lbytes crypto_bytes
  -> pk:lbytes crypto_publickeybytes
  -> Stack uint32
    (requires fun h ->
      live h ct /\ live h ss /\ live h pk /\
      disjoint ct ss /\ disjoint ct pk /\ disjoint ss pk)
    (ensures  fun h0 _ h1 -> modifies (loc_union (loc_buffer ct) (loc_buffer ss)) h0 h1)
let crypto_kem_enc ct ss pk = Hacl.Impl.Frodo.KEM.Encaps.crypto_kem_enc ct ss pk

val crypto_kem_dec:
    ss:lbytes crypto_bytes
  -> ct:lbytes crypto_ciphertextbytes
  -> sk:lbytes crypto_secretkeybytes
  -> Stack uint32
    (requires fun h ->
      live h ss /\ live h ct /\ live h sk /\
      disjoint ss ct /\ disjoint ss sk /\ disjoint ct sk)
    (ensures  fun h0 r h1 -> live h1 ss /\ modifies (loc_buffer ss) h0 h1)
let crypto_kem_dec ss ct sk = Hacl.Impl.Frodo.KEM.Decaps.crypto_kem_dec ss ct sk
