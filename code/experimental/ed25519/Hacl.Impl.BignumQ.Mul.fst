module Hacl.Impl.BignumQ.Mul

module ST = FStar.HyperStack.ST
open FStar.HyperStack.All
open FStar.Mul

open Lib.IntTypes
open Lib.Buffer

module SE = Spec.Ed25519

module S56 = Hacl.Spec.Ed25519.Field56.Definition

#reset-options "--z3rlimit 20 --max_fuel 0 --max_ifuel 0"

noextract
let mu_v : n:nat = 0xfffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c131b

inline_for_extraction noextract
val make_q:
  m:qelemB ->
  Stack unit
    (requires fun h -> live h m)
    (ensures  fun h0 _ h1 -> modifies (loc m) h0 h1 /\
      F56.as_nat h1 m == SE.q
    )
let make_q m =
  m.(0ul) <- u64 0x12631a5cf5d3ed;
  m.(1ul) <- u64 0xf9dea2f79cd658;
  m.(2ul) <- u64 0x000000000014de;
  m.(3ul) <- u64 0x00000000000000;
  m.(4ul) <- u64 0x00000010000000;
  assert_norm (S56.as_nat5 (u64 0x12631a5cf5d3ed, u64 0xf9dea2f79cd658,
    u64 0x000000000014de, u64 0x00000000000000,  u64 0x00000010000000) == SE.q)

inline_for_extraction noextract
val make_mu:
  m:qelemB ->
  Stack unit
    (requires fun h -> live h m)
    (ensures  fun h0 _ h1 -> modifies (loc m) h0 h1)
let make_mu m =
  m.(0ul) <- u64 0x9ce5a30a2c131b;
  m.(1ul) <- u64 0x215d086329a7ed;
  m.(2ul) <- u64 0xffffffffeb2106;
  m.(3ul) <- u64 0xffffffffffffff;
  m.(4ul) <- u64 0x00000fffffffff

inline_for_extraction noextract
val choose:
    z:qelemB
  -> x:qelemB
  -> y:qelemB
  -> b:uint64{v b == 0 \/ v b == 1} ->
  Stack unit
    (requires fun h -> live h x /\ live h y /\ live h z)
    (ensures  fun h0 _ h1 -> modifies (loc z) h0 h1 /\
      (v b == 0 ==> Seq.equal (as_seq h1 z) (as_seq h0 y)) /\
      (v b == 1 ==> Seq.equal (as_seq h1 z) (as_seq h0 x))
    )
let choose z x y b =
  let mask = b -. u64 1 in
  let x0 = x.(0ul) in
  let x1 = x.(1ul) in
  let x2 = x.(2ul) in
  let x3 = x.(3ul) in
  let x4 = x.(4ul) in
  let y0 = y.(0ul) in
  let y1 = y.(1ul) in
  let y2 = y.(2ul) in
  let y3 = y.(3ul) in
  let y4 = y.(4ul) in
  let z0 = x0 ^. ((y0 ^. x0) &. mask) in
  let z1 = x1 ^. ((y1 ^. x1) &. mask) in
  let z2 = x2 ^. ((y2 ^. x2) &. mask) in
  let z3 = x3 ^. ((y3 ^. x3) &. mask) in
  let z4 = x4 ^. ((y4 ^. x4) &. mask) in
  Hacl.Bignum25519.make_u64_5 z z0 z1 z2 z3 z4;
  let lemma_mask0 () : Lemma
    (requires v b == 0)
    (ensures y0 == z0 /\ y1 == z1 /\ y2 == z2 /\ y3 == z3 /\ y4 == z4)
    =
    Lib.IntTypes.Compatibility.uintv_extensionality mask (ones U64 SEC);
    logand_ones (y0 ^. x0);
    logand_ones (y1 ^. x1);
    logand_ones (y2 ^. x2);
    logand_ones (y3 ^. x3);
    logand_ones (y4 ^. x4);
    logxor_lemma x0 y0;
    logxor_lemma x1 y1;
    logxor_lemma x2 y2;
    logxor_lemma x3 y3;
    logxor_lemma x4 y4
  in
  let lemma_mask1 () : Lemma
    (requires v b == 1)
    (ensures x0 == z0 /\ x1 == z1 /\ x2 == z2 /\ x3 == z3 /\ x4 == z4)
    =
    assert (v mask == 0);
    logand_zeros (y0 ^. x0);
    logand_zeros (y1 ^. x1);
    logand_zeros (y2 ^. x2);
    logand_zeros (y3 ^. x3);
    logand_zeros (y4 ^. x4);
    logxor_lemma x0 x0;
    logxor_lemma x1 x0;
    logxor_lemma x2 x0;
    logxor_lemma x3 x0;
    logxor_lemma x4 x0
  in
  Classical.move_requires lemma_mask1 ();
  Classical.move_requires lemma_mask0 ()

inline_for_extraction noextract
let lt (a:uint64{v a < pow2 63}) (b:uint64{v b < pow2 63}) : (c:uint64{if v a >= v b then v c == 0 else v c == 1})
  = (a -. b) >>. 63ul

inline_for_extraction noextract
let shiftl_56 (b:uint64{v b == 0 \/ v b == 1}) : (c:uint64{v c == 0x100000000000000 * v b})
  =
    assert_norm ((1 * pow2 56) % pow2 64 == 0x100000000000000);
    assert_norm ((0 * pow2 56) % pow2 64 == 0);
    b <<. 56ul

inline_for_extraction noextract
let shiftl_40 (b:uint64{v b == 0 \/ v b == 1}) : (c:uint64{v c == 0x10000000000 * v b}) =
  assert_norm ((1 * pow2 40) % pow2 64 == 0x10000000000);
  assert_norm ((0 * pow2 40) % pow2 64 == 0);
  b <<. 40ul

let lemma_mult_distr4 (n:nat) (a b c d:nat) : Lemma
  (n * (a - b - c + d) == n * a - n * b - n * c + n * d)
  = ()

inline_for_extraction noextract
val sub_mod_264:
    z:qelemB
  -> x:qelemB
  -> y:qelemB ->
  Stack unit
    (requires fun h -> live h x /\ live h y /\ live h z /\
      F56.as_nat h x < pow2 264 /\
      F56.as_nat h y < pow2 264 /\
      (let s = as_seq h x in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000) /\
      (let s = as_seq h y in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000)
    )
    (ensures fun h0 _ h1 -> modifies (loc z) h0 h1 /\
      // (let s = as_seq h1 z in
      //  let op_String_Access = Seq.index in
      //  v s.[0] < 0x100000000000000 /\
      //  v s.[1] < 0x100000000000000 /\
      //  v s.[2] < 0x100000000000000 /\
      //  v s.[3] < 0x100000000000000 /\
      //  v s.[4] < 0x100000000000000) /\
      (F56.as_nat h0 x < F56.as_nat h0 y ==>
        F56.as_nat h1 z == pow2 264 + F56.as_nat h0 x - F56.as_nat h0 y) /\
      (F56.as_nat h0 x >= F56.as_nat h0 y ==>
        F56.as_nat h1 z ==  F56.as_nat h0 x - F56.as_nat h0 y)
    )

#push-options "--z3rlimit 600"

let sub_mod_264 z x y =
  assert_norm(pow2 264 = 0x1000000000000000000000000000000000000000000000000000000000000000000);
  assert_norm(pow2 64 = 0x10000000000000000);
  assert_norm(pow2 56 = 0x100000000000000);
  assert_norm(pow2 40 = 0x10000000000);
  assert_norm(pow2 32 = 0x100000000);
  let h0 = get() in

  let x0 = x.(0ul) in
  let x1 = x.(1ul) in
  let x2 = x.(2ul) in
  let x3 = x.(3ul) in
  let x4 = x.(4ul) in
  let y0 = y.(0ul) in
  let y1 = y.(1ul) in
  let y2 = y.(2ul) in
  let y3 = y.(3ul) in
  let y4 = y.(4ul) in
  let pb = y0 in
  let b0  = lt x0 y0 in
  let t0 = (shiftl_56 b0 +. x0) -. y0 in
  let y1' = y1 +. b0 in
  let b1  = lt x1 y1' in
  let t1 = (shiftl_56 b1 +. x1) -. y1' in
  let y2' = y2 +. b1 in
  let b2  = lt x2 y2' in
  let t2 = (shiftl_56 b2 +. x2) -. y2' in
  let y3' = y3 +. b2 in
  let b3  = lt x3 y3' in
  let t3 = (shiftl_56 b3 +. x3) -. y3' in
  let y4' = y4 +. b3 in
  let b4  = lt x4 y4' in
  let t4 = (shiftl_40 b4 +. x4) -. y4' in

  calc (==) {
    v t0 <: int;
    (==) { Math.Lemmas.small_mod (v (shiftl_56 b0) + v x0) (pow2 64);
           Math.Lemmas.small_mod (v (shiftl_56 b0 +. x0) - v y0) (pow2 64) }
    v x0 - v y0 + 0x100000000000000 * v b0;
  };
  calc (==) {
    v t1 <: int;
    (==) {  Math.Lemmas.small_mod (v y1 + v b0) (pow2 64);
            Math.Lemmas.small_mod (v (shiftl_56 b1) + v x1) (pow2 64);
            Math.Lemmas.small_mod (v (shiftl_56 b1 +. x1) - v y1') (pow2 64) }
     v x1 - v y1 - v b0 + 0x100000000000000 * v b1;
  };
  calc (==) {
    v t2 <: int;
    (==) {  Math.Lemmas.small_mod (v y2 + v b1) (pow2 64);
            Math.Lemmas.small_mod (v (shiftl_56 b2) + v x2) (pow2 64);
            Math.Lemmas.small_mod (v (shiftl_56 b2 +. x2) - v y2') (pow2 64) }
     v x2 - v y2 - v b1 + 0x100000000000000 * v b2;
  };
  calc (==) {
    v t3 <: int;
    (==) {  Math.Lemmas.small_mod (v y3 + v b2) (pow2 64);
            Math.Lemmas.small_mod (v (shiftl_56 b3) + v x3) (pow2 64);
            Math.Lemmas.small_mod (v (shiftl_56 b3 +. x3) - v y3') (pow2 64) }
     v x3 - v y3 - v b2 + 0x100000000000000 * v b3;
  };
  // calc (==) {
  //   v t4 <: int;
  //   (==) {  Math.Lemmas.small_mod (v y4 + v b3) (pow2 64);
  //           assert_norm (pow2 40 + pow2 56 < pow2 64);
  //           Math.Lemmas.small_mod (v (shiftl_40 b4) + v x4) (pow2 64) }
  //    (( 0x100000000000000 * v b4 + v x4) - (v y4 + v b3)) % pow2 64;
  // };
  admit();

  admit();
  // assert_norm (0x100000000000000 + (0x100000000000000 - 1) * pow2 56 + (0x100000000000000 - 1) * pow2 112 + (0x100000000000000 - 1) * pow2 168 + (0x10000000000 - 1) * pow2 224 == pow2 264);
  // Math.Lemmas.small_mod (v y1 + v b0) (pow2 64);
  // Math.Lemmas.small_mod (v ((shiftl_56 b1 +. x1) -. y1')) (pow2 64);
  // Math.Lemmas.small_mod (v (shiftl_56 b1 +. x1)) (pow2 64);
  // assert (v t1 == v x1 - v y1 - v b0 + 0x100000000000000 * v b1);
  // // assert (v t1 < 0x10000000000);
  // // admit();
  // // assume (v x1 - v y1' + 0x100000000000000 * v b1 == v t1 /\ v t1 < 0x10000000000);
  // Math.Lemmas.small_mod (v y2 + v b1) (pow2 64);
  // Math.Lemmas.small_mod (v ((shiftl_56 b2 +. x2) -. y2')) (pow2 64);
  // Math.Lemmas.small_mod (v (shiftl_56 b2 +. x2)) (pow2 64);
  // admit();
  // assert (v t2 == v x2 - v y2 - v b1 + 0x100000000000000 * v b2);
  // admit();
  // Math.Lemmas.small_mod (v y3 + v b2) (pow2 64);
  // assume (v t3 == v x3 - v y3 - v b2 + 0x100000000000000 * v b3);
  // Math.Lemmas.small_mod (v y4 + v b3) (pow2 64);
  // assume (v t4 == v x4 - v y4 - v b3 - 0x10000000000 * v b4);
  // let lemma_b () : Lemma
  //   (requires b4 == 0)
  //   (ensures F56.as_nat h0 x < F56.as_nat h0 y)
  //   = admit()
  // in
  // calc (==) {
  //   0x100000000000000 * v b0  + v x0 - v y0 +
  //   0x100000000000000 * (v x1 - v y1 - v b0 + 0x100000000000000 * v b1) +
  //   0x10000000000000000000000000000 * (v x2 - v y2 - v b1 + 0x100000000000000 * v b2) +
  //   0x1000000000000000000000000000000000000000000 * (v x3 - v y3 - v b2 + 0x100000000000000 * v b3) +
  //   0x100000000000000000000000000000000000000000000000000000000 * (
  //     v x4 - v y4 - v b3 + 0x10000000000 * v b4);
  //   (==) {lemma_mult_distr4 0x100000000000000 (v x1) (v y1) (v b0) (0x100000000000000 * v b1);
  //         lemma_mult_distr4 0x10000000000000000000000000000 (v x2) (v y2) (v b1) (0x100000000000000 * v b2);
  //         lemma_mult_distr4 0x1000000000000000000000000000000000000000000 (v x3) (v y3) (v b2) (0x100000000000000 * v b3);
  //         lemma_mult_distr4 0x100000000000000000000000000000000000000000000000000000000 (v x4) (v y4) (v b3) (0x100000000000000 * v b4)
  //   }
  //    v x0 - v y0 +
  //   0x100000000000000 * v x1 - 0x100000000000000 * v y1 +
  //   0x100000000000000 * (0x100000000000000 * v b1) +
  //   0x10000000000000000000000000000 * v x2 -
  //   0x10000000000000000000000000000 * v y2 -
  //   0x10000000000000000000000000000 * v b1 +
  //   0x10000000000000000000000000000 * (0x100000000000000 * v b2) +
  //   0x1000000000000000000000000000000000000000000 * v x3 -
  //   0x1000000000000000000000000000000000000000000 * v y3 -
  //   0x1000000000000000000000000000000000000000000 * v b2 +
  //   0x1000000000000000000000000000000000000000000 * (0x100000000000000 * v b3) +
  //   0x100000000000000000000000000000000000000000000000000000000 * v x4 -
  //   0x100000000000000000000000000000000000000000000000000000000 * v y4 -
  //   0x100000000000000000000000000000000000000000000000000000000 * v b3 +
  //   0x100000000000000000000000000000000000000000000000000000000 * (0x10000000000 * v b4);
  //   (==) { Math.Lemmas.paren_mul_right 0x100000000000000 0x100000000000000 (v b1);
  //          Math.Lemmas.paren_mul_right 0x10000000000000000000000000000 0x100000000000000 (v b2);
  //          Math.Lemmas.paren_mul_right 0x1000000000000000000000000000000000000000000  0x100000000000000 (v b3);
  //          Math.Lemmas.paren_mul_right 0x100000000000000000000000000000000000000000000000000000000 0x100000000000000 (v b4);
  //          assert_norm (0x100000000000000 * 0x100000000000000 == 0x10000000000000000000000000000)
  //   }

  //    v x0 - v y0 +
  //   0x100000000000000 * v x1 - 0x100000000000000 * v y1 +
  //   0x10000000000000000000000000000 * v x2 -
  //   0x10000000000000000000000000000 * v y2 +
  //   0x1000000000000000000000000000000000000000000 * v x3 -
  //   0x1000000000000000000000000000000000000000000 * v y3 +
  //   0x100000000000000000000000000000000000000000000000000000000 * v x4 -
  //   0x100000000000000000000000000000000000000000000000000000000 * v y4 +
  //   pow2 264 * v b4;
  //   (==) { }
  //   S56.as_nat5 (x0, x1, x2, x3, x4) - S56.as_nat5 (y0, y1, y2, y3, y4) + pow2 264 * v b4;
  // };
  // assume (v b4 <> 0 <==> F56.as_nat h0 x < F56.as_nat h0 y);
  Hacl.Bignum25519.make_u64_5 z t0 t1 t2 t3 t4

#pop-options

inline_for_extraction noextract
val subm_conditional:
    z:qelemB
  -> x:qelemB ->
  Stack unit
    (requires fun h -> live h x /\ live h z /\ disjoint x z /\
      (let s = as_seq h x in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000)
    )
    (ensures  fun h0 _ h1 -> modifies (loc z) h0 h1 /\
      (let s = as_seq h1 z in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000) /\
     (F56.as_nat h0 x >= SE.q ==> F56.as_nat h1 z == F56.as_nat h0 x - SE.q) /\
     (F56.as_nat h0 x < SE.q ==> F56.as_nat h1 z == F56.as_nat h0 x)
    )

let subm_conditional z x =
  admit();
  let h' = ST.get () in
  push_frame();
  let tmp = create 5ul (u64 0) in
  let h0 = ST.get () in
  let x0 = x.(0ul) in
  let x1 = x.(1ul) in
  let x2 = x.(2ul) in
  let x3 = x.(3ul) in
  let x4 = x.(4ul) in
  Hacl.Bignum25519.make_u64_5 tmp x0 x1 x2 x3 x4;

  let y0 = u64 0x12631a5cf5d3ed in
  let y1 = u64 0xf9dea2f79cd658 in
  let y2 = u64 0x000000000014de in
  let y3 = u64 0x00000000000000 in
  let y4 = u64 0x00000010000000 in
  let b  = lt x0 y0 in
  let t0 = (shiftl_56 b +. x0) -. y0 in
  let y1 = y1 +. b in
  let b  = lt x1 y1 in
  let t1 = (shiftl_56 b +. x1) -. y1 in
  let y2 = y2 +. b in
  let b  = lt x2 y2 in
  let t2 = (shiftl_56 b +. x2) -. y2 in
  let y3 = y3 +. b in
  let b  = lt x3 y3 in
  let t3 = (shiftl_56 b +. x3) -. y3 in
  let y4 = y4 +. b in
  let b  = lt x4 y4 in
  let t4 = (shiftl_56 b +. x4) -. y4 in
  Hacl.Bignum25519.make_u64_5 z t0 t1 t2 t3 t4;
  choose z tmp z b;
  pop_frame()

inline_for_extraction noextract
val mod_40: x:uint128 -> (c:uint64{v c == v x % pow2 40})
let mod_40 x =
  let x' = to_u64 x in
  assert_norm (pow2 40 - 1  == 0xffffffffff);
  logand_mask x' (u64 0xffffffffff) 40;
  let x'' = x' &. u64 0xffffffffff in
  x''

inline_for_extraction noextract
val low_mul_5:
    z:qelemB
  -> x:qelemB
  -> y:qelemB ->
  Stack unit
    (requires fun h -> live h z /\ live h x /\ live h y /\
      (let s = as_seq h x in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000) /\
      (let s = as_seq h y in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000)
    )
    (ensures  fun h0 _ h1 -> modifies (loc z) h0 h1 /\
      (let s = as_seq h1 z in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000) /\
     F56.as_nat h1 z == (F56.as_nat h0 x * F56.as_nat h0 y) % pow2 264
    )

let low_mul_5 z x y =
  let x0 = x.(0ul) in
  let x1 = x.(1ul) in
  let x2 = x.(2ul) in
  let x3 = x.(3ul) in
  let x4 = x.(4ul) in
  let y0 = y.(0ul) in
  let y1 = y.(1ul) in
  let y2 = y.(2ul) in
  let y3 = y.(3ul) in
  let y4 = y.(4ul) in
  let xy00 = mul64_wide x0 y0 in
  let xy01 = mul64_wide x0 y1 in
  let xy02 = mul64_wide x0 y2 in
  let xy03 = mul64_wide x0 y3 in
  let xy04 = mul64_wide x0 y4 in
  let xy10 = mul64_wide x1 y0 in
  let xy11 = mul64_wide x1 y1 in
  let xy12 = mul64_wide x1 y2 in
  let xy13 = mul64_wide x1 y3 in
  let xy20 = mul64_wide x2 y0 in
  let xy21 = mul64_wide x2 y1 in
  let xy22 = mul64_wide x2 y2 in
  let xy30 = mul64_wide x3 y0 in
  let xy31 = mul64_wide x3 y1 in
  let xy40 = mul64_wide x4 y0 in
  let x    = xy00 in
  let carry = x >>. 56ul in
  assert_norm (0xffffffffffffff == pow2 56 - 1);
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let t0  = t in
  let x = xy01 +. xy10 +. carry in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let t1 = t in
  let x = xy02 +. xy11 +. xy20 +. carry in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let t2 = t in
  let x = xy03 +. xy12 +. xy21 +. xy30 +. carry in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let t3 = t in
  let t4 = mod_40 (xy04 +. xy13 +. xy22 +. xy31 +. xy40 +. carry) in
  admit();
  Hacl.Bignum25519.make_u64_5 z t0 t1 t2 t3 t4

inline_for_extraction noextract
val mul_5:
    z:lbuffer uint128 9ul
  -> x:qelemB
  -> y:qelemB ->
  Stack unit
    (requires fun h -> live h z /\ live h x /\ live h y /\
      (let s = as_seq h x in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000) /\
      (let s = as_seq h y in
       let op_String_Access = Seq.index in
       v s.[0] < 0x100000000000000 /\
       v s.[1] < 0x100000000000000 /\
       v s.[2] < 0x100000000000000 /\
       v s.[3] < 0x100000000000000 /\
       v s.[4] < 0x100000000000000)
    )
    (ensures fun h0 _ h1 -> modifies (loc z) h0 h1 /\
      F56.feval_wide9 h1 z == F56.as_nat h0 x * F56.as_nat h0 y /\
      (let s = as_seq h1 z in
       let op_String_Access = Seq.index in
       v s.[0] < 0x10000000000000000000000000000 /\
       v s.[1] < 0x20000000000000000000000000000 /\
       v s.[2] < 0x30000000000000000000000000000 /\
       v s.[3] < 0x40000000000000000000000000000 /\
       v s.[4] < 0x50000000000000000000000000000 /\
       v s.[5] < 0x40000000000000000000000000000 /\
       v s.[6] < 0x30000000000000000000000000000 /\
       v s.[7] < 0x20000000000000000000000000000 /\
       v s.[8] < 0x10000000000000000000000000000)
    )

let mul_5 z x y =
  admit();
  let x0 = x.(0ul) in
  let x1 = x.(1ul) in
  let x2 = x.(2ul) in
  let x3 = x.(3ul) in
  let x4 = x.(4ul) in
  let y0 = y.(0ul) in
  let y1 = y.(1ul) in
  let y2 = y.(2ul) in
  let y3 = y.(3ul) in
  let y4 = y.(4ul) in
  let xy00 = mul64_wide x0 y0 in
  let xy01 = mul64_wide x0 y1 in
  let xy02 = mul64_wide x0 y2 in
  let xy03 = mul64_wide x0 y3 in
  let xy04 = mul64_wide x0 y4 in
  let xy10 = mul64_wide x1 y0 in
  let xy11 = mul64_wide x1 y1 in
  let xy12 = mul64_wide x1 y2 in
  let xy13 = mul64_wide x1 y3 in
  let xy14 = mul64_wide x1 y4 in
  let xy20 = mul64_wide x2 y0 in
  let xy21 = mul64_wide x2 y1 in
  let xy22 = mul64_wide x2 y2 in
  let xy23 = mul64_wide x2 y3 in
  let xy24 = mul64_wide x2 y4 in
  let xy30 = mul64_wide x3 y0 in
  let xy31 = mul64_wide x3 y1 in
  let xy32 = mul64_wide x3 y2 in
  let xy33 = mul64_wide x3 y3 in
  let xy34 = mul64_wide x3 y4 in
  let xy40 = mul64_wide x4 y0 in
  let xy41 = mul64_wide x4 y1 in
  let xy42 = mul64_wide x4 y2 in
  let xy43 = mul64_wide x4 y3 in
  let xy44 = mul64_wide x4 y4 in
  let z0 = xy00 in
  let z1 = xy01 +. xy10 in
  let z2 = xy02 +. xy11 +. xy20 in
  let z3 = xy03 +. xy12 +. xy21 +. xy30 in
  let z4 = xy04 +. xy13 +. xy22 +. xy31 +. xy40 in
  let z5 =         xy14 +. xy23 +. xy32 +. xy41 in
  let z6 =                 xy24 +. xy33 +. xy42 in
  let z7 =                         xy34 +. xy43 in
  let z8 =                                 xy44 in
  Hacl.Bignum25519.make_u128_9 z z0 z1 z2 z3 z4 z5 z6 z7 z8

inline_for_extraction noextract
val carry_step:
  x:uint128 -> y:uint128 -> uint64 & uint128
let carry_step x y =
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  t, y +. carry

inline_for_extraction noextract
val carry:
  t:lbuffer uint64 10ul
  -> z:lbuffer uint128 9ul ->
  Stack unit
    (requires fun h -> live h z /\ live h t)
    (ensures  fun h0 _ h1 -> modifies (loc t) h0 h1 /\
      fits_elem10 (as_seq h1 t) /\
      F56.as_nat10 h1 t == F56.feval_wide9 h0 z
    )
let carry out z =
  admit();
  let z0 = z.(0ul) in
  let z1 = z.(1ul) in
  let z2 = z.(2ul) in
  let z3 = z.(3ul) in
  let z4 = z.(4ul) in
  let z5 = z.(5ul) in
  let z6 = z.(6ul) in
  let z7 = z.(7ul) in
  let z8 = z.(8ul) in

  let x = z0  in let y = z1 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x0 = t in let z1' = y +. carry in

  let x = z1' in let y = z2 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x1 = t in let z2' = y +. carry in

  let x = z2' in let y = z3 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x2 = t in let z3' = y +. carry in

  let x = z3' in let y = z4 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x3 = t in let z4' = y +. carry in

  let x = z4' in let y = z5 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x4 = t in let z5' = y +. carry in

  let x = z5' in let y = z6 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x5 = t in let z6' = y +. carry in

  let x = z6' in let y = z7 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x6 = t in let z7' = y +. carry in

  let x = z7' in let y = z8 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x7 = t in let z8' = y +. carry in

  let x = z8' in let y = u128 0 in
  let carry = x >>. 56ul in
  let t     = to_u64 x &. u64 0xffffffffffffff in
  let x8 = t in let z9' = y +. carry in
  let x9 = to_u64 z9' in
  Hacl.Bignum25519.make_u64_10 out x0 x1 x2 x3 x4 x5 x6 x7 x8 x9

inline_for_extraction noextract
val mod_264:
    r:qelemB
  -> t:lbuffer uint64 10ul ->
  Stack unit
    (requires fun h -> live h r /\ live h t)
    (ensures  fun h0 _ h1 ->  modifies (loc r) h0 h1 /\
      F56.as_nat h1 r == F56.as_nat10 h0 t % pow2 264
    )
let mod_264 r t =
  admit();
  let x0 = t.(0ul) in
  let x1 = t.(1ul) in
  let x2 = t.(2ul) in
  let x3 = t.(3ul) in
  let x4 = t.(4ul) in
  let x4' = x4 &. u64 0xffffffffff in
  Hacl.Bignum25519.make_u64_5 r x0 x1 x2 x3 x4'

inline_for_extraction noextract
val div_2_24_step: x:uint64 -> y:uint64 -> uint64
let div_2_24_step x y =
  let y' = (y &. u64 0xffffff) <<. 32ul in
  let x' = x >>. 24ul in
  let z = y' |. x' in
  z

inline_for_extraction noextract
val div_2_40_step: x:uint64 -> y:uint64 -> uint64
let div_2_40_step x y =
  let y' = (y &. u64 0xffffffffff) <<. 16ul in
  let x' = x >>. 40ul in
  let z = y' |. x' in
  z

inline_for_extraction noextract
val div_248:
    q:qelemB
  -> t:lbuffer uint64 10ul ->
  Stack unit
    (requires fun h -> live h q /\ live h t)
    (ensures  fun h0 _ h1 -> modifies (loc q) h0 h1 /\
      F56.as_nat h1 q == F56.as_nat10 h0 t / pow2 248
    )
let div_248 out t =
  admit();
  let x0 = t.(0ul) in
  let x1 = t.(1ul) in
  let x2 = t.(2ul) in
  let x3 = t.(3ul) in
  let x4 = t.(4ul) in
  let x5 = t.(5ul) in
  let x6 = t.(6ul) in
  let x7 = t.(7ul) in
  let x8 = t.(8ul) in
  let x9 = t.(9ul) in
  let z0 = div_2_24_step x4 x5 in
  let z1 = div_2_24_step x5 x6 in
  let z2 = div_2_24_step x6 x7 in
  let z3 = div_2_24_step x7 x8 in
  let z4 = div_2_24_step x8 x9 in
  Hacl.Bignum25519.make_u64_5 out z0 z1 z2 z3 z4

inline_for_extraction noextract
val div_264:
    q:qelemB
  -> t:lbuffer uint64 10ul ->
  Stack unit
    (requires fun h -> live h q /\ live h t)
    (ensures  fun h0 _ h1 -> modifies (loc q) h0 h1 /\
      F56.as_nat h1 q == F56.as_nat10 h0 t / pow2 264
    )
let div_264 out t =
  admit();
  let x0 = t.(0ul) in
  let x1 = t.(1ul) in
  let x2 = t.(2ul) in
  let x3 = t.(3ul) in
  let x4 = t.(4ul) in
  let x5 = t.(5ul) in
  let x6 = t.(6ul) in
  let x7 = t.(7ul) in
  let x8 = t.(8ul) in
  let x9 = t.(9ul) in
  let z0 = div_2_40_step x4 x5 in
  let z1 = div_2_40_step x5 x6 in
  let z2 = div_2_40_step x6 x7 in
  let z3 = div_2_40_step x7 x8 in
  let z4 = div_2_40_step x8 x9 in
  Hacl.Bignum25519.make_u64_5 out z0 z1 z2 z3 z4

inline_for_extraction noextract
val barrett_reduction__1:
    qmu:lbuffer uint128 9ul
  -> t:lbuffer uint64 10ul
  -> mu:qelemB
  -> tmp:lbuffer uint64 30ul ->
  Stack unit
    (requires fun h ->
      live h t /\ live h qmu /\ live h mu /\ live h tmp /\
      disjoint tmp mu /\ disjoint tmp qmu)
    (ensures fun h0 _ h1 ->  modifies (loc qmu |+| loc tmp) h0 h1 /\
      (let q = F56.as_nat10 h0 t / pow2 248 in
       let qmu = q * mu_v in
       let qmu264 = qmu / pow2 264 in
       F56.as_nat h1 (gsub tmp 20ul 5ul) == qmu264)
    )
let barrett_reduction__1 qmu t mu tmp =
  let q   = sub tmp 0ul 5ul in
  let qmu'  = sub tmp 10ul 10ul in
  let qmu_264 = sub tmp 20ul 5ul in
  admit();
  div_248 q t;
  mul_5 qmu q mu;
  carry qmu' qmu;
  div_264 qmu_264 qmu'

inline_for_extraction noextract
val barrett_reduction__2:
    t:lbuffer uint64 10ul
  -> m:qelemB
  -> tmp:lbuffer uint64 30ul ->
  Stack unit
    (requires fun h ->
      live h t /\ live h m /\ live h tmp /\
      disjoint tmp m /\ disjoint tmp t)
    (ensures fun h0 _ h1 -> modifies (loc tmp) h0 h1)

let barrett_reduction__2 t m tmp =
  let qmul = sub tmp 0ul 5ul in
  let r    = sub tmp 5ul 5ul in
  let qmu_264 = sub tmp 20ul 5ul in
  let s    = sub tmp 25ul 5ul in
  admit();
  mod_264 r t;
  low_mul_5 qmul qmu_264 m;
  sub_mod_264 s r qmul

inline_for_extraction noextract
val barrett_reduction__:
    z:qelemB
  -> t:lbuffer uint64 10ul
  -> m:qelemB
  -> mu:qelemB
  -> tmp:lbuffer uint64 30ul ->
  Stack unit
    (requires fun h ->
      live h z /\ live h t /\ live h m /\ live h mu /\ live h tmp /\
      disjoint tmp t /\ disjoint tmp mu /\ disjoint tmp m /\ disjoint tmp z)
    (ensures fun h0 _ h1 -> modifies (loc z |+| loc tmp) h0 h1)
let barrett_reduction__ z t m mu tmp =
  let s   = sub tmp 25ul 5ul in
  admit();
  push_frame();
  let qmu = create 9ul (u128 0) in
  let h0 = ST.get () in
  barrett_reduction__1 qmu t mu tmp;
  let h1 = ST.get () in
  assert (modifies (loc qmu |+| loc tmp) h0 h1);
  barrett_reduction__2 t m tmp;
  let h2 = ST.get () in
  assert (modifies (loc tmp) h1 h2);
  assert (modifies (loc qmu |+| loc tmp) h0 h2);
  subm_conditional z s;
  let h3 = ST.get () in
  assert (modifies (loc z) h2 h3);
  assert (modifies (loc qmu |+| loc tmp |+| loc z) h0 h3);
  pop_frame()

inline_for_extraction noextract
val barrett_reduction_:
    z:qelemB
  -> t:lbuffer uint64 10ul ->
  Stack unit
    (requires fun h -> live h z /\ live h t)
    (ensures  fun h0 _ h1 -> modifies (loc z) h0 h1)
let barrett_reduction_ z t =
  push_frame();
  let tmp = create 40ul (u64 0) in
  let m   = sub tmp 0ul 5ul in
  let mu  = sub tmp 5ul 5ul in
  let tmp = sub tmp 10ul 30ul in
  make_q m;
  make_mu mu;
  barrett_reduction__ z t m mu tmp;
  pop_frame()

let barrett_reduction z t =
  admit();
  barrett_reduction_ z t

#reset-options "--z3rlimit 40 --max_fuel 0 --max_ifuel 0"

let mul_modq out x y =
  push_frame();
  let z' = create 10ul (u64 0) in
  let z  = create 9ul (u128 0) in
  mul_5 z x y;
  carry z' z;
  barrett_reduction out z';
  pop_frame()

inline_for_extraction noextract
val add_modq_:
    z:qelemB
  -> x:qelemB
  -> y:qelemB ->
  Stack unit
    (requires fun h -> live h z /\ live h x /\ live h y)
    (ensures  fun h0 _ h1 -> modifies (loc z) h0 h1 /\
      F56.as_nat h1 z == (F56.as_nat h0 x + F56.as_nat h0 y) % Spec.Ed25519.q
    )
let add_modq_ out x y =
  push_frame();
  let tmp = create 5ul (u64 0) in
  let x0 = x.(0ul) in
  let x1 = x.(1ul) in
  let x2 = x.(2ul) in
  let x3 = x.(3ul) in
  let x4 = x.(4ul) in
  let y0 = y.(0ul) in
  let y1 = y.(1ul) in
  let y2 = y.(2ul) in
  let y3 = y.(3ul) in
  let y4 = y.(4ul) in
  let z0 = x0 +. y0 in
  let z1 = x1 +. y1 in
  let z2 = x2 +. y2 in
  let z3 = x3 +. y3 in
  let z4 = x4 +. y4 in
  let x = z0  in let y = z1 in
  let carry =x >>. 56ul in
  let t     = x &. u64 0xffffffffffffff in
  let x0 = t in let z1' = y +. carry in

  let x = z1' in let y = z2 in
  let carry = x >>. 56ul in
  let t     = x &. u64 0xffffffffffffff in
  let x1 = t in let z2' = y +. carry in

  let x = z2' in let y = z3 in
  let carry = x >>. 56ul in
  let t     = x &. u64 0xffffffffffffff in
  let x2 = t in let z3' = y +. carry in

  let x = z3' in let y = z4 in
  let carry = x >>. 56ul in
  let t     = x &. u64 0xffffffffffffff in
  let x3 = t in let x4 = y +. carry in
  Hacl.Bignum25519.make_u64_5 tmp x0 x1 x2 x3 x4;
  admit();
  subm_conditional out tmp;
  pop_frame()

let add_modq out x y = admit(); add_modq_ out x y
