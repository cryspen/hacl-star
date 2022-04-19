module Hacl.Impl.Blake2.Scalar

module ST = FStar.HyperStack.ST
open FStar.HyperStack
open FStar.HyperStack.All
open FStar.Mul

open Lib.IntTypes
open Lib.Buffer
open Lib.ByteBuffer

module Loops = Lib.LoopCombinators
module Spec = Spec.Blake2.Scalar
module Constants = Hacl.Impl.Blake2.Scalar.Constants

noextract inline_for_extraction
unfold let state_p (a:Spec.alg) =
  lbuffer (Spec.word_t a) 16ul

noextract inline_for_extraction
unfold let state_v (#a:Spec.alg) (h:mem) (st:state_p a) : GTot (Spec.state a) =
       as_seq h st

noextract inline_for_extraction
unfold let index_t = n:size_t{v n < 16}

noextract inline_for_extraction
let size_block (a:Spec.alg) : x:size_t{v x = 16 * Spec.size_word a} =
  Spec.alg_inversion_lemma a;
  match a with
  | Spec.Blake2S -> 64ul
  | Spec.Blake2B -> 128ul

noextract inline_for_extraction
unfold let block_p (a:Spec.alg) =
  lbuffer uint8 (size_block a)

noextract inline_for_extraction
type block_w_p (a:Spec.alg) = lbuffer (Spec.word_t a) 16ul

noextract inline_for_extraction
val alloc_state: a:Spec.alg ->
	  StackInline (state_p a)
	  (requires (fun h -> True))
	  (ensures (fun h0 r h1 -> stack_allocated r h0 h1 (Lib.Sequence.create 16 (Spec.zero a)) /\
				live h1 r))

let alloc_state a = 
  create 16ul (Spec.zero a)


noextract inline_for_extraction
val copy_state: #a:Spec.alg -> st2:state_p a -> st1:state_p a ->
	  Stack unit
	  (requires (fun h0 -> live h0 st1 /\ live h0 st2 /\ disjoint st1 st2))
	  (ensures (fun h0 r h1 -> modifies (loc st2) h0 h1 /\
			        state_v h1 st2 == state_v h0 st1))


let copy_state st2 st1 =
  copy #_ #_ #16ul st2 st1

/// Accessors for constants

#set-options "--z3rlimit 200 --max_ifuel 0 --max_fuel 0"

inline_for_extraction noextract
val get_iv:
  a:Spec.alg
  -> s: size_t{size_v s < 8} ->
  Stack (Spec.word_t a)
    (requires (fun h -> True))
    (ensures  (fun h0 z h1 -> h0 == h1 /\
      v z == v (Seq.index (Spec.ivTable a) (v s))))

let get_iv a s =
  recall_contents #(Spec.pub_word_t Spec.Blake2S) #8ul Constants.ivTable_S (Spec.ivTable Spec.Blake2S);
  recall_contents #(Spec.pub_word_t Spec.Blake2B) #8ul Constants.ivTable_B (Spec.ivTable Spec.Blake2B);
  [@inline_let]
  let ivTable: (x:glbuffer (Spec.pub_word_t a) 8ul{witnessed x (Spec.ivTable a) /\ recallable x}) =
    match a with
    | Spec.Blake2S -> Constants.ivTable_S
    | Spec.Blake2B -> Constants.ivTable_B
  in
  let r = index ivTable s in
  secret #(Spec.wt a) r


inline_for_extraction noextract
val get_sigma:
  i:size_t{v i < 12} ->
  s:size_t{v s < 16} ->
  Stack Spec.sigma_elt_t
    (requires (fun h -> True))
    (ensures  (fun h0 z h1 -> h0 == h1 /\ v z == Spec.sigma (v i) (v s)))

let get_sigma i s =
  recall_contents Constants.sigmaTable Spec.sigmaTable;
  index Constants.sigmaTable (16ul *. i +. s)


(*
inline_for_extraction noextract
val get_sigma_sub:
  start: size_t ->
  i: size_t{v i < 16 /\ v start + v i < 160} ->
  Stack Spec.sigma_elt_t
    (requires (fun h -> True))
    (ensures  (fun h0 z h1 -> h0 == h1 /\ v z == v (Seq.index Spec.sigmaTable (v start + v i))))

let get_sigma_sub start i = get_sigma (start +. i)
*)

inline_for_extraction noextract
let rounds_t (a:Spec.alg): size_t = size (Spec.rounds a)

inline_for_extraction noextract
val size_to_word: al:Spec.alg -> s:size_t -> u:Spec.word_t al{u == Spec.nat_to_word al (v s)}
let size_to_word al s = match al with
  | Spec.Blake2S -> size_to_uint32 s
  | Spec.Blake2B -> size_to_uint64 s

inline_for_extraction noextract
val size_to_limb: al:Spec.alg -> s:size_t -> u:Spec.limb_t al{u == Spec.nat_to_limb al (v s)}
let size_to_limb al s = match al with
  | Spec.Blake2S -> size_to_uint64 s
  | Spec.Blake2B -> to_u128 (size_to_uint64 s)

inline_for_extraction noextract
val g1: #al:Spec.alg -> wv:state_p al -> a:index_t -> b:index_t -> r:rotval (Spec.wt al) ->
  Stack unit
    (requires (fun h -> live h wv /\ a <> b))
    (ensures  (fun h0 _ h1 -> modifies (loc wv) h0 h1
                         /\ (state_v h1 wv) == Spec.g1 al (state_v h0 wv) (v a) (v b) r))

let g1 #al wv a b r =
  wv.(a) <- (wv.(a) ^. wv.(b)) >>>. r 

inline_for_extraction noextract
val g2: #al:Spec.alg -> wv:state_p al -> a:index_t -> b:index_t -> x:Spec.word_t al ->
  Stack unit
    (requires (fun h -> live h wv /\ a <> b))
    (ensures  (fun h0 _ h1 -> modifies (loc wv) h0 h1
                         /\ state_v h1 wv == Spec.g2 al (state_v h0 wv) (v a) (v b) x))

let g2 #al wv a b x =
  wv.(a) <- wv.(a) +. wv.(b) +. x

inline_for_extraction noextract
val g2z: #al:Spec.alg -> wv:state_p al -> a:index_t -> b:index_t ->
  Stack unit
    (requires (fun h -> live h wv /\ a <> b))
    (ensures  (fun h0 _ h1 -> modifies (loc wv) h0 h1
                         /\ state_v h1 wv == Spec.g2z al (state_v h0 wv) (v a) (v b)))

let g2z #al wv a b =
  wv.(a) <- wv.(a) +. wv.(b)

inline_for_extraction noextract
val blake2_mixing : #al:Spec.alg -> wv:state_p al ->
  a:index_t -> b:index_t -> c:index_t -> d:index_t ->
  x:Spec.word_t al -> y:Spec.word_t al ->
  Stack unit
    (requires (fun h -> live h wv /\ a <> b /\ a <> d /\ c <> d /\ b <> c ))
    (ensures  (fun h0 _ h1 -> modifies (loc wv) h0 h1
     /\ state_v h1 wv == Spec.blake2_mixing al (state_v h0 wv) (v a) (v b) (v c) (v d) x y))

let blake2_mixing #al wv a b c d x y =
  reveal_opaque (`%Spec.blake2_mixing) Spec.blake2_mixing;
  let h0 = ST.get() in
  push_frame ();
  [@inline_let]
  let r0 = normalize_term (Lib.Sequence.index (Spec.rTable al) 0) in
  normalize_term_spec (Lib.Sequence.index (Spec.rTable al) 0);
  [@inline_let]
  let r1 = normalize_term (Lib.Sequence.index (Spec.rTable al) 1) in
  normalize_term_spec (Lib.Sequence.index (Spec.rTable al) 1);
  [@inline_let]
  let r2 = normalize_term (Lib.Sequence.index (Spec.rTable al) 2) in
  normalize_term_spec (Lib.Sequence.index (Spec.rTable al) 2);
  [@inline_let]
  let r3 = normalize_term (Lib.Sequence.index (Spec.rTable al) 3) in
  normalize_term_spec (Lib.Sequence.index (Spec.rTable al) 3);
  let h1 = ST.get() in
  g2 wv a b x;
  g1 wv d a r0;
  g2z wv c d;
  g1 wv b c r1;
  g2 wv a b y;
  g1 wv d a r2;
  g2z wv c d;
  g1 wv b c r3;
  let h2 = ST.get() in
  pop_frame ();
  let h3 = ST.get() in
  assert(modifies (loc wv) h0 h3);
  Lib.Sequence.eq_intro (state_v h2 wv) (Spec.blake2_mixing al (state_v h1 wv) (v a) (v b) (v c) (v d) (x) (y))

inline_for_extraction noextract
val blake2_round : #al:Spec.alg -> wv:state_p al ->  m:block_w_p al -> i:size_t{v i < 12} ->
  Stack unit
    (requires (fun h -> live h wv /\ live h m /\ disjoint wv m))
    (ensures  (fun h0 _ h1 -> modifies (loc wv) h0 h1
                         /\ state_v h1 wv == Spec.blake2_round al (as_seq h0 m) (v i) (state_v h0 wv)))

let blake2_round #al wv m i =
  reveal_opaque (`%Spec.blake2_round) Spec.blake2_round;
  push_frame();
  let m0 = m.(get_sigma i 0ul) in
  let m1 = m.(get_sigma i 1ul) in
  let m2 = m.(get_sigma i 2ul) in
  let m3 = m.(get_sigma i 3ul) in
  let m4 = m.(get_sigma i 4ul) in
  let m5 = m.(get_sigma i 5ul) in
  let m6 = m.(get_sigma i 6ul) in
  let m7 = m.(get_sigma i 7ul) in
  let m8 = m.(get_sigma i 8ul) in
  let m9 = m.(get_sigma i 9ul) in
  let m10 = m.(get_sigma i 10ul) in
  let m11 = m.(get_sigma i 11ul) in
  let m12 = m.(get_sigma i 12ul) in
  let m13 = m.(get_sigma i 13ul) in
  let m14 = m.(get_sigma i 14ul) in
  let m15 = m.(get_sigma i 15ul) in
  let h1 = ST.get() in
  blake2_mixing wv 0ul 4ul 8ul 12ul m0 m1;
  blake2_mixing wv 1ul 5ul 9ul 13ul m2 m3;
  blake2_mixing wv 2ul 6ul 10ul 14ul m4 m5;
  blake2_mixing wv 3ul 7ul 11ul 15ul m6 m7;
  blake2_mixing wv 0ul 5ul 10ul 15ul m8 m9;
  blake2_mixing wv 1ul 6ul 11ul 12ul m10 m11;
  blake2_mixing wv 2ul 7ul 8ul 13ul m12 m13;
  blake2_mixing wv 3ul 4ul 9ul 14ul m14 m15;
  pop_frame ()


inline_for_extraction noextract
val blake2_compress0:
    #al:Spec.alg
  -> m_s: block_p al
  -> m_w: block_w_p al
  -> Stack unit
    (requires (fun h -> live h m_s /\ live h m_w /\ disjoint m_s m_w))
    (ensures  (fun h0 _ h1 -> modifies (loc m_w) h0 h1
                         /\ as_seq h1 m_w == Spec.blake2_compress0 al (as_seq h0 m_s)))

let blake2_compress0 #al m_s m_w =
  uints_from_bytes_le m_w m_s

inline_for_extraction noextract
val blake2_compress1:
    #al:Spec.alg
  -> wv: state_p al
  -> s_iv: state_p al
  -> offset: Spec.limb_t al
  -> flag: bool ->
  Stack unit
    (requires (fun h -> live h wv /\ live h s_iv /\ disjoint wv s_iv))
    (ensures  (fun h0 _ h1 -> modifies (loc wv) h0 h1
                         /\ state_v h1 wv == Spec.blake2_compress1 al (state_v h0 s_iv) offset flag))

let blake2_compress1 #al wv s_iv offset flag =
  let h0 = ST.get() in
  push_frame();
  [@inline_let]
  let wv_12 = Spec.limb_to_word al offset in
  [@inline_let]
  let wv_13 = Spec.limb_to_word al (offset >>. (size (bits (Spec.wt al)))) in
  // SH: TODO: for some reason, ``ones`` below doesn't get inlined by KaRaMeL,
  // causing an extraction problem. The 3 lines below are a hack to fix
  // extraction for the time being:
  // [> let wv_14 = if flag then (ones (Spec.wt al) SEC) else (Spec.zero al) in
  // After investigation, it is because ones is [@(strict_on_arguments [0])],
  // and so isn't unfolded if its first argument is not normalized to a constant.
  // However, the first argument should always be normalized (I checked the
  // output generated by KaRaMeL and the definitions).
  (**) normalize_term_spec (Spec.wt al);
  [@inline_let] let wt_al = normalize_term (Spec.wt al) in
  let wv_14 = if flag then ones wt_al SEC else (Spec.zero al) in
  // end of the TODO
  copy_state wv s_iv;
  wv.(12ul) <- wv.(12ul) ^. wv_12;
  wv.(13ul) <- wv.(13ul) ^. wv_13;
  wv.(14ul) <- wv.(14ul) ^. wv_14;
  pop_frame();
  let h1 = ST.get() in
  assert(modifies (loc wv) h0 h1);
  Lib.Sequence.eq_intro (state_v h1 wv) (Spec.blake2_compress1 al (state_v h0 s_iv) offset flag)

inline_for_extraction noextract
val blake2_compress2 :
  #al:Spec.alg
  -> wv: state_p al
  -> m: block_w_p al ->
  Stack unit
    (requires (fun h -> live h wv /\ live h m /\ disjoint wv m))
    (ensures  (fun h0 _ h1 -> modifies1 wv h0 h1
                         /\ state_v h1 wv == Spec.blake2_compress2 al (state_v h0 wv) (as_seq h0 m)))

let blake2_compress2 #al wv m =
  let h0 = ST.get () in
  [@inline_let]
  let a_spec = Spec.state al in
  [@inline_let]
  let refl h = state_v h wv in
  [@inline_let]
  let footprint = Ghost.hide(loc wv) in
  [@inline_let]
  let spec h = Spec.blake2_round al h.[|m|] in
  loop_refl h0 (rounds_t al) a_spec refl footprint spec
  (fun i ->
    Loops.unfold_repeati (Spec.rounds al) (spec h0) (state_v h0 wv) (v i);
    blake2_round wv m i)

inline_for_extraction noextract
val blake2_compress3 :
  #al:Spec.alg
  -> s_iv:state_p al
  -> wv:state_p al ->
  Stack unit
    (requires (fun h -> live h s_iv /\ live h wv /\ disjoint s_iv wv))
    (ensures  (fun h0 _ h1 -> modifies (loc s_iv) h0 h1
                         /\ state_v h1 s_iv == Spec.blake2_compress3 al (state_v h0 wv) (state_v h0 s_iv)))

let blake2_compress3 #al s_iv wv =
  let h0 = ST.get() in
  let s0 = s_iv.(0ul) in
  let s1 = s_iv.(1ul) in
  let s2 = s_iv.(2ul) in
  let s3 = s_iv.(3ul) in
  let s4 = s_iv.(4ul) in
  let s5 = s_iv.(5ul) in
  let s6 = s_iv.(6ul) in
  let s7 = s_iv.(7ul) in
  s_iv.(0ul) <- (s0 ^. wv.(0ul)) ^. wv.(8ul);
  s_iv.(1ul) <- (s1 ^. wv.(1ul)) ^. wv.(9ul);
  s_iv.(2ul) <- (s2 ^. wv.(2ul)) ^. wv.(10ul);
  s_iv.(3ul) <- (s3 ^. wv.(3ul)) ^. wv.(11ul);
  s_iv.(4ul) <- (s4 ^. wv.(4ul)) ^. wv.(12ul);
  s_iv.(5ul) <- (s5 ^. wv.(5ul)) ^. wv.(13ul);
  s_iv.(6ul) <- (s6 ^. wv.(6ul)) ^. wv.(14ul);
  s_iv.(7ul) <- (s7 ^. wv.(7ul)) ^. wv.(15ul);
  let h1 = ST.get() in
  Lib.Sequence.eq_intro (state_v h1 s_iv) (Spec.blake2_compress3 al (state_v h0 wv) (state_v h0 s_iv))



inline_for_extraction noextract
let compress_t (al:Spec.alg) =
    wv:state_p al
  -> s: state_p al
  -> m: block_p al
  -> offset: Spec.limb_t al
  -> flag: bool ->
  Stack unit
    (requires (fun h -> live h wv /\ live h s /\ live h m /\ disjoint s m /\ disjoint wv s /\ disjoint wv m))
    (ensures  (fun h0 _ h1 -> modifies (loc s |+| loc wv) h0 h1
                         /\ state_v h1 s == Spec.blake2_compress al (state_v h0 s) h0.[|m|] offset flag))


inline_for_extraction noextract
val blake2_compress: #al:Spec.alg -> compress_t al
let blake2_compress #al wv s m offset flag =
  push_frame();
  let m_w = create 16ul (Spec.zero al) in
  blake2_compress0 #al m m_w;
  blake2_compress1 wv s offset flag;
  blake2_compress2 wv m_w;
  blake2_compress3 s wv;
  pop_frame()

inline_for_extraction noextract
let blake2_update_block_st (al:Spec.alg) =
    wv:state_p al
  -> hash: state_p al
  -> flag: bool
  -> totlen: Spec.limb_t al{v totlen <= Spec.max_limb al}
  -> d: block_p al ->
  Stack unit
    (requires (fun h -> live h wv /\ live h hash /\ live h d /\ disjoint hash d /\ disjoint wv hash /\ disjoint wv d))
    (ensures  (fun h0 _ h1 -> modifies (loc hash |+| loc wv) h0 h1
                         /\ state_v h1 hash == Spec.blake2_update_block al flag (v totlen) h0.[|d|] (state_v h0 hash)))

inline_for_extraction noextract
val blake2_update_block: #al:Spec.alg -> blake2_update_block_st al

let blake2_update_block #al wv hash flag totlen d =
    blake2_compress wv hash d totlen flag

inline_for_extraction noextract
let blake2_update1_st (al:Spec.alg) =
   #len:size_t
  -> wv: state_p al
  -> hash: state_p al
  -> prev: Spec.limb_t al{v prev + v len <= Spec.max_limb al}
  -> d: lbuffer uint8 len
  -> i: size_t{v i < length d / Spec.size_block al} ->
  Stack unit
    (requires (fun h -> live h wv /\ live h hash /\ live h d /\ disjoint hash d /\ disjoint wv hash /\ disjoint wv d))
    (ensures  (fun h0 _ h1 -> modifies (loc hash |+| loc wv) h0 h1
                         /\ state_v h1 hash == Spec.blake2_update1 al (v prev) h0.[|d|] (v i) (state_v h0 hash)))

inline_for_extraction noextract
val blake2_update1: #al:Spec.alg -> blake2_update_block: blake2_update_block_st al -> blake2_update1_st al

let blake2_update1 #al blake2_update_block #len wv hash prev d i =
  let totlen = prev +. size_to_limb al ((i+!1ul) *! size_block al) in
  assert (v totlen == v prev + (v i + 1) * Spec.size_block al);
  let b = sub d (i *. size_block al) (size_block al) in
  let h = ST.get() in
  assert (as_seq h b == Spec.get_blocki al (as_seq h d) (v i));
  blake2_update_block wv hash false totlen b

inline_for_extraction noextract
let blake2_update_last_st (al:Spec.alg) =
   #len:size_t
  -> wv: state_p al
  -> hash: state_p al
  -> prev: Spec.limb_t al{v prev + v len <= Spec.max_limb al}
  -> rem: size_t {v rem <= v len /\ v rem <= Spec.size_block al}
  -> d: lbuffer uint8 len ->
  Stack unit
    (requires (fun h -> live h wv /\ live h hash /\ live h d /\ disjoint hash d /\ disjoint wv hash /\ disjoint wv d))
    (ensures  (fun h0 _ h1 -> modifies (loc hash |+| loc wv) h0 h1
                         /\ state_v h1 hash == Spec.blake2_update_last al (v prev) (v rem) h0.[|d|] (state_v h0 hash)))

inline_for_extraction noextract
val blake2_update_last:
     #al:Spec.alg
  -> blake2_update_block: blake2_update_block_st al
  -> blake2_update_last_st al

#push-options "--z3rlimit 200"
let blake2_update_last #al blake2_update_block #len wv hash prev rem d =
  let h0 = ST.get () in
  let last = sub d (len -! rem) rem in
  [@inline_let]
  let spec _ h1 = state_v h1 hash == Spec.blake2_update_last al (v prev) (v rem) h0.[|d|] (state_v h0 hash) in
  salloc1 h0 (size_block al) (u8 0) (Ghost.hide (loc hash |+| loc wv)) spec
  (fun last_block ->
    let h1 = ST.get() in
    assert(disjoint last_block last);
    update_sub last_block 0ul rem last;
    let h2 = ST.get() in
    as_seq_gsub h1 d (len -! rem) rem;
    assert (as_seq h1 last == Lib.Sequence.sub (as_seq h1 d) (v len - v rem) (v rem));
    assert (as_seq h1 last == Lib.Sequence.slice (as_seq h0 d) (v len - v rem) (v len));
    assert (as_seq h2 last_block == Spec.get_last_padded_block al (as_seq h0 d) (v rem));
    let totlen = prev +. (size_to_limb al len) in
    blake2_update_block wv hash true totlen last_block;
    let h3 = ST.get() in
    assert (v totlen == v prev + v len);
    assert (state_v h3 hash == Spec.blake2_update_block al true (v totlen) (as_seq h2 last_block) (state_v h0 hash)))
#pop-options

inline_for_extraction noextract
let blake2_init_st  (al:Spec.alg) =
    s_iv: state_p al
  -> kk: size_t{v kk <= Spec.max_key al}
  -> nn: size_t{1 <= v nn /\ v nn <= Spec.max_output al} ->
  Stack unit
    (requires (fun h -> live h s_iv))
    (ensures  (fun h0 _ h1 -> modifies (loc s_iv) h0 h1 /\
			   state_v h1 s_iv == Spec.blake2_init_hash al (v kk) (v nn)))

inline_for_extraction noextract
val blake2_init:
    #al:Spec.alg
  -> blake2_init_st al

#push-options "--z3rlimit 200"
let blake2_init #al s_iv kk nn =
  let h0 = ST.get() in
  let iv0 = get_iv al 0ul in
  let iv1 = get_iv al 1ul in
  let iv2 = get_iv al 2ul in
  let iv3 = get_iv al 3ul in
  let iv4 = get_iv al 4ul in
  let iv5 = get_iv al 5ul in
  let iv6 = get_iv al 6ul in
  let iv7 = get_iv al 7ul in
  let kk_shift_8 = shift_left (size_to_word al kk) (size 8) in
  let s0 = (Spec.nat_to_word al 0x01010000) ^. kk_shift_8 ^. (size_to_word al nn) in
  assert (s0 == (Spec.nat_to_word al 0x01010000) ^. ((Spec.nat_to_word al (v kk)) <<. (size 8)) ^. (Spec.nat_to_word al (v nn)));
  let iv0' = iv0 ^. s0 in
  s_iv.(0ul) <- iv0';
  s_iv.(1ul) <- iv1;
  s_iv.(2ul) <- iv2;
  s_iv.(3ul) <- iv3;
  s_iv.(4ul) <- iv4;
  s_iv.(5ul) <- iv5;
  s_iv.(6ul) <- iv6;
  s_iv.(7ul) <- iv7;
  s_iv.(8ul) <- iv0;
  s_iv.(9ul) <- iv1;
  s_iv.(10ul) <- iv2;
  s_iv.(11ul) <- iv3;
  s_iv.(12ul) <- iv4;
  s_iv.(13ul) <- iv5;
  s_iv.(14ul) <- iv6;
  s_iv.(15ul) <- iv7;
  let h1 = ST.get() in
  assert(modifies (loc s_iv) h0 h1);
  admit();
  Lib.Sequence.eq_intro (state_v h1 s_iv) (Spec.blake2_init_hash al (v kk) (v nn))
#pop-options

let _ : squash (inversion Spec.alg) = allow_inversion Spec.alg

inline_for_extraction noextract
val split_blocks: al:Spec.alg -> len:size_t -> r:(size_t & size_t){
					  let (x,y) = r in
					  let (sx,sy) = Spec.split al (v len) in
					  sx == v x /\
					  sy == v y}

let split_blocks al len =
  let nb = len /. size_block al in
  let rem = len %. size_block al in
  if rem =. 0ul && nb >. 0ul then
      let nb' = nb -! 1ul in
      let rem' = size_block al in
      (nb',rem')
  else (nb,rem)

inline_for_extraction noextract
let blake2_update_multi_st (al : Spec.alg) =
     #len:size_t
  -> wv: state_p al
  -> hash: state_p al
  -> prev: Spec.limb_t al{v prev + v len <= Spec.max_limb al}
  -> blocks: lbuffer uint8 len
  -> nb : size_t{length blocks >= v nb * v (size_block al) } ->
  Stack unit
    (requires (fun h -> live h wv /\ live h hash /\ live h blocks /\
                      disjoint hash blocks /\ disjoint wv hash /\ disjoint wv blocks))
    (ensures  (fun h0 _ h1 ->
      modifies (loc hash |+| loc wv) h0 h1 /\
      state_v h1 hash == Lib.LoopCombinators.repeati (v nb) (Spec.blake2_update1 al (v prev) h0.[|blocks|])
                                 (state_v h0 hash)))

inline_for_extraction noextract
val blake2_update_multi (#al : Spec.alg) :
     blake2_update_block:blake2_update_block_st al
  -> blake2_update_multi_st al

let blake2_update_multi #al blake2_update_block #len wv hash prev blocks nb =
  let h0 = ST.get () in
  [@inline_let]
  let a_spec = Spec.state al in
  [@inline_let]
  let refl h = state_v h hash in
  [@inline_let]
  let footprint = Ghost.hide(loc hash |+| loc wv) in
  [@inline_let]
  let spec h = Spec.blake2_update1 al (v prev) h.[|blocks|] in
  loop_refl h0 nb a_spec refl footprint spec
  (fun i ->
    Loops.unfold_repeati (v nb) (spec h0) (state_v h0 hash) (v i);
    blake2_update1 #al blake2_update_block #len wv hash prev blocks i)

inline_for_extraction noextract
let blake2_update_blocks_st (al : Spec.alg) =
     #len:size_t
  -> wv: state_p al
  -> hash: state_p al
  -> prev: Spec.limb_t al{v prev + v len <= Spec.max_limb al}
  -> blocks: lbuffer uint8 len ->
  Stack unit
    (requires (fun h -> live h wv /\ live h hash /\ live h blocks /\ disjoint hash blocks /\ disjoint wv hash /\ disjoint wv blocks))
    (ensures  (fun h0 _ h1 -> modifies (loc hash |+| loc wv) h0 h1 /\
			   state_v h1 hash ==
			   Spec.blake2_update_blocks al (v prev) h0.[|blocks|] (state_v h0 hash)))

inline_for_extraction noextract
val blake2_update_blocks (#al : Spec.alg) :
     blake2_update_multi_st al
  -> blake2_update_last_st al
  -> blake2_update_blocks_st al

let blake2_update_blocks #al blake2_update_multi blake2_update_last #len wv hash prev blocks =
  let (nb,rem) = split_blocks al len in
  blake2_update_multi wv hash prev blocks nb;
  blake2_update_last #len wv hash prev rem blocks

inline_for_extraction noextract
let blake2_finish_st (al:Spec.alg) =
    nn: size_t{1 <= v nn /\ v nn <= Spec.max_output al}
  -> output: lbuffer uint8 nn
  -> hash: state_p al ->
  Stack unit
    (requires (fun h -> live h hash /\ live h output /\ disjoint output hash))
    (ensures  (fun h0 _ h1 -> modifies (loc output) h0 h1
                         /\ h1.[|output|] == Spec.blake2_finish al (state_v h0 hash) (v nn)))

inline_for_extraction noextract
val blake2_finish:#al:Spec.alg -> blake2_finish_st al

let blake2_finish #al nn output hash =
  let h0 = ST.get () in
  [@inline_let]
  let spec _ h1 = h1.[|output|] == Spec.blake2_finish al (state_v h0 hash) (v nn) in
  salloc1 h0 (size_block al) (u8 0) (Ghost.hide (loc output)) spec
  (fun full ->
    uints_to_bytes_le #(Spec.wt al) 16ul full hash;
    let final = sub full (size 0) nn in
    copy output final)


inline_for_extraction noextract
let blake2_update_key_st (al:Spec.alg) =
    wv:state_p al
  -> hash: state_p al
  -> kk: size_t{v kk > 0 /\ v kk <= Spec.max_key al}
  -> k: lbuffer uint8 kk
  -> ll: size_t ->
  Stack unit
    (requires (fun h -> live h wv /\ live h hash /\ live h k /\
                     disjoint hash k /\ disjoint wv hash /\ disjoint wv k))
    (ensures  (fun h0 _ h1 -> modifies (loc hash |+| loc wv) h0 h1
                         /\ state_v h1 hash == Spec.blake2_update_key al (v kk) h0.[|k|] (v ll) (state_v h0 hash)))

inline_for_extraction noextract
val blake2_update_key:
     #al:Spec.alg
  -> blake2_update_block_st al
  -> blake2_update_key_st al

inline_for_extraction noextract
let blake2_update_key #al blake2_update_block wv hash kk k ll =
  let lb = size_to_limb al (size_block al) in
  assert (v lb = Spec.size_block al);
  let h0 = ST.get () in
  salloc1 h0 (size_block al) (u8 0) (Ghost.hide (loc hash |+| loc wv))
    (fun _ h1 -> live h1 hash /\ state_v h1 hash == Spec.blake2_update_key al (v kk) h0.[|k|] (v ll) (state_v h0 hash))
    (fun key_block ->
      update_sub key_block 0ul kk k;
      let h1 = ST.get() in
      if ll =. 0ul then
         blake2_update_block wv hash true lb key_block
      else
         blake2_update_block wv hash false lb key_block)

inline_for_extraction noextract
let blake2_update_st (al:Spec.alg) =
    wv:state_p al
  -> hash: state_p al
  -> kk: size_t{v kk <= Spec.max_key al}
  -> k: lbuffer uint8 kk
  -> ll: size_t
  -> d: lbuffer uint8 ll ->
  Stack unit
    (requires (fun h -> live h wv /\ live h hash /\ live h k /\ live h d /\
                     disjoint hash k /\ disjoint wv hash /\ disjoint wv k /\
                     disjoint hash d /\ disjoint wv d /\ disjoint d k))
    (ensures  (fun h0 _ h1 -> modifies (loc hash |+| loc wv) h0 h1
                         /\ state_v h1 hash == Spec.blake2_update al (v kk) h0.[|k|] h0.[|d|] (state_v h0 hash)))


inline_for_extraction noextract
val blake2_update:
     #al:Spec.alg
  -> blake2_update_key_st al
  -> blake2_update_blocks_st al
  -> blake2_update_st al

inline_for_extraction noextract
let blake2_update #al blake2_update_key blake2_update_blocks
                  wv hash kk k ll d =
    let lb = size_to_limb al (size_block al) in
    assert (v lb = Spec.size_block al);
    if kk >. 0ul then (
      blake2_update_key wv hash kk k ll;
      if ll =. 0ul then ()
      else blake2_update_blocks wv hash lb d)
    else blake2_update_blocks wv hash (size_to_limb al 0ul) d


inline_for_extraction noextract
let blake2_st (al:Spec.alg) =
    nn:size_t{1 <= v nn /\ v nn <= Spec.max_output al}
  -> output: lbuffer uint8 nn
  -> ll: size_t
  -> d: lbuffer uint8 ll
  -> kk: size_t{v kk <= Spec.max_key al}
  -> k: lbuffer uint8 kk ->
  Stack unit
    (requires (fun h -> live h output /\ live h d /\ live h k
                   /\ disjoint output d /\ disjoint output k /\ disjoint d k))
    (ensures  (fun h0 _ h1 -> modifies1 output h0 h1
                         /\ h1.[|output|] == Spec.blake2 al h0.[|d|] (v kk) h0.[|k|] (v nn)))

inline_for_extraction noextract
val blake2:
     #al:Spec.alg
  -> blake2_init_st al
  -> blake2_update_st al
  -> blake2_finish_st al
  -> blake2_st al

#push-options "--z3rlimit 100"
let blake2 #al blake2_init blake2_update blake2_finish nn output ll d kk k =
  let h0 = ST.get() in
  [@inline_let]
  let spec _ h1 = h1.[|output|] == Spec.blake2 al h0.[|d|] (v kk) h0.[|k|] (v nn) in
  salloc1 h0 16ul (Spec.zero al) (Ghost.hide (loc output)) spec
  (fun h ->
    assert (max_size_t <= Spec.max_limb al);
    let h1 = ST.get() in
    salloc1 h1 16ul (Spec.zero al) (Ghost.hide (loc output |+| loc h)) spec
    (fun wv ->
      blake2_init h kk nn;
      blake2_update wv h kk k ll d;
      blake2_finish nn output h))
#pop-options

