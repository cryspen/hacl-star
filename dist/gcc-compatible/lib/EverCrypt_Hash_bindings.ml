open Ctypes
module Bindings(F:Cstubs.FOREIGN) =
  struct
    open F
    module Hacl_Spec_applied = (Hacl_Spec_bindings.Bindings)(Hacl_Spec_stubs)
    open Hacl_Spec_applied
    type everCrypt_Hash_alg = spec_Hash_Definitions_hash_alg
    let everCrypt_Hash_alg =
      typedef spec_Hash_Definitions_hash_alg "EverCrypt_Hash_alg"
    let constant everCrypt_Hash_string_of_alg =
      foreign "EverCrypt_Hash_string_of_alg"
        (spec_Hash_Definitions_hash_alg @-> (returning string))
    type everCrypt_Hash_broken_alg = spec_Hash_Definitions_hash_alg
    let everCrypt_Hash_broken_alg =
      typedef spec_Hash_Definitions_hash_alg "EverCrypt_Hash_broken_alg"
    type everCrypt_Hash_alg13 = spec_Hash_Definitions_hash_alg
    let everCrypt_Hash_alg13 =
      typedef spec_Hash_Definitions_hash_alg "EverCrypt_Hash_alg13"
    type everCrypt_Hash_state_s_tags = Unsigned.UInt8.t
    let everCrypt_Hash_state_s_tags =
      typedef uint8_t "EverCrypt_Hash_state_s_tags"
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_MD5_s =
      Unsigned.UInt8.of_int 0
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_SHA1_s =
      Unsigned.UInt8.of_int 1
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_SHA2_224_s =
      Unsigned.UInt8.of_int 2
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_SHA2_256_s =
      Unsigned.UInt8.of_int 3
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_SHA2_384_s =
      Unsigned.UInt8.of_int 4
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_SHA2_512_s =
      Unsigned.UInt8.of_int 5
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_Blake2S_s =
      Unsigned.UInt8.of_int 6
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_Blake2S_128_s =
      Unsigned.UInt8.of_int 7
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_Blake2B_s =
      Unsigned.UInt8.of_int 8
    let everCrypt_Hash_state_s_tags_EverCrypt_Hash_Blake2B_256_s =
      Unsigned.UInt8.of_int 9
    let everCrypt_Hash_update_multi_256 =
      foreign "EverCrypt_Hash_update_multi_256"
        ((ptr uint32_t) @-> (ocaml_bytes @-> (uint32_t @-> (returning void))))
    let everCrypt_Hash_update_last_256 =
      foreign "EverCrypt_Hash_update_last_256"
        ((ptr uint32_t) @->
           (uint64_t @-> (ocaml_bytes @-> (uint32_t @-> (returning void)))))
    let everCrypt_Hash_hash_256 =
      foreign "EverCrypt_Hash_hash_256"
        (ocaml_bytes @-> (uint32_t @-> (ocaml_bytes @-> (returning void))))
    let everCrypt_Hash_hash_224 =
      foreign "EverCrypt_Hash_hash_224"
        (ocaml_bytes @-> (uint32_t @-> (ocaml_bytes @-> (returning void))))
    let everCrypt_Hash_hash =
      foreign "EverCrypt_Hash_hash"
        (spec_Hash_Definitions_hash_alg @->
           (ocaml_bytes @-> (ocaml_bytes @-> (uint32_t @-> (returning void)))))
    let everCrypt_Hash_Incremental_hash_len =
      foreign "EverCrypt_Hash_Incremental_hash_len"
        (spec_Hash_Definitions_hash_alg @-> (returning uint32_t))
    let everCrypt_Hash_Incremental_block_len =
      foreign "EverCrypt_Hash_Incremental_block_len"
        (spec_Hash_Definitions_hash_alg @-> (returning uint32_t))
  end