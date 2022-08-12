// Copyright 2022 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "common/algorithms.h"

#include <string.h>

#include "everparse/SPDMWrapper.h"

static void get_base_alg_support(const SPDM_AsymHashAlgs* asym_hash_algs,
                                 bool is_resp,
                                 SpdmSupportedAlgs* supported_algs) {
  SpdmSupportedAsymAlgs* supported_asym_algs =
      is_resp ? &supported_algs->asym_verify : &supported_algs->asym_sign;

  supported_asym_algs->ecdsa_ecc_nist_p256 =
      (asym_hash_algs->base_asym_alg_ecdsa_ecc_nist_p256 == 1);
  supported_asym_algs->ecdsa_ecc_nist_p384 =
      (asym_hash_algs->base_asym_alg_ecdsa_ecc_nist_p384 == 1);
  supported_asym_algs->ecdsa_ecc_nist_p521 =
      (asym_hash_algs->base_asym_alg_ecdsa_ecc_nist_p521 == 1);

  supported_algs->hash_sha256 = (asym_hash_algs->base_hash_algo_sha_256 == 1);
  supported_algs->hash_sha384 = (asym_hash_algs->base_hash_algo_sha_384 == 1);
  supported_algs->hash_sha512 = (asym_hash_algs->base_hash_algo_sha_512 == 1);
}

static int get_dhe_support(buffer* alg_structs, buffer* rest, bool is_resp,
                           SpdmSupportedAlgs* supported_algs) {
  SPDM_AlgStruct_DHE dhe_msg;
  uint32_t alg_count_extended;
  int rc;

  rc = SpdmCheckDheAlg(alg_structs, rest, is_resp, &alg_count_extended);
  if (rc != 0) {
    return rc;
  }

  memcpy(&dhe_msg, alg_structs->data, sizeof(dhe_msg));

  supported_algs->dhe_secp256r1 = (dhe_msg.alg_supported_secp256r1 == 1);
  supported_algs->dhe_secp384r1 = (dhe_msg.alg_supported_secp384r1 == 1);
  supported_algs->dhe_secp521r1 = (dhe_msg.alg_supported_secp521r1 == 1);

  return 0;
}

static int get_aead_support(buffer* alg_structs, buffer* rest, bool is_resp,
                            SpdmSupportedAlgs* supported_algs) {
  SPDM_AlgStruct_AEAD aead_msg;
  uint32_t alg_count_extended;
  int rc;

  rc = SpdmCheckAeadAlg(alg_structs, rest, is_resp, &alg_count_extended);
  if (rc != 0) {
    return rc;
  }

  memcpy(&aead_msg, alg_structs->data, sizeof(aead_msg));

  supported_algs->aead_aes_128_gcm = (aead_msg.alg_supported_aes_128_gcm == 1);
  supported_algs->aead_aes_256_gcm = (aead_msg.alg_supported_aes_256_gcm == 1);

  return 0;
}

static int get_asym_support(buffer* alg_structs, buffer* rest, bool is_resp,
                            SpdmSupportedAlgs* supported_algs) {
  SPDM_AlgStruct_BaseAsym asym_msg;
  uint32_t alg_count_extended;
  int rc;

  rc = SpdmCheckAsymAlg(alg_structs, rest, is_resp, &alg_count_extended);
  if (rc != 0) {
    return rc;
  }

  memcpy(&asym_msg, alg_structs->data, sizeof(asym_msg));

  SpdmSupportedAsymAlgs* supported_asym_algs =
      is_resp ? &supported_algs->asym_sign : &supported_algs->asym_verify;

  supported_asym_algs->ecdsa_ecc_nist_p256 =
      (asym_msg.alg_supported_ecdsa_ecc_nist_p256 == 1);
  supported_asym_algs->ecdsa_ecc_nist_p384 =
      (asym_msg.alg_supported_ecdsa_ecc_nist_p384 == 1);
  supported_asym_algs->ecdsa_ecc_nist_p521 =
      (asym_msg.alg_supported_ecdsa_ecc_nist_p521 == 1);

  return 0;
}

static int get_keyschedule_support(buffer* alg_structs, buffer* rest,
                                   bool is_resp,
                                   SpdmSupportedAlgs* supported_algs) {
  SPDM_AlgStruct_KeySchedule keyschedule_msg;
  uint32_t alg_count_extended;
  int rc;

  rc = SpdmCheckKeySchedule(alg_structs, rest, is_resp, &alg_count_extended);
  if (rc != 0) {
    return rc;
  }

  memcpy(&keyschedule_msg, alg_structs->data, sizeof(keyschedule_msg));

  supported_algs->keyschedule_spdm =
      (keyschedule_msg.alg_supported_spdm_key_schedule == 1);

  return 0;
}

int spdm_get_their_supported_algs(const SPDM_AsymHashAlgs* asym_hash_algs,
                                  buffer alg_structs,
                                  uint32_t alg_structs_count, bool is_resp,
                                  SpdmSupportedAlgs* supported_algs) {
  memset(supported_algs, 0, sizeof(*supported_algs));

  get_base_alg_support(asym_hash_algs, is_resp, supported_algs);

  // EverParse does not ensure that `alg_structs_count` accurately reflects the
  // number of structs in `alg_structs`. All we know is that the structs are
  // well-formed. Track remaining bytes and error out if any are left over.
  uint32_t bytes_remaining = alg_structs.size;

  for (int i = 0; i < alg_structs_count; ++i) {
    buffer rest;
    int rc = 0;

    if (alg_structs.size < 1) {
      return -1;
    }

    switch (alg_structs.data[0]) {
      case SPDM_ALG_TYPE_DHE:
        rc = get_dhe_support(&alg_structs, &rest, is_resp, supported_algs);
        break;
      case SPDM_ALG_TYPE_AEAD:
        rc = get_aead_support(&alg_structs, &rest, is_resp, supported_algs);
        break;
      case SPDM_ALG_TYPE_ASYM:
        rc = get_asym_support(&alg_structs, &rest, is_resp, supported_algs);
        break;
      case SPDM_ALG_TYPE_KEYSCHEDULE:
        rc = get_keyschedule_support(&alg_structs, &rest, is_resp,
                                     supported_algs);
        break;
    }

    if (rc != 0) {
      return rc;
    }

    bytes_remaining -= alg_structs.size;
    alg_structs = rest;
  }

  if (bytes_remaining > 0) {
    return -1;
  }

  return 0;
}

static void get_negotiated_asym_alg(const SpdmSupportedAsymAlgs* my_algs,
                                    const SpdmSupportedAsymAlgs* their_algs,
                                    SpdmSupportedAsymAlgs* common_algs,
                                    SpdmAsymAlgorithm* asym_sign_alg) {
  if (my_algs->ecdsa_ecc_nist_p521 && their_algs->ecdsa_ecc_nist_p521) {
    common_algs->ecdsa_ecc_nist_p521 = true;
    *asym_sign_alg = SPDM_ASYM_ECDSA_ECC_NIST_P521;
  } else if (my_algs->ecdsa_ecc_nist_p384 && their_algs->ecdsa_ecc_nist_p384) {
    common_algs->ecdsa_ecc_nist_p384 = true;
    *asym_sign_alg = SPDM_ASYM_ECDSA_ECC_NIST_P384;
  } else if (my_algs->ecdsa_ecc_nist_p256 && their_algs->ecdsa_ecc_nist_p256) {
    common_algs->ecdsa_ecc_nist_p256 = true;
    *asym_sign_alg = SPDM_ASYM_ECDSA_ECC_NIST_P256;
  } else {
    *asym_sign_alg = SPDM_ASYM_UNSUPPORTED;
  }
}

static void get_negotiated_hash_alg(const SpdmSupportedAlgs* my_algs,
                                    const SpdmSupportedAlgs* their_algs,
                                    SpdmSupportedAlgs* common_algs,
                                    SpdmHashAlgorithm* hash_alg) {
  if (my_algs->hash_sha512 && their_algs->hash_sha512) {
    common_algs->hash_sha512 = true;
    *hash_alg = SPDM_HASH_SHA512;
  } else if (my_algs->hash_sha384 && their_algs->hash_sha384) {
    common_algs->hash_sha384 = true;
    *hash_alg = SPDM_HASH_SHA384;
  } else if (my_algs->hash_sha256 && their_algs->hash_sha256) {
    common_algs->hash_sha256 = true;
    *hash_alg = SPDM_HASH_SHA256;
  } else {
    *hash_alg = SPDM_HASH_UNSUPPORTED;
  }
}

static void get_negotiated_dhe_alg(const SpdmSupportedAlgs* my_algs,
                                   const SpdmSupportedAlgs* their_algs,
                                   SpdmSupportedAlgs* common_algs,
                                   SpdmDheAlgorithm* dhe_alg) {
  if (my_algs->dhe_secp521r1 && their_algs->dhe_secp521r1) {
    common_algs->dhe_secp521r1 = true;
    *dhe_alg = SPDM_DHE_SECP521R1;
  } else if (my_algs->dhe_secp384r1 && their_algs->dhe_secp384r1) {
    common_algs->dhe_secp384r1 = true;
    *dhe_alg = SPDM_DHE_SECP384R1;
  } else if (my_algs->dhe_secp256r1 && their_algs->dhe_secp256r1) {
    common_algs->dhe_secp256r1 = true;
    *dhe_alg = SPDM_DHE_SECP256R1;
  } else {
    *dhe_alg = SPDM_DHE_UNSUPPORTED;
  }
}

static void get_negotiated_aead_alg(const SpdmSupportedAlgs* my_algs,
                                    const SpdmSupportedAlgs* their_algs,
                                    SpdmSupportedAlgs* common_algs,
                                    SpdmAeadAlgorithm* aead_alg) {
  if (my_algs->aead_aes_256_gcm && their_algs->aead_aes_256_gcm) {
    common_algs->aead_aes_256_gcm = true;
    *aead_alg = SPDM_AEAD_AES_256_GCM;
  } else if (my_algs->aead_aes_128_gcm && their_algs->aead_aes_128_gcm) {
    common_algs->aead_aes_128_gcm = true;
    *aead_alg = SPDM_AEAD_AES_128_GCM;
  } else {
    *aead_alg = SPDM_AEAD_UNSUPPORTED;
  }
}

static void get_negotiated_keyschedule_alg(
    const SpdmSupportedAlgs* my_algs, const SpdmSupportedAlgs* their_algs,
    SpdmSupportedAlgs* common_algs, SpdmKeyScheduleAlgorithm* keyschedule_alg) {
  if (my_algs->keyschedule_spdm && their_algs->keyschedule_spdm) {
    common_algs->keyschedule_spdm = true;
    *keyschedule_alg = SPDM_KEYSCHEDULE_SPDM;
  } else {
    *keyschedule_alg = SPDM_KEYSCHEDULE_UNSUPPORTED;
  }
}

void spdm_get_my_supported_algs(const SpdmCryptoSpec* crypto_spec,
                                const SpdmAsymPubKey* my_pub_key,
                                SpdmSupportedAlgs* supported_algs) {
  *supported_algs = crypto_spec->supported_algs;

  if (my_pub_key->alg != SPDM_ASYM_ECDSA_ECC_NIST_P256) {
    supported_algs->asym_sign.ecdsa_ecc_nist_p256 = false;
  }
  if (my_pub_key->alg != SPDM_ASYM_ECDSA_ECC_NIST_P384) {
    supported_algs->asym_sign.ecdsa_ecc_nist_p384 = false;
  }
  if (my_pub_key->alg != SPDM_ASYM_ECDSA_ECC_NIST_P521) {
    supported_algs->asym_sign.ecdsa_ecc_nist_p521 = false;
  }
}

void spdm_get_negotiated_algs(const SpdmSupportedAlgs* my_algs,
                              const SpdmSupportedAlgs* their_algs,
                              SpdmSupportedAlgs* common_algs,
                              SpdmNegotiatedAlgs* negotiated_algs) {
  memset(common_algs, 0, sizeof(*common_algs));
  memset(negotiated_algs, 0, sizeof(*negotiated_algs));

  get_negotiated_asym_alg(&my_algs->asym_sign, &their_algs->asym_sign,
                          &common_algs->asym_sign,
                          &negotiated_algs->asym_sign_alg);
  get_negotiated_asym_alg(&my_algs->asym_verify, &their_algs->asym_verify,
                          &common_algs->asym_verify,
                          &negotiated_algs->asym_verify_alg);
  get_negotiated_hash_alg(my_algs, their_algs, common_algs,
                          &negotiated_algs->hash_alg);
  get_negotiated_dhe_alg(my_algs, their_algs, common_algs,
                         &negotiated_algs->dhe_alg);
  get_negotiated_aead_alg(my_algs, their_algs, common_algs,
                          &negotiated_algs->aead_alg);
  get_negotiated_keyschedule_alg(my_algs, their_algs, common_algs,
                                 &negotiated_algs->keyschedule_alg);
}

void spdm_write_algs(const SpdmSupportedAlgs* algs, bool is_resp,
                     SPDM_AsymHashAlgs* algs_msg, SPDM_AlgStruct_DHE* dhe_msg,
                     SPDM_AlgStruct_AEAD* aead_msg,
                     SPDM_AlgStruct_BaseAsym* asym_msg,
                     SPDM_AlgStruct_KeySchedule* keysched_msg) {
  memset(algs_msg, 0, sizeof(*algs_msg));
  memset(dhe_msg, 0, sizeof(*dhe_msg));
  memset(aead_msg, 0, sizeof(*aead_msg));
  memset(asym_msg, 0, sizeof(*asym_msg));
  memset(keysched_msg, 0, sizeof(*keysched_msg));

  const SpdmSupportedAsymAlgs* base_asym_algs =
      is_resp ? &algs->asym_sign : &algs->asym_verify;
  const SpdmSupportedAsymAlgs* ext_asym_algs =
      is_resp ? &algs->asym_verify : &algs->asym_sign;

  if (base_asym_algs->ecdsa_ecc_nist_p256) {
    algs_msg->base_asym_alg_ecdsa_ecc_nist_p256 = 1;
  }
  if (base_asym_algs->ecdsa_ecc_nist_p384) {
    algs_msg->base_asym_alg_ecdsa_ecc_nist_p384 = 1;
  }
  if (base_asym_algs->ecdsa_ecc_nist_p521) {
    algs_msg->base_asym_alg_ecdsa_ecc_nist_p521 = 1;
  }

  if (algs->hash_sha256) {
    algs_msg->base_hash_algo_sha_256 = 1;
  }
  if (algs->hash_sha384) {
    algs_msg->base_hash_algo_sha_384 = 1;
  }
  if (algs->hash_sha512) {
    algs_msg->base_hash_algo_sha_512 = 1;
  }

  dhe_msg->alg_type = SPDM_ALG_TYPE_DHE;
  dhe_msg->alg_count_fixed_width = 2;
  if (algs->dhe_secp256r1) {
    dhe_msg->alg_supported_secp256r1 = 1;
  }
  if (algs->dhe_secp384r1) {
    dhe_msg->alg_supported_secp384r1 = 1;
  }
  if (algs->dhe_secp521r1) {
    dhe_msg->alg_supported_secp521r1 = 1;
  }

  aead_msg->alg_type = SPDM_ALG_TYPE_AEAD;
  aead_msg->alg_count_fixed_width = 2;
  if (algs->aead_aes_128_gcm) {
    aead_msg->alg_supported_aes_128_gcm = 1;
  }
  if (algs->aead_aes_256_gcm) {
    aead_msg->alg_supported_aes_256_gcm = 1;
  }

  asym_msg->alg_type = SPDM_ALG_TYPE_ASYM;
  asym_msg->alg_count_fixed_width = 2;
  if (ext_asym_algs->ecdsa_ecc_nist_p256) {
    asym_msg->alg_supported_ecdsa_ecc_nist_p256 = 1;
  }
  if (ext_asym_algs->ecdsa_ecc_nist_p384) {
    asym_msg->alg_supported_ecdsa_ecc_nist_p384 = 1;
  }
  if (ext_asym_algs->ecdsa_ecc_nist_p521) {
    asym_msg->alg_supported_ecdsa_ecc_nist_p521 = 1;
  }

  keysched_msg->alg_type = SPDM_ALG_TYPE_KEYSCHEDULE;
  keysched_msg->alg_count_fixed_width = 2;
  if (algs->keyschedule_spdm) {
    keysched_msg->alg_supported_spdm_key_schedule = 1;
  }
}
