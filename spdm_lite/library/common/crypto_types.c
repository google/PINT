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

#include "spdm_lite/common/crypto_types.h"

#include <string.h>

static uint16_t spdm_get_asym_pub_key_size(SpdmAsymAlgorithm alg) {
  switch (alg) {
    case SPDM_ASYM_ECDSA_ECC_NIST_P256:
      return P256_SERIALIZED_POINT_SIZE;
    case SPDM_ASYM_ECDSA_ECC_NIST_P384:
      return P384_SERIALIZED_POINT_SIZE;
    case SPDM_ASYM_ECDSA_ECC_NIST_P521:
      return P521_SERIALIZED_POINT_SIZE;
    case SPDM_ASYM_UNSUPPORTED:
    default:
      return 0;
  }
}

void spdm_init_asym_pub_key(SpdmAsymPubKey* key, SpdmAsymAlgorithm alg) {
  key->alg = alg;
  key->size = spdm_get_asym_pub_key_size(alg);
}

void spdm_init_hash_result(SpdmHashResult* hash, SpdmHashAlgorithm alg) {
  hash->alg = alg;
  hash->size = spdm_get_hash_size(alg);
}

void spdm_init_dhe_pub_key(SpdmDhePubKey* key, SpdmDheAlgorithm alg) {
  key->alg = alg;
  key->size = spdm_get_dhe_pub_key_size(alg);
}

void spdm_init_dhe_priv_key(SpdmDhePrivKey* key, SpdmDheAlgorithm alg) {
  key->alg = alg;
  key->size = spdm_get_dhe_priv_key_size(alg);
}

void spdm_init_dhe_secret(SpdmDheSecret* secret, SpdmDheAlgorithm alg) {
  secret->alg = alg;
  secret->size = spdm_get_dhe_secret_size(alg);
}

void spdm_init_aead_key(SpdmAeadKey* key, SpdmAeadAlgorithm alg) {
  key->alg = alg;
  key->size = spdm_get_aead_key_size(alg);
}

void spdm_init_aead_iv(SpdmAeadIv* iv, SpdmAeadAlgorithm alg) {
  iv->alg = alg;
  iv->size = spdm_get_aead_iv_size(alg);
}

uint16_t spdm_get_asym_signature_size(SpdmAsymAlgorithm alg) {
  switch (alg) {
    case SPDM_ASYM_ECDSA_ECC_NIST_P256:
      return P256_SERIALIZED_POINT_SIZE;
    case SPDM_ASYM_ECDSA_ECC_NIST_P384:
      return P384_SERIALIZED_POINT_SIZE;
    case SPDM_ASYM_ECDSA_ECC_NIST_P521:
      return P521_SERIALIZED_POINT_SIZE;
    case SPDM_ASYM_UNSUPPORTED:
    default:
      return 0;
  }
}

uint16_t spdm_get_hash_size(SpdmHashAlgorithm alg) {
  switch (alg) {
    case SPDM_HASH_SHA256:
      return SHA256_DIGEST_SIZE;
    case SPDM_HASH_SHA384:
      return SHA384_DIGEST_SIZE;
    case SPDM_HASH_SHA512:
      return SHA512_DIGEST_SIZE;
    case SPDM_HASH_UNSUPPORTED:
    default:
      return 0;
  }
}

uint16_t spdm_get_dhe_pub_key_size(SpdmDheAlgorithm alg) {
  switch (alg) {
    case SPDM_DHE_SECP256R1:
      return P256_SERIALIZED_POINT_SIZE;
    case SPDM_DHE_SECP384R1:
      return P384_SERIALIZED_POINT_SIZE;
    case SPDM_DHE_SECP521R1:
      return P521_SERIALIZED_POINT_SIZE;
    case SPDM_DHE_UNSUPPORTED:
    default:
      return 0;
  }
}

uint16_t spdm_get_dhe_priv_key_size(SpdmDheAlgorithm alg) {
  switch (alg) {
    case SPDM_DHE_SECP256R1:
      return P256_COORD_SIZE;
    case SPDM_DHE_SECP384R1:
      return P384_COORD_SIZE;
    case SPDM_DHE_SECP521R1:
      return P521_COORD_SIZE;
    case SPDM_DHE_UNSUPPORTED:
    default:
      return 0;
  }
}

uint16_t spdm_get_dhe_secret_size(SpdmDheAlgorithm alg) {
  switch (alg) {
    case SPDM_DHE_SECP256R1:
      return P256_COORD_SIZE;
    case SPDM_DHE_SECP384R1:
      return P384_COORD_SIZE;
    case SPDM_DHE_SECP521R1:
      return P521_COORD_SIZE;
    case SPDM_DHE_UNSUPPORTED:
    default:
      return 0;
  }
}

uint16_t spdm_get_aead_key_size(SpdmAeadAlgorithm alg) {
  switch (alg) {
    case SPDM_AEAD_AES_128_GCM:
      return AES_GCM_128_KEY_SIZE;
    case SPDM_AEAD_AES_256_GCM:
      return AES_GCM_256_KEY_SIZE;
    case SPDM_AEAD_UNSUPPORTED:
    default:
      return 0;
  }
}

uint16_t spdm_get_aead_iv_size(SpdmAeadAlgorithm alg) {
  switch (alg) {
    case SPDM_AEAD_AES_128_GCM:
      return AES_GCM_128_IV_SIZE;
    case SPDM_AEAD_AES_256_GCM:
      return AES_GCM_256_IV_SIZE;
    case SPDM_AEAD_UNSUPPORTED:
    default:
      return 0;
  }
}
