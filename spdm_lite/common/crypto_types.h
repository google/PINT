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

#ifndef SPDM_LITE_COMMON_CRYPTO_TYPES_H_
#define SPDM_LITE_COMMON_CRYPTO_TYPES_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#define SPDM_MAX_HASH_CTX_SIZE 256

#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64

#define P256_COORD_SIZE 32
#define P384_COORD_SIZE 48
#define P521_COORD_SIZE 66

#define P256_SERIALIZED_POINT_SIZE (2 * P256_COORD_SIZE)
#define P384_SERIALIZED_POINT_SIZE (2 * P384_COORD_SIZE)
#define P521_SERIALIZED_POINT_SIZE (2 * P521_COORD_SIZE)

#define AES_GCM_128_KEY_SIZE 16
#define AES_GCM_256_KEY_SIZE 32

#define AES_GCM_128_IV_SIZE 12
#define AES_GCM_256_IV_SIZE 12

#define AES_GCM_MAC_SIZE 16

typedef enum {
  SPDM_ASYM_UNSUPPORTED = 0,
  SPDM_ASYM_ECDSA_ECC_NIST_P256,
  SPDM_ASYM_ECDSA_ECC_NIST_P384,
  SPDM_ASYM_ECDSA_ECC_NIST_P521,
} SpdmAsymAlgorithm;

typedef enum {
  SPDM_HASH_UNSUPPORTED = 0,
  SPDM_HASH_SHA256,
  SPDM_HASH_SHA384,
  SPDM_HASH_SHA512,
} SpdmHashAlgorithm;

typedef enum {
  SPDM_DHE_UNSUPPORTED = 0,
  SPDM_DHE_SECP256R1,
  SPDM_DHE_SECP384R1,
  SPDM_DHE_SECP521R1,
} SpdmDheAlgorithm;

typedef enum {
  SPDM_AEAD_UNSUPPORTED = 0,
  SPDM_AEAD_AES_128_GCM,
  SPDM_AEAD_AES_256_GCM,
} SpdmAeadAlgorithm;

typedef enum {
  SPDM_KEYSCHEDULE_UNSUPPORTED = 0,
  SPDM_KEYSCHEDULE_SPDM,
} SpdmKeyScheduleAlgorithm;

typedef struct {
  bool ecdsa_ecc_nist_p256;
  bool ecdsa_ecc_nist_p384;
  bool ecdsa_ecc_nist_p521;
} SpdmSupportedAsymAlgs;

typedef struct {
  SpdmSupportedAsymAlgs asym_sign;
  SpdmSupportedAsymAlgs asym_verify;

  bool hash_sha256;
  bool hash_sha384;
  bool hash_sha512;

  bool dhe_secp256r1;
  bool dhe_secp384r1;
  bool dhe_secp521r1;

  bool aead_aes_128_gcm;
  bool aead_aes_256_gcm;

  bool keyschedule_spdm;
} SpdmSupportedAlgs;

typedef struct {
  SpdmAsymAlgorithm asym_sign_alg;
  SpdmAsymAlgorithm asym_verify_alg;
  SpdmHashAlgorithm hash_alg;
  SpdmDheAlgorithm dhe_alg;
  SpdmAeadAlgorithm aead_alg;
  SpdmKeyScheduleAlgorithm keyschedule_alg;
} SpdmNegotiatedAlgs;

// All algorithm-agile types have a field `.data` that is guaranteed to point to
// the start of the data regardless of algorithm selection.

typedef struct {
  SpdmAsymAlgorithm alg;
  uint16_t size;
  union {
    uint8_t ecdsa_p256[P256_SERIALIZED_POINT_SIZE];
    uint8_t ecdsa_p384[P384_SERIALIZED_POINT_SIZE];
    uint8_t ecdsa_p521[P521_SERIALIZED_POINT_SIZE];
    uint8_t data[1];
  };
} SpdmAsymPubKey;

typedef struct {
  SpdmHashAlgorithm alg;
  uint16_t size;
  union {
    uint8_t sha256[SHA256_DIGEST_SIZE];
    uint8_t sha384[SHA384_DIGEST_SIZE];
    uint8_t sha512[SHA512_DIGEST_SIZE];
    uint8_t data[1];
  };
} SpdmHashResult;

typedef struct {
  SpdmDheAlgorithm alg;
  uint16_t size;
  union {
    uint8_t dhe_secp256r1[P256_SERIALIZED_POINT_SIZE];
    uint8_t dhe_secp384r1[P384_SERIALIZED_POINT_SIZE];
    uint8_t dhe_secp521r1[P521_SERIALIZED_POINT_SIZE];
    uint8_t data[1];
  };
} SpdmDhePubKey;

typedef struct {
  SpdmDheAlgorithm alg;
  uint16_t size;
  union {
    uint8_t dhe_secp256r1[P256_COORD_SIZE];
    uint8_t dhe_secp384r1[P384_COORD_SIZE];
    uint8_t dhe_secp521r1[P521_COORD_SIZE];
    uint8_t data[1];
  };
} SpdmDhePrivKey;

typedef struct {
  SpdmDheAlgorithm alg;
  uint16_t size;
  union {
    uint8_t dhe_secp256r1[P256_COORD_SIZE];
    uint8_t dhe_secp384r1[P384_COORD_SIZE];
    uint8_t dhe_secp521r1[P521_COORD_SIZE];
    uint8_t data[1];
  };
} SpdmDheSecret;

typedef struct {
  SpdmAeadAlgorithm alg;
  uint16_t size;
  union {
    uint8_t aes_128_gcm[AES_GCM_128_KEY_SIZE];
    uint8_t aes_256_gcm[AES_GCM_256_KEY_SIZE];
    uint8_t data[1];
  };
} SpdmAeadKey;

typedef struct {
  SpdmAeadAlgorithm alg;
  uint16_t size;
  union {
    uint8_t aes_128_gcm[AES_GCM_128_IV_SIZE];
    uint8_t aes_256_gcm[AES_GCM_256_IV_SIZE];
    uint8_t data[1];
  };
} SpdmAeadIv;

typedef struct {
  SpdmAeadKey key;
  SpdmAeadIv iv;
} SpdmAeadKeys;

void spdm_init_asym_pub_key(SpdmAsymPubKey* key, SpdmAsymAlgorithm alg);
void spdm_init_hash_result(SpdmHashResult* hash, SpdmHashAlgorithm alg);
void spdm_init_dhe_pub_key(SpdmDhePubKey* key, SpdmDheAlgorithm alg);
void spdm_init_dhe_priv_key(SpdmDhePrivKey* key, SpdmDheAlgorithm alg);
void spdm_init_dhe_secret(SpdmDheSecret* secret, SpdmDheAlgorithm alg);
void spdm_init_aead_key(SpdmAeadKey* key, SpdmAeadAlgorithm alg);
void spdm_init_aead_iv(SpdmAeadIv* iv, SpdmAeadAlgorithm alg);

uint16_t spdm_get_asym_pub_key_size(SpdmAsymAlgorithm alg);
uint16_t spdm_get_asym_signature_size(SpdmAsymAlgorithm alg);
uint16_t spdm_get_hash_size(SpdmHashAlgorithm alg);
uint16_t spdm_get_dhe_pub_key_size(SpdmDheAlgorithm alg);
uint16_t spdm_get_dhe_priv_key_size(SpdmDheAlgorithm alg);
uint16_t spdm_get_dhe_secret_size(SpdmDheAlgorithm alg);
uint16_t spdm_get_aead_key_size(SpdmAeadAlgorithm alg);
uint16_t spdm_get_aead_iv_size(SpdmAeadAlgorithm alg);

// Random functions
typedef int (*GetRandomFn)(uint8_t* data, uint32_t len);

// Hash functions
typedef void (*InitializeHashFn)(void* ctx, SpdmHashAlgorithm alg);
typedef void (*ExtendHashFn)(void* ctx, SpdmHashAlgorithm alg,
                             const uint8_t* data, uint32_t len);
typedef int (*GetHashFn)(void* ctx, SpdmHashAlgorithm alg, uint8_t* digest);

// EC functions
typedef int (*ValidateAsymKeyFn)(const SpdmAsymPubKey* pub_key);
typedef int (*ValidateDheKeyFn)(const SpdmDhePubKey* pub_key);
typedef int (*GenerateDheKeypairFn)(SpdmDheAlgorithm alg, uint8_t* priv_key,
                                    uint8_t* pub_key);
typedef int (*GenerateDheSecretFn)(const SpdmDhePrivKey* priv_key,
                                   const SpdmDhePubKey* pub_key,
                                   uint8_t* shared_secret);
typedef int (*SignWithPrivateKeyFn)(SpdmAsymAlgorithm alg, void* ctx,
                                    const uint8_t* input, uint32_t input_len,
                                    uint8_t* sig, uint32_t sig_len);
typedef int (*VerifyWithPublicKeyFn)(const SpdmAsymPubKey* pub_key,
                                     const uint8_t* input, uint32_t input_len,
                                     const uint8_t* sig, uint32_t sig_len);

// HKDF functions
typedef int (*HmacFn)(SpdmHashAlgorithm alg, const uint8_t* key,
                      uint32_t key_len, const uint8_t* data, uint32_t data_len,
                      uint8_t* out);
typedef int (*HkdfExpandFn)(SpdmHashAlgorithm alg, const uint8_t* prk,
                            uint32_t prk_len, const uint8_t* info,
                            uint32_t info_len, uint8_t* out, uint32_t out_len);

// GCM functions
typedef int (*AesGcmEncryptFn)(const SpdmAeadKey* key, const SpdmAeadIv* iv,
                               const uint8_t* plaintext, uint32_t plaintext_len,
                               const uint8_t* aad, uint32_t aad_len,
                               uint8_t* ciphertext, uint8_t* mac,
                               uint32_t mac_len);
typedef int (*AesGcmDecryptFn)(const SpdmAeadKey* key, const SpdmAeadIv* iv,
                               const uint8_t* ciphertext,
                               uint32_t ciphertext_len, const uint8_t* aad,
                               uint32_t aad_len, const uint8_t* mac,
                               uint32_t mac_len, uint8_t* plaintext);

typedef struct {
  SpdmHashAlgorithm alg;
  uint8_t ctx_buf[SPDM_MAX_HASH_CTX_SIZE];
  InitializeHashFn initialize_hash;
  ExtendHashFn extend_hash;
  GetHashFn get_hash;
} SpdmHash;

typedef struct {
  SpdmSupportedAlgs supported_algs;

  // Rand spec
  GetRandomFn get_random;

  // Hash spec
  uint32_t hash_ctx_size;
  InitializeHashFn initialize_hash;
  ExtendHashFn extend_hash;
  GetHashFn get_hash;

  // EC spec
  ValidateAsymKeyFn validate_asym_key;
  ValidateDheKeyFn validate_dhe_key;
  GenerateDheKeypairFn gen_dhe_keypair;
  GenerateDheSecretFn gen_dhe_secret;
  SignWithPrivateKeyFn sign_with_priv_key;
  VerifyWithPublicKeyFn verify_with_pub_key;

  // HKDF spec
  HmacFn hmac;
  HkdfExpandFn hkdf_expand;

  // GCM spec
  AesGcmEncryptFn aes_gcm_encrypt;
  AesGcmDecryptFn aes_gcm_decrypt;
} SpdmCryptoSpec;

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_CRYPTO_TYPES_H_
