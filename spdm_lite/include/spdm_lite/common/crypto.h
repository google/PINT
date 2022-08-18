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

#ifndef SPDM_LITE_COMMON_CRYPTO_H_
#define SPDM_LITE_COMMON_CRYPTO_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "spdm_lite/common/crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

int spdm_get_random(const SpdmCryptoSpec* crypto_spec, uint8_t* data,
                    uint32_t len);
int spdm_initialize_hash_struct(const SpdmCryptoSpec* crypto_spec,
                                SpdmHashAlgorithm alg, SpdmHash* hash);
void spdm_initialize_hash(SpdmHash* hash);
void spdm_extend_hash(SpdmHash* hash, const void* data, uint32_t len);
int spdm_get_hash(const SpdmHash* hash, SpdmHashResult* digest);
int spdm_get_hash_destructive(SpdmHash* hash, SpdmHashResult* digest);
int spdm_hash(const SpdmCryptoSpec* crypto_spec, SpdmHashAlgorithm alg,
              const uint8_t* data, uint32_t len, SpdmHashResult* digest);

int spdm_validate_asym_pubkey(const SpdmCryptoSpec* spec,
                              const SpdmAsymPubKey* pub_key);
int spdm_validate_dhe_pubkey(const SpdmCryptoSpec* spec,
                             const SpdmDhePubKey* pub_key);
int spdm_gen_dhe_keypair(const SpdmCryptoSpec* spec, SpdmDheAlgorithm alg,
                         SpdmDhePrivKey* priv_key, SpdmDhePubKey* pub_key);
int spdm_gen_dhe_secret(const SpdmCryptoSpec* spec,
                        const SpdmDhePrivKey* priv_key,
                        const SpdmDhePubKey* pub_key,
                        SpdmDheSecret* shared_secret);
int spdm_sign_with_private_key(const SpdmCryptoSpec* spec,
                               SpdmAsymAlgorithm alg, void* ctx,
                               const SpdmHashResult* input, uint8_t* sig,
                               uint32_t sig_len);
int spdm_verify_with_pub_key(const SpdmCryptoSpec* spec,
                             const SpdmAsymPubKey* pub_key,
                             const SpdmHashResult* input, const uint8_t* sig,
                             uint32_t sig_len);
int spdm_hmac(const SpdmCryptoSpec* spec, const SpdmHashResult* key,
              const SpdmHashResult* data, SpdmHashResult* out);
int spdm_hmac_raw(const SpdmCryptoSpec* spec, const SpdmHashResult* key,
                  const uint8_t* data, uint16_t data_size, SpdmHashResult* out);
int spdm_validate_hmac(const SpdmCryptoSpec* spec, const SpdmHashResult* key,
                       const SpdmHashResult* data, const uint8_t* mac);
int spdm_hkdf_expand(const SpdmCryptoSpec* spec, const SpdmHashResult* prk,
                     const uint8_t* info, uint32_t info_len,
                     SpdmHashResult* out);
int spdm_hkdf_expand_raw(const SpdmCryptoSpec* spec, SpdmHashAlgorithm alg,
                         const uint8_t* prk, uint32_t prk_len,
                         const uint8_t* info, uint32_t info_len, uint8_t* out,
                         uint32_t out_len);
int spdm_aes_gcm_encrypt(const SpdmCryptoSpec* spec, const SpdmAeadKey* key,
                         const SpdmAeadIv* iv, const uint8_t* plaintext,
                         uint32_t plaintext_len, const uint8_t* aad,
                         uint32_t aad_len, uint8_t* ciphertext, uint8_t* mac,
                         uint32_t mac_len);
int spdm_aes_gcm_decrypt(const SpdmCryptoSpec* spec, const SpdmAeadKey* key,
                         const SpdmAeadIv* iv, const uint8_t* ciphertext,
                         uint32_t ciphertext_len, const uint8_t* aad,
                         uint32_t aad_len, const uint8_t* mac, uint32_t mac_len,
                         uint8_t* plaintext);

int spdm_extend_hash_with_pub_key(const SpdmCryptoSpec* spec, SpdmHash* hash,
                                  const SpdmAsymPubKey* pub_key);

int constant_memcmp(const uint8_t* a, const uint8_t* b, uint32_t n);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_CRYPTO_H_
