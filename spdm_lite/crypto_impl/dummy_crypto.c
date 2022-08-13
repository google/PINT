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

#include <string.h>

#include "common/crypto_types.h"

static int NonRandom(uint8_t* data, uint32_t len) {
  for (int i = 0; i < len; ++i) {
    data[i] = i;
  }
  return 0;
}

static void InitializeHash(void* ctx, SpdmHashAlgorithm alg) {}

static void ExtendHash(void* ctx, SpdmHashAlgorithm alg, const uint8_t* data,
                       uint32_t len) {}

static int GetHash(void* ctx, SpdmHashAlgorithm alg, uint8_t* digest) {
  return NonRandom(digest, spdm_get_hash_size(alg));
}

static int ValidateAsymKey(const SpdmAsymPubKey* pub_key) { return 0; }
static int ValidateDheKey(const SpdmDhePubKey* pub_key) { return 0; }

static int GenerateDheKeypair(SpdmDheAlgorithm alg, uint8_t* priv_key,
                              uint8_t* pub_key) {
  NonRandom(priv_key, spdm_get_dhe_priv_key_size(alg));
  NonRandom(pub_key, spdm_get_dhe_pub_key_size(alg));

  return 0;
}

static int GenerateDheSecret(const SpdmDhePrivKey* priv_key,
                             const SpdmDhePubKey* pub_key,
                             uint8_t* shared_secret) {
  NonRandom(shared_secret, spdm_get_dhe_secret_size(priv_key->alg));

  return 0;
}

static int SignWithPrivateKey(SpdmAsymAlgorithm alg, void* priv_key_ctx,
                              const uint8_t* input, uint32_t input_len,
                              uint8_t* sig, uint32_t sig_len) {
  return NonRandom(sig, sig_len);
}

static int VerifyWithPublicKey(const SpdmAsymPubKey* pub_key,
                               const uint8_t* input, uint32_t input_len,
                               const uint8_t* sig, uint32_t sig_len) {
  return 0;
}

static int Hmac(SpdmHashAlgorithm alg, const uint8_t* key, uint32_t key_len,
                const uint8_t* data, uint32_t data_len, uint8_t* out) {
  return NonRandom(out, spdm_get_hash_size(alg));
}

static int HkdfExpand(SpdmHashAlgorithm alg, const uint8_t* key,
                      uint32_t key_len, const uint8_t* context,
                      uint32_t context_len, uint8_t* out, uint32_t out_len) {
  return NonRandom(out, out_len);
}

static int AesGcmEncrypt(const SpdmAeadKey* key, const SpdmAeadIv* iv,
                         const uint8_t* plaintext, uint32_t plaintext_len,
                         const uint8_t* aad, uint32_t aad_len,
                         uint8_t* ciphertext, uint8_t* mac, uint32_t mac_len) {
  memmove(ciphertext, plaintext, plaintext_len);

  for (int i = 0; i < plaintext_len; ++i) {
    ciphertext[i] = ciphertext[i] + 128;
  }

  return NonRandom(mac, mac_len);
}

static int AesGcmDecrypt(const SpdmAeadKey* key, const SpdmAeadIv* iv,
                         const uint8_t* ciphertext, uint32_t ciphertext_len,
                         const uint8_t* aad, uint32_t aad_len,
                         const uint8_t* mac, uint32_t mac_len,
                         uint8_t* plaintext) {
  memmove(plaintext, ciphertext, ciphertext_len);

  for (int i = 0; i < ciphertext_len; ++i) {
    plaintext[i] = plaintext[i] + 128;
  }

  return 0;
}

const SpdmCryptoSpec DUMMY_CRYPTO_SPEC = {
    .supported_algs =
        {
            .asym_sign =
                {
                    .ecdsa_ecc_nist_p384 = true,
                },
            .asym_verify =
                {
                    .ecdsa_ecc_nist_p384 = true,
                },
            .hash_sha384 = true,
            .dhe_secp384r1 = true,
            .aead_aes_256_gcm = true,
        },
    .get_random = NonRandom,
    .hash_ctx_size = 0,
    .initialize_hash = InitializeHash,
    .extend_hash = ExtendHash,
    .get_hash = GetHash,
    .validate_asym_key = ValidateAsymKey,
    .validate_dhe_key = ValidateDheKey,
    .gen_dhe_keypair = GenerateDheKeypair,
    .gen_dhe_secret = GenerateDheSecret,
    .sign_with_priv_key = SignWithPrivateKey,
    .verify_with_pub_key = VerifyWithPublicKey,
    .hmac = Hmac,
    .hkdf_expand = HkdfExpand,
    .aes_gcm_encrypt = AesGcmEncrypt,
    .aes_gcm_decrypt = AesGcmDecrypt,
};
