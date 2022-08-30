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

#include "spdm_lite/common/crypto.h"

#include "spdm_lite/common/crypto_types.h"

int spdm_get_random(const SpdmCryptoSpec* spec, uint8_t* data, uint32_t len) {
  if (spec->get_random == NULL) {
    return -1;
  }

  return spec->get_random(data, len);
}

int spdm_initialize_hash_struct(const SpdmCryptoSpec* crypto_spec,
                                SpdmHashAlgorithm alg, SpdmHash* hash) {
  if (crypto_spec->hash_ctx_size > sizeof(hash->ctx_buf)) {
    return -1;
  }

  hash->alg = alg;
  hash->initialize_hash = crypto_spec->initialize_hash;
  hash->extend_hash = crypto_spec->extend_hash;
  hash->get_hash = crypto_spec->get_hash;

  return 0;
}

void spdm_initialize_hash(SpdmHash* hash) {
  if (hash->initialize_hash != NULL) {
    hash->initialize_hash(hash->ctx_buf, hash->alg);
  }
}

void spdm_extend_hash(SpdmHash* hash, const void* data, uint32_t len) {
  if (hash->extend_hash != NULL) {
    hash->extend_hash(hash->ctx_buf, hash->alg, data, len);
  }
}

int spdm_get_hash(const SpdmHash* hash, SpdmHashResult* digest) {
  SpdmHash h = *hash;
  return spdm_get_hash_destructive(&h, digest);
}

int spdm_get_hash_destructive(SpdmHash* hash, SpdmHashResult* digest) {
  if (hash->get_hash == NULL) {
    return -1;
  }

  spdm_init_hash_result(digest, hash->alg);
  return hash->get_hash(hash->ctx_buf, hash->alg, digest->data);
}

int spdm_hash(const SpdmCryptoSpec* crypto_spec, SpdmHashAlgorithm alg,
              const uint8_t* data, uint32_t len, SpdmHashResult* digest) {
  SpdmHash hash;
  int rc = spdm_initialize_hash_struct(crypto_spec, alg, &hash);
  if (rc != 0) {
    return rc;
  }

  spdm_initialize_hash(&hash);
  spdm_extend_hash(&hash, data, len);

  return spdm_get_hash(&hash, digest);
}

int spdm_serialize_asym_key(const SpdmCryptoSpec* spec,
                            const SpdmAsymPubKey* pub_key,
                            SpdmHashAlgorithm hash_alg,
                            SpdmSerializedAsymPubKey* out) {
  if (spec->serialize_pub_key == NULL) {
    return -1;
  }

  out->alg = pub_key->alg;
  out->size = sizeof(out->data);

  return spec->serialize_pub_key(pub_key->alg, hash_alg, pub_key->data,
                                 pub_key->size, out->data, &out->size);
}

int spdm_deserialize_asym_key(const SpdmCryptoSpec* spec,
                              SpdmAsymAlgorithm asym_alg,
                              SpdmHashAlgorithm hash_alg, const uint8_t* in,
                              uint32_t size, SpdmAsymPubKey* pub_key) {
  if (spec->deserialize_pub_key == NULL) {
    return -1;
  }

  spdm_init_asym_pub_key(pub_key, asym_alg);
  uint16_t pub_key_size = pub_key->size;

  int rc = spec->deserialize_pub_key(asym_alg, hash_alg, in, size,
                                     pub_key->data, &pub_key_size);
  if (rc != 0) {
    return rc;
  }

  // All keys' internal representations are fixed-length.
  if (pub_key_size != pub_key->size) {
    return -1;
  }

  return 0;
}

int spdm_validate_asym_pubkey(const SpdmCryptoSpec* spec,
                              const SpdmAsymPubKey* pub_key) {
  if (spec->validate_asym_key == NULL) {
    return -1;
  }

  return spec->validate_asym_key(pub_key);
}

int spdm_validate_dhe_pubkey(const SpdmCryptoSpec* spec,
                             const SpdmDhePubKey* pub_key) {
  if (spec->validate_dhe_key == NULL) {
    return -1;
  }

  return spec->validate_dhe_key(pub_key);
}

int spdm_gen_dhe_keypair(const SpdmCryptoSpec* spec, SpdmDheAlgorithm alg,
                         SpdmDhePrivKey* priv_key, SpdmDhePubKey* pub_key) {
  if (spec->gen_dhe_keypair == NULL) {
    return -1;
  }

  spdm_init_dhe_priv_key(priv_key, alg);
  spdm_init_dhe_pub_key(pub_key, alg);
  return spec->gen_dhe_keypair(alg, priv_key->data, pub_key->data);
}

int spdm_gen_dhe_secret(const SpdmCryptoSpec* spec,
                        const SpdmDhePrivKey* priv_key,
                        const SpdmDhePubKey* pub_key,
                        SpdmDheSecret* shared_secret) {
  if (spec->gen_dhe_secret == NULL) {
    return -1;
  }

  spdm_init_dhe_secret(shared_secret, priv_key->alg);
  return spec->gen_dhe_secret(priv_key, pub_key, shared_secret->data);
}

int spdm_sign_with_private_key(const SpdmCryptoSpec* spec,
                               SpdmAsymAlgorithm alg, void* ctx,
                               const SpdmHashResult* input, uint8_t* sig,
                               uint32_t sig_len) {
  if (spec->sign_with_priv_key == NULL) {
    return -1;
  }

  return spec->sign_with_priv_key(alg, ctx, input->data, input->size, sig,
                                  sig_len);
}

int spdm_verify_with_pub_key(const SpdmCryptoSpec* spec,
                             const SpdmAsymPubKey* pub_key,
                             const SpdmHashResult* input, const uint8_t* sig,
                             uint32_t sig_len) {
  if (spec->verify_with_pub_key == NULL) {
    return -1;
  }

  return spec->verify_with_pub_key(pub_key, input->data, input->size, sig,
                                   sig_len);
}

int spdm_hmac(const SpdmCryptoSpec* spec, const SpdmHashResult* key,
              const SpdmHashResult* data, SpdmHashResult* out) {
  return spdm_hmac_raw(spec, key, data->data, data->size, out);
}

int spdm_hmac_raw(const SpdmCryptoSpec* spec, const SpdmHashResult* key,
                  const uint8_t* data, uint16_t size, SpdmHashResult* out) {
  if (spec->hmac == NULL) {
    return -1;
  }

  spdm_init_hash_result(out, key->alg);

  return spec->hmac(key->alg, key->data, key->size, data, size, out->data);
}

int spdm_validate_hmac(const SpdmCryptoSpec* spec, const SpdmHashResult* key,
                       const SpdmHashResult* data, const uint8_t* mac) {
  SpdmHashResult candidate_mac;

  int rc = spdm_hmac(spec, key, data, &candidate_mac);
  if (rc != 0) {
    return rc;
  }

  return constant_memcmp(mac, candidate_mac.data, candidate_mac.size);
}

int spdm_hkdf_expand(const SpdmCryptoSpec* spec, const SpdmHashResult* prk,
                     const uint8_t* info, uint32_t info_len,
                     SpdmHashResult* out) {
  spdm_init_hash_result(out, prk->alg);

  return spdm_hkdf_expand_raw(spec, prk->alg, prk->data, prk->size, info,
                              info_len, out->data, out->size);
}

int spdm_hkdf_expand_raw(const SpdmCryptoSpec* spec, SpdmHashAlgorithm alg,
                         const uint8_t* prk, uint32_t prk_len,
                         const uint8_t* info, uint32_t info_len, uint8_t* out,
                         uint32_t out_len) {
  if (spec->hkdf_expand == NULL) {
    return -1;
  }

  return spec->hkdf_expand(alg, prk, prk_len, info, info_len, out, out_len);
}

int spdm_aes_gcm_encrypt(const SpdmCryptoSpec* spec, const SpdmAeadKey* key,
                         const SpdmAeadIv* iv, const uint8_t* plaintext,
                         uint32_t plaintext_len, const uint8_t* aad,
                         uint32_t aad_len, uint8_t* ciphertext, uint8_t* mac,
                         uint32_t mac_len) {
  if (spec->aes_gcm_encrypt == NULL) {
    return -1;
  }

  return spec->aes_gcm_encrypt(key, iv, plaintext, plaintext_len, aad, aad_len,
                               ciphertext, mac, mac_len);
}

int spdm_aes_gcm_decrypt(const SpdmCryptoSpec* spec, const SpdmAeadKey* key,
                         const SpdmAeadIv* iv, const uint8_t* ciphertext,
                         uint32_t ciphertext_len, const uint8_t* aad,
                         uint32_t aad_len, const uint8_t* mac, uint32_t mac_len,
                         uint8_t* plaintext) {
  if (spec->aes_gcm_decrypt == NULL) {
    return -1;
  }

  return spec->aes_gcm_decrypt(key, iv, ciphertext, ciphertext_len, aad,
                               aad_len, mac, mac_len, plaintext);
}

int spdm_extend_hash_with_pub_key(const SpdmCryptoSpec* spec, SpdmHash* hash,
                                  const SpdmAsymPubKey* pub_key) {
  SpdmSerializedAsymPubKey serialized_key;
  SpdmHashResult key_digest;

  int rc = spdm_serialize_asym_key(spec, pub_key, hash->alg, &serialized_key);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_hash(spec, hash->alg, serialized_key.data, serialized_key.size,
                 &key_digest);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(hash, key_digest.data, key_digest.size);

  return 0;
}

int constant_memcmp(const uint8_t* a, const uint8_t* b, uint32_t n) {
  int diff = 0;

  for (int i = 0; i < n; ++i) {
    diff |= a[i] ^ b[i];
  }

  if (diff != 0) {
    return -1;
  }

  return 0;
}
