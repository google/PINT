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

#include "spdm_lite/crypto_impl/mbedtls_crypto.h"

#include <string.h>

#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/defs.h"

#include "mbedtls/version.h"
#if MBEDTLS_VERSION_MAJOR > 2
#include "mbedtls/compat-2.x.h"
#endif

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

static void make_blinding_drbg(mbedtls_ctr_drbg_context* ctr_drbg) {
  mbedtls_entropy_context entropy;

  mbedtls_ctr_drbg_init(ctr_drbg);
  mbedtls_entropy_init(&entropy);

  const char context[] = "spdm_lite";
  mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, &entropy, context,
                        sizeof(context));

  mbedtls_entropy_free(&entropy);
}

static int get_random(uint8_t* data, uint32_t len) {
  mbedtls_ctr_drbg_context ctr_drbg;
  make_blinding_drbg(&ctr_drbg);

  int rc = mbedtls_ctr_drbg_random(&ctr_drbg, data, len);
  mbedtls_ctr_drbg_free(&ctr_drbg);

  return rc;
}

typedef struct {
  union {
    mbedtls_sha256_context sha256;
    mbedtls_sha512_context sha384;
    mbedtls_sha512_context sha512;
  };
} HashCtx;

static void initialize_hash(void* ctx, SpdmHashAlgorithm alg) {
  HashCtx* hash_ctx = (HashCtx*)ctx;

  switch (alg) {
    case SPDM_HASH_SHA256:
      mbedtls_sha256_init(&hash_ctx->sha256);
      mbedtls_sha256_starts_ret(&hash_ctx->sha256, /*is224=*/0);
      break;
    case SPDM_HASH_SHA384:
      mbedtls_sha512_init(&hash_ctx->sha384);
      mbedtls_sha512_starts_ret(&hash_ctx->sha384, /*is_384=*/1);
      break;
    case SPDM_HASH_SHA512:
      mbedtls_sha512_init(&hash_ctx->sha512);
      mbedtls_sha512_starts_ret(&hash_ctx->sha512, /*is_384=*/0);
      break;
    case SPDM_HASH_UNSUPPORTED:
    default:
      break;
  }
}

static void extend_hash(void* ctx, SpdmHashAlgorithm alg, const uint8_t* data,
                        uint32_t len) {
  // mbedtls_sha{256,512}_update only errors out if `len` == 0.
  if (len == 0) {
    return;
  }

  HashCtx* hash_ctx = (HashCtx*)ctx;

  switch (alg) {
    case SPDM_HASH_SHA256:
      mbedtls_sha256_update_ret(&hash_ctx->sha256, data, len);
      break;
    case SPDM_HASH_SHA384:
      mbedtls_sha512_update_ret(&hash_ctx->sha384, data, len);
      break;
    case SPDM_HASH_SHA512:
      mbedtls_sha512_update_ret(&hash_ctx->sha512, data, len);
      break;
    case SPDM_HASH_UNSUPPORTED:
    default:
      break;
  }
}

static int get_hash(void* ctx, SpdmHashAlgorithm alg, uint8_t* digest) {
  HashCtx* hash_ctx = (HashCtx*)ctx;

  switch (alg) {
    case SPDM_HASH_SHA256:
      mbedtls_sha256_finish_ret(&hash_ctx->sha256, digest);
      break;
    case SPDM_HASH_SHA384:
      mbedtls_sha512_finish_ret(&hash_ctx->sha384, digest);
      break;
    case SPDM_HASH_SHA512:
      mbedtls_sha512_finish_ret(&hash_ctx->sha512, digest);
      break;
    case SPDM_HASH_UNSUPPORTED:
    default:
      return -1;
  }

  return 0;
}

static uint16_t get_coord_size(mbedtls_ecp_group_id group_id) {
  uint16_t bit_size = mbedtls_ecp_curve_info_from_grp_id(group_id)->bit_size;
  return (bit_size / 8) + ((bit_size % 8) != 0);
}

static int read_ec_point(uint16_t coord_size, const uint8_t* data,
                         mbedtls_ecp_point* p) {
  int rc = mbedtls_mpi_read_binary(&p->X, data, coord_size);
  if (rc != 0) {
    return rc;
  }

  rc = mbedtls_mpi_read_binary(&p->Y, data + coord_size, coord_size);
  if (rc != 0) {
    return rc;
  }

  rc = mbedtls_mpi_lset(&p->Z, 1);
  if (rc != 0) {
    return rc;
  }

  return 0;
}

static int write_ec_point(uint16_t coord_size, const mbedtls_mpi* x,
                          const mbedtls_mpi* y, uint8_t* data) {
  int rc = mbedtls_mpi_write_binary(x, data, coord_size);
  if (rc != 0) {
    return rc;
  }

  rc = mbedtls_mpi_write_binary(y, data + coord_size, coord_size);
  if (rc != 0) {
    return rc;
  }

  return 0;
}

static mbedtls_ecp_group_id get_asym_group_id(SpdmAsymAlgorithm alg) {
  switch (alg) {
    case SPDM_ASYM_ECDSA_ECC_NIST_P256:
      return MBEDTLS_ECP_DP_SECP256R1;
    case SPDM_ASYM_ECDSA_ECC_NIST_P384:
      return MBEDTLS_ECP_DP_SECP384R1;
    case SPDM_ASYM_ECDSA_ECC_NIST_P521:
      return MBEDTLS_ECP_DP_SECP521R1;
    case SPDM_ASYM_UNSUPPORTED:
    default:
      return MBEDTLS_ECP_DP_NONE;
  }
}

static mbedtls_ecp_group_id get_dhe_group_id(SpdmDheAlgorithm alg) {
  switch (alg) {
    case SPDM_DHE_SECP256R1:
      return MBEDTLS_ECP_DP_SECP256R1;
    case SPDM_DHE_SECP384R1:
      return MBEDTLS_ECP_DP_SECP384R1;
    case SPDM_DHE_SECP521R1:
      return MBEDTLS_ECP_DP_SECP521R1;
    case SPDM_ASYM_UNSUPPORTED:
    default:
      return MBEDTLS_ECP_DP_NONE;
  }
}

static mbedtls_md_type_t get_md_type(SpdmHashAlgorithm alg) {
  switch (alg) {
    case SPDM_HASH_SHA256:
      return MBEDTLS_MD_SHA256;
    case SPDM_HASH_SHA384:
      return MBEDTLS_MD_SHA384;
    case SPDM_HASH_SHA512:
      return MBEDTLS_MD_SHA512;
    case SPDM_HASH_UNSUPPORTED:
    default:
      return MBEDTLS_MD_NONE;
  }
}

static int validate_asym_key(const SpdmAsymPubKey* pub_key) {
  mbedtls_ecp_group g;
  mbedtls_ecp_group_init(&g);

  mbedtls_ecp_point p;
  mbedtls_ecp_point_init(&p);

  mbedtls_ecp_group_id group_id = get_asym_group_id(pub_key->alg);
  if (group_id == MBEDTLS_ECP_DP_NONE) {
    return -1;
  }

  int rc = mbedtls_ecp_group_load(&g, group_id);
  if (rc != 0) {
    goto cleanup;
  }

  rc = read_ec_point(get_coord_size(group_id), pub_key->data, &p);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecp_check_pubkey(&g, &p);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  mbedtls_ecp_group_free(&g);
  mbedtls_ecp_point_free(&p);

  return rc;
}

static int validate_dhe_key(const SpdmDhePubKey* pub_key) {
  mbedtls_ecp_group g;
  mbedtls_ecp_group_init(&g);

  mbedtls_ecp_point p;
  mbedtls_ecp_point_init(&p);

  mbedtls_ecp_group_id group_id = get_dhe_group_id(pub_key->alg);
  if (group_id == MBEDTLS_ECP_DP_NONE) {
    return -1;
  }

  int rc = mbedtls_ecp_group_load(&g, group_id);
  if (rc != 0) {
    goto cleanup;
  }

  rc = read_ec_point(get_coord_size(group_id), pub_key->data, &p);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecp_check_pubkey(&g, &p);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  mbedtls_ecp_group_free(&g);
  mbedtls_ecp_point_free(&p);

  return rc;
}

static int generate_keypair(mbedtls_ecp_group_id group_id,
                            uint8_t* pub_key_data, uint8_t* priv_key_data) {
  mbedtls_ecp_group g;
  mbedtls_ecp_group_init(&g);

  mbedtls_mpi d;
  mbedtls_mpi_init(&d);

  mbedtls_ecp_point p;
  mbedtls_ecp_point_init(&p);

  mbedtls_ctr_drbg_context ctr_drbg;
  make_blinding_drbg(&ctr_drbg);

  uint16_t coord_size = get_coord_size(group_id);

  int rc = mbedtls_ecp_group_load(&g, group_id);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecp_gen_keypair(&g, &d, &p, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_write_binary(&d, priv_key_data, coord_size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = write_ec_point(coord_size, &p.X, &p.Y, pub_key_data);

cleanup:
  mbedtls_ecp_group_free(&g);
  mbedtls_ecp_point_free(&p);
  mbedtls_mpi_free(&d);
  mbedtls_ctr_drbg_free(&ctr_drbg);

  return rc;
}

static int gen_dhe_keypair(SpdmDheAlgorithm alg, uint8_t* priv_key,
                           uint8_t* pub_key) {
  mbedtls_ecp_group_id group_id = get_dhe_group_id(alg);
  if (group_id == MBEDTLS_ECP_DP_NONE) {
    return -1;
  }

  return generate_keypair(group_id, pub_key, priv_key);
}

static int gen_dhe_secret(const SpdmDhePrivKey* priv_key,
                          const SpdmDhePubKey* pub_key,
                          uint8_t* shared_secret) {
  mbedtls_ecp_group g;
  mbedtls_ecp_group_init(&g);

  mbedtls_mpi d;
  mbedtls_mpi_init(&d);

  mbedtls_ecp_point p;
  mbedtls_ecp_point_init(&p);

  mbedtls_mpi z;
  mbedtls_mpi_init(&z);

  mbedtls_ctr_drbg_context ctr_drbg;
  make_blinding_drbg(&ctr_drbg);

  mbedtls_ecp_group_id group_id = get_dhe_group_id(pub_key->alg);
  if (group_id == MBEDTLS_ECP_DP_NONE) {
    return -1;
  }

  if (priv_key->alg != pub_key->alg) {
    return -1;
  }

  uint16_t secret_size = spdm_get_dhe_secret_size(priv_key->alg);
  uint16_t coord_size = get_coord_size(group_id);

  int rc = mbedtls_ecp_group_load(&g, group_id);
  if (rc != 0) {
    goto cleanup;
  }

  rc = read_ec_point(coord_size, pub_key->data, &p);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecp_check_pubkey(&g, &p);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_read_binary(&d, priv_key->data, coord_size);
  if (rc != 0) {
    return rc;
  }

  rc = mbedtls_ecp_check_privkey(&g, &d);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecdh_compute_shared(&g, &z, &p, &d, mbedtls_ctr_drbg_random,
                                   &ctr_drbg);
  if (rc != 0) {
    goto cleanup;
  }

  if (mbedtls_mpi_size(&z) > secret_size) {
    rc = -1;
    goto cleanup;
  }

  rc = mbedtls_mpi_write_binary(&z, shared_secret, secret_size);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  mbedtls_ecp_group_free(&g);
  mbedtls_ecp_point_free(&p);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&z);
  mbedtls_ctr_drbg_free(&ctr_drbg);

  return rc;
}

static int sign_with_priv_key(SpdmAsymAlgorithm alg, void* priv_key_ctx,
                              const uint8_t* input, uint32_t input_len,
                              uint8_t* sig, uint32_t sig_len) {
  SpdmAsymPrivKey* priv_key = (SpdmAsymPrivKey*)priv_key_ctx;

  if (alg != priv_key->alg) {
    return -1;
  }

  mbedtls_ecp_group_id group_id = get_asym_group_id(alg);
  if (group_id == MBEDTLS_ECP_DP_NONE) {
    return -1;
  }

  uint8_t* priv_key_data;

  switch (alg) {
    case SPDM_ASYM_ECDSA_ECC_NIST_P256:
      priv_key_data = priv_key->ecdsa_p256;
      break;
    case SPDM_ASYM_ECDSA_ECC_NIST_P384:
      priv_key_data = priv_key->ecdsa_p384;
      break;
    case SPDM_ASYM_ECDSA_ECC_NIST_P521:
      priv_key_data = priv_key->ecdsa_p521;
      break;
    case SPDM_ASYM_UNSUPPORTED:
    default:
      return -1;
  }

  uint16_t coord_size = get_coord_size(group_id);

  if (sig_len != spdm_get_asym_signature_size(alg)) {
    return -1;
  }

  mbedtls_ecp_group g;
  mbedtls_ecp_group_init(&g);

  mbedtls_mpi r, s, d;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&d);

  mbedtls_ctr_drbg_context ctr_drbg;
  make_blinding_drbg(&ctr_drbg);

  int rc = mbedtls_ecp_group_load(&g, group_id);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_read_binary(&d, (unsigned char*)priv_key_data, coord_size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecdsa_sign_det_ext(&g, &r, &s, &d, (const unsigned char*)input,
                                  input_len, MBEDTLS_MD_SHA384,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_write_binary(&r, (unsigned char*)sig, coord_size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_write_binary(&s, (unsigned char*)(sig + coord_size),
                                coord_size);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  mbedtls_ecp_group_free(&g);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&d);
  mbedtls_ctr_drbg_free(&ctr_drbg);

  return rc;
}

static int verify_with_pub_key(const SpdmAsymPubKey* pub_key,
                               const uint8_t* input, uint32_t input_len,
                               const uint8_t* sig, uint32_t sig_len) {
  mbedtls_ecp_group_id group_id = get_asym_group_id(pub_key->alg);
  if (group_id == MBEDTLS_ECP_DP_NONE) {
    return -1;
  }

  if (sig_len != spdm_get_asym_signature_size(pub_key->alg)) {
    return -1;
  }

  uint16_t coord_size = get_coord_size(group_id);

  mbedtls_ecp_group g;
  mbedtls_ecp_group_init(&g);

  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);

  int rc = mbedtls_ecp_group_load(&g, group_id);
  if (rc != 0) {
    goto cleanup;
  }

  rc = read_ec_point(coord_size, pub_key->data, &Q);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecp_check_pubkey(&g, &Q);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_read_binary(&r, (const unsigned char*)sig, coord_size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_read_binary(&s, (const unsigned char*)(sig + coord_size),
                               coord_size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecdsa_verify(&g, input, input_len, &Q, &r, &s);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  mbedtls_ecp_group_free(&g);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_ecp_point_free(&Q);

  return rc;
}

static int hmac(SpdmHashAlgorithm alg, const uint8_t* key, uint32_t key_len,
                const uint8_t* data, uint32_t data_len, uint8_t* out) {
  const mbedtls_md_info_t* md_info =
      mbedtls_md_info_from_type(get_md_type(alg));
  if (md_info == NULL) {
    return -1;
  }

  return mbedtls_md_hmac(md_info, key, key_len, data, data_len, out);
}

static int hkdf_expand(SpdmHashAlgorithm alg, const uint8_t* key,
                       uint32_t key_len, const uint8_t* context,
                       uint32_t context_len, uint8_t* out, uint32_t out_len) {
  const mbedtls_md_info_t* md_info =
      mbedtls_md_info_from_type(get_md_type(alg));
  if (md_info == NULL) {
    return -1;
  }

  return mbedtls_hkdf_expand(md_info, key, key_len, context, context_len, out,
                             out_len);
}

static int aes_gcm_encrypt(const SpdmAeadKey* key, const SpdmAeadIv* iv,
                           const uint8_t* plaintext, uint32_t plaintext_len,
                           const uint8_t* aad, uint32_t aad_len,
                           uint8_t* ciphertext, uint8_t* mac,
                           uint32_t mac_len) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                              (const unsigned char*)key->data,
                              /*keybits=*/key->size * 8);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_gcm_crypt_and_tag(
      &ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len, (const unsigned char*)iv->data,
      iv->size, (const unsigned char*)aad, aad_len,
      (const unsigned char*)plaintext, (unsigned char*)ciphertext, mac_len,
      (unsigned char*)mac);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  mbedtls_gcm_free(&ctx);

  return rc;
}

static int aes_gcm_decrypt(const SpdmAeadKey* key, const SpdmAeadIv* iv,
                           const uint8_t* ciphertext, uint32_t ciphertext_len,
                           const uint8_t* aad, uint32_t aad_len,
                           const uint8_t* mac, uint32_t mac_len,
                           uint8_t* plaintext) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES,
                              (const unsigned char*)key->data,
                              /*keybits=*/key->size * 8);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_gcm_auth_decrypt(
      &ctx, ciphertext_len, (const unsigned char*)iv->data, iv->size,
      (const unsigned char*)aad, aad_len, (const unsigned char*)mac, mac_len,
      (const unsigned char*)ciphertext, (unsigned char*)plaintext);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  mbedtls_gcm_free(&ctx);

  return rc;
}

int spdm_generate_asym_keypair(SpdmAsymPrivKey* priv_key,
                               SpdmAsymPubKey* pub_key) {
  BUILD_ASSERT(sizeof(pub_key->data) >= P256_SERIALIZED_POINT_SIZE);

  int rc = generate_keypair(MBEDTLS_ECP_DP_SECP256R1, pub_key->data,
                            priv_key->ecdsa_p256);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_init_asym_pub_key(pub_key, SPDM_ASYM_ECDSA_ECC_NIST_P256,
                              pub_key->data, P256_SERIALIZED_POINT_SIZE);
  if (rc != 0) {
    return rc;
  }

  priv_key->alg = SPDM_ASYM_ECDSA_ECC_NIST_P256;

  return 0;
}

const SpdmCryptoSpec MBEDTLS_CRYPTO_SPEC = {
    .supported_algs =
        {
            .asym_sign =
                {
                    .ecdsa_ecc_nist_p256 = true,
                    .ecdsa_ecc_nist_p384 = true,
                    .ecdsa_ecc_nist_p521 = true,
                },
            .asym_verify =
                {
                    .ecdsa_ecc_nist_p256 = true,
                    .ecdsa_ecc_nist_p384 = true,
                    .ecdsa_ecc_nist_p521 = true,
                },
            .hash_sha256 = true,
            .hash_sha384 = true,
            .hash_sha512 = true,
            .dhe_secp256r1 = true,
            .dhe_secp384r1 = true,
            .dhe_secp521r1 = true,
            .aead_aes_128_gcm = true,
            .aead_aes_256_gcm = true,
        },
    .get_random = get_random,
    .hash_ctx_size = sizeof(HashCtx),
    .initialize_hash = initialize_hash,
    .extend_hash = extend_hash,
    .get_hash = get_hash,
    .validate_asym_key = validate_asym_key,
    .validate_dhe_key = validate_dhe_key,
    .gen_dhe_keypair = gen_dhe_keypair,
    .gen_dhe_secret = gen_dhe_secret,
    .sign_with_priv_key = sign_with_priv_key,
    .verify_with_pub_key = verify_with_pub_key,
    .hmac = hmac,
    .hkdf_expand = hkdf_expand,
    .aes_gcm_encrypt = aes_gcm_encrypt,
    .aes_gcm_decrypt = aes_gcm_decrypt,
};
