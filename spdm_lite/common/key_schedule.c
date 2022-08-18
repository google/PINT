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

#include "spdm_lite/common/key_schedule.h"

#include <string.h>

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/version.h"

#define BINCONCAT_MAX_LABEL_LEN 12
#define BINCONCAT_BUF_LEN (2 + 8 + BINCONCAT_MAX_LABEL_LEN + SHA512_DIGEST_SIZE)

#define BINCONCAT_STR0 "derived"
#define BINCONCAT_STR0_LEN 7

#define BINCONCAT_STR1 "req hs data"
#define BINCONCAT_STR1_LEN 11

#define BINCONCAT_STR2 "rsp hs data"
#define BINCONCAT_STR2_LEN 11

#define BINCONCAT_STR3 "rsp app data"
#define BINCONCAT_STR3_LEN 12

#define BINCONCAT_STR4 "rsp app data"
#define BINCONCAT_STR4_LEN 12

#define BINCONCAT_STR5 "key"
#define BINCONCAT_STR5_LEN 3

#define BINCONCAT_STR6 "iv"
#define BINCONCAT_STR6_LEN 2

#define BINCONCAT_STR7 "finished"
#define BINCONCAT_STR7_LEN 8

typedef struct {
  uint16_t len;
  uint8_t data[BINCONCAT_BUF_LEN];
} binconcat_buffer;

static void gen_bin_str(uint16_t len, const char* label, uint8_t label_len,
                        const SpdmHashResult* context, binconcat_buffer* buf) {
  uint8_t* out = buf->data;
  buf->len = 0;

  // TODO(jeffandersen): endianness
  memcpy(out, &len, sizeof(len));
  out += sizeof(len);
  buf->len += sizeof(len);

  out[0] = 's';
  out[1] = 'p';
  out[2] = 'd';
  out[3] = 'm';
  out[4] = (SPDM_THIS_VER >> 4) + '0';
  out[5] = '.';
  out[6] = (SPDM_THIS_VER & 0x0F) + '0';
  out[7] = ' ';

  out += 8;
  buf->len += 8;

  memcpy(out, label, label_len);
  out += label_len;
  buf->len += label_len;

  if (context != NULL) {
    uint16_t context_size = spdm_get_hash_size(context->alg);

    memcpy(out, context->data, context_size);
    out += context_size;
    buf->len += context_size;
  }
}

static void gen_bin_str0(SpdmHashAlgorithm alg, binconcat_buffer* buf) {
  gen_bin_str(spdm_get_hash_size(alg), BINCONCAT_STR0, BINCONCAT_STR0_LEN, NULL,
              buf);
}

static void gen_bin_str1(const SpdmHashResult* th_1, binconcat_buffer* buf) {
  gen_bin_str(th_1->size, BINCONCAT_STR1, BINCONCAT_STR1_LEN, th_1, buf);
}

static void gen_bin_str2(const SpdmHashResult* th_1, binconcat_buffer* buf) {
  gen_bin_str(th_1->size, BINCONCAT_STR2, BINCONCAT_STR2_LEN, th_1, buf);
}

static void gen_bin_str3(const SpdmHashResult* th_2, binconcat_buffer* buf) {
  gen_bin_str(th_2->size, BINCONCAT_STR3, BINCONCAT_STR3_LEN, th_2, buf);
}

static void gen_bin_str4(const SpdmHashResult* th_2, binconcat_buffer* buf) {
  gen_bin_str(th_2->size, BINCONCAT_STR4, BINCONCAT_STR4_LEN, th_2, buf);
}

static void gen_bin_str5(SpdmAeadAlgorithm alg, binconcat_buffer* buf) {
  gen_bin_str(spdm_get_aead_key_size(alg), BINCONCAT_STR5, BINCONCAT_STR5_LEN,
              NULL, buf);
}

static void gen_bin_str6(SpdmAeadAlgorithm alg, binconcat_buffer* buf) {
  gen_bin_str(spdm_get_aead_iv_size(alg), BINCONCAT_STR6, BINCONCAT_STR6_LEN,
              NULL, buf);
}

static void gen_bin_str7(SpdmHashAlgorithm alg, binconcat_buffer* buf) {
  gen_bin_str(spdm_get_hash_size(alg), BINCONCAT_STR7, BINCONCAT_STR7_LEN, NULL,
              buf);
}

static int hkdf_expand(const SpdmCryptoSpec* crypto_spec,
                       const SpdmHashResult* prk, const binconcat_buffer* info,
                       SpdmHashResult* out) {
  return spdm_hkdf_expand(crypto_spec, prk, info->data, info->len, out);
}

static int hkdf_expand_raw(const SpdmCryptoSpec* crypto_spec,
                           const SpdmHashResult* prk,
                           const binconcat_buffer* info, uint8_t* out,
                           uint32_t out_len) {
  return spdm_hkdf_expand_raw(crypto_spec, prk->alg, prk->data, prk->size,
                              info->data, info->len, out, out_len);
}

static void tweak_iv(uint64_t seq_num, SpdmAeadIv* iv) {
  uint16_t iv_size = spdm_get_aead_iv_size(iv->alg);

  if (iv_size < 4) {
    return;
  }

  iv->data[iv_size - 4] ^= (seq_num >> 24) & 0xFF;
  iv->data[iv_size - 3] ^= (seq_num >> 16) & 0xFF;
  iv->data[iv_size - 2] ^= (seq_num >> 8) & 0xFF;
  iv->data[iv_size - 1] ^= (seq_num >> 0) & 0xFF;
}

static int derive_handshake_secret(const SpdmCryptoSpec* crypto_spec,
                                   SpdmHashAlgorithm alg,
                                   const SpdmDheSecret* shared_secret,
                                   SpdmHashResult* handshake_secret) {
  SpdmHashResult salt_0;
  spdm_init_hash_result(&salt_0, alg);
  memset(salt_0.data, 0, salt_0.size);

  return spdm_hmac_raw(crypto_spec, &salt_0, shared_secret->data,
                       shared_secret->size, handshake_secret);
}

static int derive_master_secret(const SpdmCryptoSpec* crypto_spec,
                                const SpdmHashResult* handshake_secret,
                                SpdmHashResult* master_secret) {
  binconcat_buffer bin_str0;
  SpdmHashResult salt_1;
  SpdmHashResult zero_filled;

  spdm_init_hash_result(&zero_filled, handshake_secret->alg);
  memset(zero_filled.data, 0, zero_filled.size);

  gen_bin_str0(handshake_secret->alg, &bin_str0);

  int rc = hkdf_expand(crypto_spec, handshake_secret, &bin_str0, &salt_1);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_hmac(crypto_spec, &salt_1, &zero_filled, master_secret);
  if (rc != 0) {
    memset(master_secret, 0, sizeof(*master_secret));
    goto cleanup;
  }

cleanup:
  memset(&handshake_secret, 0, sizeof(handshake_secret));
  memset(&salt_1, 0, sizeof(salt_1));

  return rc;
}

static int populate_message_secrets(const SpdmCryptoSpec* crypto_spec,
                                    const SpdmHashResult* secret,
                                    const binconcat_buffer* req_binstr,
                                    const binconcat_buffer* rsp_binstr,
                                    SpdmMessageSecrets* secrets) {
  int rc =
      hkdf_expand(crypto_spec, secret, req_binstr, &secrets->request_direction);
  if (rc != 0) {
    goto cleanup;
  }

  rc = hkdf_expand(crypto_spec, secret, rsp_binstr,
                   &secrets->response_direction);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  if (rc != 0) {
    memset(secrets, 0, sizeof(*secrets));
  }

  return rc;
}

int spdm_generate_message_secrets(const SpdmCryptoSpec* crypto_spec,
                                  const SpdmSessionParams* session,
                                  SpdmSessionPhase phase,
                                  SpdmMessageSecrets* secrets) {
  SpdmHashResult secret;
  binconcat_buffer req_binstr, rsp_binstr;

  if (phase == SPDM_NO_SESSION) {
    return -1;
  }

  int rc = derive_handshake_secret(crypto_spec,
                                   session->info.negotiated_algs.hash_alg,
                                   &session->shared_key, &secret);
  if (rc != 0) {
    goto cleanup;
  }

  switch (phase) {
    case SPDM_HANDSHAKE_PHASE:
      gen_bin_str1(&session->th_1, &req_binstr);
      gen_bin_str2(&session->th_1, &rsp_binstr);
      break;
    case SPDM_DATA_PHASE:
      gen_bin_str3(&session->th_2, &req_binstr);
      gen_bin_str4(&session->th_2, &rsp_binstr);

      rc = derive_master_secret(crypto_spec, &secret, &secret);
      if (rc != 0) {
        goto cleanup;
      }
      break;
    default:
      return -1;
  }

  rc = populate_message_secrets(crypto_spec, &secret, &req_binstr, &rsp_binstr,
                                secrets);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&secret, 0, sizeof(secret));
  return rc;
}

int spdm_generate_finished_key(const SpdmCryptoSpec* crypto_spec,
                               SPDMRole originator,
                               const SpdmMessageSecrets* secrets,
                               SpdmHashResult* key) {
  const SpdmHashResult* secret;
  if (originator == SPDM_REQUESTER) {
    secret = &secrets->request_direction;
  } else {
    secret = &secrets->response_direction;
  }

  binconcat_buffer bin_str7;
  gen_bin_str7(secret->alg, &bin_str7);

  return hkdf_expand(crypto_spec, secret, &bin_str7, key);
}

static int generate_directional_keys(const SpdmCryptoSpec* crypto_spec,
                                     SpdmAeadAlgorithm alg,
                                     const SpdmHashResult* secret,
                                     uint64_t seq_num, SpdmAeadKeys* keys) {
  binconcat_buffer bin_str5, bin_str6;
  gen_bin_str5(alg, &bin_str5);
  gen_bin_str6(alg, &bin_str6);

  spdm_init_aead_key(&keys->key, alg);
  spdm_init_aead_iv(&keys->iv, alg);

  int rc = hkdf_expand_raw(crypto_spec, secret, &bin_str5, keys->key.data,
                           keys->key.size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = hkdf_expand_raw(crypto_spec, secret, &bin_str6, keys->iv.data,
                       keys->iv.size);
  if (rc != 0) {
    goto cleanup;
  }

  tweak_iv(seq_num, &keys->iv);

cleanup:
  if (rc != 0) {
    memset(keys, 0, sizeof(*keys));
  }

  return rc;
}

int spdm_generate_aead_keys(const SpdmCryptoSpec* crypto_spec,
                            SpdmAeadAlgorithm alg,
                            const SpdmMessageSecrets* secrets,
                            uint64_t req_seq_num, uint64_t rsp_seq_num,
                            SpdmSessionAeadKeys* keys) {
  int rc =
      generate_directional_keys(crypto_spec, alg, &secrets->request_direction,
                                req_seq_num, &keys->req_keys);
  if (rc != 0) {
    goto cleanup;
  }

  rc = generate_directional_keys(crypto_spec, alg, &secrets->response_direction,
                                 rsp_seq_num, &keys->rsp_keys);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  if (rc != 0) {
    memset(keys, 0, sizeof(*keys));
  }

  return rc;
}
