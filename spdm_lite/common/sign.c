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

#include "spdm_lite/common/sign.h"

#include <string.h>

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"

#define COMBINED_PREFIX_LEN 100

static int make_spdm_combined_prefix(SPDMRole my_role, const char* context,
                                     uint8_t output[COMBINED_PREFIX_LEN]) {
  uint32_t remaining = COMBINED_PREFIX_LEN;
  const char* dmtf_str = "dmtf-spdm-v";
  const uint32_t dmtf_str_len = strlen(dmtf_str);

  const char* spdm_context_prefix_requester = "requester-";
  const char* spdm_context_prefix_responder = "responder-";
  const uint32_t spdm_context_prefix_len =
      strlen(spdm_context_prefix_requester);

  const uint32_t context_len = strlen(context);

  for (int i = 0; i < 4; ++i) {
    memcpy(output, dmtf_str, dmtf_str_len);
    output += dmtf_str_len;
    remaining -= dmtf_str_len;

    output[0] = (SPDM_THIS_VER >> 4) + '0';
    output[1] = '.';
    output[2] = (SPDM_THIS_VER & 0x0F) + '0';
    output[3] = '.';
    output[4] = '*';

    output += 5;
    remaining -= 5;
  }

  output[0] = 0;
  output += 1;
  remaining -= 1;

  if (context_len > (remaining - spdm_context_prefix_len)) {
    return -1;
  }

  uint32_t pad_len = remaining - spdm_context_prefix_len - context_len;
  memset(output, 0, pad_len);

  output += pad_len;
  remaining -= pad_len;

  if (my_role == SPDM_REQUESTER) {
    memcpy(output, spdm_context_prefix_requester, spdm_context_prefix_len);
  } else {
    memcpy(output, spdm_context_prefix_responder, spdm_context_prefix_len);
  }

  output += spdm_context_prefix_len;
  memcpy(output, context, context_len);

  return 0;
}

static int make_message_to_sign(const SpdmCryptoSpec* crypto_spec,
                                SPDMRole signer_role,
                                const SpdmHashResult* message_hash,
                                const char* context, SpdmHashResult* out) {
  uint8_t combined_prefix[COMBINED_PREFIX_LEN];
  SpdmHash hash;

  int rc = make_spdm_combined_prefix(signer_role, context, combined_prefix);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_initialize_hash_struct(crypto_spec, message_hash->alg, &hash);
  if (rc != 0) {
    return rc;
  }

  spdm_initialize_hash(&hash);
  spdm_extend_hash(&hash, combined_prefix, sizeof(combined_prefix));
  spdm_extend_hash(&hash, message_hash->data, message_hash->size);

  return spdm_get_hash_destructive(&hash, out);
}

int spdm_sign(const SpdmCryptoSpec* crypto_spec, SpdmAsymAlgorithm asym_alg,
              void* priv_key_ctx, SPDMRole my_role,
              const SpdmHashResult* message_hash, const char* context,
              uint8_t* out, uint32_t out_len) {
  SpdmHashResult to_sign;

  int rc = make_message_to_sign(crypto_spec, my_role, message_hash, context,
                                &to_sign);
  if (rc != 0) {
    return rc;
  }

  return spdm_sign_with_private_key(crypto_spec, asym_alg, priv_key_ctx,
                                    &to_sign, out, out_len);
}

int spdm_verify(const SpdmCryptoSpec* crypto_spec,
                const SpdmAsymPubKey* pub_key, SPDMRole signer_role,
                const SpdmHashResult* message_hash, const char* context,
                const uint8_t* sig, uint32_t sig_len) {
  SpdmHashResult signed_hash;

  int rc = make_message_to_sign(crypto_spec, signer_role, message_hash, context,
                                &signed_hash);
  if (rc != 0) {
    return rc;
  }

  return spdm_verify_with_pub_key(crypto_spec, pub_key, &signed_hash, sig,
                                  sig_len);
}
