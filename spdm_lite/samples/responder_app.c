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

#include "spdm_lite/samples/responder_app.h"

#include <stdio.h>

#include "spdm_lite/crypto_impl/mbedtls_crypto.h"
#include "spdm_lite/crypto_impl/mbedtls_sign.h"
#include "spdm_lite/crypto_impl/raw_serialize.h"
#include "spdm_lite/responder/responder.h"

// Handle application requests that comes over a secure SPDM session.
// `session_info` holds information such as the peer's public key and the
// negotiated algorithms.
static int handle_rot13_request(const SpdmSessionInfo* session_info,
                                uint16_t standard_id, const uint8_t* vendor_id,
                                size_t vendor_id_size, const uint8_t* payload,
                                size_t payload_size, uint8_t* output,
                                size_t* output_size) {
  if (standard_id != SAMPLE_APP_STANDARD_ID) {
    fprintf(stderr,
            "handle_rot13_request failed, expected standard_id %d, got %d\n",
            SAMPLE_APP_STANDARD_ID, standard_id);
    return -1;
  }

  if (vendor_id_size != 1 || vendor_id[0] != SAMPLE_APP_VENDOR_ID) {
    fprintf(stderr,
            "handle_rot13_request failed, expected vendor_id %d, got %zu bytes "
            "starting with %d\n",
            SAMPLE_APP_VENDOR_ID, vendor_id_size, vendor_id[0]);
    return -1;
  }

  if (payload_size != 1 || *output_size < 1) {
    fprintf(stderr,
            "handle_rot13_request failed, expected payload size %d, got %zu "
            "with output buffer size %zu\n",
            1, payload_size, *output_size);
    return -1;
  }

  // Perform ROT-128 on the input.
  uint8_t input_val = payload[0];
  uint8_t output_val = input_val + 128;

  *output = output_val;
  *output_size = 1;

  return 0;
}

static SpdmResponderContext* get_global_responder_ctx(void) {
  static SpdmResponderContext ctx;
  static SpdmAsymPrivKey responder_priv_key;
  static bool initialized;

  if (!initialized) {
    SpdmCryptoSpec crypto_spec = MBEDTLS_BASE_CRYPTO_SPEC;
    crypto_spec.sign_with_priv_key = spdm_mbedtls_sign_with_priv_key;
    crypto_spec.serialize_pub_key = spdm_raw_serialize_asym_key;
    crypto_spec.deserialize_pub_key = spdm_raw_serialize_asym_key;

    // Place-holder for unimplemented features like max transport size.
    SpdmCapabilities responder_caps = {};

    SpdmAsymPubKey responder_pub_key;
    int rc = spdm_generate_asym_keypair(
        SPDM_ASYM_ECDSA_ECC_NIST_P256, &responder_priv_key, &responder_pub_key);
    if (rc != 0) {
      fprintf(stderr, "spdm_generate_asym_keypair failed on line %d, err %d\n",
              __LINE__, rc);
      return NULL;
    }

    rc = spdm_initialize_responder_context(
        &ctx, &crypto_spec, &responder_caps, &responder_pub_key,
        &responder_priv_key, handle_rot13_request);
    if (rc != 0) {
      fprintf(stderr,
              "spdm_initialize_responder_context failed on line %d, err %d\n",
              __LINE__, rc);
      return NULL;
    }

    initialized = true;
  }

  return &ctx;
}

int sample_app_dispatch_spdm_request(bool is_secure, const uint8_t* req,
                                     size_t req_size, uint8_t* rsp,
                                     size_t* rsp_size) {
  SpdmResponderContext* ctx = get_global_responder_ctx();
  if (ctx == NULL) {
    return -1;
  }

  return spdm_dispatch_request(ctx, is_secure, req, req_size, rsp, rsp_size);
}
