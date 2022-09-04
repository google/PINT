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

#include "spdm_lite/samples/requester_app.h"

#include <stdio.h>

#include "spdm_lite/samples/responder_app.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/crypto_impl/mbedtls_crypto.h"
#include "spdm_lite/crypto_impl/mbedtls_sign.h"
#include "spdm_lite/crypto_impl/raw_serialize.h"
#include "spdm_lite/requester/requester.h"

static SpdmSessionParams global_session;
static bool global_session_initialized;

// Amount of memory to allocate for scratch-space for each request.
#define SCRATCH_SIZE 384

// Sends a request to the Responder. `is_secure_msg` indicates whether `req`
// holds an encrypted payload or whether it is a plaintext SPDM request. This
// value should be reflected onto the transport, so the Responder can properly
// handle the request.
int dispatch_spdm_request(void* ctx, bool is_secure_msg, const uint8_t* req,
                          size_t req_size, uint8_t* rsp, size_t* rsp_size) {
  // This implementation ignores `ctx`, as it is unneeded.

  return sample_app_dispatch_spdm_request(is_secure_msg, req, req_size, rsp,
                                          rsp_size);
}

static SpdmDispatchRequestCtx* get_global_requester_ctx(void) {
  static SpdmDispatchRequestCtx req_ctx;
  static bool initialized = false;

  if (!initialized) {
    req_ctx.crypto_spec = MBEDTLS_BASE_CRYPTO_SPEC;
    req_ctx.crypto_spec.sign_with_priv_key = spdm_mbedtls_sign_with_priv_key;
    req_ctx.crypto_spec.serialize_pub_key = spdm_raw_serialize_asym_key;
    req_ctx.crypto_spec.deserialize_pub_key = spdm_raw_serialize_asym_key;

    req_ctx.dispatch_fn = dispatch_spdm_request;
    req_ctx.dispatch_ctx = NULL;  // Unused by `dispatch_spdm_request`.

    initialized = true;
  }

  return &req_ctx;
}

int sample_app_initialize_spdm_session(void) {
  if (global_session_initialized) {
    fprintf(stderr,
            "sample_app_initialize_spdm_session failed: global session already "
            "initialized\n");
    return -1;
  }

  SpdmAsymPrivKey requester_priv_key;
  uint8_t scratch_mem[SCRATCH_SIZE];

  SpdmRequesterSessionParams params = {
    .dispatch_ctx = get_global_requester_ctx(),
    .requester_priv_key_ctx = &requester_priv_key,
    .scratch = {scratch_mem, sizeof(scratch_mem)},
  };

  int rc = spdm_generate_asym_keypair(SPDM_ASYM_ECDSA_ECC_NIST_P256,
                                      &requester_priv_key,
                                      &params.requester_pub_key);
  if (rc != 0) {
    fprintf(stderr, "spdm_generate_asym_keypair failed on line %d, err %d\n",
            __LINE__, rc);
    return rc;
  }

  rc = spdm_establish_session(&params, &global_session);
  if (rc != 0) {
    fprintf(stderr, "spdm_establish_session failed on line %d, err %d\n",
            __LINE__, rc);
    return rc;
  }

  global_session_initialized = true;

  return 0;
}

int sample_app_rot128_byte(uint8_t input, uint8_t* output) {
  if (!global_session_initialized) {
    fprintf(stderr,
            "sample_app_rot128_byte failed: global session not initialized\n");
    return -1;
  }

  uint8_t scratch_mem[SCRATCH_SIZE];
  SpdmScratchSpace scratch_space = {scratch_mem, sizeof(scratch_mem)};

  uint16_t standard_id = SAMPLE_APP_STANDARD_ID;
  uint8_t vendor_id = SAMPLE_APP_VENDOR_ID;

  size_t output_size = sizeof(*output);

  int rc = spdm_dispatch_app_request(get_global_requester_ctx(), scratch_space,
                                     &global_session, standard_id, &vendor_id,
                                     sizeof(vendor_id), &input, sizeof(input),
                                     output, &output_size);
  if (rc != 0) {
    fprintf(stderr, "spdm_dispatch_app_request failed on line %d, err %d\n",
            __LINE__, rc);
    return rc;
  }

  if (output_size != sizeof(*output)) {
    fprintf(
        stderr,
        "sample_app_rot128_byte failed: not enough data written (expected %lu, "
        "got %zu\n",
        sizeof(*output), output_size);
    return -1;
  }

  return 0;
}

int sample_app_end_spdm_session(void) {
  if (!global_session_initialized) {
    fprintf(
        stderr,
        "sample_app_end_spdm_session failed: global session not initialized\n");
    return -1;
  }

  uint8_t scratch_mem[SCRATCH_SIZE];
  SpdmScratchSpace scratch_space = {scratch_mem, sizeof(scratch_mem)};

  int rc = spdm_end_session(get_global_requester_ctx(), scratch_space,
                            &global_session);
  if (rc != 0) {
    fprintf(stderr, "spdm_end_session failed on line %d, err %d\n", __LINE__,
            rc);
    return rc;
  }

  global_session_initialized = false;

  return 0;
}
