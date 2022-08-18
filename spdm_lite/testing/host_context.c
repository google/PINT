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

#include "spdm_lite/testing/host_context.h"

#include <assert.h>
#include <stdlib.h>

#include "spdm_lite/crypto_impl/mbedtls_crypto.h"
#include "spdm_lite/requester/requester.h"
#include "spdm_lite/responder/responder.h"

#define SCRATCH_SIZE 1024

static uint8_t* get_scratch_space() {
  static uint8_t* scratch_space;
  static bool initialized;

  if (!initialized) {
    scratch_space = malloc(SCRATCH_SIZE);
  }

  return scratch_space;
}

static int dispatch_request(void* ctx, bool is_secure_msg, const uint8_t* req,
                            size_t req_size, uint8_t* rsp, size_t* rsp_size) {
  SpdmResponderContext* responder_ctx = (SpdmResponderContext*)ctx;

  if (is_secure_msg) {
    return spdm_dispatch_secure_request(responder_ctx, req, req_size, rsp,
                                        rsp_size);
  } else {
    return spdm_dispatch_request(responder_ctx, req, req_size, rsp, rsp_size);
  }
}

static const SpdmCapabilities HOST_CAPS = {
    .ct_exponent = SPDM_HOST_CT_EXPONENT,
    .data_transfer_size = SPDM_HOST_DATA_TRANSFER_SIZE,
};

void initialize_host_requester_context(SpdmAsymPrivKey* priv_key,
                                       SpdmAsymPubKey* pub_key,
                                       SpdmResponderContext* target_responder,
                                       SpdmRequesterContext* ctx) {
  int rc = spdm_generate_asym_keypair(priv_key, pub_key);
  assert(rc == 0);

  SpdmDispatchRequestCtx dispatch_ctx = {
      .crypto_spec = MBEDTLS_CRYPTO_SPEC,
      .dispatch_fn = dispatch_request,
      .ctx = target_responder,
      .scratch = get_scratch_space(),
      .scratch_size = SCRATCH_SIZE,
  };

  rc = spdm_initialize_requester_context(ctx, &dispatch_ctx, HOST_CAPS, pub_key,
                                         priv_key);
  assert(rc == 0);
}

void initialize_host_responder_context(SpdmAsymPrivKey* priv_key,
                                       SpdmAsymPubKey* pub_key,
                                       SpdmResponderContext* ctx,
                                       spdm_app_dispatch_request_fn app_fn) {
  spdm_generate_asym_keypair(priv_key, pub_key);

  int rc = spdm_initialize_responder_context(
      ctx, &MBEDTLS_CRYPTO_SPEC, HOST_CAPS, pub_key, priv_key, app_fn);
  assert(rc == 0);
}
