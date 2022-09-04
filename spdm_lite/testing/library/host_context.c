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
#include <string.h>

#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/crypto_impl/mbedtls_crypto.h"
#include "spdm_lite/crypto_impl/mbedtls_sign.h"
#include "spdm_lite/crypto_impl/raw_serialize.h"
#include "spdm_lite/requester/requester.h"
#include "spdm_lite/responder/responder.h"

static int dispatch_request(void* ctx, bool is_secure_msg, const uint8_t* req,
                            size_t req_size, uint8_t* rsp, size_t* rsp_size) {
  return spdm_dispatch_request((SpdmResponderContext*)ctx, is_secure_msg, req,
                               req_size, rsp, rsp_size);
}

void initialize_dispatch_req_ctx(SpdmResponderContext* target_responder,
                                 SpdmDispatchRequestCtx* req_ctx) {
  req_ctx->crypto_spec = *get_mbedtls_crypto_spec();
  req_ctx->dispatch_fn = dispatch_request,
  req_ctx->dispatch_ctx = target_responder;
}

const SpdmCryptoSpec* get_mbedtls_crypto_spec(void) {
  static SpdmCryptoSpec spec;
  static bool initialized = false;

  if (!initialized) {
    spec = MBEDTLS_BASE_CRYPTO_SPEC;
    spec.serialize_pub_key = spdm_raw_serialize_asym_key;
    spec.deserialize_pub_key = spdm_raw_serialize_asym_key;
    spec.sign_with_priv_key = spdm_mbedtls_sign_with_priv_key;

    initialized = true;
  }

  return &spec;
}

void initialize_host_responder_context(SpdmAsymPrivKey* priv_key,
                                       SpdmAsymPubKey* pub_key,
                                       SpdmResponderContext* ctx,
                                       spdm_app_dispatch_request_fn app_fn) {
  spdm_generate_asym_keypair(SPDM_ASYM_ECDSA_ECC_NIST_P256, priv_key, pub_key);

  int rc = spdm_initialize_responder_context(
      ctx, get_mbedtls_crypto_spec(), &HOST_CAPS, pub_key, priv_key, app_fn);
  assert(rc == 0);
  (void)rc;
}
