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

#include "spdm_lite/requester/requester.h"

int dispatch_spdm_request(void* ctx, bool is_secure_msg, const uint8_t* req,
                          size_t req_size, uint8_t* rsp, size_t* rsp_size) {
  // Sends a request to the Responder. `is_secure_msg` indicates whether `req`
  // holds an encrypted payload or whether it is a plaintext SPDM request. This
  // value should be reflected onto the transport, so the Responder can properly
  // handle the request.
}

void* dispatch_ctx = ...;  // Passed to `dispatch_spdm_request`

int sign_with_priv_key(SpdmAsymAlgorithm alg, void* ctx, const uint8_t* input,
                       uint32_t input_len, uint8_t* sig, uint32_t sig_len) {
  // Signs a given message with the private key referred to by `ctx`.
}

int serialize_pub_key(SpdmAsymAlgorithm asym_alg, SpdmHashAlgorithm hash_alg,
                      const uint8_t* in, uint16_t in_size, uint8_t* out,
                      uint16_t* out_size) {
  // Serializes the given public key for transmission across the wire.
}

int deserialize_pub_key(SpdmAsymAlgorithm asym_alg, SpdmHashAlgorithm hash_alg,
                        const uint8_t* in, uint16_t in_size, uint8_t* out,
                        uint16_t* out_size) {
  // Deserializes the given wire-format value into a public key.
}

SpdmCryptoSpec crypto_spec = {
  // Provides implementations of all low-level crypto functions.
  ...
  .sign_with_priv_key = sign_with_priv_key,
  .serialize_pub_key = serialize_pub_key,
  .deserialize_pub_key = deserialize_pub_key,
  ...
};

uint8_t scratch_space[(max payload size + SPDM_SECURE_MESSAGE_OVERHEAD)]

SpdmDispatchRequestCtx dispatch_ctx = {
  .crypto_spec = crypto_spec,
  .dispatch_fn = dispatch_spdm_request,
  .ctx = dispatch_ctx,
  .scratch = scratch_space,
  .scratch_size = sizeof(scratch_space),
};

// Place-holder for unimplemented features like max transport size.
SpdmCapabilities requester_caps = {};

// The key that will be used to sign SPDM messages.
SpdmAsymPubKey signing_pub_key = ...;
void* signing_priv_key_ctx = ...;

// Initialize the Requester context.
SpdmRequesterContext requester_ctx;
spdm_initialize_requester_context(&requester_ctx, &dispatch_ctx, requester_caps,
                                  &signing_pub_key, &signing_priv_key_ctx);

// Establish the session and start sending application requests.
SpdmSessionParams session;
spdm_establish_session(&requester_ctx, &session);

// All requests are wrapped within a vendor-defined command.
uint16_t standard_id = ...;
uint8_t vendor_id[] = ...;

uint8_t request[] = ...;
uint8_t response_buf[...];
size_t response_size = sizeof(response_buf);

spdm_dispatch_app_request(&dispatch_ctx, &session, standard_id, vendor_id,
                          sizeof(vendor_id), request, sizeof(request),
                          response_buf, &response_size);

// [Handle response]

// Tear down session
spdm_end_session(&dispatch_ctx, &session);
