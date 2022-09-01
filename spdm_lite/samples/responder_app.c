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

#include "spdm_lite/responder/responder.h"

int dispatch_app_request(const SpdmSessionInfo* session_info,
                         uint16_t standard_id, const uint8_t* vendor_id,
                         size_t vendor_id_size, const uint8_t* payload,
                         size_t payload_size, uint8_t* output,
                         size_t* output_size) {
  // Handle any application request that comes over a secure SPDM session.
  // `session_info` holds information such as the peer's public key and the
  // negotiated algorithms.
  //
  // All requests are encapsulated within a vendor-defined command;
  // `standard_id` and `vendor_id` indicate what kind of request came through.
}

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

SpdmCapabilities responder_caps = {
  .ct_exponent = 0,          // Timing parameter (currently unimplemented)
  .data_transfer_size = ...  // Max payload size allowable by the transport.
};

// The key that will be used to sign SPDM messages.
SpdmAsymPubKey signing_pub_key = ...;
void* signing_priv_key_ctx = ...;

// Initialize the Responder context.
SpdmResponderContext responer_ctx;
spdm_initialize_responder_context(&responer_ctx, &crypto_spec, responder_caps,
                                  &signing_pub_key, &signing_priv_key_ctx,
                                  dispatch_app_request);

// Handle incoming SPDM request.
bool is_secure = ...;       // Sensed from the transport.
uint8_t* request = ...;    // Holds either an encrypted or a plaintext payload.
size_t request_size = ...;
uint8_t response_buf[...];  // Location to write the response.
size_t response_size = sizeof(response_buf);

spdm_dispatch_request(&responer_ctx, is_secure, request, request_size,
                      response_buf, &response_size);

// [Write response to the transport]
