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

#ifndef SPDM_LITE_TESTING_UTILS_H_
#define SPDM_LITE_TESTING_UTILS_H_

#include <type_traits>
#include <vector>

#include "common/crypto_types.h"
#include "common/session_types.h"
#include "common/utils.h"
#include "crypto_impl/mbedtls_crypto.h"
#include "responder/responder.h"

void ExtendHash(SpdmHash* hash, const std::vector<uint8_t>& b);
std::vector<uint8_t> GetDigest(const uint8_t* data, uint32_t len);
std::vector<uint8_t> GetDigest(const SpdmHash& hash);
SpdmHashResult GetHashResult(const std::vector<uint8_t>& digest);

template <typename T, typename = std::enable_if_t<std::is_pod<T>::value>>
inline buffer MakeBuffer(T& t) {
  return {reinterpret_cast<uint8_t*>(&t), sizeof(t)};
}

buffer MakeBuffer(std::vector<uint8_t>& vec);
byte_writer MakeWriter(std::vector<uint8_t>& vec);

int DispatchRequest(SpdmResponderContext* ctx, std::vector<uint8_t>& req,
                    std::vector<uint8_t>* rsp = nullptr);

int DispatchSecureRequest(SpdmResponderContext* ctx, SpdmSessionPhase phase,
                          std::vector<uint8_t>& req,
                          std::vector<uint8_t>* rsp = nullptr);

std::vector<uint8_t> MakeGetVersion();
std::vector<uint8_t> MakeGetCapabilities();
std::vector<uint8_t> MakeNegotiateAlgorithms();
std::vector<uint8_t> MakeGetPubKey();
std::vector<uint8_t> MakeKeyExchange(uint8_t req_session_id[2],
                                     const SpdmDhePubKey& dhe_pub_key);
std::vector<uint8_t> MakeGetEncapsulatedRequest();
std::vector<uint8_t> MakeEncapsulatedResponse(uint8_t req_id,
                                              const SpdmAsymPubKey& pub_key);
std::vector<uint8_t> MakeFinish(SpdmHash* transcript_hash,
                                const SpdmSessionParams& session,
                                SpdmAsymPrivKey& req_priv_key);
std::vector<uint8_t> MakeEndSession();

int GetSecureMessageKeys(const SpdmSessionParams& session, SPDMRole originator,
                         SpdmSessionPhase phase, SpdmAeadKeys* keys);

int EncryptMessage(const std::vector<uint8_t>& message,
                   const SpdmSessionParams& session, SPDMRole my_role,
                   SpdmSessionPhase phase, std::vector<uint8_t>* output);

#endif  // SPDM_LITE_TESTING_UTILS_H_
