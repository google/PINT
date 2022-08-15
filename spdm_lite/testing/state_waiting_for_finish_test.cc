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

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "common/crypto.h"
#include "common/key_schedule.h"
#include "common/messages.h"
#include "common/session_types.h"
#include "common/utils.h"
#include "crypto_impl/mbedtls_crypto.h"
#include "everparse/SPDMWrapper.h"
#include "responder/responder.h"
#include "testing/host_context.h"
#include "testing/utils.h"

#include "gtest/gtest.h"

namespace {

TEST(WaitingForFinish, Finish) {
  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &ctx,
                                    /*app_fn=*/nullptr);

  SpdmAsymPrivKey req_priv_key;
  SpdmAsymPubKey req_pub_key;
  ASSERT_EQ(0, spdm_generate_asym_keypair(&req_priv_key, &req_pub_key));

  SpdmDhePrivKey req_key_ex_priv_key;
  SpdmDhePubKey req_key_ex_pub_key;
  ASSERT_EQ(0, spdm_gen_dhe_keypair(&MBEDTLS_CRYPTO_SPEC, SPDM_DHE_SECP521R1,
                                    &req_key_ex_priv_key, &req_key_ex_pub_key));

  uint8_t req_session_id[2];
  spdm_get_random(&ctx.crypto_spec, req_session_id, sizeof(req_session_id));

  std::vector<uint8_t> get_version_msg = MakeGetVersion();
  std::vector<uint8_t> get_caps_msg = MakeGetCapabilities();
  std::vector<uint8_t> negotiate_algs_msg = MakeNegotiateAlgorithms();
  std::vector<uint8_t> key_exchange_msg =
      MakeKeyExchange(req_session_id, req_key_ex_pub_key);
  std::vector<uint8_t> get_encapsulated_req_msg = MakeGetEncapsulatedRequest();

  std::vector<uint8_t> rsp;

  SpdmHash target_digest;
  ASSERT_EQ(0, spdm_initialize_hash_struct(&MBEDTLS_CRYPTO_SPEC,
                                           SPDM_HASH_SHA512, &target_digest));
  spdm_initialize_hash(&target_digest);

  ASSERT_EQ(0, DispatchRequest(&ctx, get_version_msg, &rsp));
  ExtendHash(&target_digest, get_version_msg);
  ExtendHash(&target_digest, rsp);

  ASSERT_EQ(0, DispatchRequest(&ctx, get_caps_msg, &rsp));
  ExtendHash(&target_digest, get_caps_msg);
  ExtendHash(&target_digest, rsp);

  ASSERT_EQ(0, DispatchRequest(&ctx, negotiate_algs_msg, &rsp));
  ExtendHash(&target_digest, negotiate_algs_msg);
  ExtendHash(&target_digest, rsp);

  ASSERT_EQ(0, DispatchRequest(&ctx, key_exchange_msg, &rsp));

  std::vector<uint8_t> pub_key_digest =
      GetDigest(rsp_pub_key.data, rsp_pub_key.size);

  ExtendHash(&target_digest, pub_key_digest);
  ExtendHash(&target_digest, key_exchange_msg);
  ExtendHash(&target_digest, rsp);

  ASSERT_EQ(0, DispatchSecureRequest(&ctx, SPDM_HANDSHAKE_PHASE,
                                     get_encapsulated_req_msg));

  std::vector<uint8_t> encapsulated_response =
      MakeEncapsulatedResponse(ctx.session.pending_pub_key_req_id, req_pub_key);

  ASSERT_EQ(0, DispatchSecureRequest(&ctx, SPDM_HANDSHAKE_PHASE,
                                     encapsulated_response));

  // Check the transcript before proceeding.
  std::vector<uint8_t> transcript_digest = GetDigest(target_digest);
  SpdmHashResult actual_transcript_digest;
  ASSERT_EQ(0, spdm_get_hash(&ctx.session.transcript_hash,
                             &actual_transcript_digest));
  ASSERT_EQ(0, memcmp(transcript_digest.data(), actual_transcript_digest.data,
                      transcript_digest.size()));

  std::vector<uint8_t> digest = GetDigest(req_pub_key.data, req_pub_key.size);
  ExtendHash(&target_digest, digest);

  std::vector<uint8_t> finish_msg =
      MakeFinish(&target_digest, ctx.session.params, req_priv_key);

  ASSERT_EQ(
      0, DispatchSecureRequest(&ctx, SPDM_HANDSHAKE_PHASE, finish_msg, &rsp));

  buffer output_msg = MakeBuffer(rsp);
  const uint8_t* responder_verify_data;
  ASSERT_EQ(0, SpdmCheckFinishRsp(&output_msg, /*rest=*/nullptr,
                                  /*hash_len=*/SHA512_DIGEST_SIZE,
                                  /*responder_verify_data_expected=*/true,
                                  &responder_verify_data));

  SpdmMessageSecrets handshake_secrets;
  SpdmHashResult finish_key;
  ASSERT_EQ(0, spdm_generate_message_secrets(
                   &MBEDTLS_CRYPTO_SPEC, &ctx.session.params,
                   SPDM_HANDSHAKE_PHASE, &handshake_secrets));

  ASSERT_EQ(0, spdm_generate_finished_key(&MBEDTLS_CRYPTO_SPEC, SPDM_RESPONDER,
                                          &handshake_secrets, &finish_key));

  spdm_extend_hash(&target_digest, reinterpret_cast<const uint8_t*>(rsp.data()),
                   sizeof(SPDM_FINISH_RSP));

  transcript_digest = GetDigest(target_digest);
  SpdmHashResult digest_result = GetHashResult(transcript_digest);
  ASSERT_EQ(0, spdm_validate_hmac(&ctx.crypto_spec, &finish_key, &digest_result,
                                  responder_verify_data));

  spdm_extend_hash(&target_digest,
                   reinterpret_cast<const uint8_t*>(responder_verify_data),
                   SHA512_DIGEST_SIZE);

  transcript_digest = GetDigest(target_digest);
  EXPECT_EQ(0, memcmp(transcript_digest.data(), ctx.session.params.th_2.data,
                      transcript_digest.size()));

  EXPECT_EQ(ctx.state, STATE_SESSION_ESTABLISHED);
}

}  // namespace
