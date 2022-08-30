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

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/key_schedule.h"
#include "spdm_lite/common/session.h"
#include "spdm_lite/common/sign.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/vendor_defined_pub_key.h"
#include "spdm_lite/crypto_impl/mbedtls_crypto.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/responder/responder.h"
#include "spdm_lite/testing/host_context.h"
#include "spdm_lite/testing/utils.h"

#include "gtest/gtest.h"

namespace {

TEST(WaitingForKeyExchange, KeyExchange) {
  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &ctx,
                                    /*app_fn=*/nullptr);

  SpdmDhePrivKey req_priv_key;
  SpdmDhePubKey req_pub_key;
  ASSERT_EQ(0,
            spdm_gen_dhe_keypair(get_mbedtls_crypto_spec(), SPDM_DHE_SECP521R1,
                                 &req_priv_key, &req_pub_key));

  uint8_t req_session_id[2];
  spdm_get_random(&ctx.crypto_spec, req_session_id, sizeof(req_session_id));

  std::vector<uint8_t> get_version_msg = MakeGetVersion();
  std::vector<uint8_t> get_caps_msg = MakeGetCapabilities();
  std::vector<uint8_t> negotiate_algs_msg = MakeNegotiateAlgorithms();
  std::vector<uint8_t> get_pub_key_msg = MakeGetPubKey();
  std::vector<uint8_t> key_exchange_msg =
      MakeKeyExchange(req_session_id, req_pub_key);

  std::vector<uint8_t> rsp;

  SpdmHash target_digest;
  ASSERT_EQ(0, spdm_initialize_hash_struct(get_mbedtls_crypto_spec(),
                                           SPDM_HASH_SHA512, &target_digest));
  spdm_initialize_hash(&target_digest);

  // Send GET_VERSION
  ASSERT_EQ(0, DispatchRequest(&ctx, get_version_msg, &rsp));

  // Hash GET_VERSION/VERSION
  ExtendHash(&target_digest, get_version_msg);
  ExtendHash(&target_digest, rsp);

  // Send GET_CAPABILITIES
  ASSERT_EQ(0, DispatchRequest(&ctx, get_caps_msg, &rsp));

  // Hash GET_CAPABILITIES/CAPABILITIES
  ExtendHash(&target_digest, get_caps_msg);
  ExtendHash(&target_digest, rsp);

  // Send NEGOTIATE_ALGORITHMS
  ASSERT_EQ(0, DispatchRequest(&ctx, negotiate_algs_msg, &rsp));

  // Hash NEGOTIATE_ALGORITHMS/ALGORITHMS
  ExtendHash(&target_digest, negotiate_algs_msg);
  ExtendHash(&target_digest, rsp);

  // Send VENDOR_DEFINED_REQUEST(GET_PUB_KEY)
  ASSERT_EQ(0, DispatchRequest(&ctx, get_pub_key_msg, &rsp));

  buffer output_msg = MakeBuffer(rsp);

  uint16_t standard_id;
  buffer vendor_id;
  buffer payload;

  ASSERT_EQ(0, SpdmCheckVendorDefinedResponse(
                   &output_msg, /*rest=*/nullptr, &standard_id, &vendor_id.data,
                   &vendor_id.size, &payload.data, &payload.size));

  ASSERT_EQ(standard_id, DMTF_STANDARD_ID);
  ASSERT_EQ(vendor_id.size, 0);
  ASSERT_GT(payload.size, sizeof(SPDM_VendorDefinedPubKeyMsg));

  auto* pub_key_rsp =
      reinterpret_cast<const SPDM_VendorDefinedPubKeyMsg*>(payload.data);
  ASSERT_EQ(pub_key_rsp->vd_id, DMTF_VD_ID);
  // TODO(jeffandersen): endianness
  ASSERT_EQ(pub_key_rsp->vd_req_rsp, DMTF_VD_GET_PUBKEY_CODE);

  SpdmAsymPubKey pub_key_in_response;
  ASSERT_EQ(
      0, spdm_deserialize_asym_key(
             &ctx.crypto_spec, ctx.negotiated_algs.asym_verify_alg,
             ctx.negotiated_algs.hash_alg, payload.data + sizeof(*pub_key_rsp),
             payload.size - sizeof(*pub_key_rsp), &pub_key_in_response));

  ASSERT_EQ(0, memcmp(pub_key_in_response.data, ctx.responder_pub_key.data,
                      pub_key_in_response.size));

  EXPECT_EQ(ctx.state, STATE_WAITING_FOR_KEY_EXCHANGE);

  // Send KEY_EXCHANGE
  ASSERT_EQ(0, DispatchRequest(&ctx, key_exchange_msg, &rsp));

  output_msg = MakeBuffer(rsp);

  uint8_t heartbeat_period;
  const uint8_t* rsp_session_id;
  uint8_t mut_auth_requested_flow;
  uint8_t slot_id;
  const uint8_t* rsp_exchange_data;
  const uint8_t* measurement_summary_hash;
  buffer opaque_data;
  const uint8_t* signature;
  const uint8_t* responder_verify_data;

  ASSERT_EQ(
      0, SpdmCheckKeyExchangeRsp(
             &output_msg, /*rest=*/nullptr,
             /*exchange_data_len=*/P521_SERIALIZED_POINT_SIZE,
             /*hash_len=*/SHA512_DIGEST_SIZE,
             /*signature_len=*/P256_SERIALIZED_POINT_SIZE,
             /*measurement_summary_hash_expected=*/false,
             /*responder_verify_data_expected=*/true, &heartbeat_period,
             &rsp_session_id, &mut_auth_requested_flow, &slot_id,
             &rsp_exchange_data, &measurement_summary_hash, &opaque_data.data,
             &opaque_data.size, &signature, &responder_verify_data));

  std::vector<uint8_t> pub_key_digest =
      GetDigest(rsp_pub_key.data, rsp_pub_key.size);

  ExtendHash(&target_digest, pub_key_digest);
  ExtendHash(&target_digest, key_exchange_msg);

  spdm_extend_hash(
      &target_digest, rsp.data(),
      rsp.size() - P256_SERIALIZED_POINT_SIZE - SHA512_DIGEST_SIZE);

  std::vector<uint8_t> transcript_digest = GetDigest(target_digest);
  SpdmHashResult result = GetHashResult(transcript_digest);

  EXPECT_EQ(0, spdm_verify(&ctx.crypto_spec, &rsp_pub_key,
                           /*signer_role=*/SPDM_RESPONDER, &result,
                           /*context=*/"key_exchange_rsp signing", signature,
                           P256_SERIALIZED_POINT_SIZE));

  spdm_extend_hash(&target_digest, signature, P256_SERIALIZED_POINT_SIZE);

  transcript_digest = GetDigest(target_digest);
  EXPECT_EQ(0, memcmp(transcript_digest.data(), ctx.session.params.th_1.data,
                      transcript_digest.size()));

  EXPECT_EQ(heartbeat_period, 0);
  EXPECT_EQ(mut_auth_requested_flow, 1);
  EXPECT_EQ(slot_id, 0);

  SpdmDhePubKey peer_pub_key;
  spdm_init_dhe_pub_key(&peer_pub_key, SPDM_DHE_SECP521R1);

  memcpy(peer_pub_key.data, rsp_exchange_data, peer_pub_key.size);

  SpdmSessionParams session = {};
  session.info.negotiated_algs.hash_alg = SPDM_HASH_SHA512;
  session.info.negotiated_algs.asym_sign_alg = SPDM_ASYM_ECDSA_ECC_NIST_P256;
  session.info.negotiated_algs.asym_verify_alg = SPDM_ASYM_ECDSA_ECC_NIST_P256;

  spdm_generate_session_id(
      /*my_role=*/SPDM_REQUESTER, req_session_id, rsp_session_id,
      &session.info.session_id);

  ASSERT_EQ(0, spdm_gen_dhe_secret(&ctx.crypto_spec, &req_priv_key,
                                   &peer_pub_key, &session.shared_key));

  session.th_1 = ctx.session.params.th_1;  // Already verified.

  ASSERT_EQ(
      0, memcmp(&session.info.session_id, &ctx.session.params.info.session_id,
                sizeof(session.info.session_id)));

  ASSERT_EQ(0,
            memcmp(session.shared_key.data, ctx.session.params.shared_key.data,
                   session.shared_key.size));

  SpdmMessageSecrets handshake_secrets;
  ASSERT_EQ(0, spdm_generate_message_secrets(&ctx.crypto_spec, &session,
                                             SPDM_HANDSHAKE_PHASE,
                                             &handshake_secrets));

  SpdmHashResult finish_key;
  ASSERT_EQ(0, spdm_generate_finished_key(&ctx.crypto_spec,
                                          /*originator=*/SPDM_RESPONDER,
                                          &handshake_secrets, &finish_key));

  SpdmHashResult hmac;
  ASSERT_EQ(0, spdm_hmac(&ctx.crypto_spec, &finish_key, &session.th_1, &hmac));

  EXPECT_EQ(0, memcmp(responder_verify_data, hmac.data, hmac.size));

  EXPECT_EQ(ctx.state, STATE_MUTUAL_AUTH_NEED_REQUESTER_KEY);
  EXPECT_EQ(ctx.session.params.req_seq_num, 0);
  EXPECT_EQ(ctx.session.params.rsp_seq_num, 0);
}

// TODO(jeffandersen): Add negative test

}  // namespace
