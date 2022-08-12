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

#include "gtest/gtest.h"

#include "common/crypto.h"
#include "common/messages.h"
#include "common/session_types.h"
#include "common/utils.h"
#include "crypto_impl/mbedtls_crypto.h"
#include "everparse/SPDMWrapper.h"
#include "responder/responder.h"
#include "testing/add_2_app.h"
#include "testing/host_context.h"
#include "testing/utils.h"

namespace {

std::vector<uint8_t> MakeAdd2AppRequest(uint16_t standard_id,
                                        const std::vector<uint8_t>& vendor_id,
                                        uint32_t num) {
  const uint32_t msg_len = sizeof(SPDM_VENDOR_DEFINED_REQ_RSP) +
                           vendor_id.size() + sizeof(uint16_t) +
                           sizeof(uint32_t);

  std::vector<uint8_t> msg(msg_len);

  auto* vendor_defined_req =
      reinterpret_cast<SPDM_VENDOR_DEFINED_REQ_RSP*>(msg.data());
  auto* out_vendor_id = reinterpret_cast<uint8_t*>(&vendor_defined_req[1]);
  auto* req_len = reinterpret_cast<uint16_t*>(out_vendor_id + vendor_id.size());
  auto* number = reinterpret_cast<uint32_t*>(&req_len[1]);

  *vendor_defined_req = {
      .preamble =
          {
              .version = 0x12,
              .request_response_code = SPDM_CODE_VENDOR_DEFINED_REQUEST,
          },
      .standard_id = standard_id,
      .vendor_id_len = static_cast<uint8_t>(vendor_id.size()),
  };

  memcpy(out_vendor_id, vendor_id.data(), vendor_id.size());
  *req_len = sizeof(*number);
  *number = num;

  return msg;
}

TEST(SessionEstablished, AppTraffic) {
  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &ctx,
                                    Add2AppFn);

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

  ASSERT_EQ(0, DispatchRequest(&ctx, get_version_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, get_caps_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, negotiate_algs_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, key_exchange_msg));
  ASSERT_EQ(0, DispatchSecureRequest(&ctx, SPDM_HANDSHAKE_PHASE,
                                     get_encapsulated_req_msg));

  std::vector<uint8_t> encapsulated_response =
      MakeEncapsulatedResponse(ctx.session.pending_pub_key_req_id, req_pub_key);

  ASSERT_EQ(0, DispatchSecureRequest(&ctx, SPDM_HANDSHAKE_PHASE,
                                     encapsulated_response));

  SpdmHash transcript = ctx.session.transcript_hash;
  std::vector<uint8_t> digest = GetDigest(req_pub_key.data, req_pub_key.size);
  spdm_extend_hash(&transcript, digest.data(), digest.size());

  std::vector<uint8_t> finish_msg =
      MakeFinish(&transcript, ctx.session.params, req_priv_key);

  ASSERT_EQ(0, DispatchSecureRequest(&ctx, SPDM_HANDSHAKE_PHASE, finish_msg));
  ASSERT_EQ(ctx.state, STATE_SESSION_ESTABLISHED);

  uint16_t req_standard_id = 4;
  std::vector<uint8_t> req_vendor_id = {0x01, 0x02, 0x03, 0x04};
  uint32_t req_num = 1701;

  std::vector<uint8_t> app_req =
      MakeAdd2AppRequest(req_standard_id, req_vendor_id, req_num);
  std::vector<uint8_t> rsp;
  ASSERT_EQ(0, DispatchSecureRequest(&ctx, SPDM_DATA_PHASE, app_req, &rsp));

  buffer output_msg = MakeBuffer(rsp);

  uint16_t rsp_standard_id;
  buffer rsp_vendor_id;
  buffer payload;

  ASSERT_EQ(0, SpdmCheckVendorDefinedResponse(
                   &output_msg, /*rest=*/nullptr, &rsp_standard_id,
                   &rsp_vendor_id.data, &rsp_vendor_id.size, &payload.data,
                   &payload.size));

  ASSERT_EQ(rsp_standard_id, req_standard_id);
  ASSERT_EQ(rsp_vendor_id.size, req_vendor_id.size());
  ASSERT_EQ(
      0, memcmp(rsp_vendor_id.data, req_vendor_id.data(), rsp_vendor_id.size));

  uint16_t pub_key_size = spdm_get_asym_pub_key_size(req_pub_key.alg);

  ASSERT_EQ(payload.size,
            sizeof(SpdmSessionId) + pub_key_size + sizeof(req_num));

  const uint8_t* rsp_session_id = payload.data;
  const uint8_t* rsp_req_key = rsp_session_id + sizeof(SpdmSessionId);
  const uint8_t* rsp_num = rsp_req_key + pub_key_size;

  EXPECT_EQ(0, memcmp(rsp_session_id, &ctx.session.params.session_id,
                      sizeof(SpdmSessionId)));
  EXPECT_EQ(0, memcmp(rsp_req_key, req_pub_key.data, pub_key_size));

  uint32_t result;
  memcpy(&result, rsp_num, sizeof(result));

  EXPECT_EQ(result, req_num + 2);

  // Tear down session
  std::vector<uint8_t> end_session_msg = MakeEndSession();
  ASSERT_EQ(0, DispatchSecureRequest(&ctx, SPDM_DATA_PHASE, end_session_msg));

  // Test that we can start a new flow.
  ASSERT_EQ(0, DispatchRequest(&ctx, get_version_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, get_caps_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, negotiate_algs_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, key_exchange_msg));
  ASSERT_EQ(ctx.state, STATE_MUTUAL_AUTH_NEED_REQUESTER_KEY);

  // Restart in the middle.
  ASSERT_EQ(0, DispatchRequest(&ctx, get_version_msg));
  ASSERT_EQ(ctx.state, STATE_WAITING_FOR_GET_CAPABILITIES);
}

}  // namespace
