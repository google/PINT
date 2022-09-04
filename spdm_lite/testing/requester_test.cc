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

#include <vector>

#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/crypto_impl/mbedtls_sign.h"
#include "spdm_lite/responder/responder.h"
#include "spdm_lite/testing/add_2_app.h"
#include "spdm_lite/testing/host_context.h"

#include "gtest/gtest.h"

namespace {

TEST(SpdmRequester, EstablishSession) {
  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext rsp_ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &rsp_ctx,
                                    add_2_app_fn);

  SpdmDispatchRequestCtx req_dispatch_ctx;
  initialize_dispatch_req_ctx(&rsp_ctx, &req_dispatch_ctx);

  SpdmRequesterSessionParams req_session_params = {};
  req_session_params.dispatch_ctx = &req_dispatch_ctx;

  SpdmAsymPrivKey req_priv_key;
  ASSERT_EQ(0, spdm_generate_asym_keypair(
                   SPDM_ASYM_ECDSA_ECC_NIST_P256, &req_priv_key,
                   &req_session_params.requester_pub_key));

  req_session_params.requester_priv_key_ctx = &req_priv_key;

  std::vector<uint8_t> scratch_mem(1024);
  req_session_params.scratch = {scratch_mem.data(), scratch_mem.size()};

  SpdmSessionParams session;
  ASSERT_EQ(0, spdm_establish_session(&req_session_params, &session));

  uint16_t standard_id = 4;
  std::vector<uint8_t> vendor_id = {0x01, 0x02, 0x03, 0x04};
  uint32_t req_num = 1701;
  std::vector<uint8_t> rsp(sizeof(Add2AppResponse) +
                           req_session_params.requester_pub_key.size);
  size_t rsp_size = rsp.size();

  ASSERT_EQ(0, spdm_dispatch_app_request(
                   &req_dispatch_ctx, req_session_params.scratch, &session,
                   standard_id, vendor_id.data(), vendor_id.size(), &req_num,
                   sizeof(req_num), rsp.data(), &rsp_size));

  ASSERT_EQ(rsp_size, rsp.size());

  const auto* response = reinterpret_cast<const Add2AppResponse*>(rsp.data());

  EXPECT_EQ(response->num, req_num + 2);
  EXPECT_EQ(0, memcmp(response->session_id.id, session.info.session_id.id,
                      sizeof(response->session_id.id)));
  EXPECT_EQ(0, memcmp(rsp.data() + sizeof(*response),
                      req_session_params.requester_pub_key.data,
                      req_session_params.requester_pub_key.size));

  const SpdmNegotiatedAlgs* session_algs = &session.info.negotiated_algs;
  EXPECT_EQ(response->asym_sign_alg, session_algs->asym_sign_alg);
  EXPECT_EQ(response->asym_verify_alg, session_algs->asym_verify_alg);
  EXPECT_EQ(response->hash_alg, session_algs->hash_alg);
  EXPECT_EQ(response->dhe_alg, session_algs->dhe_alg);
  EXPECT_EQ(response->aead_alg, session_algs->aead_alg);

  // Tear down session
  ASSERT_EQ(0, spdm_end_session(&req_dispatch_ctx, req_session_params.scratch,
                                &session));

  SpdmResponderSession zeroed_session = {};
  EXPECT_EQ(0, memcmp(&zeroed_session.params, &session, sizeof(session)));
  EXPECT_EQ(0,
            memcmp(&zeroed_session, &rsp_ctx.session, sizeof(rsp_ctx.session)));

  EXPECT_EQ(rsp_ctx.state, STATE_WAITING_FOR_GET_VERSION);

  // Start a new one.
  ASSERT_EQ(0, spdm_establish_session(&req_session_params, &session));

  req_num = 42;
  ASSERT_EQ(0, spdm_dispatch_app_request(
                   &req_dispatch_ctx, req_session_params.scratch, &session,
                   standard_id, vendor_id.data(), vendor_id.size(), &req_num,
                   sizeof(req_num), rsp.data(), &rsp_size));

  ASSERT_EQ(rsp_size, rsp.size());

  response = reinterpret_cast<const Add2AppResponse*>(rsp.data());
  EXPECT_EQ(response->num, req_num + 2);
}

}  // namespace
