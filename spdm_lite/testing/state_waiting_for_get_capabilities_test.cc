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
#include <vector>

#include "common/crypto.h"
#include "common/messages.h"
#include "common/utils.h"
#include "crypto_impl/mbedtls_crypto.h"
#include "everparse/SPDMWrapper.h"
#include "responder/responder.h"
#include "testing/host_context.h"
#include "testing/utils.h"

#include "gtest/gtest.h"

namespace {

TEST(WaitingForGetCapabilities, GetCapabilities) {
  std::vector<uint8_t> get_version_msg = MakeGetVersion();
  std::vector<uint8_t> get_caps_msg = MakeGetCapabilities();

  std::vector<uint8_t> rsp;

  SpdmHash target_digest;
  ASSERT_EQ(0, spdm_initialize_hash_struct(&MBEDTLS_CRYPTO_SPEC,
                                           SPDM_HASH_SHA512, &target_digest));
  spdm_initialize_hash(&target_digest);

  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &ctx,
                                    /*app_fn=*/nullptr);

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

  buffer output_msg = MakeBuffer(rsp);
  ASSERT_EQ(0, SpdmCheckCapabilities(&output_msg, /*rest=*/nullptr));

  SPDM_CAPABILITIES caps;
  memcpy(&caps, output_msg.data, sizeof(caps));
  EXPECT_EQ(caps.ct_exponent, SPDM_HOST_CT_EXPONENT);
  EXPECT_EQ(caps.flags_ENCRYPT_CAP, 1);
  EXPECT_EQ(caps.flags_MAC_CAP, 1);
  EXPECT_EQ(caps.flags_MUT_AUTH_CAP, 1);
  EXPECT_EQ(caps.flags_KEY_EX_CAP, 1);
  EXPECT_EQ(caps.flags_ALIAS_CERT_CAP, 1);
  EXPECT_EQ(caps.data_transfer_size, SPDM_HOST_DATA_TRANSFER_SIZE);
  EXPECT_EQ(caps.max_spdm_message_size, SPDM_HOST_DATA_TRANSFER_SIZE);

  // Compare digests
  std::vector<uint8_t> ctx_digest = GetDigest(ctx.negotiation_transcript.data,
                                              ctx.negotiation_transcript.size);
  std::vector<uint8_t> expected_digest = GetDigest(target_digest);
  EXPECT_EQ(ctx_digest, expected_digest);

  EXPECT_EQ(ctx.state, STATE_WAITING_FOR_NEGOTIATE_ALGORITHMS);
  EXPECT_EQ(ctx.requester_caps.ct_exponent, SPDM_HOST_CT_EXPONENT);
  EXPECT_EQ(ctx.requester_caps.data_transfer_size,
            SPDM_HOST_DATA_TRANSFER_SIZE);
}

// TODO(jeffandersen): Add negative test

}  // namespace
