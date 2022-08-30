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

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/error.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/responder/responder.h"
#include "spdm_lite/testing/host_context.h"
#include "spdm_lite/testing/utils.h"

#include "gtest/gtest.h"

namespace {

TEST(WaitingForGetVersion, GetVersion) {
  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &ctx,
                                    /*app_fn=*/nullptr);

  std::vector<uint8_t> get_version_msg = MakeGetVersion();

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

  uint8_t entry_count;
  const uint8_t* entries;

  buffer output_msg = MakeBuffer(rsp);
  ASSERT_EQ(0, SpdmCheckVersion(&output_msg, /*rest=*/nullptr, &entry_count,
                                &entries));
  ASSERT_EQ(entry_count, 1);

  SPDM_VersionNumberEntry entry;
  memcpy(&entry, entries, sizeof(entry));
  EXPECT_EQ(entry.major_version, 1);
  EXPECT_EQ(entry.minor_version, 2);
  EXPECT_EQ(entry.update_version, 0);
  EXPECT_EQ(entry.alpha, 0);

  // Compare digests
  std::vector<uint8_t> ctx_digest = GetDigest(ctx.negotiation_transcript.data,
                                              ctx.negotiation_transcript.size);
  std::vector<uint8_t> expected_digest = GetDigest(target_digest);
  EXPECT_EQ(ctx_digest, expected_digest);

  // Test that we can re-start the flow with another GET_VERSION.
  ASSERT_EQ(0, DispatchRequest(&ctx, get_version_msg, &rsp));

  ctx_digest = GetDigest(ctx.negotiation_transcript.data,
                         ctx.negotiation_transcript.size);
  EXPECT_EQ(ctx_digest, expected_digest);

  EXPECT_EQ(ctx.state, STATE_WAITING_FOR_GET_CAPABILITIES);
}

TEST(WaitingForGetVersion, InvalidGetVersion) {
  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &ctx,
                                    /*app_fn=*/nullptr);

  SPDM_GET_VERSION get_version_msg = {};

  get_version_msg.preamble.version = 0x10;
  get_version_msg.preamble.request_response_code = SPDM_CODE_VERSION;  // Wrong

  std::vector<uint8_t> output(256);
  size_t output_size = output.size();

  ASSERT_EQ(0, spdm_dispatch_request(
                   &ctx, /*is_secure=*/false,
                   reinterpret_cast<const uint8_t*>(&get_version_msg),
                   sizeof(get_version_msg), output.data(), &output_size));

  buffer output_msg = {output.data(), (uint32_t)output_size};

  uint8_t error_code, error_data;
  ASSERT_EQ(0, SpdmCheckError(&output_msg, /*rest=*/nullptr, &error_code,
                              &error_data));

  EXPECT_EQ(error_code, SPDM_ERR_VERSION_MISMATCH);
  EXPECT_EQ(error_data, 0);

  EXPECT_EQ(ctx.state, STATE_WAITING_FOR_GET_VERSION);
}

}  // namespace
