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

#include "gtest/gtest.h"

#include "common/crypto.h"
#include "common/messages.h"
#include "common/utils.h"
#include "crypto_impl/mbedtls_crypto.h"
#include "everparse/SPDMWrapper.h"
#include "responder/responder.h"
#include "testing/host_context.h"
#include "testing/utils.h"

namespace {

TEST(WaitingForNegotiateAlgorithms, NegotiateAlgorithms) {
  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &ctx,
                                    /*app_fn=*/nullptr);

  std::vector<uint8_t> get_version_msg = MakeGetVersion();
  std::vector<uint8_t> get_caps_msg = MakeGetCapabilities();
  std::vector<uint8_t> negotiate_algs_msg = MakeNegotiateAlgorithms();

  std::vector<uint8_t> rsp;

  SpdmHash target_digest;
  ASSERT_EQ(0, spdm_initialize_hash_struct(&MBEDTLS_CRYPTO_SPEC,
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

  buffer output_msg = MakeBuffer(rsp);

  const uint8_t* ext_asym_algs;
  uint32_t ext_asym_algs_count;
  const uint8_t* ext_hash_algs;
  uint32_t ext_hash_algs_count;
  buffer alg_structs;
  uint32_t alg_structs_count;

  ASSERT_EQ(0, SpdmCheckAlgorithms(
                   &output_msg, /*rest=*/nullptr, &ext_asym_algs,
                   &ext_asym_algs_count, &ext_hash_algs, &ext_hash_algs_count,
                   &alg_structs.data, &alg_structs_count, &alg_structs.size));

  auto* algs_msg = reinterpret_cast<const SPDM_ALGORITHMS*>(output_msg.data);
  EXPECT_EQ(algs_msg->other_params_opaque_data_fmt_1, 1);
  EXPECT_EQ(algs_msg->asym_hash_algs.base_asym_alg_ecdsa_ecc_nist_p256, 1);
  EXPECT_EQ(algs_msg->asym_hash_algs.base_hash_algo_sha_512, 1);

  ASSERT_EQ(ext_asym_algs_count, 0);
  ASSERT_EQ(ext_hash_algs_count, 0);
  ASSERT_EQ(alg_structs_count, 4);

  buffer rest;
  uint32_t alg_count_extended;

  // Check DHE algs
  ASSERT_EQ(0, SpdmCheckDheAlg(&alg_structs, &rest, /*is_resp=*/true,
                               &alg_count_extended));
  ASSERT_EQ(alg_count_extended, 0);
  EXPECT_EQ(reinterpret_cast<const SPDM_AlgStruct_DHE*>(alg_structs.data)
                ->alg_supported_secp521r1,
            1);

  // Check AEAD algs
  alg_structs = rest;
  ASSERT_EQ(0, SpdmCheckAeadAlg(&alg_structs, &rest, /*is_resp=*/true,
                                &alg_count_extended));
  ASSERT_EQ(alg_count_extended, 0);
  EXPECT_EQ(reinterpret_cast<const SPDM_AlgStruct_AEAD*>(alg_structs.data)
                ->alg_supported_aes_256_gcm,
            1);

  // Check asym algs
  alg_structs = rest;
  ASSERT_EQ(0, SpdmCheckAsymAlg(&alg_structs, &rest, /*is_resp=*/true,
                                &alg_count_extended));
  ASSERT_EQ(alg_count_extended, 0);
  EXPECT_EQ(reinterpret_cast<const SPDM_AlgStruct_BaseAsym*>(alg_structs.data)
                ->alg_supported_ecdsa_ecc_nist_p256,
            1);

  // Check key schedule algs
  alg_structs = rest;
  ASSERT_EQ(0, SpdmCheckKeySchedule(&alg_structs, &rest, /*is_resp=*/true,
                                    &alg_count_extended));
  ASSERT_EQ(alg_count_extended, 0);
  EXPECT_EQ(
      reinterpret_cast<const SPDM_AlgStruct_KeySchedule*>(alg_structs.data)
          ->alg_supported_spdm_key_schedule,
      1);

  // Compare digests
  std::vector<uint8_t> ctx_digest = GetDigest(ctx.negotiation_transcript.data,
                                              ctx.negotiation_transcript.size);
  std::vector<uint8_t> expected_digest = GetDigest(target_digest);
  EXPECT_EQ(ctx_digest, expected_digest);

  EXPECT_EQ(ctx.state, STATE_WAITING_FOR_KEY_EXCHANGE);
}

// TODO(jeffandersen): Add negative test

}  // namespace
