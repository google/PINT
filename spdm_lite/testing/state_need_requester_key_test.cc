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
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/vendor_defined_pub_key.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/responder/responder.h"
#include "spdm_lite/testing/host_context.h"
#include "spdm_lite/testing/utils.h"

#include "gtest/gtest.h"

namespace {

TEST(NeedRequesterKey, GetRequesterKey) {
  SpdmAsymPrivKey rsp_priv_key;
  SpdmAsymPubKey rsp_pub_key;
  SpdmResponderContext ctx;
  initialize_host_responder_context(&rsp_priv_key, &rsp_pub_key, &ctx,
                                    /*app_fn=*/nullptr);

  SpdmAsymPrivKey req_priv_key;
  SpdmAsymPubKey req_pub_key;
  ASSERT_EQ(0, spdm_generate_asym_keypair(SPDM_ASYM_ECDSA_ECC_NIST_P256,
                                          &req_priv_key, &req_pub_key));

  SpdmDhePrivKey req_key_ex_priv_key;
  SpdmDhePubKey req_key_ex_pub_key;
  ASSERT_EQ(0,
            spdm_gen_dhe_keypair(get_mbedtls_crypto_spec(), SPDM_DHE_SECP521R1,
                                 &req_key_ex_priv_key, &req_key_ex_pub_key));

  uint8_t req_session_id[2];
  ASSERT_EQ(0, spdm_get_random(&ctx.crypto_spec, req_session_id,
                               sizeof(req_session_id)));

  std::vector<uint8_t> get_version_msg = MakeGetVersion();
  std::vector<uint8_t> get_caps_msg = MakeGetCapabilities();
  std::vector<uint8_t> negotiate_algs_msg = MakeNegotiateAlgorithms();
  std::vector<uint8_t> key_exchange_msg =
      MakeKeyExchange(req_session_id, req_key_ex_pub_key);
  std::vector<uint8_t> give_pub_key_msg = MakeGivePubKey(req_pub_key);

  ASSERT_EQ(0, DispatchRequest(&ctx, get_version_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, get_caps_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, negotiate_algs_msg));
  ASSERT_EQ(0, DispatchRequest(&ctx, key_exchange_msg));

  std::vector<uint8_t> rsp;
  ASSERT_EQ(0, DispatchSecureRequest(&ctx, SPDM_HANDSHAKE_PHASE,
                                     give_pub_key_msg, &rsp));

  buffer output_msg = MakeBuffer(rsp);

  uint16_t standard_id;
  buffer vendor_id;
  buffer payload;

  ASSERT_EQ(0, SpdmCheckVendorDefinedResponse(
                   &output_msg, /*rest=*/nullptr, &standard_id, &vendor_id.data,
                   &vendor_id.size, &payload.data, &payload.size));

  EXPECT_EQ(standard_id, DMTF_STANDARD_ID);
  EXPECT_EQ(vendor_id.size, 0);
  EXPECT_EQ(payload.size, sizeof(SPDM_VendorDefinedPubKeyMsg));

  auto* pub_key_rsp =
      reinterpret_cast<const SPDM_VendorDefinedPubKeyMsg*>(payload.data);

  // TODO(jeffandersen): endianness
  ASSERT_EQ(pub_key_rsp->vd_id, DMTF_VD_ID);
  ASSERT_EQ(pub_key_rsp->vd_req_rsp, DMTF_VD_GIVE_PUBKEY_CODE);

  ASSERT_EQ(ctx.session.params.info.peer_pub_key.alg, req_pub_key.alg);

  ASSERT_EQ(0,
            memcmp(ctx.session.params.info.peer_pub_key.data, req_pub_key.data,
                   ctx.session.params.info.peer_pub_key.size));
  ASSERT_EQ(ctx.state, STATE_MUTUAL_AUTH_WAITING_FOR_FINISH);
}

}  // namespace
