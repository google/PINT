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

#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/crypto_impl/mbedtls_sign.h"
#include "spdm_lite/crypto_impl/tpmt_public_serialize.h"
#include "tss2/tss2_mu.h"
#include "tss2/tss2_tpm2_types.h"

#include "gtest/gtest.h"

namespace {

TEST(TpmtPublicSerializeTest, Serialize) {
  SpdmAsymPrivKey priv_key;
  SpdmAsymPubKey pub_key;

  ASSERT_EQ(0, spdm_generate_asym_keypair(SPDM_ASYM_ECDSA_ECC_NIST_P256,
                                          &priv_key, &pub_key));

  std::vector<uint8_t> serialized(sizeof(TPMT_PUBLIC));
  uint16_t serialized_size = serialized.size();

  ASSERT_EQ(0, spdm_serialize_asym_pub_to_tpmt_public(
                   pub_key.alg, SPDM_HASH_SHA256, pub_key.data, pub_key.size,
                   serialized.data(), &serialized_size));

  ASSERT_LT(serialized_size, serialized.size());
  serialized.resize(serialized_size);

  TPMT_PUBLIC tpmt_public;
  ASSERT_EQ(TSS2_RC_SUCCESS,
            Tss2_MU_TPMT_PUBLIC_Unmarshal(serialized.data(), serialized.size(),
                                          /*offset=*/nullptr, &tpmt_public));

  EXPECT_EQ(tpmt_public.type, TPM2_ALG_ECC);
  EXPECT_EQ(tpmt_public.nameAlg, TPM2_ALG_NULL);
  EXPECT_EQ(tpmt_public.objectAttributes, TPMA_OBJECT_SIGN_ENCRYPT);
  EXPECT_EQ(tpmt_public.authPolicy.size, 0);

  const TPMS_ECC_PARMS* params = &tpmt_public.parameters.eccDetail;

  EXPECT_EQ(params->symmetric.algorithm, TPM2_ALG_NULL);
  EXPECT_EQ(params->scheme.scheme, TPM2_ALG_ECDSA);
  EXPECT_EQ(params->scheme.details.ecdsa.hashAlg, TPM2_ALG_SHA256);
  EXPECT_EQ(params->kdf.scheme, TPM2_ALG_NULL);
  EXPECT_EQ(params->curveID, TPM2_ECC_NIST_P256);

  const TPMS_ECC_POINT* ecc = &tpmt_public.unique.ecc;

  EXPECT_EQ(ecc->x.size, P256_COORD_SIZE);
  EXPECT_EQ(ecc->y.size, P256_COORD_SIZE);
}

TEST(TpmtPublicSerializeTest, Deserialize) {
  SpdmAsymPrivKey priv_key;
  SpdmAsymPubKey pub_key;

  ASSERT_EQ(0, spdm_generate_asym_keypair(SPDM_ASYM_ECDSA_ECC_NIST_P256,
                                          &priv_key, &pub_key));

  std::vector<uint8_t> serialized(sizeof(TPMT_PUBLIC));
  uint16_t serialized_size = serialized.size();

  ASSERT_EQ(0, spdm_serialize_asym_pub_to_tpmt_public(
                   pub_key.alg, SPDM_HASH_SHA256, pub_key.data, pub_key.size,
                   serialized.data(), &serialized_size));

  ASSERT_LT(serialized_size, serialized.size());
  serialized.resize(serialized_size);

  std::vector<uint8_t> serialized_2(sizeof(TPMT_PUBLIC));

  SpdmAsymPubKey post_pub_key;
  spdm_init_asym_pub_key(&post_pub_key, pub_key.alg);
  uint16_t post_pub_key_size = post_pub_key.size;

  // First try with the wrong hash alg.
  ASSERT_EQ(-1, spdm_deserialize_asym_pub_from_tpmt_public(
                   pub_key.alg, SPDM_HASH_SHA384, serialized.data(),
                   serialized.size(), post_pub_key.data, &post_pub_key_size));

  ASSERT_EQ(0, spdm_deserialize_asym_pub_from_tpmt_public(
                   pub_key.alg, SPDM_HASH_SHA256, serialized.data(),
                   serialized.size(), post_pub_key.data, &post_pub_key_size));

  ASSERT_EQ(post_pub_key_size, post_pub_key.size);

  ASSERT_EQ(pub_key.alg, post_pub_key.alg);
  ASSERT_EQ(pub_key.size, post_pub_key.size);

  ASSERT_EQ(0, memcmp(pub_key.data, post_pub_key.data, post_pub_key.size));
}

}  // namespace
