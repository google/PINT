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

#ifndef SPDM_LITE_LIBRARY_CRYPTO_IMPL_MBEDTLS_HELPERS_H_
#define SPDM_LITE_LIBRARY_CRYPTO_IMPL_MBEDTLS_HELPERS_H_

// Provides functions used to work with mbedtls keys.

#include <stdint.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"

#include "spdm_lite/common/crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Get the EC coordinate size based on the given group.
uint16_t get_coord_size(mbedtls_ecp_group_id group_id);

// Initialize a DRBG suitable for use in keygen and signing.
void make_blinding_drbg(mbedtls_ctr_drbg_context* ctr_drbg);

// Map an spdm-lite alg to an mbedtls group ID.
mbedtls_ecp_group_id get_asym_group_id(SpdmAsymAlgorithm alg);

// Generate an EC key.
int generate_keypair(mbedtls_ecp_group_id group_id, uint8_t* pub_key_data,
                     uint8_t* priv_key_data);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_LIBRARY_CRYPTO_IMPL_MBEDTLS_HELPERS_H_
