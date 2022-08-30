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

#include "mbedtls_helpers.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "spdm_lite/common/crypto_types.h"

uint16_t get_coord_size(mbedtls_ecp_group_id group_id) {
  uint16_t bit_size = mbedtls_ecp_curve_info_from_grp_id(group_id)->bit_size;
  return (bit_size / 8) + ((bit_size % 8) != 0);
}

void make_blinding_drbg(mbedtls_ctr_drbg_context* ctr_drbg) {
  mbedtls_entropy_context entropy;

  mbedtls_ctr_drbg_init(ctr_drbg);
  mbedtls_entropy_init(&entropy);

  const char context[] = "spdm_lite";
  mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, &entropy, context,
                        sizeof(context));

  mbedtls_entropy_free(&entropy);
}

mbedtls_ecp_group_id get_asym_group_id(SpdmAsymAlgorithm alg) {
  switch (alg) {
    case SPDM_ASYM_ECDSA_ECC_NIST_P256:
      return MBEDTLS_ECP_DP_SECP256R1;
    case SPDM_ASYM_ECDSA_ECC_NIST_P384:
      return MBEDTLS_ECP_DP_SECP384R1;
    case SPDM_ASYM_ECDSA_ECC_NIST_P521:
      return MBEDTLS_ECP_DP_SECP521R1;
    case SPDM_ASYM_UNSUPPORTED:
    default:
      return MBEDTLS_ECP_DP_NONE;
  }
}

int generate_keypair(mbedtls_ecp_group_id group_id, uint8_t* pub_key_data,
                     uint8_t* priv_key_data) {
  mbedtls_ecp_group g;
  mbedtls_ecp_group_init(&g);

  mbedtls_mpi d;
  mbedtls_mpi_init(&d);

  mbedtls_ecp_point p;
  mbedtls_ecp_point_init(&p);

  mbedtls_ctr_drbg_context ctr_drbg;
  make_blinding_drbg(&ctr_drbg);

  uint16_t coord_size = get_coord_size(group_id);

  int rc = mbedtls_ecp_group_load(&g, group_id);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecp_gen_keypair(&g, &d, &p, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_write_binary(&d, priv_key_data, coord_size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_write_binary(&p.X, pub_key_data, coord_size);
  if (rc != 0) {
    return rc;
  }

  rc = mbedtls_mpi_write_binary(&p.Y, pub_key_data + coord_size, coord_size);
  if (rc != 0) {
    return rc;
  }

cleanup:
  mbedtls_ecp_group_free(&g);
  mbedtls_ecp_point_free(&p);
  mbedtls_mpi_free(&d);
  mbedtls_ctr_drbg_free(&ctr_drbg);

  return rc;
}
