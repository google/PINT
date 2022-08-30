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

#include "spdm_lite/crypto_impl/mbedtls_sign.h"

#include <string.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

#include "mbedtls_helpers.h"
#include "spdm_lite/common/crypto_types.h"

int spdm_generate_asym_keypair(SpdmAsymAlgorithm alg, SpdmAsymPrivKey* priv_key,
                               SpdmAsymPubKey* pub_key) {
  spdm_init_asym_pub_key(pub_key, alg);
  priv_key->alg = alg;

  // Detect bad alg.
  if (pub_key->size == 0) {
    return -1;
  }

  return generate_keypair(get_asym_group_id(alg), pub_key->data,
                          priv_key->data);
}

int spdm_mbedtls_sign_with_priv_key(SpdmAsymAlgorithm alg, void* priv_key_ctx,
                                    const uint8_t* input, uint32_t input_len,
                                    uint8_t* sig, uint32_t sig_len) {
  SpdmAsymPrivKey* priv_key = (SpdmAsymPrivKey*)priv_key_ctx;

  if (alg != priv_key->alg) {
    return -1;
  }

  mbedtls_ecp_group_id group_id = get_asym_group_id(alg);
  if (group_id == MBEDTLS_ECP_DP_NONE) {
    return -1;
  }

  uint16_t coord_size = get_coord_size(group_id);

  if (sig_len != spdm_get_asym_signature_size(alg)) {
    return -1;
  }

  mbedtls_ecp_group g;
  mbedtls_ecp_group_init(&g);

  mbedtls_mpi r, s, d;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&d);

  mbedtls_ctr_drbg_context ctr_drbg;
  make_blinding_drbg(&ctr_drbg);

  int rc = mbedtls_ecp_group_load(&g, group_id);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_read_binary(&d, (unsigned char*)priv_key->data, coord_size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_ecdsa_sign_det_ext(&g, &r, &s, &d, (const unsigned char*)input,
                                  input_len, MBEDTLS_MD_SHA384,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_write_binary(&r, (unsigned char*)sig, coord_size);
  if (rc != 0) {
    goto cleanup;
  }

  rc = mbedtls_mpi_write_binary(&s, (unsigned char*)(sig + coord_size),
                                coord_size);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  mbedtls_ecp_group_free(&g);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&d);
  mbedtls_ctr_drbg_free(&ctr_drbg);

  return rc;
}
