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

#include "spdm_lite/crypto_impl/tpmt_public_serialize.h"

#include <string.h>

#include "spdm_lite/common/crypto_types.h"
#include "tss2/tss2_mu.h"
#include "tss2/tss2_tpm2_types.h"

static TPMI_ALG_HASH get_hash_alg(SpdmHashAlgorithm alg) {
  switch (alg) {
    case SPDM_HASH_SHA256:
      return TPM2_ALG_SHA256;
    case SPDM_HASH_SHA384:
      return TPM2_ALG_SHA384;
    case SPDM_HASH_SHA512:
      return TPM2_ALG_SHA512;
    default:
      return TPM2_ALG_NULL;
  }
}

static TPMI_ECC_CURVE get_curve_id(SpdmAsymAlgorithm alg) {
  switch (alg) {
    case SPDM_ASYM_ECDSA_ECC_NIST_P256:
      return TPM2_ECC_NIST_P256;
    case SPDM_ASYM_ECDSA_ECC_NIST_P384:
      return TPM2_ECC_NIST_P384;
    case SPDM_ASYM_ECDSA_ECC_NIST_P521:
      return TPM2_ECC_NIST_P521;
    default:
      return TPM2_ECC_NONE;
  }
}

static uint16_t get_coord_size(TPMI_ECC_CURVE curve_id) {
  switch (curve_id) {
    case TPM2_ECC_NIST_P256:
      return P256_COORD_SIZE;
    case TPM2_ECC_NIST_P384:
      return P384_COORD_SIZE;
    case TPM2_ECC_NIST_P521:
      return P521_COORD_SIZE;
    default:
      return 0;
  }
}

int spdm_serialize_asym_pub_to_tpmt_public(SpdmAsymAlgorithm asym_alg,
                                           SpdmHashAlgorithm hash_alg,
                                           const uint8_t* in, uint16_t in_size,
                                           uint8_t* out, uint16_t* out_size) {
  TPMT_PUBLIC tpmt_public = {
      .type = TPM2_ALG_ECC,
      .nameAlg = TPM2_ALG_NULL,
      .objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT,
      .parameters =
          {
              .eccDetail =
                  {
                      .symmetric = {.algorithm = TPM2_ALG_NULL},
                      .scheme = {.scheme = TPM2_ALG_ECDSA,
                                 .details = {.ecdsa = {.hashAlg = get_hash_alg(
                                                           hash_alg)}}},
                      .curveID = get_curve_id(asym_alg),
                      .kdf = {.scheme = TPM2_ALG_NULL},
                  },
          },
  };

  TPMS_ECC_POINT* ecc = &tpmt_public.unique.ecc;
  uint16_t coord_size =
      get_coord_size(tpmt_public.parameters.eccDetail.curveID);

  memcpy(ecc->x.buffer, in, coord_size);
  memcpy(ecc->y.buffer, in + coord_size, coord_size);

  ecc->x.size = coord_size;
  ecc->y.size = coord_size;

  size_t offset = 0;

  TSS2_RC tss_rc =
      Tss2_MU_TPMT_PUBLIC_Marshal(&tpmt_public, out, *out_size, &offset);
  if (tss_rc != TSS2_RC_SUCCESS) {
    return -1;
  }

  *out_size = offset;

  return 0;
}

int spdm_deserialize_asym_pub_from_tpmt_public(SpdmAsymAlgorithm asym_alg,
                                               SpdmHashAlgorithm hash_alg,
                                               const uint8_t* in,
                                               uint16_t in_size, uint8_t* out,
                                               uint16_t* out_size) {
  TPMT_PUBLIC tpmt_public;
  TSS2_RC tss_rc = Tss2_MU_TPMT_PUBLIC_Unmarshal(in, in_size,
                                                 /*offset=*/NULL, &tpmt_public);
  if (tss_rc != TSS2_RC_SUCCESS) {
    return -1;
  }

  if (tpmt_public.type != TPM2_ALG_ECC ||
      tpmt_public.nameAlg != TPM2_ALG_NULL ||
      tpmt_public.objectAttributes != TPMA_OBJECT_SIGN_ENCRYPT ||
      tpmt_public.authPolicy.size != 0) {
    return -1;
  }

  const TPMS_ECC_PARMS* params = &tpmt_public.parameters.eccDetail;

  if (params->symmetric.algorithm != TPM2_ALG_NULL ||
      params->scheme.scheme != TPM2_ALG_ECDSA ||
      params->scheme.details.ecdsa.hashAlg != get_hash_alg(hash_alg) ||
      params->kdf.scheme != TPM2_ALG_NULL) {
    return -1;
  }

  const TPMS_ECC_POINT* ecc = &tpmt_public.unique.ecc;

  if (get_curve_id(asym_alg) != params->curveID) {
    return -1;
  }

  uint16_t coord_size = get_coord_size(params->curveID);

  if (ecc->x.size != coord_size || ecc->y.size != coord_size) {
    return -1;
  }

  if (*out_size < 2 * coord_size) {
    return -1;
  }

  *out_size = 2 * coord_size;

  memcpy(out, ecc->x.buffer, coord_size);
  memcpy(out + coord_size, ecc->y.buffer, coord_size);

  return 0;
}
