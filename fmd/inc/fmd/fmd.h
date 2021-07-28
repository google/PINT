/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __FMD_H
#define __FMD_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/**
 *  ---------------------------------- Layout ----------------------------------
 *  |                             struct fmd_header                            |
 *  ----------------------------------------------------------------------------
 *  |                         struct fmd_region_info                           |
 *  ----------------------------------------------------------------------------
 *  |                 struct fmd_region[fmd_region_info.region_count]          |
 *  ----------------------------------------------------------------------------
 */

typedef uint16_t fmd_hash;
#define FMD_HASH_SHA1     (fmd_hash)0
#define FMD_HASH_SHA256   (fmd_hash)1

typedef uint16_t fmd_tlv_tag;
#define FMD_HEADER_TAG        (fmd_tlv_tag)0
#define FMD_REGION_INFO_TAG   (fmd_tlv_tag)1
#define FMD_REGION_TAG        (fmd_tlv_tag)2

typedef uint16_t fmd_tlv_version;
#define FMD_REGION_INFO_VERSION   (fmd_tlv_version)1
#define FMD_REGION_VERSION        (fmd_tlv_version)1
#define FMD_HEADER_VERSION        (fmd_tlv_version)1

typedef uint16_t fmd_region_group_type;
#define FMD_REGION_GROUP_MEASURE  (fmd_region_group_type)0
#define FMD_REGION_GROUP_UPDATE   (fmd_region_group_type)1
#define FMD_REGION_GROUP_VERIFY   (fmd_region_group_type)2

typedef uint16_t fmd_ecc_curve;
#define FMD_ECC_CURVE_P256 (fmd_ecc_curve)0

#define FMD_MAGIC 0xAABBCCDD
#define FMD_RSA_MAX_KEY_BYTES 512
#define FMD_ECC_MAX_KEY_BYTES 32

/**
 * The header structure of every TLV. To simplify parsing, every FMD section
 * must start with this structure at offset 0
 */
struct tlv_header {
  /* Tag for the TLV section described by this tlv_header */
  fmd_tlv_tag tag;

  /* Length of the TLV section described by this tlv_header, including this
   * tlv_header */
  uint16_t length;

  /* version of the struct in which this header is embedded. */
  fmd_tlv_version version;

  /* If this field is non-zero, this TLV section is covered by the descriptor
   * signature */
  uint8_t verify;

  uint8_t reserved_0;
};
_Static_assert(sizeof(struct tlv_header) == 8);

/**
 * Metadata for a group of regions. `region_count` regions must immedieately
 * follow this structure.
 */
struct fmd_region_info {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  /* Number of regions following this info structure */
  uint16_t region_count;

  /* Type of region group this structure defines. */
  fmd_region_group_type group_type;

  /* Hash algorithm to use for hashing the `fmd_region`s following this
   * stucture */
  uint32_t hash_type;
};
_Static_assert(sizeof(struct fmd_region_info) == 16);

/**
 * A region of firmware described by this FMD.
 */
struct fmd_region {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  uint8_t region_name[32];  /* null-terminated ASCII string */

  uint32_t region_offset;

  uint32_t region_size;
};
_Static_assert(sizeof(struct fmd_region) == 48);

/**
 * Metadata about this FMD. This strcuture must be the first structure in the
 * FMD at offset 0.
 */
struct fmd_header {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  /* Magic number denoting this is an FMD. Must be FMD_MAGIC */
  uint32_t magic;

  /* The offset is relative to the start of the image data. */
  uint32_t descriptor_offset;

  /* Includes this struct as well as the auxiliary structs. This many bytes
   * will be skipped when computing the hash of the region this struct
   * resides in. Tail padding is allowed but must be all 0xff's.
   */
  uint32_t descriptor_area_size;
};
_Static_assert(sizeof(struct fmd_header) == 20);

/**
 * An RSA signature over all the structures in a given FMD with
 * tlv.verified != 0. This structure must set tlv.verified equal to 0.
 */
struct fmd_rsa_signature {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  /* Length of the RSA public key modulus used to verify this signature. */
  uint16_t key_len;

  /* Type of padding used when computing this RSA signature. */
  uint16_t padding_type;

  /* An RSA signature over this FMD, with length key_len. */
  uint8_t signature[FMD_RSA_MAX_KEY_BYTES];
};
_Static_assert(sizeof(struct fmd_rsa_signature) == 524);

/**
 * An ECDSA signature over all the structures in a given FMD with
 * tlv.verified != 0; This structure must set tlv.verified equal to 0.
 */
struct fmd_ecdsa_signature {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  /* The ECC curve used to compute this signature. */
  fmd_ecc_curve curve;

  /* The r component of this ECDSA signature. */
  uint8_t signature_r[FMD_ECC_MAX_KEY_BYTES];

  /* The s component of this ECDSA signature. */
  uint8_t signature_s[FMD_ECC_MAX_KEY_BYTES];
};
_Static_assert(sizeof(struct fmd_ecdsa_signature) == 74);

#endif // __FMD_H
