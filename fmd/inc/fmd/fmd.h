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

typedef uint16_t fmd_hash_type;
#define FMD_HASH_NULL     (fmd_hash_type)0
#define FMD_HASH_SHA1     (fmd_hash_type)1
#define FMD_HASH_SHA256   (fmd_hash_type)2
#define FMD_HASH_SHA384   (fmd_hash_type)3
#define FMD_HASH_SHA512   (fmd_hash_type)4
#define FMD_HASH_SM3_256  (fmd_hash_type)5

typedef uint16_t fmd_signature_alg;
#define FMD_SIGNATURE_RSA   (fmd_signature_alg)0
#define FMD_SIGNATURE_ECDSA (fmd_signature_alg)1

typedef uint16_t fmd_tlv_tag;
#define FMD_HEADER_TAG            (fmd_tlv_tag)0
#define FMD_REGION_INFO_TAG       (fmd_tlv_tag)1
#define FMD_REGION_TAG            (fmd_tlv_tag)2
#define FMD_PAYLOAD_INFO_TAG      (fmd_tlv_tag)3
#define FMD_SIGNATURE_TAG         (fmd_tlv_tag)4

typedef uint16_t fmd_tlv_version;
#define FMD_HEADER_VERSION          (fmd_tlv_version)1
#define FMD_REGION_INFO_VERSION     (fmd_tlv_version)1
#define FMD_REGION_VERSION          (fmd_tlv_version)1
#define FMD_PAYLOAD_INFO_VERSION    (fmd_tlv_version)1
#define FMD_SIGNATURE_VERSION       (fmd_tlv_version)1

typedef uint16_t fmd_region_group_type;
#define FMD_REGION_GROUP_MEASURE  (fmd_region_group_type)0
#define FMD_REGION_GROUP_UPDATE   (fmd_region_group_type)1
#define FMD_REGION_GROUP_VERIFY   (fmd_region_group_type)2

typedef uint16_t fmd_region_type;
#define FMD_REGION_TYPE_MIGRATE   (fmd_region_type)0
#define FMD_REGION_TYPE_STATIC    (fmd_region_type)1

typedef uint16_t fmd_ecc_curve;
#define FMD_ECC_CURVE_P256 (fmd_ecc_curve)0

#define FMD_MAGIC 0xAABBCCDD
#define FMD_RSA_MAX_KEY_BYTES 512 // Supports up to RSA4096
#define FMD_ECC_MAX_KEY_BYTES 32 // Supports ECC keys up to 256 bits

#define FMD_SHA1_DIGEST_SIZE 20
#define FMD_SHA256_DIGEST_SIZE 32
#define FMD_SHA384_DIGEST_SIZE 48
#define FMD_SHA512_DIGEST_SIZE 64
#define FMD_SM3_256_DIGEST_SIZE 32

// =====================
// FMD helper unions
// =====================
union fmdu_hash_bytes {
    uint8_t sha1[FMD_SHA1_DIGEST_SIZE];
    uint8_t sha256[FMD_SHA256_DIGEST_SIZE];
    uint8_t sha384[FMD_SHA384_DIGEST_SIZE];
    uint8_t sha512[FMD_SHA512_DIGEST_SIZE];
    uint8_t sm3_256[FMD_SM3_256_DIGEST_SIZE];
};

// Signature forward declarations
struct fmd_rsa_signature;
struct fmd_ecdsa_signature;

union fmdu_signature {
    struct fmd_rsa_signature rsa;
    struct fmd_ecdsa_signature ecdsa;
};

// =====================
// FMD helper structures
// =====================

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

  uint16_t reserved_0;
};
_Static_assert(sizeof(struct tlv_header) == 8);

struct fmd_rsa_signature {
  /* Length of the RSA public key modulus used to verify this signature. */
  uint16_t key_len;

  /* Type of padding used when computing this RSA signature. */
  uint16_t padding_type;

  uint8_t pubkey[FMD_RSA_MAX_KEY_BYTES];

  /* An RSA signature over this FMD, with length key_len. */
  uint8_t signature[FMD_RSA_MAX_KEY_BYTES];
};
_Static_assert(sizeof(struct fmd_rsa_signature) == 1028);

struct fmd_ecdsa_signature {
  /* The ECC curve used to compute this signature. */
  fmd_ecc_curve curve;

  uint16_t reserved_0;

  uint8_t pubkey_x[FMD_ECC_MAX_KEY_BYTES];

  uint8_t pubkey_y[FMD_ECC_MAX_KEY_BYTES];

  /* The r component of this ECDSA signature. */
  uint8_t signature_r[FMD_ECC_MAX_KEY_BYTES];

  /* The s component of this ECDSA signature. */
  uint8_t signature_s[FMD_ECC_MAX_KEY_BYTES];
};
_Static_assert(sizeof(struct fmd_ecdsa_signature) == 132);

struct fmd_hash {
  fmd_hash_type hash_type;

  uint16_t reserved_0;

  union fmdu_hash_bytes bytes;
};
_Static_assert(sizeof(struct fmd_hash) == 68);

// =====================
// FMD TLV sections
// =====================

/**
 * Metadata for a group of regions. `region_count` regions must immedieately
 * follow this structure.
 *
 * Only one `fmd_region_info` for each `group_type` may be present in an FMD.
 */
struct fmd_region_group {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  /* Number of regions following this info structure */
  uint32_t region_count;

  /* Type of region group this structure defines. Only one of each group_type
   * may be present in an FMD
   */
  fmd_region_group_type group_type;

  /* Hash algorithm to use for hashing the `fmd_region`s following this
   * stucture */
  fmd_hash_type hash_type;

  /* The expected result of hashing all the regions in this region group
   * using the algorithm `hash_type`. `expected_hash.hash_type` must be
   * the same as the above `hash_type` field or FMD_HASH_NULL.
   */
  struct fmd_hash expected_hash;
};
_Static_assert(sizeof(struct fmd_region_info) == 20);

/**
 * A region of firmware described by this FMD.
 */
struct fmd_region {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  /* Type of region this structure describes. Note that when hashing regions,
   * regions with type FMD_REGION_TYPE_MIGRATE will not be hashed.
   */
  fmd_region_type region_type;

  /* Unused field for alignment */
  uint16_t _reserved0;

  /* null-terminated ASCII string. Included for diagnostic reasons. */
  uint8_t region_name[32];

  /* Offset in image where this region resides. */
  uint32_t region_offset;

  /* Size, in bytes, of this region */
  uint32_t region_size;
};
_Static_assert(sizeof(struct fmd_region) == 52);

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
 * Metadata about the payload described by this FMD.
 */
struct fmd_payload_info {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  /* Image secure version number. This should be incremented when a
   * security-relevant change is make to the image.
   */
  uint32_t image_svn;

  /* Minimum SVN allowed for future updates. Once this update has been applied,
   * all future updates must have an image_svn <= this field.
   */
  uint32_t minimum_svn;

  /* 16-byte version field. It is up to the payload writer if the image_version
   * bytes hold any significance. This is included primarily for diagnostic
   * reasons and is not intended to be consumed by roots of trust.
   */
  uint32_t image_version[4];

  /* Null-terminated ASCII string containing human readable name of this
   * image. This is included primarily for diagnostic reasons and is not
   * intended to be consumed by roots of trust.
   */
  uint8_t image_name[32];
};
_Static_assert(sizeof(struct fmd_payload_info) == 60);

/**
 * An RSA signature over all the structures in a given FMD with
 * tlv.verified != 0. This structure must set tlv.verified equal to 0.
 */
struct fmd_signature {
  /* TLV header for this TLV section */
  struct tlv_header tlv;

  fmd_signature_alg algorithm;

  uint16_t reserved_0;

  union fmdu_signature signature;
};
_Static_assert(sizeof(struct fmd_rsa_signature) == 530);

#endif // __FMD_H
