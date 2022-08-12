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

#ifndef SPDM_LITE_COMMON_MESSAGES_H_
#define SPDM_LITE_COMMON_MESSAGES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// This file contains enum and struct definitions for SPDM messages. The
// definitions follow SPDM 1.2, as defined at
// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.2.0.pdf

// Request codes
#define SPDM_CODE_GET_VERSION 0x84
#define SPDM_CODE_GET_CAPABILITIES 0xE1
#define SPDM_CODE_NEGOTIATE_ALGORITHMS 0xE3
#define SPDM_CODE_KEY_EXCHANGE 0xE4
#define SPDM_CODE_GET_ENCAPSULATED_REQUEST 0xEA
#define SPDM_CODE_DELIVER_ENCAPSULATED_RESPONSE 0xEB
#define SPDM_CODE_END_SESSION 0xEC
#define SPDM_CODE_FINISH 0xE5
#define SPDM_CODE_VENDOR_DEFINED_REQUEST 0xFE

// Response codes
#define SPDM_CODE_VERSION 0x04
#define SPDM_CODE_CAPABILITIES 0x61
#define SPDM_CODE_ALGORITHMS 0x63
#define SPDM_CODE_KEY_EXCHANGE_RSP 0x64
#define SPDM_CODE_ENCAPSULATED_REQUEST 0x6A
#define SPDM_CODE_ENCAPSULATED_RESPONSE_ACK 0x6B
#define SPDM_CODE_END_SESSION_ACK 0x6C
#define SPDM_CODE_FINISH_RSP 0x65
#define SPDM_CODE_VENDOR_DEFINED_RESPONSE 0x7E
#define SPDM_CODE_ERROR 0x7F

// Algorithm types
#define SPDM_ALG_TYPE_DHE 2
#define SPDM_ALG_TYPE_AEAD 3
#define SPDM_ALG_TYPE_ASYM 4
#define SPDM_ALG_TYPE_KEYSCHEDULE 5

#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif

typedef struct PACKED {
  uint8_t version;
  uint8_t request_response_code;
} SPDM_Preamble;

// Table 8
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_reserved;
  uint8_t param_2_reserved;
} SPDM_GET_VERSION;

// Table 10
typedef struct PACKED {
  uint16_t alpha : 4;
  uint16_t update_version : 4;
  uint16_t minor_version : 4;
  uint16_t major_version : 4;
} SPDM_VersionNumberEntry;

// Table 9
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_reserved;
  uint8_t param_2_reserved;
  uint8_t reserved;
  uint8_t version_number_entry_count;
  // SPDM_VersionNumberEntry[version_number_entry_count]
} SPDM_VERSION;

// Table 11
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_reserved;
  uint8_t param_2_reserved;
  uint8_t reserved_0;
  uint8_t ct_exponent;
  uint16_t reserved_1;
  uint32_t flags_reserved_0 : 1;
  uint32_t flags_CERT_CAP : 1;
  uint32_t flags_CHAL_CAP : 1;
  uint32_t flags_reserved_1 : 3;
  uint32_t flags_ENCRYPT_CAP : 1;
  uint32_t flags_MAC_CAP : 1;
  uint32_t flags_MUT_AUTH_CAP : 1;
  uint32_t flags_KEY_EX_CAP : 1;
  uint32_t flags_PSK_CAP : 2;
  uint32_t flags_ENCAP_CAP : 1;
  uint32_t flags_HBEAT_CAP : 1;
  uint32_t flags_KEY_UPD_CAP : 1;
  uint32_t flags_HANDSHAKE_IN_THE_CLEAR_CAP : 1;
  uint32_t flags_PUB_KEY_ID_CAP : 1;
  uint32_t flags_CHUNK_CAP : 1;
  uint32_t flags_reserved_2 : 14;
  uint32_t data_transfer_size;
  uint32_t max_spdm_message_size;
} SPDM_GET_CAPABILITIES;

// Table 12
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_reserved;
  uint8_t param_2_reserved;
  uint8_t reserved_0;
  uint8_t ct_exponent;
  uint16_t reserved_1;
  uint32_t flags_CACHE_CAP : 1;
  uint32_t flags_CERT_CAP : 1;
  uint32_t flags_CHAL_CAP : 1;
  uint32_t flags_MEAS_CAP : 2;
  uint32_t flags_MEAS_FRESH_CAP : 1;
  uint32_t flags_ENCRYPT_CAP : 1;
  uint32_t flags_MAC_CAP : 1;
  uint32_t flags_MUT_AUTH_CAP : 1;
  uint32_t flags_KEY_EX_CAP : 1;
  uint32_t flags_PSK_CAP : 2;
  uint32_t flags_ENCAP_CAP : 1;
  uint32_t flags_HBEAT_CAP : 1;
  uint32_t flags_KEY_UPD_CAP : 1;
  uint32_t flags_HANDSHAKE_IN_THE_CLEAR_CAP : 1;
  uint32_t flags_CHUNK_CAP : 1;
  uint32_t flags_ALIAS_CERT_CAP : 1;
  uint32_t flags_reserved : 13;
  uint32_t data_transfer_size;
  uint32_t max_spdm_message_size;
} SPDM_CAPABILITIES;

// Table 27
typedef struct PACKED {
  uint8_t registry_id;
  uint8_t reserved;
  uint16_t algorithm_id;
} SPDM_ExtendedAlg;

// Table 16/22
typedef struct PACKED {
  uint8_t alg_type;
  uint8_t alg_count_extended : 4;
  uint8_t alg_count_fixed_width : 4;
  // uint8_t algs_supported[alg_count_fixed_width];
  // SPDM_ExtendedAlg extended_algs[alg_count_extended];
} SPDM_AlgStruct;

// Part of tables 15 and 21
typedef struct PACKED {
  uint32_t base_asym_alg_rsa_ssa_2048 : 1;
  uint32_t base_asym_alg_rsa_pss_2048 : 1;
  uint32_t base_asym_alg_rsa_ssa_3072 : 1;
  uint32_t base_asym_alg_rsa_pss_3072 : 1;
  uint32_t base_asym_alg_ecdsa_ecc_nist_p256 : 1;
  uint32_t base_asym_alg_rsa_pss_4096 : 1;
  uint32_t base_asym_alg_rsa_ssa_4096 : 1;
  uint32_t base_asym_alg_ecdsa_ecc_nist_p384 : 1;
  uint32_t base_asym_alg_ecdsa_ecc_nist_p521 : 1;
  uint32_t base_asym_alg_sm2_ecc_sm2_p256 : 1;
  uint32_t base_asym_alg_ed25519 : 1;
  uint32_t base_asym_alg_ed448 : 1;
  uint32_t base_asym_alg_reserved : 20;
  uint32_t base_hash_algo_sha_256 : 1;
  uint32_t base_hash_algo_sha_384 : 1;
  uint32_t base_hash_algo_sha_512 : 1;
  uint32_t base_hash_algo_sha3_256 : 1;
  uint32_t base_hash_algo_sha3_384 : 1;
  uint32_t base_hash_algo_sha3_512 : 1;
  uint32_t base_hash_algo_sm3_256 : 1;
  uint32_t base_hash_algo_reserved : 25;
} SPDM_AsymHashAlgs;

// Table 15
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_alg_struct_count;
  uint8_t param_2_reserved;
  uint16_t length;
  uint8_t meas_spec_dmtf : 1;
  uint8_t meas_spec_reserved : 7;
  uint8_t other_params_opaque_data_fmt_0 : 1;
  uint8_t other_params_opaque_data_fmt_1 : 1;
  uint8_t other_params_opaque_data_fmt_reserved : 2;
  uint8_t other_params_reserved : 4;
  SPDM_AsymHashAlgs asym_hash_algs;
  uint8_t reserved_0[12];
  uint8_t ext_asym_count;
  uint8_t ext_hash_count;
  uint16_t reserved_1;
  // SPDM_ExtendedAlg ext_asym[ext_asym_count]
  // SPDM_ExtendedAlg ext_hash[ext_hash_count]
  // SPDM_AlgStruct alg_structs[param_1_alg_struct_count]
} SPDM_NEGOTIATE_ALGORITHMS;

// Table 21
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_alg_struct_count;
  uint8_t param_2_reserved;
  uint16_t length;
  uint8_t meas_spec_dmtf : 1;
  uint8_t meas_spec_reserved : 7;
  uint8_t other_params_opaque_data_fmt_0 : 1;
  uint8_t other_params_opaque_data_fmt_1 : 1;
  uint8_t other_params_opaque_data_fmt_reserved : 2;
  uint8_t other_params_reserved : 4;
  uint32_t meas_hash_alg_raw_bitstream_only : 1;
  uint32_t meas_hash_alg_sha_256 : 1;
  uint32_t meas_hash_alg_sha_384 : 1;
  uint32_t meas_hash_alg_sha_512 : 1;
  uint32_t meas_hash_alg_sha3_256 : 1;
  uint32_t meas_hash_alg_sha3_384 : 1;
  uint32_t meas_hash_alg_sha3_512 : 1;
  uint32_t meas_hash_alg_sm3_256 : 1;
  uint32_t meas_hash_alg_reserved : 24;
  SPDM_AsymHashAlgs asym_hash_algs;
  uint8_t reserved_0[12];
  uint8_t ext_asym_count;
  uint8_t ext_hash_count;
  uint16_t reserved_1;
  // SPDM_ExtendedAlg ext_asym[ext_asym_count]
  // SPDM_ExtendedAlg ext_hash[ext_hash_count]
  // SPDM_AlgStruct alg_structs[param_1_alg_struct_count]
} SPDM_ALGORITHMS;

// Table 17/23
typedef struct PACKED {
  uint8_t alg_type;
  uint8_t alg_count_extended : 4;
  uint8_t alg_count_fixed_width : 4;
  uint16_t alg_supported_ffdhe2048 : 1;
  uint16_t alg_supported_ffdhe3072 : 1;
  uint16_t alg_supported_ffdhe4096 : 1;
  uint16_t alg_supported_secp256r1 : 1;
  uint16_t alg_supported_secp384r1 : 1;
  uint16_t alg_supported_secp521r1 : 1;
  uint16_t alg_supported_sm2_p256 : 1;
  uint16_t alg_supported_reserved : 9;
  // SPDM_ExtendedAlg alg_external[ext_alg_count];
} SPDM_AlgStruct_DHE;

// Table 18/24
typedef struct PACKED {
  uint8_t alg_type;
  uint8_t alg_count_extended : 4;
  uint8_t alg_count_fixed_width : 4;
  uint16_t alg_supported_aes_128_gcm : 1;
  uint16_t alg_supported_aes_256_gcm : 1;
  uint16_t alg_supported_chacha20_poly1305 : 1;
  uint16_t alg_supported_aead_sm4_gcm : 1;
  uint16_t alg_supported_reserved : 12;
  // SPDM_ExtendedAlg alg_external[ext_alg_count];
} SPDM_AlgStruct_AEAD;

// Table 19/25
typedef struct PACKED {
  uint8_t alg_type;
  uint8_t alg_count_extended : 4;
  uint8_t alg_count_fixed_width : 4;
  uint16_t alg_supported_rsa_ssa_2048 : 1;
  uint16_t alg_supported_rsa_pss_2048 : 1;
  uint16_t alg_supported_rsa_ssa_3072 : 1;
  uint16_t alg_supported_rsa_pss_3072 : 1;
  uint16_t alg_supported_ecdsa_ecc_nist_p256 : 1;
  uint16_t alg_supported_rsa_pss_4096 : 1;
  uint16_t alg_supported_rsa_ssa_4096 : 1;
  uint16_t alg_supported_ecdsa_ecc_nist_p384 : 1;
  uint16_t alg_supported_ecdsa_ecc_nist_p521 : 1;
  uint16_t alg_supported_sm2_ecc_sm2_p256 : 1;
  uint16_t alg_supported_ed25519 : 1;
  uint16_t alg_supported_ed448 : 1;
  uint16_t alg_supported_reserved : 4;
  // SPDM_ExtendedAlg alg_external[ext_alg_count];
} SPDM_AlgStruct_BaseAsym;

// Table 20/26
typedef struct PACKED {
  uint8_t alg_type;
  uint8_t alg_count_extended : 4;
  uint8_t alg_count_fixed_width : 4;
  uint16_t alg_supported_spdm_key_schedule : 1;
  uint16_t alg_supported_reserved : 15;
  // SPDM_ExtendedAlg alg_external[ext_alg_count];
} SPDM_AlgStruct_KeySchedule;

// Table 58
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_measurement_summary_type;
  uint8_t param_2_slot_id;
  uint8_t req_session_id[2];
  uint8_t session_policy_termination : 1;
  uint8_t session_policy_reserved : 7;
  uint8_t reserved;
  uint8_t random_data[32];
  // uint8_t exchange_data[D];
  // uint16_t opaque_data_length;
  // uint8_t opaque_data[opaque_data_length];
} SPDM_KEY_EXCHANGE;

// Table 60
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_heartbeat_period;
  uint8_t param_2_reserved;
  uint8_t rsp_session_id[2];
  uint8_t mut_auth_requested_no_encapsulated_flow : 1;
  uint8_t mut_auth_requested_encapsulated_flow : 1;
  uint8_t mut_auth_requested_optimized_flow : 1;
  uint8_t mut_auth_requested_reserved : 5;
  uint8_t slot_id_param_slot_id : 4;
  uint8_t slot_id_param_reserved : 4;
  uint8_t random_data[32];
  // uint8_t exchange_data[D];
  // uint8_t measurement_summary_hash[H || 0];
  // uint16_t opaque_data_length;
  // uint8_t opaque_data[opaque_data_length];
  // uint8_t signature[SigLen];
  // uint8_t responder_verify_data[H || 0];
} SPDM_KEY_EXCHANGE_RSP;

// Table 72
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_reserved;
  uint8_t param_2_reserved;
} SPDM_GET_ENCAPSULATED_REQUEST;

// Table 73
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_request_id;
  uint8_t param_2_reserved;
  // uint8_t encapsulated_request[]
} SPDM_ENCAPSULATED_REQUEST;

// Table 74
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_request_id;
  uint8_t param_2_reserved;
  // uint8_t encapsulated_response[]
} SPDM_DELIVER_ENCAPSULATED_RESPONSE;

// Table 75
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_request_id;
  uint8_t param_2_payload_type;
  uint8_t ack_request_id;
  uint8_t reserved[3];
  // uint8_t encapsulated_request[]
} SPDM_ENCAPSULATED_RESPONSE_ACK;

// Table 76
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_negotiated_state_preservation_indicator : 1;
  uint8_t param_1_reserved : 7;
  uint8_t param_2_reserved;
} SPDM_END_SESSION;

// Table 78
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_reserved;
  uint8_t param_2_reserved;
} SPDM_END_SESSION_ACK;

// Table 61
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_sig_included : 1;
  uint8_t param_1_reserved : 7;
  uint8_t param_2_slot_id;
  // uint8_t signature[SigLen || 0]
  // uint8_t requester_verify_data[H]
} SPDM_FINISH;

// Table 62
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_reserved;
  uint8_t param_2_reserved;
  // uint8_t responder_verify_data[H || 0]
} SPDM_FINISH_RSP;

// Table 56/57
typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_reserved;
  uint8_t param_2_reserved;
  uint16_t standard_id;
  uint8_t vendor_id_len;
  // uint8_t vendor_id[vendor_id_len];
  // uint16_t req_len;
  // uint8_t req_payload[req_len];
} SPDM_VENDOR_DEFINED_REQ_RSP;

// Table 49
typedef struct PACKED {
  uint8_t rdt_exponent;
  uint8_t request_code;
  uint8_t token;
  uint8_t rdtm;
} SPDM_ResponseNotReadyExtendedError;

// Table 51
typedef struct PACKED {
  uint8_t len;
  // uint8_t vendor_id[len];
  // uint8_t opaque_error_data[];
} SPDM_VendorDefinedExtendedError;

// Table 52
typedef struct PACKED {
  uint32_t actual_size;
} SPDM_ResponseTooLargeExtendedError;

// Table 53
typedef struct PACKED {
  uint8_t handle;
} SPDM_LargeResponseExtendedError;

typedef struct PACKED {
  SPDM_Preamble preamble;
  uint8_t param_1_error_code;
  uint8_t param_2_error_data;
  // uint8_t extended_error_data[]
} SDPM_ERROR;

typedef struct PACKED {
  uint8_t total_elements;
  uint8_t padding[3];
} SPDM_OpaqueDataHeader;

typedef struct PACKED {
  uint8_t id;
  uint8_t vendor_len;
  // uint8_t vendor_id[vendor_len]
  // uint16_t opaque_element_data_len
  // uint8_t opaque_element_data[opaque_element_data_len]
  // uint8_t padding[L % 4]
} SPDM_OpaqueDataElement;

typedef struct PACKED {
  uint8_t sm_data_version;
  uint8_t sm_data_id;
  uint8_t num_versions;
  // SPDM_VersionNumberEntry versions[num_versions];
} SPDM_SecuredMessagesSupportedVersions;

typedef struct PACKED {
  uint8_t sm_data_version;
  uint8_t sm_data_id;
  SPDM_VersionNumberEntry version;
} SPDM_SecuredMessagesSelectedVersion;

typedef struct PACKED {
  uint8_t session_id[4];
  uint64_t seq_num;
  uint16_t len;
  uint16_t app_data_len;
  // uint8_t app_data[app_data_len]
  // uint8_t random_data[...]
  // uint8_t mac[mac_len]
} SPDM_SecuredMessageRecord;

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_MESSAGES_H_
