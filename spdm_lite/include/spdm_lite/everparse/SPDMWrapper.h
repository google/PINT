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

#ifndef SPDM_LITE_EVERPARSE_SPDMWRAPPER_H_
#define SPDM_LITE_EVERPARSE_SPDMWRAPPER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "spdm_lite/common/utils.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// These functions are helpful wrappers around EverParse-generated routines from
// SPDM.h. See SPDM.3d for the message definitions.
//
// Each of these functions takes `input` and `rest` buffers. On success, `input`
// is updated to point to the portion of the input buffer that contains the
// parsed message, and `rest` points to the remainder of the buffer. If `rest`
// is NULL, the function returns an error if any remaining un-parsed data is
// left in the input buffer.

int SpdmCheckGetVersion(buffer* input, buffer* rest);

int SpdmCheckVersion(buffer* input, buffer* rest, uint8_t* entry_count,
                     const uint8_t** entries);

int SpdmCheckGetCapabilities(buffer* input, buffer* rest);

int SpdmCheckCapabilities(buffer* input, buffer* rest);

int SpdmCheckNegotiateAlgorithms(
    buffer* input, buffer* rest, const uint8_t** ext_asym_algs,
    uint32_t* ext_asym_algs_count, const uint8_t** ext_hash_algs,
    uint32_t* ext_hash_algs_count, const uint8_t** alg_structs,
    uint32_t* alg_structs_count, uint32_t* alg_structs_len);

int SpdmCheckAlgorithms(buffer* input, buffer* rest,
                        const uint8_t** ext_asym_algs,
                        uint32_t* ext_asym_algs_count,
                        const uint8_t** ext_hash_algs,
                        uint32_t* ext_hash_algs_count,
                        const uint8_t** alg_structs,
                        uint32_t* alg_structs_count, uint32_t* alg_structs_len);

int SpdmCheckDheAlg(buffer* input, buffer* rest, bool is_resp,
                    uint32_t* alg_count_extended);

int SpdmCheckAeadAlg(buffer* input, buffer* rest, bool is_resp,
                     uint32_t* alg_count_extended);

int SpdmCheckAsymAlg(buffer* input, buffer* rest, bool is_resp,
                     uint32_t* alg_count_extended);

int SpdmCheckKeySchedule(buffer* input, buffer* rest, bool is_resp,
                         uint32_t* alg_count_extended);

int SpdmCheckGetMeasurements(buffer* input, buffer* rest,
                             unsigned char* signature_requested,
                             unsigned char* raw_bitstream_requested,
                             uint8_t* operation, const uint8_t** nonce,
                             uint8_t* slot_id);

int SpdmCheckMeasurements(buffer* input, buffer* rest,
                          bool expect_measurement_count, bool expect_signature,
                          uint32_t signature_len, uint8_t* slot_id,
                          uint8_t* content_changed, uint32_t* number_of_blocks,
                          uint32_t* record_length, const uint8_t** record_data,
                          const uint8_t** nonce, uint16_t* opaque_data_length,
                          const uint8_t** opaque_data,
                          const uint8_t** signature);

int SpdmCheckMeasurementBlock(buffer* input, buffer* rest, uint8_t* index,
                              uint8_t* measurement_spec,
                              uint16_t* measurement_size,
                              const uint8_t** measurement);

int SpdmCheckDmtfMeasurement(buffer* input, buffer* rest,
                             unsigned char* raw_bitstream, uint8_t* value_type,
                             uint16_t* value_size, const uint8_t** value);

int SpdmCheckKeyExchange(buffer* input, buffer* rest,
                         uint32_t exchange_data_len,
                         uint8_t* requested_measurement_summary_type,
                         uint8_t* slot_id, const uint8_t** req_session_id,
                         bool* session_policy_termination,
                         const uint8_t** exchange_data,
                         const uint8_t** opaque_data,
                         uint32_t* opaque_data_len);

int SpdmCheckKeyExchangeRsp(
    buffer* input, buffer* rest, uint32_t exchange_data_len, uint32_t hash_len,
    uint32_t signature_len, bool measurement_summary_hash_expected,
    bool responder_verify_data_expected, uint8_t* heartbeat_period,
    const uint8_t** rsp_session_id, uint8_t* mut_auth_requested_flow,
    uint8_t* slot_id, const uint8_t** exchange_data,
    const uint8_t** measurement_summary_hash, const uint8_t** opaque_data,
    uint32_t* opaque_data_len, const uint8_t** signature,
    const uint8_t** responder_verify_data);

int SpdmCheckVendorDefinedRequest(buffer* input, buffer* rest,
                                  uint16_t* standard_id,
                                  const uint8_t** vendor_id,
                                  uint32_t* vendor_id_len,
                                  const uint8_t** payload,
                                  uint32_t* payload_len);

int SpdmCheckVendorDefinedResponse(buffer* input, buffer* rest,
                                   uint16_t* standard_id,
                                   const uint8_t** vendor_id,
                                   uint32_t* vendor_id_len,
                                   const uint8_t** payload,
                                   uint32_t* payload_len);

int SpdmCheckOpaqueElement(buffer* input, buffer* rest, uint8_t* id,
                           const uint8_t** vendor_id, uint32_t* vendor_id_len,
                           const uint8_t** opaque_element_data,
                           uint32_t* opaque_element_data_len);

int SpdmCheckEndSession(buffer* input, buffer* rest,
                        bool* preserve_negotiated_state);

int SpdmCheckEndSessionAck(buffer* input, buffer* rest);

int SpdmCheckFinish(buffer* input, buffer* rest, uint32_t hash_len,
                    uint32_t sig_len, bool* sig_included, uint8_t* slot_id,
                    const uint8_t** sig, const uint8_t** verify_data);

int SpdmCheckFinishRsp(buffer* input, buffer* rest, uint32_t hash_len,
                       bool responder_verify_data_expected,
                       const uint8_t** responder_verify_data);

int SpdmCheckError(buffer* input, buffer* rest, uint8_t* code, uint8_t* data);

int SpdmCheckSecuredMessageRecord(buffer* input, buffer* rest,
                                  uint32_t seq_num_len, uint32_t mac_len,
                                  uint32_t* session_id, const uint8_t** seq_num,
                                  const uint8_t** ciphertext,
                                  uint32_t* ciphertext_len,
                                  const uint8_t** mac);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_EVERPARSE_SPDMWRAPPER_H_
