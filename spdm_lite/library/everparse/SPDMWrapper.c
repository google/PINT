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

#include "spdm_lite/everparse/SPDMWrapper.h"

#include "EverParse.h"
#include "SPDM.h"
#include "spdm_lite/common/defs.h"

static void ErrorHandler(const char* typename_s, const char* fieldname,
                         const char* reason, uint8_t* context,
                         EverParseInputBuffer input, uint64_t start_pos) {}

// Note: invocations with args require a trailing comma for reasons.
#define SPDM_CHECK_BODY(func, ...)                                             \
  do {                                                                         \
    uint64_t res = func(__VA_ARGS__ NULL, ErrorHandler, (uint8_t*)input->data, \
                        input->size, 0);                                       \
                                                                               \
    if (EverParseIsError(res)) {                                               \
      return -1;                                                               \
    }                                                                          \
                                                                               \
    if (rest != NULL) {                                                        \
      rest->data = input->data + res;                                          \
      rest->size = input->size - res;                                          \
      input->size = res;                                                       \
    } else if (res != input->size) {                                           \
      return -1;                                                               \
    }                                                                          \
                                                                               \
    return 0;                                                                  \
  } while (0)

int SpdmCheckGetVersion(buffer* input, buffer* rest) {
  SPDM_CHECK_BODY(SpdmValidateGetVersion);
}

int SpdmCheckVersion(buffer* input, buffer* rest, uint8_t* entry_count,
                     const uint8_t** entries) {
  SPDM_CHECK_BODY(SpdmValidateVersion, entry_count, (uint8_t**)entries, );
}

int SpdmCheckGetCapabilities(buffer* input, buffer* rest) {
  SPDM_CHECK_BODY(SpdmValidateGetCapabilities);
}

int SpdmCheckCapabilities(buffer* input, buffer* rest) {
  SPDM_CHECK_BODY(SpdmValidateCapabilities);
}

int SpdmCheckNegotiateAlgorithms(
    buffer* input, buffer* rest, const uint8_t** ext_asym_algs,
    uint32_t* ext_asym_algs_count, const uint8_t** ext_hash_algs,
    uint32_t* ext_hash_algs_count, const uint8_t** alg_structs,
    uint32_t* alg_structs_count, uint32_t* alg_structs_len) {
  SPDM_CHECK_BODY(SpdmValidateNegotiateAlgorithms, (uint8_t**)ext_asym_algs,
                  ext_asym_algs_count, (uint8_t**)ext_hash_algs,
                  ext_hash_algs_count, (uint8_t**)alg_structs,
                  alg_structs_count, alg_structs_len, );
}

int SpdmCheckAlgorithms(
    buffer* input, buffer* rest, const uint8_t** ext_asym_algs,
    uint32_t* ext_asym_algs_count, const uint8_t** ext_hash_algs,
    uint32_t* ext_hash_algs_count, const uint8_t** alg_structs,
    uint32_t* alg_structs_count, uint32_t* alg_structs_len) {
  SPDM_CHECK_BODY(SpdmValidateAlgorithms, (uint8_t**)ext_asym_algs,
                  ext_asym_algs_count, (uint8_t**)ext_hash_algs,
                  ext_hash_algs_count, (uint8_t**)alg_structs,
                  alg_structs_count, alg_structs_len, );
}

int SpdmCheckDheAlg(buffer* input, buffer* rest, bool is_resp,
                    uint32_t* alg_count_extended) {
  SPDM_CHECK_BODY(SpdmValidateDheAlg, is_resp, alg_count_extended, );
}

int SpdmCheckAeadAlg(buffer* input, buffer* rest, bool is_resp,
                     uint32_t* alg_count_extended) {
  SPDM_CHECK_BODY(SpdmValidateAeadAlg, is_resp, alg_count_extended, );
}

int SpdmCheckAsymAlg(buffer* input, buffer* rest, bool is_resp,
                     uint32_t* alg_count_extended) {
  SPDM_CHECK_BODY(SpdmValidateAsymAlg, is_resp, alg_count_extended, );
}

int SpdmCheckKeySchedule(buffer* input, buffer* rest, bool is_resp,
                         uint32_t* alg_count_extended) {
  SPDM_CHECK_BODY(SpdmValidateKeySchedule, is_resp, alg_count_extended, );
}

int SpdmCheckGetMeasurements(buffer* input, buffer* rest,
                             unsigned char* signature_requested,
                             unsigned char* raw_bitstream_requested,
                             uint8_t* operation, const uint8_t** nonce,
                             uint8_t* slot_id) {
  SPDM_CHECK_BODY(SpdmValidateGetMeasurements, signature_requested,
                  raw_bitstream_requested, operation, (uint8_t**)nonce,
                  slot_id, );
}

int SpdmCheckMeasurements(buffer* input, buffer* rest,
                          bool expect_measurement_count, bool expect_signature,
                          uint32_t signature_len, uint8_t* slot_id,
                          uint8_t* content_changed, uint32_t* number_of_blocks,
                          uint32_t* record_length, const uint8_t** record_data,
                          const uint8_t** nonce, uint16_t* opaque_data_length,
                          const uint8_t** opaque_data,
                          const uint8_t** signature) {
  SPDM_CHECK_BODY(SpdmValidateMeasurements, expect_measurement_count,
                  expect_signature, signature_len, slot_id, content_changed,
                  number_of_blocks, record_length, (uint8_t**)record_data,
                  (uint8_t**)nonce, opaque_data_length, (uint8_t**)opaque_data,
                  (uint8_t**)signature, );
}

int SpdmCheckMeasurementBlock(buffer* input, buffer* rest, uint8_t* index,
                              uint8_t* measurement_spec,
                              uint16_t* measurement_size,
                              const uint8_t** measurement) {
  SPDM_CHECK_BODY(SpdmValidateMeasurementBlock, index, measurement_spec,
                  measurement_size, (uint8_t**)measurement, );
}

int SpdmCheckDmtfMeasurement(buffer* input, buffer* rest,
                             unsigned char* raw_bitstream, uint8_t* value_type,
                             uint16_t* value_size, const uint8_t** value) {
  SPDM_CHECK_BODY(SpdmValidateDmtfMeasurement, raw_bitstream, value_type,
                  value_size, (uint8_t**)value, );
};

static int SpdmCheckKeyExchangeInternal(
    buffer* input, buffer* rest, uint32_t exchange_data_len,
    uint8_t* requested_measurement_summary_hash, uint8_t* slot_id,
    const uint8_t** req_session_id, unsigned char* session_policy_termination,
    const uint8_t** exchange_data, const uint8_t** opaque_data,
    uint32_t* opaque_data_len) {
  SPDM_CHECK_BODY(SpdmValidateKeyExchange, exchange_data_len,
                  requested_measurement_summary_hash, slot_id,
                  (uint8_t**)req_session_id, session_policy_termination,
                  (uint8_t**)exchange_data, (uint8_t**)opaque_data,
                  opaque_data_len, );
}

int SpdmCheckKeyExchange(buffer* input, buffer* rest,
                         uint32_t exchange_data_len,
                         uint8_t* requested_measurement_summary_type,
                         uint8_t* slot_id, const uint8_t** req_session_id,
                         bool* session_policy_termination,
                         const uint8_t** exchange_data,
                         const uint8_t** opaque_data,
                         uint32_t* opaque_data_len) {
  unsigned char local_session_policy_termination;
  int rc = SpdmCheckKeyExchangeInternal(
      input, rest, exchange_data_len, requested_measurement_summary_type,
      slot_id, req_session_id, &local_session_policy_termination, exchange_data,
      opaque_data, opaque_data_len);

  *session_policy_termination = local_session_policy_termination;
  return rc;
}

int SpdmCheckKeyExchangeRspInternal(
    buffer* input, buffer* rest, uint32_t exchange_data_len, uint32_t hash_len,
    uint32_t signature_len, bool measurement_summary_hash_expected,
    bool responder_verify_data_expected, uint8_t* heartbeat_period,
    const uint8_t** rsp_session_id, uint8_t* mut_auth_requested,
    uint8_t* slot_id, const uint8_t** exchange_data,
    const uint8_t** measurement_summary_hash, const uint8_t** opaque_data,
    uint32_t* opaque_data_len, const uint8_t** signature,
    const uint8_t** responder_verify_data) {
  SPDM_CHECK_BODY(SpdmValidateKeyExchangeRsp, exchange_data_len, hash_len,
                  signature_len, measurement_summary_hash_expected,
                  responder_verify_data_expected, heartbeat_period,
                  (uint8_t**)rsp_session_id, mut_auth_requested, slot_id,
                  (uint8_t**)exchange_data, (uint8_t**)measurement_summary_hash,
                  (uint8_t**)opaque_data, opaque_data_len, (uint8_t**)signature,
                  (uint8_t**)responder_verify_data, );
}

int SpdmCheckKeyExchangeRsp(
    buffer* input, buffer* rest, uint32_t exchange_data_len, uint32_t hash_len,
    uint32_t signature_len, bool measurement_summary_hash_expected,
    bool responder_verify_data_expected, uint8_t* heartbeat_period,
    const uint8_t** rsp_session_id, MutAuthRequestedFlag* mut_auth_requested,
    uint8_t* slot_id, const uint8_t** exchange_data,
    const uint8_t** measurement_summary_hash, const uint8_t** opaque_data,
    uint32_t* opaque_data_len, const uint8_t** signature,
    const uint8_t** responder_verify_data) {
  BUILD_ASSERT(SPDM____MUT_AUTH_FLAG_NOT_REQUESTED ==
               MUT_AUTH_FLAG_NOT_REQUESTED);
  BUILD_ASSERT(SPDM____MUT_AUTH_FLAG_NO_ENCAPSULATED_FLOW ==
               MUT_AUTH_FLAG_NO_ENCAPSULATED_FLOW);
  BUILD_ASSERT(SPDM____MUT_AUTH_FLAG_ENCAPSULATED_FLOW ==
               MUT_AUTH_FLAG_ENCAPSULATED_FLOW);
  BUILD_ASSERT(SPDM____MUT_AUTH_FLAG_OPTIMIZED_FLOW ==
               MUT_AUTH_FLAG_OPTIMIZED_FLOW);

  uint8_t local_mut_auth_requested;
  int rc = SpdmCheckKeyExchangeRspInternal(
      input, rest, exchange_data_len, hash_len, signature_len,
      measurement_summary_hash_expected, responder_verify_data_expected,
      heartbeat_period, rsp_session_id, &local_mut_auth_requested, slot_id,
      exchange_data, measurement_summary_hash, opaque_data, opaque_data_len,
      signature, responder_verify_data);
  *mut_auth_requested = local_mut_auth_requested;
  return rc;
}

int SpdmCheckVendorDefinedRequest(buffer* input, buffer* rest,
                                  uint16_t* out_standard_id,
                                  const uint8_t** out_vendor_id,
                                  uint32_t* out_vendor_id_len,
                                  const uint8_t** out_payload,
                                  uint32_t* out_payload_len) {
  SPDM_CHECK_BODY(SpdmValidateVendorDefinedRequest, out_standard_id,
                  (uint8_t**)out_vendor_id, out_vendor_id_len,
                  (uint8_t**)out_payload, out_payload_len, );
}

int SpdmCheckVendorDefinedResponse(buffer* input, buffer* rest,
                                   uint16_t* out_standard_id,
                                   const uint8_t** out_vendor_id,
                                   uint32_t* out_vendor_id_len,
                                   const uint8_t** out_payload,
                                   uint32_t* out_payload_len) {
  SPDM_CHECK_BODY(SpdmValidateVendorDefinedResponse, out_standard_id,
                  (uint8_t**)out_vendor_id, out_vendor_id_len,
                  (uint8_t**)out_payload, out_payload_len, );
}

int SpdmCheckOpaqueElement(buffer* input, buffer* rest, uint8_t* id,
                           const uint8_t** vendor_id, uint32_t* vendor_id_len,
                           const uint8_t** opaque_element_data,
                           uint32_t* opaque_element_data_len) {
  SPDM_CHECK_BODY(SpdmValidateOpaqueElement, id, (uint8_t**)vendor_id,
                  vendor_id_len, (uint8_t**)opaque_element_data,
                  opaque_element_data_len, );
}

static int SpdmCheckEndSessionInternal(
    buffer* input, buffer* rest, unsigned char* preserve_negotiated_state) {
  SPDM_CHECK_BODY(SpdmValidateEndSession, preserve_negotiated_state, );
}

int SpdmCheckEndSession(buffer* input, buffer* rest,
                        bool* preserve_negotiated_state) {
  unsigned char local_preserve_negotiated_state;
  int rc = SpdmCheckEndSessionInternal(input, rest,
                                       &local_preserve_negotiated_state);
  *preserve_negotiated_state = local_preserve_negotiated_state;

  return rc;
}

int SpdmCheckEndSessionAck(buffer* input, buffer* rest) {
  SPDM_CHECK_BODY(SpdmValidateEndSessionAck);
}

static int SpdmCheckFinishInternal(buffer* input, buffer* rest,
                                   uint32_t hash_len, uint32_t sig_len,
                                   unsigned char* sig_included,
                                   uint8_t* slot_id, const uint8_t** sig,
                                   const uint8_t** verify_data) {
  SPDM_CHECK_BODY(SpdmValidateFinish, hash_len, sig_len, sig_included, slot_id,
                  (uint8_t**)sig, (uint8_t**)verify_data, );
}

int SpdmCheckFinish(buffer* input, buffer* rest, uint32_t hash_len,
                    uint32_t sig_len, bool* sig_included, uint8_t* slot_id,
                    const uint8_t** sig, const uint8_t** verify_data) {
  unsigned char local_sig_included;
  int rc =
      SpdmCheckFinishInternal(input, rest, hash_len, sig_len,
                              &local_sig_included, slot_id, sig, verify_data);
  *sig_included = local_sig_included;
  return rc;
}

int SpdmCheckFinishRsp(buffer* input, buffer* rest, uint32_t hash_len,
                       bool responder_verify_data_expected,
                       const uint8_t** responder_verify_data) {
  SPDM_CHECK_BODY(SpdmValidateFinishRsp, hash_len,
                  responder_verify_data_expected,
                  (uint8_t**)responder_verify_data, );
}

int SpdmCheckError(buffer* input, buffer* rest, uint8_t* code, uint8_t* data) {
  SPDM_CHECK_BODY(SpdmValidateError, code, data, );
}

int SpdmCheckSecuredMessageRecord(buffer* input, buffer* rest,
                                  uint32_t seq_num_len, uint32_t mac_len,
                                  uint32_t* session_id, const uint8_t** seq_num,
                                  const uint8_t** ciphertext,
                                  uint32_t* ciphertext_len,
                                  const uint8_t** mac) {
  SPDM_CHECK_BODY(SpdmValidateSecuredMessageRecord, seq_num_len, mac_len,
                  session_id, (uint8_t**)seq_num, (uint8_t**)ciphertext,
                  ciphertext_len, (uint8_t**)mac, );
}
