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

#include <stdbool.h>
#include <string.h>

#include "spdm_lite/common/algorithms.h"
#include "spdm_lite/common/error.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/transcript.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/responder/responder.h"

static int write_algorithms(const SpdmSupportedAlgs* negotiated_algs,
                            byte_writer* output, bool support_opaque_data_fmt_1,
                            bool support_spdm_key_schedule, buffer* written) {
  SPDM_ALGORITHMS algs_msg = {};
  SPDM_AlgStruct_DHE dhe_msg;
  SPDM_AlgStruct_AEAD aead_msg;
  SPDM_AlgStruct_BaseAsym asym_msg;
  SPDM_AlgStruct_KeySchedule keyschedule_msg;
  uint8_t* output_ptr;

  algs_msg.preamble.version = SPDM_THIS_VER;
  algs_msg.preamble.request_response_code = SPDM_CODE_ALGORITHMS;
  algs_msg.param_1_alg_struct_count = 4;
  algs_msg.length = sizeof(algs_msg) + sizeof(dhe_msg) + sizeof(aead_msg) +
                    sizeof(asym_msg) + sizeof(keyschedule_msg);

  if (support_opaque_data_fmt_1) {
    algs_msg.other_params_opaque_data_fmt_1 = 1;
  }

  spdm_write_algs(negotiated_algs, /*is_resp=*/true, support_spdm_key_schedule,
                  &algs_msg.asym_hash_algs, &dhe_msg, &aead_msg, &asym_msg,
                  &keyschedule_msg);

  output_ptr = reserve_from_writer(output, algs_msg.length);
  if (output_ptr == NULL) {
    return -1;
  }

  written->data = output_ptr;
  written->size = algs_msg.length;

  memcpy(output_ptr, &algs_msg, sizeof(algs_msg));
  output_ptr += sizeof(algs_msg);

  memcpy(output_ptr, &dhe_msg, sizeof(dhe_msg));
  output_ptr += sizeof(dhe_msg);

  memcpy(output_ptr, &aead_msg, sizeof(aead_msg));
  output_ptr += sizeof(aead_msg);

  memcpy(output_ptr, &asym_msg, sizeof(asym_msg));
  output_ptr += sizeof(asym_msg);

  memcpy(output_ptr, &keyschedule_msg, sizeof(keyschedule_msg));
  output_ptr += sizeof(keyschedule_msg);

  return 0;
}

int spdm_dispatch_request_waiting_for_negotiate_algorithms(
    SpdmResponderContext* ctx, uint8_t code, buffer input,
    byte_writer* output) {
  int rc;
  SPDM_NEGOTIATE_ALGORITHMS msg;
  const uint8_t* ext_asym_algs;
  uint32_t ext_asym_count;
  const uint8_t* ext_hash_algs;
  uint32_t ext_hash_algs_count;
  buffer alg_structs;
  uint32_t alg_structs_count;
  SpdmSupportedAlgs my_algs;
  SpdmSupportedAlgs their_algs;
  SpdmSupportedAlgs common_algs;
  bool support_opaque_data_fmt_1;
  bool support_spdm_key_schedule;
  buffer written;

  if (ctx->state != STATE_WAITING_FOR_NEGOTIATE_ALGORITHMS) {
    return -1;
  }

  if (code != SPDM_CODE_NEGOTIATE_ALGORITHMS) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  rc = SpdmCheckNegotiateAlgorithms(&input, /*rest=*/NULL, &ext_asym_algs,
                                    &ext_asym_count, &ext_hash_algs,
                                    &ext_hash_algs_count, &alg_structs.data,
                                    &alg_structs_count, &alg_structs.size);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  memcpy(&msg, input.data, sizeof(msg));

  support_opaque_data_fmt_1 = (msg.other_params_opaque_data_fmt_1 == 1);

  spdm_get_my_supported_algs(&ctx->crypto_spec, &ctx->responder_pub_key,
                             &my_algs);
  rc = spdm_get_their_supported_algs(
      &msg.asym_hash_algs, alg_structs, alg_structs_count,
      /*is_resp=*/false, &their_algs, &support_spdm_key_schedule);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  spdm_get_negotiated_algs(&my_algs, &their_algs, &common_algs,
                           &ctx->negotiated_algs);

  rc = spdm_append_to_transcript(&ctx->negotiation_transcript, input.data,
                                 input.size);
  if (rc != 0) {
    return rc;
  }

  rc = write_algorithms(&common_algs, output, support_opaque_data_fmt_1,
                        support_spdm_key_schedule, &written);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_UNSPECIFIED, output);
  }

  rc = spdm_append_to_transcript(&ctx->negotiation_transcript, written.data,
                                 written.size);
  if (rc != 0) {
    return rc;
  }

  ctx->state = STATE_WAITING_FOR_KEY_EXCHANGE;

  return 0;
}
