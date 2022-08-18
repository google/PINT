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

#include <string.h>

#include "spdm_lite/common/algorithms.h"
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/transcript.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/requester/requester.h"
#include "spdm_lite/requester/send_request.h"

static int write_negotiate_algorithms(SpdmSupportedAlgs* supported_algs,
                                      byte_writer* output) {
  SPDM_NEGOTIATE_ALGORITHMS negotiate_algs_msg = {};
  SPDM_AlgStruct_DHE dhe_msg;
  SPDM_AlgStruct_AEAD aead_msg;
  SPDM_AlgStruct_BaseAsym asym_msg;
  SPDM_AlgStruct_KeySchedule keyschedule_msg;

  const uint32_t msg_len = sizeof(negotiate_algs_msg) + sizeof(dhe_msg) +
                           sizeof(aead_msg) + sizeof(asym_msg) +
                           sizeof(keyschedule_msg);

  negotiate_algs_msg.preamble.version = SPDM_THIS_VER;
  negotiate_algs_msg.preamble.request_response_code =
      SPDM_CODE_NEGOTIATE_ALGORITHMS;

  negotiate_algs_msg.param_1_alg_struct_count = 4;
  negotiate_algs_msg.length = msg_len;
  negotiate_algs_msg.other_params_opaque_data_fmt_1 = 1;

  spdm_write_algs(supported_algs, /*is_resp=*/false,
                  /*support_spdm_key_schedule=*/true,
                  &negotiate_algs_msg.asym_hash_algs, &dhe_msg, &aead_msg,
                  &asym_msg, &keyschedule_msg);

  uint8_t* out = reserve_from_writer(output, msg_len);
  if (out == NULL) {
    return -1;
  }

  memcpy(out, &negotiate_algs_msg, sizeof(negotiate_algs_msg));
  out += sizeof(negotiate_algs_msg);

  memcpy(out, &dhe_msg, sizeof(dhe_msg));
  out += sizeof(dhe_msg);

  memcpy(out, &aead_msg, sizeof(aead_msg));
  out += sizeof(aead_msg);

  memcpy(out, &asym_msg, sizeof(asym_msg));
  out += sizeof(asym_msg);

  memcpy(out, &keyschedule_msg, sizeof(keyschedule_msg));
  out += sizeof(keyschedule_msg);

  return 0;
}

int read_algorithms(buffer rsp, SpdmSupportedAlgs* their_algs) {
  SPDM_ALGORITHMS algs_msg;

  const uint8_t* ext_asym_algs;
  uint32_t ext_asym_algs_count;
  const uint8_t* ext_hash_algs;
  uint32_t ext_hash_algs_count;
  buffer alg_structs;
  uint32_t alg_structs_count;
  bool supports_spdm_key_schedule;

  int rc = SpdmCheckAlgorithms(&rsp, /*rest=*/NULL, &ext_asym_algs,
                               &ext_asym_algs_count, &ext_hash_algs,
                               &ext_hash_algs_count, &alg_structs.data,
                               &alg_structs_count, &alg_structs.size);
  if (rc != 0) {
    return rc;
  }

  memcpy(&algs_msg, rsp.data, sizeof(algs_msg));

  if (algs_msg.other_params_opaque_data_fmt_1 != 1) {
    return -1;
  }

  if (ext_asym_algs_count > 0 || ext_hash_algs_count > 0) {
    return -1;
  }

  rc = spdm_get_their_supported_algs(&algs_msg.asym_hash_algs, alg_structs,
                                     alg_structs_count, /*is_resp=*/true,
                                     their_algs, &supports_spdm_key_schedule);
  if (rc != 0) {
    return rc;
  }

  if (!supports_spdm_key_schedule) {
    return -1;
  }

  return 0;
}

static int check_negotiated_algs(const SpdmNegotiatedAlgs* negotiated_algs) {
  if (negotiated_algs->asym_sign_alg == SPDM_ASYM_UNSUPPORTED) {
    return -1;
  }

  if (negotiated_algs->asym_verify_alg == SPDM_ASYM_UNSUPPORTED) {
    return -1;
  }

  if (negotiated_algs->hash_alg == SPDM_HASH_UNSUPPORTED) {
    return -1;
  }

  if (negotiated_algs->dhe_alg == SPDM_DHE_UNSUPPORTED) {
    return -1;
  }

  if (negotiated_algs->aead_alg == SPDM_AEAD_UNSUPPORTED) {
    return -1;
  }

  return 0;
}

int spdm_negotiate_algorithms(SpdmRequesterContext* ctx,
                              SpdmSessionParams* session) {
  SpdmSupportedAlgs my_algs;
  spdm_get_my_supported_algs(&ctx->dispatch_ctx.crypto_spec,
                             &ctx->requester_pub_key, &my_algs);

  byte_writer writer = {ctx->dispatch_ctx.scratch,
                        ctx->dispatch_ctx.scratch_size, 0};

  int rc = write_negotiate_algorithms(&my_algs, &writer);
  if (rc != 0) {
    return rc;
  }

  buffer req = {writer.data, writer.bytes_written};
  buffer rsp;

  rc = spdm_append_to_transcript(&ctx->negotiation_transcript, req.data,
                                 req.size);
  if (rc != 0) {
    return rc;
  }

  rc =
      spdm_send_request(&ctx->dispatch_ctx, /*is_secure_msg=*/false, req, &rsp);
  if (rc != 0) {
    return rc;
  }

  SpdmSupportedAlgs their_algs;
  SpdmSupportedAlgs common_algs;

  rc = read_algorithms(rsp, &their_algs);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_append_to_transcript(&ctx->negotiation_transcript, rsp.data,
                                 rsp.size);
  if (rc != 0) {
    return rc;
  }

  spdm_get_negotiated_algs(&my_algs, &their_algs, &common_algs,
                           &session->info.negotiated_algs);

  return check_negotiated_algs(&session->info.negotiated_algs);
}
