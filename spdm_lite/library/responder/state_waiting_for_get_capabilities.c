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

#include "spdm_lite/common/error.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/transcript.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/responder/responder.h"

static int write_capabilities(SpdmResponderContext* ctx,
                              byte_writer* output) {
  SPDM_CAPABILITIES msg;
  int rc;

  memset(&msg, 0, sizeof(msg));

  msg.preamble.version = SPDM_THIS_VER;
  msg.preamble.request_response_code = SPDM_CODE_CAPABILITIES;
  msg.ct_exponent = 0;
  msg.data_transfer_size = ctx->responder_caps.data_transfer_size;
  msg.max_spdm_message_size = msg.data_transfer_size;

  msg.flags_ENCRYPT_CAP = 1;
  msg.flags_MAC_CAP = 1;
  msg.flags_MUT_AUTH_CAP = 1;
  msg.flags_KEY_EX_CAP = 1;
  msg.flags_ALIAS_CERT_CAP = 1;

  rc = write_to_writer(output, &msg, sizeof(msg));
  if (rc != 0) {
    return rc;
  }

  return spdm_append_to_transcript(&ctx->negotiation_transcript, &msg,
                                   sizeof(msg));
}

int spdm_dispatch_request_waiting_for_get_capabilities(
    SpdmResponderContext* ctx, uint8_t code, buffer input,
    byte_writer* output) {
  int rc;
  SPDM_GET_CAPABILITIES msg;

  if (ctx->state != STATE_WAITING_FOR_GET_CAPABILITIES) {
    return -1;
  }

  if (code != SPDM_CODE_GET_CAPABILITIES) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  rc = SpdmCheckGetCapabilities(&input, /*rest=*/NULL);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  memcpy(&msg, input.data, sizeof(msg));

  memset(&ctx->requester_caps, 0, sizeof(ctx->requester_caps));
  ctx->requester_caps.data_transfer_size = msg.data_transfer_size;

  rc = spdm_append_to_transcript(&ctx->negotiation_transcript, input.data,
                                 input.size);

  rc = write_capabilities(ctx, output);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_UNSPECIFIED, output);
  }

  ctx->state = STATE_WAITING_FOR_NEGOTIATE_ALGORITHMS;

  return 0;
}
