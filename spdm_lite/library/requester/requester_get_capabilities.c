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

#include "requester_functions.h"
#include "send_request.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/requester/requester.h"

int spdm_get_capabilities(SpdmRequesterContext* ctx) {
  const SpdmRequesterSessionParams* params = ctx->params;

  SPDM_GET_CAPABILITIES msg = {};

  msg.preamble.version = SPDM_THIS_VER;
  msg.preamble.request_response_code = SPDM_CODE_GET_CAPABILITIES;

  msg.ct_exponent = 0;
  msg.data_transfer_size = params->requester_caps.data_transfer_size;
  msg.max_spdm_message_size = params->requester_caps.data_transfer_size;
  msg.flags_ENCRYPT_CAP = 1;
  msg.flags_MAC_CAP = 1;
  msg.flags_KEY_EX_CAP = 1;

  buffer req = {(const uint8_t*)&msg, sizeof(msg)};
  buffer rsp;

  int rc = spdm_send_request(params->dispatch_ctx, params->scratch,
                             /*is_secure_msg=*/false, req, &rsp);
  if (rc != 0) {
    return rc;
  }

  rc = SpdmCheckCapabilities(&rsp, /*rest=*/NULL);
  if (rc != 0) {
    return rc;
  }

  SPDM_CAPABILITIES caps;
  memcpy(&caps, rsp.data, sizeof(caps));

  memset(&ctx->responder_caps, 0, sizeof(ctx->responder_caps));
  ctx->responder_caps.data_transfer_size = caps.data_transfer_size;

  if (caps.flags_ENCRYPT_CAP != 1 || caps.flags_MAC_CAP != 1 ||
      caps.flags_KEY_EX_CAP != 1) {
    return -1;
  }

  rc = spdm_append_to_transcript(&ctx->negotiation_transcript, req.data,
                                 req.size);
  if (rc != 0) {
    return rc;
  }

  return spdm_append_to_transcript(&ctx->negotiation_transcript, rsp.data,
                                   rsp.size);
}
