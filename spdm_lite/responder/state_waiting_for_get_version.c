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

#include "common/error.h"
#include "common/messages.h"
#include "common/transcript.h"
#include "common/utils.h"
#include "everparse/SPDMWrapper.h"
#include "responder/responder.h"

static int write_version(SpdmResponderContext* ctx, byte_writer* output) {
  SPDM_VERSION version_msg = {};
  SPDM_VersionNumberEntry version_entry_msg = {};
  uint32_t output_len;
  uint8_t* output_buf;
  uint8_t* output_ptr;

  version_msg.preamble.version = 0x10;
  version_msg.preamble.request_response_code = SPDM_CODE_VERSION;
  version_msg.version_number_entry_count = 1;
  version_entry_msg.major_version = 1;
  version_entry_msg.minor_version = 2;

  output_len = sizeof(version_msg) + sizeof(version_entry_msg);

  output_buf = reserve_from_writer(output, output_len);
  if (output_buf == NULL) {
    return -1;
  }

  output_ptr = output_buf;

  memcpy(output_ptr, &version_msg, sizeof(version_msg));
  output_ptr += sizeof(version_msg);

  memcpy(output_ptr, &version_entry_msg, sizeof(version_entry_msg));
  output_ptr += sizeof(version_entry_msg);

  return spdm_append_to_transcript(&ctx->negotiation_transcript, output_buf,
                                   output_len);
}

int spdm_dispatch_request_waiting_for_get_version(SpdmResponderContext* ctx,
                                                  uint8_t code, buffer input,
                                                  byte_writer* output) {
  int rc;

  if (ctx->state != STATE_WAITING_FOR_GET_VERSION) {
    return -1;
  }

  if (code != SPDM_CODE_GET_VERSION) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  rc = SpdmCheckGetVersion(&input, /*rest=*/NULL);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  rc = spdm_append_to_transcript(&ctx->negotiation_transcript, input.data,
                                 input.size);
  if (rc != 0) {
    return rc;
  }

  rc = write_version(ctx, output);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_UNSPECIFIED, output);
  }

  ctx->state = STATE_WAITING_FOR_GET_CAPABILITIES;

  return 0;
}
