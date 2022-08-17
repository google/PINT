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

#include "common/crypto.h"
#include "common/error.h"
#include "common/messages.h"
#include "common/utils.h"
#include "common/version.h"
#include "everparse/SPDMWrapper.h"
#include "responder/responder.h"

static int handle_end_session(SpdmResponderContext* ctx, buffer input,
                              byte_writer* output, bool* end_session) {
  bool preserve_negotiated_state;  // Will ignore this as we don't support
                                   // caching negotiated state.
  SPDM_END_SESSION_ACK ack = {};

  int rc =
      SpdmCheckEndSession(&input, /*rest=*/NULL, &preserve_negotiated_state);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  ack.preamble.version = SPDM_THIS_VER;
  ack.preamble.request_response_code = SPDM_CODE_END_SESSION_ACK;

  rc = write_to_writer(output, &ack, sizeof(ack));
  if (rc != 0) {
    return rc;
  }

  *end_session = true;

  return 0;
}

static int handle_vendor_defined_req(SpdmResponderContext* ctx, buffer input,
                                     byte_writer* output) {
  uint16_t standard_id;
  buffer vendor_id;
  buffer payload;

  int rc = SpdmCheckVendorDefinedRequest(&input, /*rest=*/NULL, &standard_id,
                                         &vendor_id.data, &vendor_id.size,
                                         &payload.data, &payload.size);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  if (ctx->app_dispatch_fn == NULL) {
    return spdm_write_error(SPDM_ERR_UNSPECIFIED, output);
  }

  SPDM_VENDOR_DEFINED_REQ_RSP vendor_defined_rsp = {};
  uint16_t rsp_len;

  uint32_t header_len =
      sizeof(vendor_defined_rsp) + vendor_id.size + sizeof(rsp_len);

  uint8_t* header = reserve_from_writer(output, header_len);
  if (header == NULL) {
    return -1;
  }

  vendor_defined_rsp.preamble.version = SPDM_THIS_VER;
  vendor_defined_rsp.preamble.request_response_code =
      SPDM_CODE_VENDOR_DEFINED_RESPONSE;
  vendor_defined_rsp.standard_id = standard_id;
  vendor_defined_rsp.vendor_id_len = vendor_id.size;

  uint8_t* rsp_bytes = output->data + output->bytes_written;
  size_t rsp_bytes_written = output->size - output->bytes_written;

  rc = ctx->app_dispatch_fn(&ctx->session.params.info, standard_id,
                            vendor_id.data, vendor_id.size, payload.data,
                            payload.size, rsp_bytes, &rsp_bytes_written);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_UNSPECIFIED, output);
  }

  output->bytes_written += rsp_bytes_written;
  rsp_len = rsp_bytes_written;

  memcpy(header, &vendor_defined_rsp, sizeof(vendor_defined_rsp));
  header += sizeof(vendor_defined_rsp);

  memcpy(header, vendor_id.data, vendor_id.size);
  header += vendor_id.size;

  // TODO(jeffandersen): endianness.
  memcpy(header, &rsp_len, sizeof(rsp_len));
  header += sizeof(rsp_len);

  return 0;
}

int spdm_dispatch_request_session_established(SpdmResponderContext* ctx,
                                              uint8_t code, buffer input,
                                              byte_writer* output,
                                              bool* end_session) {
  *end_session = false;

  if (ctx->state != STATE_SESSION_ESTABLISHED) {
    return -1;
  }

  switch (code) {
    case SPDM_CODE_END_SESSION:
      return handle_end_session(ctx, input, output, end_session);
    case SPDM_CODE_VENDOR_DEFINED_REQUEST:
      return handle_vendor_defined_req(ctx, input, output);
    default:
      return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }
}
