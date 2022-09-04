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

#include "spdm_lite/requester/requester.h"

#include <string.h>

#include "requester_functions.h"
#include "send_request.h"
#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"

int spdm_establish_session(const SpdmRequesterSessionParams* params,
                           SpdmSessionParams* session) {
  int rc = spdm_validate_asym_pubkey(&params->dispatch_ctx->crypto_spec,
                                     &params->requester_pub_key);
  if (rc != 0) {
    return rc;
  }

  SpdmRequesterContext ctx = {};
  ctx.params = params;

  memset(session, 0, sizeof(*session));

  rc = spdm_get_version(&ctx);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_get_capabilities(&ctx);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_negotiate_algorithms(&ctx, session);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_get_pub_key(&ctx, session);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_key_exchange(&ctx, session);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_give_pub_key(&ctx, session);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_finish(&ctx, session);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  if (rc != 0) {
    memset(session, 0, sizeof(*session));
  }

  return rc;
}

int spdm_dispatch_app_request(const SpdmDispatchRequestCtx* dispatch_ctx,
                              SpdmScratchSpace scratch_space,
                              SpdmSessionParams* session, uint16_t standard_id,
                              const uint8_t* vendor_id, size_t vendor_id_size,
                              const void* req, size_t req_size, void* rsp,
                              size_t* rsp_size) {
  SPDM_VENDOR_DEFINED_REQ_RSP req_msg = {};

  byte_writer writer = {scratch_space.data, scratch_space.size, 0};

  uint8_t* out = reserve_from_writer(
      &writer, sizeof(req_msg) + vendor_id_size + sizeof(uint16_t) + req_size);
  if (out == NULL) {
    return -1;
  }

  req_msg.preamble.version = SPDM_THIS_VER;
  req_msg.preamble.request_response_code = SPDM_CODE_VENDOR_DEFINED_REQUEST;
  req_msg.standard_id = standard_id;
  req_msg.vendor_id_len = vendor_id_size;

  uint16_t req_len = req_size;

  memmove(out + sizeof(req_msg) + vendor_id_size + sizeof(req_len), req,
          req_size);

  memcpy(out, &req_msg, sizeof(req_msg));
  out += sizeof(req_msg);

  memcpy(out, vendor_id, vendor_id_size);
  out += vendor_id_size;

  memcpy(out, &req_len, sizeof(req_len));
  out += sizeof(req_len);

  buffer vendor_req = {writer.data, writer.bytes_written};
  buffer rsp_buf;

  int rc = spdm_send_secure_request(dispatch_ctx, scratch_space, session,
                                    SPDM_DATA_PHASE, vendor_req, &rsp_buf);

  if (rc != 0) {
    return rc;
  }

  uint16_t rsp_standard_id;
  buffer rsp_vendor_id;
  buffer payload;

  rc = SpdmCheckVendorDefinedResponse(&rsp_buf, /*rest=*/NULL, &rsp_standard_id,
                                      &rsp_vendor_id.data, &rsp_vendor_id.size,
                                      &payload.data, &payload.size);
  if (rc != 0) {
    return rc;
  }

  if (rsp_standard_id != standard_id || rsp_vendor_id.size != vendor_id_size) {
    return -1;
  }

  if (memcmp(rsp_vendor_id.data, vendor_id, vendor_id_size) != 0) {
    return -1;
  }

  if (payload.size > *rsp_size) {
    return -1;
  }

  memcpy(rsp, payload.data, payload.size);
  *rsp_size = payload.size;

  return 0;
}

int spdm_end_session(const SpdmDispatchRequestCtx* dispatch_ctx,
                     SpdmScratchSpace scratch_space,
                     SpdmSessionParams* session) {
  SPDM_END_SESSION req_msg = {};

  req_msg.preamble.version = SPDM_THIS_VER;
  req_msg.preamble.request_response_code = SPDM_CODE_END_SESSION;

  buffer req_buf = {(uint8_t*)&req_msg, sizeof(req_msg)};
  buffer rsp_buf;

  int rc = spdm_send_secure_request(dispatch_ctx, scratch_space, session,
                                    SPDM_DATA_PHASE, req_buf, &rsp_buf);
  if (rc != 0) {
    return rc;
  }

  rc = SpdmCheckEndSessionAck(&rsp_buf, /*rest=*/NULL);
  if (rc != 0) {
    return rc;
  }

  memset(session, 0, sizeof(*session));

  return 0;
}
