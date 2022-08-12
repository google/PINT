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

#include <stdio.h>
#include <string.h>

#include "common/messages.h"
#include "common/utils.h"
#include "common/vendor_defined_pub_key.h"
#include "common/version.h"
#include "everparse/SPDMWrapper.h"
#include "requester/requester.h"
#include "requester/send_request.h"

static int check_encapsulated_pub_key_request(buffer rsp, uint8_t* req_id) {
  buffer rest;
  int rc = SpdmCheckEncapsulatedRequest(&rsp, &rest, req_id);
  if (rc != 0) {
    return rc;
  }

  uint16_t standard_id;
  buffer vendor_id;
  buffer payload;

  rc = SpdmCheckVendorDefinedRequest(&rest, /*rest=*/NULL, &standard_id,
                                     &vendor_id.data, &vendor_id.size,
                                     &payload.data, &payload.size);
  if (rc != 0) {
    return rc;
  }

  SPDM_VendorDefinedPubKeyReq pub_key_req;

  if (standard_id != DMTF_STANDARD_ID || vendor_id.size != 0 ||
      payload.size != sizeof(pub_key_req)) {
    return -1;
  }

  memcpy(&pub_key_req, payload.data, sizeof(pub_key_req));

  // TODO(jeffandersen): endianness
  if (pub_key_req.vd_id != DMTF_VD_ID ||
      pub_key_req.vd_req != DMTF_VD_PUBKEY_CODE) {
    return -1;
  }

  return 0;
}

static int write_pub_key(uint8_t req_id, const SpdmAsymPubKey* pub_key,
                         byte_writer* output) {
  SPDM_DELIVER_ENCAPSULATED_RESPONSE encapsulated_rsp = {};
  SPDM_VENDOR_DEFINED_REQ_RSP vendor_defined_rsp = {};
  uint16_t rsp_len;
  SPDM_VendorDefinedPubKeyRsp pub_key_rsp = {};

  uint16_t pub_key_size = spdm_get_asym_pub_key_size(pub_key->alg);

  const uint32_t msg_len = sizeof(encapsulated_rsp) +
                           sizeof(vendor_defined_rsp) + sizeof(rsp_len) +
                           sizeof(pub_key_rsp) + pub_key_size;

  uint8_t* out = reserve_from_writer(output, msg_len);
  if (out == NULL) {
    return -1;
  }

  encapsulated_rsp.preamble.version = SPDM_THIS_VER;
  encapsulated_rsp.preamble.request_response_code =
      SPDM_CODE_DELIVER_ENCAPSULATED_RESPONSE;
  encapsulated_rsp.param_1_request_id = req_id;

  vendor_defined_rsp.preamble.version = SPDM_THIS_VER;
  vendor_defined_rsp.preamble.request_response_code =
      SPDM_CODE_VENDOR_DEFINED_RESPONSE;
  vendor_defined_rsp.standard_id = DMTF_STANDARD_ID;

  // TODO(jeffandersen): endianness.
  rsp_len = sizeof(pub_key_rsp) + pub_key_size;

  pub_key_rsp.vd_id = DMTF_VD_ID;
  pub_key_rsp.vd_rsp = DMTF_VD_PUBKEY_CODE;  // TODO(jeffandersen): endianness.

  memcpy(out, &encapsulated_rsp, sizeof(encapsulated_rsp));
  out += sizeof(encapsulated_rsp);

  memcpy(out, &vendor_defined_rsp, sizeof(vendor_defined_rsp));
  out += sizeof(vendor_defined_rsp);

  memcpy(out, &rsp_len, sizeof(rsp_len));
  out += sizeof(rsp_len);

  memcpy(out, &pub_key_rsp, sizeof(pub_key_rsp));
  out += sizeof(pub_key_rsp);

  memcpy(out, pub_key->data, pub_key_size);
  out += pub_key_size;

  return 0;
}

static int check_response_ack(buffer rsp, uint8_t original_req_id) {
  uint8_t req_id, payload_type, ack_req_id;
  int rc = SpdmCheckEncapsulatedResponseAck(&rsp, /*rest=*/NULL, &req_id,
                                            &payload_type, &ack_req_id);
  if (rc != 0) {
    return rc;
  }

  if (req_id != 0 || payload_type != 0 || ack_req_id != original_req_id) {
    return -1;
  }

  return 0;
}

int spdm_give_pub_key(SpdmRequesterContext* ctx, SpdmSessionParams* session) {
  SPDM_GET_ENCAPSULATED_REQUEST msg = {};

  msg.preamble.version = SPDM_THIS_VER;
  msg.preamble.request_response_code = SPDM_CODE_GET_ENCAPSULATED_REQUEST;

  buffer req = {(uint8_t*)&msg, sizeof(msg)};
  buffer rsp;

  int rc = spdm_send_secure_request(&ctx->dispatch_ctx, session,
                                    SPDM_HANDSHAKE_PHASE, req, &rsp);
  if (rc != 0) {
    return rc;
  }

  uint8_t req_id;
  rc = check_encapsulated_pub_key_request(rsp, &req_id);
  if (rc != 0) {
    return rc;
  }

  byte_writer writer = {ctx->dispatch_ctx.scratch,
                        ctx->dispatch_ctx.scratch_size, 0};

  rc = write_pub_key(req_id, &ctx->requester_pub_key, &writer);
  if (rc != 0) {
    return rc;
  }

  req.data = writer.data;
  req.size = writer.bytes_written;

  rc = spdm_send_secure_request(&ctx->dispatch_ctx, session,
                                SPDM_HANDSHAKE_PHASE, req, &rsp);
  if (rc != 0) {
    return rc;
  }

  rc = check_response_ack(rsp, req_id);
  if (rc != 0) {
    return rc;
  }

  return 0;
}
