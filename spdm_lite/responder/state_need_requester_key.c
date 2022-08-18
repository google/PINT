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

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/error.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/vendor_defined_pub_key.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/responder/responder.h"

static int handle_get_encapsulated_req(SpdmResponderContext* ctx, buffer input,
                                       byte_writer* output) {
  SPDM_ENCAPSULATED_REQUEST outer_msg;
  SPDM_VENDOR_DEFINED_REQ_RSP inner_msg_vendor_defined;
  SPDM_VendorDefinedPubKeyReq inner_msg_get_pub_key;

  int rc = SpdmCheckGetEncapsulatedRequest(&input, /*rest=*/NULL);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  memset(&outer_msg, 0, sizeof(outer_msg));
  memset(&inner_msg_vendor_defined, 0, sizeof(inner_msg_vendor_defined));
  memset(&inner_msg_get_pub_key, 0, sizeof(inner_msg_get_pub_key));

  uint8_t request_id;
  rc = spdm_get_random(&ctx->crypto_spec, &request_id, 1);
  if (rc != 0) {
    return rc;
  }

  request_id = MAX(request_id, 1);

  outer_msg.preamble.version = SPDM_THIS_VER;
  outer_msg.preamble.request_response_code = SPDM_CODE_ENCAPSULATED_REQUEST;
  outer_msg.param_1_request_id = request_id;

  inner_msg_vendor_defined.preamble.version = SPDM_THIS_VER;
  inner_msg_vendor_defined.preamble.request_response_code =
      SPDM_CODE_VENDOR_DEFINED_REQUEST;
  inner_msg_vendor_defined.standard_id = DMTF_STANDARD_ID;
  uint16_t req_len = sizeof(inner_msg_get_pub_key);

  inner_msg_get_pub_key.vd_id = DMTF_VD_ID;
  inner_msg_get_pub_key.vd_req = DMTF_VD_PUBKEY_CODE;

  uint8_t* out = reserve_from_writer(
      output, sizeof(outer_msg) + sizeof(inner_msg_vendor_defined) +
                  sizeof(req_len) + sizeof(inner_msg_get_pub_key));
  if (out == NULL) {
    return -1;
  }

  memcpy(out, &outer_msg, sizeof(outer_msg));
  out += sizeof(outer_msg);

  memcpy(out, &inner_msg_vendor_defined, sizeof(inner_msg_vendor_defined));
  out += sizeof(inner_msg_vendor_defined);

  memcpy(out, &req_len, sizeof(req_len));
  out += sizeof(req_len);

  memcpy(out, &inner_msg_get_pub_key, sizeof(inner_msg_get_pub_key));
  out += sizeof(inner_msg_get_pub_key);

  ctx->session.pending_pub_key_req_id = request_id;

  return 0;
}

static int write_response_ack(uint8_t req_id, byte_writer* output) {
  SPDM_ENCAPSULATED_RESPONSE_ACK ack;

  memset(&ack, 0, sizeof(ack));

  uint8_t* out = reserve_from_writer(output, sizeof(ack));
  if (out == NULL) {
    return -1;
  }

  ack.preamble.version = SPDM_THIS_VER;
  ack.preamble.request_response_code = SPDM_CODE_ENCAPSULATED_RESPONSE_ACK;
  ack.ack_request_id = req_id;

  memcpy(out, &ack, sizeof(ack));

  return 0;
}

static int handle_deliver_encapsulated_response(SpdmResponderContext* ctx,
                                                buffer input,
                                                byte_writer* output) {
  uint8_t req_id;
  buffer rest;

  int rc = SpdmCheckDeliverEncapsulatedResponse(&input, &rest, &req_id);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  if (req_id == 0 || req_id != ctx->session.pending_pub_key_req_id) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  uint16_t standard_id;
  buffer vendor_id;
  buffer payload;

  rc = SpdmCheckVendorDefinedResponse(&rest, /*rest=*/NULL, &standard_id,
                                      &vendor_id.data, &vendor_id.size,
                                      &payload.data, &payload.size);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  uint16_t pub_key_size =
      spdm_get_asym_pub_key_size(ctx->negotiated_algs.asym_verify_alg);

  if (standard_id != DMTF_STANDARD_ID || vendor_id.size != 0 ||
      payload.size != sizeof(SPDM_VendorDefinedPubKeyRsp) + pub_key_size) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  SPDM_VendorDefinedPubKeyRsp pub_key_rsp;
  consume_from_buffer(&payload, &pub_key_rsp, sizeof(pub_key_rsp));

  // TODO(jeffandersen): endianness
  if (pub_key_rsp.vd_id != DMTF_VD_ID ||
      pub_key_rsp.vd_rsp != DMTF_VD_PUBKEY_CODE) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  SpdmAsymPubKey req_pub_key;
  spdm_init_asym_pub_key(&req_pub_key, ctx->negotiated_algs.asym_verify_alg);
  consume_from_buffer(&payload, req_pub_key.data, pub_key_size);

  rc = spdm_validate_asym_pubkey(&ctx->crypto_spec, &req_pub_key);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  rc = write_response_ack(req_id, output);
  if (rc != 0) {
    return rc;
  }

  ctx->session.pending_pub_key_req_id = 0;
  ctx->session.params.info.peer_pub_key = req_pub_key;

  ctx->state = STATE_MUTUAL_AUTH_WAITING_FOR_FINISH;
  return 0;
}

int spdm_dispatch_request_need_requester_key(SpdmResponderContext* ctx,
                                             uint8_t code, buffer input,
                                             byte_writer* output) {
  if (ctx->state != STATE_MUTUAL_AUTH_NEED_REQUESTER_KEY) {
    return -1;
  }

  switch (code) {
    case SPDM_CODE_GET_ENCAPSULATED_REQUEST:
      return handle_get_encapsulated_req(ctx, input, output);
    case SPDM_CODE_DELIVER_ENCAPSULATED_RESPONSE:
      return handle_deliver_encapsulated_response(ctx, input, output);
    default:
      return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  return -1;
}
