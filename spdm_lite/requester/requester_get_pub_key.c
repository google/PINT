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

#include "common/crypto.h"
#include "common/messages.h"
#include "common/utils.h"
#include "common/vendor_defined_pub_key.h"
#include "common/version.h"
#include "everparse/SPDMWrapper.h"
#include "requester/requester.h"
#include "requester/send_request.h"

static int write_get_pub_key(byte_writer* output) {
  SPDM_VENDOR_DEFINED_REQ_RSP vendor_defined_req = {};
  SPDM_VendorDefinedPubKeyReq pub_key_req = {};
  uint16_t req_len = sizeof(pub_key_req);

  vendor_defined_req.preamble.version = SPDM_THIS_VER;
  vendor_defined_req.preamble.request_response_code =
      SPDM_CODE_VENDOR_DEFINED_REQUEST;
  vendor_defined_req.standard_id = DMTF_STANDARD_ID;

  pub_key_req.vd_id = DMTF_VD_ID;
  pub_key_req.vd_req = DMTF_VD_PUBKEY_CODE;

  const uint32_t msg_len =
      sizeof(vendor_defined_req) + sizeof(req_len) + sizeof(pub_key_req);

  uint8_t* out = reserve_from_writer(output, msg_len);
  if (out == NULL) {
    return -1;
  }

  memcpy(out, &vendor_defined_req, sizeof(vendor_defined_req));
  out += sizeof(vendor_defined_req);

  // TODO(jeffandersen): endianness.
  memcpy(out, &req_len, sizeof(req_len));
  out += sizeof(req_len);

  memcpy(out, &pub_key_req, sizeof(pub_key_req));
  out += sizeof(pub_key_req);

  return 0;
}

int spdm_get_pub_key(SpdmRequesterContext* ctx, SpdmSessionParams* session) {
  byte_writer writer = {ctx->dispatch_ctx.scratch,
                             ctx->dispatch_ctx.scratch_size, 0};

  int rc = write_get_pub_key(&writer);
  if (rc != 0) {
    return rc;
  }

  buffer req = {writer.data, writer.bytes_written};
  buffer rsp;

  rc =
      spdm_send_request(&ctx->dispatch_ctx, /*is_secure_msg=*/false, req, &rsp);
  if (rc != 0) {
    return rc;
  }

  uint16_t standard_id;
  buffer vendor_id;
  buffer payload;

  rc = SpdmCheckVendorDefinedResponse(&rsp, /*rest=*/NULL, &standard_id,
                                      &vendor_id.data, &vendor_id.size,
                                      &payload.data, &payload.size);
  if (rc != 0) {
    return rc;
  }

  if (standard_id != DMTF_STANDARD_ID || vendor_id.size != 0) {
    return -1;
  }

  uint16_t pub_key_size =
      spdm_get_asym_pub_key_size(session->info.negotiated_algs.asym_verify_alg);

  if (payload.size != sizeof(SPDM_VendorDefinedPubKeyRsp) + pub_key_size) {
    return -1;
  }

  SPDM_VendorDefinedPubKeyRsp pub_key_rsp;
  consume_from_buffer(&payload, &pub_key_rsp, sizeof(pub_key_rsp));

  if (pub_key_rsp.vd_id != DMTF_VD_ID ||
      pub_key_rsp.vd_rsp != DMTF_VD_PUBKEY_CODE) {
    return -1;
  }

  SpdmAsymPubKey pub_key_in_response;
  spdm_init_asym_pub_key(&pub_key_in_response,
                         session->info.negotiated_algs.asym_verify_alg);

  consume_from_buffer(&payload, pub_key_in_response.data, pub_key_size);

  rc = spdm_validate_asym_pubkey(&ctx->dispatch_ctx.crypto_spec,
                                 &pub_key_in_response);
  if (rc != 0) {
    return rc;
  }

  session->info.peer_pub_key = pub_key_in_response;

  return 0;
}
