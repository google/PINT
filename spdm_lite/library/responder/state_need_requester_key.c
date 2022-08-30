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

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/error.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/vendor_defined_pub_key.h"
#include "spdm_lite/responder/responder.h"

int spdm_dispatch_request_need_requester_key(SpdmResponderContext* ctx,
                                             uint8_t code, buffer input,
                                             byte_writer* output) {
  int rc;
  SpdmSessionInfo* session_info = &ctx->session.params.info;

  if (ctx->state != STATE_MUTUAL_AUTH_NEED_REQUESTER_KEY) {
    return -1;
  }

  SpdmAsymPubKey pub_key_in_request;
  rc = spdm_check_give_pub_key_req(
      &ctx->crypto_spec, input, session_info->negotiated_algs.asym_verify_alg,
      session_info->negotiated_algs.hash_alg, &pub_key_in_request);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  rc = spdm_validate_asym_pubkey(&ctx->crypto_spec, &pub_key_in_request);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_write_give_pub_key_rsp(output);
  if (rc != 0) {
    return rc;
  }

  session_info->peer_pub_key = pub_key_in_request;
  ctx->state = STATE_MUTUAL_AUTH_WAITING_FOR_FINISH;

  return 0;
}
