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

#include <stdint.h>
#include <string.h>

#include "requester_functions.h"
#include "send_request.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/vendor_defined_pub_key.h"
#include "spdm_lite/requester/requester.h"

int spdm_give_pub_key(SpdmRequesterContext* ctx, SpdmSessionParams* session) {
  const SpdmRequesterSessionParams* params = ctx->params;

  byte_writer writer = {params->scratch.data, params->scratch.size, 0};

  int rc = spdm_write_give_pub_key_req(
      &params->dispatch_ctx->crypto_spec, &params->requester_pub_key,
      session->info.negotiated_algs.hash_alg, &writer);
  if (rc != 0) {
    return rc;
  }

  buffer req = {writer.data, writer.bytes_written};
  buffer rsp;

  rc = spdm_send_secure_request(params->dispatch_ctx, params->scratch, session,
                                SPDM_HANDSHAKE_PHASE, req, &rsp);
  if (rc != 0) {
    return rc;
  }

  return spdm_check_give_pub_key_rsp(rsp);
}
