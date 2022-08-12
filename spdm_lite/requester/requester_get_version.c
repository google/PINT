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

#include "common/messages.h"
#include "common/transcript.h"
#include "common/version.h"
#include "everparse/SPDMWrapper.h"
#include "requester/requester.h"
#include "requester/send_request.h"

static int check_version(uint8_t entry_count, const uint8_t* entries) {
  for (int i = 0; i < entry_count; ++i) {
    SPDM_VersionNumberEntry entry;
    memcpy(&entry, entries, sizeof(entry));
    entries += sizeof(entry);

    if (entry.major_version != SPDM_THIS_VER >> 4) {
      continue;
    }

    // TODO(jeffandersen): allow minor version skew?
    if (entry.minor_version != (SPDM_THIS_VER & 0x0F)) {
      continue;
    }

    if (entry.alpha != 0) {
      continue;
    }

    return 0;
  }

  return -1;
}

int spdm_get_version(SpdmRequesterContext* ctx) {
  SPDM_GET_VERSION msg = {};

  msg.preamble.version = 0x10;
  msg.preamble.request_response_code = SPDM_CODE_GET_VERSION;

  buffer req = {(const uint8_t*)&msg, sizeof(msg)};
  buffer rsp;

  int rc =
      spdm_send_request(&ctx->dispatch_ctx, /*is_secure_msg=*/false, req, &rsp);
  if (rc != 0) {
    return rc;
  }

  uint8_t entry_count;
  const uint8_t* entries;

  rc = SpdmCheckVersion(&rsp, /*rest=*/NULL, &entry_count, &entries);
  if (rc != 0) {
    return rc;
  }

  rc = check_version(entry_count, entries);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_append_to_transcript(&ctx->negotiation_transcript, req.data,
                                 req.size);
  if (rc != 0) {
    return rc;
  }

  return spdm_append_to_transcript(&ctx->negotiation_transcript, rsp.data,
                                   rsp.size);
}
