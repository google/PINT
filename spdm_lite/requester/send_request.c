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

#include "spdm_lite/requester/send_request.h"

#include <string.h>

#include "spdm_lite/common/key_schedule.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/session.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/requester/requester.h"

static int generate_session_keys(const SpdmCryptoSpec* crypto_spec,
                                 SpdmSessionParams* session,
                                 SpdmSessionPhase phase, uint64_t req_seq_num,
                                 uint64_t rsp_seq_num,
                                 SpdmSessionAeadKeys* keys) {
  SpdmMessageSecrets secrets;

  int rc = spdm_generate_message_secrets(crypto_spec, session, phase, &secrets);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_generate_aead_keys(crypto_spec,
                               session->info.negotiated_algs.aead_alg, &secrets,
                               req_seq_num, rsp_seq_num, keys);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&secrets, 0, sizeof(secrets));
  return rc;
}

int spdm_send_secure_request(const SpdmDispatchRequestCtx* dispatch_ctx,
                             SpdmSessionParams* session, SpdmSessionPhase phase,
                             buffer req, buffer* rsp) {
  SpdmSessionAeadKeys keys;
  int rc = 0;

  if (dispatch_ctx->scratch_size < req.size + SPDM_SECURE_MESSAGE_OVERHEAD) {
    rc = -1;
    goto cleanup;
  }

  uint8_t* header = dispatch_ctx->scratch;

  uint8_t* plaintext_start = header + sizeof(SPDM_SecuredMessageRecord);
  memmove(plaintext_start, req.data, req.size);

  byte_writer footer = {plaintext_start + req.size,
                        SPDM_MAX_SECURE_MESSAGE_FOOTER_LEN, 0};

  rc = generate_session_keys(&dispatch_ctx->crypto_spec, session, phase,
                             session->req_seq_num, session->rsp_seq_num, &keys);
  if (rc != 0) {
    goto cleanup;
  }

  buffer msg_buf = {plaintext_start, req.size};

  rc = spdm_encrypt_secure_message(
      &dispatch_ctx->crypto_spec, &session->info.session_id,
      session->req_seq_num, &keys.req_keys, header, msg_buf, &footer);
  if (rc != 0) {
    goto cleanup;
  }

  session->req_seq_num++;

  uint32_t encrypted_msg_len =
      sizeof(SPDM_SecuredMessageRecord) + req.size + footer.bytes_written;

  buffer encrypted_req = {header, encrypted_msg_len};

  rc = spdm_send_request(dispatch_ctx,
                         /*is_secure_msg=*/true, encrypted_req, rsp);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_decrypt_secure_message(&dispatch_ctx->crypto_spec,
                                   &session->info.session_id,
                                   session->rsp_seq_num, &keys.rsp_keys, rsp);
  if (rc != 0) {
    goto cleanup;
  }

  session->rsp_seq_num++;

cleanup:
  memset(&keys, 0, sizeof(keys));

  return rc;
}

int spdm_send_request(const SpdmDispatchRequestCtx* dispatch_ctx,
                      bool is_secure_msg, buffer req, buffer* rsp) {
  uint8_t* rsp_data = dispatch_ctx->scratch;
  size_t rsp_size = dispatch_ctx->scratch_size;

  int rc = dispatch_ctx->dispatch_fn(dispatch_ctx->ctx, is_secure_msg, req.data,
                                     req.size, rsp_data, &rsp_size);
  if (rc != 0) {
    return rc;
  }

  rsp->data = rsp_data;
  rsp->size = rsp_size;

  return 0;
}
