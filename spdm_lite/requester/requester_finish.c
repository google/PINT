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
#include "spdm_lite/common/key_schedule.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/sign.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/requester/requester.h"
#include "spdm_lite/requester/send_request.h"

static int generate_finish_key(const SpdmCryptoSpec* crypto_spec,
                               const SpdmSessionParams* session,
                               SPDMRole originator,
                               SpdmHashResult* finish_key) {
  SpdmMessageSecrets handshake_secrets;

  int rc = spdm_generate_message_secrets(
      crypto_spec, session, SPDM_HANDSHAKE_PHASE, &handshake_secrets);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_generate_finished_key(crypto_spec, originator, &handshake_secrets,
                                  finish_key);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&handshake_secrets, 0, sizeof(handshake_secrets));

  return rc;
}

static int hmac_finish_msg(const SpdmCryptoSpec* crypto_spec,
                           const SpdmHash* transcript_hash,
                           const SpdmSessionParams* session, uint8_t* hmac) {
  SpdmHashResult finish_key;
  SpdmHashResult transcript_digest;
  SpdmHashResult hmac_result;

  int rc = spdm_get_hash(transcript_hash, &transcript_digest);
  if (rc != 0) {
    goto cleanup;
  }

  rc = generate_finish_key(crypto_spec, session,
                           /*originator=*/SPDM_REQUESTER, &finish_key);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_hmac(crypto_spec, &finish_key, &transcript_digest, &hmac_result);
  if (rc != 0) {
    goto cleanup;
  }

  memcpy(hmac, hmac_result.data, hmac_result.size);

cleanup:
  memset(&finish_key, 0, sizeof(finish_key));

  return rc;
}

static int write_finish(SpdmRequesterContext* ctx,
                        const SpdmSessionParams* session,
                        SpdmHash* transcript_hash, byte_writer* output) {
  SPDM_FINISH msg = {};

  const uint16_t sig_size =
      spdm_get_asym_signature_size(session->info.negotiated_algs.asym_sign_alg);
  const uint16_t hmac_size =
      spdm_get_hash_size(session->info.negotiated_algs.hash_alg);

  const uint32_t msg_len = sizeof(msg) + sig_size + hmac_size;

  uint8_t* out = reserve_from_writer(output, msg_len);
  if (out == NULL) {
    return -1;
  }

  msg.preamble.version = SPDM_THIS_VER;
  msg.preamble.request_response_code = SPDM_CODE_FINISH;
  msg.param_1_sig_included = 1;
  msg.param_2_slot_id = 0xFF;

  memcpy(out, &msg, sizeof(msg));
  spdm_extend_hash(transcript_hash, out, sizeof(msg));
  out += sizeof(msg);

  SpdmHashResult transcript_digest;
  int rc = spdm_get_hash(transcript_hash, &transcript_digest);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_sign(&ctx->dispatch_ctx.crypto_spec,
                 session->info.negotiated_algs.asym_sign_alg,
                 ctx->requester_priv_key_ctx,
                 /*my_role=*/SPDM_REQUESTER, &transcript_digest,
                 /*context=*/"finish signing", out, sig_size);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(transcript_hash, out, sig_size);
  out += sig_size;

  rc = hmac_finish_msg(&ctx->dispatch_ctx.crypto_spec, transcript_hash, session,
                       out);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(transcript_hash, out, hmac_size);
  out += hmac_size;

  return 0;
}

static int verify_finish_rsp(SpdmRequesterContext* ctx,
                             SpdmSessionParams* session,
                             SpdmHash* transcript_hash, buffer rsp) {
  SpdmHashResult finish_key;
  SpdmHashResult transcript_digest;
  const uint8_t* responder_verify_data;

  uint16_t hash_len =
      spdm_get_hash_size(session->info.negotiated_algs.hash_alg);

  int rc = SpdmCheckFinishRsp(&rsp, /*rest=*/NULL, hash_len,
                              /*responder_verify_data_expected=*/true,
                              &responder_verify_data);
  if (rc != 0) {
    goto cleanup;
  }

  spdm_extend_hash(transcript_hash, rsp.data, sizeof(SPDM_FINISH_RSP));
  rc = spdm_get_hash(transcript_hash, &transcript_digest);
  if (rc != 0) {
    goto cleanup;
  }

  rc = generate_finish_key(&ctx->dispatch_ctx.crypto_spec, session,
                           /*originator=*/SPDM_RESPONDER, &finish_key);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_validate_hmac(&ctx->dispatch_ctx.crypto_spec, &finish_key,
                          &transcript_digest, responder_verify_data);
  if (rc != 0) {
    goto cleanup;
  }

  // Finalize TH_2
  spdm_extend_hash(transcript_hash, responder_verify_data, hash_len);

  rc = spdm_get_hash(transcript_hash, &session->th_2);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&finish_key, 0, sizeof(finish_key));

  return rc;
}

int spdm_finish(SpdmRequesterContext* ctx, SpdmSessionParams* session,
                SpdmHash* transcript_hash) {
  byte_writer writer = {ctx->dispatch_ctx.scratch,
                        ctx->dispatch_ctx.scratch_size, 0};

  int rc = spdm_extend_hash_with_pub_key(
      &ctx->dispatch_ctx.crypto_spec, transcript_hash, &ctx->requester_pub_key);
  if (rc != 0) {
    return rc;
  }

  rc = write_finish(ctx, session, transcript_hash, &writer);
  if (rc != 0) {
    return rc;
  }

  buffer req = {writer.data, writer.bytes_written};
  buffer rsp;

  rc = spdm_send_secure_request(&ctx->dispatch_ctx, session,
                                SPDM_HANDSHAKE_PHASE, req, &rsp);
  if (rc != 0) {
    return rc;
  }

  return verify_finish_rsp(ctx, session, transcript_hash, rsp);
}
