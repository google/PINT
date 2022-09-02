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
#include "spdm_lite/common/key_schedule.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/sign.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/responder/responder.h"

static int generate_finish_key(const SpdmCryptoSpec* crypto_spec,
                               const SpdmSessionParams* session,
                               SPDMRole originator, SpdmHashResult* key) {
  SpdmMessageSecrets handshake_secrets;

  int rc = spdm_generate_message_secrets(
      crypto_spec, session, SPDM_HANDSHAKE_PHASE, &handshake_secrets);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_generate_finished_key(crypto_spec, originator, &handshake_secrets,
                                  key);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&handshake_secrets, 0, sizeof(handshake_secrets));

  return rc;
}

static int validate_finish_hmac(const SpdmCryptoSpec* crypto_spec,
                                const SpdmSessionParams* session,
                                const SpdmHashResult* transcript_hash,
                                const uint8_t* mac) {
  SpdmHashResult finish_key;

  int rc = generate_finish_key(crypto_spec, session,
                               /*originator=*/SPDM_REQUESTER, &finish_key);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_validate_hmac(crypto_spec, &finish_key, transcript_hash, mac);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&finish_key, 0, sizeof(finish_key));

  return rc;
}

static int write_finish_rsp(const SpdmCryptoSpec* crypto_spec,
                            const SpdmSessionParams* session,
                            SpdmHash* transcript_hash, byte_writer* output) {
  SPDM_FINISH_RSP msg;

  memset(&msg, 0, sizeof(msg));

  msg.preamble.version = SPDM_THIS_VER;
  msg.preamble.request_response_code = SPDM_CODE_FINISH_RSP;

  uint8_t* out = reserve_from_writer(output, sizeof(msg));
  if (out == NULL) {
    return -1;
  }

  memcpy(out, &msg, sizeof(msg));

  spdm_extend_hash(transcript_hash, &msg, sizeof(msg));

  return 0;
}

int spdm_dispatch_request_waiting_for_finish(SpdmResponderContext* ctx,
                                             uint8_t code, buffer input,
                                             byte_writer* output) {
  if (ctx->state != STATE_MUTUAL_AUTH_WAITING_FOR_FINISH) {
    return -1;
  }

  bool sig_included;
  uint8_t slot_id;
  const uint8_t *sig, *verify_data;

  const uint16_t hash_len = spdm_get_hash_size(ctx->negotiated_algs.hash_alg);
  const uint16_t sig_len =
      spdm_get_asym_signature_size(ctx->negotiated_algs.asym_verify_alg);

  int rc = SpdmCheckFinish(&input, /*rest=*/NULL, hash_len, sig_len,
                           &sig_included, &slot_id, &sig, &verify_data);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  if (!sig_included) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  if (slot_id != 0xFF) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  SpdmHash transcript_hash = ctx->session.transcript_hash;

  rc = spdm_extend_hash_with_pub_key(&ctx->crypto_spec, &transcript_hash,
                                     &ctx->session.params.info.peer_pub_key);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(&transcript_hash, input.data, sizeof(SPDM_FINISH));

  SpdmHashResult transcript_hash_result;
  rc = spdm_get_hash(&transcript_hash, &transcript_hash_result);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_verify(&ctx->crypto_spec, &ctx->session.params.info.peer_pub_key,
                   /*signer_role=*/SPDM_REQUESTER, &transcript_hash_result,
                   /*context=*/"finish signing", sig, sig_len);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  spdm_extend_hash(&transcript_hash, sig, sig_len);
  rc = spdm_get_hash(&transcript_hash, &transcript_hash_result);
  if (rc != 0) {
    return rc;
  }

  rc = validate_finish_hmac(&ctx->crypto_spec, &ctx->session.params,
                            &transcript_hash_result, verify_data);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  spdm_extend_hash(&transcript_hash, verify_data, hash_len);

  rc = write_finish_rsp(&ctx->crypto_spec, &ctx->session.params,
                        &transcript_hash, output);
  if (rc != 0) {
    return rc;
  }

  // Finalize TH2.
  rc = spdm_get_hash(&transcript_hash, &ctx->session.params.th_2);
  if (rc != 0) {
    return rc;
  }

  ctx->session.transcript_hash = transcript_hash;
  ctx->state = STATE_SESSION_ESTABLISHED;

  return 0;
}
