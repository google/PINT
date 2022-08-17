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

#include "responder/responder.h"

#include <stdbool.h>
#include <string.h>

#include "common/crypto.h"
#include "common/error.h"
#include "common/key_schedule.h"
#include "common/messages.h"
#include "common/session.h"
#include "common/session_types.h"
#include "common/utils.h"
#include "common/version.h"

// State-specific message handlers.

typedef int (*spdm_dispatch_request_fn)(SpdmResponderContext* ctx, uint8_t code,
                                        buffer input, byte_writer* output);

int spdm_dispatch_request_waiting_for_get_version(SpdmResponderContext* ctx,
                                                  uint8_t code, buffer input,
                                                  byte_writer* output);
int spdm_dispatch_request_waiting_for_get_capabilities(
    SpdmResponderContext* ctx, uint8_t code, buffer input, byte_writer* output);
int spdm_dispatch_request_waiting_for_negotiate_algorithms(
    SpdmResponderContext* ctx, uint8_t code, buffer input, byte_writer* output);
int spdm_dispatch_request_waiting_for_key_exchange(SpdmResponderContext* ctx,
                                                   uint8_t code, buffer input,
                                                   byte_writer* output);
int spdm_dispatch_request_need_requester_key(SpdmResponderContext* ctx,
                                             uint8_t code, buffer input,
                                             byte_writer* output);
int spdm_dispatch_request_waiting_for_finish(SpdmResponderContext* ctx,
                                             uint8_t code, buffer input,
                                             byte_writer* output);
int spdm_dispatch_request_session_established(SpdmResponderContext* ctx,
                                              uint8_t code, buffer input,
                                              byte_writer* output,
                                              bool* end_session);

static void reset_context_state(SpdmResponderContext* ctx) {
  ctx->state = STATE_WAITING_FOR_GET_VERSION;
  memset(&ctx->negotiation_transcript, 0, sizeof(ctx->negotiation_transcript));
  memset(&ctx->requester_caps, 0, sizeof(ctx->requester_caps));
  memset(&ctx->negotiated_algs, 0, sizeof(ctx->negotiated_algs));
  memset(&ctx->session, 0, sizeof(ctx->session));
}

int spdm_initialize_responder_context(
    SpdmResponderContext* ctx, const SpdmCryptoSpec* crypto_spec,
    SpdmCapabilities responder_caps, const SpdmAsymPubKey* responder_pub_key,
    void* responder_priv_key_ctx,
    spdm_app_dispatch_request_fn app_dispatch_fn) {
  memset(ctx, 0, sizeof(*ctx));

  ctx->crypto_spec = *crypto_spec;

  ctx->responder_caps = responder_caps;

  int rc = spdm_validate_asym_pubkey(crypto_spec, responder_pub_key);
  if (rc != 0) {
    return rc;
  }

  ctx->responder_pub_key = *responder_pub_key;
  ctx->responder_priv_key_ctx = responder_priv_key_ctx;
  ctx->app_dispatch_fn = app_dispatch_fn;

  return 0;
}

static int get_req_preamble(buffer input, SPDM_Preamble* preamble) {
  if (input.size < sizeof(*preamble)) {
    return -1;
  }

  memcpy(preamble, input.data, sizeof(*preamble));

  return 0;
}

static bool is_get_version(const SPDM_Preamble* preamble) {
  return preamble->version == 0x10 &&
         preamble->request_response_code == SPDM_CODE_GET_VERSION;
}

static int spdm_dispatch_request_internal(SpdmResponderContext* ctx,
                                          const SPDM_Preamble* preamble,
                                          buffer input, byte_writer* output,
                                          bool* end_session) {
  *end_session = false;

  bool valid_version;
  if (preamble->request_response_code == SPDM_CODE_GET_VERSION) {
    valid_version = (preamble->version == 0x10);
  } else {
    valid_version = (preamble->version == SPDM_THIS_VER);
  }

  if (!valid_version) {
    return spdm_write_error(SPDM_ERR_VERSION_MISMATCH, output);
  }

  spdm_dispatch_request_fn fn = NULL;

  switch (ctx->state) {
    case STATE_WAITING_FOR_GET_VERSION:
      fn = spdm_dispatch_request_waiting_for_get_version;
      break;
    case STATE_WAITING_FOR_GET_CAPABILITIES:
      fn = spdm_dispatch_request_waiting_for_get_capabilities;
      break;
    case STATE_WAITING_FOR_NEGOTIATE_ALGORITHMS:
      fn = spdm_dispatch_request_waiting_for_negotiate_algorithms;
      break;
    case STATE_WAITING_FOR_KEY_EXCHANGE:
      fn = spdm_dispatch_request_waiting_for_key_exchange;
      break;
    case STATE_MUTUAL_AUTH_NEED_REQUESTER_KEY:
      fn = spdm_dispatch_request_need_requester_key;
      break;
    case STATE_MUTUAL_AUTH_WAITING_FOR_FINISH:
      fn = spdm_dispatch_request_waiting_for_finish;
      break;
    case STATE_SESSION_ESTABLISHED:
      // Special-case this to pass the `end_session` flag.
      return spdm_dispatch_request_session_established(
          ctx, preamble->request_response_code, input, output, end_session);
    default:
      return -1;
  }

  return fn(ctx, preamble->request_response_code, input, output);
}

static SpdmSessionPhase get_session_phase(SpdmResponderState state) {
  switch (state) {
    case STATE_MUTUAL_AUTH_NEED_REQUESTER_KEY:
    case STATE_MUTUAL_AUTH_WAITING_FOR_FINISH:
      return SPDM_HANDSHAKE_PHASE;
    case STATE_SESSION_ESTABLISHED:
      return SPDM_DATA_PHASE;
    default:
      return SPDM_NO_SESSION;
  }
}

static int get_session_keys(SpdmResponderContext* ctx, SpdmSessionPhase phase,
                            SpdmSessionAeadKeys* keys) {
  SpdmMessageSecrets secrets;
  int rc = spdm_generate_message_secrets(&ctx->crypto_spec,
                                         &ctx->session.params, phase, &secrets);

  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_generate_aead_keys(&ctx->crypto_spec, ctx->negotiated_algs.aead_alg,
                               &secrets, ctx->session.params.req_seq_num,
                               ctx->session.params.rsp_seq_num, keys);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&secrets, 0, sizeof(secrets));

  return rc;
}

int spdm_dispatch_request(SpdmResponderContext* ctx, const uint8_t* req,
                          size_t req_size, uint8_t* rsp, size_t* rsp_size) {
  buffer input = {req, req_size};
  byte_writer output = {rsp, *rsp_size, 0};

  SPDM_Preamble preamble;
  int rc = get_req_preamble(input, &preamble);
  if (rc == -1) {
    rc = spdm_write_error(SPDM_ERR_INVALID_REQUEST, &output);
    goto cleanup;
  }

  // GET_VERSION (when called outside a secure session) always resets the state
  // machine.
  if (is_get_version(&preamble)) {
    reset_context_state(ctx);
  }

  if (get_session_phase(ctx->state) == SPDM_NO_SESSION) {
    bool unused_end_session;
    rc = spdm_dispatch_request_internal(ctx, &preamble, input, &output,
                                        &unused_end_session);
  } else {
    rc = spdm_write_error(SPDM_ERR_SESSION_REQURED, &output);
  }

cleanup:
  *rsp_size = output.bytes_written;

  return rc;
}

int spdm_dispatch_secure_request(SpdmResponderContext* ctx, const uint8_t* req,
                                 size_t req_size, uint8_t* rsp,
                                 size_t* rsp_size) {
  SPDM_Preamble preamble;
  SpdmSessionPhase phase;
  SpdmSessionAeadKeys keys;
  bool end_session = false;
  buffer input = {req, req_size};
  byte_writer output = {rsp, *rsp_size, 0};

  phase = get_session_phase(ctx->state);
  if (phase == SPDM_NO_SESSION) {
    return -1;
  }

  int rc = get_session_keys(ctx, phase, &keys);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_decrypt_secure_message(
      &ctx->crypto_spec, &ctx->session.params.info.session_id,
      ctx->session.params.req_seq_num, &keys.req_keys, &input);
  if (rc != 0) {
    goto cleanup;
  }

  uint8_t* record_header =
      reserve_from_writer(&output, sizeof(SPDM_SecuredMessageRecord));
  if (record_header == NULL) {
    rc = -1;
    goto cleanup;
  }

  rc = get_req_preamble(input, &preamble);
  if (rc == -1) {
    rc = spdm_write_error(SPDM_ERR_INVALID_REQUEST, &output);
  } else {
    rc = spdm_dispatch_request_internal(ctx, &preamble, input, &output,
                                        &end_session);
  }

  if (rc != 0) {
    goto cleanup;
  }

  buffer response = {output.data + sizeof(SPDM_SecuredMessageRecord),
                     output.bytes_written - sizeof(SPDM_SecuredMessageRecord)};

  rc = spdm_encrypt_secure_message(
      &ctx->crypto_spec, &ctx->session.params.info.session_id,
      ctx->session.params.rsp_seq_num, &keys.rsp_keys, record_header, response,
      &output);
  if (rc != 0) {
    goto cleanup;
  }

  if (!end_session) {
    ctx->session.params.req_seq_num++;
    ctx->session.params.rsp_seq_num++;
  } else {
    reset_context_state(ctx);
  }

  *rsp_size = output.bytes_written;

cleanup:
  memset(&keys, 0, sizeof(keys));

  return rc;
}
