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
#include "spdm_lite/common/crypto_types.h"
#include "spdm_lite/common/error.h"
#include "spdm_lite/common/key_schedule.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/session.h"
#include "spdm_lite/common/session_types.h"
#include "spdm_lite/common/sign.h"
#include "spdm_lite/common/transcript.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/vendor_defined_pub_key.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/responder/responder.h"

static int handle_vendor_defined_req(SpdmResponderContext* ctx, buffer input,
                                     byte_writer* output) {
  int rc = spdm_check_get_pub_key_req(input);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  rc = spdm_write_get_pub_key_rsp(&ctx->crypto_spec, &ctx->responder_pub_key,
                                  ctx->negotiated_algs.hash_alg, output);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_UNSPECIFIED, output);
  }

  return 0;
}

static int verify_secured_messages_version(buffer opaque_data) {
  SPDM_OpaqueDataHeader header;

  if (opaque_data.size < sizeof(header)) {
    return -1;
  }

  consume_from_buffer(&opaque_data, &header, sizeof(header));

  for (int i = 0; i < header.total_elements; ++i) {
    buffer rest;
    uint8_t id;
    buffer vendor_id;
    buffer opaque_element_data;
    SPDM_SecuredMessagesSupportedVersions supported_versions;

    int rc = SpdmCheckOpaqueElement(&opaque_data, &rest, &id, &vendor_id.data,
                                    &vendor_id.size, &opaque_element_data.data,
                                    &opaque_element_data.size);
    if (rc != 0) {
      return -1;
    }

    opaque_data = rest;

    if (!(id == 0 && vendor_id.size == 0 &&
          opaque_element_data.size >= sizeof(supported_versions))) {
      continue;
    }

    consume_from_buffer(&opaque_element_data, &supported_versions,
                        sizeof(supported_versions));

    if (!(supported_versions.sm_data_version == 1 &&
          supported_versions.sm_data_id == 1)) {
      continue;
    }

    for (int j = 0; j < supported_versions.num_versions; ++j) {
      SPDM_VersionNumberEntry entry;
      if (opaque_element_data.size != sizeof(entry)) {
        return -1;
      }

      consume_from_buffer(&opaque_element_data, &entry, sizeof(entry));

      if (entry.major_version == 1 && entry.minor_version == 1 &&
          entry.alpha == 0) {
        return 0;
      }
    }
  }

  return -1;
}

// Everything but signature and responder_verify_data.
static int write_key_exchange_rsp_header(
    SpdmResponderContext* ctx, const SpdmSelfKeyExchangeParams* my_params,
    byte_writer* output, buffer* written) {
  SPDM_KEY_EXCHANGE_RSP rsp_msg = {};
  uint16_t opaque_data_length;
  SPDM_OpaqueDataHeader opaque_header = {};
  SPDM_OpaqueDataElement opaque_element = {};
  uint16_t opaque_element_data_len;
  SPDM_SecuredMessagesSelectedVersion selected_version = {};
  uint8_t opaque_data_padding_len;

  opaque_data_length = sizeof(opaque_header) + sizeof(opaque_element) +
                       sizeof(opaque_element_data_len) +
                       sizeof(selected_version);
  opaque_data_padding_len = (4 - (opaque_data_length % 4)) % 4;
  opaque_data_length += opaque_data_padding_len;

  uint16_t pub_key_size =
      spdm_get_dhe_pub_key_size(ctx->negotiated_algs.dhe_alg);

  written->size = sizeof(rsp_msg) + pub_key_size + sizeof(opaque_data_length) +
                  opaque_data_length;

  uint8_t* out = reserve_from_writer(output, written->size);
  if (out == NULL) {
    return -1;
  }

  written->data = out;

  rsp_msg.preamble.version = SPDM_THIS_VER;
  rsp_msg.preamble.request_response_code = SPDM_CODE_KEY_EXCHANGE_RSP;
  rsp_msg.param_1_heartbeat_period = 0;
  memcpy(rsp_msg.rsp_session_id, my_params->my_session_id_part, 2);
  rsp_msg.mut_auth_requested_encapsulated_flow = 1;

  int rc = ctx->crypto_spec.get_random(rsp_msg.random_data,
                                       sizeof(rsp_msg.random_data));
  if (rc != 0) {
    return rc;
  }

  opaque_header.total_elements = 1;
  opaque_element.id = 0;
  opaque_element.vendor_len = 0;
  opaque_element_data_len = sizeof(selected_version);
  selected_version.sm_data_version = 1;
  selected_version.sm_data_id = 0;
  selected_version.version.major_version = 1;
  selected_version.version.minor_version = 1;
  selected_version.version.update_version = 0;

  memcpy(out, &rsp_msg, sizeof(rsp_msg));
  out += sizeof(rsp_msg);

  // Exchange data
  memcpy(out, my_params->my_pub_key.data, pub_key_size);
  out += pub_key_size;

  // TODO(jeffandersen): Endianness
  memcpy(out, &opaque_data_length, sizeof(opaque_data_length));
  out += sizeof(opaque_data_length);

  memcpy(out, &opaque_header, sizeof(opaque_header));
  out += sizeof(opaque_header);

  memcpy(out, &opaque_element, sizeof(opaque_element));
  out += sizeof(opaque_element);

  memcpy(out, &opaque_element_data_len, sizeof(opaque_element_data_len));
  out += sizeof(opaque_element_data_len);

  memcpy(out, &selected_version, sizeof(selected_version));
  out += sizeof(selected_version);

  memset(out, 0, opaque_data_padding_len);
  out += opaque_data_padding_len;

  return 0;
}

static int extend_transcript_to_req(
    const SpdmCryptoSpec* crypto_spec, SpdmHashAlgorithm hash_alg,
    const SpdmNegotiationTranscript* negotiation_transcript,
    const SpdmAsymPubKey* pub_key, buffer key_exchange,
    SpdmHash* transcript_hash) {
  int rc = spdm_initialize_transcript_hash(
      crypto_spec, hash_alg, negotiation_transcript, transcript_hash);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_extend_hash_with_pub_key(crypto_spec, transcript_hash, pub_key);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(transcript_hash, key_exchange.data, key_exchange.size);

  return 0;
}

static int sign_key_exchange_msg(const SpdmCryptoSpec* crypto_spec,
                                 SpdmAsymAlgorithm asym_alg, void* priv_key_ctx,
                                 const SpdmHash* transcript,
                                 byte_writer* output, buffer* written) {
  SpdmHashResult message_hash;

  written->size = spdm_get_asym_signature_size(asym_alg);

  uint8_t* out = reserve_from_writer(output, written->size);
  if (out == NULL) {
    return -1;
  }

  written->data = out;

  int rc = spdm_get_hash(transcript, &message_hash);
  if (rc != 0) {
    return rc;
  }

  return spdm_sign(crypto_spec, asym_alg, priv_key_ctx,
                   /*my_role=*/SPDM_RESPONDER, &message_hash,
                   "key_exchange_rsp signing", out, written->size);
}

static int hmac_key_exchange_msg(const SpdmCryptoSpec* crypto_spec,
                                 const SpdmSessionParams* session,
                                 byte_writer* output, buffer* written) {
  SpdmMessageSecrets handshake_secrets;
  SpdmHashResult finish_key;
  SpdmHashResult hmac;

  int rc = spdm_generate_message_secrets(
      crypto_spec, session, SPDM_HANDSHAKE_PHASE, &handshake_secrets);
  if (rc != 0) {
    goto cleanup;
  }

  rc = spdm_generate_finished_key(crypto_spec,
                                  /*originator=*/SPDM_RESPONDER,
                                  &handshake_secrets, &finish_key);
  if (rc != 0) {
    goto cleanup;
  }

  uint16_t hmac_size =
      spdm_get_hash_size(session->info.negotiated_algs.hash_alg);
  uint8_t* out = reserve_from_writer(output, hmac_size);
  if (out == NULL) {
    rc = -1;
    goto cleanup;
  }

  rc = spdm_hmac(crypto_spec, &finish_key, &session->th_1, &hmac);
  if (rc != 0) {
    goto cleanup;
  }

  memcpy(out, hmac.data, hmac_size);

  written->data = out;
  written->size = hmac_size;

cleanup:
  memset(&handshake_secrets, 0, sizeof(handshake_secrets));
  memset(&finish_key, 0, sizeof(finish_key));

  return rc;
}

static int handle_key_exchange(SpdmResponderContext* ctx, buffer input,
                               byte_writer* output) {
  uint8_t requested_measurement_summary_hash;
  uint8_t slot_id;
  const uint8_t* req_session_id;
  bool session_policy_termination;
  buffer exchange_data;
  buffer opaque_data;

  memset(&ctx->session, 0, sizeof(ctx->session));

  exchange_data.size = spdm_get_dhe_pub_key_size(ctx->negotiated_algs.dhe_alg);

  int rc = SpdmCheckKeyExchange(
      &input, /*rest=*/NULL, /*exchange_data_len=*/exchange_data.size,
      &requested_measurement_summary_hash, &slot_id, &req_session_id,
      &session_policy_termination, &exchange_data.data, &opaque_data.data,
      &opaque_data.size);
  if (rc != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  if (slot_id != 0xFF) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  if (verify_secured_messages_version(opaque_data) != 0) {
    return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }

  SpdmDhePubKey their_pub_key;
  spdm_init_dhe_pub_key(&their_pub_key, ctx->negotiated_algs.dhe_alg);
  memcpy(their_pub_key.data, exchange_data.data, exchange_data.size);

  SpdmSelfKeyExchangeParams my_params;
  rc = spdm_generate_session_params(&ctx->crypto_spec,
                                    ctx->negotiated_algs.dhe_alg, &my_params);
  if (rc != 0) {
    goto cleanup;
  }

  spdm_generate_session_id(
      /*my_role=*/SPDM_RESPONDER, my_params.my_session_id_part, req_session_id,
      &ctx->session.params.info.session_id);

  ctx->session.params.info.negotiated_algs = ctx->negotiated_algs;

  rc = spdm_gen_dhe_secret(&ctx->crypto_spec, &my_params.my_priv_key,
                           &their_pub_key, &ctx->session.params.shared_key);
  if (rc != 0) {
    goto cleanup;
  }

  rc = extend_transcript_to_req(
      &ctx->crypto_spec, ctx->negotiated_algs.hash_alg,
      &ctx->negotiation_transcript, &ctx->responder_pub_key, input,
      &ctx->session.transcript_hash);
  if (rc != 0) {
    goto cleanup;
  }

  buffer written;

  rc = write_key_exchange_rsp_header(ctx, &my_params, output, &written);
  if (rc != 0) {
    goto cleanup;
  }

  spdm_extend_hash(&ctx->session.transcript_hash, written.data, written.size);

  rc = sign_key_exchange_msg(&ctx->crypto_spec,
                             ctx->negotiated_algs.asym_sign_alg,
                             ctx->responder_priv_key_ctx,
                             &ctx->session.transcript_hash, output, &written);
  if (rc != 0) {
    goto cleanup;
  }

  // Finalize TH1.
  spdm_extend_hash(&ctx->session.transcript_hash, written.data, written.size);
  rc = spdm_get_hash(&ctx->session.transcript_hash, &ctx->session.params.th_1);
  if (rc != 0) {
    goto cleanup;
  }

  rc = hmac_key_exchange_msg(&ctx->crypto_spec, &ctx->session.params, output,
                             &written);
  if (rc != 0) {
    goto cleanup;
  }

  spdm_extend_hash(&ctx->session.transcript_hash, written.data, written.size);

  ctx->state = STATE_MUTUAL_AUTH_NEED_REQUESTER_KEY;

cleanup:
  memset(&my_params, 0, sizeof(my_params));
  if (rc != 0) {
    memset(&ctx->session, 0, sizeof(ctx->session));
  }

  return rc;
}

int spdm_dispatch_request_waiting_for_key_exchange(SpdmResponderContext* ctx,
                                                   uint8_t code, buffer input,
                                                   byte_writer* output) {
  if (ctx->state != STATE_WAITING_FOR_KEY_EXCHANGE) {
    return -1;
  }

  switch (code) {
    case SPDM_CODE_VENDOR_DEFINED_REQUEST:
      return handle_vendor_defined_req(ctx, input, output);
    case SPDM_CODE_KEY_EXCHANGE:
      return handle_key_exchange(ctx, input, output);
    default:
      return spdm_write_error(SPDM_ERR_INVALID_REQUEST, output);
  }
}
