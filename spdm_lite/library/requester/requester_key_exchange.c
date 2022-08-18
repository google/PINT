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
#include "spdm_lite/common/key_schedule.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/session.h"
#include "spdm_lite/common/sign.h"
#include "spdm_lite/common/transcript.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/common/version.h"
#include "spdm_lite/everparse/SPDMWrapper.h"
#include "spdm_lite/requester/requester.h"
#include "spdm_lite/requester/send_request.h"

static int write_key_exchange(const SpdmSelfKeyExchangeParams* params,
                              byte_writer* output) {
  SPDM_KEY_EXCHANGE key_exchange_msg = {};
  uint16_t opaque_data_length;
  SPDM_OpaqueDataHeader opaque_data_header = {};
  SPDM_OpaqueDataElement opaque_data_element = {};
  uint16_t opaque_element_data_len;
  SPDM_SecuredMessagesSupportedVersions supported_sm_versions = {};
  SPDM_VersionNumberEntry supported_sm_version = {};

  uint16_t pub_key_size = spdm_get_dhe_pub_key_size(params->my_pub_key.alg);

  uint32_t msg_len =
      sizeof(key_exchange_msg) + pub_key_size + sizeof(opaque_data_length) +
      sizeof(opaque_data_header) + sizeof(opaque_data_element) +
      sizeof(opaque_element_data_len) + sizeof(supported_sm_versions) +
      sizeof(supported_sm_version);

  key_exchange_msg.preamble.version = SPDM_THIS_VER;
  key_exchange_msg.preamble.request_response_code = SPDM_CODE_KEY_EXCHANGE;
  key_exchange_msg.param_2_slot_id = 0xFF;
  memcpy(key_exchange_msg.req_session_id, params->my_session_id_part,
         sizeof(params->my_session_id_part));

  opaque_data_length =
      sizeof(opaque_data_header) + sizeof(opaque_data_element) +
      sizeof(opaque_element_data_len) + sizeof(supported_sm_versions) +
      sizeof(supported_sm_version);

  opaque_data_header.total_elements = 1;
  opaque_element_data_len =
      sizeof(supported_sm_versions) + sizeof(supported_sm_version);

  supported_sm_versions.sm_data_version = 1;
  supported_sm_versions.sm_data_id = 1;
  supported_sm_versions.num_versions = 1;

  supported_sm_version.major_version = 1;
  supported_sm_version.minor_version = 1;
  supported_sm_version.update_version = 0;

  const uint8_t padding = (4 - (opaque_data_length % 4)) % 4;
  opaque_data_length += padding;
  msg_len += padding;

  uint8_t* out = reserve_from_writer(output, msg_len);
  if (out == NULL) {
    return -1;
  }

  memcpy(out, &key_exchange_msg, sizeof(key_exchange_msg));
  out += sizeof(key_exchange_msg);

  memcpy(out, params->my_pub_key.data, pub_key_size);
  out += pub_key_size;

  memcpy(out, &opaque_data_length, sizeof(opaque_data_length));
  out += sizeof(opaque_data_length);

  memcpy(out, &opaque_data_header, sizeof(opaque_data_header));
  out += sizeof(opaque_data_header);

  memcpy(out, &opaque_data_element, sizeof(opaque_data_element));
  out += sizeof(opaque_data_element);

  memcpy(out, &opaque_element_data_len, sizeof(opaque_element_data_len));
  out += sizeof(opaque_element_data_len);

  memcpy(out, &supported_sm_versions, sizeof(supported_sm_versions));
  out += sizeof(supported_sm_versions);

  memcpy(out, &supported_sm_version, sizeof(supported_sm_version));
  out += sizeof(supported_sm_version);

  memset(out, 0, padding);

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
    SPDM_SecuredMessagesSelectedVersion selected_version;

    int rc = SpdmCheckOpaqueElement(&opaque_data, &rest, &id, &vendor_id.data,
                                    &vendor_id.size, &opaque_element_data.data,
                                    &opaque_element_data.size);
    if (rc != 0) {
      return -1;
    }

    opaque_data = rest;

    if (!(id == 0 && vendor_id.size == 0 &&
          opaque_element_data.size >= sizeof(selected_version))) {
      continue;
    }

    consume_from_buffer(&opaque_element_data, &selected_version,
                        sizeof(selected_version));

    if (!(selected_version.sm_data_version == 1 &&
          selected_version.sm_data_id == 0)) {
      continue;
    }

    if (selected_version.version.major_version == 1 &&
        selected_version.version.minor_version == 1 &&
        selected_version.version.alpha == 0) {
      return 0;
    }
  }

  return -1;
}

static int validate_verify_data(const SpdmCryptoSpec* crypto_spec,
                                const SpdmSessionParams* session,
                                const uint8_t* responder_verify_data) {
  SpdmMessageSecrets handshake_secrets;
  SpdmHashResult finish_key;

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

  rc = spdm_validate_hmac(crypto_spec, &finish_key, &session->th_1,
                          responder_verify_data);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&handshake_secrets, 0, sizeof(handshake_secrets));
  memset(&finish_key, 0, sizeof(finish_key));

  return 0;
}

static int handle_key_exchange_rsp(const SpdmNegotiatedAlgs* negotiated_algs,
                                   const SpdmCryptoSpec* crypto_spec,
                                   buffer rsp, SpdmHash* transcript_hash,
                                   const SpdmSelfKeyExchangeParams* my_params,
                                   SpdmSessionParams* session) {
  uint8_t heartbeat_period;
  const uint8_t* rsp_session_id;
  uint8_t mut_auth_requested_flow;
  uint8_t slot_id;
  const uint8_t* rsp_exchange_data;
  const uint8_t* measurement_summary_hash;
  buffer opaque_data;
  const uint8_t* signature;
  const uint8_t* responder_verify_data;

  const uint16_t dhe_pub_key_size =
      spdm_get_dhe_pub_key_size(negotiated_algs->dhe_alg);
  const uint16_t hmac_size = spdm_get_hash_size(negotiated_algs->hash_alg);
  const uint16_t sig_size =
      spdm_get_asym_signature_size(negotiated_algs->asym_verify_alg);

  int rc = SpdmCheckKeyExchangeRsp(
      &rsp, /*rest=*/NULL, dhe_pub_key_size, hmac_size, sig_size,
      /*measurement_summary_hash_expected=*/false,
      /*responder_verify_data_expected=*/true, &heartbeat_period,
      &rsp_session_id, &mut_auth_requested_flow, &slot_id, &rsp_exchange_data,
      &measurement_summary_hash, &opaque_data.data, &opaque_data.size,
      &signature, &responder_verify_data);
  if (rc != 0) {
    return rc;
  }

  if (heartbeat_period != 0 || mut_auth_requested_flow != 1 || slot_id != 0) {
    return -1;
  }

  SpdmDhePubKey peer_ecdh_pub_key;
  spdm_init_dhe_pub_key(&peer_ecdh_pub_key, negotiated_algs->dhe_alg);

  memcpy(peer_ecdh_pub_key.data, rsp_exchange_data, dhe_pub_key_size);

  rc = spdm_validate_dhe_pubkey(crypto_spec, &peer_ecdh_pub_key);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(transcript_hash, rsp.data, rsp.size - sig_size - hmac_size);

  SpdmHashResult transcript_digest;
  rc = spdm_get_hash(transcript_hash, &transcript_digest);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_verify(crypto_spec, &session->info.peer_pub_key,
                   /*signer_role=*/SPDM_RESPONDER, &transcript_digest,
                   /*context=*/"key_exchange_rsp signing", signature, sig_size);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(transcript_hash, signature, sig_size);
  rc = spdm_get_hash(transcript_hash, &session->th_1);
  if (rc != 0) {
    return rc;
  }

  rc = validate_verify_data(crypto_spec, session, responder_verify_data);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(transcript_hash, responder_verify_data, hmac_size);

  rc = verify_secured_messages_version(opaque_data);
  if (rc != 0) {
    return rc;
  }

  spdm_generate_session_id(
      /*my_role=*/SPDM_REQUESTER, my_params->my_session_id_part, rsp_session_id,
      &session->info.session_id);

  rc = spdm_gen_dhe_secret(crypto_spec, &my_params->my_priv_key,
                           &peer_ecdh_pub_key, &session->shared_key);
  if (rc != 0) {
    return rc;
  }

  return 0;
}

int spdm_key_exchange(SpdmRequesterContext* ctx, SpdmSessionParams* session,
                      SpdmHash* transcript_hash) {
  SpdmSelfKeyExchangeParams my_params;

  int rc = spdm_generate_session_params(&ctx->dispatch_ctx.crypto_spec,
                                        session->info.negotiated_algs.dhe_alg,
                                        &my_params);
  if (rc != 0) {
    goto cleanup;
  }

  byte_writer writer = {ctx->dispatch_ctx.scratch,
                        ctx->dispatch_ctx.scratch_size, 0};

  rc = write_key_exchange(&my_params, &writer);
  if (rc != 0) {
    goto cleanup;
  }

  buffer req = {writer.data, writer.bytes_written};
  buffer rsp;

  rc = spdm_initialize_transcript_hash(
      &ctx->dispatch_ctx.crypto_spec, session->info.negotiated_algs.hash_alg,
      &ctx->negotiation_transcript, transcript_hash);
  if (rc != 0) {
    return rc;
  }

  rc = spdm_extend_hash_with_pub_key(&ctx->dispatch_ctx.crypto_spec,
                                     transcript_hash,
                                     &session->info.peer_pub_key);
  if (rc != 0) {
    return rc;
  }

  spdm_extend_hash(transcript_hash, req.data, req.size);

  rc =
      spdm_send_request(&ctx->dispatch_ctx, /*is_secure_msg=*/false, req, &rsp);
  if (rc != 0) {
    goto cleanup;
  }

  rc = handle_key_exchange_rsp(&session->info.negotiated_algs,
                               &ctx->dispatch_ctx.crypto_spec, rsp,
                               transcript_hash, &my_params, session);
  if (rc != 0) {
    goto cleanup;
  }

cleanup:
  memset(&my_params, 0, sizeof(my_params));

  return rc;
}
