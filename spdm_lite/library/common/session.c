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

#include "spdm_lite/common/session.h"

#include <string.h>

#include "spdm_lite/common/crypto.h"
#include "spdm_lite/common/messages.h"
#include "spdm_lite/common/utils.h"
#include "spdm_lite/everparse/SPDMWrapper.h"

int spdm_generate_session_params(const SpdmCryptoSpec* spec,
                                 SpdmDheAlgorithm alg,
                                 SpdmSelfKeyExchangeParams* my_params) {
  int rc = spdm_get_random(spec, my_params->my_session_id_part,
                           sizeof(my_params->my_session_id_part));
  if (rc != 0) {
    return rc;
  }

  return spdm_gen_dhe_keypair(spec, alg, &my_params->my_priv_key,
                              &my_params->my_pub_key);
}

void spdm_generate_session_id(SPDMRole my_role, const uint8_t my_part[2],
                              const uint8_t their_part[2],
                              SpdmSessionId* session_id) {
  const uint8_t *first_part, *second_part;

  if (my_role == SPDM_REQUESTER) {
    first_part = my_part;
    second_part = their_part;
  } else {
    first_part = their_part;
    second_part = my_part;
  }

  memcpy(session_id->id, first_part, 2);
  memcpy(session_id->id + 2, second_part, 2);
}

int spdm_encrypt_secure_message(const SpdmCryptoSpec* spec,
                                const SpdmSessionId* session_id,
                                uint64_t seq_num, const SpdmAeadKeys* keys,
                                uint8_t* header_buf, buffer input,
                                byte_writer* footer) {
  uint8_t rand_len;
  int rc = spdm_get_random(spec, &rand_len, 1);
  if (rc != 0) {
    return rc;
  }

  // 0-16 bytes of randomness.
  rand_len &= 0x0F;

  uint8_t* footer_bytes =
      reserve_from_writer(footer, rand_len + AES_GCM_MAC_SIZE);
  if (footer_bytes == NULL) {
    return -1;
  }

  rc = spdm_get_random(spec, footer_bytes, rand_len);
  if (rc != 0) {
    return rc;
  }

  uint8_t* mac = footer_bytes + rand_len;

  SPDM_SecuredMessageRecord header = {};

  memcpy(&header.session_id, session_id->id, sizeof(header.session_id));
  header.seq_num = seq_num;
  header.len =
      sizeof(header.app_data_len) + input.size + rand_len + AES_GCM_MAC_SIZE;
  header.app_data_len = input.size;

  memcpy(header_buf, &header, sizeof(header));

  uint8_t* aad = header_buf;
  size_t aad_size = sizeof(header) - sizeof(header.app_data_len);

  // Encrypt app_data_len along with app data.
  uint8_t* plaintext = aad + aad_size;
  size_t plaintext_size = sizeof(header.app_data_len) + input.size + rand_len;

  rc = spdm_aes_gcm_encrypt(spec, &keys->key, &keys->iv, plaintext,
                            plaintext_size, aad, aad_size, plaintext, mac,
                            AES_GCM_MAC_SIZE);

  return rc;
}

int spdm_decrypt_secure_message(const SpdmCryptoSpec* spec,
                                const SpdmSessionId* session_id,
                                uint64_t seq_num, const SpdmAeadKeys* keys,
                                buffer* message) {
  uint32_t record_session_id;
  const uint8_t* seq_num_ptr;
  const uint8_t* ciphertext;
  uint32_t ciphertext_size;
  const uint8_t* mac;

  int rc = SpdmCheckSecuredMessageRecord(
      message, /*rest=*/NULL,
      /*seq_num_len=*/sizeof(uint64_t), /*mac_len=*/AES_GCM_MAC_SIZE,
      &record_session_id, &seq_num_ptr, &ciphertext, &ciphertext_size,
      &mac);
  if (rc != 0) {
    return rc;
  }

  if (memcmp(&record_session_id, session_id->id, sizeof(record_session_id)) !=
      0) {
    return -1;
  }

  // TODO(jeffandersen): endianness.
  if (memcmp(seq_num_ptr, &seq_num, sizeof(seq_num)) != 0) {
    return -1;
  }

  buffer aad = {message->data, sizeof(*session_id) + sizeof(uint64_t) + 2};

  uint8_t* plaintext = (uint8_t*)message->data;

  rc = spdm_aes_gcm_decrypt(spec, &keys->key, &keys->iv, ciphertext,
                            ciphertext_size, aad.data, aad.size, mac,
                            AES_GCM_MAC_SIZE, plaintext);
  if (rc != 0) {
    return rc;
  }

  // Strip off app_data_len and randomness.
  uint16_t app_data_len;
  if (ciphertext_size < sizeof(app_data_len)) {
    return -1;
  }

  // TODO(jeffandersen): endianness.
  memcpy(&app_data_len, message->data, sizeof(app_data_len));

  if ((ciphertext_size - sizeof(app_data_len)) < app_data_len) {
    return -1;
  }

  uint8_t* message_start = plaintext + sizeof(app_data_len);

  message->data = message_start;
  message->size = app_data_len;

  return 0;
}
