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

#include "spdm_lite/common/utils.h"

#include <string.h>

void consume_from_buffer(buffer* buf, void* out, uint32_t len) {
  memcpy(out, buf->data, len);
  buf->data += len;
  buf->size -= len;
}

void spdm_init_writer(byte_writer* writer, void* data, size_t size) {
  writer->data = data;
  writer->size = size;
  writer->bytes_written = 0;
}

void buffer_to_writer(buffer buf, byte_writer* writer) {
  spdm_init_writer(writer, (uint8_t*)buf.data, buf.size);
}

uint8_t* reserve_from_writer(byte_writer* writer, size_t size) {
  size_t bytes_available;
  uint8_t* reserved_bytes;

  if (writer->bytes_written > writer->size) {
    return NULL;
  }

  bytes_available = writer->size - writer->bytes_written;

  if (bytes_available < size) {
    return NULL;
  }

  reserved_bytes = writer->data + writer->bytes_written;
  writer->bytes_written += size;

  return reserved_bytes;
}

int write_to_writer(byte_writer* writer, const void* data, size_t size) {
  void* reserved_bytes = reserve_from_writer(writer, size);

  if (reserved_bytes == NULL) {
    return -1;
  }

  memcpy(reserved_bytes, data, size);

  return 0;
}
