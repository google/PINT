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

#ifndef SPDM_LITE_COMMON_UTILS_H_
#define SPDM_LITE_COMMON_UTILS_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

typedef enum {
  SPDM_REQUESTER,
  SPDM_RESPONDER,
} SPDMRole;

typedef struct {
  const uint8_t* data;
  uint32_t size;
} buffer;

// This structure holds the details of a "byte writer", an object used to write
// bytes to a fixed size buffer.
typedef struct {
  uint8_t* data;
  uint32_t size;
  uint32_t bytes_written;
} byte_writer;

// Copy `len` bytes from `buf` into `out`, reducing its size by `len`. Both
// `buf` and `out` must have `len` bytes available.
void consume_from_buffer(buffer* buf, void* out, uint32_t len);

// Initializes `writer` to point to a given buffer of data.
void init_writer(byte_writer* writer, void* data, size_t size);
void buffer_to_writer(buffer buf, byte_writer* writer);

// Reserves `size` bytes for writing. Returns a pointer to the reserved bytes,
// or NULL if there was insufficient room in `writer`.
uint8_t* reserve_from_writer(byte_writer* writer, size_t size);

// Writes `size` bytes from `data` to the next bytes in `writer`. Returns 0 on
// success, or an error code if there are not `size` bytes available in the
// buffer for writing.
int write_to_writer(byte_writer* writer, const void* data, size_t size);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SPDM_LITE_COMMON_UTILS_H_
