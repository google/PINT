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

#include <ostream>
#include <vector>

#include "common/messages.h"
#include "everparse/SPDMWrapper.h"

#include "gtest/gtest.h"

namespace {

TEST(SpdmTest, ParseVersion) {
  std::vector<uint8_t> buf{
      0x12,        // version
      0x04,        // request_response_code
      0x00,        // param_1
      0x00,        // param_2
      0x00,        // reserved
      0x02,        // Two version entries
      0x23, 0x45,  // v4.5.2.3
      0x67, 0x89,  // v8.9.6.7
  };

  buffer input{buf.data(), static_cast<uint32_t>(buf.size())};

  uint8_t entry_count;
  const uint8_t *entries;

  int res = SpdmCheckVersion(&input, /*rest=*/nullptr, &entry_count, &entries);
  ASSERT_EQ(res, 0);

  ASSERT_EQ(entry_count, 2);
  ASSERT_EQ(entries, buf.data() + 6);

  SPDM_VersionNumberEntry entry;
  memcpy(&entry, entries, sizeof(entry));
  EXPECT_EQ(entry.major_version, 4);
  EXPECT_EQ(entry.minor_version, 5);
  EXPECT_EQ(entry.update_version, 2);
  EXPECT_EQ(entry.alpha, 3);

  memcpy(&entry, entries + sizeof(entry), sizeof(entry));
  EXPECT_EQ(entry.major_version, 8);
  EXPECT_EQ(entry.minor_version, 9);
  EXPECT_EQ(entry.update_version, 6);
  EXPECT_EQ(entry.alpha, 7);
}

TEST(SpdmTest, ParseVersionFailure) {
  std::vector<uint8_t> buf{
      0x12,  // version
      0x04,  // request_response_code
      0x00,  // param_1
      0x00,  // param_2
      0x00,  // reserved
      0x01,  // One version entry
  };         // But no entries

  buffer input{buf.data(), static_cast<uint32_t>(buf.size())};

  uint8_t entry_count;
  const uint8_t *entries;

  int res = SpdmCheckVersion(&input, /*rest=*/nullptr, &entry_count, &entries);
  EXPECT_EQ(res, -1);

  buf[5] = 0;  // Now we're saying there's no entries.
  res = SpdmCheckVersion(&input, /*rest=*/nullptr, &entry_count, &entries);
  EXPECT_EQ(res, 0);
}

}  // namespace
