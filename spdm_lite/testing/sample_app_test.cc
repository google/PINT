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

#include "spdm_lite/samples/requester_app.h"

#include "gtest/gtest.h"

namespace {

TEST(SampleApp, RunSampleApp) {
  ASSERT_EQ(0, sample_app_initialize_spdm_session());

  const uint8_t start_num = 42;
  const uint8_t end_num = 170;

  uint8_t output;

  ASSERT_EQ(0, sample_app_rot128_byte(start_num, &output));
  EXPECT_EQ(output, end_num);

  ASSERT_EQ(0, sample_app_rot128_byte(end_num, &output));
  EXPECT_EQ(output, start_num);

  ASSERT_EQ(0, sample_app_end_spdm_session());
}

}  // namespace
