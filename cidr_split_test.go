// Copyright 2021 helloshaohua <wu.shaohua@foxmail.com>;
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cidr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPCIDRSplit(t *testing.T) {
	grids := []struct {
		cidr     string
		expected int
	}{
		{
			cidr:     "192.168.0.0/24",
			expected: 255,
		},
		{
			cidr:     "192.168.0.200/24",
			expected: 55,
		},
		{
			cidr:     "172.172.0.0/16",
			expected: 65535,
		},
		{
			cidr:     "172.172.0.1/16",
			expected: 65534,
		},
		{
			cidr:     "172.172.1.0/16",
			expected: 65279,
		},
		{
			cidr:     "1.0.0.0/8",
			expected: 16777215,
		},
	}

	for _, grid := range grids {
		actual, err := CIDRSplitToStringSlice(grid.cidr)
		assert.Nil(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, grid.expected, len(actual))
	}
}
