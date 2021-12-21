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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCIDRMaskType(t *testing.T) {
	grids := []struct {
		cidr     string
		err      error
		expected CIDRClassType
	}{
		{
			cidr:     "192.168.0.0/24",
			expected: CIDRClassTypeOfCMask,
		},
		{
			cidr:     "192.168.0.200/24",
			expected: CIDRClassTypeOfCMask,
		},
		{
			cidr:     "172.172.0.0/16",
			expected: CIDRClassTypeOfBMask,
		},
		{
			cidr:     "172.172.0.1/16",
			expected: CIDRClassTypeOfBMask,
		},
		{
			cidr:     "172.172.1.0/16",
			expected: CIDRClassTypeOfBMask,
		},
		{
			cidr:     "1.0.0.0/8",
			expected: CIDRClassTypeOfAMask,
		},
		{
			cidr:     "1.0.0.0/8",
			expected: CIDRClassTypeOfAMask,
		},
		{
			cidr:     "A.B.C.D/8",
			err:      &net.ParseError{Type: "CIDR address", Text: "A.B.C.D/8"},
			expected: CIDRClassTypeOfUnknownMask,
		},
	}

	for _, grid := range grids {
		actual, err := CIDRMaskType(grid.cidr)
		if err != nil {
			assert.Equal(t, grid.err, err)
			assert.Equal(t, grid.expected, actual)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, grid.expected, actual)
		}
	}
}

// https://www.ipaddressguide.com/cidr
func TestIPRangeToCIDR(t *testing.T) {
	grids := []struct {
		start    string
		end      string
		expected []string
	}{
		{
			start: "10.0.0.20",
			end:   "100.0.0.30",
			expected: []string{
				"10.0.0.20/30",
				"10.0.0.24/29",
				"10.0.0.32/27",
				"10.0.0.64/26",
				"10.0.0.128/25",
				"10.0.1.0/24",
				"10.0.2.0/23",
				"10.0.4.0/22",
				"10.0.8.0/21",
				"10.0.16.0/20",
				"10.0.32.0/19",
				"10.0.64.0/18",
				"10.0.128.0/17",
				"10.1.0.0/16",
				"10.2.0.0/15",
				"10.4.0.0/14",
				"10.8.0.0/13",
				"10.16.0.0/12",
				"10.32.0.0/11",
				"10.64.0.0/10",
				"10.128.0.0/9",
				"11.0.0.0/8",
				"12.0.0.0/6",
				"16.0.0.0/4",
				"32.0.0.0/3",
				"64.0.0.0/3",
				"96.0.0.0/6",
				"100.0.0.0/28",
				"100.0.0.16/29",
				"100.0.0.24/30",
				"100.0.0.28/31",
				"100.0.0.30/32",
			},
		},
		{
			start: "10.0.0.20",
			end:   "10.0.0.25",
			expected: []string{
				"10.0.0.20/30",
				"10.0.0.24/31",
			},
		},
		{
			start: "10.10.10.100",
			end:   "10.10.10.100",
			expected: []string{
				"10.10.10.100/32",
			},
		},
		{
			start: "10.10.10.100",
			end:   "10.10.10.102",
			expected: []string{
				"10.10.10.100/31",
				"10.10.10.102/32",
			},
		},
		{
			start: "192.168.1.0",
			end:   "192.168.1.255",
			expected: []string{
				"192.168.1.0/24",
			},
		},
	}

	for _, grid := range grids {
		actual, err := IPRangeToCIDR(grid.start, grid.end)
		assert.NoError(t, err)
		assert.Equal(t, grid.expected, actual)
	}
}

func TestCIDRToIPRange(t *testing.T) {
	grids := []struct {
		cidr          string
		expectedStart string
		expectedEnd   string
	}{
		{
			cidr:          "10.10.10.100/32",
			expectedStart: "10.10.10.100",
			expectedEnd:   "10.10.10.100",
		},
		{
			cidr:          "192.168.1.0/24",
			expectedStart: "192.168.1.0",
			expectedEnd:   "192.168.1.255",
		},
	}

	for _, grid := range grids {
		actualStart, actualEnd, err := CIDRToIPRange(grid.cidr)
		assert.NoError(t, err)
		assert.Equal(t, grid.expectedStart, actualStart)
		assert.Equal(t, grid.expectedEnd, actualEnd)
	}
}

func TestCIDRRangeToIPRange(t *testing.T) {
	grids := []struct {
		cidr          []string
		expectedStart string
		expectedEnd   string
	}{
		{
			cidr:          []string{"10.10.10.100/32"},
			expectedStart: "10.10.10.100",
			expectedEnd:   "10.10.10.100",
		},
		{
			cidr:          []string{"192.168.1.0/24", "10.10.10.100/31"},
			expectedStart: "10.10.10.100",
			expectedEnd:   "192.168.1.255",
		},
	}

	for _, grid := range grids {
		actualStart, actualEnd, err := CIDRRangeToIPRange(grid.cidr)
		assert.NoError(t, err)
		assert.Equal(t, grid.expectedStart, actualStart)
		assert.Equal(t, grid.expectedEnd, actualEnd)
	}
}
