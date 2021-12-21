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

func TestCIDRIsContainsIPManualImpl(t *testing.T) {
	grids := []struct {
		ip       string
		cidr     string
		expected bool
	}{
		{
			ip:       "192.168.0.103",
			cidr:     "192.168.0.0/1",
			expected: true,
		},
		{
			ip:       "190.168.0.103",
			cidr:     "192.168.0.0/2",
			expected: false,
		},
		{
			ip:       "194.168.0.103",
			cidr:     "192.168.0.0/2",
			expected: true,
		},
		{
			ip:       "192.255.255.103",
			cidr:     "192.168.0.0/4",
			expected: true,
		},
		{
			ip:       "192.255.255.103",
			cidr:     "192.168.0.0/8",
			expected: true,
		},
		{
			ip:       "193.255.255.103",
			cidr:     "192.168.0.0/8",
			expected: false,
		},
		{
			ip:       "192.255.255.103",
			cidr:     "192.168.0.0/16",
			expected: false,
		},
		{
			ip:       "192.168.255.103",
			cidr:     "192.168.0.0/16",
			expected: true,
		},
		{
			ip:       "192.168.255.103",
			cidr:     "192.168.0.0/24",
			expected: false,
		},
		{
			ip:       "192.168.0.103",
			cidr:     "192.168.0.0/24",
			expected: true,
		},
		{
			ip:       "192.168.10.103",
			cidr:     "192.168.10.0/24",
			expected: true,
		},
		{
			ip:       "192.168.10.1",
			cidr:     "192.168.10.0/32",
			expected: false,
		},
		{
			ip:       "192.168.10.0",
			cidr:     "192.168.10.0/32",
			expected: true,
		},
		{
			ip:       "192.168.10.255",
			cidr:     "192.168.10.0/24",
			expected: true,
		},
		{
			ip:       "192.168.10.256",
			cidr:     "192.168.10.0/24",
			expected: false,
		},
		{
			ip:       "172.172.255.0",
			cidr:     "172.172.1.0/16",
			expected: true,
		},
	}

	for _, grid := range grids {
		actual := CIDRIsContainsIPManualImpl(grid.ip, grid.cidr)
		assert.Equal(t, grid.expected, actual)
	}
}

func TestCIDRIsContainsIP(t *testing.T) {
	grids := []struct {
		ip       string
		cidr     string
		expected bool
	}{
		{
			ip:       "192.168.0.103",
			cidr:     "192.168.0.0/1",
			expected: true,
		},
		{
			ip:       "190.168.0.103",
			cidr:     "192.168.0.0/2",
			expected: false,
		},
		{
			ip:       "194.168.0.103",
			cidr:     "192.168.0.0/2",
			expected: true,
		},
		{
			ip:       "192.255.255.103",
			cidr:     "192.168.0.0/4",
			expected: true,
		},
		{
			ip:       "192.255.255.103",
			cidr:     "192.168.0.0/8",
			expected: true,
		},
		{
			ip:       "193.255.255.103",
			cidr:     "192.168.0.0/8",
			expected: false,
		},
		{
			ip:       "192.255.255.103",
			cidr:     "192.168.0.0/16",
			expected: false,
		},
		{
			ip:       "192.168.255.103",
			cidr:     "192.168.0.0/16",
			expected: true,
		},
		{
			ip:       "192.168.255.103",
			cidr:     "192.168.0.0/24",
			expected: false,
		},
		{
			ip:       "192.168.0.103",
			cidr:     "192.168.0.0/24",
			expected: true,
		},
		{
			ip:       "192.168.10.103",
			cidr:     "192.168.10.0/24",
			expected: true,
		},
		{
			ip:       "192.168.10.1",
			cidr:     "192.168.10.0/32",
			expected: false,
		},
		{
			ip:       "192.168.10.0",
			cidr:     "192.168.10.0/32",
			expected: true,
		},
		{
			ip:       "192.168.10.255",
			cidr:     "192.168.10.0/24",
			expected: true,
		},
		{
			ip:       "192.168.10.256",
			cidr:     "192.168.10.0/24",
			expected: false,
		},
		{
			ip:       "192.168.10.0",
			cidr:     "192.168.10.0/32",
			expected: true,
		},
		{
			ip:       "172.172.255.0",
			cidr:     "172.172.1.0/16",
			expected: true,
		},
	}

	for _, grid := range grids {
		actual := CIDRIsContainsIP(grid.ip, grid.cidr)
		assert.Equal(t, grid.expected, actual)
	}
}
