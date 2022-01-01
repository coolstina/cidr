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
	"strconv"
	"strings"

	"github.com/coolstina/expression"
)

// CIDRIsContainsIPManualImpl Checks whether the IP is within a CIDR representation range.
func CIDRIsContainsIPManualImpl(addr, cidr string) bool {
	ipv4Addr := net.ParseIP(addr)
	if ipv4Addr == nil {
		return false
	}

	parse, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	ones, err := strconv.Atoi(strings.Split(cidr, "/")[1])
	if err != nil {
		return false
	}

	ipv4Mask := net.CIDRMask(ones, 32)
	original := ipv4Addr.Mask(ipv4Mask).String()
	destination := parse.Mask(ipv4Mask).String()
	if original == destination {
		return true
	}

	return false
}

// CIDRIsContainsIP reports whether the network includes ip.
func CIDRIsContainsIP(ip, cidr string) bool {
	ipv4Addr := net.ParseIP(ip)
	if ipv4Addr == nil {
		return false
	}

	_, ni, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	return ni.Contains(ipv4Addr)
}

// IsCIDR Check whether the IP is in CIDR format.
func IsCIDR(ip string) bool {
	ok, _ := expression.RegularMatchString(`\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}\/\d+`, ip)
	return ok
}
