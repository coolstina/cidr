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
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/coolstina/fireness"
)

// CIDRClassType type definition.
type CIDRClassType string

// String is implemented by any value that has a String method,
// which defines the ``native'' format for that value.
// The String method is used to print values passed as an operand
// to any format that accepts a string or to an unformatted printer
// such as Print.
func (C CIDRClassType) String() string {
	return string(C)
}

// CIDR class type related constant definition.
const (
	CIDRClassTypeOfAMask       CIDRClassType = "ANet"
	CIDRClassTypeOfBMask       CIDRClassType = "BNet"
	CIDRClassTypeOfCMask       CIDRClassType = "CNet"
	CIDRClassTypeOfUnknownMask CIDRClassType = "UnknownNet"
)

// Default route masks for IPv4.
var (
	classAMask = net.IPv4Mask(0xff, 0, 0, 0)
	classBMask = net.IPv4Mask(0xff, 0xff, 0, 0)
	classCMask = net.IPv4Mask(0xff, 0xff, 0xff, 0)
)

// CIDRMaskType returns the CIDR mask class type.
func CIDRMaskType(cidr string) (CIDRClassType, error) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return CIDRClassTypeOfUnknownMask, err
	}

	var r CIDRClassType

	switch ip.DefaultMask().String() {
	case classAMask.String():
		r = CIDRClassTypeOfAMask
	case classBMask.String():
		r = CIDRClassTypeOfBMask
	case classCMask.String():
		r = CIDRClassTypeOfCMask
	default:
		r = CIDRClassTypeOfUnknownMask
	}

	return r, err
}

// IPRangeToCIDR Convert IPv4 range into CIDR.
func IPRangeToCIDR(ipStart string, ipEnd string) ([]string, error) {
	var (
		cidr2mask = []uint32{
			0x00000000, 0x80000000, 0xC0000000,
			0xE0000000, 0xF0000000, 0xF8000000,
			0xFC000000, 0xFE000000, 0xFF000000,
			0xFF800000, 0xFFC00000, 0xFFE00000,
			0xFFF00000, 0xFFF80000, 0xFFFC0000,
			0xFFFE0000, 0xFFFF0000, 0xFFFF8000,
			0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
			0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00,
			0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0,
			0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
			0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
		}

		is    = fireness.IPv4ToInt(ipStart)
		ie    = fireness.IPv4ToInt(ipEnd)
		cidrs = make([]string, 0)
	)

	if is > ie {
		return nil, fmt.Errorf("start ip %s must be less than end ip %s", ipStart, ipEnd)
	}

	for ie >= is {
		maxSize := 32
		for maxSize > 0 {
			maskedBase := is & cidr2mask[maxSize-1]
			if maskedBase != is {
				break
			}
			maxSize--
		}

		x := math.Log(float64(ie-is+1)) / math.Log(2)
		maxDiff := 32 - int(math.Floor(x))
		if maxSize < maxDiff {
			maxSize = maxDiff
		}

		cidrs = append(cidrs, fireness.IntToIPv4(is)+"/"+strconv.Itoa(maxSize))
		is += uint32(math.Exp2(float64(32 - maxSize)))
	}

	return cidrs, nil
}

// CIDRToIPRange Convert CIDR range to IPv4 range.
func CIDRToIPRange(cidr string) (ipStart string, ipEnd string, err error) {
	return CIDRRangeToIPRange([]string{cidr})
}

// CIDRRangeToIPRange Convert CIDR range to IPv4 range.
func CIDRRangeToIPRange(cidrs []string) (ipStart string, ipEnd string, err error) {
	var ip uint32 // ip address
	var is uint32 // Start IP address range
	var ie uint32 // End IP address range

	for _, cidr := range cidrs {
		slice := strings.Split(cidr, "/")
		if len(slice) != 2 {
			return "", "", fmt.Errorf("cidr %s invalid", cidr)
		}

		ip = fireness.IPv4ToInt(slice[0])
		bits, err := strconv.ParseUint(slice[1], 10, 32)
		if err != nil {
			continue
		}

		if is == 0 || is > ip {
			is = ip
		}

		ip = ip | (0xFFFFFFFF >> bits)
		if ie < ip {
			ie = ip
		}
	}

	return fireness.IntToIPv4(is), fireness.IntToIPv4(ie), err
}
