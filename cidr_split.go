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
	"math/big"
	"net"
)

// CIDRSplitToStringSlice Extract CIDR representation range to IP list.
func CIDRSplitToStringSlice(cidr string) ([]string, error) {
	mask, in, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var (
		result    []string
		ipMask    = mask.DefaultMask().String()
		beginning = big.NewInt(0).SetBytes(mask.To4()).Int64()
		stating   = big.NewInt(0).SetBytes(in.IP.To4()).Int64()
		excluding = beginning - stating
	)

	switch ipMask {
	case classAMask.String():
		buff := 1<<24 - int(excluding)
		result = make([]string, 0, buff)

		for i := 1; i < buff; i++ {
			beginning++
			result = append(result, Int64ToIPv4(beginning))
		}
	case classBMask.String():
		buff := 1<<16 - int(excluding)
		result = make([]string, 0, buff)

		for i := 1; i < buff; i++ {
			beginning++
			result = append(result, Int64ToIPv4(beginning))
		}
	case classCMask.String():
		buff := 1<<8 - int(excluding)
		result = make([]string, 0, buff)

		for i := 1; i < buff; i++ {
			beginning++
			result = append(result, Int64ToIPv4(beginning))
		}
	}

	return result, nil
}
