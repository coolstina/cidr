package cidr

import (
	"math/big"
	"net"
)

type Statistics struct {
	ip  net.IP
	net *net.IPNet
}

func (c *Statistics) IPCount() *big.Int {
	ones, bits := c.net.Mask.Size()
	return big.NewInt(0).Lsh(big.NewInt(1), uint(bits-ones))
}

func NewStatistics(cidr string) (*Statistics, error) {
	i, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	s := &Statistics{
		ip:  i,
		net: n,
	}

	return s, nil
}
