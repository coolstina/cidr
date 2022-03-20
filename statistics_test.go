package cidr

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestStatisticsSuite(t *testing.T) {
	suite.Run(t, &StatisticsSuite{})
}

type StatisticsSuite struct {
	suite.Suite
	statistics *Statistics
}

func (suite *StatisticsSuite) BeforeTest(suiteName, testName string) {
	var err error

	suite.statistics, err = NewStatistics("10.10.10.0/24")
	assert.NoError(suite.T(), err)
}

func (suite *StatisticsSuite) Test_IPCount() {
	count := suite.statistics.IPCount()
	assert.Equal(suite.T(), int64(256), count.Int64())
}
