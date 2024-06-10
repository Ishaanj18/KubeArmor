package policy_enforcement_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestPolicyEnforcement(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "PolicyEnforcement Suite")
}
