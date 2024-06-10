package policy_enforcement_test

import (
	"fmt"
	"os/exec"
	"time"

	. "github.com/kubearmor/KubeArmor/tests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = BeforeSuite(func() {
	// delete all HSPs
	DeleteAllHsp()
})

var _ = AfterSuite(func() {
	// delete all HSPs
	DeleteAllHsp()
})

var _ = Describe("HSP", func() {

	BeforeEach(func() {
		time.Sleep(1 * time.Second)
	})

	AfterEach(func() {
		KarmorLogStop()
		err := DeleteAllHsp()
		Expect(err).To(BeNil())
		// wait for policy deletion
		time.Sleep(2 * time.Second)
	})

	Describe("KubeArmorHostPolicy Tests", func() {
		Context("Test hsp-kubearmor-dev-next-proc-path-block", func() {
			It("Should block execution of /usr/bin/diff", func() {
				err := K8sApplyFile("res/hsp-kubearmor-dev-next-proc-path-block.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "Process", "")
				Expect(err).To(BeNil())

				out, err := exec.Command("/usr/bin/diff", "--help").CombinedOutput()

				fmt.Printf("---START---\n%s---END---\n", string(out))
				Expect(err).To(HaveOccurred())

				// check policy violation alert
				_, alerts, err := KarmorGetLogs(5*time.Second, 1)
				Expect(err).To(BeNil())
				Expect(len(alerts)).To(BeNumerically(">=", 1))
				Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-next-proc-path-block"))
				Expect(alerts[0].Action).To(Equal("Block"))
			})
		})

		Context("Test hsp-kubearmor-dev-next-file-path-audit", func() {
			It("Should audit access to /etc/passwd", func() {
				err := K8sApplyFile("res/hsp-kubearmor-dev-next-file-path-audit.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "File", "")
				Expect(err).To(BeNil())

				out, err := exec.Command("cat", "/etc/passwd").CombinedOutput()
				fmt.Printf("---START---\n%s---END---\n", string(out))
				Expect(err).ToNot(HaveOccurred())

				out, err = exec.Command("head", "/etc/passwd").CombinedOutput()
				fmt.Printf("---START---\n%s---END---\n", string(out))
				Expect(err).ToNot(HaveOccurred())

				// check policy audit alert
				_, alerts, err := KarmorGetLogs(5*time.Second, 2)
				Expect(err).To(BeNil())
				Expect(len(alerts)).To(BeNumerically(">=", 2))
				for _, alert := range alerts {
					Expect(alert.PolicyName).To(Equal("hsp-kubearmor-dev-next-file-path-audit"))
					Expect(alert.Action).To(Equal("Audit"))
				}
			})
		})

		Context("Test hsp-kubearmor-dev-next-file-path-block", func() {
			It("Should block access to /etc/hostname", func() {
				err := K8sApplyFile("res/hsp-kubearmor-dev-next-file-path-block.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "File", "")
				Expect(err).To(BeNil())

				out, err := exec.Command("cat", "/etc/hostname").CombinedOutput()
				fmt.Printf("---START---\n%s---END---\n", string(out))
				Expect(err).To(HaveOccurred())

				// check policy violation alert
				_, alerts, err := KarmorGetLogs(5*time.Second, 1)
				Expect(err).To(BeNil())
				Expect(len(alerts)).To(BeNumerically(">=", 1))
				Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-next-file-path-block"))
				Expect(alerts[0].Action).To(Equal("Block"))
			})
		})

		Context("Test hsp-kubearmor-dev-next-proc-path-block-fromsource", func() {
			It("Should block execution of /bin/date by /bin/bash", func() {
				// Apply KubeArmor policy
				err := K8sApplyFile("res/hsp-kubearmor-dev-next-proc-path-block-fromSource.yaml")
				Expect(err).To(BeNil(), "Failed to apply KubeArmor policy")

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "Process", "")
				Expect(err).To(BeNil(), "Failed to start KubeArmor logs")

				// Execute 'date' command from 'bash' shell
				out, err := exec.Command("bash", "-c", "date").CombinedOutput()
				fmt.Printf("---START---\n%s---END---\n", string(out))
				Expect(err).To(HaveOccurred(), "Expected error, but none occurred")
				Expect(string(out)).To(ContainSubstring("Permission denied"), "Expected permission denied error")

				// Execute 'ls' command from 'bash' shell
				out, err = exec.Command("bash", "-c", "ls").CombinedOutput()
				fmt.Printf("---START---\n%s---END---\n", string(out))
				Expect(err).ToNot(HaveOccurred(), "Expected no error, but an error occurred")

				// Check for policy violation alert for 'date' command
				_, alerts, err := KarmorGetLogs(5*time.Second, 1)
				Expect(err).To(BeNil(), "Failed to retrieve KubeArmor logs")
				Expect(len(alerts)).To(BeNumerically(">=", 1), "Expected at least one alert")
				Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-next-proc-path-block-fromSource"), "Unexpected policy name in alert")
				Expect(alerts[0].Action).To(Equal("Block"), "Unexpected action in alert")
			})
		})

		Context("Test hsp-kubearmor-dev-next-proc-path-allow-fromsource", func() {
			It("Should allow execution of /bin/date by /bin/bash", func() {
				err := K8sApplyFile("res/hsp-kubearmor-dev-next-proc-path-allow-fromSource.yaml")
				Expect(err).To(BeNil())

				// Start Kubearmor Logs
				err = KarmorLogStart("policy", "", "Process", "")
				Expect(err).To(BeNil())

				out, err := exec.Command("bash", "-c", "date").CombinedOutput()
				fmt.Printf("---START---\n%s---END---\n", string(out))
				Expect(err).ToNot(HaveOccurred())

				out, err = exec.Command("bash", "-c", "ls").CombinedOutput()
				fmt.Printf("---START---\n%s---END---\n", string(out))
				Expect(err).To(HaveOccurred())

				// check policy allow alert for date command
				_, alerts, err := KarmorGetLogs(5*time.Second, 1)
				Expect(err).To(BeNil())
				Expect(len(alerts)).To(BeNumerically(">=", 1))
				Expect(alerts[0].PolicyName).To(Equal("hsp-kubearmor-dev-next-proc-path-allow-fromsource"))
				Expect(alerts[0].Action).To(Equal("Allow"))
			})
		})

	})
})
