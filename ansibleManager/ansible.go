package ansible

import (
	ansibler "github.com/apenella/go-ansible"
	"path"
	"fmt"
	"os"
)

type Ansible struct {
	ExicutionPath string
	LuksPass string
	Production string
	Environment string
	BecomePass string
}

func (a *Ansible) Init () {
	path2, err := os.Executable()
	if err != nil {
	    fmt.Println(err)
	}
	a.ExicutionPath = path.Dir(path2)
}

func (a *Ansible) AddKeysToSigner () {
	// connectionOptions := &ansibler.AnsiblePlaybookConnectionOptions{
	// 	User: "teku",
	// }
	playbookOptions := &ansibler.AnsiblePlaybookOptions{
		Inventory: a.ExicutionPath + "/automation/" + a.Environment + "_hosts.yaml",
	}
	fmt.Println(a.LuksPass)
	playbookOptions.AddExtraVar("lukspassword", a.LuksPass)
	playbookOptions.AddExtraVar("productioncheck", a.Production)
	playbookOptions.AddExtraVar("ansible_become_pass", a.BecomePass)
	privilegeOptions := &ansibler.AnsiblePlaybookPrivilegeEscalationOptions{
		Become: true,
	}
	playbook := &ansibler.AnsiblePlaybookCmd{
		Playbook: a.ExicutionPath + "/automation/Playbooks/web3signer-updatekeys-offline.yaml",
		// ConnectionOptions: connectionOptions,
		PrivilegeEscalationOptions: privilegeOptions,
		Options:                    playbookOptions,
	}
	runerr := playbook.Run()
	if runerr != nil {
		panic(runerr)
	}
}

func (a *Ansible) SshAgent () {
	connectionOptions := &ansibler.AnsiblePlaybookConnectionOptions{
	}

	playbookOptions := &ansibler.AnsiblePlaybookOptions{
		Inventory: a.ExicutionPath + "/automation/" + a.Environment + "_hosts.yaml",
	}
	ansiblePlaybookPrivilegeEscalationOptions := &ansibler.AnsiblePlaybookPrivilegeEscalationOptions{
		Become: true,
	}
	playbookOptions.AddExtraVar("ansible_become_pass", a.BecomePass)
	playbook := &ansibler.AnsiblePlaybookCmd{
		Playbook: a.ExicutionPath + "/automation/Playbooks/ssh-agent.yaml",
		ConnectionOptions: connectionOptions,
		PrivilegeEscalationOptions: ansiblePlaybookPrivilegeEscalationOptions,
		Options: playbookOptions,
	}

	err := playbook.Run()
	if err != nil {
		panic(err)
	}
}


func (a *Ansible) UpdateTekuConfig () {
	// connectionOptions := &ansibler.AnsiblePlaybookConnectionOptions{
	// 	User: "teku",
	// }
	playbookOptions := &ansibler.AnsiblePlaybookOptions{
		Inventory: a.ExicutionPath + "/automation/" + a.Environment + "_hosts.yaml",
	}
	privilegeOptions := &ansibler.AnsiblePlaybookPrivilegeEscalationOptions{
		Become: true,
	}
	playbookOptions.AddExtraVar("ansible_become_pass", "a.BecomePass")
	playbook := &ansibler.AnsiblePlaybookCmd{
		Playbook: a.ExicutionPath + "/automation/Playbooks/teku-config-update.yaml",
		// ConnectionOptions: connectionOptions,
		PrivilegeEscalationOptions: privilegeOptions,
		Options:                    playbookOptions,
	}
	runerr := playbook.Run()
	if runerr != nil {
		panic(runerr)
	}
}





















































