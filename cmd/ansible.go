package cmd

import (
	"github.com/spf13/cobra"
	ansibleManager "github.com/JordanCason/createKeys/ansibleManager"
	"os"

	"github.com/spf13/viper"
	"bufio"
	"fmt"
)

func varifyProduction () {
	scanner := bufio.NewScanner(os.Stdin)
	if ansible.Environment == "prod" {
		fmt.Printf("Type production in all caps: ")
		if scanner.Scan() {
		    ansible.Production = scanner.Text()
		}
	}
}

var ansible ansibleManager.Ansible


var manageAnsible = &cobra.Command {
	Use: "ansible",
	Short: "Manage ansible",
}

var signer = &cobra.Command {
	Use: "signer",
	Short: "Preform actions on the web3signer",
}

var loadkyes = &cobra.Command {
	Use: "uploadkeys",
	Short: "upload new keys",
	Run: func(cmd *cobra.Command, args []string) {
		varifyProduction()
		if ansible.BecomePass == "" {
			ansible.BecomePass = viper.GetString("BecomePass")
		}
		if ansible.LuksPass == "" {
			ansible.LuksPass = viper.GetString("LuksPass")
		}
		if ansible.LuksPass == "" {
			scanner := bufio.NewScanner(os.Stdin)
			fmt.Printf("LuksPass: ")
			if scanner.Scan() {
			    ansible.LuksPass = scanner.Text()
			}
		}
		ansible.SshAgent()
		ansible.AddKeysToSigner()
		ansible.UpdateTekuConfig()
	},
}


var sshAgent= &cobra.Command {
	Use: "ssh-agent",
	Short: "make sure the ssh-agent is running with our identity files",
	Run: func(cmd *cobra.Command, args []string) {
		varifyProduction()
		if ansible.BecomePass == "" {
			ansible.BecomePass = viper.GetString("BecomePass")
		}
		ansible.SshAgent()
	},
}

var tekuConfigUpdate= &cobra.Command {
	Use: "updateTekuConfig",
	Short: "Update the Teku config file",
	Run: func(cmd *cobra.Command, args []string) {
		varifyProduction()
		if ansible.BecomePass == "" {
			ansible.BecomePass = viper.GetString("BecomePass")
		}
		ansible.UpdateTekuConfig()
	},
}



func init() {
	ansible.Init()

	os.Setenv("ANSIBLE_FORCE_COLOR", "true")


	rootCmd.AddCommand(manageAnsible)
	manageAnsible.AddCommand(signer)

	signer.PersistentFlags().StringVarP(&ansible.Environment, "env", "", "", "Environment to run in i.e \"dev\" \"prod\"")
	signer.PersistentFlags().StringVarP(&ansible.BecomePass, "becomepass", "", "", "become pass for ansible")
	signer.MarkPersistentFlagRequired("env")
	signer.AddCommand(loadkyes)
	signer.AddCommand(sshAgent)
	signer.AddCommand(tekuConfigUpdate)

}


