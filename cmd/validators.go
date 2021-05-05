package cmd

import (
	"fmt"
	"strings"
	"github.com/spf13/cobra"
	"github.com/JordanCason/createKeys/mergeManager"
	"bufio"
	"os"
)


var Manage mergeManager.Manage



var manageValidators = &cobra.Command {
	Use: "validators",
	Short: "Manage Validators",
}
var addValidators = &cobra.Command {
	Use: "add",
	Short: "Add a new validator keystores from dirctory",
	Run: func(cmd *cobra.Command, args []string) {
		scanner := bufio.NewScanner(os.Stdin)
		if len(Manage.ClientName) == 0 {
			fmt.Printf("Client Name: ")
			if scanner.Scan() {
			    Manage.ClientName = scanner.Text()
			}
		}
		Manage.ClientName = strings.ToLower(strings.ReplaceAll(Manage.ClientName, " ", ""))
		Manage.LoadClientConfig()
		isClient := Manage.IsClient()
		if !isClient {
			fmt.Println("Need to create this client first")
			return
		}
		if len(Manage.Import) == 0 {
			fmt.Printf("Keystore Import Directory: ")
			if scanner.Scan() {
			    Manage.Import = scanner.Text()
			}
		}
		if len(Manage.KeystorePassword) == 0 {
			fmt.Printf("Keystore Password: ")
			if scanner.Scan() {
			    Manage.KeystorePassword = scanner.Text()
			}
		}
		Manage.ImportNewKeyStores()
		fmt.Println("########## " + Manage.ClientName + " ############")
		Manage.PrintClientAndValidators()
		fmt.Println("#####################################")
		fmt.Printf("\n\n\n")
		for _, account := range Manage.SourceAccounts {
			fmt.Println("########## " + account.FileName + " ############")
			account.KeystoreFileName = account.FileName
			account.ConfigFileName = strings.Replace(strings.Replace(account.FileName, "keystore", "config", 1), "json", "yaml", 1)
			account.KeystorePassFileName = strings.Replace(account.FileName, "json", "pass", 1)
			Manage.CreateTekuSignerConfig(account)
			Manage.CreateTekuPasswordFile(account)
			Manage.CreateTekuValidators(account)
			Manage.AddConfigValidator(account)
			fmt.Println("###################################################################")
			fmt.Printf("\n\n\n")
		}
		Manage.BackupConfig()
		Manage.WrightConfig()
		Manage.WrightPubkeyList()
		fmt.Println("Client data written:")
		fmt.Println("########## " + Manage.ClientName + " ############")
		Manage.PrintClientAndValidators()
		fmt.Println("#####################################")
	},
}

func init() {
	rootCmd.AddCommand(manageValidators)
	manageValidators.AddCommand(addValidators)
	addValidators.Flags().StringVarP(&Manage.ClientConfigFile,
					"clientconfigfile",
					"C",
					"./clients.json",
					"source files to merge into base directory")
	addValidators.Flags().StringVarP(&Manage.RootDir, "rootdir", "r", "", "source files to merge into base directory")
	addValidators.Flags().StringVarP(&Manage.Import, "import", "i", "", "The directory of validator keystors to add to configuration")
	addValidators.Flags().StringVarP(&Manage.ClientName, "name", "n", "", "Name of the client")
	addValidators.Flags().StringVarP(&Manage.KeystorePassword, "keystorepassword", "p", "", "KeystorePassword")

}


