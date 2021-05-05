package cmd

import (
	"fmt"
	"strings"
	"github.com/spf13/cobra"
	"github.com/JordanCason/createKeys/mergeManager"
	"bufio"
	"os"
)


var manage mergeManager.Manage

var manageClients = &cobra.Command {
	Use: "clients",
	Short: "Manage Clients",
}
var addNewClient = &cobra.Command {
	Use: "add",
	Short: "Add a new Client to the client config",
	Run: func(cmd *cobra.Command, args []string) {
		scanner := bufio.NewScanner(os.Stdin)
		// Add User Name
		if len(manage.ClientName) == 0 {
			fmt.Printf("Name: ")
			if scanner.Scan() {
			    manage.ClientName = scanner.Text()
			}
		}
		manage.ClientName = strings.ToLower(strings.ReplaceAll(manage.ClientName, " ", ""))
		isClient := manage.IsClient()
		if isClient {
			fmt.Println("Client Already Exists")
			return
		}
		// Add User Email
		if len(manage.ClientEmail) == 0 {
			fmt.Printf("Email: ")
			if scanner.Scan() {
			    manage.ClientEmail = scanner.Text()
			}
		}
		manage.ClientName = strings.ToLower(strings.ReplaceAll(manage.ClientName, " ", ""))
		// Add User phone
		if len(manage.ClientPhone) == 0 {
			fmt.Printf("Phone: ")
			if scanner.Scan() {
			    manage.ClientPhone = scanner.Text()
			}
		}
		manage.ClientPhone = strings.ReplaceAll(manage.ClientPhone, " ", "")
		// Add User Eth1
		if len(manage.ClientEth1) == 0 {
			fmt.Printf("Eth1: ")
			if scanner.Scan() {
			    manage.ClientEth1 = scanner.Text()
			}
		}
		manage.ClientEth1 = strings.ReplaceAll(manage.ClientEth1, " ", "")
		manage.LoadClientConfig()
		manage.CreateNewClient()
		manage.BackupConfig()
		manage.WrightConfig()
	},
}


func init() {
	rootCmd.AddCommand(manageClients)
	manageClients.AddCommand(addNewClient)
	addNewClient.Flags().StringVarP(&manage.ClientName, "name", "n", "", "Name of the client")
	addNewClient.Flags().StringVarP(&manage.ClientEmail, "email", "e", "", "Email of the client")
	addNewClient.Flags().StringVarP(&manage.ClientPhone, "phone", "p", "", "phone of the client")
	addNewClient.Flags().StringVarP(&manage.ClientEth1, "eth1", "E", "", "Eth1 Address of the client")
	addNewClient.Flags().StringVarP(&manage.ClientConfigFile, "clientconfigfile", "C", "./clients.json", "source files to merge into base directory")

}


