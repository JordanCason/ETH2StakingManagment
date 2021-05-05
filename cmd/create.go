/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"context"

	"github.com/spf13/cobra"
	"github.com/JordanCason/createKeys/keyManager"
)

type LocalFlags struct {
	Export bool
	CreateDeposits bool
}

var localFlags LocalFlags

// var s keyManager.SeedPrase
var validators keyManager.Validators
// createCmd represents the create command

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create Keys and Deposits",
}

var withdrawCmd = &cobra.Command{
	Use:   "withdraw",
	Short: "Print the publick key for the withdraw address",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		validators.SeedPrase.GenerateSeed()
		validators.CreateNewWallet(ctx)
		validators.CreateWithdraw(ctx)
		fmt.Println(validators.WithdrawPubkey)
	},
}

var validatorsCmd = &cobra.Command{
	Use:   "validators",
	Short: "Create and export validators and deposit data",
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		validators.SeedPrase.GenerateSeed()
		validators.CreateNewWallet(ctx)
		validators.CreateWithdraw(ctx)
		validators.CreateValidators(ctx, validators.Count, validators.StartIndex)
		validators.CreateValidatorDeposits(ctx, "32 ether")
		if localFlags.Export {
			validators.ExportTekuKeyConfig()
			validators.ExportValidators(ctx)
			validators.ExportDepositsLaunchpad()
			validators.ExportDepositsEthdo()
			validators.ExportDepositsRaw()
		}
	},
}

func init() {
	rootCmd.AddCommand(createCmd)
	createCmd.AddCommand(withdrawCmd)
	withdrawCmd.Flags().StringVarP(&validators.SeedPrase.Prase, "bip39Seed", "s", "", "bip39 seed prase words seporated via spaces")
	withdrawCmd.Flags().BoolVarP(&validators.SeedPrase.ErrCheck, "checkSeed", "", true, "Should bip39 prase be validated")
	withdrawCmd.Flags().StringVarP(&validators.WithdrawPath, "WithdrawPath", "", "m/12381/3600/0/0", "Withdraw Path")
	withdrawCmd.Flags().StringVarP(&validators.PassPrase, "walletPassword", "", "test", "Password for accounts")

	createCmd.AddCommand(validatorsCmd)
	validatorsCmd.Flags().StringVarP(&validators.SeedPrase.Prase, "bip39Seed", "s", "", "bip39 seed prase words seporated via spaces")
	validatorsCmd.Flags().StringVarP(&validators.SeedPrase.Pass, "bip39Password", "p", "", "bip39 password 25th word on seedprase")
	validatorsCmd.Flags().BoolVarP(&validators.SeedPrase.ErrCheck, "checkSeed", "c", true, "If the bip39 seedprase should be validated")
	validatorsCmd.Flags().StringVarP(&validators.WithdrawPath, "withdrawPath", "W", "m/12381/3600/0/0", "Withdraw Path")
	validatorsCmd.Flags().StringVarP(&validators.PassPrase, "keystorePasswords", "P", "", "Password for Validators keystors")
	validatorsCmd.Flags().StringVarP(&validators.ValidatorsPath, "validatorsPath", "V", "m/12381/3600/%d/0/0", "Custom Path for Validators")
	validatorsCmd.Flags().StringVarP(&validators.ForkVersion, "ForkVersion", "f", "0x00000000", "Ethereum Fork Version to use i.e \"0x00000000\" is the main net")
	validatorsCmd.Flags().IntVarP(&validators.Count, "Count", "C", 0, "Validators To Create")
	validatorsCmd.Flags().IntVarP(&validators.StartIndex, "StartIndex", "i", 0, "Validators To Create")


	validatorsCmd.Flags().BoolVarP(&localFlags.Export, "export", "e", true, "Export Validator keystors and deposit data")
	validatorsCmd.Flags().BoolVarP(&localFlags.CreateDeposits, "createDeposits", "", true, "Create Deposit Data")
	validatorsCmd.MarkFlagRequired("keystorePasswords")
	validatorsCmd.MarkFlagRequired("bip39Seed")
	validatorsCmd.MarkFlagRequired("Count")
}


