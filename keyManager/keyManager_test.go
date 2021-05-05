package keyManager

import (
	"testing"
	"io/ioutil"
	"encoding/json"
	"context"
	"strings"
	"fmt"

	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"github.com/stretchr/testify/assert"
)

type ValidatorPubkey struct {
	Path string `json:"path"`
	Pubkey string `json:"pubkey"`
}

var (
	TestData_ValidatorsPubkeys []ValidatorPubkey
	TestData_DepositData []LaunchpadOutputs
	TestData_SeedPhrase string
)

var validators Validators


func TestLoadSeedPrase (t *testing.T) {
	data, err := ioutil.ReadFile("../TestFiles/words.txt")
	if err != nil {
		t.Error(err)
	}
	TestData_SeedPhrase = strings.TrimSuffix(string(data), "\n")
	// t.Log(TestData_SeedPhrase)
}

func TestLoadValidatorPubkeys (t *testing.T) {
	entries, err := ioutil.ReadDir("../TestFiles/Validators/")
	if err != nil {
		t.Error(err)
	}
	for _, entry := range entries {
		data, err := ioutil.ReadFile("../TestFiles/Validators/" + entry.Name())
		if err != nil {
			t.Error(err)
		}
		var validator ValidatorPubkey
		json.Unmarshal(data, &validator)
		TestData_ValidatorsPubkeys = append(TestData_ValidatorsPubkeys, validator)
	}
	// jsondata, err := json.MarshalIndent(TestData_ValidatorsPubkeys, "", "  ")
	// t.Log(string(jsondata))
}

func TestLoadDepositData (t *testing.T) {
	entries, err := ioutil.ReadDir("../TestFiles/DepositData")
	if err != nil {
		t.Error(err)
	}
	if len(entries) > 1 {
		// NOTE through a new error
		t.Error("There Should only be one file in the DepositData DIR")
	}
	data, err := ioutil.ReadFile("../TestFiles/DepositData/" + entries[0].Name())
	if err != nil {
		t.Error(err)
	}
	err = json.Unmarshal(data, &TestData_DepositData)
	if err != nil {
		t.Error(err)
	}
	// jsondata, err := json.MarshalIndent(TestData_DepositData, "", "  ")
	// t.Log(string(jsondata))
}


func  TestValidatorsAndDepositCreation (t *testing.T) {
	ctx := context.Background()
	_ = ctx
	validators.SeedPrase.Prase = TestData_SeedPhrase
	validators.SeedPrase.Pass = ""
	validators.SeedPrase.ErrCheck = true
	validators.ForkVersion = "0x00000001"
	err := validators.SeedPrase.GenerateSeed()
	if err != nil {
		t.Log(err)
	}
	for index, imported_validator := range TestData_ValidatorsPubkeys {
		_ = index
		_ = imported_validator
		validators.ValidatorsPath = fmt.Sprintf("m/12381/3600/%d/0/0", index)
		validators.WithdrawPath = fmt.Sprintf("m/12381/3600/%d/0", index)
		validators.CreateNewWallet(ctx)
		validators.CreateWithdraw(ctx)
		err = validators.CreateValidator(ctx, validators.ValidatorsPath, fmt.Sprintf("validator%d", index))
		if err != nil {
			t.Log(err)
		}
		err = validators.CreateValidatorDeposits(ctx, "32 ether")
		if err != nil {
			t.Log(err)
		}
		// Reset Validators slice for CreateValidatorDeposits only has one account to loop over
		validators.Validators = make([]e2wtypes.Account, 0)
	}
	// test1, err := json.MarshalIndent(validators.Exports.DepositsLaunchpad, "", "  ")
	// test2, err := json.MarshalIndent(TestData_DepositData, "", "  ")
	// t.Log(string(test1))
	// t.Log(string(test2))

}

func TestDepositDataVsLaunchpadData (t *testing.T) {
	// compare Ethereum Launchpad deposits to our deposits
	for index, TestDeposit := range TestData_DepositData {
		assert.Equal(t, TestDeposit.Pubkey, validators.Exports.DepositsLaunchpad[index].Pubkey, "Pubkeys should match")
		assert.Equal(t, TestDeposit.Signature, validators.Exports.DepositsLaunchpad[index].Signature, "Signature should match")
		assert.Equal(t, TestDeposit.Amount, validators.Exports.DepositsLaunchpad[index].Amount, "Amount should match")
		assert.Equal(t, TestDeposit.Deposit_data_root, validators.Exports.DepositsLaunchpad[index].Deposit_data_root, "Deposit_data_root should match")
		assert.Equal(t, TestDeposit.Deposit_message_root, validators.Exports.DepositsLaunchpad[index].Deposit_message_root, "Deposit_message_root should match")
		assert.Equal(t, TestDeposit.Fork_version, validators.Exports.DepositsLaunchpad[index].Fork_version, "Fork_version should match")
		assert.Equal(t, TestDeposit.Withdrawal_credentials, validators.Exports.DepositsLaunchpad[index].Withdrawal_credentials, "Withdrawal_credentials should match")
	}
}
