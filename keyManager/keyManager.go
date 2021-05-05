package keyManager

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	// "bytes"

	"github.com/prysmaticlabs/go-ssz"
	bip39 "github.com/tyler-smith/go-bip39"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	string2eth "github.com/wealdtech/go-string2eth"
)

type SeedPrase struct {
	Prase string
	Pass string
	Seed *[]byte
	ErrCheck bool
}

type LaunchpadOutputs struct {
	Pubkey string `json:"pubkey"`
	Withdrawal_credentials string `json:"withdrawal_credentials"`
	Amount int `json:"amount"`
	Signature string `json:"signature"`
	Deposit_message_root string `json:"deposit_message_root"`
	Deposit_data_root string `json:"deposit_data_root"`
	Fork_version string `json:"fork_version"`
	Deposit_cli_version string `json:"deposit_cli_version"`
}

type EthdoOutputs struct {
	Name string `json:"name"`
	Account string `json:"account"`
	Pubkey string `json:"pubkey"`
	Withdrawal_credentials string `json:"withdrawal_credentials"`
	Signature string `json:"signature"`
	Value int `json:"value"`
	Deposit_data_root string `json:"deposit_data_root"`
	Version int `json:"version"`
}

type RawOutputs struct {
	Validator string
	Data string
}

type Exports struct {
	Acounts []string
	DepositsLaunchpad []LaunchpadOutputs
	DepositsEthdo []EthdoOutputs
	DepositsRaw []RawOutputs
}


type Validators struct {
	Store e2wtypes.Store
	SeedPrase SeedPrase
	PassPrase string
	Wallet e2wtypes.Wallet
	WithdrawAccount e2wtypes.Account
	WithdrawPubkey string
	WithdrawPath string
	ValidatorsPath string
	Validators []e2wtypes.Account
	Count int
	StartIndex int
	Exports Exports
	ForkVersion string
}

func (s *SeedPrase) GenerateSeed() error {
	if (s.ErrCheck) {
		seed, err := bip39.NewSeedWithErrorChecking(s.Prase, s.Pass)
		if (err != nil) {
			fmt.Println(err)
			return err
		}
		s.Seed = &seed
	} else {
		seed := bip39.NewSeed(s.Prase, s.Pass)
		s.Seed = &seed
	}
	return nil
}

func init () {
	err := e2types.InitBLS()
	if err != nil {
		fmt.Println("BLS: ", err)
	}
}

func (v *Validators) CreateWithdraw (ctx context.Context) {
	account1, err := v.Wallet.(e2wtypes.WalletPathedAccountCreator).CreatePathedAccount(ctx, v.WithdrawPath, "withdrawal", []byte(v.PassPrase))
	if err != nil {
	       fmt.Println(err)
	}
	v.WithdrawAccount = account1
	v.WithdrawPubkey = fmt.Sprintln("0x" + hex.EncodeToString(v.WithdrawAccount.PublicKey().Marshal()))
	// jsonData, _:= json.MarshalIndent(account1, "", "  ")
	// fmt.Println(string(jsonData))
	// fmt.Println(hex.EncodeToString(account1.PublicKey().Marshal()))
}

func (v *Validators) CreateValidators (ctx context.Context, count int, startIndex int) error {
	rex := regexp.MustCompile(`m/12381/3600/(\d*).*`)
	for i := startIndex; i < count; i++ {
		var path string
		var name string
		if strings.Contains(v.ValidatorsPath, "%d") {
			path = fmt.Sprintf(v.ValidatorsPath, i)
			name = fmt.Sprintf("validator%d", i)
		} else {
			path = v.ValidatorsPath
			name = fmt.Sprintf("validator%v", rex.FindStringSubmatch(v.ValidatorsPath)[1])
		}
		v.CreateValidator (ctx, path, name)
		// v.Exports.Acounts = append(v.Exports.Acounts, string(jsonData))
	}
	// v.Wallet.(e2wtypes.WalletPathedAccountCreator).CreatePathedAccount(ctx, "m/12381/3600/0/0/0", v.PassPrase, []byte(v.PassPrase))
	return nil
}

func (v *Validators) CreateValidator (ctx context.Context, path string, name string) error {
	account, err := v.Wallet.(e2wtypes.WalletPathedAccountCreator).CreatePathedAccount(ctx, path, name, []byte(v.PassPrase))
	if err != nil {
		fmt.Println(err)
		return err
	}
	// jsonData, _:= json.MarshalIndent(account, "", "  ")
	v.Validators = append(v.Validators, account)
	return err
}

func (v *Validators) ExportValidators (ctx context.Context) {
	path, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	if _, err := os.Stat(path + "/Validators"); os.IsNotExist(err) {
	    os.Mkdir(path + "/Validators", 0775)
	}
	for _, account := range v.Validators {
		jsonData, _:= json.MarshalIndent(account, "", "  ")
		// fmt.Println(string(jsonData))
		// fmt.Println(hex.EncodeToString(account.PublicKey().Marshal()))
		err = ioutil.WriteFile(path + "/Validators/" + account.Name() + ".json" , jsonData, 0664)
		if err != nil {
			fmt.Println(err)
		}
	}
}

type Keystore struct {
	Path string `json:"path"`
	Pubkey string `json:"pubkey"`
}

func (v *Validators) ExportTekuKeyConfig () {
	pubkeyList := make([]string, 0)
	var key Keystore
	path, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}
	if _, err := os.Stat(path + "/TekuKeyConfig"); os.IsNotExist(err) {
	    os.Mkdir(path + "/TekuKeyConfig", 0775)
	}
	if _, err := os.Stat(path + "/TekuKeyConfig/passwords"); os.IsNotExist(err) {
	    os.Mkdir(path + "/TekuKeyConfig/passwords", 0775)
	}
	if _, err := os.Stat(path + "/TekuKeyConfig/validators"); os.IsNotExist(err) {
	    os.Mkdir(path + "/TekuKeyConfig/validators", 0775)
	}
	for index, account := range v.Validators {
		jsonData, _:= json.MarshalIndent(account, "", "  ")
		json.Unmarshal(jsonData, &key)
		pubkeyList = append(pubkeyList, key.Pubkey)
		configFileName := fmt.Sprintf("config-%s-%d.yaml", strings.ReplaceAll(key.Path, "/", "_"), index)
		keystoreFileName := fmt.Sprintf("keystore-%s-%d.json", strings.ReplaceAll(key.Path, "/", "_"), index)
		keystorePassFileName := fmt.Sprintf("keystore-%s-%d.pass", strings.ReplaceAll(key.Path, "/", "_"), index)
		// fmt.Println(string(jsonData))
		// fmt.Println(hex.EncodeToString(account.PublicKey().Marshal()))

		err = ioutil.WriteFile(path + "/TekuKeyConfig/validators/" + keystoreFileName , jsonData, 0664)
		if err != nil {
			fmt.Println(err)
		}

		// create web3signer config file
		configData := "type: \"file-keystore\"\n" +
			"keyType: \"BLS\"\n" +
			"keystoreFile: \"validators/" + keystoreFileName + "\"\n" +
			"keystorePasswordFile: \"passwords/" + keystorePassFileName + "\""
		err = ioutil.WriteFile(path + "/TekuKeyConfig/" + configFileName , []byte(configData), 0664)
		if err != nil {
			fmt.Println(err)
		}

		// create web3signer password file
		err = ioutil.WriteFile(path + "/TekuKeyConfig/passwords/" + keystorePassFileName , []byte(v.PassPrase), 0664)
		if err != nil {
			fmt.Println(err)
		}
	}
	pubkeyListData, _:= json.MarshalIndent(pubkeyList, "", "  ")
	// fmt.Println(pubkeyList)
	// fmt.Println(string(pubkeyListData))

	err = ioutil.WriteFile(path + "/tekuPubKeyArray.json" , pubkeyListData, 0664)
	if err != nil {
		fmt.Println(err)
	}


}

func (v *Validators) ExportDepositsLaunchpad () {
	jsonList, _ := json.MarshalIndent(v.Exports.DepositsLaunchpad, "", "  ")
	path, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	if _, err := os.Stat(path + "/DepositData"); os.IsNotExist(err) {
	    os.Mkdir(path + "/DepositData", 0775)
	}

	err = ioutil.WriteFile(path + "/DepositData/LaunchpadFormat.json", jsonList, 0664)
	if err != nil {
		fmt.Println(err)
	}
}

func (v *Validators) ExportDepositsEthdo () {
	jsonList, _ := json.MarshalIndent(v.Exports.DepositsEthdo, "", "  ")
	path, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	if _, err := os.Stat(path + "/DepositData"); os.IsNotExist(err) {
	    os.Mkdir(path + "/DepositData", 0775)
	}

	err = ioutil.WriteFile(path + "/DepositData/EthdoFormat.json", jsonList, 0664)
	if err != nil {
		fmt.Println(err)
	}
}

func (v *Validators) ExportDepositsRaw () {
	jsonList, _ := json.MarshalIndent(v.Exports.DepositsRaw, "", "  ")
	path, err := os.Getwd()
	if err != nil {
		fmt.Println(err)
	}

	if _, err := os.Stat(path + "/DepositData"); os.IsNotExist(err) {
	    os.Mkdir(path + "/DepositData", 0775)
	}

	err = ioutil.WriteFile(path + "/DepositData/RawFormat.json", jsonList, 0664)
	if err != nil {
		fmt.Println(err)
	}
}

func (v *Validators) CreateNewWallet (ctx context.Context) {
	v.Store = scratch.New()
	var encryptor = keystorev4.New()
	// fmt.Printf("%+v\n",s)

	wallet, err := hd.CreateWallet(ctx, "Wallet", []byte(v.PassPrase), v.Store, encryptor, *v.SeedPrase.Seed)
	if err != nil {
		fmt.Println(err)
	}
	err = wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte(v.PassPrase))
	if err != nil {
		fmt.Println(err)
	}
	v.Wallet = wallet
}



func unlock(account e2wtypes.Account, passphrase string) (bool, error) {
	locker, isAccountLocker := account.(e2wtypes.AccountLocker)
	if !isAccountLocker {
//		outputIf(debug, "Account does not support unlocking")
		// This account doesn't support unlocking; return okay.
		return true, nil
	}
							// viper.GetDuration("timeout")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	alreadyUnlocked, err := locker.IsUnlocked(ctx)
	if err != nil {
		return false, fmt.Errorf("unable to ascertain if account is unlocked: %v", err)
	}

	if alreadyUnlocked {
		return true, nil
	}

	// Not already unlocked; attempt to unlock it.
	// for _, passphrase := range getPassphrases() {
							// viper.GetDuration("timeout")
	err = locker.Unlock(ctx, []byte(passphrase))
	cancel()
	if err == nil {
		// Unlocked.
		return false, nil
	}
	// }

	// Failed to unlock it.
	return false, fmt.Errorf("failed to unlock account")
}

// lock attempts to lock an account.
func lock(account e2wtypes.Account) error {
	locker, isAccountLocker := account.(e2wtypes.AccountLocker)
	if !isAccountLocker {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return locker.Lock(ctx)
}

func signGeneric(account e2wtypes.Account, data []byte, domain []byte, passphrase string) (e2types.Signature, error) {
	alreadyUnlocked, err := unlock(account, passphrase)
	if err != nil {
		return nil, err
	}
//	outputIf(debug, fmt.Sprintf("Signing %x (%d)", data, len(data)))
							// viper.GetDuration("timeout")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	signer, isProtectingSigner := account.(e2wtypes.AccountProtectingSigner)
	if !isProtectingSigner {
		return nil, fmt.Errorf("account does not provide generic signing")
	}

	signature, err := signer.SignGeneric(ctx, data, domain)
//	errCheck(err, "failed to sign")
	if !alreadyUnlocked {
		if err := lock(account); err != nil {
			return nil, fmt.Errorf("failed to lock account: %v", err)
		}
	}
	return signature, err
}

// SigningContainer is the container for signing roots with a domain.
// Contains SSZ sizes to allow for correct calculation of root.
type signingContainer struct {
	Root   []byte `ssz-size:"32"`
	Domain []byte `ssz-size:"32"`
}

// signRoot signs a root.
func signRoot(account e2wtypes.Account, root [32]byte, domain []byte, passprase string) (e2types.Signature, error) {
	if _, isProtectingSigner := account.(e2wtypes.AccountProtectingSigner); isProtectingSigner {
		// Signer signs the data to sign itself.
		return signGeneric(account, root[:], domain, passprase)
	}
	// Build the signing data manually.
	container := &signingContainer{
		Root:   root[:],
		Domain: domain,
	}
	// outputIf(debug, fmt.Sprintf("Signing container:\n root: %#x\n domain: %#x", container.Root, container.Domain))
	signingRoot, err := ssz.HashTreeRoot(container)
	if err != nil {
		return nil, err
	}
	// outputIf(debug, fmt.Sprintf("Signing root: %#x", signingRoot))
	return sign(account, signingRoot[:], passprase)
}

// sign signs arbitrary data, handling unlocking and locking as required.
func sign(account e2wtypes.Account, data []byte, passprase string) (e2types.Signature, error) {
	alreadyUnlocked, err := unlock(account, passprase)
	if err != nil {
		return nil, err
	}
	// outputIf(debug, fmt.Sprintf("Signing %x (%d)", data, len(data)))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	signer, isSigner := account.(e2wtypes.AccountSigner)
	if !isSigner {
		return nil, fmt.Errorf("account does not provide signing")
	}

	signature, err := signer.Sign(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign")
	}
	if !alreadyUnlocked {
		if err := lock(account); err != nil {
			return nil, fmt.Errorf("failed to lock account \n%v", err)
		}
	}
	return signature, err
}

// signStruct signs an arbitrary structure.
func signStruct(account e2wtypes.Account, data interface{}, domain []byte, passprase string) (e2types.Signature, error) {
	objRoot, err := ssz.HashTreeRoot(data)
	if err != nil {
		return nil, err
	}
	return signRoot(account, objRoot, domain, passprase)
}

func (v *Validators) CreateValidatorDeposits (ctx context.Context, depositValue string) error {
        // https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/deposit-contract.md
	// NOTE need for version validation
	// NOTE need to validate depositValue
	validators := v.Validators
	withdrawalPublicKeyBytes, err := hex.DecodeString(strings.TrimPrefix(v.WithdrawPubkey, "0x"))
	_ = withdrawalPublicKeyBytes
	if len(withdrawalPublicKeyBytes) != 48 {
		err := fmt.Errorf("Public key should be 48 bytes")
		return err
	}
	withdrawalPublicKey, err := e2types.BLSPublicKeyFromBytes(withdrawalPublicKeyBytes)
	if err != nil {
		newerr := fmt.Errorf("Public Key Suplied is not correct:\n%v", err)
		return newerr
	}
	withdrawalCredentials := util.SHA256(withdrawalPublicKey.Marshal())
	// fmt.Println(withdrawalCredentials)
	// NOTE need to varify the first byte shold be overwritten
	withdrawalCredentials[0] = byte(0) // BLS_WITHDRAWAL_PREFIX
	// fmt.Println(withdrawalCredentials)
	// fmt.Printf("Withdrawal credentials are %#x\n", withdrawalCredentials)

	val, err := string2eth.StringToGWei(depositValue)
	if err != nil {
		newErr := fmt.Errorf("Eth to Gwei Error: %v\n", err)
		return newErr
	}
	// NOTE Print interger as a string
	if val <= 1000000000 {
		return fmt.Errorf("deposit value must be at least 1 Ether")
	}

	// outputsRaw := make([]string, 0)
	// outputsLaunchpad := make([]string, 0)
	// outputsEthdo := make([]string, 0)
	for _, validatorAccount := range validators {
		publicKeyProvider, isPublicKeyProvider := validatorAccount.(e2wtypes.AccountPublicKeyProvider)
		var validatorPubKey e2types.PublicKey
		if isPublicKeyProvider {
			validatorPubKey = publicKeyProvider.PublicKey()
		} else {
			return fmt.Errorf("account does not provide a public key")
		}
		if err != nil {
			return fmt.Errorf("Validator account does not provide a public key")
		}
		depositData := struct {
			PubKey                []byte `ssz-size:"48"`
			WithdrawalCredentials []byte `ssz-size:"32"`
			Value                 uint64
		}{
			PubKey:                validatorPubKey.Marshal(),
			WithdrawalCredentials: withdrawalCredentials,
			Value:                 val,
		}
		// fmt.Println(depositData)
		// jsonData, _:= json.MarshalIndent(depositData, "", "  ")
		// fmt.Println(string(jsonData))

		var forkVersion []byte
		_ = forkVersion
		forkVersion, err = hex.DecodeString(strings.TrimPrefix(v.ForkVersion, "0x"))
		if err != nil {
			return fmt.Errorf("Invalid Fork Version: %v", err)
		}
		if len(forkVersion) != 4 {
			return fmt.Errorf("Fork version must be exactly four bytes")
		}
		domain := e2types.Domain(e2types.DomainDeposit, forkVersion, e2types.ZeroGenesisValidatorsRoot)
		signature, err := signStruct(validatorAccount, depositData, domain, v.PassPrase)
		if err != nil {
			return fmt.Errorf("Failed to generate deposit data signature: %v", err)
		}
		signedDepositData := struct {
			PubKey                []byte `ssz-size:"48"`
			WithdrawalCredentials []byte `ssz-size:"32"`
			Value                 uint64
			Signature             []byte `ssz-size:"96"`
		}{
			PubKey:                validatorPubKey.Marshal(),
			WithdrawalCredentials: withdrawalCredentials,
			Value:                 val,
			Signature:             signature.Marshal(),
		}

		depositDataRoot, err := ssz.HashTreeRoot(signedDepositData)
		// Raw Data Output
		// Build a raw transaction by hand
		txData := []byte{0x22, 0x89, 0x51, 0x18}
		// Pointer to validator public key
		txData = append(txData, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}...)
		// Pointer to withdrawal credentials
		txData = append(txData, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0}...)
		// Pointer to validator signature
		txData = append(txData, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20}...)
		// Deposit data root
		txData = append(txData, depositDataRoot[:]...)
		// Validator public key (pad to 32-byte boundary)
		txData = append(txData, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30}...)
		txData = append(txData, validatorPubKey.Marshal()...)
		txData = append(txData, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
		// Withdrawal credentials
		txData = append(txData, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20}...)
		txData = append(txData, withdrawalCredentials...)
		// Deposit signature
		txData = append(txData, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60}...)
		txData = append(txData, signedDepositData.Signature...)
		// outputsRaw = append(outputsRaw, fmt.Sprintf("%#x", txData))
		// Ethereum Launchpad Output
		var rawOutput RawOutputs
		rawOutput.Validator = fmt.Sprintf("%s/%s", v.Wallet.Name(), validatorAccount.Name())
		rawOutput.Data = fmt.Sprintf("%#x", txData)
		v.Exports.DepositsRaw = append(v.Exports.DepositsRaw, rawOutput)
		depositMessage := struct {
			PubKey                []byte `ssz-size:"48"`
			WithdrawalCredentials []byte `ssz-size:"32"`
			Value                 uint64
		}{
			PubKey:                validatorPubKey.Marshal(),
			WithdrawalCredentials: withdrawalCredentials,
			Value:                 val,
		}
		depositMessageRoot, err := ssz.HashTreeRoot(depositMessage)
		if err != nil {
			fmt.Errorf("Failed to generate deposit message root: %v", err)
		}
		var launchpadOutput LaunchpadOutputs
		json.Unmarshal([]byte(fmt.Sprintf(`{"pubkey":"%x","withdrawal_credentials":"%x","amount":%d,"signature":"%x","deposit_message_root":"%x","deposit_data_root":"%x","fork_version":"%x","deposit_cli_version":"1.0.0"}`,
			signedDepositData.PubKey,
			signedDepositData.WithdrawalCredentials,
			val,
			signedDepositData.Signature,
			depositMessageRoot,
			depositDataRoot,
			forkVersion)), &launchpadOutput)
		v.Exports.DepositsLaunchpad = append(v.Exports.DepositsLaunchpad, launchpadOutput)
		// Ethdo Output
		var ethdoOutputs EthdoOutputs
		err1 := json.Unmarshal([]byte(fmt.Sprintf(`{"name":"Deposit for %s","account":"%s","pubkey":"%#x","withdrawal_credentials":"%#x","signature":"%#x","value":%d,"deposit_data_root":"%#x","version":2}`,
			fmt.Sprintf("%s/%s",
			v.Wallet.Name(),
			validatorAccount.Name()),
			fmt.Sprintf("%s/%s",
			v.Wallet.Name(),
			validatorAccount.Name()),
			signedDepositData.PubKey,
			signedDepositData.WithdrawalCredentials,
			signedDepositData.Signature,
			val,
			depositDataRoot)), &ethdoOutputs)
		if err1 != nil {
			fmt.Println(err1)
		}
		v.Exports.DepositsEthdo = append(v.Exports.DepositsEthdo, ethdoOutputs)
	}

	// DepositsLaunchpad []string
	// DepositsEthdo []string

	// for _, output := range outputsLaunchpad {
	// 	var jsonOutput bytes.Buffer
	// 	// fmt.Println(output)
	// 	err = json.Indent(&jsonOutput, []byte(output), "", "  ")
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	}
	// 	// fmt.Println(jsonOutput.String())
	// 	v.Exports.DepositsLaunchpad = append(v.Exports.DepositsLaunchpad, jsonOutput.String())
	// }
	// for _, output := range outputsEthdo {
	// 	var jsonOutput bytes.Buffer
	// 	// fmt.Println(output)
	// 	err = json.Indent(&jsonOutput, []byte(output), "", "  ")
	// 	if err != nil {
	// 		fmt.Println(err)
	// 	}
	// 	fmt.Println(jsonOutput.String())
	// 	v.Exports.DepositsEthdo = append(v.Exports.DepositsEthdo, jsonOutput.String())
	// }


	// fmt.Println(withdrawalPublicKeyString, withdrawalPublicKeyBytes, withdrawalPublicKey)
	return nil
}



