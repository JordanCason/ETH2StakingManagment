package mergeManager

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"
	"github.com/fatih/color"
	// "strings"
	"regexp"
	"os"
	// "path/filepath"
	"github.com/otiai10/copy"
)

type Manage struct {
	BaseDir string
	Import string
	RootDir string
	KeystorePassword string
	ClientName string
	ClientEmail string
	ClientPhone string
	ClientEth1 string
	ClientConfigFile string
	SourceAccounts []Account
	Config Config
}

type Account struct {
	FileBytes []byte
	FileName string `json:"fileName"`
	ConfigFileName string
	KeystorePassFileName string
	KeystoreFileName string
	Pubkey string `json:"pubkey"`
	Path string `json:"path"`
}

type Config map[string]ClientConfig
// type PrivKyes map[string]bool

type ClientConfig struct {
	Info ClientInfoConfig `json:"info"`
	Validators map[string]ClientValidatorConfig `json:"validators"`
}

type ClientInfoConfig struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
	Eth1 string `json:"eth1"`
}

type ClientValidatorConfig struct {
	Path string `json:"path"`
	Pubkey string `json:"pubkey"`
	Teku ClientTekuConfig `json:"teku"`
}

type ClientTekuConfig struct {
	ConfigFile string `json:"configFile"`
	KeystoreFile string `json:"keystoreFile"`
	KeystorePasswordFile string `json:"keystorePasswordFile"`
}

var pubKeys = make(map[string]bool)
var red = color.New(color.FgRed).SprintFunc()

func (m *Manage) Test () {
	m.LoadClientConfig()
	m.ImportNewKeyStores()
	priv := make(map[string]bool)
	for key, validator := range m.Config[m.ClientName].Validators {
		fmt.Println(key, validator.Pubkey)
		priv[validator.Pubkey] = true
	}
	for _, validator :=  range m.SourceAccounts {
		if priv[validator.Pubkey] {
			fmt.Println("validator " + validator.FileName + " already exists in config")
		}
	}
}

func (m *Manage) ValidatorExists () bool {
	for _, validator :=  range m.SourceAccounts {
		if pubKeys[validator.Pubkey] {
			return true
		}
	}
	return false
}

func (m *Manage) IsClient () bool {
	m.LoadClientConfig()
	for key := range m.Config {
		if m.ClientName == key {
			return true
		}
	}
	return false
}

func (m *Manage) ListClients () {
	m.LoadClientConfig()
	for key, element := range m.Config {
		_ = element
		fmt.Println(key)
	}
}

func (m *Manage) CreateNewClient () {
	var newClient ClientConfig
	newClient.Info.Email = m.ClientEmail
	newClient.Info.Phone = m.ClientPhone
	newClient.Info.Eth1 = m.ClientEth1
	newClient.Validators = make(map[string]ClientValidatorConfig)
	m.Config[m.ClientName] = newClient
}

func (m *Manage) AddConfigValidator (account Account) {
	re := regexp.MustCompile(`^keystore-m_12381_3600_(\d*)`)
	index := re.FindStringSubmatch(account.FileName)

	var newTeku ClientTekuConfig
	newTeku.ConfigFile = "ClientKeyManagment/TekuKeyConfig/" + account.ConfigFileName
	newTeku.KeystoreFile = "ClientKeyManagment/TekuKeyConfig/validators/" + account.KeystoreFileName
	newTeku.KeystorePasswordFile = "ClientKeyManagment/TekuKeyConfig/passwords/" +account.KeystorePassFileName

	var newValidator ClientValidatorConfig
	newValidator.Path = account.Path
	newValidator.Pubkey = account.Pubkey
	newValidator.Teku = newTeku

	// m.ImportNewKeyStores()

	if !pubKeys[newValidator.Pubkey] {
		data, err := json.MarshalIndent(newValidator, "", "  ")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%v", color.GreenString("New Config Entry: "))
		fmt.Println(string(data))
		m.Config[m.ClientName].Validators[index[1]] = newValidator
	} else {
		fmt.Printf("%v%v %v\n", color.RedString("Already Exists: "), newValidator.Pubkey, m.ClientConfigFile)
	}
}

func (m *Manage) WrightConfig () {
	config, err := json.MarshalIndent(m.Config, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	// fmt.Println(string(config))
	err = ioutil.WriteFile(m.ClientConfigFile , config, 0664)
	if err != nil {
		fmt.Println(err)
	}
}

func (m *Manage) WrightPubkeyList () {
	var pubkeyList []string
	for clientname := range m.Config {
		for _, validator := range m.Config[clientname].Validators {
			pubkeyList = append(pubkeyList, validator.Pubkey)
		}
	}

	data, err := json.MarshalIndent(pubkeyList, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	err = ioutil.WriteFile(m.RootDir + "TekuPubkeyList.json" , data, 0664)
	if err != nil {
		fmt.Println(err)
	}
}

func (m *Manage) PrintClientAndValidators () {
	data, err := json.MarshalIndent(m.Config[m.ClientName], "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(data))
}

func (m *Manage) CreateTekuValidators (account Account) {
	if _, err := os.Stat(m.RootDir + "TekuKeyConfig/validators/" + account.KeystoreFileName); os.IsNotExist(err) {
		err := ioutil.WriteFile(m.RootDir + "TekuKeyConfig/validators/" + account.KeystoreFileName , []byte(account.FileBytes), 0664)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%v%v%v%v\n", color.GreenString("Writeing File:  "), m.RootDir, "TekuKeyConfig/validators/", account.KeystoreFileName)
	} else {
		fmt.Printf("%v%v%v%v\n", color.RedString("Already Exists: "), m.RootDir, "TekuKeyConfig/validators/", account.KeystoreFileName)
	}
}

func (m *Manage) CreateTekuSignerConfig (account Account) {
	if _, err := os.Stat(m.RootDir + "TekuKeyConfig/" + account.ConfigFileName); os.IsNotExist(err) {
		configData := "type: \"file-keystore\"\n" +
			"keyType: \"BLS\"\n" +
			"keystoreFile: \"validators/" + account.KeystoreFileName + "\"\n" +
			"keystorePasswordFile: \"passwords/" + account.KeystorePassFileName + "\""
		// fmt.Println(string(configData))
		err := ioutil.WriteFile(m.RootDir + "TekuKeyConfig/" + account.ConfigFileName, []byte(configData), 0664)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%v%v%v%v\n", color.GreenString("Writeing File:  "), m.RootDir, "TekuKeyConfig/", account.ConfigFileName)
	} else {
		fmt.Printf("%v%v%v%v\n", color.RedString("Already Exists: "), m.RootDir, "TekuKeyConfig/", account.ConfigFileName)
	}
}

func (m *Manage) CreateTekuPasswordFile (account Account) {
	// create web3signer password file
	if _, err := os.Stat(m.RootDir + "TekuKeyConfig/passwords/" + account.KeystorePassFileName); os.IsNotExist(err) {
		err := ioutil.WriteFile(m.RootDir + "TekuKeyConfig/passwords/" + account.KeystorePassFileName , []byte(m.KeystorePassword), 0664)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%v%v%v%v\n", color.GreenString("Writeing File:  "), m.RootDir, "TekuKeyConfig/passwords/", account.KeystorePassFileName)
	} else {
		fmt.Printf("%v%v%v%v\n", color.RedString("Already Exists: "), m.RootDir, "TekuKeyConfig/passwords/", account.KeystorePassFileName)
	}
}

func (m *Manage) BackupConfig () {
	timename := int32(time.Now().Unix())
	copy.Copy(m.RootDir + "TekuKeyConfig", "backups/backup-" + fmt.Sprint(timename))
	copy.Copy(m.ClientConfigFile, "backups/backup-" + fmt.Sprint(timename))
}

func (m *Manage) ImportNewKeyStores () {
	files, err := ioutil.ReadDir(m.Import)
	if err != nil {
		fmt.Println(err)
	}
	for _, f := range files {
		file, err := ioutil.ReadFile(m.Import + "/" + f.Name())
		if err != nil {
			fmt.Println(err)
			return
		}
		res, err := regexp.MatchString(`^keystore-m_12381_3600_\d*_\d_\d-\d+.json$`, f.Name())
		if err != nil {
			fmt.Println(err)
			return
		}
		if res == false {
			fmt.Println("Invalid Keystore Name")
			return
		}
		var account Account
		err = json.Unmarshal(file, &account)
		account.FileBytes = file
		account.FileName = f.Name()
		m.SourceAccounts = append(m.SourceAccounts, account)
	}
}

func (m *Manage) CheckDestDir () {
	if _, err := os.Stat(m.ClientConfigFile); os.IsNotExist(err) {
		fmt.Println("Didn't find client config at: " + m.ClientConfigFile)
		return
	}
}

func (m *Manage) LoadClientConfig () {
	if _, err := os.Stat(m.ClientConfigFile); os.IsNotExist(err) {
		fmt.Println("Didn't find client config at: " + m.ClientConfigFile)
		return
	}
	file, err := ioutil.ReadFile(m.ClientConfigFile)
	if err != nil {
		fmt.Println(err)
	}
	err = json.Unmarshal(file, &m.Config)
	if err != nil {
		fmt.Println(err)
	}
	for _, validator := range m.Config[m.ClientName].Validators {
		pubKeys[validator.Pubkey] = true
	}
}


























































