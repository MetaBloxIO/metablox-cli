package metablox_cli

import (
	"fmt"
	"os"
)

const (
	cliCreateDID   = "createDID"
	cliListDIDs    = "listDIDs"
	cliPrintDID    = "printDID"
	cliRegisterDID = "registerDID"
	cliResolveDID  = "resolveDID"
	cliCreateVC    = "createVC"
	cliVerifyVC    = "verifyVC"
	cliCreateVP    = "createVP"
	cliVerifyVP    = "verifyVP"
	cliHelp        = "help"
)

type valueType int

type commandHandler func(args []string)

//type enum
const (
	valueTypeInt = iota
	valueTypeString
	boolType
	valueTypeUint64
)

type flagPars struct {
	name         string
	defaultValue interface{}
	valueType    valueType
	usage        string
}

//list of commands
var cmdList = []string{
	cliCreateDID,
	cliListDIDs,
	cliPrintDID,
	cliRegisterDID,
	cliResolveDID,
	cliCreateVC,
	cliVerifyVC,
	cliCreateVP,
	cliVerifyVP,
	cliHelp,
}

var cmdHandleMap = map[string]commandHandler{
	cliCreateDID:   createDIDHandler,
	cliListDIDs:    listDIDsHandler,
	cliPrintDID:    printDIDHandler,
	cliRegisterDID: registerDIDHandler,
	cliResolveDID:  resolveDIDHandler,
	cliCreateVC:    createVCHandler,
	cliVerifyVC:    verifyVCHandler,
	cliCreateVP:    createVPHandler,
	cliVerifyVP:    verifyVPHandler,
	cliHelp:        helpHandler,
}

var cmdFlagsMap = map[string][]flagPars{
	cliCreateDID: {
		flagPars{
			name:         "key",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "key hex string, if no key, create random key",
		},
		flagPars{
			name:         "name",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "DID Name",
		},
	},

	cliListDIDs: {},

	cliPrintDID: {
		flagPars{
			name:         "name",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "DID Name",
		},
	},

	cliRegisterDID: {
		flagPars{
			name:         "name",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "DID Name",
		},
	},

	cliResolveDID: {
		flagPars{
			name:         "did",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "DID String",
		},
	},

	cliCreateVC: {
		flagPars{
			name:         "name",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "DID Name",
		},
		flagPars{
			name:         "type",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "Credential Type",
		},
		flagPars{
			name:         "subjects",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "Credential Subjects",
		},
	},
	cliVerifyVC: {
		flagPars{
			name:         "vc",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "Credential Contents",
		},
	},
	cliCreateVP: {
		flagPars{
			name:         "vc",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "Credentials",
		},
		flagPars{
			name:         "name",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "DID Name",
		},
	},
	cliVerifyVP: {
		flagPars{
			name:         "vp",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "Presentation Contents",
		},
	},
	cliHelp: {},
}

func printUsage() {
	fmt.Println("Usage:")
	for _, cmd := range cmdList {
		fmt.Println(" ", cmd)
	}
	fmt.Println("Note: Use the command 'cli help' to get the command usage in details")
}

func createDIDHandler(args []string) {

}

func listDIDsHandler(args []string) {

}

func printDIDHandler(args []string) {

}

func registerDIDHandler(args []string) {

}

func resolveDIDHandler(args []string) {

}

func createVCHandler(args []string) {

}

func verifyVCHandler(args []string) {

}

func createVPHandler(args []string) {

}

func verifyVPHandler(args []string) {

}

func helpHandler(args []string) {

}

func main() {
	args := os.Args[1:]

	if len(args) < 1 {
		printUsage()
		return
	}

	cmdHandle, exist := cmdHandleMap[args[0]]
	if exist == false {
		fmt.Println("Invalid command:", args[0])
		printUsage()
		return
	}

	cmdHandle(args[1:])
}
