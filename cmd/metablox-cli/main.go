package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MetaBloxIO/metablox-foundation-services/contract"
	"github.com/MetaBloxIO/metablox-foundation-services/did"
	"github.com/MetaBloxIO/metablox-foundation-services/models"
	"github.com/ethereum/go-ethereum/crypto"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"os"
	"strings"
)

const (
	cliCreateDID    = "createDID"
	cliListDIDs     = "listDIDs"
	cliPrintDID     = "printDID"
	cliRegisterDID  = "registerDID"
	cliResolveDID   = "resolveDID"
	cliCreateWiFiVC = "createWiFiVC"
	cliVerifyVC     = "verifyVC"
	cliCreateVP     = "createVP"
	cliVerifyVP     = "verifyVP"
	cliHelp         = "help"
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
	cliCreateWiFiVC,
	cliVerifyVC,
	cliCreateVP,
	cliVerifyVP,
	cliHelp,
}

var cmdHandleMap = map[string]commandHandler{
	cliCreateDID:    createDIDHandler,
	cliListDIDs:     listDIDsHandler,
	cliPrintDID:     printDIDHandler,
	cliRegisterDID:  registerDIDHandler,
	cliResolveDID:   resolveDIDHandler,
	cliCreateWiFiVC: createWiFiVCHandler,
	cliVerifyVC:     verifyVCHandler,
	cliCreateVP:     createVPHandler,
	cliVerifyVP:     verifyVPHandler,
	cliHelp:         helpHandler,
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

	cliCreateWiFiVC: {
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

type AppContext struct {
	db *leveldb.DB
}

var GlobalContext AppContext

func createDIDHandler(args []string) {

	createArgsFlag := flag.NewFlagSet("createDID", flag.ExitOnError)

	keyPtr := createArgsFlag.String("key", "", "Private key in hex")
	namePtr := createArgsFlag.String("name", "", "DID Name")

	createArgsFlag.Parse(args)

	if namePtr == nil || len(*namePtr) == 0 {
		log.Error("Create DID must have a name")
		return
	}

	var privKey *ecdsa.PrivateKey
	if keyPtr != nil && len(*keyPtr) > 0 {
		privKeyLoad, err := crypto.HexToECDSA(*keyPtr)
		if err != nil {
			log.Error("Import private key failed")
			return
		}
		privKey = privKeyLoad
	} else {
		privKey, _ = crypto.GenerateKey()
	}

	didDoc := did.CreateDID(privKey)

	didDocStr, _ := json.Marshal(didDoc)

	GlobalContext.db.Put([]byte("did"+*namePtr), didDocStr, nil)
	GlobalContext.db.Put([]byte("key"+*namePtr), privKey.D.Bytes(), nil)

	fmt.Printf("Create DID:%s name:%s  privateKeyHex:%s\n", didDoc.ID, *namePtr, hex.EncodeToString(privKey.D.Bytes()))
}

func listDIDsHandler(args []string) {
	iter := GlobalContext.db.NewIterator(&util.Range{Start: []byte("did"), Limit: []byte("die")}, nil)
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		didName := string(key)[3:]

		var didDoc models.DIDDocument
		json.Unmarshal(value, &didDoc)

		fmt.Printf("%s: %s\n", didName, didDoc.ID)
	}
	iter.Release()
}

func printDIDHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("printDID", flag.ExitOnError)
	namePtr := printArgsFlag.String("name", "", "DID Name")
	printArgsFlag.Parse(args)

	didDoc, err := GlobalContext.db.Get([]byte("did"+*namePtr), nil)
	if err != nil {
		log.Error("Read did document failed")
		return
	}
	didKey, err := GlobalContext.db.Get([]byte("key"+*namePtr), nil)
	if err != nil {
		log.Error("Read did key failed")
		return
	}

	fmt.Println("DID Document:")
	fmt.Println(string(didDoc))

	fmt.Printf("DID key:%s\n", hex.EncodeToString(didKey))
}

func registerDIDHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("printDID", flag.ExitOnError)
	namePtr := printArgsFlag.String("name", "", "DID Name")
	printArgsFlag.Parse(args)

	didDocStr, err := GlobalContext.db.Get([]byte("did"+*namePtr), nil)
	if err != nil {
		log.Error("Read did document failed")
		return
	}
	didKey, err := GlobalContext.db.Get([]byte("key"+*namePtr), nil)
	if err != nil {
		log.Error("Read did key failed")
		return
	}
	privKey, err := crypto.ToECDSA(didKey)
	if err != nil {
		log.Error("Parse did key failed")
		return
	}

	var didDoc models.DIDDocument
	json.Unmarshal(didDocStr, &didDoc)

	err = contract.UploadDocument(&didDoc, didDoc.ID, privKey)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Upload did failed")
		return
	}
}

func resolveDIDHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("resolveDID", flag.ExitOnError)
	didPtr := printArgsFlag.String("did", "", "DID")
	printArgsFlag.Parse(args)

	if didPtr == nil || len(*didPtr) == 0 {
		log.Error("An DID must be specified")
		return
	}

	didStr := *didPtr

	if strings.HasPrefix(didStr, "did:metablox:") {
		didStr = didStr[13:]
	}

	doc, _, err := contract.GetDocument(didStr)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Resolve DID failed")
		return
	}

	docJsonBytes, _ := json.Marshal(doc)

	fmt.Println("DID Document")
	fmt.Println(string(docJsonBytes))
}

func createWiFiVCHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("createVC", flag.ExitOnError)
	namePtr := printArgsFlag.String("name", "", "DID Name")
	typePtr := printArgsFlag.String("type", "", "Credential Type")
	subjectsPtr := printArgsFlag.String("subjects", "", "Credential Subjects")
	printArgsFlag.Parse(args)

	if namePtr == nil || len(*namePtr) == 0 {
		log.Error("DID Name must be specified")
		return
	}

	if typePtr == nil || len(*typePtr) == 0 {
		log.Error("Credential Type must be specified")
		return
	}

	if subjectsPtr == nil || len(*subjectsPtr) == 0 {
		log.Error("Credential Subjects must be specified")
		return
	}

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

	db, err := leveldb.OpenFile("./db", nil)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
			"path":  "./db",
		}).Error("Open database failed")
		return
	}

	GlobalContext = AppContext{db: db}

	cmdHandle(args[1:])
}
