package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/MetaBloxIO/metablox-foundation-services/contract"
	"github.com/MetaBloxIO/metablox-foundation-services/credentials"
	"github.com/MetaBloxIO/metablox-foundation-services/did"
	"github.com/MetaBloxIO/metablox-foundation-services/key"
	"github.com/MetaBloxIO/metablox-foundation-services/models"
	"github.com/MetaBloxIO/metablox-foundation-services/presentations"
	"github.com/ethereum/go-ethereum/crypto"
	hmyAddress "github.com/harmony-one/go-sdk/pkg/address"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
	"math/big"
	"os"
	"strconv"
	"strings"
)

const (
	cliCreateDID       = "createDID"
	cliListDIDs        = "listDIDs"
	cliPrintDID        = "printDID"
	cliRegisterDID     = "registerDID"
	cliResolveDID      = "resolveDID"
	cliCreateWiFiVC    = "createWiFiVC"
	cliCreateMiningVC  = "createMiningVC"
	cliVerifyVC        = "verifyVC"
	cliCreateVP        = "createVP"
	cliVerifyVP        = "verifyVP"
	cliNetworkRequest  = "networkRequest"
	cliNetworkResponse = "networkResponse"
	cliHelp            = "help"
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

const baseIDString = "http://metablox.com/credentials/"

type flagPars struct {
	name         string
	defaultValue interface{}
	valueType    valueType
	usage        string
}

type NetworkConfirmRequest struct {
	Did           string `json:"did"`
	Target        string `json:"target"`
	LastBlockHash string `json:"lastBlockHash"`
	Quality       string `json:"quality"`
	PubKey        string `json:"pubKey"`
	Challenge     string `json:"challenge"`
	Signature     string `json:"signature"`
}

type NetworkConfirmResult struct {
	Did           string `json:"did"`
	Target        string `json:"target"`
	LastBlockHash string `json:"lastBlockHash"`
	PubKey        string `json:"pubKey"`
	Challenge     string `json:"challenge"`
	Signature     string `json:"signature"`
}

//list of commands
var cmdList = []string{
	cliCreateDID,
	cliListDIDs,
	cliPrintDID,
	cliRegisterDID,
	cliResolveDID,
	cliCreateWiFiVC,
	cliCreateMiningVC,
	cliVerifyVC,
	cliCreateVP,
	cliVerifyVP,
	cliNetworkRequest,
	cliNetworkResponse,
	cliHelp,
}

var cmdHandleMap = map[string]commandHandler{
	cliCreateDID:       createDIDHandler,
	cliListDIDs:        listDIDsHandler,
	cliPrintDID:        printDIDHandler,
	cliRegisterDID:     registerDIDHandler,
	cliResolveDID:      resolveDIDHandler,
	cliCreateWiFiVC:    createWiFiVCHandler,
	cliCreateMiningVC:  createMiningVCHandler,
	cliVerifyVC:        verifyVCHandler,
	cliCreateVP:        createVPHandler,
	cliVerifyVP:        verifyVPHandler,
	cliNetworkRequest:  networkRequestHandler,
	cliNetworkResponse: networkResponseHandler,
	cliHelp:            helpHandler,
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
		flagPars{
			name:         "id",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "Credential id",
		},
	},
	cliCreateMiningVC: {
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
		flagPars{
			name:         "id",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "Credential id",
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
		flagPars{
			name:         "nonce",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "VP Nonce",
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

	cliNetworkRequest: {
		flagPars{
			name:         "name",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "DID Name",
		},
		flagPars{
			name:         "target",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "target did",
		},
		flagPars{
			name:         "nonce",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "VP Nonce",
		},
	},

	cliNetworkResponse: {
		flagPars{
			name:         "name",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "DID Name",
		},
		flagPars{
			name:         "target",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "target did",
		},
		flagPars{
			name:         "nonce",
			defaultValue: "",
			valueType:    valueTypeString,
			usage:        "VP Nonce",
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

	privKey, err := crypto.ToECDSA(didKey)
	if err != nil {
		log.Error("Parse did key failed")
		return
	}
	address := crypto.PubkeyToAddress(privKey.PublicKey)
	hmyAddr := hmyAddress.ToBech32(hmyAddress.Parse(address.Hex()))
	fmt.Println("DID Document:")
	fmt.Println(string(didDoc))

	fmt.Printf("DID key:%s\n", hex.EncodeToString(didKey))
	fmt.Printf("hmy Address key:%s\n", hmyAddr)
}

func registerDIDHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("registerDID", flag.ExitOnError)
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

	contract.Init()

	didStr := didDoc.ID[13:]

	err = contract.UploadDocument(&didDoc, didStr, privKey)
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

	contract.Init()

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
	printArgsFlag := flag.NewFlagSet("createWiFiVC", flag.ExitOnError)
	namePtr := printArgsFlag.String("name", "", "DID Name")
	typePtr := printArgsFlag.String("type", "", "Credential Type")
	subjectsPtr := printArgsFlag.String("subjects", "", "Credential Subjects")
	idPtr := printArgsFlag.String("id", "", "Credential id")
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

	if idPtr == nil || len(*idPtr) == 0 {
		log.Error("Credential id must be specified")
		return
	}

	var wifiSubject models.WifiAccessInfo

	err := json.Unmarshal([]byte(*subjectsPtr), &wifiSubject)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Decode WifiAccess json error")
		return
	}

	createVC(*namePtr, wifiSubject, models.TypeWifi, *idPtr)
}

func createVC(name string, subject any, subType string, id string) {
	didDocStr, err := GlobalContext.db.Get([]byte("did"+name), nil)
	if err != nil {
		log.Error("Read did document failed")
		return
	}

	var didDoc models.DIDDocument
	json.Unmarshal(didDocStr, &didDoc)

	didKey, err := GlobalContext.db.Get([]byte("key"+name), nil)
	if err != nil {
		log.Error("Read did key failed")
		return
	}
	privKey, err := crypto.ToECDSA(didKey)
	if err != nil {
		log.Error("Parse did key failed")
		return
	}

	credentials.IssuerDID = didDoc.ID
	credentials.IssuerPrivateKey = privKey

	vc, err := credentials.CreateVC(&didDoc)
	if err != nil {
		log.Error("Create vc failed")
		return
	}

	vc.Type = append(vc.Type, subType)
	vc.Description = subType + "Credential"
	vc.CredentialSubject = subject

	//Upload VC to DB and generate ID. Has to be done before creating signature, as changing the ID will change the signature
	err = credentials.ConvertTimesToDBFormat(vc)
	if err != nil {
		log.Error("Create vc failed")
		return
	}

	vc.ID = baseIDString + id
	hashedVC := sha256.Sum256(credentials.ConvertVCToBytes(*vc))

	signatureData, err := key.CreateJWSSignature(privKey, hashedVC[:])
	if err != nil {
		log.Error("Signature vc failed")
		return
	}
	vc.Proof.JWSSignature = signatureData

	vcStr, _ := json.Marshal(vc)

	fmt.Println("VC:")
	fmt.Println(string(vcStr))
}

func createMiningVCHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("createMiningVC", flag.ExitOnError)
	namePtr := printArgsFlag.String("name", "", "DID Name")
	typePtr := printArgsFlag.String("type", "", "Credential Type")
	subjectsPtr := printArgsFlag.String("subjects", "", "Credential Subjects")
	idPtr := printArgsFlag.String("id", "", "Credential id")
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

	if idPtr == nil || len(*idPtr) == 0 {
		log.Error("Credential id must be specified")
		return
	}

	var miningSubject models.MiningLicenseInfo

	err := json.Unmarshal([]byte(*subjectsPtr), &miningSubject)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Decode MiningLicense json error")
		return
	}

	createVC(*namePtr, miningSubject, models.TypeMining, *idPtr)
}

func verifyVCHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("verifyVC", flag.ExitOnError)
	vcPtr := printArgsFlag.String("vc", "", "vc")
	printArgsFlag.Parse(args)

	if vcPtr == nil || len(*vcPtr) == 0 {
		log.Error("VC must be specified")
		return
	}
	fmt.Printf("VC:\n%s\n", *vcPtr)

	var vcModel models.VerifiableCredential
	err := json.Unmarshal([]byte(*vcPtr), &vcModel)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Decode VC json error")
		return
	}

	patchVCSubjects(&vcModel)

	credentials.IssuerDID = vcModel.Issuer
	contract.Init()

	ret, err := credentials.VerifyVC(&vcModel)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Verify VC json error")
		return
	}

	fmt.Println("Verify vc " + strconv.FormatBool(ret))
}

func createVPHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("createVP", flag.ExitOnError)
	namePtr := printArgsFlag.String("name", "", "DID Name")
	vcPtr := printArgsFlag.String("vc", "", "vc")
	noncePtr := printArgsFlag.String("nonce", "", "Nonce")

	printArgsFlag.Parse(args)

	if namePtr == nil || len(*namePtr) == 0 {
		log.Error("Name must be specified")
		return
	}

	if vcPtr == nil || len(*vcPtr) == 0 {
		log.Error("VC must be specified")
		return
	}

	if noncePtr == nil || len(*noncePtr) == 0 {
		log.Error("Nonce must be specified")
		return
	}

	var vcModel []models.VerifiableCredential
	err := json.Unmarshal([]byte(*vcPtr), &vcModel)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Decode VC json error")
		return
	}

	for i, _ := range vcModel {
		patchVCSubjects(&vcModel[i])
	}

	didDocStr, err := GlobalContext.db.Get([]byte("did"+*namePtr), nil)
	if err != nil {
		log.Error("Read did document failed")
		return
	}

	var didDoc models.DIDDocument
	json.Unmarshal(didDocStr, &didDoc)

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

	vp, err := presentations.CreatePresentation(vcModel, didDoc, privKey, *noncePtr)
	if err != nil {
		log.Error("Create vp failed")
		return
	}

	vpStr, _ := json.Marshal(vp)

	fmt.Println("VP:")
	fmt.Println(string(vpStr))
}

func verifyVPHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("verifyVP", flag.ExitOnError)
	vpPtr := printArgsFlag.String("vp", "", "vp")
	printArgsFlag.Parse(args)

	if vpPtr == nil || len(*vpPtr) == 0 {
		log.Error("VP must be specified")
		return
	}

	var vpModel models.VerifiablePresentation
	err := json.Unmarshal([]byte(*vpPtr), &vpModel)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Decode VP json error")
		return
	}

	for i, _ := range vpModel.VerifiableCredential {
		patchVCSubjects(&vpModel.VerifiableCredential[i])
	}

	credentials.IssuerDID = vpModel.VerifiableCredential[0].Issuer
	contract.Init()

	ret, err := presentations.VerifyVP(&vpModel)
	if err != nil {
		log.WithFields(
			log.Fields{
				"error": err,
			}).Error("Verify VP json error")
		return
	}

	fmt.Println("Verify vp " + strconv.FormatBool(ret))
}

func networkRequestHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("networkRequest", flag.ExitOnError)
	namePtr := printArgsFlag.String("name", "", "did name")
	targetPtr := printArgsFlag.String("target", "", "target did")
	noncePtr := printArgsFlag.String("nonce", "", "nonce")
	printArgsFlag.Parse(args)

	if namePtr == nil || len(*namePtr) == 0 {
		log.Error("did name must be specified")
		return
	}

	if targetPtr == nil || len(*targetPtr) == 0 {
		log.Error("target did must be specified")
		return
	}

	if noncePtr == nil || len(*noncePtr) == 0 {
		log.Error("nonce must be specified")
		return
	}

	didDocStr, err := GlobalContext.db.Get([]byte("did"+*namePtr), nil)
	if err != nil {
		log.Error("Read did document failed")
		return
	}

	var didDoc models.DIDDocument
	json.Unmarshal(didDocStr, &didDoc)

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

	pubKeyBytes := crypto.FromECDSAPub(&privKey.PublicKey)
	pubkeyStr := base64.StdEncoding.EncodeToString(pubKeyBytes)

	req := NetworkConfirmRequest{
		Did:           didDoc.ID,
		Target:        *targetPtr,
		LastBlockHash: "",
		Quality:       "100",
		PubKey:        pubkeyStr,
		Challenge:     *noncePtr,
	}

	reqBytes, _ := serializeNetworkReq(&req)
	hashedData := sha256.Sum256(reqBytes)

	sig, _ := limitEcdsaSign(privKey, hashedData[:])
	req.Signature = sig

	reqStr, _ := json.Marshal(req)
	fmt.Println("Req:")
	fmt.Println(string(reqStr))
}

func networkResponseHandler(args []string) {
	printArgsFlag := flag.NewFlagSet("networkResponse", flag.ExitOnError)
	namePtr := printArgsFlag.String("name", "", "did name")
	targetPtr := printArgsFlag.String("target", "", "target did")
	noncePtr := printArgsFlag.String("nonce", "", "nonce")
	printArgsFlag.Parse(args)

	if namePtr == nil || len(*namePtr) == 0 {
		log.Error("did name must be specified")
		return
	}

	if targetPtr == nil || len(*targetPtr) == 0 {
		log.Error("target did must be specified")
		return
	}

	if noncePtr == nil || len(*noncePtr) == 0 {
		log.Error("nonce must be specified")
		return
	}

	didDocStr, err := GlobalContext.db.Get([]byte("did"+*namePtr), nil)
	if err != nil {
		log.Error("Read did document failed")
		return
	}

	var didDoc models.DIDDocument
	json.Unmarshal(didDocStr, &didDoc)

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

	pubKeyBytes := crypto.FromECDSAPub(&privKey.PublicKey)
	pubkeyStr := base64.StdEncoding.EncodeToString(pubKeyBytes)

	req := NetworkConfirmResult{
		Did:           didDoc.ID,
		Target:        *targetPtr,
		LastBlockHash: "",
		PubKey:        pubkeyStr,
		Challenge:     *noncePtr,
	}

	reqBytes, _ := serializeNetworkResult(&req)
	hashedData := sha256.Sum256(reqBytes)

	sig, _ := limitEcdsaSign(privKey, hashedData[:])
	req.Signature = sig

	reqStr, _ := json.Marshal(req)
	fmt.Println("Resp:")
	fmt.Println(string(reqStr))
}

func limitEcdsaSign(privKey *ecdsa.PrivateKey, hashedData []byte) (string, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashedData[:])
	if err != nil {
		return "", err
	}

	halfN := new(big.Int).Div(privKey.Curve.Params().N, big.NewInt(2))
	if s.Cmp(halfN) > 0 {
		s = new(big.Int).Sub(privKey.Curve.Params().N, s)
	}

	curveBits := privKey.Curve.Params().BitSize
	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes++
	}

	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	out := append(rBytesPadded, sBytesPadded...)

	return base64.StdEncoding.EncodeToString(out), nil
}

func serializeNetworkReq(req *NetworkConfirmRequest) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(req.Did)
	buffer.WriteString(req.Target)
	buffer.WriteString(req.LastBlockHash)
	buffer.WriteString(req.Quality)
	buffer.WriteString(req.PubKey)
	buffer.WriteString(req.Challenge)

	return buffer.Bytes(), nil
}

func serializeNetworkResult(result *NetworkConfirmResult) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(result.Did)
	buffer.WriteString(result.Target)
	buffer.WriteString(result.LastBlockHash)
	buffer.WriteString(result.PubKey)
	buffer.WriteString(result.Challenge)

	return buffer.Bytes(), nil
}

func patchVCSubjects(vc *models.VerifiableCredential) {
	subjectJsonStr, _ := json.Marshal(vc.CredentialSubject)
	if vc.Type[1] == models.TypeWifi {
		var wifiSubject models.WifiAccessInfo
		json.Unmarshal(subjectJsonStr, &wifiSubject)
		vc.CredentialSubject = wifiSubject
	} else if vc.Type[1] == models.TypeMining {
		var miningSubject models.MiningLicenseInfo
		json.Unmarshal(subjectJsonStr, &miningSubject)
		vc.CredentialSubject = miningSubject
	}
}

func helpHandler(args []string) {
	if len(args) == 0 {
		printUsage()
		return
	}

	cmdFlag, exist := cmdFlagsMap[args[0]]
	if exist == false {
		fmt.Println("Invalid command:", args[0])
		printUsage()
		return
	}

	fmt.Println("Flags:")
	for _, v := range cmdFlag {
		fmt.Printf("\t-%s: %s\n", v.name, v.usage)
	}
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

	viper.SetConfigFile("./config.yaml")
	viper.ReadInConfig()

	GlobalContext = AppContext{db: db}

	cmdHandle(args[1:])
}
