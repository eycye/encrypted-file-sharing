package proj2

// use methods and variables from https://github.com/cs161-staff/userlib/blob/master/userlib.go

// CS 161 Project 2 Spring 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
  var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	UUID uuid.UUID
	SignK userlib.DSSignKey // user signs message, pairs with VerifyK
	PrivateK userlib.PKEDecKey // pairs with PublicK
	UEncK []byte // symmetric key, param of SymEnc to encrypt user struct
	HMACKey []byte
	Location map[string]uuid.UUID // map: String filename -> UUID location of file information
	UUIDMap uuid.UUID

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}


type File struct{
	UUIDF uuid.UUID
	SourceUUID uuid.UUID
	FEncK []byte // symmetric key for encrypting the file
	FHMACK []byte
	Data []byte // content
}

type CompFile struct {
	UUIDCF uuid.UUID
	CFEncK []byte
	CFHMACK []byte
	Count int
	FilesUUID map[int]uuid.UUID
	FilesFEncK map[int][]byte
	FilesHMACK map[int][]byte
	Record *Node
 }

type Node struct {
 Children []*Node
 UUIDreceive uuid.UUID
 Username string
}

type Secret struct {
	Encryption []byte
	HMAC []byte
}


// encrypts data/struct and add to Datastore
func StoringData(UUID *uuid.UUID, EncK *[]byte, HMACK *[]byte, jsonData *[]byte) (err error) {
	IV := userlib.RandomBytes(userlib.AESBlockSize) // userlib.go
	encryption := userlib.SymEnc(*EncK, IV, *jsonData)// SymEnc(key []byte, iv []byte, plaintext []byte) ([]byte)
	hmacd, err := userlib.HMACEval(*HMACK, encryption)
	if err != nil {
		return
	}
	// combinedEnc := append(encryption, hmacd...)
	var secretive Secret
	secretive.Encryption = encryption
	secretive.HMAC = hmacd
	jsonEncryption, err := json.Marshal(secretive)
	userlib.DatastoreSet(*UUID, jsonEncryption)
	return
}

func GettingData(UUID *uuid.UUID, EncK *[]byte, HMACK *[]byte) (data []byte, err error) {
	jsonEncryption, ok := userlib.DatastoreGet(*UUID)
	if !ok {
		err = errors.New("UUID not found in keystore")
		return
	}

	// combinedEnc := make([]byte, 64)
	var secretive Secret
	err = json.Unmarshal(jsonEncryption, &secretive)
	if err!= nil {
		return
	}
	encryption := secretive.Encryption // ciphertext; encryption := userlib.SymEnc(*EncK, IV, *jsonData)
	givenHmacd := secretive.HMAC
	hmacd, err := userlib.HMACEval(*HMACK, encryption)
	if !userlib.HMACEqual(hmacd, givenHmacd) {
		err = errors.New("Integrity/Authenticity violated")
	}
	data = userlib.SymDec(*EncK, encryption)
	return
}


// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" || password == "" {
		err = errors.New("Can't have empty username/password")
		return
	}

	var userdata User
	userdataptr = &userdata

	// Initialize userdata
	userdata.Username = username
	userdata.Location = make(map[string]uuid.UUID)

	concatKeys := userlib.Argon2Key([]byte(password), []byte(username), 32) // UEncK || HMACKey
	userdata.UEncK = concatKeys[:16]
	userdata.HMACKey = concatKeys[16:]
	genUUID, _ := userlib.HMACEval(userdata.HMACKey, []byte(username))
	userdata.UUID, _ = uuid.FromBytes(genUUID[:16]) // UUID 16 bytes


	signingKey, VerifyK, _ := userlib.DSKeyGen()
	PublicK, privateKey, _ := userlib.PKEKeyGen()
	userdata.UUIDMap = uuid.New()
	userdata.SignK = signingKey
	userdata.PrivateK = privateKey
	userlib.KeystoreSet(username + "_vfyk", VerifyK)
	userlib.KeystoreSet(username + "_enck", PublicK)

	jsonUserdata, _ := json.Marshal(userdata)
	err = StoringData(&userdata.UUID, &userdata.UEncK, &userdata.HMACKey, &jsonUserdata) // encrypt user struct and store in Datastore
	return
}


// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	if username == "" || password == "" {
		err = errors.New("Can't have empty username/password")
		return
	}
	var userdata User
	userdataptr = &userdata

	concatKeys := userlib.Argon2Key([]byte(password), []byte(username), 32) // UEncK || HMACKey
	userdata.UEncK = concatKeys[:16]
	userdata.HMACKey = concatKeys[16:]
	genUUID, _ := userlib.HMACEval(userdata.HMACKey, []byte(username))
	userdata.UUID, _ = uuid.FromBytes(genUUID[:16]) // UUID 16 bytes

	byteUserdata, err := GettingData(&userdata.UUID, &userdata.UEncK, &userdata.HMACKey)
	if err != nil || byteUserdata == nil {
		err = errors.New("Can't login")
	}
	err = json.Unmarshal(byteUserdata, userdataptr)
	if err != nil {
		err = errors.New("Can't login")
	}
	return
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	if filename == "" {
		return
	}
	UUIDtemp := uuid.New()
	// figure out what to do if filename exists
	userdata.Location[filename] = UUIDtemp

	var file File
	file.Data = data
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	concatFKeys := userlib.Argon2Key(IV, file.UUIDF[:], 32)
	file.FEncK = concatFKeys[:16]
	file.FHMACK = concatFKeys[16:]
	file.UUIDF = uuid.New()

	var compfile CompFile
	compfile.UUIDCF = uuid.New()
	file.SourceUUID = compfile.UUIDCF
	concatCFKeys := userlib.Argon2Key(IV, compfile.UUIDCF[:], 32)
	compfile.CFEncK = concatCFKeys[:16]
	compfile.CFHMACK = concatCFKeys[16:]
	compfile.Count = 1
	compfile.FilesUUID = make(map[int]uuid.UUID)
	compfile.FilesUUID[0] = file.UUIDF
	compfile.FilesFEncK = make(map[int][]byte)
	compfile.FilesFEncK[0] = file.FEncK
	compfile.FilesHMACK = make(map[int][]byte)
	compfile.FilesHMACK[0] = file.FHMACK

	// store file and cf.

	// DataSize := 16 + userlib.AESKeySize * 2
	// CF_Data := make([]byte, DataSize)
	CF_Data := append(compfile.UUIDCF[:], compfile.CFEncK...)
	CF_Data = append(CF_Data, compfile.CFHMACK...)
	jsonEncryption, err := json.Marshal(CF_Data)
	userlib.DatastoreSet(UUIDtemp, jsonEncryption)
	var node Node
	node.Username = userdata.Username
	node.UUIDreceive = userdata.UUID
	var chdn []*Node
	node.Children = chdn
	compfile.Record = &node

	// encrypt file & compfile
	jsonFiledata, _ := json.Marshal(file)
	err = StoringData(&file.UUIDF, &file.FEncK, &file.FHMACK, &jsonFiledata)
	if err != nil {
		userlib.DebugMsg("Storing failed", err)
		return
	}
	jsonCFdata, _ := json.Marshal(compfile)
	err = StoringData(&compfile.UUIDCF, &compfile.CFEncK, &compfile.CFHMACK, &jsonCFdata)
	if err != nil {
		userlib.DebugMsg("Storing failed", err)
		return
	}
	jsonMapData, _ := json.Marshal(userdata.Location)
	err = StoringData(&userdata.UUIDMap, &userdata.UEncK, &userdata.HMACKey, &jsonMapData)
	if err != nil {
		userlib.DebugMsg("Storing failed", err)
		return
	}
	//TODO: This is a toy implementation.
	// UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// packaged_data, _ := json.Marshal(data)
	// userlib.DatastoreSet(UUID, packaged_data)
	//End of toy implementation
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	if filename == "" {
		err = errors.New("Can't have empty filename")
		return
	}
	UUIDtemp, ok := userdata.Location[filename]
	if !ok {
		err = errors.New("UUID not found in keystore")
		return
	}
	jsonEncryption, _ := userlib.DatastoreGet(UUIDtemp)
	if !ok {
		err = errors.New("UUID not found in keystore")
		return
	}
	//uuidcf, cfenk and cfhmack, 16 + 16 + 16
	combined := make([]byte, 48)
	err = json.Unmarshal(jsonEncryption, &combined)
	if err!= nil {
		return
	}
	UUIDCF := bytesToUUID(combined[:16])
	CFEncK := []byte(combined[16:32])
	CFHMACK := []byte(combined[32:])

	var file File
	file.Data = data
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	concatFKeys := userlib.Argon2Key(IV, file.UUIDF[:], 32)
	//file.uuidf[:] []bytes(file.UUIDF.String())
	file.FEncK = concatFKeys[:16]
	file.FHMACK = concatFKeys[16:]
	file.UUIDF = uuid.New()
	var index int
 	compfileBytes, err := GettingData(&UUIDCF, &CFEncK, &CFHMACK)
	var compfile CompFile
	err = json.Unmarshal(compfileBytes, &compfile)
	if err!= nil {
		return
	}
	file.SourceUUID = compfile.UUIDCF
	jsonFiledata, _ := json.Marshal(file)
	err = StoringData(&file.UUIDF, &file.FEncK, &file.FHMACK, &jsonFiledata)
	if err != nil {
		return
	}
	index = compfile.Count
	compfile.FilesUUID[index] = file.UUIDF
	compfile.FilesFEncK[index] = file.FEncK
	compfile.FilesHMACK[index] = file.FHMACK
	compfile.Count += 1
	jsonCFdata, _ := json.Marshal(compfile)
	err = StoringData(&compfile.UUIDCF, &compfile.CFEncK, &compfile.CFHMACK, &jsonCFdata)
	if err != nil {
		return
	}
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.

func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	if filename == "" {
		err = errors.New("Can't have empty filename")
		return
	}
	currMapByte, err := GettingData(&userdata.UUIDMap, &userdata.UEncK, &userdata.HMACKey)
	if err != nil {
		return
	}
	var currMap map[string]uuid.UUID
	err = json.Unmarshal(currMapByte, &currMap)
	if err != nil{
		userlib.DebugMsg("Error occurs when loading User's map", err)
		return
	}
	userdata.Location = currMap
	UUIDtemp, ok := userdata.Location[filename]
	if !ok {
		err = errors.New("UUID not found in keystore")
		return
	}
	jsonEncryption, _ := userlib.DatastoreGet(UUIDtemp)
	if !ok {
		err = errors.New("UUID not found in keystore")
		return
	}

	combined := make([]byte, 48)
	err = json.Unmarshal(jsonEncryption, &combined)
	if err!= nil {
		return
	}
	UUIDCF := bytesToUUID(combined[:16])
	CFEncK := []byte(combined[16:32])
	CFHMACK := []byte(combined[32:])
 	compfileBytes, err := GettingData(&UUIDCF, &CFEncK, &CFHMACK)
	var compfile CompFile
	err = json.Unmarshal(compfileBytes, &compfile)
	currNode, err2 := findByIdDFS(compfile.Record, userdata.Username)
	if err2 != nil || currNode == nil || currNode.Username == "Deleted" {
		err = errors.New("you do not have access")
		return
	}
	for i := 0; i < compfile.Count; i++ {
		UUIDF, _ := compfile.FilesUUID[i]
		FEncK, _ := compfile.FilesFEncK[i]
		FHMACK, _ := compfile.FilesHMACK[i]
		fileBytes, _ := GettingData(&UUIDF, &FEncK, &FHMACK)
		var file File
		err = json.Unmarshal(fileBytes, &file)
		if err!= nil {
			break
		}
		data = append(data, file.Data...)
	}

	return
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
		//check if file exists in sender
		UUIDtemp, ok := userdata.Location[filename]
		if !ok {
			err = errors.New("user does not have access to file")
			return
		}
		//getting the compfile from datastore
		jsonEncryption, ok := userlib.DatastoreGet(UUIDtemp)
		if !ok {
			err = errors.New("UUID not found in datastore")
			return
		}
		UUIDreceive := uuid.New()
		userlib.DatastoreSet(UUIDreceive, jsonEncryption)
		//The following lines are for updating record
		combined := make([]byte, 48)
		err = json.Unmarshal(jsonEncryption, &combined)
		if err != nil {
			return
		}
		UUIDCF := bytesToUUID(combined[:16])
		CFEncK := []byte(combined[16:32])
		CFHMACK := []byte(combined[32:])
		// var compfile CompFile
	 	compfileBytes, err := GettingData(&UUIDCF, &CFEncK, &CFHMACK)
		var compfile CompFile
		err = json.Unmarshal(compfileBytes, &compfile)
		if err != nil {
			err = errors.New("file not found")
			return
		}
		tree := compfile.Record
		currNode, err := findByIdDFS(tree, userdata.Username)
		if err != nil || currNode == nil {
			err = errors.New("file/user not found")
			return
		}

		var child Node
		child.Username = recipient
		child.UUIDreceive = UUIDreceive
		var chdn []*Node
		child.Children = chdn
		currNode.Children = append(currNode.Children, &child)
		// reencrypt compfile and store back in Datastore
		jsonCFdata, _ := json.Marshal(compfile)
		err = StoringData(&UUIDCF, &CFEncK, &CFHMACK, &jsonCFdata)
		if err != nil {
			return
		}

		// access_token: append UUIDreceive to the end, sign the msg, then enc with receiver's publickey
		// IV := userlib.RandomBytes(userlib.AESBlockSize)
		msg := UUIDreceive
		encryptKey, ok := userlib.KeystoreGet(recipient + "_enck")
		//encmsg := userlib.SymEnc(encryptKey, IV, msg[:]) // SymEnc(key []byte, iv []byte, plaintext []byte) ([]byte)
		encmsg, err := userlib.PKEEnc(encryptKey, msg[:])
		signed, err := userlib.DSSign(userdata.SignK, msg[:])
		//encrypt the signature and append it to encmsg
		var secret Secret
		secret.Encryption = encmsg
		secret.HMAC = signed
		magic_string_Bytes, _ := json.Marshal(secret)
		magic_string = string(magic_string_Bytes)
		return
}

func findByIdDFS(node *Node, username string)(ret *Node, err error) {
	if node == nil {
		ret = node
		return
	}
	if node.Username == username {
		ret = node
		return
	}
	if len(node.Children) > 0 {
		for _, child := range node.Children {
			found, err := findByIdDFS(child, username)
			if found == nil|| err != nil {
				err = errors.New("file not found")
				continue
			}
			if found.Username == username {
				ret = found
				err = nil
				break
			}
		}
	}
	return
}

func appendByIdDFS(node *Node, jsonEncryption []byte) {
	if node.Username != "Deleted" {
		UUIDreceive := node.UUIDreceive
		userlib.DatastoreSet(UUIDreceive, jsonEncryption)
	}
	if len(node.Children) > 0 {
		for _, child := range node.Children {
			appendByIdDFS(child, jsonEncryption)
		}
	}
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) (err error) {
	if filename == "" || sender == "" || magic_string == "" {
		err = errors.New("Can't have empty filename/sender/magic_string")
		return
	}
	var magic_string_Bytes Secret
	err = json.Unmarshal([]byte(magic_string), &magic_string_Bytes)
	if err!= nil {
		return
	}
	//msg := userlib.SymDec(userdata.PrivateK, magic_string_Bytes[:len(magic_string) / 2]) // []byte of UUIDreceive
	msg, err := userlib.PKEDec(userdata.PrivateK, magic_string_Bytes.Encryption) // []byte of UUIDreceive
	//signed := userlib.SymDec(userdata.PrivateK, magic_string_Bytes[len(magic_string) / 2:])
	signed := magic_string_Bytes.HMAC
	senderVerifyK, ok := userlib.KeystoreGet(sender + "_vfyk")
	if !ok {
		return errors.New("sender doesn't exist")
	}
	err = userlib.DSVerify(senderVerifyK, msg, signed)
	if err != nil {
		return errors.New("verification failed for msg")
	}
	UUIDreceive := bytesToUUID(msg)
	_, ok = userdata.Location[filename]
	if ok {
		return errors.New("use a different filename")
	}
	userdata.Location[filename] = UUIDreceive
	jsonMapData, _ := json.Marshal(userdata.Location)
	err = StoringData(&userdata.UUIDMap, &userdata.UEncK, &userdata.HMACKey, &jsonMapData)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	if filename == "" || target_username == "" {
		err = errors.New("Can't have empty filename/username")
		return
	}
	//verify the file exists
	UUIDtemp, ok := userdata.Location[filename]
	if !ok {
		err = errors.New("user does not have access to file")
		return
	}
	//getting the compfile from datastore
	jsonEncryption, ok := userlib.DatastoreGet(UUIDtemp)
	if !ok {
		err = errors.New("UUID not found in keystore")
		return
	}
	combined := make([]byte, 48)
	err = json.Unmarshal(jsonEncryption, &combined)
	if err!= nil {
		return
	}
	UUIDCF := bytesToUUID(combined[:16])
	CFEncK := []byte(combined[16:32])
	CFHMACK := []byte(combined[32:])
	compfileBytes, err := GettingData(&UUIDCF, &CFEncK, &CFHMACK)
	var compfile CompFile
	err = json.Unmarshal(compfileBytes, &compfile)
	if err != nil {
		err = errors.New("file not found")
		return
	}
	userlib.DatastoreDelete(compfile.UUIDCF)
	record := compfile.Record
	// Only the owner can revoke someone's access
	if userdata.UUID != record.UUIDreceive {
		err = errors.New("Only the owner can revoke somone's access")
		return
	}
	currnode, err := findByIdDFS(record, target_username)
	if err != nil || currnode == nil {
		err = errors.New("Target user not found")
		return
	}
	currnode.Children = nil
	currnode.Username = "Deleted"
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	compfile.UUIDCF = uuid.New()
	concatFKeys := userlib.Argon2Key(IV, compfile.UUIDCF[:], 32)
	compfile.CFEncK = concatFKeys[:16]
	compfile.CFHMACK = concatFKeys[16:]

	CF_Data := append(compfile.UUIDCF[:], compfile.CFEncK...)
	CF_Data = append(CF_Data, compfile.CFHMACK...)
	jsonEncryption, err = json.Marshal(CF_Data)
	userlib.DatastoreSet(UUIDtemp, jsonEncryption)
	appendByIdDFS(record, jsonEncryption)
	jsonCompfile, err := json.Marshal(compfile)
	err = StoringData(&compfile.UUIDCF, &compfile.CFEncK, &compfile.CFHMACK, &jsonCompfile)
	if err != nil {
		return
	}
	return
}
