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
	Record Node
 }

type Node struct {
 Children []*Node
 UUIDreceive uuid.UUID
 Username string
}

// encrypts data/struct and add to Datastore
func StoringData(UUID *uuid.UUID, EncK *[]byte, HMACK *[]byte, jsonData *[]byte) (err error) {
	IV := userlib.RandomBytes(userlib.AESBlockSize) // userlib.go
	encryption := userlib.SymEnc(*EncK, IV, *jsonData)// SymEnc(key []byte, iv []byte, plaintext []byte) ([]byte)
	hmacd, err := userlib.HMACEval(*HMACK, encryption)
	if err != nil {
		return
	}
	combinedEnc := append(encryption, hmacd...)
	jsonEncryption, err := json.Marshal(combinedEnc)
	userlib.DatastoreSet(*UUID, jsonEncryption)
	return
}

func GettingData(UUID *uuid.UUID, EncK *[]byte, HMACK *[]byte) (data *[]byte, err error) {
	jsonEncryption, ok := userlib.DatastoreGet(*UUID)
	if !ok {
		err = errors.New("UUID not found in keystore")
		return
	}

	combinedEnc := make([]byte, 16 + 64)
	err = json.Unmarshal(jsonEncryption, &combinedEnc)
	if err!= nil {
		return
	}
	encryption := combinedEnc[:16]
	givenHmacd := combinedEnc[16:]
	hmacd, err := userlib.HMACEval(*HMACK, encryption)
	if !userlib.HMACEqual(hmacd, givenHmacd) {
		err = errors.New("Integrity/Authenticity violated")
	}
	*data = userlib.SymDec(*EncK, encryption)
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
	var userdata User
	userdataptr = &userdata

	// Initialize userdata
	userdata.Username = username
	userdata.Location = make(map[string]uuid.UUID)

	concatKeys := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySize + userlib.HashSize)) // UEncK || HMACKey
	userdata.UEncK = concatKeys[:userlib.AESKeySize]
	userdata.HMACKey = concatKeys[userlib.AESKeySize:]
	genUUID, _ := userlib.HMACEval(userdata.HMACKey, []byte(username))
	userdata.UUID, _ = uuid.FromBytes(genUUID[:16]) // UUID 16 bytes

	signingKey, VerifyK, _ := userlib.DSKeyGen()
	PublicK, privateKey, _ := userlib.PKEKeyGen()
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
	var userdata User
	userdataptr = &userdata

	concatKeys := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySize + userlib.HashSize)) // UEncK || HMACKey
	userdata.UEncK = concatKeys[:userlib.AESKeySize]
	userdata.HMACKey = concatKeys[userlib.AESKeySize:]
	genUUID, _ := userlib.HMACEval(userdata.HMACKey, []byte(username))
	userdata.UUID, _ = uuid.FromBytes(genUUID[:16]) // UUID 16 bytes

	byteUserdata, err := GettingData(&userdata.UUID, &userdata.UEncK, &userdata.HMACKey)
	err = json.Unmarshal(*byteUserdata, userdataptr)
	if err != nil {
		if err.Error() == "UUID not found in keystore" {
			err = errors.New("incorrect login credentials")
		}
		return
	}
	return
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	UUIDtemp := uuid.New()
	// figure out what to do if filename exists
	userdata.Location[filename] = UUIDtemp

	var file File
	file.Data = data
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	concatFKeys := userlib.Argon2Key(IV, file.UUIDF[:], uint32(userlib.AESKeySize * 2))
	file.FEncK = concatFKeys[:userlib.AESKeySize]
	file.FHMACK = concatFKeys[userlib.AESKeySize:]
	file.UUIDF = uuid.New()

	var compfile CompFile
	compfile.UUIDCF = uuid.New()
	file.SourceUUID = compfile.UUIDCF
	concatCFKeys := userlib.Argon2Key(IV, compfile.UUIDCF[:], uint32(userlib.AESKeySize * 2))
	compfile.CFEncK = concatCFKeys[:userlib.AESKeySize]
	compfile.CFHMACK = concatCFKeys[userlib.AESKeySize:]
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
	stringCFEncK := string(compfile.CFEncK)
	stringCFHMACK := string(compfile.CFHMACK)
	CF_Data := compfile.UUIDCF.String() + stringCFEncK + stringCFHMACK
	jsonEncryption, err := json.Marshal(CF_Data)
	userlib.DatastoreSet(UUIDtemp, jsonEncryption)
	var node Node
	node.Username = userdata.Username
	node.UUIDreceive = userdata.UUID
	var chdn []*Node
	node.Children = chdn
	compfile.Record = node

	// encrypt file & compfile
	jsonFiledata, _ := json.Marshal(file)
	err = StoringData(&file.UUIDF, &file.FEncK, &file.FHMACK, &jsonFiledata)
	if err != nil {
		userlib.DebugMsg("", err)
		return
	}
	jsonCFdata, _ := json.Marshal(compfile)
	err = StoringData(&compfile.UUIDCF, &compfile.CFEncK, &compfile.CFHMACK, &jsonCFdata)
	if err != nil {
		userlib.DebugMsg("", err)
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
	DataSize := 16 + userlib.AESKeySize * 2
	combined := make([]byte, DataSize)
	err = json.Unmarshal(jsonEncryption, &combined)
	if err!= nil {
		return
	}
	UUIDCF := bytesToUUID(combined[:16])
	CFEncK := []byte(combined[16:16+userlib.AESKeySize-1])
	CFHMACK := []byte(combined[16+userlib.AESKeySize:])

	var file File
	file.Data = data
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	concatFKeys := userlib.Argon2Key(IV, file.UUIDF[:], uint32(userlib.AESKeySize * 2))
	file.FEncK = concatFKeys[:userlib.AESKeySize]
	file.FHMACK = concatFKeys[userlib.AESKeySize:]
	file.UUIDF = uuid.New()
	var index int
 	compfileBytes, err := GettingData(&UUIDCF, &CFEncK, &CFHMACK)
	var compfile CompFile
	err = json.Unmarshal(*compfileBytes, &compfile)
	if err!= nil {
		return
	}
	file.SourceUUID = compfile.UUIDCF
	jsonFiledata, _ := json.Marshal(file)
	err = StoringData(&file.UUIDF, &file.FEncK, &file.FHMACK, &jsonFiledata)
	if err != nil {
		userlib.DebugMsg("", err)
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
		userlib.DebugMsg("", err)
		return
	}
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.

func (userdata *User) LoadFile(filename string) (data []byte, err error) {
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

	DataSize := 16 + userlib.AESKeySize * 2
	combined := make([]byte, DataSize)
	err = json.Unmarshal(jsonEncryption, &combined)
	if err!= nil {
		return
	}
	UUIDCF := bytesToUUID(combined[:16])
	CFEncK := []byte(combined[16:16+userlib.AESKeySize-1])
	CFHMACK := []byte(combined[16+userlib.AESKeySize:])

 	compfileBytes, err := GettingData(&UUIDCF, &CFEncK, &CFHMACK)
	var compfile CompFile
	err = json.Unmarshal(*compfileBytes, &compfile)
	//TODO: This is a toy implementation.
	// UUID, _ := uuid.FromBytes([]byte(filename + userdata.Username)[:16])
	// packaged_data, ok := userlib.DatastoreGet(UUID)
	// if !ok {
	// 	return nil, errors.New(strings.ToTitle("File not found!"))
	// }
	// json.Unmarshal(packaged_data, &data)
	// // return data
	//End of toy implementation

	for i := 0; i < compfile.Count; i++ {
		UUIDF, _ := compfile.FilesUUID[i]
		FEncK, _ := compfile.FilesFEncK[i]
		FHMACK, _ := compfile.FilesHMACK[i]
		fileBytes, _ := GettingData(&UUIDF, &FEncK, &FHMACK)
		var file File
		err = json.Unmarshal(*fileBytes, &file)
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
			err = errors.New("UUID not found in keystore")
			return
		}
		UUIDreceive := uuid.New()
		userlib.DatastoreSet(UUIDreceive, jsonEncryption)

		DataSize := 16 + userlib.AESKeySize * 2
		combined := make([]byte, DataSize)
		err = json.Unmarshal(jsonEncryption, &combined)
		if err!= nil {
			return
		}
		UUIDCF := bytesToUUID(combined[:16])
		CFEncK := []byte(combined[16:16+userlib.AESKeySize-1])
		CFHMACK := []byte(combined[16+userlib.AESKeySize:])

		// var compfile CompFile
	 	compfileBytes, err := GettingData(&UUIDCF, &CFEncK, &CFHMACK)
		var compfile CompFile
		err = json.Unmarshal(*compfileBytes, &compfile)
		if err != nil {
			err = errors.New("file not found")
			return
		}
		tree := compfile.Record
		currNode, err := findByIdDFS(tree, userdata.Username)
		if err != nil {
			err = errors.New("file not found")
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
			userlib.DebugMsg("", err)
			return
		}

		// access_token: append UUIDreceive to the end, sign the msg, then enc with receiver's publickey
		// IV := userlib.RandomBytes(userlib.AESBlockSize)

		msg := UUIDreceive

		encryptKey, ok := userlib.KeystoreGet(recipient + "_enck")
		//encmsg := userlib.SymEnc(encryptKey, IV, msg[:]) // SymEnc(key []byte, iv []byte, plaintext []byte) ([]byte)
		encmsg, err := userlib.PKEEnc(encryptKey, msg[:])
		signed, err := userlib.DSSign(userdata.SignK, msg[:])
		//encsign := userlib.SymEnc(encryptKey, IV, signed)
		encsign, err := userlib.PKEEnc(encryptKey, signed[:])
		//encrypt the signature and append it to encmsg
		combined = append(encmsg, encsign...)
		magic_string_Bytes, _ := json.Marshal(combined)
		magic_string = string(magic_string_Bytes)
		return
}

func findByIdDFS(node Node, username string)(ret Node, err error) {
	if node.Username == username {
		ret = node
		return
	}
	if len(node.Children) > 0 {
		for _, child := range node.Children {
			found, err := findByIdDFS(*child, username)
			if err != nil {
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
			//findByIdDFS(*child, jsonEncryption)
		}
	}
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) (err error) {
	var magic_string_Bytes []byte
	err = json.Unmarshal([]byte(magic_string), &magic_string_Bytes)
	if err!= nil {
		return
	}
	//msg := userlib.SymDec(userdata.PrivateK, magic_string_Bytes[:len(magic_string) / 2]) // []byte of UUIDreceive
	msg, err:= userlib.PKEDec(userdata.PrivateK, magic_string_Bytes[:len(magic_string) / 2]) // []byte of UUIDreceive
	//signed := userlib.SymDec(userdata.PrivateK, magic_string_Bytes[len(magic_string) / 2:])
	signed, err := userlib.PKEDec(userdata.PrivateK, magic_string_Bytes[len(magic_string) / 2:])
	senderVerifyK, ok := userlib.KeystoreGet(sender + "_vfyk")
	if !ok {
		return errors.New("sender doesn't exist")
	}
	err = userlib.DSVerify(senderVerifyK, msg, signed)
	if err != nil {
		return errors.New("verification failed for msg")
	}
	UUIDreceive := bytesToUUID(msg)
	userdata.Location[filename] = UUIDreceive
	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
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

	DataSize := 16 + userlib.AESKeySize * 2
	combined := make([]byte, DataSize)
	err = json.Unmarshal(jsonEncryption, &combined)
	if err!= nil {
		return
	}
	UUIDCF := bytesToUUID(combined[:16])
	CFEncK := []byte(combined[16:16+userlib.AESKeySize-1])
	CFHMACK := []byte(combined[16+userlib.AESKeySize:])
	compfileBytes, err := GettingData(&UUIDCF, &CFEncK, &CFHMACK)
	var compfile CompFile
	err = json.Unmarshal(*compfileBytes, &compfile)
	if err != nil {
		err = errors.New("file not found")
		return
	}

	record := compfile.Record
	// Only the owner can revoke someone's access
	if userdata.UUID != record.UUIDreceive {
		err = errors.New("Only the owner can revoke somone's access")
		return
	}
	currnode, err := findByIdDFS(record, target_username)
	if err != nil {
		return
	}
	currnode.Children = nil
	currnode.Username = "Deleted"
	IV := userlib.RandomBytes(userlib.AESBlockSize)
	compfile.UUIDCF = uuid.New()
	concatFKeys := userlib.Argon2Key(IV, compfile.UUIDCF[:], uint32(userlib.AESKeySize * 2))
	compfile.CFEncK = concatFKeys[:userlib.AESKeySize]
	compfile.CFHMACK = concatFKeys[userlib.AESKeySize:]

	stringCFEncK := string(compfile.CFEncK)
	stringCFHMACK := string(compfile.CFHMACK)
	CF_Data := compfile.UUIDCF.String() + stringCFEncK + stringCFHMACK
	jsonEncryptionupdated, err := json.Marshal([]byte(CF_Data))
	appendByIdDFS(&record, jsonEncryptionupdated)

	err = StoringData(&compfile.UUIDCF, &compfile.CFEncK, &compfile.CFHMACK, &jsonEncryptionupdated)
	if err != nil {
		userlib.DebugMsg("", err)
		return
	}
	return
}
