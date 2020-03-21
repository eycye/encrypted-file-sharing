package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect" // https://golang.org/pkg/reflect/
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(false)

	alice, err := InitUser("alice", "fubar")
	if alice == nil || err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	bob, err := InitUser("bob", "fubar")
	if bob == nil || err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	alice2, err := GetUser("alice", "fubar")
	if alice2 == nil || err != nil {
		// t.Error says the test fails
		t.Error("Failed to get existing user", err)
		return
	}

	aliceBytes, _ := json.Marshal(alice)
	alice2Bytes, _ := json.Marshal(alice2)
	if !reflect.DeepEqual(aliceBytes, alice2Bytes) {
		t.Error("InitUser and GetUser didn't obtain same user")
	}

	for _, val := range userlib.DatastoreGetMap() {
		if strings.Contains("alice", string(val)) || strings.Contains("bob", string(val) {
			t.Error("Username not encoded")
			return
		}
	}

	notalice, err := GetUser("alice", "ufbar")
	if notalice != nil || err == nil {
		// t.Error says the test fails
		t.Error("User entered wrong password", err)
		return
	}

	notuser, err := GetUser("bob", "fubar")
	if notuser != nil || err == nil {
		// t.Error says the test fails
		t.Error("User should not exist", err)
		return
	}

	clear()
	rjh, err := InitUser("rjh", "nk")
	if rjh == nil || err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	seri, err := InitUser("seri", "sk")
	if seri == nil || err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	var keys []userlib.UUID
	for key, _ := range datastore {
		keys = append(keys, key)
	}
	for i := 0; i < len(keys); i++ {
		datastore[keys[i]] = userlib.RandomBytes(len(keys[i]))
	}

	_, err := GetUser("rjh", "fubar")
	_, err2 := GetUser("seri", "fubar")

	if err == nil || err2 == nil {
		t.Error("Datastore was corrupted but got users")
	}

	clear()
	dan, err := InitUser("dan", "seo")
	if rjh == nil || err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	alberto, err := InitUser("alberto", "gu")
	if seri == nil || err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	var keys []userlib.UUID
	for key, _ := range datastore {
		keys = append(keys, key)
	}

	replace := []byte{'c', 'l', 'o', 'y'}
	for i := 0; i < len(keys) - 1; i++ {
		userlib.DataStoreSet(keys[i], replace)
	}

	_, err := GetUser("dan", "fubar")
	_, err2 := GetUser("alberto", "fubar")

	if err == nil || err2 == nil {
		t.Error("Datastore was corrupted but got users")
	}

	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	userlib.SetDebugStatus(false)
	clear()

	alice, err := InitUser("alice", "fubar")
	bob, err := InitUser("bob", "fubar")
	charley, err := InitUser("charley", "fubar")

	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	data1 := []byte("This is a test")
	alice.StoreFile("file1", data1)
	notFile1, err1 := charley.LoadFile("file1")
	if err1 == nil || reflect.DeepEqual(data1, notFile1) {
		t.Error("Charley should not have access to a file that alice saved", err1)
		return
	}

	data2 := []bytes("This is another test")
	charley.StoreFile("file2", data2)
	data2Get, err2 := charley.LoadFile("file2")
	if err2 != nil || !reflect.DeepEqual(data2, data2Get) {
		t.Error("Failed to upload and download", err2)
		return
	}

	notFile1Again, err3 := bob.LoadFile("file1")
	if err3 != nil || reflect.DeepEqual(data1, notFile1Again) {
		t.Error("Bob should not be able to load the file because he is not the owner", err3)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}
}


func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}
