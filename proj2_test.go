package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect" // https://golang.org/pkg/reflect/
	"github.com/cs161-staff/userlib"
	"encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	"strings"
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

	u, err0 := InitUser("staff", "fubar")
	if err0 != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err0)
		return
	}

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	_, err1 := InitUser("bob", "fubar") //bob
	if err1 != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err1)
		return
	}

	alice2, err2 := GetUser("alice", "fubar")
	if err2 != nil {
		// t.Error says the test fails
		t.Error("Failed to get existing user", err2)
		return
	}

	aliceBytes, _ := json.Marshal(alice)
	alice2Bytes, _ := json.Marshal(alice2)
	if !reflect.DeepEqual(aliceBytes, alice2Bytes) {
		t.Error("Didn't obtain same user as the one created", aliceBytes, alice2Bytes)
		return
	}

	datastoreMap := userlib.DatastoreGetMap()
	var dsKeys []userlib.UUID
	var values [][]byte
	for k, v := range datastoreMap {
		dsKeys = append(dsKeys, k)
		values = append(values, v)
	}

	for val := range values {
		if strings.Contains("alice", string(val)) || strings.Contains("bob", string(val)) {
			t.Error("Username readable to public", err)
			return
		}
	}

	_, err3 := GetUser("alice", "ufbar")
	if err3 == nil {
		// t.Error says the test fails
		t.Error("User entered wrong password but successfully logged in", err3)
		return
	}

	_, err4 := GetUser("donald", "fubar")
	if err4 == nil {
		// t.Error says the test fails
		t.Error("User should not exist", err4)
		return
	}

	for i := 0; i < len(dsKeys); i++ {
		datastoreMap[dsKeys[i]] = userlib.RandomBytes(len(dsKeys[i]))
	}

	_, err5 := GetUser("alice", "fubar")
	_, err6 := GetUser("bob", "fubar")

	if err5 == nil || err6 == nil {
		t.Error("Datastore was corrupted but got user")
	}

	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// userlib.SetDebugStatus(true)
	clear()

	u, err0 := InitUser("black", "fubar")
	if err0 != nil {
		t.Error("Failed to initialize user", err0)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("pink", v)

	v2, err00 := u.LoadFile("pink")
	if err00 != nil {
		t.Error("Failed to upload and download", err00)
		return
	}

	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	bob, err1 := InitUser("bob", "fubar")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}

	charley, err2 := InitUser("charley", "fubar")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	data1 := []byte("This is Alice's test")
	alice.StoreFile("file1", data1)
	notFile1, err3 := charley.LoadFile("file1")
	if err3 == nil || reflect.DeepEqual(data1, notFile1) {
		t.Error("Charley should not have access to a file that alice saved", err3)
		return
	}

	data2 := []byte("This is Charley's test")
	charley.StoreFile("file2", data2)
	data2Get, err4 := charley.LoadFile("file2")
	if err4 != nil {
		t.Error("Failed to upload and download", err4)
		return
	}
	if !reflect.DeepEqual(data2, data2Get) {
		t.Error("Uploaded and downloaded file not the same", data2, data2Get)
		return
	}

	notFile1Again, err5 := bob.LoadFile("file1")
	if err5 == nil || reflect.DeepEqual(data1, notFile1Again) {
		t.Error("Bob should not be able to load the file because he is not the owner", err5)
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
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}


func TestShare(t *testing.T) {
	clear()

	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	bob, err0 := InitUser("bob", "foobar")
	if err0 != nil {
		t.Error("Failed to initialize bob", err0)
		return
	}

	charley, err1 := InitUser("charley", "fuubar")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}

	david, err2 := InitUser("david", "fuuubar")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	eve, err3 := InitUser("eve", "fuuuubar")
	if err3 != nil {
		t.Error("Failed to initialize user", err3)
		return
	}

	frank, err4 := InitUser("frank", "fuuuuubar")
	if err4 != nil {
		t.Error("Failed to initialize user", err4)
		return
	}

	// revoke testing: alice shares with bob, bob shares with david, alice shares with frank, frank shares with eve
	// alice can only revoke the files she owned, with the name she chose
	// revoke bob's access, neither bob nor david has access
	// revoke eve's access, frank should still have access, and eve should not

	// alice.file1 = bob.file2 = david.file4 = frank.frankfile = eve.evefile

	test1 := []byte("This is Alice's test")
	alice.StoreFile("file1", test1)

	var test1get []byte
	var magic_string string

	test1get, err5 := alice.LoadFile("file1")
	if err5 != nil {
		t.Error("Failed to download the file from Alice", err5)
		return
	}
	if !reflect.DeepEqual(test1, test1get) {
		t.Error("Saved file is not the same", test1, test1get)
		return
	}

	magic_string, err6 := alice.ShareFile("file1", "bob")
	if err6 != nil {
		t.Error("Failed to share file with Bob", err6)
		return
	}

	err7 := bob.ReceiveFile("file2", "alice", magic_string)
	if err7 != nil {
		t.Error("Failed to receive the shared message", err7)
		return
	}

	err8 := charley.ReceiveFile("file3", "alice", magic_string)
	if err8 == nil {
		t.Error("Charley should not be able to load the file since it was not sent to her", err8)
		return
	}

	test2get, err9 := bob.LoadFile("file2")
	if err9 != nil {
		t.Error("Failed to download the file after sharing", err9)
		return
	}
	if !reflect.DeepEqual(test1get, test2get) {
		t.Error("Shared file is not the same", test1get, test2get)
		return
	}

	var magic_string2 string
	magic_string2, err10 := bob.ShareFile("file1", "david")
	if err10 == nil {
		t.Error("Bob doesn't have a file named 'file1'", err10)
		return
	}
	magic_string2, err11 := bob.ShareFile("file2", "david")
	if err11 != nil {
		t.Error("Bob failed to share existing file", err11)
		return
	}

	err12 := david.ReceiveFile("file4", "bob", magic_string2)
	if err12 != nil {
		t.Error("David failed to receive the file sent from Bob", err12)
		return
	}

	test3get, err13 := david.LoadFile("file4")
	if err13 != nil {
		t.Error("Failed to download received file", err13)
		return
	}

	if !reflect.DeepEqual(test1get, test3get) {
		t.Error("Shared file is not the same, non direct child's file should be the same as owner's", test1get, test3get)
		return
	}

	if !reflect.DeepEqual(test2get, test3get) {
		t.Error("Shared file is not the same", test2get, test3get)
		return
	}

	magic_string3, err14 := alice.ShareFile("file1", "frank")
	if err14 != nil {
		t.Error("Sharing failed", err14)
		return
	}
	err14 = frank.ReceiveFile("frankfile", "alice", magic_string3)
	if err14 != nil {
		t.Error("Receive failed", err14)
		return
	}

	magic_string4, err15 := frank.ShareFile("frankfile", "eve")
	if err15 != nil {
		t.Error("Sharing failed", err15)
		return
	}
	err15 = eve.ReceiveFile("evefile", "frank", magic_string4)
	if err15 != nil {
		t.Error("Receive failed", err15)
		return
	}

	err15 = alice.RevokeFile("file2", "bob")
	if err15 == nil {
		t.Error("Alice doesn't have file named 'file2'", err15)
		return
	}
	err15 = alice.RevokeFile("file1", "bob")
	if err15 != nil {
		t.Error("Revocation failed", err15)
		return
	}

	_, err16 := bob.LoadFile("file2")
	if err16 == nil {
			t.Error("Bob should not have access anymore", err16)
			return
	}

	_, err17 := david.LoadFile("file4")
	if err17 == nil {
			t.Error("David should not have access anymore", err17)
			return
	}
	err17 = alice.RevokeFile("file1", "eve")
	if err17 != nil {
			t.Error("Revocation failed", err17)
			return
	}

	_, err18 := eve.LoadFile("evefile")
	if err18 == nil {
			t.Error("Eve's access should have been revoked by Alice", err18)
			return
	}

	_, err19 := frank.LoadFile("frankfile")
	if err19 != nil {
			t.Error("Frank should still have access since only Eve's access is revoked", err19)
			return
	}
}

func TestAppend(t *testing.T) {
	clear()
	alex, err := InitUser("alex", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	aaron, err1 := InitUser("aaron", "fubar")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}

	file := userlib.RandomBytes(userlib.AESBlockSize + 16)
	file2 := userlib.RandomBytes(userlib.AESBlockSize + 32)
	additional := userlib.RandomBytes(userlib.AESBlockSize + 8)

	alex.StoreFile("hamilton", file)
	aaron.StoreFile("burr", file2)
	err2 := alex.AppendFile("hamilton", additional)
	if err2 != nil {
		t.Error("Append failed", err2)
		return
	}

	err2 = alex.AppendFile("burr", additional)
	if err2 == nil {
		t.Error("Alex should not have access to Aaron's file", err2)
		return
	}

	loading, err3 := alex.LoadFile("hamilton")
	if err3 != nil {
		t.Error("Load appended file failed", err3)
		return
	}

	expectedAppend := append(file, additional...)
	if !reflect.DeepEqual(expectedAppend, loading) {
		t.Error("Loaded content should be the same as expected", expectedAppend, loading)
		return
	}
}
