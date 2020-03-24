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
	userlib.SetDebugStatus(true)

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
		t.Error("InitUser and GetUser didn't obtain same user", aliceBytes, alice2Bytes)
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
	userlib.SetDebugStatus(true)
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
	if err1 == nil {
		t.Error("Charley should not have access to a file that alice saved", err1)
		return
	}
	if reflect.DeepEqual(data1, notFile1) {
		t.Error("Charley should not have access to a file that alice saved", data1, notFile1)
		return
	}

	data2 := []bytes("This is another test")
	charley.StoreFile("file2", data2)
	data2Get, err2 := charley.LoadFile("file2")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(data2, data2Get) {
		t.Error("Failed to upload and download", data2, data2Get)
		return
	}

	notFile1Again, err3 := bob.LoadFile("file1")
	if err3 != nil {
		t.Error("Bob should not be able to load the file because he is not the owner", err3)
		return
	}
	if reflect.DeepEqual(data1, notFile1Again) {
		t.Error("Bob should not be able to load the file because he is not the owner", data1, notFile1Again)
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


func TestShareandRevoke(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	charley, err := InitUser("charley", "fuubar")
	david, err := InitUser("david", "fuuubar")
	eve, err := InitUser("eve", "fuuuubar")
	frank, err := InitUser("frank", "fuuuuubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	test1 := []byte("This is a test")
	alice.StoreFile("file1", test1)

	var test2 []byte
	var magic_string string

	test1, err = alice.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = alice.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = bob.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	err = charley.ReceiveFile("file3", "alice", magic_string)
	if err == nil {
		t.Error("C should not be able to load the file since it was not sent to her", err)
		return
	}
	test2, err = bob.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(test1, test2) {
		t.Error("Shared file is not the same", test1, test2)
		return
	}
	var magic_string2 string
	magic_string2, err = bob.ShareFile("file1", "david")
	if err == nil {
		t.Error("The name of Bob's file should be file2, but not file1", err)
		return
	}
	magic_string2, err = bob.ShareFile("file2", "david")
	if err != nil {
		t.Error("Bob should be able to share the file since he has access to it", err)
		return
	}
	err = david.ReceiveFile("file4", "bob", magic_string2)
	if err != nil {
		t.Error("David failed to receive the file sent from Bob", err)
		return
	}
	test3, err = david.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(test1, test3) {
		t.Error("Shared file is not the same, non direct child's file should be the same as owner's.", test1, test3)
		return
	}
	// revoke testing: alice shares with bob, bob shares with david, alice shares with frank, frank shares with eve
	// alice can only revoke the files she owned, with the name she chose
	// revoke bob's access, neither bob nor david has access
	// revoke eve's access, frank should still have access, and eve should not
	magic_string3, err =  alice.ShareFile("file1", "frank")
	frank.ReceiveFile("frankfile", "alice", magic_string3)
	magic_string4, err =  frank.ShareFile("file1", "eve")
	eve.ReceiveFile("evefile", "frank", magic_string4)
	err = alice.RevokeFile("file2", "bob")
	if err == nil {
		t.Error("alice should only be able to revoke the file based on how she named it", err)
		return
	}
	err = alice.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("alice should be able to revoke the file since she is the owner", err)
		return
	}
	test2, err = bob.LoadFile("file2")
	if err == nil {
			t.Error("Bob should not have access anymore", err)
			return
	}
	test4, err = david.LoadFile("file4")
	if err == nil {
			t.Error("David should not have access anymore", err)
			return
	}
	err = alice.RevokeFile("file1", "eve")
	test5, err = eve.LoadFile("evefile")
	if err == nil {
			t.Error("Alice should be able to revoke a non direct child's access", err)
			return
	}
	test6, err = frank.LoadFile("frankfile")
	if err != nil {
			t.Error("Frank should still have access since only eve's access is revoked", err)
			return
	}
}

func TestCorruptDatastore(t *testing.T){
	clear()
	test1 := []byte("This is a test")
	alice, err := InitUser("alice", "fubar")
	alice.StoreFile("file1", test1)

	datastore := userlib.DatastoreGetMap()
	for key, _ := range datastore{
		if datastore[key] == test1 {
			datastore[key] = "The file is now modified"
		}
	}
	test2, err = alice.LoadFile("file1")
	if err == nil {
		t.Error("Alice should be notified that the file has been modified and thus not be able to retrieve the file", err)
		return
	}
	if reflect.DeepEqual(test1, test2) {
		t.Error("The file should not be the same", test1, test2)
		return
	}
}


func TestAppend(t *testing.T) {
	userlib.SetDebugStatus(true)
	clear()

	alex, err := InitUser("alex", "fubar")
	if err != nil {
		t.Error(err)
		return
	}

	aaron, err := InitUser("aaron", "fubar")
	if err != nil {
		t.Error(err)
		return
	}

	file := userlib.RandomBytes(userlib.AESBlockSize + 16)
	file2 := userlib.RandomBytes(userlib.AESBlockSize + 32)
	additional := userlib.RandomBytes(userlib.AESBlockSize + 8)

	user.StoreFile("hamilton", file)
	user.StoreFile("burr", file2)
	err1 := alex.AppendFile("hamilton", additional)
	if err1 != nil {
		t.Error("Append failed", err)
		return
	}

	err2 := alex.AppendFile("burr", additional)
	if err2 == nil {
		t.Error("Alex should not have access to Aaron's file", err2)
		return
	}

	loading, err3 := alex.LoadFile("hamilton")
	if err != nil {
		t.Error("Load appended file failed", err)
		return
	}
	expectedAppend := append(file, additional...)
	if !reflect.DeepEqual(expectedAppend, loading) {
		t.Error("Loaded content should be the same as expected", err)
		return
	}
}
