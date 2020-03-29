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

func TestMultiShare(t *testing.T) {
	alice, _:= InitUser("alice", "fubar")
	bob, _:= InitUser("bob", "foobar")
	caitlyn, _ := InitUser("caitlyn", "foobar")
	data1 := []byte("This is a test")
	data2 := []byte("This is a test also")
	alice.StoreFile("alicefile",data1)
	bob.StoreFile("bobfile", data2)
	magic_string_alice, _:= alice.ShareFile("alicefile", "caitlyn")
	magic_string_bob, _:= bob.ShareFile("bobfile", "caitlyn")
	err := caitlyn.ReceiveFile("caitlynfile", "alice", magic_string_bob)
	if err == nil {
		t.Error("Should not be able to receive it with wrong string", err)
		return
	}
	err2 := caitlyn.ReceiveFile("caitlynfile", "alice", magic_string_alice)

	if err2 != nil{
		t.Error("Should be able to receive it with good string", err2)
		return
	}
	_, err3 := alice.LoadFile("alicefile")
	if err3!=nil {
		t.Error("Should be able to load it after sharing", err3)
		return
	}

}
func TestMultiLogin(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	laptop, _ := GetUser("alice", "fubar")
	phone, _ := GetUser("alice", "fubar")
	if (!reflect.DeepEqual(u, phone) || !reflect.DeepEqual(laptop, phone)) {
		t.Error("User is not the same")
		return
	}

	data := []byte("This is a test")
	u.StoreFile("file1", data)

	data2, err := laptop.LoadFile("file1")
	if err != nil {
		t.Error("should be able to load file when login using 2 devices", err)
		return
	}

	data3, err2 := phone.LoadFile("file1")
	if err2 != nil {
		t.Error("Phone is not getting the update from laptop", err2)
		return
	}

	if (!reflect.DeepEqual(data, data2) || !reflect.DeepEqual(data2, data3) || !reflect.DeepEqual(data, data3)) {
		t.Error("Data is not the same. Loading after one user instance stores.")
		return
	}

	text := []byte("This is the appended msg")
	phone.AppendFile("file1", text)

	data4, _ := u.LoadFile("file1")
	data5, _ := phone.LoadFile("file1")
	data6, _ := laptop.LoadFile("file1")
	if (!reflect.DeepEqual(data4, data5) || !reflect.DeepEqual(data5, data6) || !reflect.DeepEqual(data4, data6)) {
		t.Error("Data is not the same. Loading after one user instance appends.")
		return
	}
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
	bob_file := []byte("This is a different test")
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

	//testing Bob storing a different file with same name should not affect alice's file or equal to alice's file
	bob.StoreFile("file1", bob_file)
	notFile1Again, err6 := bob.LoadFile("file1")
	if err6 != nil || reflect.DeepEqual(data1, notFile1Again) {
		t.Error("Bob's file should not be the same anymore", err6)
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
	test2 := []byte("sss")
	err22 := david.AppendFile("file4", test2)
	if err22 == nil {
		t.Error("David should not have access anymore", err22)
		return
	}
	_, err20 := eve.LoadFile("evefile")
	if err20 != nil {
			t.Error("Eve failed to load", err20)
			return
	}
	err17 = alice.RevokeFile("file1", "frank")
	if err17 != nil {
			t.Error("Revocation failed", err17)
			return
	}
	_, err18 := frank.LoadFile("frankfile")
	if err18 == nil {
			t.Error("frank's access should have been revoked by Alice", err18)
			return
	}
	_, err21 := eve.LoadFile("evefile")
	if err21 == nil {
		t.Error("frank's access should have been revoked by Alice", err21)
		return
	}

	test4 := []byte("This is another test by Alice")
	alice.StoreFile("fileforcharley", test4)

	magic_string5, err22 := alice.ShareFile("fileforcharley", "charley")
	if err22 != nil {
		t.Error("Sharing failed", err22)
		return
	}
	err22 = charley.ReceiveFile("charleysfile", "alice", magic_string3)
	if err22 == nil {
		t.Error("Charley shouldn't be able to get Alice's shared file without the correct magic string", err22)
		return
	}
	err22 = charley.ReceiveFile("charleysfile", "alice", magic_string5)
	if err22 != nil {
		t.Error("Receiving file failed", err22)
		return
	}

	test5 := []byte("Alice's last test!!!!!")
	alice.StoreFile("file2forcharley", test5)

	magic_string6, err23 := alice.ShareFile("file2forcharley", "charley")
	if err23 != nil {
		t.Error("Sharing failed", err23)
		return
	}
	err23 = charley.ReceiveFile("charleysfile", "alice", magic_string6)
	if err23 == nil {
		t.Error("Charley shouldn't be able to save two files unde the same name", err22)
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
	bob, _ := InitUser("bob", "fubar")
	file := userlib.RandomBytes(userlib.AESBlockSize + 16)
	file2 := userlib.RandomBytes(userlib.AESBlockSize + 32)
	additional := userlib.RandomBytes(userlib.AESBlockSize + 8)

	alex.StoreFile("hamilton", file)
	aaron.StoreFile("burr", file2)
	magic1, _ := alex.ShareFile("hamilton", "bob")
	bob.ReceiveFile("bobfile", "alex", magic1)
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
	loading2, _ := bob.LoadFile("bobfile")

	expectedAppend := append(file, additional...)
	if !reflect.DeepEqual(expectedAppend, loading) || !reflect.DeepEqual(expectedAppend, loading2){
		t.Error("Loaded content should be the same as expected", expectedAppend, loading)
		return
	}


}
