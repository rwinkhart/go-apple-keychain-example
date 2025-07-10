package main

/*
#cgo LDFLAGS: -L./ -lSwiftLibrary -Wl,-rpath,.
#include <stdlib.h>

extern int delete_keychain_item();
extern int register_keychain_item(char* password, _Bool accessControl);
extern int keychain_item_exists();
extern int get_keychain_item(char* passwordBuffer, int bufferSize);
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "register":
		// Clean up any existing keychain item first
		fmt.Println("Cleaning up existing keychain items...")
		status := C.delete_keychain_item()
		fmt.Printf("Cleanup status: %d\n", status)

		// Register a new keychain item
		fmt.Println("Trying keychain registration...")
		password := C.CString("abc123")
		defer C.free(unsafe.Pointer(password))
		status = C.register_keychain_item(password, false)
		fmt.Printf("Registration status: %d\n", status)

		// Check if it worked
		exists := C.keychain_item_exists()
		if exists == 1 {
			fmt.Println(":) Keychain item was successfully created!")
		} else {
			fmt.Println(":'( Keychain item was not found")
		}
	case "read":
		// Read the keychain item
		fmt.Println("Reading keychain item...")
		passwordBuffer := make([]byte, 256) // Allocate buffer for password
		status := C.get_keychain_item((*C.char)(unsafe.Pointer(&passwordBuffer[0])), 256)

		if status == 0 { // errSecSuccess
			// Find the null terminator
			passwordLength := 0
			for i, b := range passwordBuffer {
				if b == 0 {
					passwordLength = i
					break
				}
			}
			password := string(passwordBuffer[:passwordLength])
			fmt.Printf(":) Successfully retrieved password: %s\n", password)
		} else {
			fmt.Printf(":'( Failed to retrieve keychain item. Status: %d\n", status)
		}
	}
}
