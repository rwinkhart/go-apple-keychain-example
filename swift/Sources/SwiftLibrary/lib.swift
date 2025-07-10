import Foundation

// -25300 = Item not found (errSecItemNotFound)
// -25299 = Duplicate item (errSecDuplicateItem)
// -25293 = Authentication failed (errSecAuthFailed)

// Global constants for keychain item identification
private let account = "null"
private let server = "com.rwinkhart.gokeychainexample"

@_cdecl("delete_keychain_item")
public func deleteKeychainItem() -> Int32 {
    let query: [String: Any] = [
        kSecClass as String: kSecClassInternetPassword,
        kSecAttrAccount as String: account,
        kSecAttrServer as String: server,
    ]

    let status = SecItemDelete(query as CFDictionary)
    return status
}

@_cdecl("register_keychain_item")
public func registerKeychainItem(_ password: UnsafePointer<CChar>, _ accessControl: CBool) -> Int32
{
    let swiftPassword = String(cString: password)

    // Define the base keychain item query
    var query: [String: Any] = [
        kSecClass as String: kSecClassInternetPassword,
        kSecAttrAccount as String: account,
        kSecAttrServer as String: server,
        kSecValueData as String: swiftPassword.data(using: .utf8)!,
    ]

    if accessControl {
        let access = SecAccessControlCreateWithFlags(
            nil,  // Use the default allocator.
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .userPresence,
            nil)  // Ignore any error.

        // Add access control to the query
        query[kSecAttrAccessControl as String] = access as Any
    } else {
        // Add accessibility attribute without access control
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }

    // Register the keychain item
    let status = SecItemAdd(query as CFDictionary, nil)
    return status
}

@_cdecl("keychain_item_exists")
public func keychainItemExists() -> UInt8 {
    let query: [String: Any] = [
        kSecClass as String: kSecClassInternetPassword,
        kSecAttrAccount as String: account,
        kSecAttrServer as String: server,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]

    let status = SecItemCopyMatching(query as CFDictionary, nil)

    // Return 1 if exists, 0 if not found
    return status == errSecSuccess ? 1 : 0
}

@_cdecl("get_keychain_item")
public func getKeychainItem(_ passwordBuffer: UnsafeMutablePointer<CChar>?, _ bufferSize: Int32)
    -> Int32
{
    let query: [String: Any] = [
        kSecClass as String: kSecClassInternetPassword,
        kSecAttrAccount as String: account,
        kSecAttrServer as String: server,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecReturnAttributes as String: true,
        kSecReturnData as String: true,
    ]

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)

    if let existingItem = item as? [String: Any],
        let passwordData = existingItem[kSecValueData as String] as? Data,
        let password = String(data: passwordData, encoding: String.Encoding.utf8),
        let passwordBuffer = passwordBuffer
    {
        // Successfully retrieved keychain item
        let passwordCString = password.cString(using: .utf8) ?? []
        let copyLength = min(Int(bufferSize) - 1, passwordCString.count - 1)

        if copyLength > 0 {
            passwordBuffer.update(from: passwordCString, count: copyLength)
            passwordBuffer[copyLength] = 0  // Null terminate
        } else if bufferSize > 0 {
            passwordBuffer[0] = 0  // Empty string if buffer too small
        }

        return status
    } else {
        // Failed to retrieve or parse keychain item
        if let passwordBuffer = passwordBuffer, bufferSize > 0 {
            passwordBuffer[0] = 0  // Empty string on failure
        }
        return status
    }
}
