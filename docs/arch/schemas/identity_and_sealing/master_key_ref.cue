// DDD role: ValueObject

package identity_and_sealing

// #MasterKeyRef is a value object that locates the Master Key in the OS
// keychain without embedding the key material.
#MasterKeyRef: {
	service_id: "dev.fapp.merkle"
	account:    =~ "^master-v\\d+$"
	version:    int & >=1
}
