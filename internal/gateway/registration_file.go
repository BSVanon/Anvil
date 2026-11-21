package gateway

import "path/filepath"

const registrationFileName = "gateway-registrations.conf"

// RegistrationFile returns the daemon-writable certificate registration file.
func RegistrationFile(dataDir string) string {
	return filepath.Join(dataDir, registrationFileName)
}
