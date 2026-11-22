package wallet

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

const (
	walletSchemaMigration       = "wallet-schema"
	walletToolboxModulePath     = "github.com/bsv-blockchain/go-wallet-toolbox"
	walletToolboxVersionFile    = "wallet-toolbox.version"
	walletVersionUnavailableLog = "wallet migration version tracking disabled: wallet-toolbox build version unavailable"
)

type walletBuildInfoReader func() (*debug.BuildInfo, bool)

type walletMigrationVersion struct {
	path    string
	version string
}

func walletDatabaseNeedsInitialization(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return info.Size() == 0, nil
}

func prepareWalletMigrationVersion(
	dataDir string,
	needsInitialization bool,
	logger *slog.Logger,
	readBuildInfo walletBuildInfoReader,
	started []func(string) error,
) (walletMigrationVersion, error) {
	state := walletMigrationVersion{path: filepath.Join(dataDir, walletToolboxVersionFile)}
	version, ok := walletToolboxBuildVersion(readBuildInfo)
	if !ok {
		logger.Warn(walletVersionUnavailableLog)
		return state, nil
	}
	state.version = version
	if needsInitialization {
		return state, nil
	}

	previous, err := os.ReadFile(state.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return state, fmt.Errorf("read wallet toolbox version: %w", err)
	}
	if err == nil && strings.TrimSpace(string(previous)) == version {
		return state, nil
	}
	if err := recordWalletMigration(started); err != nil {
		return state, fmt.Errorf("record wallet migration start: %w", err)
	}
	return state, nil
}

func walletToolboxBuildVersion(readBuildInfo walletBuildInfoReader) (string, bool) {
	info, ok := readBuildInfo()
	if !ok || info == nil {
		return "", false
	}
	for _, dependency := range info.Deps {
		if dependency == nil || dependency.Path != walletToolboxModulePath {
			continue
		}
		builtModule := dependency
		if dependency.Replace != nil {
			builtModule = dependency.Replace
		}
		if !usableModuleVersion(builtModule.Version) {
			return "", false
		}
		if builtModule.Path != "" && builtModule.Path != walletToolboxModulePath {
			return builtModule.Path + "@" + builtModule.Version, true
		}
		return builtModule.Version, true
	}
	return "", false
}

func usableModuleVersion(version string) bool {
	return version != "" && version != "(devel)"
}

func migrateWalletStorage(migrate func() error, version walletMigrationVersion) error {
	if err := migrate(); err != nil {
		return fmt.Errorf("migrate wallet storage: %w", err)
	}
	if version.version == "" {
		return nil
	}
	if err := writeWalletToolboxVersion(version.path, version.version); err != nil {
		return fmt.Errorf("write wallet toolbox version: %w", err)
	}
	return nil
}

func writeWalletToolboxVersion(path, version string) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0640); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.WriteString(temporary, version+"\n"); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	removeTemporary = false

	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func recordWalletMigration(started []func(string) error) error {
	if len(started) == 0 || started[0] == nil {
		return nil
	}
	return started[0](walletSchemaMigration)
}
