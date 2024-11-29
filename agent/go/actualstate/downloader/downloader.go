package downloader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"sync"
)

type Downloader interface {
	GetFilePath(key string) string
	GetBinariesActualState() map[string]string
	DownloadBinary(key string, url string, expectedHash string) (err error)
}

func NewDownloader(filePath string) Downloader {
	return &downloaderImpl{
		mutex:    &sync.RWMutex{},
		filePath: filePath,
		binaries: make(map[string]string),
	}
}

type downloaderImpl struct {
	mutex    *sync.RWMutex
	filePath string
	binaries map[string]string
}

func (d *downloaderImpl) GetFilePath(key string) string {
	return fmt.Sprintf("%s/%s", d.filePath, key)
}

func (d *downloaderImpl) GetBinariesActualState() map[string]string {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	result := make(map[string]string)
	maps.Copy(result, d.binaries)
	return result
}

func (d *downloaderImpl) DownloadBinary(key string, url string, expectedHash string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	path := fmt.Sprintf("%s/%s", d.filePath, expectedHash)
	symlinkPath := fmt.Sprintf("%s/%s", d.filePath, key)
	_, err := os.Stat(path)
	if err == nil {
		// If no error here the content already exists, no need to download anything
		err = os.Symlink(path, symlinkPath)
		if err != nil {
			return err
		}
		d.binaries[key] = expectedHash
		return nil
	}

	response, err := http.Get(url)
	if err != nil {
		return err
	}
	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	responseBytesHash := sha256.Sum256(responseBytes)
	responseBytesHashStr := hex.EncodeToString(responseBytesHash[:])
	if responseBytesHashStr != expectedHash {
		return fmt.Errorf("expected hash %s, got %s", expectedHash, responseBytesHash)
	}

	err = os.WriteFile(path, responseBytes, 0700)
	if err != nil {
		return err
	}
	err = os.Symlink(path, symlinkPath)
	if err != nil {
		return err
	}
	d.binaries[key] = responseBytesHashStr

	return nil
}
