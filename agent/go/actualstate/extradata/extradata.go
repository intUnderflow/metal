package extradata

import (
	"encoding/json"
	"os"
	"sync"
)

type ExtraData interface {
	GetExtraData() map[string]string
	ApplyExtraData(map[string]string) error
}

func NewExtraData(filePath string) ExtraData {
	return &extraData{
		mutex:       &sync.RWMutex{},
		filePath:    filePath,
		appliedData: make(map[string]string),
	}
}

type extraData struct {
	mutex       *sync.RWMutex
	filePath    string
	appliedData map[string]string
}

func (e *extraData) GetExtraData() map[string]string {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.appliedData
}

func (e *extraData) ApplyExtraData(data map[string]string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	marshalledData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	err = os.WriteFile(e.filePath, marshalledData, 0644)
	if err != nil {
		return err
	}

	e.appliedData = data
	return nil
}
