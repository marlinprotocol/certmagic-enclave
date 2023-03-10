package certmagic_enclave

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/marlinprotocol/certmagic-enclave/attestation"
	"github.com/marlinprotocol/certmagic-enclave/utils"
	"go.uber.org/zap"
)

type Enclave struct {
	logger        *zap.Logger
	encryptionKey []byte

	// Enclave
	HostUrl     string          `json:"host_url"`
	Pcrs        map[uint][]byte `json:"pcrs"`
	MinCpus     uint64          `json:"min_cpus"`
	MinMem      uint64          `json:"min_mem"`
	MaxAge      int64           `json:"max_age"`
	RootCertPem []byte          `json:"root_cert_pem"`
}

type LoadResponse struct {
	Value string `json:"value"`
}

type ExistsResponse struct {
	Exists bool `json:"exists"`
}

type ListResponse struct {
	Keys []string `json:"keys"`
}

func init() {
	caddy.RegisterModule(Enclave{})
}

func (enclave *Enclave) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var value string

		key := d.Val()

		if !d.Args(&value) {
			continue
		}

		switch key {
		case "host_url":
			enclave.HostUrl = value
		case "pcrs":
			if err := json.Unmarshal([]byte(value), &enclave.Pcrs); err != nil {
				return err
			}
		case "min_cpus":
			var err error
			enclave.MinCpus, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				return err
			}
		case "min_mem":
			var err error
			enclave.MinMem, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				return err
			}
		case "max_age":
			var err error
			enclave.MaxAge, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return err
			}
		case "root_cert_pem":
			enclave.RootCertPem = []byte(value)
		}
	}

	return nil
}

func (enclave *Enclave) Provision(ctx caddy.Context) error {
	enclave.logger = ctx.Logger()

	// verify attestation document and store encryption key
	resp, err := http.Get(enclave.HostUrl + "/attestationDoc")
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return readErr
	}

	pubKey, err := attestation.Verify(body, enclave.Pcrs, enclave.RootCertPem, enclave.MinCpus, enclave.MinMem, enclave.MaxAge)
	if err != nil {
		return err
	}
	enclave.encryptionKey = pubKey
	return nil
}

func (Enclave) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "caddy.storage.enclave",
		New: func() caddy.Module {
			return new(Enclave)
		},
	}
}

func (enclave Enclave) CertMagicStorage() (certmagic.Storage, error) {
	return enclave, nil
}

func (enclave Enclave) Lock(ctx context.Context, key string) error {
	return nil
}

func (enclave Enclave) Unlock(ctx context.Context, key string) error {
	return nil
}

func (enclave Enclave) Store(ctx context.Context, key string, value []byte) error {

	// encrypt value using encryption key
	encryptedValue, err := utils.Encrypt(enclave.encryptionKey, value)
	if err != nil {
		return err
	}
	// make an api call to store
	postBody, _ := json.Marshal(map[string]string{
		"key":   key,
		"value": encryptedValue,
	})
	body := bytes.NewBuffer(postBody)
	resp, err := http.Post(enclave.HostUrl+"/store", "application/json", body)

	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("store non 200 status")
	}
	defer resp.Body.Close()
	// enclave.logger.Debug(fmt.Sprintf("Store: %s, %d bytes", key, length))
	return err
}

func (enclave Enclave) Load(ctx context.Context, key string) ([]byte, error) {

	// check if the key exists
	if !enclave.Exists(ctx, key) {
		return nil, fs.ErrNotExist
	}
	// get encrypted value from enclave and then decrypt using key
	postBody, _ := json.Marshal(map[string]string{
		"key": key,
	})
	bytesBody := bytes.NewBuffer(postBody)
	resp, err := http.Post(enclave.HostUrl+"/load", "application/json", bytesBody)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}
	var responseObject LoadResponse
	if err := json.Unmarshal(body, &responseObject); err != nil {
		return nil, err
	}
	// enclave.logger.Debug(fmt.Sprintf("Load key: %s", key))
	return utils.Decrypt(enclave.encryptionKey, responseObject.Value)
}

func (enclave Enclave) Delete(ctx context.Context, key string) error {

	// delete api call to enclave
	postBody, _ := json.Marshal(map[string]string{
		"key": key,
	})
	body := bytes.NewBuffer(postBody)
	resp, err := http.Post(enclave.HostUrl+"/delete", "application/json", body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("delete non 200 status")
	}
	// enclave.logger.Debug(fmt.Sprintf("Delete key: %s", key))
	return nil
}

func (enclave Enclave) Exists(ctx context.Context, key string) bool {

	// exists api call to enclave
	postBody, _ := json.Marshal(map[string]string{
		"key": key,
	})
	bytesBody := bytes.NewBuffer(postBody)
	resp, err := http.Post(enclave.HostUrl+"/exists", "application/json", bytesBody)
	if err != nil {
		return false
	}

	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return false
	}
	var responseObject ExistsResponse
	if err := json.Unmarshal(body, &responseObject); err != nil {
		return false
	}
	// enclave.logger.Debug(fmt.Sprintf("Check exists: %s, %t", key, exists))
	return responseObject.Exists
}

func (enclave Enclave) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {

	// list api call to enclave
	postBody, _ := json.Marshal(map[string]interface{}{
		"prefix":    prefix,
		"recursive": recursive,
	})
	bytesBody := bytes.NewBuffer(postBody)
	resp, err := http.Post(enclave.HostUrl+"/list", "application/json", bytesBody)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, readErr
	}
	var responseObject ListResponse
	if err := json.Unmarshal(body, &responseObject); err != nil {
		return nil, err
	}

	return responseObject.Keys, nil
}

func (enclave Enclave) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {

	// stat api call to enclave
	postBody, _ := json.Marshal(map[string]string{
		"key": key,
	})
	bytesBody := bytes.NewBuffer(postBody)
	resp, err := http.Post(enclave.HostUrl+"/stat", "application/json", bytesBody)

	var responseObject certmagic.KeyInfo
	if err != nil {
		return responseObject, err
	}

	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return responseObject, readErr
	}
	if err := json.Unmarshal(body, &responseObject); err != nil {
		return responseObject, err
	}

	return responseObject, nil
}
