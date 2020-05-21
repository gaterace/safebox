// Copyright 2019 Demian Harvill
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The safeservice package provides the implementation of the MServiceSafebox.proto GRPC service.
package safeservice

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"regexp"
	"sync"
	"time"

	"google.golang.org/grpc"

	"database/sql"
	"encoding/hex"

	"github.com/gaterace/dml-go/pkg/dml"
	"github.com/gaterace/safebox/pkg/cryptutil"
	pb "github.com/gaterace/safebox/pkg/mservicesafebox"
	"github.com/gaterace/safebox/pkg/sssa"
	_ "github.com/go-sql-driver/mysql"
)

var NotImplemented = errors.New("not implemented")
var NotInitialized = errors.New("not initialized")

var dataKeyValidator = regexp.MustCompile("^[a-z]{1,20}$")
var keyNodeValidator = regexp.MustCompile("^[a-z]{1,20}$")
var accountValidator = regexp.MustCompile("^[a-z]{4,10}$")
var pathValidator = regexp.MustCompile("^([a-z]{1,20}/)+$")

type safeService struct {
	logger          *log.Logger
	db              *sql.DB
	minSecretShares int
	secretShares    int
	shares          []string
	startSecs       int64
	mu              sync.RWMutex
}

func NewSafeboxService(minSecretShares int, secretShares int) *safeService {
	svc := safeService{}
	svc.minSecretShares = minSecretShares
	svc.secretShares = secretShares
	svc.shares = make([]string, 0, secretShares)
	svc.startSecs = time.Now().Unix()

	return &svc
}

func (s *safeService) SetLogger(logger *log.Logger) {
	s.logger = logger
}

func (s *safeService) SetDatabaseConnection(sqlDB *sql.DB) {
	s.db = sqlDB
}

func (s *safeService) NewApiServer(gServer *grpc.Server) error {
	if s != nil {
		pb.RegisterMServiceSafeboxServer(gServer, s)
	}
	return nil
}

func (s *safeService) getTreeNodeId(accountName string, nodePath string) (int64, error) {
	var treeNodeId int64

	sqlstring2 := `SELECT inbNodeId FROM tb_TreeNode WHERE chvAccountName = ? AND chvNodePath = ? AND bitIsDeleted = 0`
	stmt2, err := s.db.Prepare(sqlstring2)
	if err != nil {
		return 0, err
	}

	defer stmt2.Close()

	err = stmt2.QueryRow(accountName, nodePath).Scan(&treeNodeId)

	return treeNodeId, err
}

func (s *safeService) GetMasterKey() ([]byte, error) {
	// TODO
	// mkey := []byte("O;iO%XUNOozGS,|Y(}@jSuV>ej5uj93(")
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.shares) < s.minSecretShares {
		return nil, NotInitialized
	}

	recover, err := sssa.Combine(s.shares)

	mkey := []byte(recover)

	return mkey, err
}

func (s *safeService) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	initialized := len(s.shares) >= s.minSecretShares
	return initialized
}

// initialize service with shared secret
func (s *safeService) AddSharedSecret(ctx context.Context, req *pb.AddSharedSecretRequest) (*pb.AddSharedSecretResponse, error) {
	s.logger.Print("AddSharedSecret called")
	resp := &pb.AddSharedSecretResponse{}
	var err error

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.shares) >= s.minSecretShares {
		resp.ErrorCode = 210
		resp.ErrorMessage = "shares already initialized"
	} else {

		sharedSecret := req.GetSharedSecret()
		present := false
		for _, share := range s.shares {
			if share == sharedSecret {
				present = true
				break
			}
		}

		if !present {
			s.shares = append(s.shares, sharedSecret)
		}
	}

	return resp, err
}

// remove shared secrets
func (s *safeService) ClearSharedSecrets(ctx context.Context, req *pb.ClearSharedSecretsRequest) (*pb.ClearSharedSecretsResponse, error) {
	s.logger.Print("ClearSharedSecrets called")
	resp := &pb.ClearSharedSecretsResponse{}
	var err error

	s.mu.Lock()
	defer s.mu.Unlock()

	s.shares = make([]string, 0, s.secretShares)

	return resp, err
}

// create a new data key
func (s *safeService) CreateDataKey(ctx context.Context, req *pb.CreateDataKeyRequest) (*pb.CreateDataKeyResponse, error) {
	s.logger.Printf("CreateDataKey called for %s:%s\n", req.GetAccountName(), req.GetDataKeyName())

	resp := &pb.CreateDataKeyResponse{}

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	if !dataKeyValidator.MatchString(req.GetDataKeyName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "data_key_name invalid format"
		return resp, nil
	}

	// generate a new key
	newkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newkey); err != nil {
		s.logger.Printf("io.ReadFull err: %v", err)
		resp.ErrorCode = 511
		resp.ErrorMessage = "unable to generate new aes key"
		return resp, nil
	}

	mkey, err := s.GetMasterKey()
	if err != nil {
		s.logger.Printf("cryptutil.GetMasterKey err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to get master key"
		return resp, nil
	}

	datakey, err := cryptutil.AesGcmEncrypt(mkey, newkey)
	// clear master key
	for k := 0; k < len(mkey); k++ {
		mkey[k] = 0
	}

	if err != nil {
		s.logger.Printf("cryptutil.AesGcmEncrypt err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to encrypt data key"
		return resp, nil
	}

	sqlstring := `INSERT INTO tb_DataKey (
		dtmCreated, dtmModified, dtmDeleted, bitIsDeleted, intVersion, 
		chvAccountName, chvDataKeyName, chvDataKeyDescription, binDataKey)
		VALUES(NOW(), NOW(), NOW(), 0, 1, ?, ?, ?, UNHEX(?))`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetAccountName(), req.GetDataKeyName(), req.GetDataKeyDescription(), hex.EncodeToString(datakey))
	if err == nil {
		dataKeyId, err := res.LastInsertId()
		if err != nil {
			s.logger.Printf("LastInsertId err: %v\n", err)
		} else {
			s.logger.Printf("dataKeyId: %d", dataKeyId)
		}

		resp.DataKeyId = dataKeyId
		resp.Version = 1
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// delete a data key
func (s *safeService) DeleteDataKey(ctx context.Context, req *pb.DeleteDataKeyRequest) (*pb.DeleteDataKeyResponse, error) {
	s.logger.Printf("DeleteDataKey called for %s:%d\n", req.GetAccountName(), req.GetDataKeyId())
	resp := &pb.DeleteDataKeyResponse{}

	var err error

	sqlstring := `UPDATE tb_DataKey SET bitIsDeleted = 1, dtmDeleted = NOW(), intVersion = ? 
	WHERE chvAccountName = ? AND inbDataKeyId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetAccountName(), req.GetDataKeyId(), req.GetVersion())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 1 {
			resp.Version = req.GetVersion() + 1
		} else {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// get a data key
func (s *safeService) GetDataKey(ctx context.Context, req *pb.GetDataKeyRequest) (*pb.GetDataKeyResponse, error) {
	s.logger.Printf("GetDataKey called for %s:%s\n", req.GetAccountName(), req.GetDataKeyName())
	resp := &pb.GetDataKeyResponse{}
	var err error

	sqlstring := `SELECT inbDataKeyId, dtmCreated, dtmModified, intVersion, chvAccountName, chvDataKeyName,
	chvDataKeyDescription, binDataKey FROM tb_DataKey WHERE chvAccountName = ? AND chvDataKeyName = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var datakey pb.DataKey
	var created string
	var modified string

	err = stmt.QueryRow(req.GetAccountName(), req.GetDataKeyName()).Scan(&datakey.DataKeyId, &created, &modified, &datakey.Version,
		&datakey.AccountName, &datakey.DataKeyName, &datakey.DataKeyDescription, &datakey.DataKey)

	if err == nil {
		datakey.Created = dml.DateTimeFromString(created)
		datakey.Modified = dml.DateTimeFromString(modified)
		resp.ErrorCode = 0
		resp.Datakey = &datakey
	} else if err == sql.ErrNoRows {
		resp.ErrorCode = 404
		resp.ErrorMessage = "not found"
		err = nil
	} else {
		s.logger.Printf("queryRow failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		err = nil
	}

	return resp, err
}

// get a data key by id
func (s *safeService) GetDataKeyById(ctx context.Context, req *pb.GetDataKeyByIdRequest) (*pb.GetDataKeyByIdResponse, error) {
	s.logger.Printf("GetDataKeyById called for %s:%d\n", req.GetAccountName(), req.GetDataKeyId())
	resp := &pb.GetDataKeyByIdResponse{}
	var err error

	sqlstring := `SELECT inbDataKeyId, dtmCreated, dtmModified, intVersion, chvAccountName, chvDataKeyName,
	chvDataKeyDescription, binDataKey FROM tb_DataKey WHERE chvAccountName = ? AND inbDataKeyId = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var datakey pb.DataKey
	var created string
	var modified string

	err = stmt.QueryRow(req.GetAccountName(), req.GetDataKeyId()).Scan(&datakey.DataKeyId, &created, &modified, &datakey.Version,
		&datakey.AccountName, &datakey.DataKeyName, &datakey.DataKeyDescription, &datakey.DataKey)

	if err == nil {
		datakey.Created = dml.DateTimeFromString(created)
		datakey.Modified = dml.DateTimeFromString(modified)
		resp.ErrorCode = 0
		resp.Datakey = &datakey
	} else if err == sql.ErrNoRows {
		resp.ErrorCode = 404
		resp.ErrorMessage = "not found"
		err = nil
	} else {
		s.logger.Printf("queryRow failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		err = nil
	}

	return resp, err
}

// get a data keys by account_name
func (s *safeService) GetDataKeysByAccount(ctx context.Context, req *pb.GetDataKeysByAccountRequest) (*pb.GetDataKeysByAccountResponse, error) {
	s.logger.Printf("GetDataKeysByAccount called for %s\n", req.GetAccountName())
	resp := &pb.GetDataKeysByAccountResponse{}
	var err error

	sqlstring := `SELECT inbDataKeyId, dtmCreated, dtmModified, intVersion, chvAccountName, chvDataKeyName,
	chvDataKeyDescription, binDataKey FROM tb_DataKey WHERE chvAccountName = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	rows, err := stmt.Query(req.GetAccountName())

	if err != nil {
		s.logger.Printf("query failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	defer rows.Close()
	for rows.Next() {
		var datakey pb.DataKey
		var created string
		var modified string
		err = rows.Scan(&datakey.DataKeyId, &created, &modified, &datakey.Version,
			&datakey.AccountName, &datakey.DataKeyName, &datakey.DataKeyDescription, &datakey.DataKey)

		if err != nil {
			s.logger.Printf("query rows scan  failed: %v\n", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
			return resp, nil
		}

		datakey.Created = dml.DateTimeFromString(created)
		datakey.Modified = dml.DateTimeFromString(modified)

		resp.Datakeys = append(resp.Datakeys, &datakey)
	}

	return resp, err
}

// get a decrypted version of data key
func (s *safeService) GetDecryptedDataKey(ctx context.Context, req *pb.GetDecryptedDataKeyRequest) (*pb.GetDecryptedDataKeyResponse, error) {
	s.logger.Printf("GetDecryptedDataKey called for %s:%s\n", req.GetAccountName(), req.GetDataKeyName())
	resp := &pb.GetDecryptedDataKeyResponse{}
	var err error

	sqlstring := `SELECT binDataKey FROM tb_DataKey WHERE chvAccountName = ? AND chvDataKeyName = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var binDataKey []byte

	err = stmt.QueryRow(req.GetAccountName(), req.GetDataKeyName()).Scan(&binDataKey)

	if err == sql.ErrNoRows {
		resp.ErrorCode = 404
		resp.ErrorMessage = "not found"
		return resp, nil
	} else if err != nil {
		s.logger.Printf("queryRow failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	mkey, err := s.GetMasterKey()
	if err != nil {
		s.logger.Printf("cryptutil.GetMasterKey err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to get master key"
		return resp, nil
	}

	decrypted, err := cryptutil.AesGcmDecrypt(mkey, binDataKey)
	// clear master key
	for k := 0; k < len(mkey); k++ {
		mkey[k] = 0
	}
	if err != nil {
		s.logger.Printf("cryptutil.AesGcmDecrypt err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to decrypt data key"
		return resp, nil
	}

	resp.ErrorCode = 0
	resp.DecryptedDataKey = decrypted

	return resp, nil

}

// create a new key node, encrypting value creating tree node if necessary
func (s *safeService) CreateKeyNode(ctx context.Context, req *pb.CreateKeyNodeRequest) (*pb.CreateKeyNodeResponse, error) {
	s.logger.Printf("CreateKeyNode called for %s:%s\n", req.GetAccountName(), req.GetKeyName())
	resp := &pb.CreateKeyNodeResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	if !keyNodeValidator.MatchString(req.GetKeyName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "key_name invalid format"
		return resp, nil
	}

	nodePath := req.GetNodePath()
	if len(nodePath) > 0 {
		if nodePath[len(nodePath)-1:] != "/" {
			// add trailing slash
			nodePath = nodePath + "/"
		}
	}

	if (len(nodePath) > 128) || (!pathValidator.MatchString(nodePath)) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "node_path invalid format"
		return resp, nil
	}

	if len(req.GetKeyValue()) == 0 {
		resp.ErrorCode = 510
		resp.ErrorMessage = "key_value empty"
		return resp, nil
	}

	var binDataKey []byte

	if req.GetDataKeyId() != 0 {
		sqlstring1 := `SELECT binDataKey FROM tb_DataKey WHERE chvAccountName = ? AND inbDataKeyId = ? AND bitIsDeleted = 0`

		stmt1, err := s.db.Prepare(sqlstring1)
		if err != nil {
			s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = "db.Prepare failed"
			return resp, nil
		}

		defer stmt1.Close()
		err = stmt1.QueryRow(req.GetAccountName(), req.GetDataKeyId()).Scan(&binDataKey)
		if err != nil {
			s.logger.Printf("invalid data_key_id: %d\n", req.GetDataKeyId())
			resp.ErrorCode = 500
			resp.ErrorMessage = "invalid data_key_id"
			return resp, nil
		}
	}

	var treeNodeId int64

	treeNodeId, err = s.getTreeNodeId(req.GetAccountName(), nodePath)

	if treeNodeId == 0 {
		// need to create a new tree node
		sqlstring3 := `INSERT INTO tb_TreeNode (
			dtmCreated, dtmModified, dtmDeleted, bitIsDeleted, intVersion, 
			chvAccountName, chvNodePath) 
			VALUES(NOW(), NOW(), NOW(), 0, 1, ?, ?)`
		stmt3, err := s.db.Prepare(sqlstring3)
		if err != nil {
			s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = "db.Prepare failed"
			return resp, nil
		}

		defer stmt3.Close()

		res, err := stmt3.Exec(req.GetAccountName(), nodePath)
		if err == nil {
			treeNodeId, err = res.LastInsertId()
			if err != nil {
				s.logger.Printf("LastInsertId err: %v\n", err)
			} else {
				s.logger.Printf("treeNodeId: %d", treeNodeId)
			}

		} else {
			resp.ErrorCode = 501
			resp.ErrorMessage = err.Error()
			s.logger.Printf("err: %v\n", err)
			err = nil
		}
	}

	var encryptedKeyVal []byte

	if req.GetDataKeyId() == 0 {
		// no encryption
		encryptedKeyVal = req.GetKeyValue()
	} else {
		// decrypt the data key
		mkey, err := s.GetMasterKey()
		if err != nil {
			s.logger.Printf("cryptutil.GetMasterKey err: %v", err)
			resp.ErrorCode = 512
			resp.ErrorMessage = "unable to get master key"
			return resp, nil
		}

		datakey, err := cryptutil.AesGcmDecrypt(mkey, binDataKey)
		// clear master key
		for k := 0; k < len(mkey); k++ {
			mkey[k] = 0
		}
		if err != nil {
			s.logger.Printf("cryptutil.AesGcmDecrypt err: %v", err)
			resp.ErrorCode = 512
			resp.ErrorMessage = "unable to decrypt data key"
			return resp, nil
		}

		// encrypt the key value
		encryptedKeyVal, err = cryptutil.AesGcmEncrypt(datakey, req.GetKeyValue())
		// clear the data key
		for k := 0; k < len(datakey); k++ {
			datakey[k] = 0
		}
		if err != nil {
			s.logger.Printf("cryptutil.AesGcmEncrypt err: %v", err)
			resp.ErrorCode = 512
			resp.ErrorMessage = "unable to encrypt key value"
			return resp, nil
		}
	}

	sqlstring4 := `INSERT INTO tb_KeyNode (
		dtmCreated, dtmModified, dtmDeleted, bitIsDeleted, intVersion, 
		inbNodeId, inbDataKeyId, bitIsEnabled, chvKeyName, chvKeyDescription, binKeyValue)
		VALUES(NOW(), NOW(), NOW(), 0, 1, ?, ?, ?, ?, ?, ?)`

	stmt4, err := s.db.Prepare(sqlstring4)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt4.Close()

	res, err := stmt4.Exec(treeNodeId, req.GetDataKeyId(), req.GetIsEnabled(), req.GetKeyName(),
		req.GetKeyDescription(), encryptedKeyVal)
	if err == nil {
		resp.KeyId, err = res.LastInsertId()
		if err != nil {
			s.logger.Printf("LastInsertId err: %v\n", err)
		}

	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// enable a key node
func (s *safeService) EnableKeyNode(ctx context.Context, req *pb.EnableKeyNodeRequest) (*pb.EnableKeyNodeResponse, error) {
	s.logger.Printf("EnableKeyNode called for %s:%d\n", req.GetAccountName(), req.GetKeyId())
	resp := &pb.EnableKeyNodeResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	sqlstring := `UPDATE tb_KeyNode as k 
	INNER JOIN tb_TreeNode AS t on k.inbNodeId = t.inbNodeId
	SET k.bitIsEnabled = 1, k.dtmModified = NOW(), k.intVersion = ? 
	WHERE t.chvAccountName = ? AND k.inbKeyId = ? AND k.intVersion = ? AND k.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetAccountName(), req.GetKeyId(), req.GetVersion())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 1 {
			resp.Version = req.GetVersion() + 1
		} else {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// disable a key node
func (s *safeService) DisableKeyNode(ctx context.Context, req *pb.DisableKeyNodeRequest) (*pb.DisableKeyNodeResponse, error) {
	s.logger.Printf("DisableKeyNode called for %s:%d\n", req.GetAccountName(), req.GetKeyId())
	resp := &pb.DisableKeyNodeResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	sqlstring := `UPDATE tb_KeyNode as k 
	INNER JOIN tb_TreeNode AS t on k.inbNodeId = t.inbNodeId
	SET k.bitIsEnabled = 0, k.dtmModified = NOW(), k.intVersion = ? 
	WHERE t.chvAccountName = ? AND k.inbKeyId = ? AND k.intVersion = ? AND k.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetAccountName(), req.GetKeyId(), req.GetVersion())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 1 {
			resp.Version = req.GetVersion() + 1
		} else {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// re-encrypt a key node
func (s *safeService) ReEncryptKeyNode(ctx context.Context, req *pb.ReEncryptKeyNodeRequest) (*pb.ReEncryptKeyNodeResponse, error) {
	s.logger.Printf("ReEncryptKeyNode called for %s:%d\n", req.GetAccountName(), req.GetKeyId())
	resp := &pb.ReEncryptKeyNodeResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	if req.GetDataKeyId() == 0 {
		resp.ErrorCode = 510
		resp.ErrorMessage = "data_key_id must not be zero"
		return resp, nil
	}

	sqlstring := `SELECT kn.inbKeyId, kn.dtmCreated, kn.dtmModified, kn.intVersion, kn.inbNodeId, kn.inbDataKeyId, 
		kn.bitIsEnabled, kn.chvKeyName, kn.chvKeyDescription, kn.binKeyValue, tn.chvNodePath FROM tb_KeyNode AS kn
		JOIN tb_TreeNode AS tn 
		ON kn.inbNodeId = tn.inbNodeId
		WHERE tn.chvAccountName = ? AND kn.inbKeyId = ? AND kn.bitIsDeleted = 0 AND tn.bitIsDeleted = 0
		AND kn.intVersion = ?`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var keyNode pb.KeyNode
	var created string
	var modified string

	err = stmt.QueryRow(req.GetAccountName(), req.GetKeyId(), req.GetVersion()).Scan(&keyNode.KeyId, &created, &modified,
		&keyNode.Version, &keyNode.NodeId, &keyNode.DataKeyId, &keyNode.IsEnabled,
		&keyNode.KeyName, &keyNode.KeyDescription, &keyNode.KeyValue, &keyNode.NodePath)

	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "key node not found"
		return resp, nil
	}

	if keyNode.GetDataKeyId() == 0 {
		resp.ErrorCode = 510
		resp.ErrorMessage = "source data_key_id must not be zero"
		return resp, nil
	}

	if keyNode.GetDataKeyId() == req.GetDataKeyId() {
		resp.ErrorCode = 516
		resp.ErrorMessage = "cannot re-encrypt key node with same data key"
		return resp, nil
	}

	sqlstring2 := `SELECT binDataKey FROM tb_DataKey WHERE chvAccountName = ? AND 
	inbDataKeyId = ? AND bitIsDeleted = 0`

	stmt2, err := s.db.Prepare(sqlstring2)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt2.Close()

	var targetDataKey []byte
	var sourceDataKey []byte

	err = stmt2.QueryRow(req.GetAccountName(), req.GetDataKeyId()).Scan(&targetDataKey)
	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "target data key not found"
		return resp, nil
	}

	err = stmt2.QueryRow(req.GetAccountName(), keyNode.GetDataKeyId()).Scan(&sourceDataKey)
	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "source data key not found"
		return resp, nil
	}

	mkey, err := s.GetMasterKey()
	if err != nil {
		s.logger.Printf("cryptutil.GetMasterKey err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to get master key"
		return resp, nil
	}

	sourcekey, err := cryptutil.AesGcmDecrypt(mkey, sourceDataKey)
	if err != nil {
		// clear master key
		for k := 0; k < len(mkey); k++ {
			mkey[k] = 0
		}
		s.logger.Printf("cryptutil.AesGcmDecrypt err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to decrypt data key"
		return resp, nil
	}

	targetkey, err := cryptutil.AesGcmDecrypt(mkey, targetDataKey)
	// clear master key
	for k := 0; k < len(mkey); k++ {
		mkey[k] = 0
	}
	if err != nil {
		s.logger.Printf("cryptutil.AesGcmDecrypt err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to decrypt data key"
		return resp, nil
	}

	decryptedValue, err := cryptutil.AesGcmDecrypt(sourcekey, keyNode.GetKeyValue())
	if err != nil {
		s.logger.Printf("cryptutil.AesGcmDecrypt err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to decrypt  key node"
		return resp, nil
	}

	reencryptedValue, err := cryptutil.AesGcmEncrypt(targetkey, decryptedValue)
	if err != nil {
		s.logger.Printf("cryptutil.AesGcmEncrypt err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to encrypt key node"
		return resp, nil
	}

	sqlstring3 := `UPDATE tb_KeyNode SET inbDataKeyId = ?, binKeyValue = ?, dtmModified = NOW(), intVersion = ? 
	WHERE inbKeyId = ? AND intVersion = ? AND bitIsDeleted = 0`

	stmt3, err := s.db.Prepare(sqlstring3)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt3.Close()

	res, err := stmt3.Exec(req.GetDataKeyId(), reencryptedValue, req.GetVersion()+1, req.GetKeyId(), req.GetVersion())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 1 {
			resp.Version = req.GetVersion() + 1
		} else {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// copy a  key node to new path
func (s *safeService) CopyKeyNode(ctx context.Context, req *pb.CopyKeyNodeRequest) (*pb.CopyKeyNodeResponse, error) {
	s.logger.Printf("CopyKeyNode called for %s:%d\n", req.GetAccountName(), req.GetKeyId())
	resp := &pb.CopyKeyNodeResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	nodePath := req.GetNodePath()
	if len(nodePath) > 0 {
		if nodePath[len(nodePath)-1:] != "/" {
			// add trailing slash
			nodePath = nodePath + "/"
		}
	}

	if (len(nodePath) > 128) || (!pathValidator.MatchString(nodePath)) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "node_path invalid format"
		return resp, nil
	}

	sqlstring := `SELECT kn.inbKeyId, kn.dtmCreated, kn.dtmModified, kn.intVersion, kn.inbNodeId, kn.inbDataKeyId, 
		kn.bitIsEnabled, kn.chvKeyName, kn.chvKeyDescription, kn.binKeyValue, tn.chvNodePath FROM tb_KeyNode AS kn
		JOIN tb_TreeNode AS tn 
		ON kn.inbNodeId = tn.inbNodeId
		WHERE tn.chvAccountName = ? AND kn.inbKeyId = ? AND kn.bitIsDeleted = 0 AND tn.bitIsDeleted = 0
		AND kn.intVersion = ?`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var keyNode pb.KeyNode
	var created string
	var modified string

	err = stmt.QueryRow(req.GetAccountName(), req.GetKeyId(), req.GetVersion()).Scan(&keyNode.KeyId, &created, &modified,
		&keyNode.Version, &keyNode.NodeId, &keyNode.DataKeyId, &keyNode.IsEnabled,
		&keyNode.KeyName, &keyNode.KeyDescription, &keyNode.KeyValue, &keyNode.NodePath)

	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "key node not found"
		return resp, nil
	}

	if keyNode.GetNodePath() == nodePath {
		resp.ErrorCode = 515
		resp.ErrorMessage = "cannot copy key node to same path"
		return resp, nil
	}

	var treeNodeId int64

	treeNodeId, err = s.getTreeNodeId(req.GetAccountName(), nodePath)

	if treeNodeId == 0 {
		// need to create a new tree node
		sqlstring3 := `INSERT INTO tb_TreeNode (
			dtmCreated, dtmModified, dtmDeleted, bitIsDeleted, intVersion, 
			chvAccountName, chvNodePath) 
			VALUES(NOW(), NOW(), NOW(), 0, 1, ?, ?)`
		stmt3, err := s.db.Prepare(sqlstring3)
		if err != nil {
			s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = "db.Prepare failed"
			return resp, nil
		}

		defer stmt3.Close()

		res, err := stmt3.Exec(req.GetAccountName(), nodePath)
		if err == nil {
			treeNodeId, err = res.LastInsertId()
			if err != nil {
				s.logger.Printf("LastInsertId err: %v\n", err)
			} else {
				s.logger.Printf("treeNodeId: %d", treeNodeId)
			}

		} else {
			resp.ErrorCode = 501
			resp.ErrorMessage = err.Error()
			s.logger.Printf("err: %v\n", err)
			err = nil
		}
	}

	sqlstring4 := `INSERT INTO tb_KeyNode (
		dtmCreated, dtmModified, dtmDeleted, bitIsDeleted, intVersion, 
		inbNodeId, inbDataKeyId, bitIsEnabled, chvKeyName, chvKeyDescription, binKeyValue)
		VALUES(NOW(), NOW(), NOW(), 0, 1, ?, ?, ?, ?, ?, ?)`

	stmt4, err := s.db.Prepare(sqlstring4)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt4.Close()

	res, err := stmt4.Exec(treeNodeId, keyNode.GetDataKeyId(), keyNode.GetIsEnabled(), keyNode.GetKeyName(),
		keyNode.GetKeyDescription(), keyNode.GetKeyValue())
	if err == nil {
		resp.CopiedKeyId, err = res.LastInsertId()
		if err != nil {
			s.logger.Printf("LastInsertId err: %v\n", err)
		}

	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	resp.Version = 1

	return resp, err
}

// delete a  key node
func (s *safeService) DeleteKeyNode(ctx context.Context, req *pb.DeleteKeyNodeRequest) (*pb.DeleteKeyNodeResponse, error) {
	s.logger.Printf("DeleteKeyNode called for %s:%d\n", req.GetAccountName(), req.GetKeyId())
	resp := &pb.DeleteKeyNodeResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	sqlstring := `UPDATE tb_KeyNode as k 
	INNER JOIN tb_TreeNode AS t on k.inbNodeId = t.inbNodeId
	SET k.bitIsDeleted = 1, k.dtmMDeleted = NOW(), k.intVersion = ? 
	WHERE t.chvAccountName = ? AND k.inbKeyId = ? AND k.intVersion = ? AND k.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	res, err := stmt.Exec(req.GetVersion()+1, req.GetAccountName(), req.GetKeyId(), req.GetVersion())

	if err == nil {
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 1 {
			resp.Version = req.GetVersion() + 1
		} else {
			resp.ErrorCode = 404
			resp.ErrorMessage = "not found"
		}
	} else {
		resp.ErrorCode = 501
		resp.ErrorMessage = err.Error()
		s.logger.Printf("err: %v\n", err)
		err = nil
	}

	return resp, err
}

// get a key node by node and path
func (s *safeService) GetKeyNode(ctx context.Context, req *pb.GetKeyNodeRequest) (*pb.GetKeyNodeResponse, error) {
	s.logger.Printf("GetKeyNode called for %s:%s:%s\n", req.GetAccountName(), req.GetNodePath(), req.GetKeyName())
	resp := &pb.GetKeyNodeResponse{}

	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	if !keyNodeValidator.MatchString(req.GetKeyName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "key_name invalid format"
		return resp, nil
	}

	nodePath := req.GetNodePath()
	if len(nodePath) > 0 {
		if nodePath[len(nodePath)-1:] != "/" {
			// add trailing slash
			nodePath = nodePath + "/"
		}
	}

	if (len(nodePath) > 128) || (!pathValidator.MatchString(nodePath)) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "node_path invalid format"
		return resp, nil
	}

	treeNodeId, err := s.getTreeNodeId(req.GetAccountName(), nodePath)

	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "node_path not found"
		return resp, nil
	}

	sqlstring := `SELECT inbKeyId, dtmCreated, dtmModified, intVersion, inbNodeId, inbDataKeyId, 
		bitIsEnabled, chvKeyName, chvKeyDescription, binKeyValue FROM tb_KeyNode
		WHERE inbNodeId = ? AND chvKeyName = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var keyNode pb.KeyNode
	var created string
	var modified string
	var keyValue []byte

	err = stmt.QueryRow(treeNodeId, req.GetKeyName()).Scan(&keyNode.KeyId, &created, &modified,
		&keyNode.Version, &keyNode.NodeId, &keyNode.DataKeyId, &keyNode.IsEnabled,
		&keyNode.KeyName, &keyNode.KeyDescription, &keyValue)
	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "key node not found"
		return resp, nil
	}

	keyNode.Created = dml.DateTimeFromString(created)
	keyNode.Modified = dml.DateTimeFromString(modified)
	keyNode.NodePath = nodePath

	if keyNode.IsEnabled {
		// only return if enabled
		keyNode.KeyValue = keyValue
	}

	resp.Keynode = &keyNode

	return resp, err
}

// get a key node by id
func (s *safeService) GetKeyNodeById(ctx context.Context, req *pb.GetKeyNodeByIdRequest) (*pb.GetKeyNodeByIdResponse, error) {
	s.logger.Printf("GetKeyNodeById called for %s:%d\n", req.GetAccountName(), req.GetKeyId())
	resp := &pb.GetKeyNodeByIdResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	sqlstring := `SELECT kn.inbKeyId, kn.dtmCreated, kn.dtmModified, kn.intVersion, kn.inbNodeId, kn.inbDataKeyId, 
		kn.bitIsEnabled, kn.chvKeyName, kn.chvKeyDescription, kn.binKeyValue, tn.chvNodePath FROM tb_KeyNode AS kn
		JOIN tb_TreeNode AS tn 
		ON kn.inbNodeId = tn.inbNodeId
		WHERE tn.chvAccountName = ? AND kn.inbKeyId = ? AND kn.bitIsDeleted = 0 AND tn.bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var keyNode pb.KeyNode
	var created string
	var modified string
	var keyValue []byte

	err = stmt.QueryRow(req.GetAccountName(), req.GetKeyId()).Scan(&keyNode.KeyId, &created, &modified,
		&keyNode.Version, &keyNode.NodeId, &keyNode.DataKeyId, &keyNode.IsEnabled,
		&keyNode.KeyName, &keyNode.KeyDescription, &keyValue, &keyNode.NodePath)

	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "key node not found"
		return resp, nil
	}

	keyNode.Created = dml.DateTimeFromString(created)
	keyNode.Modified = dml.DateTimeFromString(modified)
	if keyNode.IsEnabled {
		// only return if enabled
		keyNode.KeyValue = keyValue
	}

	resp.Keynode = &keyNode

	return resp, err
}

// get a list of key nodes by path
func (s *safeService) GetKeyNodeByPath(ctx context.Context, req *pb.GetKeyNodeByPathRequest) (*pb.GetKeyNodeByPathResponse, error) {
	s.logger.Printf("GetKeyNodeByPath called for %s:%s\n", req.GetAccountName(), req.GetNodePath())
	resp := &pb.GetKeyNodeByPathResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	var nodePath string

	if req.GetNodePath() != "" {
		nodePath = req.GetNodePath()
		if len(nodePath) > 0 {
			if nodePath[len(nodePath)-1:] != "/" {
				// add trailing slash
				nodePath = nodePath + "/"
			}
		}

		if (len(nodePath) > 128) || (!pathValidator.MatchString(nodePath)) {
			resp.ErrorCode = 510
			resp.ErrorMessage = "node_path invalid format"
			return resp, nil
		}
	}

	var sqlstring string

	if nodePath == "" {
		sqlstring = `SELECT kn.inbKeyId, kn.dtmCreated, kn.dtmModified, kn.intVersion, kn.inbNodeId, kn.inbDataKeyId, 
		kn.bitIsEnabled, kn.chvKeyName, kn.chvKeyDescription, tn.chvNodePath FROM tb_KeyNode AS kn
		JOIN tb_TreeNode AS tn 
		ON kn.inbNodeId = tn.inbNodeId
		WHERE tn.chvAccountName = ?  AND kn.bitIsDeleted = 0 AND tn.bitIsDeleted = 0`
	} else {
		sqlstring = `SELECT kn.inbKeyId, kn.dtmCreated, kn.dtmModified, kn.intVersion, kn.inbNodeId, kn.inbDataKeyId, 
		kn.bitIsEnabled, kn.chvKeyName, kn.chvKeyDescription, tn.chvNodePath FROM tb_KeyNode AS kn
		JOIN tb_TreeNode AS tn 
		ON kn.inbNodeId = tn.inbNodeId
		WHERE tn.chvAccountName = ?  AND tn.chvNodePath LIKE ? AND  kn.bitIsDeleted = 0 AND tn.bitIsDeleted = 0`
	}

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var rows *sql.Rows

	if nodePath == "" {
		rows, err = stmt.Query(req.GetAccountName())
	} else {
		partialPath := nodePath + "%"
		rows, err = stmt.Query(req.GetAccountName(), partialPath)
	}

	if err != nil {
		s.logger.Printf("query failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = err.Error()
		return resp, nil
	}

	defer rows.Close()

	for rows.Next() {
		var keyNode pb.KeyNode
		var created string
		var modified string

		err = rows.Scan(&keyNode.KeyId, &created, &modified,
			&keyNode.Version, &keyNode.NodeId, &keyNode.DataKeyId, &keyNode.IsEnabled,
			&keyNode.KeyName, &keyNode.KeyDescription, &keyNode.NodePath)

		if err != nil {
			s.logger.Printf("query rows scan  failed: %v\n", err)
			resp.ErrorCode = 500
			resp.ErrorMessage = err.Error()
			return resp, nil
		}

		keyNode.Created = dml.DateTimeFromString(created)
		keyNode.Modified = dml.DateTimeFromString(modified)
		resp.Keynodes = append(resp.Keynodes, &keyNode)
	}

	return resp, err
}

// get a decrypted version of key node
func (s *safeService) GetDecryptedKeyNode(ctx context.Context, req *pb.GetDecryptedKeyNodeRequest) (*pb.GetDecryptedKeyNodeResponse, error) {
	s.logger.Printf("GetKeyNodeByPath called for %s:%s\n", req.GetAccountName(), req.GetNodePath())
	resp := &pb.GetDecryptedKeyNodeResponse{}
	var err error

	if !accountValidator.MatchString(req.GetAccountName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "account_name invalid format"
		return resp, nil
	}

	if !keyNodeValidator.MatchString(req.GetKeyName()) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "key_name invalid format"
		return resp, nil
	}

	nodePath := req.GetNodePath()
	if len(nodePath) > 0 {
		if nodePath[len(nodePath)-1:] != "/" {
			// add trailing slash
			nodePath = nodePath + "/"
		}
	}

	if (len(nodePath) > 128) || (!pathValidator.MatchString(nodePath)) {
		resp.ErrorCode = 510
		resp.ErrorMessage = "node_path invalid format"
		return resp, nil
	}

	treeNodeId, err := s.getTreeNodeId(req.GetAccountName(), nodePath)

	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "node_path not found"
		return resp, nil
	}

	sqlstring := `SELECT inbKeyId, inbDataKeyId, bitIsEnabled, binKeyValue FROM tb_KeyNode
		WHERE inbNodeId = ? AND chvKeyName = ? AND bitIsDeleted = 0`

	stmt, err := s.db.Prepare(sqlstring)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt.Close()

	var keyId int64
	var dataKeyId int64
	var isEnabled bool
	var encryptedValue []byte

	err = stmt.QueryRow(treeNodeId, req.GetKeyName()).Scan(&keyId, &dataKeyId, &isEnabled, &encryptedValue)

	if err != nil {
		resp.ErrorCode = 404
		resp.ErrorMessage = "key node not found"
		return resp, nil
	}

	if !isEnabled {
		resp.ErrorCode = 404
		resp.ErrorMessage = "key node not enabled"
		return resp, nil
	}

	if dataKeyId == 0 {
		// no need to decrypt
		resp.DecryptedKeyValue = encryptedValue
		return resp, nil
	}

	// TODO: decrypt
	var binDataKey []byte

	sqlstring1 := `SELECT binDataKey FROM tb_DataKey WHERE chvAccountName = ? AND inbDataKeyId = ? AND bitIsDeleted = 0`

	stmt1, err := s.db.Prepare(sqlstring1)
	if err != nil {
		s.logger.Printf("db.Prepare sqlstring failed: %v\n", err)
		resp.ErrorCode = 500
		resp.ErrorMessage = "db.Prepare failed"
		return resp, nil
	}

	defer stmt1.Close()
	err = stmt1.QueryRow(req.GetAccountName(), dataKeyId).Scan(&binDataKey)
	if err != nil {
		s.logger.Printf("invalid data_key_id: %d\n", dataKeyId)
		resp.ErrorCode = 500
		resp.ErrorMessage = "invalid data_key_id"
		return resp, nil
	}

	mkey, err := s.GetMasterKey()
	if err != nil {
		s.logger.Printf("cryptutil.GetMasterKey err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to get master key"
		return resp, nil
	}

	datakey, err := cryptutil.AesGcmDecrypt(mkey, binDataKey)
	// clear master key
	for k := 0; k < len(mkey); k++ {
		mkey[k] = 0
	}
	if err != nil {
		s.logger.Printf("cryptutil.AesGcmDecrypt err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to decrypt data key"
		return resp, nil
	}

	plaintext, err := cryptutil.AesGcmDecrypt(datakey, encryptedValue)
	if err != nil {
		s.logger.Printf("cryptutil.AesGcmDecrypt err: %v", err)
		resp.ErrorCode = 512
		resp.ErrorMessage = "unable to decrypt key node"
		return resp, nil
	}

	resp.DecryptedKeyValue = plaintext

	return resp, err
}

// get current server version and uptime - health check
func (s *safeService) GetServerVersion(ctx context.Context, req *pb.GetServerVersionRequest) (*pb.GetServerVersionResponse, error) {
	s.logger.Printf("GetServerVersion called\n")
	resp := &pb.GetServerVersionResponse{}

	currentSecs := time.Now().Unix()
	resp.ServerVersion = "v0.9.2"
	resp.ServerUptime = currentSecs - s.startSecs

	return resp, nil
}