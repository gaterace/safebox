// Copyright 2019-2020 Demian Harvill
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

package safeauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"database/sql"

	"github.com/dgrijalva/jwt-go"
	pb "github.com/gaterace/safebox/pkg/mservicesafebox"
	_ "github.com/go-sql-driver/mysql"
)

const (
	tokenExpiredMatch   = "Token is expired"
	tokenExpiredMessage = "token is expired"
)

var NotImplemented = errors.New("not implemented")

type SafeAuth struct {
	logger          log.Logger
	db              *sql.DB
	rsaPSSPublicKey *rsa.PublicKey
	safeService     pb.MServiceSafeboxServer
}

func NewSafeboxAuth(safeService pb.MServiceSafeboxServer) *SafeAuth {
	svc := SafeAuth{}
	svc.safeService = safeService
	return &svc
}

func (s *SafeAuth) SetLogger(logger log.Logger) {
	s.logger = logger
}

func (s *SafeAuth) SetPublicKey(publicKeyFile string) error {
	publicKey, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		level.Error(s.logger).Log("what", "reading publicKeyFile", "error", err)
		return err
	}

	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		level.Error(s.logger).Log("what", "ParseRSAPublicKeyFromPEM", "error", err)
		return err
	}

	s.rsaPSSPublicKey = parsedKey
	return nil
}

func (s *SafeAuth) SetDatabaseConnection(sqlDB *sql.DB) {
	s.db = sqlDB
}

func (s *SafeAuth) NewApiServer(gServer *grpc.Server) error {
	if s != nil {
		pb.RegisterMServiceSafeboxServer(gServer, s)
	}
	return nil
}

func (s *SafeAuth) GetJwtFromContext(ctx context.Context) (*map[string]interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("cannot get metadata from context")
	}

	tokens := md["token"]

	if (tokens == nil) || (len(tokens) == 0) {
		return nil, fmt.Errorf("cannot get token from context")
	}

	tokenString := tokens[0]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		method := token.Method.Alg()
		if method != "PS256" {

			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// return []byte(mySigningKey), nil
		return s.rsaPSSPublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid json web token")
	}

	claims := map[string]interface{}(token.Claims.(jwt.MapClaims))

	return &claims, nil

}

func GetInt64FromClaims(claims *map[string]interface{}, key string) int64 {
	var val int64

	if claims != nil {
		cval := (*claims)[key]
		if fval, ok := cval.(float64); ok {
			val = int64(fval)
		}
	}

	return val
}

func GetStringFromClaims(claims *map[string]interface{}, key string) string {
	var val string

	if claims != nil {
		cval := (*claims)[key]
		if sval, ok := cval.(string); ok {
			val = sval
		}
	}

	return val
}

// initialize service with shared secret
func (s *SafeAuth) AddSharedSecret(ctx context.Context, req *pb.AddSharedSecretRequest) (*pb.AddSharedSecretResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.AddSharedSecretResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "operator") {
			resp, err = s.safeService.AddSharedSecret(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "AddSharedSecret",
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// remocve shared secrets
func (s *SafeAuth) ClearSharedSecrets(ctx context.Context, req *pb.ClearSharedSecretsRequest) (*pb.ClearSharedSecretsResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.ClearSharedSecretsResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "operator") {
			resp, err = s.safeService.ClearSharedSecrets(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "ClearSharedSecrets",
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// create a new data key
func (s *SafeAuth) CreateDataKey(ctx context.Context, req *pb.CreateDataKeyRequest) (*pb.CreateDataKeyResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CreateDataKeyResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.CreateDataKey(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CreateDataKey",
		"datakey", req.GetDataKeyName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// delete a data key
func (s *SafeAuth) DeleteDataKey(ctx context.Context, req *pb.DeleteDataKeyRequest) (*pb.DeleteDataKeyResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DeleteDataKeyResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.DeleteDataKey(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DeleteDataKey",
		"datakeyid", req.GetDataKeyId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get a data key
func (s *SafeAuth) GetDataKey(ctx context.Context, req *pb.GetDataKeyRequest) (*pb.GetDataKeyResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetDataKeyResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "datakeyro") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.GetDataKey(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetDataKey",
		"datakey", req.GetDataKeyName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get a data key by id
func (s *SafeAuth) GetDataKeyById(ctx context.Context, req *pb.GetDataKeyByIdRequest) (*pb.GetDataKeyByIdResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetDataKeyByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "datakeyro") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.GetDataKeyById(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetDataKeyById",
		"datakeyid", req.GetDataKeyId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get a data keys by account_name
func (s *SafeAuth) GetDataKeysByAccount(ctx context.Context, req *pb.GetDataKeysByAccountRequest) (*pb.GetDataKeysByAccountResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetDataKeysByAccountResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "datakeyro") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.GetDataKeysByAccount(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetDataKeysByAccount",
		"account", req.GetAccountName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get a decrypted version of data key
func (s *SafeAuth) GetDecryptedDataKey(ctx context.Context, req *pb.GetDecryptedDataKeyRequest) (*pb.GetDecryptedDataKeyResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetDecryptedDataKeyResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "datakeyro") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.GetDecryptedDataKey(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetDecryptedDataKey",
		"datakey", req.GetDataKeyName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// create a new key node, encrypting value creating tree node if necessary
func (s *SafeAuth) CreateKeyNode(ctx context.Context, req *pb.CreateKeyNodeRequest) (*pb.CreateKeyNodeResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CreateKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.CreateKeyNode(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CreateKeyNode",
		"path", req.GetNodePath(),
		"key", req.GetKeyName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// enable a key node
func (s *SafeAuth) EnableKeyNode(ctx context.Context, req *pb.EnableKeyNodeRequest) (*pb.EnableKeyNodeResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.EnableKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.EnableKeyNode(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "EnableKeyNode",
		"keyid", req.GetKeyId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// disable a key node
func (s *SafeAuth) DisableKeyNode(ctx context.Context, req *pb.DisableKeyNodeRequest) (*pb.DisableKeyNodeResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DisableKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.DisableKeyNode(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DisableKeyNode",
		"keyid", req.GetKeyId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// re-encrypt a key node
func (s *SafeAuth) ReEncryptKeyNode(ctx context.Context, req *pb.ReEncryptKeyNodeRequest) (*pb.ReEncryptKeyNodeResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.ReEncryptKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.ReEncryptKeyNode(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "ReEncryptKeyNode",
		"keyid", req.GetKeyId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// copy a  key node to new path
func (s *SafeAuth) CopyKeyNode(ctx context.Context, req *pb.CopyKeyNodeRequest) (*pb.CopyKeyNodeResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.CopyKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.CopyKeyNode(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "CopyKeyNode",
		"keyid", req.GetKeyId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// delete a  key node
func (s *SafeAuth) DeleteKeyNode(ctx context.Context, req *pb.DeleteKeyNodeRequest) (*pb.DeleteKeyNodeResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.DeleteKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.DeleteKeyNode(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "DeleteKeyNode",
		"keyid", req.GetKeyId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get a key node by node and path
func (s *SafeAuth) GetKeyNode(ctx context.Context, req *pb.GetKeyNodeRequest) (*pb.GetKeyNodeResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") || (safebox == "keynodero") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.GetKeyNode(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetKeyNode",
		"path", req.GetNodePath(),
		"key", req.GetKeyName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get a key node by id
func (s *SafeAuth) GetKeyNodeById(ctx context.Context, req *pb.GetKeyNodeByIdRequest) (*pb.GetKeyNodeByIdResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetKeyNodeByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") || (safebox == "keynodero") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.GetKeyNodeById(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetKeyNodeById",
		"keyid", req.GetKeyId(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get a list of key nodes by path
func (s *SafeAuth) GetKeyNodeByPath(ctx context.Context, req *pb.GetKeyNodeByPathRequest) (*pb.GetKeyNodeByPathResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetKeyNodeByPathResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") || (safebox == "keynodero") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.GetKeyNodeByPath(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetKeyNodeByPath",
		"path", req.GetNodePath(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get a decrypted version of key node
func (s *SafeAuth) GetDecryptedKeyNode(ctx context.Context, req *pb.GetDecryptedKeyNodeRequest) (*pb.GetDecryptedKeyNodeResponse, error) {
	start := time.Now().UnixNano()
	resp := &pb.GetDecryptedKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") || (safebox == "keynodero") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			resp, err = s.safeService.GetDecryptedKeyNode(ctx, req)
		}
	} else {
		if err.Error() == tokenExpiredMatch {
			resp.ErrorCode = 498
			resp.ErrorMessage = tokenExpiredMessage
		}

		err = nil
	}

	duration := time.Now().UnixNano() - start
	level.Info(s.logger).Log("endpoint", "GetDecryptedKeyNode",
		"path", req.GetNodePath(),
		"key", req.GetKeyName(),
		"errcode", resp.GetErrorCode(), "duration", duration)

	return resp, err
}

// get current server version and uptime - health check
func (s *SafeAuth) GetServerVersion(ctx context.Context, req *pb.GetServerVersionRequest) (*pb.GetServerVersionResponse, error) {
	return s.safeService.GetServerVersion(ctx, req)
}
