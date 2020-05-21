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

package safeauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"database/sql"

	"github.com/dgrijalva/jwt-go"
	pb "github.com/gaterace/safebox/pkg/mservicesafebox"
	_ "github.com/go-sql-driver/mysql"
)

var NotImplemented = errors.New("not implemented")

type safeAuth struct {
	logger          *log.Logger
	db              *sql.DB
	rsaPSSPublicKey *rsa.PublicKey
	safeService     pb.MServiceSafeboxServer
}

func NewSafeboxAuth(safeService pb.MServiceSafeboxServer) *safeAuth {
	svc := safeAuth{}
	svc.safeService = safeService
	return &svc
}

func (s *safeAuth) SetLogger(logger *log.Logger) {
	s.logger = logger
}

func (s *safeAuth) SetPublicKey(publicKeyFile string) error {
	publicKey, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		s.logger.Printf("error reading publicKeyFile: %v\n", err)
		return err
	}

	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		s.logger.Printf("error parsing publicKeyFile: %v\n", err)
		return err
	}

	s.rsaPSSPublicKey = parsedKey
	return nil
}

func (s *safeAuth) SetDatabaseConnection(sqlDB *sql.DB) {
	s.db = sqlDB
}

func (s *safeAuth) NewApiServer(gServer *grpc.Server) error {
	if s != nil {
		pb.RegisterMServiceSafeboxServer(gServer, s)
	}
	return nil
}

func (s *safeAuth) GetJwtFromContext(ctx context.Context) (*map[string]interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, fmt.Errorf("cannot get metadata from context")
	}

	tokens := md["token"]

	if (tokens == nil) || (len(tokens) == 0) {
		return nil, fmt.Errorf("cannot get token from context")
	}

	tokenString := tokens[0]

	s.logger.Printf("tokenString: %s\n", tokenString)

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

	s.logger.Printf("claims: %v\n", claims)

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
func (s *safeAuth) AddSharedSecret(ctx context.Context, req *pb.AddSharedSecretRequest) (*pb.AddSharedSecretResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "operator") {
			return s.safeService.AddSharedSecret(ctx, req)
		}
	}

	resp := &pb.AddSharedSecretResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// remocve shared secrets
func (s *safeAuth) ClearSharedSecrets(ctx context.Context, req *pb.ClearSharedSecretsRequest) (*pb.ClearSharedSecretsResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "operator") {
			return s.safeService.ClearSharedSecrets(ctx, req)
		}
	}

	resp := &pb.ClearSharedSecretsResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// create a new data key
func (s *safeAuth) CreateDataKey(ctx context.Context, req *pb.CreateDataKeyRequest) (*pb.CreateDataKeyResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.CreateDataKey(ctx, req)
		}
	}

	resp := &pb.CreateDataKeyResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// delete a data key
func (s *safeAuth) DeleteDataKey(ctx context.Context, req *pb.DeleteDataKeyRequest) (*pb.DeleteDataKeyResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.DeleteDataKey(ctx, req)
		}
	}

	resp := &pb.DeleteDataKeyResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get a data key
func (s *safeAuth) GetDataKey(ctx context.Context, req *pb.GetDataKeyRequest) (*pb.GetDataKeyResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "datakeyro") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.GetDataKey(ctx, req)
		}
	}

	resp := &pb.GetDataKeyResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get a data key by id
func (s *safeAuth) GetDataKeyById(ctx context.Context, req *pb.GetDataKeyByIdRequest) (*pb.GetDataKeyByIdResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "datakeyro") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.GetDataKeyById(ctx, req)
		}
	}

	resp := &pb.GetDataKeyByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get a data keys by account_name
func (s *safeAuth) GetDataKeysByAccount(ctx context.Context, req *pb.GetDataKeysByAccountRequest) (*pb.GetDataKeysByAccountResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "datakeyro") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.GetDataKeysByAccount(ctx, req)
		}
	}

	resp := &pb.GetDataKeysByAccountResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get a decrypted version of data key
func (s *safeAuth) GetDecryptedDataKey(ctx context.Context, req *pb.GetDecryptedDataKeyRequest) (*pb.GetDecryptedDataKeyResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "datakeyro") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.GetDecryptedDataKey(ctx, req)
		}
	}

	resp := &pb.GetDecryptedDataKeyResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// create a new key node, encrypting value creating tree node if necessary
func (s *safeAuth) CreateKeyNode(ctx context.Context, req *pb.CreateKeyNodeRequest) (*pb.CreateKeyNodeResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.CreateKeyNode(ctx, req)
		}
	}

	resp := &pb.CreateKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// enable a key node
func (s *safeAuth) EnableKeyNode(ctx context.Context, req *pb.EnableKeyNodeRequest) (*pb.EnableKeyNodeResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.EnableKeyNode(ctx, req)
		}
	}

	resp := &pb.EnableKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// disable a key node
func (s *safeAuth) DisableKeyNode(ctx context.Context, req *pb.DisableKeyNodeRequest) (*pb.DisableKeyNodeResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.DisableKeyNode(ctx, req)
		}
	}

	resp := &pb.DisableKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// re-encrypt a key node
func (s *safeAuth) ReEncryptKeyNode(ctx context.Context, req *pb.ReEncryptKeyNodeRequest) (*pb.ReEncryptKeyNodeResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.ReEncryptKeyNode(ctx, req)
		}
	}

	resp := &pb.ReEncryptKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// copy a  key node to new path
func (s *safeAuth) CopyKeyNode(ctx context.Context, req *pb.CopyKeyNodeRequest) (*pb.CopyKeyNodeResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.CopyKeyNode(ctx, req)
		}
	}

	resp := &pb.CopyKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// delete a  key node
func (s *safeAuth) DeleteKeyNode(ctx context.Context, req *pb.DeleteKeyNodeRequest) (*pb.DeleteKeyNodeResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.DeleteKeyNode(ctx, req)
		}
	}

	resp := &pb.DeleteKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get a key node by node and path
func (s *safeAuth) GetKeyNode(ctx context.Context, req *pb.GetKeyNodeRequest) (*pb.GetKeyNodeResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") || (safebox == "keynodero") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.GetKeyNode(ctx, req)
		}
	}

	resp := &pb.GetKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get a key node by id
func (s *safeAuth) GetKeyNodeById(ctx context.Context, req *pb.GetKeyNodeByIdRequest) (*pb.GetKeyNodeByIdResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") || (safebox == "keynodero") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.GetKeyNodeById(ctx, req)
		}
	}

	resp := &pb.GetKeyNodeByIdResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get a list of key nodes by path
func (s *safeAuth) GetKeyNodeByPath(ctx context.Context, req *pb.GetKeyNodeByPathRequest) (*pb.GetKeyNodeByPathResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") || (safebox == "keynodero") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.GetKeyNodeByPath(ctx, req)
		}
	}

	resp := &pb.GetKeyNodeByPathResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get a decrypted version of key node
func (s *safeAuth) GetDecryptedKeyNode(ctx context.Context, req *pb.GetDecryptedKeyNodeRequest) (*pb.GetDecryptedKeyNodeResponse, error) {
	claims, err := s.GetJwtFromContext(ctx)
	if err == nil {
		safebox := GetStringFromClaims(claims, "safebox")
		if (safebox == "admin") || (safebox == "datakeyrw") || (safebox == "keynoderw") || (safebox == "keynodero") {
			req.AccountName = GetStringFromClaims(claims, "actname")
			return s.safeService.GetDecryptedKeyNode(ctx, req)
		}
	}

	resp := &pb.GetDecryptedKeyNodeResponse{}
	resp.ErrorCode = 401
	resp.ErrorMessage = "not authorized"

	return resp, err
}

// get current server version and uptime - health check
func (s *safeAuth) GetServerVersion(ctx context.Context, req *pb.GetServerVersionRequest) (*pb.GetServerVersionResponse, error) {
	return s.safeService.GetServerVersion(ctx, req)
}
