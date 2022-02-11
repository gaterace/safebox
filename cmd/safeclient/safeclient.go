// Copyright 2019-2022 Demian Harvill
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

// command line gRPC  client for safebox service.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"

	flag "github.com/juju/gnuflag"

	pb "github.com/gaterace/safebox/pkg/mservicesafebox"
	"github.com/kylelemons/go-gypsy/yaml"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
)

// var accountName = flag.String("a", "", "account name")
var disable = flag.Bool("disable", false, "disable key node")

func main() {
	flag.Parse(true)

	configFilename := "conf.yaml"
	usr, err := user.Current()
	if err == nil {
		homeDir := usr.HomeDir
		configFilename = homeDir + string(os.PathSeparator) + ".safebox.config"
	}

	config, err := yaml.ReadFile(configFilename)
	if err != nil {
		log.Fatalf("configuration not found: " + configFilename)
	}

	// log_file, _ := config.Get("log_file")
	ca_file, _ := config.Get("ca_file")
	tls, _ := config.GetBool("tls")
	server_host_override, _ := config.Get("server_host_override")
	server, _ := config.Get("server")
	port, _ := config.GetInt("port")
	// account, _ := config.Get("account")

	// fmt.Printf("log_file: %s\n", log_file)
	// fmt.Printf("ca_file: %s\n", ca_file)
	// fmt.Printf("tls: %t\n", tls)
	// fmt.Printf("server_host_override: %s\n", server_host_override)
	// fmt.Printf("server: %s\n", server)
	// fmt.Printf("port: %d\n", port)
	// fmt.Printf("account: %s\n", account)

	if port == 0 {
		port = 50052
	}

	if len(flag.Args()) < 1 {
		prog := os.Args[0]
		fmt.Printf("Command line client for safebox grpc service\n")
		fmt.Printf("usage:\n")
		fmt.Printf("    %s add_shared_secret <shared_secret>\n", prog)
		fmt.Printf("    %s clear_shared_secrets\n", prog)
		fmt.Printf("    %s create_data_key <data_key_name> <data_key_description>\n", prog)
		fmt.Printf("    %s delete_data_key <data_key_id>\n", prog)
		fmt.Printf("    %s get_data_key <data_key_name>\n", prog)
		fmt.Printf("    %s get_data_key_by_id <data_key_id>\n", prog)
		fmt.Printf("    %s get_data_keys_by_account \n", prog)
		fmt.Printf("    %s get_decrypted_data_key <data_key_name>\n", prog)
		fmt.Printf("    %s create_key_node [--disable] <data_key_id> <key_path> <key_description> <key_value>\n", prog)
		fmt.Printf("    %s enable_key_node <key_id>\n", prog)
		fmt.Printf("    %s disable_key_node <key_id>\n", prog)
		fmt.Printf("    %s re_encrypt_key_node <key_id> <data_key_id>\n", prog)
		fmt.Printf("    %s copy_key_node <key_id> <node_path>\n", prog)
		fmt.Printf("    %s delete_key_node <key_id>\n", prog)
		fmt.Printf("    %s get_key_node <key_path>\n", prog)
		fmt.Printf("    %s get_key_node_by_id <key_id>\n", prog)
		fmt.Printf("    %s get_key_node_by_path <node_path>\n", prog)
		fmt.Printf("    %s get_decrypted_key_node <key_path>\n", prog)
		fmt.Printf("    %s get_server_version \n", prog)

		os.Exit(1)
	}

	cmd := flag.Arg(0)
	// fmt.Printf("cmd: %s\n", cmd)

	var shared_secret string
	var data_key_name string
	var data_key_description string
	var data_key_id int64
	var key_path string
	var key_description string
	var key_value string
	var key_id int64
	var node_path string

	validParams := true

	switch cmd {
	case "add_shared_secret":
		shared_secret = flag.Arg(1)
		if shared_secret == "" {
			fmt.Println("shared_secret parameter missing")
			validParams = false
		}
	case "clear_shared_secrets":
	case "create_data_key":
		data_key_name = flag.Arg(1)
		data_key_description = flag.Arg(2)
		if data_key_name == "" {
			fmt.Println("data_key_name parameter missing")
			validParams = false
		}
		if data_key_description == "" {
			fmt.Println("data_key_description parameter missing")
			validParams = false
		}
	case "delete_data_key":
		data_key_id, err = strconv.ParseInt(flag.Arg(1), 10, 64)
		if err != nil {
			fmt.Println("data_key_id parameter missing or invalid integer")
			validParams = false
		}
	case "get_data_key":
		data_key_name = flag.Arg(1)
		if data_key_name == "" {
			fmt.Println("data_key_name parameter missing")
			validParams = false
		}
	case "get_data_key_by_id":
		data_key_id, err = strconv.ParseInt(flag.Arg(1), 10, 64)
		if err != nil {
			fmt.Println("data_key_id parameter missing or invalid integer")
			validParams = false
		}
	case "get_data_keys_by_account":
	case "get_decrypted_data_key":
		data_key_name = flag.Arg(1)
		if data_key_name == "" {
			fmt.Println("data_key_name parameter missing")
			validParams = false
		}
	case "create_key_node":
		data_key_id, err = strconv.ParseInt(flag.Arg(1), 10, 64)
		if err != nil {
			fmt.Println("data_key_id parameter missing or invalid integer")
			validParams = false
		}
		key_path = flag.Arg(2)
		if key_path == "" {
			fmt.Println("key_path parameter missing")
			validParams = false
		}
		key_description = flag.Arg(3)
		if key_description == "" {
			fmt.Println("key_description parameter missing")
			validParams = false
		}
		key_value = flag.Arg(4)
		if key_value == "" {
			fmt.Println("key_value parameter missing")
			validParams = false
		}
	case "enable_key_node":
		key_id, err = strconv.ParseInt(flag.Arg(1), 10, 64)
		if err != nil {
			fmt.Println("key_id parameter missing or invalid integer")
			validParams = false
		}
	case "disable_key_node":
		key_id, err = strconv.ParseInt(flag.Arg(1), 10, 64)
		if err != nil {
			fmt.Println("key_id parameter missing or invalid integer")
			validParams = false
		}
	case "re_encrypt_key_node":
		key_id, err = strconv.ParseInt(flag.Arg(1), 10, 64)
		if err != nil {
			fmt.Println("key_id parameter missing or invalid integer")
			validParams = false
		}
		data_key_id, err = strconv.ParseInt(flag.Arg(2), 10, 64)
		if err != nil {
			fmt.Println("data_key_id parameter missing or invalid integer")
			validParams = false
		}
	case "delete_key_node":
		key_id, err = strconv.ParseInt(flag.Arg(1), 10, 64)
		if err != nil {
			fmt.Println("key_id parameter missing or invalid integer")
			validParams = false
		}
	case "get_key_node":
		key_path = flag.Arg(1)
		if key_path == "" {
			fmt.Println("key_path parameter missing")
			validParams = false
		}
	case "get_key_node_by_id":
		key_id, err = strconv.ParseInt(flag.Arg(1), 10, 64)
		if err != nil {
			fmt.Println("key_id parameter missing or invalid integer")
			validParams = false
		}
	case "get_key_node_by_path":
		node_path = flag.Arg(1)
		if node_path == "" {
			fmt.Println("node_path parameter missing")
			validParams = false
		} else if node_path == "*" {
			node_path = ""
		}
	case "get_decrypted_key_node":
		key_path = flag.Arg(1)
		if key_path == "" {
			fmt.Println("key_path parameter missing")
			validParams = false
		}
	case "get_server_version":
		validParams = true
	default:
		fmt.Printf("unknown command: %s\n", cmd)
		validParams = false
	}

	if !validParams {
		os.Exit(1)
	}

	// fmt.Printf("data_key_description: %s\n", data_key_description)
	// fmt.Printf("data_key_id: %d\n", data_key_id)
	// fmt.Printf("key_id: %d\n", key_id)

	tokenFilename := "token.txt"
	usr, err = user.Current()
	if err == nil {
		homeDir := usr.HomeDir
		tokenFilename = homeDir + string(os.PathSeparator) + ".mservice.token"
	}

	address := server + ":" + strconv.Itoa(int(port))
	// fmt.Printf("address: %s\n", address)

	var opts []grpc.DialOption
	if tls {
		var sn string
		if server_host_override != "" {
			sn = server_host_override
		}
		var creds credentials.TransportCredentials
		if ca_file != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(ca_file, sn)
			if err != nil {
				grpclog.Fatalf("Failed to create TLS credentials %v", err)
			}
		} else {
			creds = credentials.NewClientTLSFromCert(nil, sn)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	// set up connection to server
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	defer conn.Close()

	client := pb.NewMServiceSafeboxClient(conn)

	ctx := context.Background()

	savedToken := ""

	data, err := ioutil.ReadFile(tokenFilename)

	if err == nil {
		savedToken = string(data)
	}

	md := metadata.Pairs("token", savedToken)
	mctx := metadata.NewOutgoingContext(ctx, md)

	switch cmd {
	case "add_shared_secret":
		req := pb.AddSharedSecretRequest{}
		req.SharedSecret = shared_secret
		resp, err := client.AddSharedSecret(mctx, &req)
		printResponse(resp, err)

	case "clear_shared_secrets":
		req := pb.ClearSharedSecretsRequest{}
		req.DummyParam = 1
		resp, err := client.ClearSharedSecrets(mctx, &req)
		printResponse(resp, err)

	case "create_data_key":
		req := pb.CreateDataKeyRequest{}
		// req.AccountName = account
		req.DataKeyName = data_key_name
		req.DataKeyDescription = data_key_description
		resp, err := client.CreateDataKey(mctx, &req)
		printResponse(resp, err)

	case "delete_data_key":
		req1 := pb.GetDataKeyByIdRequest{}
		// req1.AccountName = account
		req1.DataKeyId = data_key_id
		resp1, err := client.GetDataKeyById(mctx, &req1)
		if (err == nil) && (resp1.GetErrorCode() == 0) {
			req2 := pb.DeleteDataKeyRequest{}
			// req2.AccountName = account
			req2.DataKeyId = data_key_id
			req2.Version = resp1.GetDatakey().GetVersion()
			resp, err := client.DeleteDataKey(mctx, &req2)
			printResponse(resp, err)
		} else {
			fmt.Printf("unable to get data key for deletion: %d\n", data_key_id)
		}
	case "get_data_key":
		req := pb.GetDataKeyRequest{}
		// req.AccountName = account
		req.DataKeyName = data_key_name
		resp, err := client.GetDataKey(mctx, &req)
		printResponse(resp, err)

	case "get_data_key_by_id":
		req := pb.GetDataKeyByIdRequest{}
		// req.AccountName = account
		req.DataKeyId = data_key_id
		resp, err := client.GetDataKeyById(mctx, &req)
		printResponse(resp, err)

	case "get_data_keys_by_account":
		req := pb.GetDataKeysByAccountRequest{}
		// req.AccountName = account
		resp, err := client.GetDataKeysByAccount(mctx, &req)
		printResponse(resp, err)

	case "get_decrypted_data_key":
		req := pb.GetDecryptedDataKeyRequest{}
		// req.AccountName = account
		req.DataKeyName = data_key_name
		resp, err := client.GetDecryptedDataKey(mctx, &req)
		printResponse(resp, err)

	case "create_key_node":
		req := pb.CreateKeyNodeRequest{}
		nodePath, keyName := splitKeyPath(key_path)
		// req.AccountName = account
		req.NodePath = nodePath
		req.DataKeyId = data_key_id
		req.IsEnabled = !*disable
		req.KeyName = keyName
		req.KeyDescription = key_description
		keyVal, err := loadKeyValue(key_value)
		if err == nil {
			req.KeyValue = keyVal
			resp, err := client.CreateKeyNode(mctx, &req)
			printResponse(resp, err)
		}
		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "enable_key_node":
		req1 := pb.GetKeyNodeByIdRequest{}
		// req1.AccountName = account
		req1.KeyId = key_id
		resp1, err := client.GetKeyNodeById(mctx, &req1)
		if err == nil {
			req := pb.EnableKeyNodeRequest{}
			// req.AccountName = account
			req.KeyId = key_id
			req.Version = resp1.GetKeynode().GetVersion()
			resp, err := client.EnableKeyNode(mctx, &req)
			printResponse(resp, err)
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "disable_key_node":
		req1 := pb.GetKeyNodeByIdRequest{}
		// req1.AccountName = account
		req1.KeyId = key_id
		resp1, err := client.GetKeyNodeById(mctx, &req1)
		if err == nil {
			req := pb.DisableKeyNodeRequest{}
			// req.AccountName = account
			req.KeyId = key_id
			req.Version = resp1.GetKeynode().GetVersion()
			resp, err := client.DisableKeyNode(mctx, &req)
			printResponse(resp, err)
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "re_encrypt_key_node":
		req1 := pb.GetKeyNodeByIdRequest{}
		// req1.AccountName = account
		req1.KeyId = key_id
		resp1, err := client.GetKeyNodeById(mctx, &req1)
		if err == nil {
			req := pb.ReEncryptKeyNodeRequest{}
			// req.AccountName = account
			req.KeyId = key_id
			req.Version = resp1.GetKeynode().GetVersion()
			req.DataKeyId = data_key_id
			resp, err := client.ReEncryptKeyNode(mctx, &req)
			printResponse(resp, err)
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "copy_key_node":
		req1 := pb.GetKeyNodeByIdRequest{}
		// req1.AccountName = account
		req1.KeyId = key_id
		resp1, err := client.GetKeyNodeById(mctx, &req1)
		if err == nil {
			req := pb.CopyKeyNodeRequest{}
			// req.AccountName = account
			req.KeyId = key_id
			req.Version = resp1.GetKeynode().GetVersion()
			req.NodePath = node_path
			resp, err := client.CopyKeyNode(mctx, &req)
			printResponse(resp, err)
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "delete_key_node":
		req1 := pb.GetKeyNodeByIdRequest{}
		// req1.AccountName = account
		req1.KeyId = key_id
		resp1, err := client.GetKeyNodeById(mctx, &req1)
		if err == nil {
			req := pb.DeleteKeyNodeRequest{}
			// req.AccountName = account
			req.KeyId = key_id
			req.Version = resp1.GetKeynode().GetVersion()
			resp, err := client.DeleteKeyNode(mctx, &req)
			printResponse(resp, err)
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_key_node":
		nodePath, keyName := splitKeyPath(key_path)
		req := pb.GetKeyNodeRequest{}
		// req.AccountName = account
		req.NodePath = nodePath
		req.KeyName = keyName
		resp, err := client.GetKeyNode(mctx, &req)
		printResponse(resp, err)

	case "get_key_node_by_id":
		req := pb.GetKeyNodeByIdRequest{}
		// req.AccountName = account
		req.KeyId = key_id
		resp, err := client.GetKeyNodeById(mctx, &req)
		printResponse(resp, err)

	case "get_key_node_by_path":
		req := pb.GetKeyNodeByPathRequest{}
		// req.AccountName = account
		req.NodePath = node_path
		resp, err := client.GetKeyNodeByPath(mctx, &req)
		printResponse(resp, err)

	case "get_decrypted_key_node":
		nodePath, keyName := splitKeyPath(key_path)
		req := pb.GetDecryptedKeyNodeRequest{}
		// req.AccountName = account
		req.NodePath = nodePath
		req.KeyName = keyName
		resp, err := client.GetDecryptedKeyNode(mctx, &req)

		if err == nil {
			if resp.GetErrorCode() == 0 {
				fmt.Println(string(resp.DecryptedKeyValue))
			} else {
				jtext, err := json.MarshalIndent(resp, "", "  ")
				if err == nil {
					fmt.Println(string(jtext))
				}
			}
		}

		if err != nil {
			fmt.Printf("err: %s\n", err)
		}
	case "get_server_version":
		req := pb.GetServerVersionRequest{}
		req.DummyParam = 1
		resp, err := client.GetServerVersion(mctx, &req)
		printResponse(resp, err)
	default:
		fmt.Printf("unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

func splitKeyPath(keyPath string) (string, string) {
	nodePath := ""
	keyName := ""

	index := strings.LastIndex(keyPath, "/")
	if index > 0 {
		nodePath = keyPath[0:(index + 1)]
		keyName = keyPath[(index + 1):]
	}

	return nodePath, keyName
}

func loadKeyValue(keyVal string) ([]byte, error) {
	if (len(keyVal) > 5) && (keyVal[0:5] == "file:") {
		filename := keyVal[5:]
		data, err := ioutil.ReadFile(filename)
		return data, err

	} else {
		return []byte(keyVal), nil
	}
}

func printResponse(resp interface{}, err error) {
	if err == nil {
		jtext, err := json.MarshalIndent(resp, "", "  ")
		if err == nil {
			fmt.Println(string(jtext))
		}
	}
	if err != nil {
		fmt.Printf("err: %s\n", err)
	}
}
