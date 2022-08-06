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

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	"github.com/gaterace/safebox/pkg/safeauth"
	"github.com/gaterace/safebox/pkg/safeservice"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

// gRPC server for safeservice.

func main() {
	cli := &cli{}

	cmd := &cobra.Command{
		Use:     "safeserver",
		PreRunE: cli.setupConfig,
		RunE:    cli.run,
	}

	if err := setupFlags(cmd); err != nil {
		fmt.Println(err)
		os.Exit(1)

	}

	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}

type cli struct {
	cfg cfg
}

type cfg struct {
	SafeConf        string
	LogFile         string
	CertFile        string
	KeyFile         string
	Tls             bool
	Port            int
	SecretShares    int
	MinSecretShares int
	DbUser          string
	DbPwd           string
	DbTransport     string
	JwtPubFile      string
}

func setupFlags(cmd *cobra.Command) error {

	cmd.Flags().String("conf", "conf.yaml", "Path to inventory config file.")
	cmd.Flags().String("log_file", "", "Path to log file.")
	cmd.Flags().String("cert_file", "", "Path to certificate file.")
	cmd.Flags().String("key_file", "", "Path to certificate key file.")
	cmd.Flags().Bool("tls", false, "Use tls for connection.")
	cmd.Flags().Int("port", 50052, "Port for RPC connections")
	cmd.Flags().Int("secret_shares", 3, "Total number of secret shares for master key")
	cmd.Flags().Int("min_secret_shares", 2, "Min number of secret shares for master key")

	cmd.Flags().String("db_user", "", "Database user name.")
	cmd.Flags().String("db_pwd", "", "Database user password.")
	cmd.Flags().String("db_transport", "", "Database transport string.")
	cmd.Flags().String("jwt_pub_file", "", "Path to JWT public certificate.")

	return viper.BindPFlags(cmd.Flags())
}

func (c *cli) setupConfig(cmd *cobra.Command, args []string) error {
	var err error

	viper.SetEnvPrefix("safe")

	viper.AutomaticEnv()

	configFile := viper.GetString("conf")

	viper.SetConfigFile(configFile)

	if err = viper.ReadInConfig(); err != nil {
		// it's ok if config file doesn't exist
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
	}

	c.cfg.LogFile = viper.GetString("log_file")
	c.cfg.CertFile = viper.GetString("cert_file")
	c.cfg.KeyFile = viper.GetString("key_file")
	c.cfg.Tls = viper.GetBool("tls")
	c.cfg.Port = viper.GetInt("port")
	c.cfg.SecretShares = viper.GetInt("secret_shares")
	c.cfg.MinSecretShares = viper.GetInt("min_secret_shares")

	c.cfg.DbUser = viper.GetString("db_user")
	c.cfg.DbPwd = viper.GetString("db_pwd")
	c.cfg.DbTransport = viper.GetString("db_transport")
	c.cfg.JwtPubFile = viper.GetString("jwt_pub_file")

	return nil
}

func (c *cli) run(cmd *cobra.Command, args []string) error {
	var err error

	log_file := c.cfg.LogFile
	cert_file := c.cfg.CertFile
	key_file := c.cfg.KeyFile
	tls := c.cfg.Tls
	port := c.cfg.Port
	db_user := c.cfg.DbUser
	db_pwd := c.cfg.DbPwd
	db_transport := c.cfg.DbTransport
	jwt_pub_file := c.cfg.JwtPubFile
	min_secret_shares := c.cfg.MinSecretShares
	secret_shares := c.cfg.SecretShares

	var logWriter io.Writer

	if log_file == "" {
		logWriter = os.Stderr
	} else {
		logfile, _ := os.OpenFile(log_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer logfile.Close()
		logWriter = logfile
	}
	logger := log.NewLogfmtLogger(log.NewSyncWriter(logWriter))
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	level.Info(logger).Log("log_file", log_file)
	level.Info(logger).Log("cert_file", cert_file)
	level.Info(logger).Log("key_file", key_file)
	level.Info(logger).Log("tls", tls)
	level.Info(logger).Log("port", port)
	level.Info(logger).Log("db_user", db_user)
	level.Info(logger).Log("db_transport", db_transport)
	level.Info(logger).Log("jwt_pub_file", jwt_pub_file)
	level.Info(logger).Log("min_secret_shares", min_secret_shares)
	level.Info(logger).Log("secret_shares", secret_shares)

	listen_port := ":" + strconv.Itoa(int(port))
	// fmt.Println(listen_port)

	lis, err := net.Listen("tcp", listen_port)
	if err != nil {
		level.Error(logger).Log("what", "net.listen", "error", err)
	}

	var opts []grpc.ServerOption
	if tls {
		creds, err := credentials.NewServerTLSFromFile(cert_file, key_file)
		if err != nil {
			level.Error(logger).Log("what", "Failed to generate credentials", "error", err)
			os.Exit(1)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}

	s := grpc.NewServer(opts...)

	safeService := safeservice.NewSafeboxService(int(min_secret_shares), int(secret_shares))

	sqlDb, err := SetupDatabaseConnections(db_user, db_pwd, db_transport)
	if err != nil {
		level.Error(logger).Log("what", "SetupDatabaseConnections", "error", err)
	}

	safeService.SetLogger(logger)
	safeService.SetDatabaseConnection(sqlDb)

	// wire up the authorization middleware

	safeAuth := safeauth.NewSafeboxAuth(safeService)

	safeAuth.SetLogger(logger)

	safeAuth.SetPublicKey(jwt_pub_file)
	safeAuth.SetDatabaseConnection(sqlDb)
	err = safeAuth.NewApiServer(s)
	if err != nil {
		level.Error(logger).Log("what", "NewApiServer", "error", err)
		os.Exit(1)
	}

	level.Info(logger).Log("msg", "starting grpc server")

	err = s.Serve(lis)
	if err != nil {
		level.Error(logger).Log("what", "Serve", "error", err)
	}

	level.Info(logger).Log("msg", "shutting down grpc server")

	return err

}

func SetupDatabaseConnections(db_user string, db_pwd string, db_transport string) (*sql.DB, error) {
	var sqlDb *sql.DB
	endpoint := db_user + ":" + db_pwd + "@" + db_transport + "/safebox"

	var err error
	sqlDb, err = sql.Open("mysql", endpoint)
	if err == nil {
		err = sqlDb.Ping()
		if err != nil {
			sqlDb = nil
		}

	}

	return sqlDb, err
}
