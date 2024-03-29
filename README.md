# Safebox

Copyright 2019-2023 Demian Harvill

## Overview

Safebox is a microservice for encrypting, saving and restoring secrets, possibly used by other microservices..
It is written in Go, and uses [gRPC](https://grpc.io) to define and implement it's application programming interface (API).
The server requires a JSON Web Token (JWT) generated by the [MService](https://github.com/gaterace/mservice) microservice
for authorization.

## Usage

Safebox maintains a catalog of AES encryption keys (data_key) for an account; the actual encryption keys are themselves
encrypted before saving in the database, using a master key.

Secrets are then created for an account using a filepath-like syntax (key_path) with reference to a data_key. They can
subsequently be decrypted (or re-encrypted) given the data_kay and master key.

Example client usage using the Go command line client (note that any thin client in any language supported by gRPC                                                                                                                                                             
can be used instead):

**safeclient add_shared_secret <shared_secret>**

When the safeserver is (re)started, it needs to reconstruct the master key. This command adds one of the shared  secrets
needed for this, at least two need to be specified (possibly by different people or processes) to establish
the master key. Once established, the master key is good until the next server restart (or until the shared secrets are
manually cleared. This requires admin or operator privilege.
The shared secrets can be generated by the **cmd/sssa/sssa** utility described later.

**safeclient clear_shared_secrets**

Clears the shared secrets. This requires admin or operator privilege.

**safeclient create_data_key test_data_key 'this is a test data key for safebox testing'**

Create a new AES encryption key, with given name and description. This requires admin or
datakeyrw privilege.

**safeclient get_data_keys_by_account**

Gets metadata about all data keys in this account. This requires admin, datakeyrw or datakeyro privilege.

**safeclient create_key_node 7 my/key/path/mysecret 'test secret to be stored in safebox' 'this is the actual secret'**

Creates a secret and encrypts it. The data_key_id (7 in the example) is returned by create_data_key and can be
discovered with get_data_keys_by_account. The key_path (my/key/path/mysecret) is the enxt parameter, followed
by the actual secret. This requires admin, datakeyrw or keynoderw privilege.

**safeclient get_decrypted_key_node my/key/path/mysecret**

This recovers the (unencrypted) secret. This requires admin, datakeyrw, keynoderw or keynodero privilege.

**Other commands** for operations (eg. update, delete, copy, re-encrypt) can be discovered with 

**safeclient**

with no parameters. 


 
## Certificates

### JWT Certificates
The generated JWT uses RSA asymmetric encryption for the public and private keys. These should have been generated
when installing the MService microservice; in particular, the safebox server needs access to the jwt_public.pem public key.

### SSL / TLS Certificates

In a production environment, the connection between the client and the MService server should be encrypted. This is
accomplished with the configuration setting:

    tls: true

If using either a public certificate for the server (ie, from LetsEncrypt) or a self-signed certificate,  the server need to know the public certificate as
well as the private key. 

The server configuration is:

    cert_file: <location of public or self-signed CA certificate

    key_file: <location of private key>

The client configuration needs to know the location of the CA cert_file if using self-signed certificates.

## Database

There are MySql scripts in the **sql/** directory that create the safebox database (safebox.sql) as well as all
the required tables (tb_*.sql).  These need to be run on the MySql server to create the database and associated tables.

## Data Model

The persistent data is managed by a MySQL / MariaDB database associated with this microservice.

The **master key** is not stored in the database, but is ephemeral and created by 2 of 3 shared secrets.

A set of **data key**s is used to encrypt the secrets, the key itself is encrypted by the master key before
saving in the database (tb_DataKey).

A **tree node** describes the filesystem-like key paths (tb_TreeNode).

A **key node** describes and holds the encrypted secret (tb_KeyNode) with reference to the data_key and tree_node.


## Server

To build the server:

**cd cmd/safeserver**
  
**go build**

The safeserver executable can then be run.  It expects a YAML configuration file in the same directory named **conf.yaml** .  The location
of the configuration file can be changed with an environment variable,**SAFE_CONF** . All of the configuration values
can be set as flags on the command line or as envirionment vaiables (with SAFE_ prefix).

```
safeserver -h

Usage:
  safeserver [flags]

Flags:
      --cert_file string        Path to certificate file.
      --conf string             Path to inventory config file. (default "conf.yaml")
      --db_pwd string           Database user password.
      --db_transport string     Database transport string.
      --db_user string          Database user name.
  -h, --help                    help for safeserver
      --jwt_pub_file string     Path to JWT public certificate.
      --key_file string         Path to certificate key file.
      --log_file string         Path to log file.
      --min_secret_shares int   Min number of secret shares for master key (default 2)
      --port int                Port for RPC connections (default 50052)
      --secret_shares int       Total number of secret shares for master key (default 3)
      --tls                     Use tls for connection.
```

A commented sample configuration file is at **cmd/safeserver/conf.sample** . The locations of the various certificates and 
keys need to be provided, as well as the database user and password and the MySql connection string.

## Go Client

A command line client written in Go is available:

**cd cmd/safeclient**

**go install** 
    
It also expects a YAML configuration file in the user's home directory, **~/.safebox.config**. A commented sample for this
file is at **cmd/safeclient/conf.sample**

Running the excutable file with no parameters will write usage information to stdout.  In particular, all subcommands expect
the user to have logged in with Mservice acctclient to establish the JWT. The JWT is also used to determine which
account is being used for the command.

Note that the use of the Go safeclient is merely a convenience, and not a requirement. Since we are using gRPC, the thin client
can be written in any supported language.  It can be part of a web or mobile application for example.

## Go SSSA Utility

A command line client written in Go can be used to generate shared secrets from a master key, using Shamir's Secret Sharing
algorithm. It uses an external library [sssa-golang](https://github.com/SSSaaS/sssa-golang).

**cd cmd/sssa**

**go build**

**./sssa <32 byte mater key>**


## Claims and Roles ##

The safebox microservice relies on the **safebox** claim, and the following claim values:

**admin**: administrative access

**operator**: able to add shared secret(s) to establish or clear master key 

**datakeyrw**: read-write access to data keys within account

**datakeyro**: read-only access to data keys within account

**keynoderw**: read-write access to key path secrets within an account.

**keynodero**: read-write access to key path secrets within an account.


Note that within an account in Mservice, a role must be created to map these claims to a logged-in user.

















