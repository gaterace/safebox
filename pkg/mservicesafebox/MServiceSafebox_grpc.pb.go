// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package mservicesafebox

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// MServiceSafeboxClient is the client API for MServiceSafebox service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MServiceSafeboxClient interface {
	// initialize service with shared secret
	AddSharedSecret(ctx context.Context, in *AddSharedSecretRequest, opts ...grpc.CallOption) (*AddSharedSecretResponse, error)
	// remocve shared secrets
	ClearSharedSecrets(ctx context.Context, in *ClearSharedSecretsRequest, opts ...grpc.CallOption) (*ClearSharedSecretsResponse, error)
	// create a new data key
	CreateDataKey(ctx context.Context, in *CreateDataKeyRequest, opts ...grpc.CallOption) (*CreateDataKeyResponse, error)
	// delete a data key
	DeleteDataKey(ctx context.Context, in *DeleteDataKeyRequest, opts ...grpc.CallOption) (*DeleteDataKeyResponse, error)
	// get a data key
	GetDataKey(ctx context.Context, in *GetDataKeyRequest, opts ...grpc.CallOption) (*GetDataKeyResponse, error)
	// get a data key by id
	GetDataKeyById(ctx context.Context, in *GetDataKeyByIdRequest, opts ...grpc.CallOption) (*GetDataKeyByIdResponse, error)
	// get a data keys by account_name
	GetDataKeysByAccount(ctx context.Context, in *GetDataKeysByAccountRequest, opts ...grpc.CallOption) (*GetDataKeysByAccountResponse, error)
	// get a decrypted version of data key
	GetDecryptedDataKey(ctx context.Context, in *GetDecryptedDataKeyRequest, opts ...grpc.CallOption) (*GetDecryptedDataKeyResponse, error)
	// create a new key node, encrypting value creating tree node if necessary
	CreateKeyNode(ctx context.Context, in *CreateKeyNodeRequest, opts ...grpc.CallOption) (*CreateKeyNodeResponse, error)
	// enable a key node
	EnableKeyNode(ctx context.Context, in *EnableKeyNodeRequest, opts ...grpc.CallOption) (*EnableKeyNodeResponse, error)
	// disable a key node
	DisableKeyNode(ctx context.Context, in *DisableKeyNodeRequest, opts ...grpc.CallOption) (*DisableKeyNodeResponse, error)
	// re-encrypt a key node
	ReEncryptKeyNode(ctx context.Context, in *ReEncryptKeyNodeRequest, opts ...grpc.CallOption) (*ReEncryptKeyNodeResponse, error)
	// copy a  key node to new path
	CopyKeyNode(ctx context.Context, in *CopyKeyNodeRequest, opts ...grpc.CallOption) (*CopyKeyNodeResponse, error)
	// delete a  key node
	DeleteKeyNode(ctx context.Context, in *DeleteKeyNodeRequest, opts ...grpc.CallOption) (*DeleteKeyNodeResponse, error)
	// get a key node by node and path
	GetKeyNode(ctx context.Context, in *GetKeyNodeRequest, opts ...grpc.CallOption) (*GetKeyNodeResponse, error)
	// get a key node by id
	GetKeyNodeById(ctx context.Context, in *GetKeyNodeByIdRequest, opts ...grpc.CallOption) (*GetKeyNodeByIdResponse, error)
	// get a list of key nodes by path
	GetKeyNodeByPath(ctx context.Context, in *GetKeyNodeByPathRequest, opts ...grpc.CallOption) (*GetKeyNodeByPathResponse, error)
	// get a decrypted version of key node
	GetDecryptedKeyNode(ctx context.Context, in *GetDecryptedKeyNodeRequest, opts ...grpc.CallOption) (*GetDecryptedKeyNodeResponse, error)
	// get current server version and uptime - health check
	GetServerVersion(ctx context.Context, in *GetServerVersionRequest, opts ...grpc.CallOption) (*GetServerVersionResponse, error)
}

type mServiceSafeboxClient struct {
	cc grpc.ClientConnInterface
}

func NewMServiceSafeboxClient(cc grpc.ClientConnInterface) MServiceSafeboxClient {
	return &mServiceSafeboxClient{cc}
}

func (c *mServiceSafeboxClient) AddSharedSecret(ctx context.Context, in *AddSharedSecretRequest, opts ...grpc.CallOption) (*AddSharedSecretResponse, error) {
	out := new(AddSharedSecretResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/add_shared_secret", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) ClearSharedSecrets(ctx context.Context, in *ClearSharedSecretsRequest, opts ...grpc.CallOption) (*ClearSharedSecretsResponse, error) {
	out := new(ClearSharedSecretsResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/clear_shared_secrets", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) CreateDataKey(ctx context.Context, in *CreateDataKeyRequest, opts ...grpc.CallOption) (*CreateDataKeyResponse, error) {
	out := new(CreateDataKeyResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/create_data_key", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) DeleteDataKey(ctx context.Context, in *DeleteDataKeyRequest, opts ...grpc.CallOption) (*DeleteDataKeyResponse, error) {
	out := new(DeleteDataKeyResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/delete_data_key", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetDataKey(ctx context.Context, in *GetDataKeyRequest, opts ...grpc.CallOption) (*GetDataKeyResponse, error) {
	out := new(GetDataKeyResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_data_key", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetDataKeyById(ctx context.Context, in *GetDataKeyByIdRequest, opts ...grpc.CallOption) (*GetDataKeyByIdResponse, error) {
	out := new(GetDataKeyByIdResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_data_key_by_id", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetDataKeysByAccount(ctx context.Context, in *GetDataKeysByAccountRequest, opts ...grpc.CallOption) (*GetDataKeysByAccountResponse, error) {
	out := new(GetDataKeysByAccountResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_data_keys_by_account", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetDecryptedDataKey(ctx context.Context, in *GetDecryptedDataKeyRequest, opts ...grpc.CallOption) (*GetDecryptedDataKeyResponse, error) {
	out := new(GetDecryptedDataKeyResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_decrypted_data_key", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) CreateKeyNode(ctx context.Context, in *CreateKeyNodeRequest, opts ...grpc.CallOption) (*CreateKeyNodeResponse, error) {
	out := new(CreateKeyNodeResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/create_key_node", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) EnableKeyNode(ctx context.Context, in *EnableKeyNodeRequest, opts ...grpc.CallOption) (*EnableKeyNodeResponse, error) {
	out := new(EnableKeyNodeResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/enable_key_node", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) DisableKeyNode(ctx context.Context, in *DisableKeyNodeRequest, opts ...grpc.CallOption) (*DisableKeyNodeResponse, error) {
	out := new(DisableKeyNodeResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/disable_key_node", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) ReEncryptKeyNode(ctx context.Context, in *ReEncryptKeyNodeRequest, opts ...grpc.CallOption) (*ReEncryptKeyNodeResponse, error) {
	out := new(ReEncryptKeyNodeResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/re_encrypt_key_node", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) CopyKeyNode(ctx context.Context, in *CopyKeyNodeRequest, opts ...grpc.CallOption) (*CopyKeyNodeResponse, error) {
	out := new(CopyKeyNodeResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/copy_key_node", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) DeleteKeyNode(ctx context.Context, in *DeleteKeyNodeRequest, opts ...grpc.CallOption) (*DeleteKeyNodeResponse, error) {
	out := new(DeleteKeyNodeResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/delete_key_node", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetKeyNode(ctx context.Context, in *GetKeyNodeRequest, opts ...grpc.CallOption) (*GetKeyNodeResponse, error) {
	out := new(GetKeyNodeResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_key_node", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetKeyNodeById(ctx context.Context, in *GetKeyNodeByIdRequest, opts ...grpc.CallOption) (*GetKeyNodeByIdResponse, error) {
	out := new(GetKeyNodeByIdResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_key_node_by_id", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetKeyNodeByPath(ctx context.Context, in *GetKeyNodeByPathRequest, opts ...grpc.CallOption) (*GetKeyNodeByPathResponse, error) {
	out := new(GetKeyNodeByPathResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_key_node_by_path", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetDecryptedKeyNode(ctx context.Context, in *GetDecryptedKeyNodeRequest, opts ...grpc.CallOption) (*GetDecryptedKeyNodeResponse, error) {
	out := new(GetDecryptedKeyNodeResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_decrypted_key_node", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mServiceSafeboxClient) GetServerVersion(ctx context.Context, in *GetServerVersionRequest, opts ...grpc.CallOption) (*GetServerVersionResponse, error) {
	out := new(GetServerVersionResponse)
	err := c.cc.Invoke(ctx, "/org.gaterace.mservice.safebox.MServiceSafebox/get_server_version", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MServiceSafeboxServer is the server API for MServiceSafebox service.
// All implementations must embed UnimplementedMServiceSafeboxServer
// for forward compatibility
type MServiceSafeboxServer interface {
	// initialize service with shared secret
	AddSharedSecret(context.Context, *AddSharedSecretRequest) (*AddSharedSecretResponse, error)
	// remocve shared secrets
	ClearSharedSecrets(context.Context, *ClearSharedSecretsRequest) (*ClearSharedSecretsResponse, error)
	// create a new data key
	CreateDataKey(context.Context, *CreateDataKeyRequest) (*CreateDataKeyResponse, error)
	// delete a data key
	DeleteDataKey(context.Context, *DeleteDataKeyRequest) (*DeleteDataKeyResponse, error)
	// get a data key
	GetDataKey(context.Context, *GetDataKeyRequest) (*GetDataKeyResponse, error)
	// get a data key by id
	GetDataKeyById(context.Context, *GetDataKeyByIdRequest) (*GetDataKeyByIdResponse, error)
	// get a data keys by account_name
	GetDataKeysByAccount(context.Context, *GetDataKeysByAccountRequest) (*GetDataKeysByAccountResponse, error)
	// get a decrypted version of data key
	GetDecryptedDataKey(context.Context, *GetDecryptedDataKeyRequest) (*GetDecryptedDataKeyResponse, error)
	// create a new key node, encrypting value creating tree node if necessary
	CreateKeyNode(context.Context, *CreateKeyNodeRequest) (*CreateKeyNodeResponse, error)
	// enable a key node
	EnableKeyNode(context.Context, *EnableKeyNodeRequest) (*EnableKeyNodeResponse, error)
	// disable a key node
	DisableKeyNode(context.Context, *DisableKeyNodeRequest) (*DisableKeyNodeResponse, error)
	// re-encrypt a key node
	ReEncryptKeyNode(context.Context, *ReEncryptKeyNodeRequest) (*ReEncryptKeyNodeResponse, error)
	// copy a  key node to new path
	CopyKeyNode(context.Context, *CopyKeyNodeRequest) (*CopyKeyNodeResponse, error)
	// delete a  key node
	DeleteKeyNode(context.Context, *DeleteKeyNodeRequest) (*DeleteKeyNodeResponse, error)
	// get a key node by node and path
	GetKeyNode(context.Context, *GetKeyNodeRequest) (*GetKeyNodeResponse, error)
	// get a key node by id
	GetKeyNodeById(context.Context, *GetKeyNodeByIdRequest) (*GetKeyNodeByIdResponse, error)
	// get a list of key nodes by path
	GetKeyNodeByPath(context.Context, *GetKeyNodeByPathRequest) (*GetKeyNodeByPathResponse, error)
	// get a decrypted version of key node
	GetDecryptedKeyNode(context.Context, *GetDecryptedKeyNodeRequest) (*GetDecryptedKeyNodeResponse, error)
	// get current server version and uptime - health check
	GetServerVersion(context.Context, *GetServerVersionRequest) (*GetServerVersionResponse, error)
	mustEmbedUnimplementedMServiceSafeboxServer()
}

// UnimplementedMServiceSafeboxServer must be embedded to have forward compatible implementations.
type UnimplementedMServiceSafeboxServer struct {
}

func (UnimplementedMServiceSafeboxServer) AddSharedSecret(context.Context, *AddSharedSecretRequest) (*AddSharedSecretResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddSharedSecret not implemented")
}
func (UnimplementedMServiceSafeboxServer) ClearSharedSecrets(context.Context, *ClearSharedSecretsRequest) (*ClearSharedSecretsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ClearSharedSecrets not implemented")
}
func (UnimplementedMServiceSafeboxServer) CreateDataKey(context.Context, *CreateDataKeyRequest) (*CreateDataKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateDataKey not implemented")
}
func (UnimplementedMServiceSafeboxServer) DeleteDataKey(context.Context, *DeleteDataKeyRequest) (*DeleteDataKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteDataKey not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetDataKey(context.Context, *GetDataKeyRequest) (*GetDataKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDataKey not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetDataKeyById(context.Context, *GetDataKeyByIdRequest) (*GetDataKeyByIdResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDataKeyById not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetDataKeysByAccount(context.Context, *GetDataKeysByAccountRequest) (*GetDataKeysByAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDataKeysByAccount not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetDecryptedDataKey(context.Context, *GetDecryptedDataKeyRequest) (*GetDecryptedDataKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDecryptedDataKey not implemented")
}
func (UnimplementedMServiceSafeboxServer) CreateKeyNode(context.Context, *CreateKeyNodeRequest) (*CreateKeyNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateKeyNode not implemented")
}
func (UnimplementedMServiceSafeboxServer) EnableKeyNode(context.Context, *EnableKeyNodeRequest) (*EnableKeyNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EnableKeyNode not implemented")
}
func (UnimplementedMServiceSafeboxServer) DisableKeyNode(context.Context, *DisableKeyNodeRequest) (*DisableKeyNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DisableKeyNode not implemented")
}
func (UnimplementedMServiceSafeboxServer) ReEncryptKeyNode(context.Context, *ReEncryptKeyNodeRequest) (*ReEncryptKeyNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReEncryptKeyNode not implemented")
}
func (UnimplementedMServiceSafeboxServer) CopyKeyNode(context.Context, *CopyKeyNodeRequest) (*CopyKeyNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CopyKeyNode not implemented")
}
func (UnimplementedMServiceSafeboxServer) DeleteKeyNode(context.Context, *DeleteKeyNodeRequest) (*DeleteKeyNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteKeyNode not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetKeyNode(context.Context, *GetKeyNodeRequest) (*GetKeyNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetKeyNode not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetKeyNodeById(context.Context, *GetKeyNodeByIdRequest) (*GetKeyNodeByIdResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetKeyNodeById not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetKeyNodeByPath(context.Context, *GetKeyNodeByPathRequest) (*GetKeyNodeByPathResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetKeyNodeByPath not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetDecryptedKeyNode(context.Context, *GetDecryptedKeyNodeRequest) (*GetDecryptedKeyNodeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDecryptedKeyNode not implemented")
}
func (UnimplementedMServiceSafeboxServer) GetServerVersion(context.Context, *GetServerVersionRequest) (*GetServerVersionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetServerVersion not implemented")
}
func (UnimplementedMServiceSafeboxServer) mustEmbedUnimplementedMServiceSafeboxServer() {}

// UnsafeMServiceSafeboxServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MServiceSafeboxServer will
// result in compilation errors.
type UnsafeMServiceSafeboxServer interface {
	mustEmbedUnimplementedMServiceSafeboxServer()
}

func RegisterMServiceSafeboxServer(s grpc.ServiceRegistrar, srv MServiceSafeboxServer) {
	s.RegisterService(&MServiceSafebox_ServiceDesc, srv)
}

func _MServiceSafebox_AddSharedSecret_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddSharedSecretRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).AddSharedSecret(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/add_shared_secret",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).AddSharedSecret(ctx, req.(*AddSharedSecretRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_ClearSharedSecrets_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ClearSharedSecretsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).ClearSharedSecrets(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/clear_shared_secrets",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).ClearSharedSecrets(ctx, req.(*ClearSharedSecretsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_CreateDataKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateDataKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).CreateDataKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/create_data_key",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).CreateDataKey(ctx, req.(*CreateDataKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_DeleteDataKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteDataKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).DeleteDataKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/delete_data_key",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).DeleteDataKey(ctx, req.(*DeleteDataKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetDataKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDataKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetDataKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_data_key",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetDataKey(ctx, req.(*GetDataKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetDataKeyById_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDataKeyByIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetDataKeyById(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_data_key_by_id",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetDataKeyById(ctx, req.(*GetDataKeyByIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetDataKeysByAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDataKeysByAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetDataKeysByAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_data_keys_by_account",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetDataKeysByAccount(ctx, req.(*GetDataKeysByAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetDecryptedDataKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDecryptedDataKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetDecryptedDataKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_decrypted_data_key",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetDecryptedDataKey(ctx, req.(*GetDecryptedDataKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_CreateKeyNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateKeyNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).CreateKeyNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/create_key_node",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).CreateKeyNode(ctx, req.(*CreateKeyNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_EnableKeyNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EnableKeyNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).EnableKeyNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/enable_key_node",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).EnableKeyNode(ctx, req.(*EnableKeyNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_DisableKeyNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DisableKeyNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).DisableKeyNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/disable_key_node",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).DisableKeyNode(ctx, req.(*DisableKeyNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_ReEncryptKeyNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReEncryptKeyNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).ReEncryptKeyNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/re_encrypt_key_node",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).ReEncryptKeyNode(ctx, req.(*ReEncryptKeyNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_CopyKeyNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CopyKeyNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).CopyKeyNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/copy_key_node",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).CopyKeyNode(ctx, req.(*CopyKeyNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_DeleteKeyNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteKeyNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).DeleteKeyNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/delete_key_node",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).DeleteKeyNode(ctx, req.(*DeleteKeyNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetKeyNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetKeyNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetKeyNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_key_node",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetKeyNode(ctx, req.(*GetKeyNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetKeyNodeById_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetKeyNodeByIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetKeyNodeById(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_key_node_by_id",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetKeyNodeById(ctx, req.(*GetKeyNodeByIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetKeyNodeByPath_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetKeyNodeByPathRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetKeyNodeByPath(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_key_node_by_path",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetKeyNodeByPath(ctx, req.(*GetKeyNodeByPathRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetDecryptedKeyNode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDecryptedKeyNodeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetDecryptedKeyNode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_decrypted_key_node",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetDecryptedKeyNode(ctx, req.(*GetDecryptedKeyNodeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MServiceSafebox_GetServerVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetServerVersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MServiceSafeboxServer).GetServerVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/org.gaterace.mservice.safebox.MServiceSafebox/get_server_version",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MServiceSafeboxServer).GetServerVersion(ctx, req.(*GetServerVersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MServiceSafebox_ServiceDesc is the grpc.ServiceDesc for MServiceSafebox service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MServiceSafebox_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "org.gaterace.mservice.safebox.MServiceSafebox",
	HandlerType: (*MServiceSafeboxServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "add_shared_secret",
			Handler:    _MServiceSafebox_AddSharedSecret_Handler,
		},
		{
			MethodName: "clear_shared_secrets",
			Handler:    _MServiceSafebox_ClearSharedSecrets_Handler,
		},
		{
			MethodName: "create_data_key",
			Handler:    _MServiceSafebox_CreateDataKey_Handler,
		},
		{
			MethodName: "delete_data_key",
			Handler:    _MServiceSafebox_DeleteDataKey_Handler,
		},
		{
			MethodName: "get_data_key",
			Handler:    _MServiceSafebox_GetDataKey_Handler,
		},
		{
			MethodName: "get_data_key_by_id",
			Handler:    _MServiceSafebox_GetDataKeyById_Handler,
		},
		{
			MethodName: "get_data_keys_by_account",
			Handler:    _MServiceSafebox_GetDataKeysByAccount_Handler,
		},
		{
			MethodName: "get_decrypted_data_key",
			Handler:    _MServiceSafebox_GetDecryptedDataKey_Handler,
		},
		{
			MethodName: "create_key_node",
			Handler:    _MServiceSafebox_CreateKeyNode_Handler,
		},
		{
			MethodName: "enable_key_node",
			Handler:    _MServiceSafebox_EnableKeyNode_Handler,
		},
		{
			MethodName: "disable_key_node",
			Handler:    _MServiceSafebox_DisableKeyNode_Handler,
		},
		{
			MethodName: "re_encrypt_key_node",
			Handler:    _MServiceSafebox_ReEncryptKeyNode_Handler,
		},
		{
			MethodName: "copy_key_node",
			Handler:    _MServiceSafebox_CopyKeyNode_Handler,
		},
		{
			MethodName: "delete_key_node",
			Handler:    _MServiceSafebox_DeleteKeyNode_Handler,
		},
		{
			MethodName: "get_key_node",
			Handler:    _MServiceSafebox_GetKeyNode_Handler,
		},
		{
			MethodName: "get_key_node_by_id",
			Handler:    _MServiceSafebox_GetKeyNodeById_Handler,
		},
		{
			MethodName: "get_key_node_by_path",
			Handler:    _MServiceSafebox_GetKeyNodeByPath_Handler,
		},
		{
			MethodName: "get_decrypted_key_node",
			Handler:    _MServiceSafebox_GetDecryptedKeyNode_Handler,
		},
		{
			MethodName: "get_server_version",
			Handler:    _MServiceSafebox_GetServerVersion_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "MServiceSafebox.proto",
}
