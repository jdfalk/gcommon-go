// file: pkg/configpb/go.mod
// version: 1.0.1
// guid: go-mod-configpb-v1

// Deprecated: This module is deprecated. Use github.com/jdfalk/gcommon/pkg/configpb/v2 instead.
// The v2 module provides enhanced functionality, additional methods, and improved protobuf definitions.
module github.com/jdfalk/gcommon/pkg/configpb

go 1.24.0

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.9-20250912141014-52f32327d4b0.1
	github.com/jdfalk/gcommon/pkg/commonpb v0.0.0-20250928005643-ef1428df82d7
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.9
)

require (
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250922171735-9219d122eba9 // indirect
)
