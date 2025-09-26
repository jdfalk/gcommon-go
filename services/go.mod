// file: services/go.mod
// version: 1.0.0
// guid: e3f4a5b6-c7d8-9e0f-1a2b-3c4d5e6f7a8b

module github.com/jdfalk/gcommon/services

go 1.24

// Use local versions
replace github.com/jdfalk/gcommon => ../

replace github.com/jdfalk/gcommon/internal => ../internal/

require (
	github.com/jdfalk/gcommon/pkg/commonpb v0.0.0-20250926164202-48e80cd3f3d1
	github.com/jdfalk/gcommon/pkg/healthpb v0.0.0-20250926191523-27df7a7ed049
	google.golang.org/grpc v1.75.1
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.9-20250912141014-52f32327d4b0.1 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
)
