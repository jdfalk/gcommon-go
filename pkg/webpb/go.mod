// file: pkg/webpb/go.mod
// version: 1.0.0
// guid: go-mod-webpb-v1

module github.com/jdfalk/gcommon/pkg/webpb

go 1.24

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.9-20250912141014-52f32327d4b0.1
	github.com/jdfalk/gcommon/pkg/commonpb v0.0.0-20250927024843-4db368d2913f
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.36.9
)

require (
	golang.org/x/net v0.25.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/text v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240528184218-531527333157 // indirect
)
