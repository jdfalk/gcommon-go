// file: internal/go.mod
// version: 1.0.0
// guid: d2e3f4a5-b6c7-8d9e-0f1a-2b3c4d5e6f7a

module github.com/jdfalk/gcommon/internal

go 1.24

require (
	google.golang.org/grpc v1.65.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240827150818-7e3bb234dfed // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

// Use local version of gcommon
replace github.com/jdfalk/gcommon => ../
