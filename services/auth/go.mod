// file: services/auth/go.mod
// version: 1.0.0
// guid: h3i4j5k6-l7m8-n9o0-p1q2-r3s4t5u6v7w8

module github.com/jdfalk/gcommon/services/auth

go 1.24.0

require (
	github.com/golang-jwt/jwt/v5 v5.3.0
	github.com/jdfalk/gcommon/pkg/authpb/v2 v2.0.0-20250928003915-5beec7aae2e9
	github.com/spf13/cobra v1.10.1
	github.com/spf13/viper v1.21.0
	google.golang.org/grpc v1.75.1
)

require (
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250922171735-9219d122eba9 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)

replace github.com/jdfalk/gcommon/pkg/authpb => ../../pkg/authpb

replace github.com/jdfalk/gcommon/pkg/authpb/v2 => ../../pkg/authpb/v2
