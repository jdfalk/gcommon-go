module github.com/jdfalk/gcommon

go 1.24.0

// Replace directives for local sub-modules
replace github.com/jdfalk/gcommon/internal => ./internal

replace github.com/jdfalk/gcommon/services => ./services

replace github.com/jdfalk/gcommon/services/health => ./services/health

replace github.com/jdfalk/gcommon/services/auth => ./services/auth

replace github.com/jdfalk/gcommon/pkg/authpb/v2 => ./pkg/authpb/v2

require (
	github.com/jdfalk/gcommon/internal v0.0.0-20250928010352-7f201c29494c
	google.golang.org/grpc v1.75.1
)

require (
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251002232023-7c0ddcbb5797 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
