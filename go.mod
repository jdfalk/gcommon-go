module github.com/jdfalk/gcommon

go 1.24

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.9-20250912141014-52f32327d4b0.1
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.36.9
)

replace (
	github.com/jdfalk/gcommon/pkg/common/v1 => ./pkg/common/v1
	github.com/jdfalk/gcommon/pkg/config/v1 => ./pkg/config/v1
	github.com/jdfalk/gcommon/pkg/database/v1 => ./pkg/database/v1
	github.com/jdfalk/gcommon/pkg/health/v1 => ./pkg/health/v1
	github.com/jdfalk/gcommon/pkg/media/v1 => ./pkg/media/v1
	github.com/jdfalk/gcommon/pkg/metrics/v1 => ./pkg/metrics/v1
	github.com/jdfalk/gcommon/pkg/organization/v1 => ./pkg/organization/v1
	github.com/jdfalk/gcommon/pkg/queue/v1 => ./pkg/queue/v1
	github.com/jdfalk/gcommon/pkg/web/v1 => ./pkg/web/v1
)
