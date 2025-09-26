module github.com/jdfalk/gcommon

go 1.24

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.9-20250912141014-52f32327d4b0.1
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.36.9
)

replace (
	github.com/jdfalk/gcommon/pkg/common/v2 => ./pkg/common/v2
	github.com/jdfalk/gcommon/pkg/config/v2 => ./pkg/config/v2
	github.com/jdfalk/gcommon/pkg/database/v2 => ./pkg/database/v2
	github.com/jdfalk/gcommon/pkg/health/v2 => ./pkg/health/v2
	github.com/jdfalk/gcommon/pkg/media/v2 => ./pkg/media/v2
	github.com/jdfalk/gcommon/pkg/metrics/v2 => ./pkg/metrics/v2
	github.com/jdfalk/gcommon/pkg/organization/v2 => ./pkg/organization/v2
	github.com/jdfalk/gcommon/pkg/queue/v2 => ./pkg/queue/v2
	github.com/jdfalk/gcommon/pkg/web/v2 => ./pkg/web/v2
)
