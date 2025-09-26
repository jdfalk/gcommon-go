module github.com/jdfalk/gcommon

go 1.24

replace (
	github.com/jdfalk/gcommon/pkg/common/ => ./pkg/common/v1
	github.com/jdfalk/gcommon/pkg/config/ => ./pkg/config/v1
	github.com/jdfalk/gcommon/pkg/database/ => ./pkg/database/v1
	github.com/jdfalk/gcommon/pkg/health/ => ./pkg/health/v1
	github.com/jdfalk/gcommon/pkg/media/ => ./pkg/media/v1
	github.com/jdfalk/gcommon/pkg/metrics/ => ./pkg/metrics/v1
	github.com/jdfalk/gcommon/pkg/organization/ => ./pkg/organization/v1
	github.com/jdfalk/gcommon/pkg/queue/ => ./pkg/queue/v1
	github.com/jdfalk/gcommon/pkg/web/ => ./pkg/web/v1
)
