package clickhousetelemetrystore

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	chparser "github.com/AfterShip/clickhouse-sql-parser/parser"
	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/telemetrystore"
	"github.com/SigNoz/signoz/pkg/types/ctxtypes"
)

// The handler sets this comment in trusted request context after authentication.
// Background alert evaluation, migrations and ingestion do not enter this path.
func applyInteractiveLimits(ctx context.Context, sql string, limits telemetrystore.InteractiveLimits) (context.Context, string, error) {
	if limits == (telemetrystore.InteractiveLimits{}) || ctxtypes.CommentFromContext(ctx).Map()["code.function"] != "QueryRange" {
		return ctx, sql, nil
	}
	caps := map[string]int64{
		"max_rows_to_read":   limits.MaxRowsToRead,
		"max_bytes_to_read":  limits.MaxBytesToRead,
		"max_memory_usage":   limits.MaxMemoryUsage,
		"max_execution_time": limits.MaxExecutionTime,
	}
	bounded, err := boundInlineSettings(sql, caps)
	if err != nil {
		return ctx, sql, errors.NewInvalidInputf(errors.CodeInvalidInput, "cannot enforce interactive query limits: %s", err)
	}
	settings := clickhouse.Settings{"read_overflow_mode": "throw", "timeout_overflow_mode": "throw"}
	for key, value := range caps {
		settings[key] = value
	}
	ctx = ctxtypes.NewContextWithCommentVals(ctx, map[string]string{"query_limits": "interactive_v1"})
	settings["log_comment"] = ctxtypes.CommentFromContext(ctx).String()
	return interactiveDeadlineContext{clickhouse.Context(ctx, clickhouse.WithSettings(settings))}, bounded, nil
}

// The ClickHouse driver overwrites max_execution_time with Deadline()+5s,
// even when a stricter setting is supplied. Keep cancellation and context
// values, but let the explicit server limit control execution time.
type interactiveDeadlineContext struct{ context.Context }

func (interactiveDeadlineContext) Deadline() (time.Time, bool) { return time.Time{}, false }

type settingEdit struct {
	start, end int
	value      string
}
type limitVisitor struct {
	chparser.DefaultASTVisitor
	caps  map[string]int64
	edits []settingEdit
}

func (v *limitVisitor) VisitSettingsExpr(expr *chparser.SettingExpr) error {
	name := strings.ToLower(expr.Name.Name)
	start, end := int(expr.Expr.Pos()), int(expr.Expr.End())
	if _, ok := expr.Expr.(*chparser.StringLiteral); ok {
		// Parser string positions exclude the surrounding quote characters.
		start--
		end++
	}
	if name == "read_overflow_mode" || name == "timeout_overflow_mode" {
		v.edits = append(v.edits, settingEdit{start, end, "'throw'"})
		return nil
	}
	cap, protected := v.caps[name]
	if !protected {
		return nil
	}
	var text string
	switch value := expr.Expr.(type) {
	case *chparser.NumberLiteral:
		text = value.Literal
	case *chparser.StringLiteral:
		text = value.Literal
	default:
		return fmt.Errorf("%s must have a numeric literal value", name)
	}
	n, ok := new(big.Rat).SetString(text)
	if !ok || n.Sign() < 0 {
		return fmt.Errorf("%s must have a nonnegative numeric literal value", name)
	}
	if n.Sign() == 0 || n.Cmp(new(big.Rat).SetInt64(cap)) > 0 {
		v.edits = append(v.edits, settingEdit{start, end, strconv.FormatInt(cap, 10)})
	}
	return nil
}

func boundInlineSettings(sql string, caps map[string]int64) (string, error) {
	lower := strings.ToLower(sql)
	// Most queries need no SQL parsing. The driver carries the defaults.
	if !strings.Contains(lower, "settings") {
		return sql, nil
	}
	protected := strings.Contains(lower, "read_overflow_mode") || strings.Contains(lower, "timeout_overflow_mode")
	for name := range caps {
		protected = protected || strings.Contains(lower, name)
	}
	if !protected {
		return sql, nil
	}
	stmts, err := chparser.NewParser(sql).ParseStmts()
	if err != nil {
		return "", fmt.Errorf("SQL containing protected SETTINGS could not be parsed")
	}
	visitor := &limitVisitor{caps: caps}
	for _, stmt := range stmts {
		if err := stmt.Accept(visitor); err != nil {
			return "", err
		}
	}
	sort.Slice(visitor.edits, func(i, j int) bool { return visitor.edits[i].start > visitor.edits[j].start })
	for _, edit := range visitor.edits {
		if edit.start < 0 || edit.end > len(sql) || edit.start > edit.end {
			return "", fmt.Errorf("invalid SETTINGS source position")
		}
		sql = sql[:edit.start] + edit.value + sql[edit.end:]
	}
	return sql, nil
}
