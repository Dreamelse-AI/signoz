package clickhousetelemetrystore

import (
	"context"
	"strings"
	"testing"

	"github.com/SigNoz/signoz/pkg/telemetrystore"
	"github.com/SigNoz/signoz/pkg/types/ctxtypes"
)

func TestBoundInlineSettings(t *testing.T) {
	caps := map[string]int64{"max_memory_usage": 1024, "max_rows_to_read": 100, "max_bytes_to_read": 2048, "max_execution_time": 30}
	for _, tc := range []struct {
		name, sql, want string
		fail            bool
	}{
		{"plain", "SELECT sum(number) FROM numbers(10)", "SELECT sum(number) FROM numbers(10)", false},
		{"clamp", "SELECT 1 SETTINGS max_memory_usage=10000000000", "SELECT 1 SETTINGS max_memory_usage=1024", false},
		{"lower", "SELECT 1 SETTINGS max_memory_usage=512,max_execution_time=1", "SELECT 1 SETTINGS max_memory_usage=512,max_execution_time=1", false},
		{"zero", "SELECT 1 SETTINGS max_rows_to_read=0, max_bytes_to_read=0", "SELECT 1 SETTINGS max_rows_to_read=100, max_bytes_to_read=2048", false},
		{"string", "SELECT 1 SETTINGS max_memory_usage='999999'", "SELECT 1 SETTINGS max_memory_usage=1024", false},
		{"overflow", "SELECT 1 SETTINGS read_overflow_mode='break', timeout_overflow_mode='break'", "SELECT 1 SETTINGS read_overflow_mode='throw', timeout_overflow_mode='throw'", false},
		{"nested", "SELECT * FROM (SELECT 1 SETTINGS max_memory_usage=9999) SETTINGS max_memory_usage=0", "SELECT * FROM (SELECT 1 SETTINGS max_memory_usage=1024) SETTINGS max_memory_usage=1024", false},
		{"unicode", "SELECT '中文 SETTINGS max_memory_usage=9999' SETTINGS max_execution_time=0", "SELECT '中文 SETTINGS max_memory_usage=9999' SETTINGS max_execution_time=30", false},
		{"quoted", "SELECT 1 SETTINGS `max_memory_usage`=9999", "SELECT 1 SETTINGS `max_memory_usage`=1024", false},
		{"predicate", "SELECT * FROM t WHERE max_memory_usage=99999", "SELECT * FROM t WHERE max_memory_usage=99999", false},
		{"unrelated", "SELECT 1 SETTINGS max_threads=1", "SELECT 1 SETTINGS max_threads=1", false},
		{"expression", "SELECT 1 SETTINGS max_memory_usage=toUInt64(9999)", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := boundInlineSettings(tc.sql, caps)
			if (err != nil) != tc.fail {
				t.Fatalf("error = %v", err)
			}
			if !tc.fail && got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInteractiveScope(t *testing.T) {
	limits := telemetrystore.InteractiveLimits{MaxRowsToRead: 100, MaxBytesToRead: 2048, MaxMemoryUsage: 1024, MaxExecutionTime: 30}
	for _, fn := range []string{"", "Evaluate", "QueryRangePreview", "QueryRange"} {
		ctx := ctxtypes.NewContextWithCommentVals(context.Background(), map[string]string{"code.function": fn})
		next, sql, err := applyInteractiveLimits(ctx, "SELECT 1 SETTINGS max_memory_usage=9999", limits)
		if err != nil {
			t.Fatal(err)
		}
		if fn == "QueryRange" {
			if !strings.Contains(sql, "max_memory_usage=1024") || ctxtypes.CommentFromContext(next).Map()["query_limits"] != "interactive_v1" {
				t.Fatal("interactive limits missing")
			}
		} else if sql != "SELECT 1 SETTINGS max_memory_usage=9999" || next != ctx {
			t.Fatalf("background context %q was changed", fn)
		}
	}
	ctx := ctxtypes.NewContextWithCommentVals(context.Background(), map[string]string{"code.function": "QueryRange"})
	next, sql, err := applyInteractiveLimits(ctx, "SELECT 1 SETTINGS max_memory_usage=9999", telemetrystore.InteractiveLimits{})
	if err != nil || next != ctx || sql != "SELECT 1 SETTINGS max_memory_usage=9999" {
		t.Fatal("disabled limits changed a query")
	}
}
