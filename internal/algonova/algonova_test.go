package algonova

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"auto-checker/internal/config"
)

func TestOpenLevelsMapUnmarshal(t *testing.T) {
	var m1 OpenLevelsMap
	if err := json.Unmarshal([]byte(`[]`), &m1); err != nil {
		t.Fatalf("unexpected error for []: %v", err)
	}
	if len(m1) != 0 {
		t.Fatalf("expected empty map for [], got %d items", len(m1))
	}

	raw := `{"1488258":{"status":"student_success","attempts":0,"isPassed":true,"modified":"2026-10-18 10:22:46"}}`
	var m2 OpenLevelsMap
	if err := json.Unmarshal([]byte(raw), &m2); err != nil {
		t.Fatalf("unexpected error for valid object: %v", err)
	}
	st, ok := m2["1488258"]
	if !ok || st.Status != "student_success" {
		t.Fatalf("expected status student_success, got %+v", st)
	}
}

func TestParseScheduleHTML(t *testing.T) {
	cfg := &config.Config{BaseURL: "https://lms.algonova.id"}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient error: %v", err)
	}

	sampleHTML := `
	<div class="closest-lesson__dropdown">
		<a href="/group/view/9999999">Navbar Ignored Group</a>
	</div>
	<div id="schedule-grid">
		<table class="kv-grid-table">
			<tbody>
				<tr class="schedule-grid" data-key="1">
					<td data-col-seq="group.title"><a href="/group/view/2175084" data-pjax="0">IND-PP2-17-SUN-13.00 {PREM}</a></td>
				</tr>
				<tr class="schedule-grid" data-key="2">
					<td data-col-seq="group.title"><a href="/group/view/2175084" data-pjax="0">IND-PP2-17-SUN-13.00 {PREM}</a></td>
				</tr>
				<tr class="schedule-grid" data-key="3">
					<td data-col-seq="group.title"><a href="/group/view/2184933" data-pjax="0">IND 1-1 VP 1311 (MON 18.00)</a></td>
				</tr>
			</tbody>
		</table>
	</div>`

	groups := client.parseScheduleHTML(sampleHTML)
	if len(groups) != 2 {
		t.Fatalf("expected 2 deduplicated groups from #schedule-grid, got %d: %+v", len(groups), groups)
	}
	if groups[0].GroupID != 2175084 || groups[0].Title != "IND-PP2-17-SUN-13.00 {PREM}" {
		t.Errorf("unexpected group[0]: %+v", groups[0])
	}
	if groups[1].GroupID != 2184933 {
		t.Errorf("unexpected group[1]: %+v", groups[1])
	}
}

func TestCheckLevelTwoStepFlow(t *testing.T) {
	var stepCalls []TeacherCommentStepPayload
	var multiCalls []ChangeMultiStatusPayload

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/platform/api/v1/teacherComment/step":
			var p TeacherCommentStepPayload
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Fatalf("decode step payload: %v", err)
			}
			stepCalls = append(stepCalls, p)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		case "/platform/api/v2/level/change-multi-status":
			var p ChangeMultiStatusPayload
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Fatalf("decode multi-status payload: %v", err)
			}
			multiCalls = append(multiCalls, p)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := &config.Config{BaseURL: ts.URL, MaxRetries: 3}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	item := YellowLevelItem{
		Key:           MakeKey(2175084, 100125754, 33163, 78507, 1488258),
		GroupID:       2175084,
		StudentID:     100125754,
		LessonID:      33163,
		TaskID:        78507,
		LevelID:       1488258,
		LevelPosition: 1,
		Status:        "student_success",
		Objectives: []ObjectiveItem{
			{HintID: "hint-1", Title: "Q1", StudentStatus: "checked", TeacherStatus: "unchecked"},
			{HintID: "hint-2", Title: "Q2", StudentStatus: "checked", TeacherStatus: "success"},
			{HintID: "hint-3", Title: "Q3", StudentStatus: "checked", TeacherStatus: "unchecked"},
		},
	}

	resDry := client.CheckLevel(context.Background(), item, true)
	if !resDry.Success || !resDry.DryRun || resDry.ObjectivesChecked != 2 {
		t.Fatalf("unexpected dry-run result: %+v", resDry)
	}
	if len(stepCalls) != 0 || len(multiCalls) != 0 {
		t.Fatalf("expected 0 HTTP calls during dry-run, got %d stepCalls and %d multiCalls", len(stepCalls), len(multiCalls))
	}

	resExec := client.CheckLevel(context.Background(), item, false)
	if !resExec.Success || resExec.DryRun || resExec.ObjectivesChecked != 2 || !resExec.LevelStatusUpdated {
		t.Fatalf("unexpected execute result: %+v", resExec)
	}
	if len(stepCalls) != 2 {
		t.Fatalf("expected 2 teacherComment/step calls (skipping already-success hint-2), got %d", len(stepCalls))
	}
	if stepCalls[0].HintID != "hint-1" || stepCalls[1].HintID != "hint-3" {
		t.Errorf("unexpected hint IDs called: %+v", stepCalls)
	}
	if len(multiCalls) != 1 || len(multiCalls[0].Levels) != 1 || multiCalls[0].Levels[0].Status != "complete" {
		t.Errorf("unexpected change-multi-status payload: %+v", multiCalls)
	}
}

func TestRateLimitRetryRecovery(t *testing.T) {
	var attempts atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		// Simulasikan terkena HTTP 429 Too Many Requests pada percobaan ke-1 dan ke-2
		if n <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"status":"error","message":"Too many attempts"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":[]}`))
	}))
	defer ts.Close()

	cfg := &config.Config{BaseURL: ts.URL, MaxRetries: 4}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.BaseBackoff = 10 * time.Millisecond

	item := YellowLevelItem{
		Key:           MakeKey(2175084, 100125754, 33163, 78507, 1488258),
		GroupID:       2175084,
		StudentID:     100125754,
		LessonID:      33163,
		TaskID:        78507,
		LevelID:       1488258,
		LevelPosition: 1,
		Status:        "student_success",
		Objectives: []ObjectiveItem{
			{HintID: "hint-1", Title: "Q1", StudentStatus: "checked", TeacherStatus: "unchecked"},
		},
	}

	res := client.CheckLevel(context.Background(), item, false)
	if !res.Success || !res.LevelStatusUpdated || res.ObjectivesChecked != 1 {
		t.Fatalf("expected recovery after 429 retries, got: %+v", res)
	}
	if attempts.Load() != 4 {
		t.Fatalf("expected 4 total HTTP attempts (2x 429 + 1x step OK + 1x multi-status OK), got %d", attempts.Load())
	}
}
