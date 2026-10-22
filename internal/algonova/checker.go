package algonova

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"
)

// CheckLevel mengeksekusi (atau menyimulasikan jika dryRun=true) proses checklist guru pada 1 YellowLevelItem.
func (c *Client) CheckLevel(ctx context.Context, item YellowLevelItem, dryRun bool) CheckResult {
	res := CheckResult{
		Item:      item,
		DryRun:    dryRun,
		CheckedAt: time.Now(),
	}

	pendingObjectives := 0
	for _, obj := range item.Objectives {
		if obj.TeacherStatus != "success" {
			pendingObjectives++
		}
	}

	if dryRun {
		res.ObjectivesChecked = pendingObjectives
		res.LevelStatusUpdated = true
		res.Success = true
		return res
	}

	// Tahap 1: Kirim POST /platform/api/v1/teacherComment/step untuk setiap objektif yang belum berstatus "success"
	checkedCount := 0
	for _, obj := range item.Objectives {
		if obj.TeacherStatus == "success" {
			continue
		}
		payload := TeacherCommentStepPayload{
			HintID:  obj.HintID,
			Level:   item.LevelID,
			Status:  "success",
			Student: item.StudentID,
		}
		if err := c.doJSON(ctx, http.MethodPost, "/platform/api/v1/teacherComment/step", payload, nil); err != nil {
			res.ObjectivesChecked = checkedCount
			res.Error = fmt.Sprintf("failed checking objective %s: %v", obj.HintID, err)
			return res
		}
		checkedCount++
	}
	res.ObjectivesChecked = checkedCount

	// Tahap 2: Kirim POST /platform/api/v2/level/change-multi-status untuk mengubah status kuning -> hijau (complete)
	levelsPayload := []ChangeLevelEntry{
		{
			Attempts:  item.Attempts,
			IsPassed:  true,
			LessonID:  item.LessonID,
			Position:  item.LevelPosition,
			Status:    "complete",
			TaskID:    item.TaskID,
			StudentID: item.StudentID,
		},
	}

	if item.ShouldOpenNextLevel && item.NextLevelPosition > 0 {
		levelsPayload = append(levelsPayload, ChangeLevelEntry{
			LessonID: item.LessonID,
			Position: item.NextLevelPosition,
			Status:   "open",
			TaskID:   item.TaskID,
		})
	}

	multiStatusPath := fmt.Sprintf("/platform/api/v2/level/change-multi-status?groupId=%d&studentId=%d", item.GroupID, item.StudentID)
	multiBody := ChangeMultiStatusPayload{
		Levels:    levelsPayload,
		StudentID: item.StudentID,
	}

	if err := c.doJSON(ctx, http.MethodPost, multiStatusPath, multiBody, nil); err != nil {
		res.Error = fmt.Sprintf("failed updating level status to complete: %v", err)
		return res
	}

	res.LevelStatusUpdated = true
	res.Success = true
	return res
}

// CheckBatch memproses sejumlah YellowLevelItem secara berurutan dengan jeda antar-level (LevelDelay + jitter).
func (c *Client) CheckBatch(ctx context.Context, items []YellowLevelItem, dryRun bool, onProgress func(idx, total int, res CheckResult)) []CheckResult {
	results := make([]CheckResult, 0, len(items))
	total := len(items)
	for i, item := range items {
		if ctx.Err() != nil {
			break
		}
		r := c.CheckLevel(ctx, item, dryRun)
		results = append(results, r)
		if onProgress != nil {
			onProgress(i+1, total, r)
		}

		// Jika masih ada level berikutnya dan bukan dry-run, berikan jeda antar-level (LevelDelay + random jitter)
		if !dryRun && i+1 < total && c.cfg.LevelDelay > 0 {
			wait := c.cfg.LevelDelay
			jitterMax := int64(wait) * 40 / 100
			if jitterMax > 0 {
				wait += time.Duration(rand.Int64N(jitterMax))
			}
			_ = sleepContext(ctx, wait)
		}
	}
	return results
}
