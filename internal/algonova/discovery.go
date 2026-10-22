package algonova

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// DiscoverOptions mengontrol parameter pencarian tugas kuning (Pending Review).
type DiscoverOptions struct {
	Mode          string // "unreviewed", "schedule", atau "both"
	GroupIDs      []int  // Filter opsional groupId
	OnlyScheduled bool   // Jika true pada mode unreviewed, batasi hanya grup di jadwal aktif
	Timeframe     string // "current", "all", "past"
}

var (
	// Mencocokkan <td ... data-col-seq="group.title"...>...<a href="/group/view/2175084"...>Judul Grup</a>...</td>
	reScheduleGroupCell = regexp.MustCompile(`(?is)<td[^>]*data-col-seq=["']group\.title["'][^>]*>.*?<a[^>]*href=["']/group/view/(\d+)["'][^>]*>(.*?)</a>.*?</td>`)
	reHTMLTags          = regexp.MustCompile(`<[^>]+>`)
)

// Discover mencari seluruh level bertanda kuning (student_success) sesuai opsi yang dipilih (100% Read-Only GET).
func (c *Client) Discover(ctx context.Context, opts DiscoverOptions) ([]YellowLevelItem, error) {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	if mode == "" {
		mode = "unreviewed"
	}
	timeframe := strings.TrimSpace(opts.Timeframe)
	if timeframe == "" {
		timeframe = "current"
	}

	var result []YellowLevelItem
	seen := make(map[string]bool)

	addUnique := func(items []YellowLevelItem) {
		for _, item := range items {
			if !seen[item.Key] {
				seen[item.Key] = true
				result = append(result, item)
			}
		}
	}

	if mode == "unreviewed" || mode == "both" {
		items, err := c.DiscoverViaUnreviewedAPI(ctx, opts.GroupIDs, opts.OnlyScheduled, timeframe)
		if err != nil {
			return nil, fmt.Errorf("discover via unreviewed-list API: %w", err)
		}
		addUnique(items)
	}

	if mode == "schedule" || mode == "both" {
		items, err := c.DiscoverViaScheduleProgress(ctx, opts.GroupIDs, timeframe)
		if err != nil {
			return nil, fmt.Errorf("discover via schedule/progress tab: %w", err)
		}
		addUnique(items)
	}

	return result, nil
}

// FetchScheduledGroups mengambil daftar grup aktif dari halaman SSR /group/default/schedule.
func (c *Client) FetchScheduledGroups(ctx context.Context, timeframe string) ([]ScheduledGroup, error) {
	if timeframe == "" {
		timeframe = "current"
	}

	q := url.Values{}
	q.Set("timeframe", timeframe)
	q.Set("GroupLessonSearch[group.status][]", "active")
	q.Set("per-page", "200")
	q.Set("page", "1")

	path := "/group/default/schedule?" + q.Encode()
	bodyBytes, statusCode, err := c.doRaw(ctx, http.MethodGet, path, nil, "text/html,application/xhtml+xml")
	if err != nil {
		return nil, err
	}
	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("schedule page returned HTTP %d", statusCode)
	}

	return c.parseScheduleHTML(string(bodyBytes)), nil
}

func (c *Client) parseScheduleHTML(rawHTML string) []ScheduledGroup {
	// Fokus pada tabel #schedule-grid jika ada agar tidak tercampur dengan navbar dropdown
	if idx := strings.Index(rawHTML, `id="schedule-grid"`); idx != -1 {
		rawHTML = rawHTML[idx:]
	}

	matches := reScheduleGroupCell.FindAllStringSubmatch(rawHTML, -1)
	seen := make(map[int]bool)
	var groups []ScheduledGroup

	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		gid, err := strconv.Atoi(m[1])
		if err != nil || gid <= 0 || seen[gid] {
			continue
		}
		seen[gid] = true
		cleanTitle := strings.TrimSpace(html.UnescapeString(reHTMLTags.ReplaceAllString(m[2], " ")))
		cleanTitle = strings.Join(strings.Fields(cleanTitle), " ")
		if cleanTitle == "" {
			cleanTitle = fmt.Sprintf("Group #%d", gid)
		}
		c.CacheGroupTitle(gid, cleanTitle)
		groups = append(groups, ScheduledGroup{
			GroupID: gid,
			Title:   cleanTitle,
		})
	}
	return groups
}

// DiscoverViaUnreviewedAPI menggunakan endpoint internal /platform/api/v2/task/unreviewed-list.
func (c *Client) DiscoverViaUnreviewedAPI(ctx context.Context, groupIDs []int, onlyScheduled bool, timeframe string) ([]YellowLevelItem, error) {
	allowedGroups := make(map[int]bool)
	for _, gid := range groupIDs {
		if gid > 0 {
			allowedGroups[gid] = true
		}
	}

	if len(allowedGroups) == 0 && onlyScheduled {
		schedGroups, err := c.FetchScheduledGroups(ctx, timeframe)
		if err != nil {
			return nil, fmt.Errorf("fetch scheduled groups filter: %w", err)
		}
		for _, g := range schedGroups {
			allowedGroups[g.GroupID] = true
		}
	}

	var taskRefs []UnreviewedTaskRef
	lessonTitles := make(map[int]string)

	// Jika hanya 1 groupId yang diminta, langsung tembak query ?groupId=<id> agar super cepat
	if len(groupIDs) == 1 {
		path := fmt.Sprintf("/platform/api/v2/task/unreviewed-list?groupId=%d", groupIDs[0])
		var env APIEnvelope[UnreviewedListData]
		if err := c.doJSON(ctx, http.MethodGet, path, nil, &env); err != nil {
			return nil, err
		}
		for _, g := range env.Data.TitleDictionary.Groups {
			c.CacheGroupTitle(g.ID, g.Title)
		}
		for _, l := range env.Data.TitleDictionary.Lessons {
			lessonTitles[l.ID] = l.Title
		}
		taskRefs = env.Data.Tasks
	} else {
		var env APIEnvelope[UnreviewedListData]
		if err := c.doJSON(ctx, http.MethodGet, "/platform/api/v2/task/unreviewed-list", nil, &env); err != nil {
			return nil, err
		}
		for _, g := range env.Data.TitleDictionary.Groups {
			c.CacheGroupTitle(g.ID, g.Title)
		}
		for _, l := range env.Data.TitleDictionary.Lessons {
			lessonTitles[l.ID] = l.Title
		}
		for _, ref := range env.Data.Tasks {
			if len(allowedGroups) > 0 && !allowedGroups[ref.GroupID] {
				continue
			}
			taskRefs = append(taskRefs, ref)
		}
	}

	var out []YellowLevelItem
	totalRefs := len(taskRefs)
	for i, ref := range taskRefs {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		fmt.Printf("[INSPECT %d/%d] Memeriksa Group=%d | Student=%d | Lesson=%d | Task=%d (UnreviewedCount=%d)...\n",
			i+1, totalRefs, ref.GroupID, ref.StudentID, ref.LessonID, ref.TaskID, ref.LevelUnreviewedCount)
		items, err := c.inspectUnreviewedTask(ctx, ref, lessonTitles[ref.LessonID])
		if err != nil {
			fmt.Printf("[ANOMALY/ERROR] Gagal menginspeksi Task=%d Student=%d Group=%d: %v (dilewati)\n",
				ref.TaskID, ref.StudentID, ref.GroupID, err)
			continue
		}
		if len(items) == 0 {
			fmt.Printf("[ANOMALY/WARN] Task=%d Student=%d Group=%d terdaftar di unreviewed-list (count=%d), namun tidak ditemukan level berstatus 'student_success'.\n",
				ref.TaskID, ref.StudentID, ref.GroupID, ref.LevelUnreviewedCount)
		}
		out = append(out, items...)
	}
	return out, nil
}

func (c *Client) inspectUnreviewedTask(ctx context.Context, ref UnreviewedTaskRef, lessonTitle string) ([]YellowLevelItem, error) {
	track := ref.Track
	if track <= 0 {
		track = 1
	}

	q := url.Values{}
	q.Set("lessonId", strconv.Itoa(ref.LessonID))
	q.Set("studentId", strconv.Itoa(ref.StudentID))
	q.Set("groupId", strconv.Itoa(ref.GroupID))
	q.Set("track", strconv.Itoa(track))
	q.Set("expand", "levels,kahoot,openLevels")

	taskViewPath := fmt.Sprintf("/platform/api/v2/task/view/%d?%s", ref.TaskID, q.Encode())
	var tvEnv APIEnvelope[TaskViewData]
	if err := c.doJSON(ctx, http.MethodGet, taskViewPath, nil, &tvEnv); err != nil {
		return nil, fmt.Errorf("getTaskView(task=%d, student=%d): %w", ref.TaskID, ref.StudentID, err)
	}
	tv := tvEnv.Data

	var items []YellowLevelItem
	for idx, lvl := range tv.Levels {
		lvlKey := strconv.Itoa(lvl.ID)
		openState, exists := tv.OpenLevels[lvlKey]
		if !exists || openState.Status != "student_success" {
			continue
		}

		// Ambil daftar basic hints (objektif yang harus diceklis guru)
		basicHints := filterBasicHints(lvl.Config.Hints)
		if len(basicHints) == 0 {
			// Fallback ke /platform/api/v1/level/{levelId} jika belum termuat di config
			var ldEnv APIEnvelope[LevelDetailData]
			if err := c.doJSON(ctx, http.MethodGet, fmt.Sprintf("/platform/api/v1/level/%d", lvl.ID), nil, &ldEnv); err == nil {
				basicHints = filterBasicHints(ldEnv.Data.Hints)
			}
		}

		objectives := c.fetchLevelObjectivesState(ctx, lvl.ID, ref.StudentID, basicHints)

		// Cek apakah level berikutnya dalam task ini perlu dibuka saat level ini lulus
		shouldOpenNext := false
		nextPos := 0
		if idx+1 < len(tv.Levels) {
			nextLvl := tv.Levels[idx+1]
			nextKey := strconv.Itoa(nextLvl.ID)
			if _, nextOpen := tv.OpenLevels[nextKey]; !nextOpen {
				shouldOpenNext = true
				nextPos = nextLvl.Position
			}
		}

		previewURL := fmt.Sprintf("%s/task-preview/%d?levelId=%d&task=%d&lesson=%d&level=%d&student=%d&track=%d&groupId=%d",
			c.cfg.BaseURL, ref.TaskID, lvl.ID, ref.TaskID, ref.LessonID, lvl.Position, ref.StudentID, track, ref.GroupID)
		groupURL := fmt.Sprintf("%s/group/view/%d#group-progress-tab", c.cfg.BaseURL, ref.GroupID)

		items = append(items, YellowLevelItem{
			Key:                 MakeKey(ref.GroupID, ref.StudentID, ref.LessonID, ref.TaskID, lvl.ID),
			Source:              "unreviewed-api",
			GroupID:             ref.GroupID,
			GroupTitle:          c.GetCachedGroupTitle(ref.GroupID),
			GroupProgressURL:    groupURL,
			LessonID:            ref.LessonID,
			LessonTitle:         lessonTitle,
			StudentID:           ref.StudentID,
			StudentName:         c.GetStudentName(ctx, ref.GroupID, ref.StudentID),
			TaskID:              ref.TaskID,
			TaskTitle:           tv.Title,
			Track:               track,
			LevelID:             lvl.ID,
			LevelPosition:       lvl.Position,
			LevelTitle:          lvl.Title,
			LevelMechanic:       lvl.Type,
			Status:              openState.Status,
			Attempts:            openState.Attempts,
			TaskPreviewURL:      previewURL,
			Objectives:          objectives,
			ShouldOpenNextLevel: shouldOpenNext,
			NextLevelPosition:   nextPos,
		})
	}

	if len(items) == 0 {
		var statuses []string
		for k, st := range tv.OpenLevels {
			statuses = append(statuses, fmt.Sprintf("lvl[%s]=%s", k, st.Status))
		}
		fmt.Printf("   -> Detail OpenLevels pada Task %d: %v\n", ref.TaskID, statuses)
	}

	return items, nil
}

func filterBasicHints(hints []LevelHint) []LevelHint {
	var out []LevelHint
	for _, h := range hints {
		if h.TaskType == "" || h.TaskType == "basic" {
			out = append(out, h)
		}
	}
	return out
}

func (c *Client) fetchLevelObjectivesState(ctx context.Context, levelID, studentID int, basicHints []LevelHint) []ObjectiveItem {
	if len(basicHints) == 0 {
		return nil
	}

	studentChecked := make(map[string]bool)
	var stuEnv APIEnvelope[StudentObjectivesData]
	stuPath := fmt.Sprintf("/platform/api/v1/student-objectives/view?levelId=%d&studentId=%d", levelID, studentID)
	if err := c.doJSON(ctx, http.MethodGet, stuPath, nil, &stuEnv); err == nil {
		for _, obj := range stuEnv.Data.Objectives {
			studentChecked[obj.HintID] = true
		}
	}

	teacherStatusMap := make(map[string]string)
	var tchEnv APIEnvelope[TeacherStepsData]
	tchPath := fmt.Sprintf("/platform/api/v1/teacherComment/steps?level=%d&student=%d", levelID, studentID)
	if err := c.doJSON(ctx, http.MethodGet, tchPath, nil, &tchEnv); err == nil {
		for _, st := range tchEnv.Data.Steps {
			teacherStatusMap[st.HintID] = st.Status
		}
	}

	var out []ObjectiveItem
	for _, h := range basicHints {
		stuStatus := "unchecked"
		if studentChecked[h.ID] {
			stuStatus = "checked"
		}
		tchStatus := "unchecked"
		if st, ok := teacherStatusMap[h.ID]; ok && st != "" && st != "unmarked" {
			tchStatus = st
		}
		title := strings.TrimSpace(h.Title)
		if title == "" {
			title = strings.TrimSpace(h.Text)
		}
		out = append(out, ObjectiveItem{
			HintID:        h.ID,
			Title:         title,
			StudentStatus: stuStatus,
			TeacherStatus: tchStatus,
		})
	}
	return out
}

// DiscoverViaScheduleProgress menelusuri Schedule -> Group -> Progress Tab -> Lesson View.
func (c *Client) DiscoverViaScheduleProgress(ctx context.Context, groupIDs []int, timeframe string) ([]YellowLevelItem, error) {
	targetGroups := groupIDs
	if len(targetGroups) == 0 {
		schedGroups, err := c.FetchScheduledGroups(ctx, timeframe)
		if err != nil {
			return nil, err
		}
		for _, g := range schedGroups {
			targetGroups = append(targetGroups, g.GroupID)
		}
	}

	var out []YellowLevelItem
	for _, gid := range targetGroups {
		items, err := c.discoverGroupProgress(ctx, gid)
		if err != nil {
			return nil, fmt.Errorf("group %d progress discovery: %w", gid, err)
		}
		out = append(out, items...)
	}
	return out, nil
}

func (c *Client) discoverGroupProgress(ctx context.Context, groupID int) ([]YellowLevelItem, error) {
	indexPath := fmt.Sprintf("/api/v2/group/lesson/index?groupId=%d&status=active&expand=module&perPage=500", groupID)
	var idxEnv APIEnvelope[GroupLessonIndexData]
	if err := c.doJSON(ctx, http.MethodGet, indexPath, nil, &idxEnv); err != nil {
		return nil, err
	}

	var out []YellowLevelItem
	for _, lessonItem := range idxEnv.Data.Items {
		// Status 10 = Lesson Opened; lewati lesson yang belum dibuka (status 0) atau belum ada skor sama sekali
		if lessonItem.Status != 10 || lessonItem.RegularTaskScoreSumPercent == nil {
			continue
		}

		viewPath := fmt.Sprintf("/api/v2/group/lesson/view/%d?expand=levels%%2Cprogress", lessonItem.ID)
		var viewEnv APIEnvelope[GroupLessonViewData]
		if err := c.doJSON(ctx, http.MethodGet, viewPath, nil, &viewEnv); err != nil {
			return nil, err
		}
		lv := viewEnv.Data

		for _, stuRow := range lv.Progress {
			for _, taskProg := range stuRow.Progress {
				track := taskProg.Track
				if track <= 0 {
					track = 1
				}
				for idx, lvl := range taskProg.Levels {
					if lvl.Status != "student_success" {
						continue
					}

					var objectives []ObjectiveItem
					for _, obj := range lvl.Objectives {
						objectives = append(objectives, ObjectiveItem{
							HintID:        obj.ID,
							Title:         strings.TrimSpace(obj.Text),
							StudentStatus: obj.StudentStatus,
							TeacherStatus: obj.TeacherStatus,
						})
					}

					shouldOpenNext := false
					nextPos := 0
					if idx+1 < len(taskProg.Levels) {
						nextLvl := taskProg.Levels[idx+1]
						if nextLvl.Status == "closed" {
							shouldOpenNext = true
							nextPos = nextLvl.Position
						}
					}

					previewURL := fmt.Sprintf("%s/task-preview/%d?levelId=%d&task=%d&lesson=%d&level=%d&student=%d&track=%d&groupId=%d",
						c.cfg.BaseURL, taskProg.ID, lvl.ID, taskProg.ID, lv.LessonID, lvl.Position, stuRow.StudentID, track, groupID)
					if lvl.URL != nil && *lvl.URL != "" {
						if strings.HasPrefix(*lvl.URL, "http") {
							previewURL = *lvl.URL
						} else {
							previewURL = c.cfg.BaseURL + *lvl.URL
						}
					}
					groupURL := fmt.Sprintf("%s/group/view/%d?progressLessonId=%d#group-progress-tab", c.cfg.BaseURL, groupID, lv.ID)

					out = append(out, YellowLevelItem{
						Key:                 MakeKey(groupID, stuRow.StudentID, lv.LessonID, taskProg.ID, lvl.ID),
						Source:              "schedule-progress",
						GroupID:             groupID,
						GroupTitle:          c.GetCachedGroupTitle(groupID),
						GroupProgressURL:    groupURL,
						ProgressLessonID:    lv.ID,
						LessonID:            lv.LessonID,
						LessonTitle:         lv.Title,
						StudentID:           stuRow.StudentID,
						StudentName:         c.GetStudentName(ctx, groupID, stuRow.StudentID),
						TaskID:              taskProg.ID,
						TaskTitle:           taskProg.Name,
						Track:               track,
						LevelID:             lvl.ID,
						LevelPosition:       lvl.Position,
						LevelTitle:          lvl.Name,
						LevelMechanic:       lvl.Mechanic,
						Status:              lvl.Status,
						Attempts:            0,
						TaskPreviewURL:      previewURL,
						Objectives:          objectives,
						ShouldOpenNextLevel: shouldOpenNext,
						NextLevelPosition:   nextPos,
					})
				}
			}
		}
	}

	return out, nil
}
