package algonova

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// APIEnvelope membungkus format standar response JSON Algonova: {"status":"success","data":...}
type APIEnvelope[T any] struct {
	Status  string `json:"status"`
	Data    T      `json:"data"`
	Message string `json:"message,omitempty"`
}

// AuthResponse memetakan response dari POST /s/auth/api/e/user/auth
type AuthResponse struct {
	Item struct {
		Step string `json:"step"`
	} `json:"item"`
}

// UnreviewedCountData memetakan GET /api/v2/teacher-dashboard/task/unreviewed
type UnreviewedCountData struct {
	Count int `json:"count"`
}

// UnreviewedListData memetakan GET /platform/api/v2/task/unreviewed-list
type UnreviewedListData struct {
	Tasks           []UnreviewedTaskRef `json:"tasks"`
	TitleDictionary TitleDictionary     `json:"titleDictionary"`
}

// TitleDictionary menangani quirk PHP di mana dictionary kosong diserialisasi sebagai `[]` alih-alih `{}`.
type TitleDictionary struct {
	Lessons []IDTitle `json:"lessons"`
	Groups  []IDTitle `json:"groups"`
}

func (td *TitleDictionary) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("[]")) {
		*td = TitleDictionary{}
		return nil
	}
	type plainTitleDict TitleDictionary
	var raw plainTitleDict
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		*td = TitleDictionary{}
		return nil
	}
	*td = TitleDictionary(raw)
	return nil
}

type UnreviewedTaskRef struct {
	GroupID              int    `json:"groupId"`
	StudentID            int    `json:"studentId"`
	LessonID             int    `json:"lessonId"`
	TaskID               int    `json:"taskId"`
	Track                int    `json:"track"`
	LevelUnreviewedCount int    `json:"levelUnreviewedCount"`
	CreatedAt            string `json:"createdAt"`
}

type IDTitle struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}

// ScheduledGroup merepresentasikan grup yang ditemukan dari halaman /group/default/schedule
type ScheduledGroup struct {
	GroupID int    `json:"groupId"`
	Title   string `json:"title"`
}

// GroupLessonIndexData memetakan GET /api/v2/group/lesson/index
type GroupLessonIndexData struct {
	Items []GroupLessonItem `json:"items"`
}

type GroupLessonItem struct {
	ID                         int      `json:"id"` // Ini adalah progressLessonId / groupLessonId
	LessonID                   int      `json:"lessonId"`
	GroupID                    int      `json:"groupId"`
	Title                      string   `json:"title"`
	Status                     int      `json:"status"` // 10 = Opened, 0 = Closed
	RegularTaskScoreSumPercent *float64 `json:"regularTaskScoreSumPercent"`
}

// GroupLessonViewData memetakan GET /api/v2/group/lesson/view/{progressLessonId}?expand=levels,progress
type GroupLessonViewData struct {
	ID       int                        `json:"id"`
	LessonID int                        `json:"lessonId"`
	GroupID  int                        `json:"groupId"`
	Title    string                     `json:"title"`
	Status   int                        `json:"status"`
	Progress []StudentLessonProgressRow `json:"progress"`
}

type StudentLessonProgressRow struct {
	StudentID       int                   `json:"studentId"`
	IsStudentActive bool                  `json:"isStudentActive"`
	Progress        []StudentTaskProgress `json:"progress"`
}

type StudentTaskProgress struct {
	ID       int                    `json:"id"` // taskId
	Name     string                 `json:"name"`
	Position int                    `json:"position"`
	Track    int                    `json:"track"`
	Type     string                 `json:"type"`
	IsKahoot bool                   `json:"isKahoot"`
	Levels   []StudentLevelProgress `json:"levels"`
}

type StudentLevelProgress struct {
	ID             int                       `json:"id"` // levelId
	TaskLevelID    int                       `json:"taskLevelId"`
	Name           string                    `json:"name"`
	Position       int                       `json:"position"`
	Type           string                    `json:"type"`
	Mechanic       string                    `json:"mechanic"`
	Status         string                    `json:"status"` // "student_success" = Kuning!
	URL            *string                   `json:"url"`
	SolvedAtLesson bool                      `json:"solvedAtLesson"`
	Objectives     []StudentProgressObjEntry `json:"objectives"`
}

type StudentProgressObjEntry struct {
	ID            string `json:"id"` // hint_id
	Text          string `json:"text"`
	StudentStatus string `json:"studentStatus"` // "checked" / "unchecked"
	TeacherStatus string `json:"teacherStatus"` // "unchecked" / "success" / "fail"
}

// GroupStudentIndexData memetakan GET /api/v2/group/student/index?groupId={groupId}
type GroupStudentIndexData struct {
	Items []GroupStudentItem `json:"items"`
}

type GroupStudentItem struct {
	ID        int     `json:"id"`
	FirstName string  `json:"firstName"`
	LastName  string  `json:"lastName"`
	FullName  string  `json:"fullName"`
	Username  string  `json:"username"`
	DeletedAt *string `json:"deletedAt"`
}

// TaskViewData memetakan GET /platform/api/v2/task/view/{taskId}?...&expand=levels,kahoot,openLevels
type TaskViewData struct {
	ID         int            `json:"id"`
	Title      string         `json:"title"`
	LessonID   int            `json:"lessonId"`
	Type       string         `json:"type"`
	IsBonus    bool           `json:"isBonus"`
	Levels     []TaskViewLvl  `json:"levels"`
	OpenLevels OpenLevelsMap  `json:"openLevels"`
}

type TaskViewLvl struct {
	ID            int             `json:"id"`
	Position      int             `json:"position"`
	TaskLevelID   int             `json:"taskLevelId"`
	TaskLevelType string          `json:"taskLevelType"`
	Type          string          `json:"type"`
	Title         string          `json:"title"`
	Config        TaskViewLvlConf `json:"config"`
}

type TaskViewLvlConf struct {
	Type  string      `json:"type"`
	Hints []LevelHint `json:"hints"`
}

type LevelHint struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Text           string `json:"text"`
	TaskType       string `json:"taskType"` // "basic" atau "bonus"
	EvaluationType string `json:"evaluationType"`
}

type OpenLevelState struct {
	Status   string `json:"status"`
	Attempts int    `json:"attempts"`
	IsPassed bool   `json:"isPassed"`
	Modified string `json:"modified"`
}

// OpenLevelsMap menangani quirk PHP di mana map kosong diserialisasi sebagai `[]` alih-alih `{}`.
type OpenLevelsMap map[string]OpenLevelState

func (m *OpenLevelsMap) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("[]")) {
		*m = make(OpenLevelsMap)
		return nil
	}
	var raw map[string]OpenLevelState
	if err := json.Unmarshal(trimmed, &raw); err != nil {
		*m = make(OpenLevelsMap)
		return nil
	}
	*m = raw
	return nil
}

// LevelDetailData memetakan GET /platform/api/v1/level/{levelId}
type LevelDetailData struct {
	ID          int         `json:"id"`
	Title       string      `json:"title"`
	Type        string      `json:"type"`
	IsAutocheck bool        `json:"isAutocheck"`
	Hints       []LevelHint `json:"hints"`
}

// StudentObjectivesData memetakan GET /platform/api/v1/student-objectives/view
type StudentObjectivesData struct {
	Objectives []struct {
		HintID string `json:"hint_id"`
	} `json:"objectives"`
}

// TeacherStepsData memetakan GET /platform/api/v1/teacherComment/steps
type TeacherStepsData struct {
	Steps []struct {
		HintID string `json:"hint_id"`
		Status string `json:"status"` // "success", "fail", "unmarked"
	} `json:"steps"`
}

// TeacherCommentStepPayload adalah body untuk POST /platform/api/v1/teacherComment/step
type TeacherCommentStepPayload struct {
	HintID  string `json:"hint_id"`
	Level   int    `json:"level"`
	Status  string `json:"status"` // "success"
	Student int    `json:"student"`
}

// ChangeMultiStatusPayload adalah body untuk POST /platform/api/v2/level/change-multi-status
type ChangeMultiStatusPayload struct {
	Levels    []ChangeLevelEntry `json:"levels"`
	StudentID int                `json:"studentId"`
}

type ChangeLevelEntry struct {
	Attempts  int    `json:"attempts"`
	IsPassed  bool   `json:"isPassed,omitempty"`
	LessonID  int    `json:"lessonId"`
	Position  int    `json:"position"`
	Status    string `json:"status"` // "complete" atau "open"
	TaskID    int    `json:"taskId"`
	StudentID int    `json:"studentId,omitempty"`
}

// ObjectiveItem merepresentasikan 1 baris checklist guru pada sebuah level.
type ObjectiveItem struct {
	HintID        string `json:"hintId"`
	Title         string `json:"title"`
	StudentStatus string `json:"studentStatus"` // "checked" / "unchecked"
	TeacherStatus string `json:"teacherStatus"` // "unchecked" / "success" / "fail"
}

// YellowLevelItem merepresentasikan 1 level bertanda kuning (student_success) yang siap diceklis guru.
type YellowLevelItem struct {
	Key                 string          `json:"key"`
	Source              string          `json:"source"`
	GroupID             int             `json:"groupId"`
	GroupTitle          string          `json:"groupTitle"`
	GroupProgressURL    string          `json:"groupProgressUrl"`
	ProgressLessonID    int             `json:"progressLessonId,omitempty"`
	LessonID            int             `json:"lessonId"`
	LessonTitle         string          `json:"lessonTitle"`
	StudentID           int             `json:"studentId"`
	StudentName         string          `json:"studentName"`
	TaskID              int             `json:"taskId"`
	TaskTitle           string          `json:"taskTitle"`
	Track               int             `json:"track"`
	LevelID             int             `json:"levelId"`
	LevelPosition       int             `json:"levelPosition"`
	LevelTitle          string          `json:"levelTitle"`
	LevelMechanic       string          `json:"levelMechanic"`
	Status              string          `json:"status"`
	Attempts            int             `json:"attempts"`
	TaskPreviewURL      string          `json:"taskPreviewUrl"`
	Objectives          []ObjectiveItem `json:"objectives"`
	ShouldOpenNextLevel bool            `json:"shouldOpenNextLevel"`
	NextLevelPosition   int             `json:"nextLevelPosition,omitempty"`
}

// MakeKey membuat identifier unik untuk sebuah YellowLevelItem.
func MakeKey(groupID, studentID, lessonID, taskID, levelID int) string {
	return fmt.Sprintf("%d:%d:%d:%d:%d", groupID, studentID, lessonID, taskID, levelID)
}

// CheckResult menyimpan hasil eksekusi (atau simulasi dry-run) pada 1 YellowLevelItem.
type CheckResult struct {
	Item               YellowLevelItem `json:"item"`
	DryRun             bool            `json:"dryRun"`
	ObjectivesChecked  int             `json:"objectivesChecked"`
	LevelStatusUpdated bool            `json:"levelStatusUpdated"`
	Success            bool            `json:"success"`
	Error              string          `json:"error,omitempty"`
	CheckedAt          time.Time       `json:"checkedAt"`
}
