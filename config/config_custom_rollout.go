package config

type CustomRolloutSpec struct {
	GoalState                 string                `json:"goal_state"`
	ApplyCommand              []string              `json:"apply_command"`
	GetActualStateCommand     []string              `json:"get_actual_state_command"`
	Priority                  CustomRolloutPriority `json:"priority"`
	BasicDisplayTextForHumans string                `json:"basic_display_text_for_humans"`
}

type CustomRolloutPriority struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}
