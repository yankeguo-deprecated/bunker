package utils

const (
	// True int for bool true
	True = 1
	// False int for bool false
	False = 0
)

// ToInt bool to int
func ToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ToBool convert int to bool
func ToBool(i int) bool {
	return i != 0
}
