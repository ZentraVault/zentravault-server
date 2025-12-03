package user

type User struct {
	Username string
	Email    string
	Password string
	Token    string
	ID       string
	Status   string
	Friends  []string
	Groups   []string
}
