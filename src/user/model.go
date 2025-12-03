package user

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	objectid primitive.ObjectID
	username string
	email    string
	password string
	token    string
	id       string
	status   string
	friends  []string
	groups   []string
}
