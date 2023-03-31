package storage

import (
	"crypto/rsa"
)

type User struct {
	ID        string
	Username  string
	Password  string
	FirstName string
	LastName  string
	Email     string
}

type Service struct {
	keys map[string]*rsa.PublicKey
}

type UserStore interface {
	GetUserByID(string) *User
	GetUserByUsername(string) *User
	ExampleClientID() string
}

type userStore struct {
	users map[string]*User
}

func NewUserStore() UserStore {
	return userStore{
		users: map[string]*User{
			"id1": {
				ID:        "id1",
				Username:  "test1",
				Password:  "test1",
				FirstName: "Test",
				LastName:  "User",
				Email:     "test1@example.com",
			},
		},
	}
}

// ExampleClientID is only used in the example server
func (u userStore) ExampleClientID() string {
	return "service"
}

func (u userStore) GetUserByID(id string) *User {
	return u.users[id]
}

func (u userStore) GetUserByUsername(username string) *User {
	for _, user := range u.users {
		if user.Username == username {
			return user
		}
	}
	return nil
}
