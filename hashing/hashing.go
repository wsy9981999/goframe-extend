package hashing

import (
	bcrypt "golang.org/x/crypto/bcrypt"
)

type Hashing struct {
	Cost int
}

func NewHashing(cost ...int) *Hashing {
	_cost := bcrypt.DefaultCost
	if len(cost) > 0 {
		_cost = cost[0]
	}
	return &Hashing{Cost: _cost}
}

func (receiver *Hashing) Make(pwd []byte, cost ...int) (string, error) {
	_cost := receiver.Cost
	if len(cost) > 0 {
		_cost = cost[0]
	}
	password, err := bcrypt.GenerateFromPassword(pwd, _cost)
	if err != nil {
		return "", err
	}
	return string(password), nil
}
func (receiver *Hashing) MustMake(pwd []byte, cost ...int) string {
	s, err := receiver.Make(pwd, cost...)
	if err != nil {
		panic(err)
	}
	return s

}
func (receiver *Hashing) MakeStr(pwd string) (string, error) {
	return receiver.Make([]byte(pwd))
}
func (receiver *Hashing) MustMakeStr(pwd string) string {
	return receiver.MustMake([]byte(pwd))
}
func (receiver *Hashing) Check(hashed, clearText []byte) bool {
	return bcrypt.CompareHashAndPassword(hashed, clearText) == nil
}
func (receiver *Hashing) CheckStr(hashed, clearText string) bool {
	return receiver.Check([]byte(hashed), []byte(clearText))
}
