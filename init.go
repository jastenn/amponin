package main

import "encoding/gob"

func init() {
	gob.Register(&Flash{})
	gob.Register(&SessionUser{})
	gob.Register(&SessionSignupValues{})
	gob.Register(&SessionEmailUpdate{})
}
