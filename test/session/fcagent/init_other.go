//go:build !linux

package main

import "errors"

func becomeInit() error { return errors.New("only a Linux guest has this agent for its init") }
