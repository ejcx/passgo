package main

import (
	"testing"
)

func StandardArgs(t *testing.T, args []string) {
	if len(args) != 2 {
		t.Fatal("Args size incorrect")
	}
	if args[0] != "insert" {
		t.Fatal("Expecting command insert")
	}
	if args[1] != "site-path" {
		t.Fatal("Expecting site path")
	}
}

func TestNotMultiline(t *testing.T) {
	var multiline bool
	args := []string{"passgo", "insert", "site-path"}
	args, multiline = SubArgs(args)
	if multiline {
		t.Fatal("Not a multiline command")
	}
	StandardArgs(t, args)
}

func TestMultiline(t *testing.T) {
	var multiline bool
	args := []string{"passgo", "insert", "-m", "site-path"}
	args, multiline = SubArgs(args)
	if !multiline {
		t.Fatal("Expecting multiline command")
	}
	StandardArgs(t, args)

	multiline = false
	args = []string{"passgo", "insert", "--multi", "site-path"}
	args, multiline = SubArgs(args)
	if !multiline {
		t.Fatal("Expecting multiline command")
	}
	StandardArgs(t, args)
}
