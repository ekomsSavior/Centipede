package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseTaskArgs(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
		want map[string]string
	}{
		{"empty", nil, map[string]string{}},
		{"bare-command-string", json.RawMessage(`"id"`), map[string]string{"cmd": "id"}},
		{"bare-command-plain", json.RawMessage(`id`), map[string]string{"cmd": "id"}},
		{"json-object", json.RawMessage(`{"cmd":"whoami"}`), map[string]string{"cmd": "whoami"}},
		{"json-object-multi", json.RawMessage(`{"cmd":"ls","shell":"/bin/bash"}`), map[string]string{"cmd": "ls", "shell": "/bin/bash"}},
		{"double-encoded-object", json.RawMessage(`"{\"cmd\":\"echo hi\"}"`), map[string]string{"cmd": "echo hi"}},
		{"double-encoded-multi", json.RawMessage(`"{\"cmd\":\"id\",\"x\":\"1\"}"`), map[string]string{"cmd": "id", "x": "1"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseTaskArgs(tc.raw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseTaskArgs(%s) = %v, want %v", string(tc.raw), got, tc.want)
			}
		})
	}
}
