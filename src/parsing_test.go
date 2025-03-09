// secureknockd
package main

import (
	"fmt"
	"testing"
)

func TestParsePayload(t *testing.T) {
	tests := []struct {
		name             string
		decryptedPayload []byte
		actions          []map[string][]string
		expectedAction   string
		expectedCommands []string
		expectedPassword string
		expectedError    error
	}{
		{
			name:             "Valid payload with action and password",
			decryptedPayload: []byte("action1:password123"),
			actions: []map[string][]string{
				{"action1": {"command1", "command2"}},
			},
			expectedAction:   "action1",
			expectedCommands: []string{"command1", "command2"},
			expectedPassword: "password123",
			expectedError:    nil,
		},
		{
			name:             "Valid payload with only action",
			decryptedPayload: []byte("action2"),
			actions: []map[string][]string{
				{"action2": {"command3", "command4"}},
			},
			expectedAction:   "action2",
			expectedCommands: []string{"command3", "command4"},
			expectedPassword: "",
			expectedError:    nil,
		},
		{
			name:             "Invalid payload (non-ASCII)",
			decryptedPayload: []byte("action1\x80"),
			actions: []map[string][]string{
				{"action1": {"command1", "command2"}},
			},
			expectedAction:   "",
			expectedCommands: nil,
			expectedPassword: "",
			expectedError:    fmt.Errorf("packet payload string is not ASCII"),
		},
		{
			name:             "Unauthorized action",
			decryptedPayload: []byte("unauthorizedAction"),
			actions: []map[string][]string{
				{"action1": {"command1", "command2"}},
			},
			expectedAction:   "",
			expectedCommands: nil,
			expectedPassword: "",
			expectedError:    fmt.Errorf("packet payload does not match an authorized action"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actionName, commands, sudoPassword, err := parsePayload(test.decryptedPayload, test.actions)

			if (err == nil && test.expectedError != nil) || (err != nil && err.Error() != test.expectedError.Error()) {
				t.Errorf("parsePayload() error = %v, expectedError %v", err, test.expectedError)
			}
			if actionName != test.expectedAction {
				t.Errorf("parsePayload() actionName = %v, expectedAction %v", actionName, test.expectedAction)
			}
			if !equalStringSlices(commands, test.expectedCommands) {
				t.Errorf("parsePayload() commands = %v, expectedCommands %v", commands, test.expectedCommands)
			}
			if sudoPassword != test.expectedPassword {
				t.Errorf("parsePayload() sudoPassword = %v, expectedPassword %v", sudoPassword, test.expectedPassword)
			}
		})
	}
}

// Helper function to compare string slices
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
