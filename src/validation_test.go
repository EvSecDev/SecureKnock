// secureknockd
package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateIPandPort(t *testing.T) {
	tests := []struct {
		address        string
		port           int
		isSource       bool
		expectErr      bool
		expectedSocket string
	}{
		{
			address:        "localhost",
			port:           8080,
			isSource:       false,
			expectErr:      false,
			expectedSocket: "127.0.0.1:8080",
		},
		{
			address:        "",
			port:           0,
			isSource:       false,
			expectErr:      true,
			expectedSocket: "",
		},
		{
			address:        "localhost",
			port:           5431,
			isSource:       true,
			expectErr:      false,
			expectedSocket: "127.0.0.1:5431",
		},
		{
			address:        "",
			port:           543,
			isSource:       true,
			expectErr:      false,
			expectedSocket: "[::]:543",
		},
		{
			address:        "invalid-domain",
			port:           8080,
			isSource:       false,
			expectErr:      true,
			expectedSocket: "",
		},
		{
			address:        "localhost",
			port:           70000, // Invalid port
			isSource:       false,
			expectErr:      true,
			expectedSocket: "",
		},
	}

	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			socket, l4Protocol, err := validateIPandPort(test.address, test.port, test.isSource)

			if (err != nil) != test.expectErr {
				t.Errorf("expected error: %v, got: %v", test.expectErr, err)
			}

			if err == nil && socket.String() != test.expectedSocket {
				t.Errorf("expected socket: %v, got: %v", test.expectedSocket, socket.String())
			}

			// Optionally check the protocol type (should always be "udp")
			if err == nil && l4Protocol != "udp" {
				t.Errorf("expected l4Protocol: udp, got: %v", l4Protocol)
			}
		})
	}
}

func TestValidateActionCommands(t *testing.T) {
	tests := []struct {
		name        string
		actions     []map[string][]string
		expectedErr string
	}{
		{
			name: "Action name contains reserved separator",
			actions: []map[string][]string{
				{
					"invalid:action": {"ls", "grep"},
				},
			},
			expectedErr: "cannot use ':' character in action name, it is reserved",
		},
		{
			name: "Command not in PATH",
			actions: []map[string][]string{
				{
					"action1": {"nonexistentCommand"},
				},
			},
			expectedErr: "nonexistentCommand",
		},
		{
			name: "Valid command in PATH",
			actions: []map[string][]string{
				{
					"action1": {"ls", "grep"},
				},
			},
			expectedErr: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test the validateActionCommands function with real commands
			err := validateActionCommands(test.actions)
			if test.expectedErr == "" && err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			} else if test.expectedErr != "" && err == nil {
				t.Errorf("Expected error containing '%s', but got no error", test.expectedErr)
			} else if test.expectedErr != "" && err != nil && !strings.Contains(err.Error(), test.expectedErr) {
				t.Errorf("Expected error containing '%s', but got: %v", test.expectedErr, err)
			}
		})
	}
}

func TestValidateActionName(t *testing.T) {
	tests := []struct {
		name        string
		actionName  string
		expectedErr string
	}{
		{
			name:        "Valid ASCII name",
			actionName:  "validAction",
			expectedErr: "",
		},
		{
			name:        "Action name contains non-ASCII characters",
			actionName:  "invalidActionÆ",
			expectedErr: "must be ASCII text only",
		},
		{
			name:        "Action name contains payload separator",
			actionName:  "invalid:action",
			expectedErr: "must not contain character ':'",
		},
		{
			name:        "Action name exceeds max length",
			actionName:  strings.Repeat("a", maxPayloadTextSize), // Length == maxPayloadTextSize
			expectedErr: fmt.Sprintf("must be less than or equal to %d bytes/characters", maxPayloadTextSize),
		},
		{
			name:        "Action name exactly max length",
			actionName:  strings.Repeat("a", maxPayloadTextSize-1), // Length = maxPayloadTextSize-1
			expectedErr: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test the validateActionName function
			err := validateActionName(test.actionName)
			if test.expectedErr == "" && err != nil {
				t.Errorf("Expected no error, but got: %v", err)
			} else if test.expectedErr != "" && err == nil {
				t.Errorf("Expected error containing '%s', but got no error", test.expectedErr)
			} else if test.expectedErr != "" && err != nil && !strings.Contains(err.Error(), test.expectedErr) {
				t.Errorf("Expected error containing '%s', but got: %v", test.expectedErr, err)
			}
		})
	}
}
