package sshx

import (
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

// AgentKeys reports which agent devtun would talk to and what it is holding.
//
// It exists for `devtun doctor`, and it resolves the socket exactly the way a
// connection does — an explicit override, then ssh_config's IdentityAgent, then
// the environment — because "which agent" is the question people actually get
// wrong. A gpg-agent that has replaced ssh-agent, a 1Password agent that is not
// running, a tmux session carrying a stale SSH_AUTH_SOCK: all three look
// identical from the outside and none of them says so.
func AgentKeys(explicit, fromConfig string) (socket string, keys []string, err error) {
	socket = resolveAgentPath(explicit, fromConfig)
	if socket == "" {
		return "", nil, nil
	}
	conn, err := dialAgentAt(socket)
	if err != nil {
		return socket, nil, fmt.Errorf("cannot reach the agent at %s: %w", socket, err)
	}
	defer func() { _ = conn.Close() }()

	listed, err := agent.NewClient(conn).List()
	if err != nil {
		return socket, nil, fmt.Errorf("the agent at %s would not list its keys: %w", socket, err)
	}
	for _, key := range listed {
		comment := key.Comment
		if comment == "" {
			comment = key.Format
		}
		keys = append(keys, fmt.Sprintf("%s %s", key.Format, comment))
	}
	return socket, keys, nil
}

// AgentSocketFromEnv is what SSH_AUTH_SOCK says, for a caller that wants to
// report the environment rather than the resolved answer.
func AgentSocketFromEnv() string { return os.Getenv("SSH_AUTH_SOCK") }
