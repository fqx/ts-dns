package outbound

import (
	"context"
	"fmt"
	"github.com/wolf-joe/go-ipset/ipset"
	"os/exec"
	"strconv"
	"time"
)

type iIPSet interface {
	Add(entry string, timeout int) error
	GetName() string
	GetTimeout() int
}

type ipSetWrapper struct {
	*ipset.IPSet
}

func (i ipSetWrapper) GetName() string { return i.Name }
func (i ipSetWrapper) GetTimeout() int { return i.Timeout }

var (
	_ iIPSet = ipSetWrapper{}
	_ iIPSet = MockIPSet{}
)

type MockIPSet struct {
	Name    string
	Timeout int
	MockAdd func(entry string, timeout int) error
}

func (i MockIPSet) GetName() string                     { return i.Name }
func (i MockIPSet) GetTimeout() int                     { return i.Timeout }
func (i MockIPSet) Add(entry string, timeout int) error { return i.MockAdd(entry, timeout) }

// Background refreshes must be able to stop privileged helper processes too.
func (i ipSetWrapper) AddContext(ctx context.Context, entry string, timeout int) error {
	cmd := exec.CommandContext(ctx, "ipset", "add", i.Name, entry, "timeout", strconv.Itoa(timeout), "-exist")
	cmd.WaitDelay = time.Second
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ipset add failed: %w (%s)", err, output)
	}
	return nil
}
