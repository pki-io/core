package ssh

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"time"
)

const (
	defaultTimeout time.Duration = time.Minute
	muxFormat      string        = "%r@%h:%p"
	aliveTries     int           = 3
	aliveInterval  time.Duration = 3 * time.Second
)

type SSH struct {
	host        string
	args        []string
	tmp         string
	mux         string
	timeout     time.Duration
	controlDone chan error
}

func New() *SSH {
	s := new(SSH)
	s.timeout = defaultTimeout
	return s
}

func Connect(host string, args []string) (*SSH, error) {
	s := New()

	if err := s.Connect(host, args); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *SSH) Connect(host string, args []string) error {
	var err error

	s.host = host
	s.args = args
	s.controlDone = make(chan error, 1)

	s.tmp, err = ioutil.TempDir("", "pki.io")
	if err != nil {
		return err
	}

	s.mux = path.Join(s.tmp, muxFormat)

	params := make([]string, 0)
	params = append(params, []string{s.host, "-M", "-S", s.mux, "-o", "ControlPersist=yes"}...)
	params = append(params, s.args...)

	controlCmd := exec.Command("ssh", params...)
	controlCmd.Stdout = os.Stdout
	controlCmd.Stderr = os.Stderr

	err = controlCmd.Start()
	if err != nil {
		return err
	}

	go func() {
		s.controlDone <- controlCmd.Wait()
	}()

	timeout := time.After(s.timeout)
	select {
	case <-timeout:
		if err := controlCmd.Process.Signal(os.Interrupt); err != nil {
			return err
		}
		<-s.controlDone
		return fmt.Errorf("control process timeout. Killed.")
	case err := <-s.controlDone:
		if err != nil {
			return err
		}
	}

	alive := false
	for i := 0; i < aliveTries; i++ {
		if s.ControlAlive() {
			alive = true
			break
		}
		time.Sleep(aliveInterval)
	}

	if !alive {
		fmt.Errorf("Could not check mux")
	}

	return nil
}

func (s *SSH) ExecuteCmd(cmd *exec.Cmd, stdin io.Reader, stdout, stderr io.Writer) error {
	var err error
	cmdDone := make(chan error, 1)

	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err = cmd.Start()
	if err != nil {
		return err
	}

	go func() {
		cmdDone <- cmd.Wait()
	}()

	timeout := time.After(s.timeout)
	select {
	case <-timeout:
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return err
		}
		<-cmdDone
		return fmt.Errorf("execution process timeout. Killed.")
	case err := <-cmdDone:
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SSH) Execute(cmd string, stdin io.Reader, stdout, stderr io.Writer) error {
	return s.ExecuteCmd(exec.Command("ssh", s.host, "-S", s.mux, cmd), stdin, stdout, stderr)
}

func (s *SSH) ControlAlive() bool {
	if err := s.ExecuteCmd(exec.Command("ssh", s.host, "-S", s.mux, "-O", "check"), nil, nil, nil); err != nil {
		return false
	}

	return true
}

func (s *SSH) PutFiles(dest string, sources ...string) error {
	var err error
	cmdDone := make(chan error, 1)

	params := make([]string, 0)
	params = append(params, []string{"-o", fmt.Sprintf("ControlPath=%s", s.mux)}...)
	params = append(params, sources...)
	params = append(params, fmt.Sprintf("%s:%s", s.host, dest))

	cmd := exec.Command("scp", params...)

	err = cmd.Start()
	if err != nil {
		return err
	}

	go func() {
		cmdDone <- cmd.Wait()
	}()

	timeout := time.After(s.timeout)
	select {
	case <-timeout:
		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			return err
		}
		<-cmdDone
		return fmt.Errorf("execution process timeout. Killed.")
	case err := <-cmdDone:
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SSH) GetFile(source, dest string) error {
	fmt.Println("getting file")
	return nil
}

func (s *SSH) Close() error {
	s.ExecuteCmd(exec.Command("ssh", s.host, "-S", s.mux, "-O", "exit"), nil, nil, nil)
	err := os.RemoveAll(s.tmp)
	s.tmp = ""
	s.mux = ""
	return err
}
