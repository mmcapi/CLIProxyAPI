// Package releasecontrol coordinates refresh ownership between release instances.
package releasecontrol

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var ErrNotOwner = errors.New("credential refresh ownership is inactive")

type Status struct {
	Owner     bool `json:"owner"`
	Accepting bool `json:"accepting"`
	InFlight  int  `json:"in_flight"`
}

// Owner starts inactive. All instances must use the same stable lock inode on a
// local host filesystem. Never remove or replace the lock file during operation.
type Owner struct {
	control   sync.Mutex
	mu        sync.Mutex
	path      string
	file      *os.File
	accepting bool
	inFlight  int
	idle      chan struct{}
}

func NewOwner(path string) (*Owner, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("refresh lock path must be absolute")
	}
	return &Owner{path: filepath.Clean(path)}, nil
}

func (o *Owner) Activate() error {
	return o.ActivateWith(nil)
}

// ActivateWith reloads durable credentials while holding exclusive ownership,
// before admitting writes or refreshes. A failed reload relinquishes ownership.
func (o *Owner) ActivateWith(reload func() error) error {
	o.control.Lock()
	defer o.control.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.file != nil {
		if o.accepting {
			return nil
		}
		return errors.New("refresh owner is quiescing; finish quiesce before activation")
	}
	info, err := os.Lstat(o.path)
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("refresh lock must be a regular file")
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(o.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err = lockFile(file); err != nil {
		_ = file.Close()
		return fmt.Errorf("acquire refresh ownership: %w", err)
	}
	o.file = file
	if reload != nil {
		o.mu.Unlock()
		errReload := reload()
		o.mu.Lock()
		if errReload != nil {
			_ = unlockFile(file)
			_ = file.Close()
			o.file = nil
			return fmt.Errorf("reload credentials before activation: %w", errReload)
		}
	}
	o.accepting = true
	return nil
}

type admissionKey struct{}
type admission struct {
	owner  *Owner
	mu     sync.Mutex
	active bool
}

// EnterContext allows nested persistence within an admitted refresh to finish
// after quiesce closes admission. The lease expires when its outer work returns.
func (o *Owner) EnterContext(ctx context.Context) (context.Context, func(), error) {
	if lease, ok := ctx.Value(admissionKey{}).(*admission); ok && lease.owner == o {
		lease.mu.Lock()
		active := lease.active
		lease.mu.Unlock()
		if active {
			return ctx, func() {}, nil
		}
	}
	release, err := o.Enter(ctx)
	if err != nil {
		return ctx, nil, err
	}
	lease := &admission{owner: o, active: true}
	return context.WithValue(ctx, admissionKey{}, lease), func() {
		lease.mu.Lock()
		lease.active = false
		lease.mu.Unlock()
		release()
	}, nil
}

// Enter admits one complete refresh including its durable persistence.
func (o *Owner) Enter(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o.mu.Lock()
	if !o.accepting || o.file == nil {
		o.mu.Unlock()
		return nil, ErrNotOwner
	}
	if o.inFlight == 0 {
		o.idle = make(chan struct{})
	}
	o.inFlight++
	o.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			o.mu.Lock()
			defer o.mu.Unlock()
			o.inFlight--
			if o.inFlight == 0 {
				close(o.idle)
			}
		})
	}, nil
}

// Quiesce closes admission immediately and waits for admitted work. Cancellation
// does not relinquish the lock: callers must retry until quiescence succeeds.
func (o *Owner) Quiesce(ctx context.Context) error {
	o.control.Lock()
	defer o.control.Unlock()
	o.mu.Lock()
	o.accepting = false
	for o.inFlight != 0 {
		idle := o.idle
		o.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-idle:
		}
		o.mu.Lock()
	}
	defer o.mu.Unlock()
	if o.file == nil {
		return nil
	}
	if err := unlockFile(o.file); err != nil {
		return err
	}
	err := o.file.Close()
	o.file = nil
	return err
}

func (o *Owner) Status() Status {
	o.mu.Lock()
	defer o.mu.Unlock()
	return Status{Owner: o.file != nil, Accepting: o.accepting, InFlight: o.inFlight}
}
