package multifind

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
)

type FindCondition interface {
	Eval(fs.DirEntry) bool
}
type PermCondition struct {
	perm uint32
}
type TypeCondition struct {
	typ byte
}
type NameCondition struct {
	glob string
}
type NoUserCondition struct {
	sysUsers map[uint32]string
}
type NoGroupCondition struct {
	sysGroups map[uint32]string
}

type FindQuery struct {
	Conditions []FindCondition
	Separator  byte
}

func NewFindQuery() *FindQuery {
	return &FindQuery{Separator: '\n'}
}

func (cnd *PermCondition) Eval(de fs.DirEntry) bool {
	fi, err := de.Info()
	if err != nil {
		return false
	}
	return uint32(fi.Mode())&cnd.perm == cnd.perm
}

func (cnd *TypeCondition) Eval(de fs.DirEntry) bool {
	if cnd.typ == 'd' {
		return de.IsDir()
	}
	fi, err := de.Info()
	if err != nil {
		return false
	}
	if cnd.typ == 'f' {
		return fi.Mode().IsRegular()
	}
	return false
}

func (cnd *NameCondition) Eval(fi fs.DirEntry) bool {
	match, err := path.Match(cnd.glob, fi.Name())
	if err != nil {
		return false
	}
	return match
}

func (cnd *NoUserCondition) Eval(de fs.DirEntry) bool {
	fi, err := de.Info()
	if err != nil {
		return false
	}
	file_sys := fi.Sys()
	uid := file_sys.(*syscall.Stat_t).Uid
	_, ok := cnd.sysUsers[uid]
	return !ok
}
func (cnd *NoUserCondition) init() error {
	grp, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return err
	}
	cnd.sysUsers = make(map[uint32]string)
	for line := range strings.SplitSeq(string(grp), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			return err
		}
		cnd.sysUsers[uint32(uid)] = f[0]
	}
	return nil
}

func (cnd *NoGroupCondition) Eval(de fs.DirEntry) bool {
	fi, err := de.Info()
	if err != nil {
		return false
	}
	file_sys := fi.Sys()
	gid := file_sys.(*syscall.Stat_t).Gid
	_, ok := cnd.sysGroups[gid]
	return !ok
}
func (cnd *NoGroupCondition) init() error {
	grp, err := os.ReadFile("/etc/group")
	if err != nil {
		return err
	}
	cnd.sysGroups = make(map[uint32]string)
	for line := range strings.SplitSeq(string(grp), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			return err
		}
		cnd.sysGroups[uint32(gid)] = f[0]
	}
	return nil
}

func (fq *FindQuery) ExtractCondition(parms []string) ([]string, FindCondition, error) {
	switch parms[0] {
	case "-perm":
		if len(parms) < 2 {
			return nil, nil, fmt.Errorf("missing permissions")
		}
		if parms[1][0] != '-' {
			return nil, nil, fmt.Errorf("wrong perm param")
		}
		perm, err := strconv.ParseUint(parms[1][1:], 8, 32)
		highPerm := perm & 0o7000
		perm = perm & 0o777
		if highPerm&0o1000 != 0 {
			perm = perm | uint64(fs.ModeSticky)
		}
		if highPerm&0o2000 != 0 {
			perm = perm | uint64(fs.ModeSetgid)
		}
		if highPerm&0o4000 != 0 {
			perm = perm | uint64(fs.ModeSetuid)
		}
		if err != nil {
			return nil, nil, err
		}
		cond := PermCondition{perm: uint32(perm)}
		return parms[2:], &cond, nil
	case "-type":
		if len(parms) < 2 {
			return nil, nil, fmt.Errorf("missing type")
		}
		cond := TypeCondition{typ: parms[1][0]}
		return parms[2:], &cond, nil
	case "-name":
		if len(parms) < 2 {
			return nil, nil, fmt.Errorf("missing name")
		}
		cond := NameCondition{glob: parms[1]}
		return parms[2:], &cond, nil
	case "-nouser":
		cond := NoUserCondition{}
		cond.init()
		return parms[1:], &cond, nil
	case "-nogroup":
		cond := NoGroupCondition{}
		cond.init()
		return parms[1:], &cond, nil
	case "-xdev", "": // xdev is implied
		return parms[1:], nil, nil
	case "-print0":
		fq.Separator = 0
	}

	return nil, nil, fmt.Errorf("unknown find clause %s", parms[0])
}

func (fq *FindQuery) ParseCommandLine(cmdline []string) error {
	for {
		p2, cond, err := fq.ExtractCondition(cmdline)
		cmdline = p2 // won't work correctly if I set cmdline in previous line
		if err != nil {
			return err
		}
		if cond != nil {
			fq.Conditions = append(fq.Conditions, cond)
		}
		if len(cmdline) == 0 {
			break
		}
	}
	return nil
}
