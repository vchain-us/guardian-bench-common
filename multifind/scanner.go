package multifind

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Scanner struct {
	query  *FindQuery
	output chan string
}

type Multiscanner struct {
	scanners []*Scanner
	path     string
	wg       sync.WaitGroup
	mounts   map[string]string
}

func NewScanner(query *FindQuery, output chan string) *Scanner {
	return &Scanner{
		query:  query,
		output: output,
	}
}

func (sc *Scanner) Scan(paths []string) {
	for _, pat := range paths {
		filepath.WalkDir(pat, func(path string, d fs.DirEntry, err error) error {
			res := true
			operator := '&'
			for _, p := range sc.query.Conditions {
				if _, ok := p.(*OrOperator); ok {
					operator = '|'
					continue
				}
				if _, ok := p.(*NotOperator); ok {
					operator = '!'
					continue
				}
				switch operator {
				case '&':
					res = res && p.Eval(d)
				case '|':
					res = res || p.Eval(d)
				case '!':
					res = res && !p.Eval(d)
				}
				operator = '&'
			}
			if res {
				sc.output <- path
			}
			return nil
		})
	}
	sc.output <- "//"
}

func NewMultiScanner(path string) *Multiscanner {
	return &Multiscanner{
		path:   path,
		mounts: getMountPoints(),
	}
}

func (ms *Multiscanner) Scan() {
	for pat := range strings.SplitSeq(ms.path, " ") {
		filepath.WalkDir(pat, func(path string, d fs.DirEntry, err error) error {
			if ms.mounts != nil && path != pat {
				_, ok := ms.mounts[path]
				if ok {
					return fs.SkipDir // skip all other mountpoints
				}
			}
			for _, sc := range ms.scanners {
				operator := '&'
				res := true
				for _, p := range sc.query.Conditions {
					if _, ok := p.(*OrOperator); ok {
						operator = '|'
						continue
					}
					if _, ok := p.(*NotOperator); ok {
						operator = '!'
						continue
					}
					switch operator {
					case '&':
						res = res && p.Eval(d)
					case '|':
						res = res || p.Eval(d)
					case '!':
						res = res && !p.Eval(d)
					}
					operator = '&'
				}
				if res {
					sc.output <- path
				}
			}
			return nil
		})
	}
	for _, sc := range ms.scanners {
		sc.output <- "//"
	}
}

func (ms *Multiscanner) AddScanner(query *FindQuery, output chan string) {
	scanner := &Scanner{
		query:  query,
		output: output,
	}
	ms.scanners = append(ms.scanners, scanner)
	ms.wg.Add(1)
}

func (ms *Multiscanner) Wait() {
	ms.wg.Wait()
}

func (ms *Multiscanner) CloseWorker() {
	ms.wg.Done()
}

func getMountPoints() map[string]string {
	mp, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil
	}
	lines := strings.Split(string(mp), "\n")
	mountpoints := make(map[string]string, len(lines))
	for _, l := range lines {
		parts := strings.Split(l, " ")
		if len(parts) < 2 {
			continue
		}
		dev := parts[0]
		mount := parts[1]
		mountpoints[mount] = dev
	}
	return mountpoints
}
