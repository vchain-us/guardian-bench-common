package multifind

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
)

func MakeMultiscanTestEnv(t *testing.T) string {
	dir, err := os.MkdirTemp(".", "test.")
	CheckErr(t, err)
	testvec := []struct {
		name string
		perm uint
	}{
		{"aaa", 0o664}, {"abc", 0o755}, {"ccc", 0o600},
		{"xyz", 0o664}, {"qwe", 0o755}, {"dsa", 0o600},
	}
	for _, x := range testvec {
		fullname := path.Join(dir, x.name)
		f, err := os.Create(fullname)
		CheckErr(t, err)
		f.Close()
		os.Chmod(fullname, os.FileMode(x.perm))
	}
	return dir
}

func TestMultiScanner2(t *testing.T) {
	dir := MakeMultiscanTestEnv(t)
	defer os.RemoveAll(dir)
	ms := NewMultiScanner(dir)
	testvec := []struct {
		cmd   string
		count int
		ch    chan string
		res   *[]string
	}{
		{"-name a*a", 1, nil, nil},
		{"-type f", 6, nil, nil},
		{"-perm -600", 7, nil, nil},
		{"-perm -755", 2, nil, nil},
	}
	for i, c := range testvec {
		// wg.Add(1)
		c.ch = make(chan string, 10)
		fq := NewFindQuery()
		err := fq.ParseCommandLine(strings.Split(c.cmd, " "))
		CheckErr(t, err)
		ms.AddScanner(fq, c.ch)
		tres := []string{}
		testvec[i].res = &tres
		go func() {
			defer ms.CloseWorker()
			for {
				s := <-c.ch
				if s == "//" {
					break
				}
				tres = append(tres, s)
				fmt.Printf("T%d <- %s %v\n", i, s, tres)
			}
		}()
	}
	ms.Scan()
	ms.Wait()
	fmt.Printf("RES: %+v\n", testvec)

	for i, c := range testvec {
		ts := c.res
		if len(*ts) != c.count {
			t.Fatalf("Fail test %d: wrong number of files %v", i, *ts)
		}
	}

}
