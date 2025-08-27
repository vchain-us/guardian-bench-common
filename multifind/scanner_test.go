package multifind

import (
	"os"
	"path"
	"strings"
	"testing"
)

func CheckErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func MakeTestEnv(t *testing.T) string {
	dir, err := os.MkdirTemp(".", "prefix")
	CheckErr(t, err)
	testvec := []struct {
		name string
		perm uint
	}{
		{"aaa", 0o664}, {"abc", 0o755}, {"ccc", 0o600},
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

func TestScanner(t *testing.T) {
	dir := MakeTestEnv(t)
	defer os.RemoveAll(dir)
	testvec := []struct {
		cmd   string
		count int
	}{
		{"-name a*", 2},
		{"-type f", 3},
		{"-perm -600", 4},
	}
	for i, c := range testvec {
		cmd1 := strings.Split(c.cmd, " ")
		pp, err := ParseCommandLine(cmd1)
		CheckErr(t, err)
		out := make(chan string, 10)
		end := make(chan bool)
		res := []string{}
		go func() {
			for {
				s := <-out
				if s == "//" {
					break
				}
				res = append(res, s)
			}
			end <- true
		}()
		sc := NewScanner(pp, out)
		sc.Scan([]string{dir})
		<-end
		if len(res) != c.count {
			t.Fatalf("Fail test %d: wrong number of files %v", i, res)
		}
	}
}
