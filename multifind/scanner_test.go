package multifind

import (
	"fmt"
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
		{"-type f \\( -name a* -o -name c* \\)", 3},
		{"-type f \\( -name aaa -o -name ccc \\)", 2},
	}
	for i, c := range testvec {
		cmd1 := strings.Split(c.cmd, " ")
		fq := NewFindQuery()
		err := fq.ParseCommandLine(cmd1)
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
		sc := NewScanner(fq, out)
		sc.Scan([]string{dir})
		<-end
		if len(res) != c.count {
			t.Fatalf("Fail test %d: wrong number of files %v", i, res)
		}
	}
}

func TestNestedCo(t *testing.T) {
	cmd := strings.Split(`-perm -600 \( -nogroup -type d -name *.txt \)`, " ")
	fq := NewFindQuery()
	err := fq.ParseCommandLine(cmd)
	CheckErr(t, err)
	fmt.Printf("NEST0: %+v\n", fq.Conditions)
	if len(fq.Conditions) != 2 {
		t.Fatalf("Wrong condition length: %d", len(fq.Conditions))
	}
	nest, ok := fq.Conditions[1].(*NestedCondition)
	if !ok {
		t.Fatal("No nested condition")
	}
	fmt.Printf("NEST1: %+v\n", nest.Conditions)
	if len(nest.Conditions) != 3 {
		t.Fatalf("Wrong condition length: %d", len(nest.Conditions))
	}
}
