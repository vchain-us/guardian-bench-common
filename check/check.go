// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package check

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/vchain-us/guardian-bench-common/auditeval"
	"github.com/vchain-us/guardian-bench-common/log"
	"github.com/vchain-us/guardian-bench-common/multifind"
	"go.uber.org/zap"
)

// State is the state of a control check.
type State string

// AuditType is the type of audit to test.
type AuditType string

// TypeAudit string representing default "Audit".
const TypeAudit = "audit"

// Audit string that holds audit to execute with its environment
type Audit string

// Execute method called by the main logic to execute the Audit's Execute type.
func (audit Audit) Execute(env Environ, customConfig ...any) (result string, errMessage string, state State) {

	res, err := audit.run(env)

	// Errors mean the audit command failed, but that might be what we expect
	// for example, if we grep for something that is not found, there is a non-zero exit code
	// It is a problem if we can't find one of the audit commands to execute, but we deal
	// with this case in (c *Check) Run()
	if err != nil {
		errMessage = err.Error()
	}
	return string(res), errMessage, ""
}

const (
	// PASS check passed.
	PASS State = "PASS"
	// FAIL check failed.
	FAIL = "FAIL"
	// WARN could not carry out check.
	WARN = "WARN"
	// INFO informational message
	INFO = "INFO"
	// SKIP for when a check should be skipped.
	SKIP = "skip"
	// MANUAL for manual check type.
	MANUAL = "manual"
)

func handleError(err error, context string) (errmsg string) {
	if err != nil {
		errmsg = fmt.Sprintf("%s, error: %s\n", context, err)
	}
	return
}

// BaseCheck (Original version) - checks don't have sub checks, each check has only one sub check as part of the check itself
type BaseCheck struct {
	AuditType     AuditType           `json:"audit_type"`
	Audit         any                 `json:"audit"`
	Type          string              `json:"type"`
	Commands      []*exec.Cmd         `json:"-"`
	Tests         *auditeval.Tests    `json:"-"`
	Remediation   string              `json:"-"`
	Constraints   map[string][]string `yaml:"constraints"`
	auditer       Auditer
	customConfigs []any
	environ       *map[string]string
}

// SubCheck additional check to be performed.
type SubCheck struct {
	BaseCheck `yaml:"check"`
}

type AsyncTest func()

// Check contains information about a recommendation.
type Check struct {
	ID             string           `yaml:"id" json:"test_number"`
	Description    string           `json:"test_desc"`
	Text           string           `json:"-"`
	Set            bool             `json:"-"`
	SubChecks      []*SubCheck      `yaml:"sub_checks"`
	AuditType      AuditType        `json:"audit_type"`
	Audit          any              `json:"audit"`
	Type           string           `json:"type"`
	Commands       []*exec.Cmd      `json:"-"`
	Tests          *auditeval.Tests `json:"-"`
	Remediation    string           `json:"-"`
	TestInfo       []string         `json:"test_info"`
	State          `json:"status"`
	ActualValue    string `json:"actual_value"`
	ExpectedResult string `json:"expected_result"`
	Scored         bool   `json:"scored"`
	IsMultiple     bool   `yaml:"use_multiple_values"`
	auditer        Auditer
	customConfigs  []any
	Reason         string `json:"reason,omitempty"`
	environ        *map[string]string
	asyncOutput    string
	asyncTestFunc  AsyncTest
}

// Group is a collection of similar checks.
type Group struct {
	ID          string              `yaml:"id" json:"section"`
	Description string              `json:"desc"`
	Text        string              `json:"-"`
	Constraints map[string][]string `yaml:"constraints"`
	Type        string              `yaml:"type" json:"type"`
	Checks      []*Check            `json:"results"`
	Pass        int                 `json:"pass"` // Tests with no type that passed
	Fail        int                 `json:"fail"` // Tests with no type that failed
	Warn        int                 `json:"warn"` // Tests of type MANUAL won't be run and will be marked as Warn
	Info        int                 `json:"info"` // Tests of type skip won't be run and will be marked as Info
}

// Run executes the audit commands specified in a check and outputs
// the results.
func (c *Check) Run(definedConstraints map[string][]string, environ *map[string]string, mscan *multifind.Multiscanner) {
	logger, err := log.ZapLogger(nil, nil)
	if err != nil {
		panic(err)
	}
	defer logger.Sync() // nolint: errcheck

	logger.Info("----- Running check  ----- ", zap.String("check ID", c.ID))
	// If check type is skip, force result to INFO
	if c.Type == SKIP {
		c.Reason = "Test marked as skip"
		c.State = INFO
		logger.Info("Skipped", zap.String("Reason", c.Reason))
		return
	}

	// Since this is an Scored check
	// without tests return a 'WARN' to alert
	// the user that this check needs attention
	if len(strings.TrimSpace(c.Type)) == 0 && c.Tests == nil && c.SubChecks == nil {
		c.Reason = "There are no test items"
		c.State = WARN
		logger.Warn("Skipped", zap.String("Reason", c.Reason))
		return
	}

	var subCheck *BaseCheck
	if c.SubChecks == nil {
		subCheck = &BaseCheck{
			Commands:      c.Commands,
			Tests:         c.Tests,
			Type:          c.Type,
			Audit:         c.Audit,
			Remediation:   c.Remediation,
			AuditType:     c.AuditType,
			auditer:       c.auditer,
			customConfigs: c.customConfigs,
			environ:       environ,
		}
	} else {
		subCheck = getFirstValidSubCheck(c.SubChecks, definedConstraints)

		if subCheck == nil {
			c.Reason = "Failed to find a valid sub check, check your constraints "
			c.State = WARN
			logger.Debug("Failed to find a valid sub check, check your constraints")
			logger.Warn("Skipped", zap.String("Reason", c.Reason))
			return
		}
	}
	if c.Type == "" && subCheck != nil && subCheck.Type == MANUAL {
		c.Type = MANUAL
	}

	var out, errmsgs string

	t0 := time.Now()
	out, errmsgs, c.State = c.runAuditCommands(*subCheck, mscan)

	if errmsgs != "" {
		logger.Info("", zap.String("errmsgs", errmsgs))
		c.Reason = out
		// Make output more readable
		if (errmsgs == "exit status 127" || errmsgs == "exit status 1") && strings.HasSuffix(out, "not found\n") {
			c.Reason = strings.ReplaceAll(c.Reason, "sh: 1:", "Command")
			logger.Warn("Error in audit command", zap.String("Reason", c.Reason))
		}
	}
	finalOutput := c.evaluateTest(out, subCheck, logger)
	if c.State == "ASYNC" {
		c.asyncTestFunc = func() {
			c.evaluateTest(c.asyncOutput, subCheck, logger)
		}
		return
	}
	testResult := false
	if finalOutput != nil {
		testResult = finalOutput.TestResult
	}
	logger.Info("Done", zap.Bool("TestResult", testResult), zap.String("State", string(c.State)), zap.Duration("Duration", time.Since(t0)))
}

func (c *Check) evaluateTest(out string, subCheck *BaseCheck, logger *zap.Logger) *auditeval.TestOutput {
	//If check type is manual, force result to WARN
	if c.Type == MANUAL {
		c.ActualValue = removeUnicodeCharsKeepNewline(out)
		c.Reason = "Test marked as a manual test"
		c.State = WARN
		logger.Info("Manual", zap.String("Reason", c.Reason))
		return nil
	}

	if c.State != "" {
		return nil
	}

	finalOutput := subCheck.Tests.Execute(out, c.ID, c.IsMultiple)

	if finalOutput != nil {
		c.ActualValue = removeUnicodeChars(finalOutput.ActualResult)
		c.ExpectedResult = finalOutput.ExpectedResult

		if finalOutput.TestResult {
			c.State = PASS
		} else if c.Scored {
			c.State = FAIL
		} else {
			c.State = WARN
		}
	} else {
		c.State = WARN
		logger.Debug("Test output contains a nil value")
		c.Reason = "Test output contains a nil value"
		logger.Warn("", zap.String("Reason", c.Reason))
	}
	return finalOutput
}

// removeUnicodeChars remove non-printable characters from the output
func removeUnicodeChars(value string) string {
	cleanValue := strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, value)
	return cleanValue
}

// removeUnicodeCharsKeepNewline remove non-printable characters from the output, keeping newlines
func removeUnicodeCharsKeepNewline(value string) string {
	cleanValue := strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, value)
	return cleanValue
}

var _isBottleRocked *bool

func IsBottlerocket() (bool, error) {
	if _isBottleRocked != nil {
		return *_isBottleRocked, nil
	}
	retValue := false
	defer func() {
		_isBottleRocked = &retValue
	}()
	_, err := os.Stat("/etc/os-release")
	if err != nil && os.IsNotExist(err) {
		return retValue, nil
	}
	out, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return retValue, err
	}
	output := strings.ToLower(string(out))
	output = strings.ReplaceAll(output, `"`, "")
	output = strings.ReplaceAll(output, `_id`, "") // version_id kills the regex

	flagRe := regexp.MustCompile("id" + `=([^ \n]*)`)
	vals := flagRe.FindStringSubmatch(output)
	if len(vals) > 1 && vals[1] == "bottlerocket" {
		retValue = true
	}
	return retValue, nil
}

func (a *Audit) run(env Environ) (output string, err error) {
	var out bytes.Buffer

	logger, err := log.ZapLogger(nil, nil)
	if err != nil {
		panic(err)
	}
	defer logger.Sync() // nolint: errcheck

	audit := strings.TrimSpace(string(*a))
	if len(audit) == 0 {
		return output, err
	}
	var shellPath string
	isBR, err := IsBottlerocket()
	if err != nil {
		return "", err
	}
	if isBR {
		execPath, err := os.Executable()
		if err != nil {
			return "", err
		}
		binaryDir := filepath.Dir(execPath)
		shellPath = filepath.Join(binaryDir, "cfg", "bash")
	} else {
		shellPath = "/bin/sh"
	}
	cmd := exec.Command(shellPath)
	cmd.Stdin = strings.NewReader(audit)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if env != nil {
		for k, v := range *env {
			cmd.Env = append(cmd.Environ(), fmt.Sprintf("%s=%s", k, v))
		}
	}
	err = cmd.Run()
	output = out.String()

	if err != nil {
		err = fmt.Errorf("failed to run: %q, output: %q, error: %s", audit, output, err)
	} else {
		logger.Info("", zap.String("Command", audit))
		logger.Info("", zap.String("Output", output))
	}
	return output, err
}

func (cc *Check) runAuditCommands(bc BaseCheck, mscan *multifind.Multiscanner) (output, errMessage string, state State) {
	if bc.Type == "skip" {
		return output, errMessage, INFO
	}
	if bc.Type == "asyncfind" && bc.auditer != nil && mscan != nil {
		s, ok := bc.Audit.(string)
		if ok && strings.HasPrefix(s, "find ") {
			cc.addAsyncFind(bc, mscan, bc.environ)
			return "", "", "ASYNC"
		}
	}
	if bc.auditer != nil {
		if len(bc.customConfigs) == 0 {
			bc.customConfigs = append(bc.customConfigs, bc.Audit)
		}
		output, errMessage, state = bc.auditer.Execute(bc.environ, bc.customConfigs...)
	}
	// If check type is manual, force result to WARN.
	if bc.Type == MANUAL {
		return output, errMessage, WARN
	}
	return
}

func getFirstValidSubCheck(subChecks []*SubCheck, definedConstraints map[string][]string) (subCheck *BaseCheck) {
	for _, sc := range subChecks {
		isSubCheckOk := true

		for testConstraintKey, testConstraintVals := range sc.Constraints {

			isSubCheckOk = isSubCheckCompatible(testConstraintKey, testConstraintVals, definedConstraints)

			// If the sub check is not compatible with the constraints, move to the next one
			if !isSubCheckOk {
				break
			}
		}

		if isSubCheckOk {
			return &sc.BaseCheck
		}
	}

	return nil
}

func (cc *Check) addAsyncFind(bc BaseCheck, mscan *multifind.Multiscanner, env Environ) error {
	command, _ := bc.Audit.(string)
	parts := strings.SplitN(command, "|", 2)
	cmdline := strings.Split(parts[0], " ")
	if cmdline[0] != "find" || cmdline[1] != "$CIS_MOUNTPOINTS" {
		return fmt.Errorf("unknown asyncfind command")
	}
	fq := multifind.NewFindQuery()
	err := fq.ParseCommandLine(cmdline[2:])
	if err != nil {
		return err
	}
	ch := make(chan string, 10)
	mscan.AddScanner(fq, ch)
	go func() {
		trackAsync(ch, cc, fq.Separator)
		out, err := cc.finalizeAsyncAudit(bc, parts[1:], env)
		mscan.CloseWorker()
		if err != nil {
			logger, err2 := log.ZapLogger(nil, nil)
			if err2 != nil {
				panic(err2)
			}
			logger.Warn("ASYNC check fail", zap.String("ERROR", err.Error()))
			defer logger.Sync() // nolint: errcheck
		} else {
			cc.asyncOutput = out
		}
	}()
	return nil
}

func trackAsync(ch chan string, c *Check, sep byte) {
	output := make([]string, 0, 10)
	for {
		s := <-ch
		if s == "//" {
			break
		}
		output = append(output, s)
	}
	c.asyncOutput = strings.Join(output, string([]byte{sep}))
}

func (cc *Check) finalizeAsyncAudit(bc BaseCheck, cmdline []string, env Environ) (string, error) {
	var out bytes.Buffer
	execline := []string{"-c", strings.Join(cmdline, " ")}
	shellPath := "/bin/sh"
	cmd := exec.Command(shellPath, execline...)
	cmd.Stdin = strings.NewReader(cc.asyncOutput)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if env != nil {
		for k, v := range *env {
			cmd.Env = append(cmd.Environ(), fmt.Sprintf("%s=%s", k, v))
		}
	}
	err := cmd.Run()
	output := out.String()
	return output, err
}
func isSubCheckCompatible(testConstraintKey string, testConstraintVals []string, definedConstraints map[string][]string) bool {
	definedConstraintsVals := definedConstraints[testConstraintKey]

	// If the constraint's key is not defined - the check is not compatible
	if !(len(definedConstraintsVals) > 0) {
		return false
	}

	// For each constraint of the check under the specific key, check if its defined
	for _, val := range testConstraintVals {
		if contains(definedConstraintsVals, val) {
			return true
		}
	}

	return false
}

func contains(arr []string, obj string) bool {
	for _, val := range arr {
		if val == obj {
			return true
		}
	}

	return false
}
