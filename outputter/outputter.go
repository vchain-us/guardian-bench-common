package outputter

import (
	"fmt"

	"github.com/vchain-us/guardian-bench-common/check"
)

// Outputter represents the output strategy for Control objects
type Outputter interface {
	Output(controls *check.Controls, summary check.Summary) error
}

type outputFunc func(controls *check.Controls, summary check.Summary) error

func (f outputFunc) Output(controls *check.Controls, summary check.Summary) error {
	return f(controls, summary)
}

// Format of the output
type Format int

const (
	// JSONFormat send json output to console
	JSONFormat Format = iota + 10
	// PgSQLFormat send output to pgsql DB
	PgSQLFormat
	// JUnitFormat send JUnit output to the console
	JUnitFormat
	// ConsoleFormat send output console
	ConsoleFormat
)

// Config configuration for either JSON or Console outputter
type Config struct {
	Console
	Format   Format
	Filename string
}

// BuildOutputter builds a new outputter
func BuildOutputter(summary check.Summary, config *Config) Outputter {
	if summary.Fail > 0 || summary.Warn > 0 || summary.Pass > 0 || summary.Info > 0 {
		switch config.Format {
		case JSONFormat:
			return NewJSON(config.Filename)
		case JUnitFormat:
			return NewJUnit(config.Filename)
		}
	}

	return NewConsole(config.Console.NoRemediations, config.Console.IncludeTestOutput)
}

// BuildOutputterFunc useful extension point to add custom Outputters
func BuildOutputterFunc(op func(controls *check.Controls, summary check.Summary) error) (Outputter, error) {
	if op == nil {
		return nil, fmt.Errorf("BuildOutputterFunc: nil outputter")
	}

	return outputFunc(op), nil
}
