package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// loadDotEnv reads a .env file from the current working directory, if one
// exists, and applies each KEY=VALUE line via os.Setenv — a real env var
// already set always wins (dotenv's own standard precedence), so `.env` is
// purely a convenience default, never an override of an operator's explicit
// environment. Applies to every subcommand (scan/serve/mcp-serve/...) since
// it runs once here in main, before Cobra parses anything — not a
// dependency: reading KEY=VALUE lines is a handful of lines of stdlib code,
// and CLAUDE.md's dependency discipline (see docs/02-architecture-and-
// tech-stack.md §8's interactsh-client lesson) argues against pulling in a
// library for this.
//
// No file is not an error — most invocations (CI, an operator who already
// exports real env vars, `.env` simply not created yet) never have one.
// A malformed line is a warning to stderr, not fatal — one bad line
// shouldn't block every subcommand from running.
func loadDotEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return // no .env in the working directory — the common case, not an error
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := parseDotEnvLine(line)
		if !ok {
			fmt.Fprintf(os.Stderr, ".env:%d: skipping malformed line (want KEY=VALUE): %q\n", lineNum, line)
			continue
		}
		if _, alreadySet := os.LookupEnv(key); alreadySet {
			continue // a real environment variable always wins over .env
		}
		_ = os.Setenv(key, value)
	}
}

// parseDotEnvLine splits "KEY=VALUE" (optionally "export KEY=VALUE", and an
// optionally single/double-quoted VALUE) into key/value. Deliberately
// minimal — no variable interpolation, no multi-line values; every env var
// this project actually reads (HACKERFIVE_AUTH_TOKEN, OPENROUTER_API_KEY,
// etc.) is a single plain token.
func parseDotEnvLine(line string) (key, value string, ok bool) {
	line = strings.TrimPrefix(line, "export ")
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:idx])
	value = strings.TrimSpace(line[idx+1:])
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	return key, value, true
}
