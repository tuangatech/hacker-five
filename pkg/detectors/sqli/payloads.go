package sqli

import "regexp"

// errorPayloads are appended to a param's existing value to try to break
// its surrounding SQL syntax. Deliberately small (CLAUDE.md's "not a
// fuzzing engine" discipline) — covers the quoting/comment styles that
// actually surface a DBMS error across MySQL/PostgreSQL/MSSQL/Oracle/SQLite,
// not every known bypass.
var errorPayloads = []string{
	`'`,
	`"`,
	`')`,
	`' AND '1'='1`,
}

// errorPatterns are recognizable DBMS error signatures — seen in a response
// to an errorPayloads probe but absent from the baseline, these are a
// strong, low-FP signal (a generic app error page doesn't coincidentally
// carry "ORA-01756" or "pg_query()"). Curated from the same well-known
// signature families sqlmap/OWASP testing guides document; narrow and
// DBMS-attributed per CLAUDE.md's "flag doubtful matchers instead of
// guessing."
var errorPatterns = []struct {
	dbms string
	re   *regexp.Regexp
}{
	{"MySQL/MariaDB", regexp.MustCompile(`(?i)SQL syntax.*MySQL|Warning.*mysqli?_|MySQLSyntaxErrorException|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)PostgreSQL.*ERROR|pg_query\(\)|pg_exec\(\)|PSQLException|org\.postgresql\.util\.PSQLException`)},
	{"MSSQL", regexp.MustCompile(`(?i)Unclosed quotation mark after the character string|Microsoft SQL (Native Client|Server)|SqlException|System\.Data\.SqlClient|SQLServer JDBC Driver`)},
	{"Oracle", regexp.MustCompile(`\bORA-[0-9]{4,5}\b|(?i)Oracle error|Oracle.*Driver`)},
	{"SQLite", regexp.MustCompile(`(?i)SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|sqlite3\.OperationalError|SQLITE_ERROR`)},
	{"Generic", regexp.MustCompile(`(?i)unclosed quotation mark|quoted string not properly terminated|incorrect syntax near|syntax error at or near|you have an error in your sql syntax`)},
}

// matchedErrorPattern returns the first errorPatterns entry found in body,
// or "" if none match.
func matchedErrorPattern(body []byte) string {
	s := string(body)
	for _, p := range errorPatterns {
		if p.re.MatchString(s) {
			return p.dbms
		}
	}
	return ""
}

// booleanPair is one tautology/negation payload pair for the boolean-based
// blind check. Each suffix is comment-terminated ("-- -") so any trailing
// literal the original query expected after the value (a closing quote, a
// LIMIT clause) is neutralized rather than breaking the query outright —
// the same reasoning real boolean-blind SQLi payloads use.
type booleanPair struct {
	name        string
	trueSuffix  string
	falseSuffix string
}

var booleanPairs = []booleanPair{
	{"numeric", " AND 1=1-- -", " AND 1=2-- -"},
	{"string", "' AND '1'='1'-- -", "' AND '1'='2'-- -"},
}

// timePayload is one DBMS-specific sleep payload for the time-based blind
// check. seconds must match the literal delay encoded in suffix.
type timePayload struct {
	dbms    string
	suffix  string
	seconds float64
}

var timePayloads = []timePayload{
	{"MySQL/PostgreSQL", "' AND SLEEP(5)-- -", 5},
	{"MSSQL", "'; WAITFOR DELAY '0:0:5'-- -", 5},
}
