package abuse_checker_errors

import (
	"fmt"
	"reflect"
	"runtime"
	"strings"
)

const (
	OPEN_FILE_ERR      = "Failed to open the file"
	FILE_SCANNER_ERROR = "An error occurred while scanning the file"
)

// MakeErr - return formatted error message with caller information
func MakeErr(message any, err error) error {
	if message == nil || reflect.TypeOf(message).Kind() != reflect.String {
		return fmt.Errorf("%s - %s", getCallerInfo(2), err)
	}
	return fmt.Errorf("%s - %s: %s\n", getCallerInfo(2), message, err)
}

// getCallerInfo - return details about the function which the error was occurred - format: filename:lineno:function
func getCallerInfo(depth int) string {
	// Get information about the calling function
	pc, file, line, ok := runtime.Caller(depth)
	// If Caller function couldn't retrieve information
	if !ok {
		return ""
	}

	// Retrieve the function name
	fnName := runtime.FuncForPC(pc).Name()

	// Extract only the file name from the full file path
	fileNameParts := strings.Split(file, "/")
	fileName := fileNameParts[len(fileNameParts)-1]

	// Extract only the function name from the full function path
	fnNameParts := strings.Split(fnName, ".")
	fnOnly := fnNameParts[len(fnNameParts)-1]

	// Format the result as "filename:lineno:function"
	result := fmt.Sprintf("file: %s - line: %d - function: %s", fileName, line, fnOnly)

	return result
}
