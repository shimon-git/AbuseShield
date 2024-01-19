package abuse_shield_errors

import (
	"fmt"
	"runtime"
	"strings"
)

const (
	OPEN_FILE_ERR          = "Failed to open the file"
	FILE_SCANNER_ERR       = "An error occurred while scanning the file"
	CONFIG_READER_ERR      = "Failed to read the config file"
	UNMARSHAL_ERR          = "Failed to unmarshal"
	RETRIEVE_FILE_INFO_ERR = "An error occurred while tying to retrieve the info of the file"
	IP_IS_NOT_VALID        = "The given IP is not valid"
	INVALID_PHONE_NUMBER   = "The provided phone number is invalid"
	MISSING_IP_FILE        = "Missing IP file, IP file must be provided"
	INVALID_MODE           = "Invalid mode"
	MISSING_MODE           = "Missing mode"
)

// MakeErr - return formatted error message with caller information
func MakeErr(message any, err error) error {
	callerInfo := getCallerInfo(2)
	if message == nil && err != nil {
		return fmt.Errorf("%s - %s", callerInfo, err.Error())
	}
	if err == nil && message != nil {
		return fmt.Errorf("%s - %v", callerInfo, message)
	}
	if err == nil && message == nil {
		return fmt.Errorf("%s", callerInfo)
	}
	return fmt.Errorf("%s - %v: %s\n", callerInfo, message, err.Error())
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
