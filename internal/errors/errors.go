package abuse_shield_errors

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	OPEN_FILE_ERR                       = "Failed to open the file"
	CLOSE_FILE_ERR                      = "Failed to close the file"
	CREATE_FILE_ERR                     = "Failed to create the file"
	COPY_FILE_ERR                       = "Failed to copy the file"
	FILE_SCANNER_ERR                    = "An error occurred while scanning the file"
	CONFIG_READER_ERR                   = "Failed to read the config file"
	UNMARSHAL_ERR                       = "Failed to unmarshal"
	RETRIEVE_FILE_INFO_ERR              = "An error occurred while trying to retrieve the info of the file"
	IP_IS_NOT_VALID                     = "The given IP is not valid"
	INVALID_PHONE_NUMBER                = "The provided phone number is invalid"
	MISSING_IP_FILE                     = "Missing IP file, IP file must be provided"
	INVALID_MODE                        = "Invalid mode"
	MISSING_MODE                        = "Missing mode, mode must be set"
	HTTP_GET_ERR                        = "HTTP Get error"
	READ_RESPONSE_BODY_ERR              = "Error occurred while trying to read the response"
	INVALID_RESPONSE_CODE               = "Invalid response status code"
	MISSING_CPANEL_USERS                = "Cpanel users not provided"
	COMMAND_EXECUTE_ERR                 = "An error occurred while trying to execute the command"
	CPANEL_USER_NOT_FOUND               = "Cpanel user not found"
	REMOVE_FILE_ERR                     = "Failed to delete the file"
	INACTIVE_CSF_SERVICE                = "the csf service is inactive"
	MISSING_API_KEYS                    = "Missing API keys, API keys must be set"
	INVALID_API_KEY                     = "Invalid api key detected"
	EMPTY_REMAINING_CHECKS_HEADER       = "X-Ratelimit-Remaining header is empty, This may be occurred if the api key is not valid"
	NO_MODULES_ENABLED                  = "Modules are not enabled, At least one module must be enabled"
	ABUSE_DB_IP_NOT_ENABLED             = "AbuseDBIP module must be enabled in order to run cpanel or csf mode"
	CPANEL_IN_NOT_INSTALLED             = "Failed to verify if cpanel is installed, command: /usr/local/cpanel/cpanel"
	FAILED_TO_SET_CPANEL_ENV            = "Failed to set the following environment variables: LC_ALL=en_US.UTF-8, LANG=en_US.UTF-8, LANGUAGE=en_US.UTF-8"
	CPANEL_GET_USERS_LIST_ERR           = "Failed to retrieve cpanel users list"
	FILE_TYPE_CHECK_ERR                 = "Failed to check the file type"
	API_KEYS_LIMIT_HAS_BEEN_REACHED     = "Api keys for abuse ip db checks has been reached to the limit"
	CSF_FILE_NOT_FOUND                  = "Csf deny file not found"
	CPANEL_IP_FILE_NOT_FOUND            = "IP file output not found"
	CREATE_FOLDER_ERR                   = "Folder creation has been failed"
	DAILY_RATE_LIMIT_EXCEEDED_ABUSEIPDB = "requests exceeded for this endpoint"
	INVALID_IP_OR_NETWORK               = "Invalid ip/network"
	UNRESOLVABLE_DOMAIN                 = "Failed to resolve the domain"
	IPV6_AND_IPV4_NOT_ENABLED           = "IPv4 and IPv6 are not enabled, you must enable at least one ip version"
	UNKNOWN_CSF_IP_LIMIT                = "CSF ip limit is unknown and cannot be fined in csf configurations file"
	CSF_DENY_BACKUP_ERR                 = "failed to create csf.deny backup file"
)

type SharedError struct {
	err []error
	mu  sync.RWMutex
}

func NewSharedError() *SharedError {
	return &SharedError{}
}

func (s *SharedError) GetErrors() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *SharedError) SetError(e error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = append(s.err, e)
}

// MakeErr - return formatted error message with caller information
func MakeErr(message any, err error) error {
	callerInfo := getCallerInfo(2)
	errTime := time.Now().Format("2 Jan 2006 15:04:05")
	if message == nil && err != nil {
		return fmt.Errorf("[%s] %s - %s", errTime, callerInfo, err.Error())
	}
	if err == nil && message != nil {
		return fmt.Errorf("[%s] %s - %v", errTime, callerInfo, message)
	}
	if err == nil && message == nil {
		return fmt.Errorf("[%s] %s", errTime, callerInfo)
	}
	return fmt.Errorf("[%s] %s - %v: %s\n", errTime, callerInfo, message, err.Error())
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
