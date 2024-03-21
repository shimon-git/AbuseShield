package helpers

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/common-nighthawk/go-figure"
	e "github.com/shimon-git/AbuseShield/internal/errors"
)

const (
	Red           = "\033[31m"
	Green         = "\033[32m"
	RedBackground = "\033[41m"
	Yellow        = "\033[33m"
	GRAY          = "\033[90m"
	Reset         = "\033[0m"
)

func FileReader(ctx context.Context, ipFile string, dataChannel chan string) {
	readFile, err := os.Open(ipFile)
	if err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERR, ipFile), err))
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)

	for fileScanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
			dataChannel <- fileScanner.Text()
		}
	}

	if err := fileScanner.Err(); err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERR, ipFile), err))
	}

	defer close(dataChannel)
}

func GenerateDummyIP() string {
	// Create a new random number generator with a custom seed
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)

	// Generate random values for each octet
	octet1 := rand.Intn(224)
	octet2 := rand.Intn(256)
	octet3 := rand.Intn(256)
	octet4 := rand.Intn(256)

	return fmt.Sprintf("%d.%d.%d.%d", octet1, octet2, octet3, octet4)
}

type BasicAuth struct {
	User     string
	Password string
}

type HttpClient struct {
	Headers map[string]string
	Auth    BasicAuth
}

func (h *HttpClient) NewHttpClient() *http.Client {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: h,
	}
	return client
}

func (h *HttpClient) RoundTrip(req *http.Request) (*http.Response, error) {
	if h.Headers != nil {
		for k, v := range h.Headers {
			req.Header.Add(k, v)
		}
	}

	if h.Auth.User != "" || h.Auth.Password != "" {
		req.SetBasicAuth(h.Auth.User, h.Auth.Password)
	}

	return http.DefaultTransport.RoundTrip(req)
}

func UniqSlice(slice []string) []string {
	uniqMap := make(map[string]bool)
	result := make([]string, 0, len(slice))

	for _, v := range slice {
		if !uniqMap[v] {
			uniqMap[v] = true
			result = append(result, v)
		}
	}
	return result
}

// check whether file of folder are exist
func IsExist(path string, isFile bool) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	if isFile {
		return !info.IsDir()
	}
	return info.IsDir()
}

func FileWriter(file string, c chan string, wg *sync.WaitGroup, sharedErr *e.SharedError) {
	var err error
	var f *os.File
	defer wg.Done()
	if IsExist(file, true) {
		if err := os.Remove(file); err != nil {
			sharedErr.SetError(err)
			return
		}
	}
	pathParts := strings.Split(file, "/")
	folder := strings.Join(pathParts[0:len(pathParts)-1], "/")
	if !IsExist(folder, false) {
		if err := os.MkdirAll(folder, 0755); err != nil {
			sharedErr.SetError(e.MakeErr(e.CREATE_FOLDER_ERR, err))
			return
		}
	}

	f, err = os.Create(file)

	if err != nil {
		sharedErr.SetError(err)
		return
	}
	defer f.Close()

	// create a new writer
	writer := bufio.NewWriter(f)
	for line := range c {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			sharedErr.SetError(err)
			return
		}
	}
	if err := writer.Flush(); err != nil {
		sharedErr.SetError(err)
	}
}

func FormatIP(IP string) (string, int, error) {
	var subnet int
	var err error

	if strings.HasSuffix(IP, "/32") || strings.HasSuffix(IP, "/128") {
		IPParts := strings.Split(IP, "/")
		IP = IPParts[0]
		subnet, err = strconv.Atoi(IPParts[len(IPParts)-1])
		if err != nil {
			return "", 0, e.MakeErr(fmt.Sprintf("%s: %s", e.INVALID_IP_OR_NETWORK, IP), nil)
		}
	}

	// parse the ip and check if the given ip is valid
	ip := net.ParseIP(IP)
	if ip == nil {
		return "", 0, e.MakeErr(fmt.Sprintf("%s:%s -  The IP should have a subnet mask of /32 for ipv4 or /128 for ipv6, indicating a single IP address.", e.INVALID_IP_OR_NETWORK, IP), nil)
	}

	// check if the ip is version 4
	if ipv4 := ip.To4(); ipv4 != nil && (subnet == 32 || subnet == 0) {
		return ipv4.String(), 4, nil
	}

	if ipv6 := ip.To16(); ipv6 != nil && (subnet == 128 || subnet == 0) {
		return ipv6.String(), 6, nil
	}
	// return invalid ip error
	return "", 0, e.MakeErr(fmt.Sprintf("%s ,ip: %s", e.IP_IS_NOT_VALID, IP), nil)
}

func ColorPrint(message string, color string) {
	message = fmt.Sprintf("[+] %s", message)
	switch color {
	case "red":
		fmt.Print(Red + message + Reset)
	case "green":
		fmt.Print(Green + message + Reset)
	case "exclude":
		fmt.Print(Yellow, message, Reset)
	case "disable":
		fmt.Print(GRAY, message, Reset)
	case "error", "warning":
		fmt.Print(RedBackground + Yellow + message + Reset + "\n")
	}
}

func FilesLinesCounter(files []string) (int, error) {
	var lines int
	for _, fileName := range files {
		file, err := os.Open(fileName)
		if err != nil {
			return 0, e.MakeErr(fmt.Sprintf("%s: %s", e.OPEN_FILE_ERR, fileName), err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines++
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return 0, e.MakeErr(fmt.Sprintf("%s: %s", e.FILE_SCANNER_ERR, fileName), err)
		}
		if err := file.Close(); err != nil {
			return 0, e.MakeErr(fmt.Sprintf("%s: %s", e.CLOSE_FILE_ERR, fileName), err)
		}
	}
	// return nil error and lines number minus length of files slice because EOF is also calculated as line
	return lines, nil
}

func IsDomainExclude(domain string, excludedDomains []string) bool {
	for _, d := range excludedDomains {
		if strings.EqualFold(domain, d) {
			return true
		}
	}
	return false
}

func IsNetworkExclude(ipAddress string, networks []string) bool {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}
	for _, cidr := range networks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Println(err)
			continue
		}

		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func printBanner(text string, color string, dashLen int) {
	myFigure := figure.NewColorFigure(strings.Repeat("-", dashLen), "", color, true)
	myFigure.Print()
	myFigure = figure.NewColorFigure(text, "", color, true)
	myFigure.Print()
	myFigure = figure.NewColorFigure(strings.Repeat("-", dashLen), "", color, true)
	myFigure.Print()
}

func PrintHeader(logo string) {
	switch logo {
	case "abuse-shield":
		// print abuse shield header
		printBanner("Abuse - Shield", "blue", 12)
	case "abuseipdb":
		// print abuseipdb header
		printBanner("AbuseIPDB", "gray", 9)
	case "cpanel":
		// print cpanel header
		printBanner("Cpanel", "cyan", 6)
	case "csf":
		// print csf header
		printBanner("CSF", "gray", 3)
	case "sophos":
		// print sophos header
		printBanner("Sophos", "yellow", 6)
	}
}

func ExecuteCommand(stderr bool, cmdName string, args ...string) (string, int, error) {
	var exitCode int
	var output bytes.Buffer
	var err error
	var cmd *exec.Cmd

	if strings.Contains(cmdName, "|") {
		cmd = exec.Command("sh", "-c", cmdName)
	} else {
		cmd = exec.Command(cmdName, args...)
	}

	cmd.Stdout = &output
	if stderr {
		cmd.Stderr = &output
	}
	//cmd.Stderr = &output

	err = cmd.Run()
	if err != nil {
		return "", 0, e.MakeErr(e.COMMAND_EXECUTE_ERR, err)
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	}

	return output.String(), exitCode, err
}

func FindTextFiles(dir string) ([]string, error) {
	var textFiles []string

	files, err := os.ReadDir(dir)
	if err != nil {
		return textFiles, err
	}
	for _, file := range files {
		if !file.IsDir() {
			logFilePath := dir + "/" + file.Name()
			output, _, err := ExecuteCommand(true, "file", logFilePath)
			if err != nil {
				return textFiles, err
			}

			if strings.Contains(output, "ASCII text") {
				textFiles = append(textFiles, logFilePath)
			}
		}
	}

	return textFiles, nil
}

func CopyFile(source, destination string) error {
	if _, err := os.Stat(source); err != nil {
		return err
	}
	sFile, err := os.Open(source)
	if err != nil {
		return e.MakeErr(e.OPEN_FILE_ERR, err)
	}
	defer sFile.Close()

	dFile, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer dFile.Close()

	if _, err := io.Copy(dFile, sFile); err != nil {
		return err
	}

	return dFile.Sync()
}

func SearchAndReplace(file, search, replace string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	tempFile, err := os.CreateTemp("/tmp", ".abuse-shield")
	if err != nil {
		return err
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	scanner := bufio.NewScanner(f)
	writer := bufio.NewWriter(tempFile)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(strings.ReplaceAll(line, "\x20", ""), strings.ReplaceAll(search, "\x20", "")) {
			line = replace
		}

		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	// Close the files before renaming.
	f.Close()
	tempFile.Close()

	return CopyFile(tempFile.Name(), file)
}

func SearchRegex(file, regex string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	re := regexp.MustCompile(regex)
	for scanner.Scan() {
		line := scanner.Text()
		if re.MatchString(line) {
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				return matches[1], nil
			}
		}
	}
	return "", nil
}

// FileAppend appends text to a file, optionally ensuring that the text starts on a new line if the file
// does not end with a newline character and the `newline` parameter is true.
func FileAppend(file, text string, newline bool) error {
	// Open the file with both read and write permissions in append mode.
	f, err := os.OpenFile(file, os.O_APPEND|os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	if newline {
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		if fi.Size() > 0 {
			// Use a separate file descriptor for reading to avoid disrupting the write descriptor.
			fr, err := os.Open(file)
			if err != nil {
				return err
			}
			defer fr.Close()

			lastChar := make([]byte, 1)
			if _, err := fr.ReadAt(lastChar, fi.Size()-1); err != nil {
				return err
			}
			if lastChar[0] != '\n' {
				text = "\n" + text
			}
		}
	}

	// Append the text, ensuring it ends with a newline.
	_, err = f.WriteString(text + "\n")
	return err
}

// CountNonCommentLines reads a file and returns the count of lines that do not start with '#'.
func CountNonCommentLines(filePath string) (int, error) {
	// Open the file for reading.
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	// Use a scanner to read the file line by line.
	scanner := bufio.NewScanner(file)

	// Line count for lines not starting with '#'.
	count := 0

	for scanner.Scan() {
		line := scanner.Text()
		// Check if the line is not empty and does not start with '#'.
		if len(line) > 0 && line[0] != '#' {
			count++
		}
	}

	// Check for errors during scanning.
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return count, nil
}

func BroadcastChannel[T any](inputChan chan T, outputChans []chan T) {
	for data := range inputChan {
		for _, outChan := range outputChans {
			go func(c chan T, data T) {
				c <- data
			}(outChan, data)
		}
	}
	for _, outChan := range outputChans {
		close(outChan)
	}
}
