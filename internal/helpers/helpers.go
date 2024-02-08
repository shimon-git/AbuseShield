package helpers

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	e "github.com/shimon-git/AbuseShield/internal/errors"
)

const (
	Red           = "\033[31m"
	Green         = "\033[32m"
	RedBackground = "\033[41m"
	Yellow        = "\033[33m"
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

func FileWriter(file string, override bool, c chan string, wg *sync.WaitGroup, sharedErr *e.SharedError) {
	var err error
	var f *os.File
	defer wg.Done()
	if IsExist(file, true) && override {
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
	if !IsExist(file, true) {
		f, err = os.Create(file)
	} else {
		f, err = os.OpenFile(file, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	}
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
	switch color {
	case "red":
		fmt.Print(Red + message + Reset)
	case "green":
		fmt.Print(Green + message + Reset)
	case "exclude":
		fmt.Print(Yellow, message, Reset)
	case "error":
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
	return lines - len(files), nil
}

func IsDomainExclude(domain string, excludedDomains []string) bool {
	for _, d := range excludedDomains {
		if strings.ToLower(domain) == strings.ToLower(d) {
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
