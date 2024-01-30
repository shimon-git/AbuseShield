package helpers

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	e "github.com/shimon-git/AbuseShield/internal/errors"
)

const (
	Red           = "\033[31m"
	Green         = "\033[32m"
	RedBackground = "\033[41m"
	Reset         = "\033[0m"
)

func IPFileReader(ipFile string, dataChannel chan string) {
	readFile, err := os.Open(ipFile)
	if err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERR, ipFile), err))
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)

	for fileScanner.Scan() {
		dataChannel <- fileScanner.Text()
	}

	if err := fileScanner.Err(); err != nil {
		log.Fatal(e.MakeErr(fmt.Sprintf("%s: %s\n", e.FILE_SCANNER_ERR, ipFile), err))
	}

	defer SafeChannelClose(dataChannel)
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
	fmt.Println()
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

func SafeChannelClose(ch chan string) {
	defer func() {
		if recover() != nil {
			return
		}
	}()
	close(ch)
}

func FormatIP(IP string) (string, error) {
	// check if the given ip has a prefix
	if !strings.Contains(IP, "/") {
		return IP, nil
	}
	// parse the cidr
	ip, _, err := net.ParseCIDR(IP)
	if err != nil {
		return "", err
	}

	// check if the ip is version 4
	if ipv4 := ip.To4(); ipv4 != nil {
		// if the given ip ends with /32 then return only the ip without the /32 suffix
		if strings.HasSuffix(IP, "/32") {
			return ipv4.String(), nil
		}
		// if the ip dose not have a suffix of /32 return the ip with the suffix
		return IP, nil
	} else if ipv6 := ip.To16(); ipv6 != nil {
		if strings.HasSuffix(IP, "/128") {
			return ipv6.String(), nil
		}
		return IP, nil
	}
	// return invalid ip error
	return "", e.MakeErr(fmt.Sprintf("%s ,ip: %s", e.IP_IS_NOT_VALID, IP), nil)
}

func ColorPrint(message string, color string) {
	switch color {
	case "red":
		fmt.Println(Red + message + Reset)
	case "green":
		fmt.Println(Green + message + Reset)
	case "error":
		fmt.Println(RedBackground + message + Reset)
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
