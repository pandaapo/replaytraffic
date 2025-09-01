package http

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// 定义一个映射，包含所有有效的 HTTP 方法
var validMethods = map[string]bool{
	"GET":     true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"PATCH":   true,
	"HEAD":    true,
	"OPTIONS": true,
	"CONNECT": true,
	"TRACE":   true,
}

// CheckRawReq 解析request数据包
func CheckRawReq(rawRequest string) error {
	//rawRequest = strings.ReplaceAll(rawRequest, "\r\n", "\n")
	// 分割请求行和请求头
	parts := strings.SplitN(rawRequest, "\r\n\r\n", 2)
	if len(parts) < 1 && !strings.HasPrefix(rawRequest, "GET") && !strings.HasPrefix(rawRequest, "HEAD") && !strings.HasPrefix(rawRequest, "DELETE") && !strings.HasPrefix(rawRequest, "OPTIONS") {
		return fmt.Errorf("request line and request header is not complete. Wait for more data")
	} else if len(parts) < 2 {
		return fmt.Errorf("request line and request header is not complete. Wait for more data")
	}

	requestLine := parts[0]
	// 分割出请求行中的前两个部分
	requestLineParts := strings.SplitN(requestLine, " ", 3)
	if len(requestLineParts) < 3 {
		return fmt.Errorf("the first two parts of request line is not complete. Wait for more data")
	}

	method := requestLineParts[0]
	// 校验 METHOD
	if !validMethods[method] {
		return fmt.Errorf("invalid method: %s", method)
	}

	headerPart := requestLineParts[2]
	err, contentLen := getReqContentLength(headerPart)
	if err != nil {
		return err
	}

	// 解析请求体
	isMethodWithBody := method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" || method == "OPTIONS"
	if isMethodWithBody {
		if len(parts) != 2 &&
			(method == "POST" || method == "PUT" || method == "PATCH" || ((method == "DELETE" || method == "OPTIONS") && contentLen > 0)) {
			return fmt.Errorf("invalid raw request format as no body")
		}
		bodyPart := parts[1]
		if contentLen > 0 && contentLen != len([]byte(bodyPart)) && !strings.HasSuffix(bodyPart, "</soap:Envelope>") {
			return fmt.Errorf("need more request content")
		}
	}

	return nil
}

// FIXME header会不会发生拆包，如果会发生可能取不到Content-Length
// 获取request的content length
func getReqContentLength(headerPart string) (error, int) {
	lines := strings.Split(headerPart, "\r\n")
	contentLen := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 忽略空行和 HTTP 版本行
		if len(line) <= 0 || strings.HasPrefix(line, "HTTP/") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		headerName := parts[0]
		if len(parts) < 2 {
			continue
		}

		headerValue := strings.TrimSpace(parts[1])
		if headerName == "Content-Length" {
			contentLength, err := strconv.Atoi(headerValue)
			if err != nil {
				return err, 0
			}
			contentLen = contentLength
		}
	}
	return nil, contentLen
}

func IsNewHTTPReqOrRespPacket(httpstr string) (success bool, httpString string) {
	// 定义正则表达式，匹配 HTTP 请求行
	re := regexp.MustCompile(`(?m)^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^ ]+ HTTP/[0-9]+\.[0-9]+`)
	matches := re.FindAllString(httpstr, -1)
	if len(matches) > 0 {
		// 找到匹配项后，我们可以获取匹配项后面剩余的字符串
		httpstr = httpstr[strings.Index(httpstr, matches[0]):]
		return true, httpstr
	}

	// 定义正则表达式，匹配 HTTP 响应行
	re = regexp.MustCompile(`(?m)^HTTP/[0-9]+\.[0-9]+ \d{3}`)
	matches = re.FindAllString(httpstr, -1)
	if len(matches) > 0 {
		// 找到匹配项后，我们可以获取匹配项后面剩余的字符串
		httpstr = httpstr[strings.Index(httpstr, matches[0]):]
		return true, httpstr
	}
	return false, ""
}

func CheckRawResp(rawResp string) error {
	// 分割状态行+响应头 和 响应体
	parts := strings.SplitN(rawResp, "\r\n\r\n", 2)
	if len(parts) < 2 {
		return fmt.Errorf("response is not complete. Wait for more data")
	}
	respLine := parts[0]
	// 分割状态行 和 响应头
	stateLineHeaderParts := strings.SplitN(respLine, "\r\n", 2)
	if len(stateLineHeaderParts) < 2 {
		return fmt.Errorf("state line and header is not complete. Wait for more data")
	}
	// 分割状态行中的各个部分
	stateLine := stateLineHeaderParts[0]
	stateLineParts := strings.SplitN(stateLine, " ", 3)
	if len(stateLineParts) < 3 {
		return fmt.Errorf("state line is not complete. Wait for more data")
	}
	httpVersion := stateLineParts[0]
	if !strings.HasPrefix(httpVersion, "HTTP") {
		return fmt.Errorf("invaild response http version")
	}
	statusCode := stateLineParts[1]
	var status int
	var err error
	if status, err = strconv.Atoi(statusCode); err != nil {
		return fmt.Errorf("invaild response status type")
	}
	if status < 100 || status > 599 {
		return fmt.Errorf("invaild response status num")
	}
	contentLen, err := getRespContentLength(stateLineHeaderParts[1])
	if err != nil {
		return fmt.Errorf("can not get content length, %v", err)
	}
	bodyPart := parts[1]
	if contentLen != len([]byte(bodyPart)) && !strings.HasSuffix(bodyPart, "</soap:Envelope>") {
		return fmt.Errorf("need more response content")
	}
	return nil
}

// 获取response的content length
func getRespContentLength(header string) (int, error) {
	lines := strings.Split(header, "\r\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			continue
		}
		headerName := parts[0]
		headerValue := strings.TrimSpace(parts[1])
		if headerName == "Content-Length" {
			contentLength, err := strconv.Atoi(headerValue)
			if err != nil {
				return 0, err
			}
			return contentLength, nil
		}
	}
	return 0, fmt.Errorf("can not get Content-Length header")
}

func ExtractBody(rawRequest string) (string, error) {
	parts := strings.SplitN(rawRequest, "\r\n\r\n", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid raw request format")
	}
	return parts[1], nil
}
