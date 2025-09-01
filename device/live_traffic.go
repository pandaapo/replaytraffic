package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/robfig/cron/v3"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	httputil "replaytraffic/utils/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	bufferSize            = 1000000
	timeout               = 5 * time.Second
	processTrafficLogFile = "process_live_traffic.log"
)

var (
	device               = flag.String("device", "eth1", "Network interface to capture traffic on")
	forwardURL           = flag.String("forwardURL", "http://localhost:8080", "URL to forward HTTP traffic to")
	logLevel             = flag.String("logLevel", "info", "Log level (error, warn, info, debug)")
	trafficLogTTL        = flag.String("trafficLogTTL", "7d", "Traffic Log TTL (e.g., 1d, 1h, 1m)")
	reqNumPerTrafficFile = flag.Int("rnptf", 10000, "Req Num Per TrafficFile")
	cronExpr             = flag.String("cron", "0 0 * * *", "Cron expression for scheduling the task")
)

var (
	// 重组数据包的缓存。key：srcIP + srcPort + destIP + destPort + ack num. value: []CachedPacket
	// []CachedPacket即一个重组的数据包的结构：[seq_0|len=0, seq_0|len>0, seq_1|len>0, seq_2|len>0, ... , seq_n|len>0|PSH]，第一个包是程序取的起始标志包，纯ACK包。有效的请求数据包从第二个包开始。中间的数据包也可能有PSH标志
	packetCache map[string]*[]CachedPacket
	// 解决一个请求中有多个PSH的情况。key: srcIP + srcPort + destIP + destPort + seq num. value: srcIP + srcPort + destIP + destPort + last ack num。value中的ack序号是key中的seq序号对应的数据包的上一个数据包的ack序号
	nextSeqMapLastAck map[string]ackNum
	// 解决一个请求中有多个PSH的情况。key: srcIP + srcPort + destIP + destPort + seq num. value: srcIP + srcPort + destIP + destPort + ack num。value中的ack序号是key中的seq序号对应的数据包的ack序号
	seqMapAck map[string]ackNum
	// 为加快过滤重复数据包速度创建的缓存。key: srcIP + srcPort + destIP + destPort + ack num. value: k-seq num, v-payload len.
	packetForbidRetranCache map[string]map[int]int
	// 用于判断是否为含有应用层协议的新请求。key：srcIP + srcPort + destIP + destPort + ack num. value: true
	packetHasNewAppLayer         map[string]bool
	packetCacheMutex             sync.RWMutex
	nextSeqMapLastAckMutex       sync.RWMutex
	seqMapAckMutex               sync.RWMutex
	packetForbidRetranCacheMutex sync.RWMutex
	packetHasNewAppLayerMutex    sync.RWMutex
	slogger                      *slog.Logger
	oldDur                       time.Duration
)

type ackNum struct {
	numStr    string
	timestamp time.Time
}
type CachedPacket struct {
	seq       int
	delta     int
	payload   string
	isPSH     bool
	timestamp time.Time
}

func main() {
	flag.Parse()
	initLogLevel()
	slogger.Info("Config parameters from flags", "device", *device, "forward to", *forwardURL, "runtime log level", *logLevel, "TTL of traffic log file", *trafficLogTTL, "max req num per traffic log file", *reqNumPerTrafficFile, "Cron expression", *cronExpr)
	err := parseDuration(*trafficLogTTL)
	if err != nil {
		slogger.Error("Parse trafficLogTTL param error", "err", err)
	}
	initCron()

	ctx, cancle := context.WithCancel(context.Background())
	defer cancle()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		slogger.Info("Received end signal")
		cancle()
		// 等待一段时间，确保清理完成
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	defer func() {
		if r := recover(); r != nil {
			slogger.Error("Main go routine panic", "err", r)
			cancle()
			// 等待一段时间，确保清理完成
			time.Sleep(3 * time.Second)
		}
	}()

	// Open the device for capturing
	handle, err := pcap.OpenLive(*device, bufferSize, true, timeout)
	if err != nil {
		slogger.Error("Error opening device", "error", err)
		log.Fatalf("Error opening device: %v", err)
	}
	defer handle.Close()

	// Create a packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	slogger.Info("Starting traffic capture on device", "device", *device)

	// 协程异常通道：用于协程panic或错误通知
	errCh := make(chan error, 10)
	go runWithRecover(ctx, cleanupCache, errCh)
	// 监听协程异常通道
	go func() {
		for err = range errCh {
			slogger.Error("Error occurs", "err", err)
			cancle()
		}
	}()

	// Loop through packets
	ex, _ := os.Executable()
	exePath := filepath.Dir(ex)
	reqNum := 0
	process_traffic_log := exePath + string(os.PathSeparator) + processTrafficLogFile
	f, err := os.Create(process_traffic_log)
	if err != nil {
		slogger.Error("IO error", "file", process_traffic_log, "err", err)
		log.Fatal(err)
	}
	fileIndex := 0
	packetCache = make(map[string]*[]CachedPacket)
	packetForbidRetranCache = make(map[string]map[int]int)
	packetHasNewAppLayer = make(map[string]bool)
	nextSeqMapLastAck = make(map[string]ackNum)
	seqMapAck = make(map[string]ackNum)
	for packet := range packetSource.Packets() {
		if reqNum >= *reqNumPerTrafficFile {
			reqNum = 0
			fileIndex += 1
			process_traffic_log = exePath + string(os.PathSeparator) + processTrafficLogFile + fmt.Sprintf("%d", fileIndex)
			f, err = os.Create(process_traffic_log)
			if err != nil {
				slogger.Error("IO error", "file", process_traffic_log, "err", err)
				log.Fatal(err)
			}
		}
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ip, _ := ipLayer.(*layers.IPv4)
			if ((ip.DstIP.Equal(net.ParseIP("192.168.0.1")) && tcp.DstPort == 20000) ||
				(ip.DstIP.Equal(net.ParseIP("192.168.0.2")) && tcp.DstPort == 23456) ||
				(ip.DstIP.Equal(net.ParseIP("192.168.0.2")) && tcp.DstPort == 22230)) && tcp.ACK {
				tranKey := getTransmissionKey(tcp, ip, int(tcp.Ack))
				payload := ""
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					payload = string(applicationLayer.Payload())
					_, exists := packetHasNewAppLayer[tranKey]
					if !exists {
						packetHasNewAppLayerMutex.Lock()
						packetHasNewAppLayer[tranKey] = true
						packetHasNewAppLayerMutex.Unlock()
						fmt.Fprintf(f, "\nnew app layer transmission. srcIP: %s, srcPort: %d, tcpIP: %s, tcpPort: %d, ack: %d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.Ack)
					}
				}
				exists := false
				packetCacheMutex.Lock()
				_, exists = packetCache[tranKey]
				if !exists {
					packetCache[tranKey] = &[]CachedPacket{}
					packetForbidRetranCacheMutex.Lock()
					packetForbidRetranCache[tranKey] = make(map[int]int)
					packetForbidRetranCacheMutex.Unlock()
					// 判断当前数据包的seq有没有出现在 nextSeqMapLastAck 缓存中，如果存在，表示该数据包tranKey虽然是新的，但是其实不是新的请求，而是之前未完成组包（即有多个PSH）的请求的一部分，所以将之前未完成的组包缓存[]CachedPacket追加进来。
					seqKey := getSeqKey(tcp, ip, int(tcp.Seq))
					nextSeqMapLastAckMutex.Lock()
					if ackNumStruc, exists2 := nextSeqMapLastAck[seqKey]; exists2 {
						oldTranKey := ackNumStruc.numStr
						if len(oldTranKey) > 0 && oldTranKey != tranKey {
							fmt.Fprintf(f, "\nnot fresh transmission. srcIP: %s, srcPort: %d, tcpIP: %s, tcpPort: %d, ack: %d, last tranKey: %s", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.Ack, oldTranKey)
							*packetCache[tranKey] = append(*packetCache[tranKey], *packetCache[oldTranKey]...)
							delete(packetCache, oldTranKey)
							delete(nextSeqMapLastAck, seqKey)
						}
					}
					nextSeqMapLastAckMutex.Unlock()
					seqMapAckMutex.Lock()
					// 缓存该数据包的seq -> ack，解决有多个PSH且乱序的情况，使得后发送的含PSH前序数据包能够找到先发送的含PSH的后序数据包。
					seqMapAck[seqKey] = ackNum{numStr: tranKey, timestamp: time.Now()}
					seqMapAckMutex.Unlock()
				}
				if cachedPackets, exists := packetCache[tranKey]; exists {
					seqExists := false
					// 防止重传的数据包
					packetForbidRetranCacheMutex.Lock()
					_, seqExists = packetForbidRetranCache[tranKey][int(tcp.Seq)]
					if seqExists && (len(tcp.Payload) == 0 || packetForbidRetranCache[tranKey][int(tcp.Seq)] == 0) {
						seqExists = false
					}
					packetForbidRetranCacheMutex.Unlock()
					if !seqExists {
						*cachedPackets = append(*cachedPackets, CachedPacket{
							seq:       int(tcp.Seq),
							delta:     len(tcp.Payload),
							payload:   payload,
							isPSH:     tcp.PSH,
							timestamp: time.Now(),
						})
						packetForbidRetranCacheMutex.Lock()
						packetForbidRetranCache[tranKey][int(tcp.Seq)] = len(tcp.Payload)
						packetForbidRetranCacheMutex.Unlock()
						sort.Slice(*cachedPackets, func(i, j int) bool {
							if (*cachedPackets)[i].seq == (*cachedPackets)[j].seq {
								return (*cachedPackets)[i].delta < (*cachedPackets)[j].delta
							} else {
								return (*cachedPackets)[i].seq < (*cachedPackets)[j].seq
							}
						})
						totalPayloadLength := 0
						for i, cp := range *cachedPackets {
							if i < len(*cachedPackets)-1 {
								totalPayloadLength += cp.delta
							}
						}
						if (*cachedPackets)[0].delta == 0 &&
							(*cachedPackets)[len(*cachedPackets)-1].isPSH &&
							(*cachedPackets)[len(*cachedPackets)-1].seq-(*cachedPackets)[0].seq == totalPayloadLength {
							httpstr := ""
							for _, cp := range *cachedPackets {
								httpstr += cp.payload
							}
							if strings.HasPrefix(httpstr, "POST") || strings.HasPrefix(httpstr, "GET") || strings.HasPrefix(httpstr, "PUT") || strings.HasPrefix(httpstr, "DELETE") || strings.HasPrefix(httpstr, "HEAD") || strings.HasPrefix(httpstr, "OPTIONS") || strings.HasPrefix(httpstr, "PATCH") {
								err = httputil.CheckRawReq(httpstr)
							} else if strings.HasPrefix(httpstr, "HTTP") {
								err = httputil.CheckRawResp(httpstr)
							} else {
								err = fmt.Errorf("unexpected error")
							}
							if err == nil {
								fmt.Fprintf(f, "\nStart=====================================================")
								fmt.Fprintf(f, "\n"+httpstr)
								fmt.Fprintf(f, "\nFinish. srcIP: %s, srcPort: %d, tcpIP: %s, tcpPort: %d, ack: %d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.Ack)
								delete(packetCache, tranKey)
								packetForbidRetranCacheMutex.Lock()
								packetHasNewAppLayerMutex.Lock()
								delete(packetForbidRetranCache, tranKey)
								delete(packetHasNewAppLayer, tranKey)
								packetForbidRetranCacheMutex.Unlock()
								packetHasNewAppLayerMutex.Unlock()
								reqNum++
								go forwardHTTPReq(httpstr, tranKey)
							} else {
								fmt.Fprintf(f, "\nTry=====================================================")
								fmt.Fprintf(f, "\n"+httpstr)
								fmt.Fprintf(f, "\nUnexpected error %v.", err)
								fmt.Fprintf(f, "\nFailed. srcIP: %s, srcPort: %d, tcpIP: %s, tcpPort: %d, ack: %d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, tcp.Ack)
								slogger.Error("Check packets error", "err", err, "tranKey", tranKey)

								if (*cachedPackets)[len(*cachedPackets)-1].isPSH {
									(*cachedPackets)[len(*cachedPackets)-1].isPSH = false
								}
								// 计算下一个数据包的seq
								nextSeq := (*cachedPackets)[len(*cachedPackets)-1].seq + (*cachedPackets)[len(*cachedPackets)-1].delta
								nextSeqKey := getSeqKey(tcp, ip, nextSeq)
								nextSeqMapLastAckMutex.Lock()
								lastAckKey, exists2 := nextSeqMapLastAck[nextSeqKey]
								if exists2 {
									fmt.Fprintf(f, "\nUnexpected reassembled error. nextSeq: %d, lastAckKey: %s", nextSeq, lastAckKey)
								} else {
									seqMapAckMutex.Lock()
									if ackNumStruc, exists3 := seqMapAck[nextSeqKey]; exists3 && ackNumStruc.numStr != tranKey {
										*packetCache[ackNumStruc.numStr] = append(*packetCache[ackNumStruc.numStr], *cachedPackets...)
										delete(packetCache, tranKey)
										packetForbidRetranCacheMutex.Lock()
										packetHasNewAppLayerMutex.Lock()
										delete(packetForbidRetranCache, tranKey)
										delete(packetHasNewAppLayer, tranKey)
										packetForbidRetranCacheMutex.Unlock()
										packetHasNewAppLayerMutex.Unlock()
										delete(seqMapAck, nextSeqKey)
									} else {
										nextSeqMapLastAck[nextSeqKey] = ackNum{numStr: tranKey, timestamp: time.Now()}
									}
									seqMapAckMutex.Unlock()
								}
								nextSeqMapLastAckMutex.Unlock()
							}
						}
					}
				}
				packetCacheMutex.Unlock()
			}
		}
	}
	slogger.Info("Ended traffic capture on device", "device", *device)
	var input string
	fmt.Scanln(&input)
	fmt.Println("You entered:", input)
}

// 带panic恢复的协程启动
func runWithRecover(ctx context.Context, fn func(), errCh chan<- error) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("panic in go routine: %v", r)
			}
		}()
		fn()
	}()
}

func execTcpdump(ctx context.Context) {
	filter := "tcp and (dst host 192.168.0.2 and (dst port 23456 or 22230)) or ((dst host 192.168.0.1 and dst port 20000))"
	cmd := exec.Command("tcpdump", "-i", *device, "-w", "r2r_traffic.pcap", "-C", "100", filter)
	err := cmd.Start()
	if err != nil {
		slogger.Error("Start tcpdump error", "err", err)
	}
	slogger.Info("tcpdump started, capturing packets...")

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		if err = cmd.Process.Kill(); err != nil {
			slogger.Error("Failed to kill tcpdump process", "err", err)
		}
		<-done
		slogger.Info("Successfully to kill tcpdump process")
	case err = <-done:
		if err != nil {
			slogger.Error("tcpdump ended exceptionally")
			os.Exit(1)
		} else {
			slogger.Info("tcpdump ended normally")
			os.Exit(0)
		}
	}
}

func getTransmissionKey(tcp *layers.TCP, ip *layers.IPv4, ack int) string {
	return fmt.Sprintf("%s:%d-%s:%d-ack:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, ack)
}

func getSeqKey(tcp *layers.TCP, ip *layers.IPv4, seq int) string {
	return fmt.Sprintf("%s:%d-%s:%d-seq:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, seq)
}

func cleanupCache() {
	for {
		time.Sleep(10 * time.Minute)
		packetCacheMutex.Lock()
		packetForbidRetranCacheMutex.Lock()
		packetHasNewAppLayerMutex.Lock()
		for key, cachedPackets := range packetCache {
			for _, cached := range *cachedPackets {
				if time.Since(cached.timestamp) > 15*time.Minute {
					delete(packetCache, key)
					delete(packetForbidRetranCache, key)
					delete(packetHasNewAppLayer, key)
					break
				}
			}
		}
		packetCacheMutex.Unlock()
		packetForbidRetranCacheMutex.Unlock()
		packetHasNewAppLayerMutex.Unlock()
		nextSeqMapLastAckMutex.Lock()
		for key, value := range nextSeqMapLastAck {
			if time.Since(value.timestamp) > 15*time.Minute {
				delete(nextSeqMapLastAck, key)
				break
			}

		}
		nextSeqMapLastAckMutex.Unlock()
		seqMapAckMutex.Lock()
		for key, value := range seqMapAck {
			if time.Since(value.timestamp) > 15*time.Minute {
				delete(seqMapAck, key)
				break
			}

		}
		seqMapAckMutex.Unlock()
	}
}

func initCron() {
	crn := cron.New()
	_, err := crn.AddFunc(*cronExpr, cleanupOldFiles)
	if err != nil {
		slogger.Error("Error adding cron job:", "cron", *cronExpr, "err", err)
		return
	}
	crn.Start()
	slogger.Info("Cron job started.", "cron", *cronExpr)
}

func cleanupOldFiles() {
	slogger.Info("Running cleanup task...")
	now := time.Now()
	oldTime := now.Add(-oldDur)
	ex, _ := os.Executable()
	exePath := filepath.Dir(ex)
	err := filepath.Walk(exePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			slogger.Error("Error accessing", "err", err)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasPrefix(info.Name(), processTrafficLogFile) {
			return nil
		}

		if info.ModTime().Before(oldTime) {
			slogger.Info("Deleting old file", "file", path)
			err := os.Remove(path)
			if err != nil {
				slogger.Error("Error deleting", "file", path, "err", err)
			}
		}
		return nil
	})

	if err != nil {
		slogger.Error("Error walking directory", "err", err)
	}
	slogger.Info("Cleanup task completed.")
}

func initLogLevel() {
	runtimeLogFile, err := os.OpenFile("runtime.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	multiHandler := slog.NewTextHandler(io.MultiWriter(runtimeLogFile, os.Stdout), nil)
	slogger = slog.New(multiHandler)
	slog.SetDefault(slogger)
	switch *logLevel {
	case "debug":
		slog.SetLogLoggerLevel(slog.LevelDebug)
	case "info":
		slog.SetLogLoggerLevel(slog.LevelInfo)
	case "warn":
		slog.SetLogLoggerLevel(slog.LevelWarn)
	case "error":
		slog.SetLogLoggerLevel(slog.LevelError)
	default:
		slog.SetLogLoggerLevel(slog.LevelError)
	}
}

func forwardHTTPReq(httpstr, tranKey string) {
	originReq, err := http.ReadRequest(bufio.NewReader(bytes.NewBufferString(httpstr)))
	if err != nil {
		slogger.Error("Resolve origin req from httpstr", "err", err, "tranKey", tranKey)
		return
	}
	defer originReq.Body.Close()

	reqBody := ""
	var extractBodyErr error
	if !strings.HasSuffix(httpstr, "\r\n\r\n") {
		reqBody, extractBodyErr = httputil.ExtractBody(httpstr)
		if extractBodyErr != nil {
			slogger.Error("Extract HTTP request body error", "err", extractBodyErr, "tranKey", tranKey)
			return
		}
	}
	index := strings.Index(httpstr, " ")
	method := httpstr[:index]
	payload := ternary(reqBody != "", []byte(reqBody), nil)

	req, err := http.NewRequest(method, *forwardURL, bytes.NewBuffer(payload))
	if err != nil {
		slogger.Error("Error build new req", "err", err, "tranKey", tranKey)
		return
	}

	req.Header = originReq.Header.Clone()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		slogger.Error("Error forwarding HTTP req", "err", err, "tranKey", tranKey)
		return
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slogger.Error("Error closing HTTP response body", "err", err, "tranKey", tranKey)
		}
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slogger.Error("Read body error after forward HTTP req", "err", err, "tranKey", tranKey)
	}
	slogger.Info("Resp after forward HTTP req, resp", "resp", resp, "body", body, "tranKey", tranKey)
}

func ternary[T any](condition bool, value1, value2 T) T {
	if condition {
		return value1
	}
	return value2
}

func parseDuration(s string) error {
	s = strings.ToLower(s)
	numStr := s[:len(s)-1]

	num, err := strconv.Atoi(numStr)
	if err != nil {
		return fmt.Errorf("invalid duration format: %w", err)
	}

	unit := s[len(s)-1:]
	switch unit {
	case "d":
		oldDur = time.Duration(num) * 24 * time.Hour
	case "h":
		oldDur = time.Duration(num) * time.Hour
	case "m":
		oldDur = time.Duration(num) * time.Minute
	default:
		oldDur = 7 * 24 * time.Hour
	}
	return nil
}
