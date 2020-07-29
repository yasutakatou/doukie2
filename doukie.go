/*
 * multi platform, one binary, automated file transfer util by Golang.
 *
 * @author    yasutakatou
 * @copyright 2020 yasutakatou
 * @license   3-clause BSD License
 */
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	crt "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/c4pt0r/cfg"
	"github.com/dariubs/percent"

	qrcodeTerminal "github.com/Baozisoftware/qrcode-terminal-go"
	"github.com/nsf/termbox-go"
)

type Dialer struct {
	laddrIP string
	err     error
	dialer  *net.Dialer
}

type Data struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type responseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type hashTable struct {
	Filename    string `json:"Filename"`
	Hash        string `json:"Hash"`
	contentType string `json:"contentType"`
}

type syncLists struct {
	IP    string `json:"IP"`
	Count int    `json:"Count"`
}

type configData struct {
	autoSync  string `json:"autoSync"`
	autoPort  string `json:"autoPort"`
	autoCast  string `json:"autoCast"`
	autoDst   string `json:"autoDst"`
	dst       string `json:"dst"`
	wait      int    `json:"wait"`
	dir       string `json:"dir"`
	https     string `json:"https"`
	token     string `json:"token"`
	port      string `json:"port"`
	cert      string `json:"cert"`
	key       string `json:"key"`
	notDelete string `json:"notDelete"`
}

var (
	Hashs          = []hashTable{}
	bakHashs       = []hashTable{}
	rs1Letters     = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	Token          string
	HTTPS          string
	dataDir        string
	notDelete      string
	debug          bool
	clients        = []syncLists{}
	downloadCounts int
	totalCounts    int
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	var config configData

	err := termbox.Init()
	if err != nil {
		panic(err)
	}
	defer termbox.Close()
	termbox.Flush()

	if Exists(".doukie") == true {
		config = loadConfig(".doukie")
	}

	_autoSync := flag.String("auto", "", "[-auto=auto sync mode. encrypt password. (*important* You must use on trustly local network.)]")
	_autoPort := flag.String("autoPort", "", "[-port=port number for auto sync]")
	_autoCast := flag.String("autoCast", "", "[-autoCast=multicast address for auto sync]")
	_autoDst := flag.String("autoDst", "", "[-autoDst=auto sync client. decrypt password.]")
	_dst := flag.String("dst", "", "[-dst=destination mode on and access url.]")
	_wait := flag.Int("wait", 0, "[-wait=monitor cycle on server mode or sync cycle on destination mode]")
	_dir := flag.String("dir", "", "[-data=sync directory]")
	_debug := flag.Bool("debug", false, "[-debug=debug mode (true is enable)]")
	_https := flag.String("https", "", "[-https=https mode (yes or no. yes is enable)]")
	_token := flag.String("token", "", "[-token=authentication token (if this value is null, is set random)]")
	_port := flag.String("port", "", "[-port=port number]")
	_cert := flag.String("cert", "", "[-cert=ssl_certificate file path (if you don't use https, haven't to use this option)]")
	_key := flag.String("key", "", "[-key=ssl_certificate_key file path (if you don't use https, haven't to use this option)]")
	_notDelete := flag.String("notDelete", "", "[-notDelete=not delete mode (yes or no. yes is enable)]")

	flag.Parse()

	config.autoSync = setConfigString(string(*_autoSync), config.autoSync)
	config.autoPort = setConfigString(string(*_autoPort), config.autoPort)
	config.autoCast = setConfigString(string(*_autoCast), config.autoCast)
	config.autoDst = setConfigString(string(*_autoDst), config.autoDst)
	config.dst = setConfigString(string(*_dst), config.dst)
	config.wait = setConfigInt(int(*_wait), config.wait)
	config.dir = setConfigString(string(*_dir), config.dir)
	config.https = setYesNoString(string(*_https), config.https)
	config.token = setConfigString(string(*_token), config.token)
	config.port = setConfigString(string(*_port), config.port)
	config.cert = setConfigString(string(*_cert), config.cert)
	config.key = setConfigString(string(*_key), config.key)
	config.notDelete = setYesNoString(string(*_notDelete), config.notDelete)

	config = setDefault(config)

	OSDIR := ""
	if runtime.GOOS == "linux" {
		OSDIR = "/"
	} else {
		OSDIR = "\\"
	}
	prevDir, _ := filepath.Abs(".")
	dataDir = prevDir + OSDIR + string(config.dir)

	if Exists(dataDir) == false {
		fmt.Println("data folder is not found. and created.")
		if err := os.MkdirAll(dataDir, 0777); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if *_debug == true {
		fmt.Println("sync target: ", dataDir)
	}

	listUpFiles()

	HTTPS = config.https
	debug = bool(*_debug)
	Token = config.token
	notDelete = config.notDelete

	if Token == "" {
		Token = RandStr(8)
		config.token = Token
	}

	if debug == true {
		fmt.Println(" - - - options - - - ")
		fmt.Println("auto: ", config.autoSync)
		fmt.Println("autoPort: ", config.autoPort)
		fmt.Println("autoCast: ", config.autoCast)
		fmt.Println("autoDst: ", config.autoDst)
		fmt.Println("dst: ", config.dst)
		fmt.Println("wait: ", config.wait)
		fmt.Println("dir: ", config.dir)
		fmt.Println("debug: ", debug)
		fmt.Println("https: ", config.https)
		fmt.Println("token: ", config.token)
		fmt.Println("port: ", config.port)
		fmt.Println("cert: ", config.cert)
		fmt.Println("key: ", config.key)
		fmt.Println("notDelete: ", config.notDelete)
		fmt.Println(" - - - - - - - - - ")
	}

	if len(config.autoDst) > 0 {
		clientAutoSync(config.autoCast, config.autoDst, config.autoPort, config.wait)
	} else if len(config.dst) > 0 {
		startClient(config.dst+":"+config.port, config.wait)
	} else {
		go func() {
			clientsMonitor(config.wait)
		}()

		serverAutoSync(config.autoSync, config.autoCast, config.autoPort, config.port, config.wait)

		go func() {
			StartAPI(config.dir, config.port, config.cert, config.key)
		}()

		fmt.Println("access token: ", Token)
		if debug == true {
			fmt.Printf("Server listening on port %s.\n", config.port)
		}
		fmt.Println("[ Press enter or space key. QR Code display. Escape is exit.]")
		startServer(config.port)
	}

	writeConfig(".doukie", config)

	os.Exit(0)
}

func clientsMonitor(wait int) {
	for {
		fmt.Println(" -- -- clients and status -- -- ")
		for i := 0; i < len(clients); i++ {
			if totalCounts == totalCounts {
				if debug == true {
					fmt.Printf(" >> %s Sync done! <<\n", clients[i].IP)
				}
			} else {
				if clients[i].Count != 0 {
					fmt.Printf(" << %s Syncing [%3d%%] (%d/%d)>>\n", clients[i].IP, int(percent.PercentOf(clients[i].Count, totalCounts)), clients[i].Count, totalCounts)
				}
			}
		}
		fmt.Println(" -- -- -- -- -- -- -- -- -- -- ")
		time.Sleep(time.Duration(wait) * time.Second)
	}
}

func printDots(count int) {
	for i := 0; i < count; i++ {
		fmt.Printf(".")
	}
}

func setDefault(config configData) configData {
	if len(config.autoPort) == 0 {
		config.autoPort = "9999"
	}

	if len(config.autoCast) == 0 {
		config.autoCast = "224.0.0.1"
	}

	if config.wait == 0 {
		config.wait = 10
	}

	if len(config.dir) == 0 {
		config.dir = "data"
	}

	if len(config.https) == 0 {
		config.https = "no"
	}

	if len(config.port) == 0 {
		config.port = "8080"
	}

	if len(config.cert) == 0 {
		config.cert = "localhost.pem"
	}

	if len(config.key) == 0 {
		config.key = "localhost-key.pem"
	}

	if len(config.notDelete) == 0 {
		config.notDelete = "no"
	}

	return config
}

func setConfigString(stra, strb string) string {
	if len(stra) > 0 {
		return stra
	}
	return strb
}

func setYesNoString(stra, strb string) string {
	if stra == "yes" || stra == "no" {
		return stra
	}
	if strb == "yes" || strb == "no" {
		return strb
	}
	return ""
}

func setConfigInt(stra, strb int) int {
	if stra > 0 {
		return stra
	}
	return strb
}

func loadConfig(filename string) configData {
	var config configData
	var err error

	c := cfg.NewCfg(filename)
	if err := c.Load(); err != nil {
		fmt.Println(err)
	}

	config.autoSync, err = c.ReadString("autoSync", "")
	if err != nil {
		fmt.Println(err)
	}
	config.autoPort, _ = c.ReadString("autoPort", "")
	config.autoCast, _ = c.ReadString("autoCast", "")
	config.autoDst, _ = c.ReadString("autoDst", "")
	config.dst, _ = c.ReadString("dst", "")
	config.wait, _ = c.ReadInt("wait", 0)
	config.dir, _ = c.ReadString("dir", "")
	config.https, _ = c.ReadString("https", "")
	config.token, _ = c.ReadString("token", "")
	config.port, _ = c.ReadString("port", "")
	config.cert, _ = c.ReadString("cert", "")
	config.key, _ = c.ReadString("key", "")
	config.notDelete, _ = c.ReadString("notDelete", "")

	return config
}

func writeConfig(filename string, config configData) {
	c := cfg.NewCfg(filename)

	c.WriteString("autoSync", config.autoSync)
	c.WriteString("autoPort", config.autoPort)
	c.WriteString("autoCast", config.autoCast)
	c.WriteString("autoDst", config.autoDst)
	c.WriteString("dst", config.dst)
	c.WriteString("wait", strconv.Itoa(config.wait))
	c.WriteString("dir", config.dir)
	c.WriteString("https", config.https)
	c.WriteString("token", config.token)
	c.WriteString("port", config.port)
	c.WriteString("cert", config.cert)
	c.WriteString("key", config.key)
	c.WriteString("notDelete", config.notDelete)

	if err := c.Save(); err != nil {
		fmt.Println(err)
	}
}

func setTrueFalse(strs string) bool {
	if strs == "true" {
		return true
	}
	return false
}

func stringTrueFalse(val bool) string {
	if val == true {
		return "true"
	}
	return "false"
}

func serverAutoSync(server, autoCast, autoport, port string, wait int) {
	if len(server) > 0 {
		fmt.Println(" - - Server AUTO SYNC! - - ")
		go func() {
			iface, ipadress, err := getIFandIP()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			conn, err := DialFromInterface(iface).Dial("udp", autoCast+":"+autoport)
			if err != nil {
				fmt.Println(err)
			}
			defer conn.Close()

			for {
				pingData, err := encrypt(ipadress+":"+port+":"+Token, []byte(addSpace(string(server))))
				if err != nil {
					fmt.Println("error: ", err)
					os.Exit(1)
				}
				conn.Write([]byte(pingData))
				if debug == true {
					fmt.Println(" ping -> ", ipadress+":"+port+":"+Token)
				}
				time.Sleep(time.Duration(wait) * time.Second)
			}
		}()
	}
}

func clientAutoSync(cast, dst, port string, wait int) {
	fmt.Println(" - - Client AUTO SYNC! - - ")
	iface, _, err := getIFandIP()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	nwiface, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println("cast port init fail.")
		panic(err)
	}

	if debug == true {
		fmt.Println("Listen tick server at " + cast + ":" + port)
	}
	address, err := net.ResolveUDPAddr("udp", cast+":"+port)
	if err != nil {
		fmt.Println("cast port init fail.")
		panic(err)
	}

	termbox.SetInputMode(termbox.InputEsc)

	go func() {
		for {
			switch ev := termbox.PollEvent(); ev.Type {
			case termbox.EventKey:
				switch ev.Key {
				case 27: //Escape
					termbox.Flush()
					os.Exit(0)
				default:
				}
			}
		}
	}()

	listener, err := net.ListenMulticastUDP("udp", nwiface, address)
	//defer listener.Close()
	buffer := make([]byte, 1500)
	for {
		length, _, err := listener.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("cast packet error.")
			fmt.Println(err)
		}
		decodes, err := decrypt(string(buffer[:length]), []byte(addSpace(dst)))
		if err == nil {
			params := strings.Split(decodes, ":")
			if len(params) == 3 {
				if debug == true {
					fmt.Println(" pong <- ", decodes)
				}
				Token = params[2]
				startClient(params[0]+":"+params[1], wait)
				break
			}
		}
	}
}

func _error(_err error) {
	if _err != nil {
		panic(_err)
	}
}

func Exists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func getList(endpoint string) (string, string) {
	var body []byte
	var err error

	if debug == true {
		fmt.Println("request url: ", endpoint+"/"+Token+"/list/"+strconv.Itoa(downloadCounts))
	}
	req, err := http.NewRequest("GET", endpoint+"/"+Token+"/list/"+strconv.Itoa(downloadCounts), nil)

	if err != nil {
		fmt.Println(err)
		return "Error", "not send rest api " + endpoint
	}

	if HTTPS == "yes" {
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}

		client := &http.Client{
			Transport: http.DefaultClient.Transport,
		}
		resp, err := client.Do(req)
		//defer resp.Body.Close()
		if err != nil {
			fmt.Println("endpoint not found: " + endpoint + "/" + Token + "/list")
			return "", ""
		}

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "Error", "not send rest api " + endpoint
		}
	} else {
		client := new(http.Client)
		resp, err := client.Do(req)
		//defer resp.Body.Close()
		if err != nil {
			fmt.Println("endpoint not found: " + endpoint + "/" + Token + "/list")
			return "", ""
		}

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return "Error", "not send rest api " + endpoint
		}
	}

	var result Data
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("auth error: token is incorrect?")
		return "Error", "not send rest api " + endpoint
	}

	return result.Status, result.Message
}

func DownloadFile(urls, filename string) error {
	if Exists(dataDir) == false {
		if err := os.MkdirAll(dataDir, 0777); err != nil {
			fmt.Println(err)
			return err
		}
	}

	resp, err := http.Get(urls)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dataDir + filename)
	if err != nil {
		return err
	}
	defer out.Close()

	strs := StreamToString(resp.Body)

	sDec, err := base64.StdEncoding.DecodeString(strs)
	if err != nil {
		fmt.Printf("Error decoding string: %s ", err.Error())
		return err
	}

	out.Write(sDec)
	return nil
}

func StreamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.String()
}

func destMode(dst string, wait int) {
	if HTTPS == "yes" {
		dst = "https://" + dst
	} else {
		dst = "http://" + dst
	}

	for {
		Status, Message := getList(dst)
		if Status == "Success" {
			if doDownload(Message, dst) == true {
				fmt.Printf(" -- -- (%s) sync completely! -- -- \n", dst)
			}
		}
		time.Sleep(time.Duration(wait) * time.Second)
	}
}

func convOS(strs string) string {
	if runtime.GOOS == "linux" {
		return strings.Replace(strs, "\\", "/", -1)
	}
	return strings.Replace(strs, "/", "\\", -1)
}

func doDownload(Message, dst string) bool {
	var files []string

	compDownload := true
	files = nil
	stra := strings.Split(Message, ",")
	downloadCounts = 0

	for i := 0; i < len(stra); i++ {
		if len(stra[i]) > 1 {
			strb := strings.Split(stra[i], ":")
			if []byte(strb[0])[0] == 32 {
				strb[0] = strb[0][1:]
			}

			tmpFilename, err := base64.StdEncoding.DecodeString(strb[0])

			if err == nil {
				filename := convOS(string(tmpFilename))
				files = append(files, filename)

				if strb[2] == "dir" {
					if Exists(dataDir+filename) == false {
						if debug == true {
							fmt.Println("directory not exsits, and create! ", dataDir+filename)
						}
						if err := os.MkdirAll(dataDir+filename, 0777); err != nil {
							fmt.Println(err)
						}
					}
				} else {
					if Exists(dataDir+filename) == false {
						if debug == true {
							fmt.Println("not exsits download! ", dst+"/"+Token+"/download/"+filename)
						}
						DownloadFile(dst+"/"+Token+"/download/"+strb[0], filename)
						compDownload = false
					} else if strings.Index(strb[1], calcHash(dataDir+filename)) == -1 {
						if debug == true {
							fmt.Println("hash differ download! ", dst+"/"+Token+"/download/"+filename)
						}
						DownloadFile(dst+"/"+Token+"/download/"+strb[0], filename)
						compDownload = false
					} else {
						if debug == true {
							fmt.Println("same or exists: ", filename)
						}
						downloadCounts = downloadCounts + 1
					}
				}
			}

		}
	}
	if notDelete == "no" {
		dstFileRemove(files)
	}
	return compDownload
}

func dstFileRemove(lists []string) {
	listUpFiles()

	for i := 0; i < len(Hashs); i++ {
		tmpFilename, err := base64.StdEncoding.DecodeString(Hashs[i].Filename)
		if err == nil {
			filename := string(tmpFilename)
			fFlag := false
			for r := 0; r < len(lists); r++ {
				if filename == lists[r] {
					fFlag = true
				}
			}
			if fFlag == false && notDelete == "no" {
				if debug == true {
					fmt.Println("source not exists, remove: ", dataDir+filename)
				}
				if err := os.Remove(dataDir + filename); err != nil {
					fmt.Println(err)
				}
			}
		}
	}
}

func startClient(dst string, wait int) {
	termbox.SetInputMode(termbox.InputEsc)

	go func() {
		destMode(dst, wait)
	}()

	for {
		switch ev := termbox.PollEvent(); ev.Type {
		case termbox.EventKey:
			switch ev.Key {
			case 27: //Escape
				termbox.Flush()
				return
			default:
			}
		}
	}
}

func listUpFiles() {
	Hashs = nil

	files := listFiles()
	totalCounts = 0
	for i := 0; i < len(files); i++ {
		fInfo, _ := os.Stat(files[i])
		fileName := strings.Replace(files[i], dataDir, "", -1)
		if len(fileName) > 0 {
			if fInfo.IsDir() == true {
				if len(fileName) > 0 {
					if fileName[len(fileName)-1] == 92 {
						fileName = fileName[0 : len(fileName)-2]
					}

					Hashs = append(Hashs, hashTable{Filename: base64.StdEncoding.EncodeToString([]byte(fileName)), Hash: "", contentType: "dir"})
				}
			} else {
				mime, err := GetFileContentType(files[i])
				if err == nil {
					Hashs = append(Hashs, hashTable{Filename: base64.StdEncoding.EncodeToString([]byte(fileName)), Hash: calcHash(files[i]), contentType: mime})
					totalCounts = totalCounts + 1
				}
			}
		}
	}

	if compareSlice() == false {
		for i := 0; i < len(clients); i++ {
			clients[i].Count = 0
		}
		bakHashs = Hashs
	}

	if debug == true {
		for i := 0; i < len(Hashs); i++ {
			encryptData, _ := base64.URLEncoding.DecodeString(Hashs[i].Filename)
			fmt.Println("Filename: ", string(encryptData), "Hash: ", Hashs[i].Hash, "ContentType:", Hashs[i].contentType)
		}
	}
}

func compareSlice() bool {
	count := 0

	if len(Hashs) >= len(bakHashs) {
		count = len(bakHashs)
	} else {
		count = len(Hashs)
	}

	for i := 0; i < count; i++ {
		if Hashs[i].Filename != bakHashs[i].Filename {
			return false
		}
		if Hashs[i].Hash != bakHashs[i].Hash {
			return false
		}
		if Hashs[i].contentType != bakHashs[i].contentType {
			return false
		}
	}
	return true
}

func GetFileContentType(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Only the first 512 bytes are used to sniff the content type.
	buffer := make([]byte, 512)

	_, err = f.Read(buffer)
	if err != nil {
		return "", err
	}

	// Use the net/http package's handy DectectContentType function. Always returns a valid
	// content-type by returning "application/octet-stream" if no others seemed to match.
	contentType := http.DetectContentType(buffer)

	return contentType, nil
}

func StartAPI(dir, port, cert, key string) {
	http.HandleFunc("/"+Token+"/list/", listHandler)

	http.HandleFunc("/"+Token+"/download/", func(w http.ResponseWriter, r *http.Request) {
		Filename, err := base64.URLEncoding.DecodeString(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
		if err == nil {
			if debug == true {
				fmt.Println("download call: " + r.RemoteAddr + " " + string(Filename))
			}
			downloadHandler(w, r, dataDir+string(Filename))
		}
	})

	if HTTPS == "yes" {
		err := http.ListenAndServeTLS(":"+port, cert, key, nil)
		if err != nil {
			log.Fatal("ListenAndServeTLS: ", err)
		}
	} else {
		err := http.ListenAndServe(":"+port, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}
}

func downloadHandler(w http.ResponseWriter, r *http.Request, filename string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	cFlag := -1
	for i := 0; i < len(clients); i++ {
		if clients[i].IP == strings.Split(r.RemoteAddr, ":")[0] {
			cFlag = i
		}
	}

	if cFlag > -1 {
		clients[cFlag].Count = 3
	}

	// Open file on disk.
	f, _ := os.Open(filename)

	// Read entire JPG into byte slice.
	reader := bufio.NewReader(f)
	content, _ := ioutil.ReadAll(reader)

	// Encode as base64.
	encoded := base64.StdEncoding.EncodeToString(content)

	// Print encoded data to console.
	// ... The base64 image can be used as a data URI in a browser.
	w.Write([]byte(encoded))
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if debug == true {
		fmt.Println("list call: ", r.RemoteAddr)
	}

	listUpFiles()

	cFlag := -1
	for i := 0; i < len(clients); i++ {
		if clients[i].IP == strings.Split(r.RemoteAddr, ":")[0] {
			cFlag = i
		}
	}

	if cFlag == -1 {
		clients = append(clients, syncLists{IP: strings.Split(r.RemoteAddr, ":")[0], Count: 0})
	} else {
		tmp, err := strconv.Atoi(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
		if err == nil {
			clients[cFlag].Count = tmp
		}
	}

	lists := ""

	for i := 0; i < len(Hashs); i++ {
		lists = lists + Hashs[i].Filename + ":" + Hashs[i].Hash + ":" + Hashs[i].contentType + ", "
	}

	data := &responseData{Status: "Success", Message: lists}
	outputJson, err := json.Marshal(data)
	if err != nil {
		fmt.Println("%s")
		return
	}

	w.Write(outputJson)
}

func JsonResponseToByte(status, message string) []byte {
	data := &responseData{Status: status, Message: message}
	outputJson, err := json.Marshal(data)
	if err != nil {
		return []byte(fmt.Sprintf("%s", err))
	}
	return []byte(outputJson)
}

// FYI: https://gist.github.com/francoishill/a5aca2a7bd598ef5b563
func listFiles() []string {
	var files []string

	err := filepath.Walk(dataDir, func(path string, f os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil
	}
	return files
}

func startServer(port string) {
	termbox.SetInputMode(termbox.InputEsc)

	for {

		switch ev := termbox.PollEvent(); ev.Type {
		case termbox.EventKey:
			switch ev.Key {
			case 13, 32: //Enter, Space
				printQR(port)
			case 27: //Escape
				termbox.Flush()
				return
			default:
			}
		}
	}
}

func printQR(port string) {
	_, ip, err := getIFandIP()
	if err != nil {
		fmt.Println(err)
	} else {
		termbox.Flush()
		if debug == true {
			fmt.Println("source ip: ", ip, " port: ", port)
		}
		obj := qrcodeTerminal.New()
		URL := ""
		if HTTPS == "yes" {
			URL = "https://" + ip + ":" + port + "/" + Token
		} else {
			URL = "http://" + ip + ":" + port + "/" + Token
		}
		obj.Get(URL).Print()
	}
}

func RandStr(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = rs1Letters[rand.Intn(len(rs1Letters))]
	}
	return string(b)
}

func calcHash(filename string) string {
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func DialFromInterface(ifaceName string) *Dialer {
	d := &Dialer{}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		d.err = err
		return d
	}

	addres, err := iface.Addrs()
	if err != nil {
		d.err = err
		return d
	}

	var targetIP string
	for _, addr := range addres {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			d.err = err
			return d
		}
		if ip.IsUnspecified() {
			continue
		}
		if ip.To4().Equal(ip) {
			targetIP = ip.String()
		}
	}
	if targetIP == "" {
		d.err = fmt.Errorf("no ipv4 found for interface")
		return d
	}
	d.laddrIP = targetIP
	return d
}

func (d *Dialer) lookupAddr(network, addr string) (net.Addr, error) {
	if d.err != nil {
		return nil, d.err
	}

	if d.dialer == nil {
		d.dialer = &net.Dialer{}
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		addr, err := net.ResolveTCPAddr(network, d.laddrIP+":0")
		return addr, err
	case "udp", "udp4", "udp6":
		addr, err := net.ResolveUDPAddr(network, d.laddrIP+":0")
		return addr, err
	default:
		return nil, fmt.Errorf("unkown network")
	}
}

func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	laddr, err := d.lookupAddr(network, addr)
	if err != nil {
		return nil, err
	}
	d.dialer.LocalAddr = laddr
	return d.dialer.Dial(network, addr)
}

func (d *Dialer) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	laddr, err := d.lookupAddr(network, addr)
	if err != nil {
		return nil, err
	}
	d.dialer.Timeout = timeout
	d.dialer.LocalAddr = laddr
	return d.dialer.Dial(network, addr)
}

func (d *Dialer) WithDialer(dialer net.Dialer) *Dialer {
	d.dialer = &dialer
	return d
}

// FYI: https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func getIFandIP() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return iface.Name, ip.String(), nil
		}
	}
	return "", "", errors.New("are you connected to the network?")
}

// FYI: http://www.inanzzz.com/index.php/post/f3pe/data-encryption-and-decryption-with-a-secret-key-in-golang
// encrypt encrypts plain string with a secret key and returns encrypt string.
func encrypt(plainData string, secret []byte) (string, error) {
	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(crt.Reader, nonce); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plainData), nil)), nil
}

// decrypt decrypts encrypt string with a secret key and returns plain string.
func decrypt(encodedData string, secret []byte) (string, error) {
	encryptData, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		return "", err
	}

	cipherBlock, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	nonceSize := aead.NonceSize()
	if len(encryptData) < nonceSize {
		return "", err
	}

	nonce, cipherText := encryptData[:nonceSize], encryptData[nonceSize:]
	plainData, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainData), nil
}

func addSpace(strs string) string {
	for i := 0; len(strs) < 16; i++ {
		strs += "0"
	}
	return strs
}
