// msgcodec.go
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/klauspost/compress/zstd"
)

var (
	hexStr    = flag.String("hex", "", "十六进制输入（解码模式）")
	text      = flag.String("text", "", "原文输入（编码模式）")
	filePath  = flag.String("f", "", "输入文件路径（解码：hex；编码：text）")
	clipboard = flag.Bool("clipboard", false, "从剪贴板读取")
	encode    = flag.Bool("encode", false, "开启编码模式：文本->十六进制")
	compress  = flag.Bool("zstd", false, "编码时开启 zstd 压缩（会自动带上 zstd 魔数）")
)

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

func main() {
	flag.Parse()
	if *encode {
		runEncode()
	} else {
		runDecode()
	}
}

func runEncode() {
	data, err := readText()
	if err != nil {
		log.Fatal(err)
	}

	if *compress {
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			log.Fatalf("初始化 zstd 失败: %v", err)
		}
		defer enc.Close()
		data = enc.EncodeAll(data, nil)
	}

	fmt.Println(strings.ToLower(hex.EncodeToString(data)))
}

func runDecode() {
	data, err := readHex()
	if err != nil {
		log.Fatal(err)
	}
	out := data
	if bytes.HasPrefix(data, zstdMagic) {
		dec, err := zstd.NewReader(nil)
		if err != nil {
			log.Fatal(err)
		}
		defer dec.Close()
		out, err = dec.DecodeAll(data, nil)
		if err != nil {
			log.Fatalf("zstd 解压失败: %v", err)
		}
		fmt.Println("[zstd 解压结果]")
	} else {
		fmt.Println("[原始字节 interpreted as UTF-8]")
	}
	fmt.Println(string(out))
}

func readHex() ([]byte, error) {
	switch {
	case *hexStr != "":
		return parseHex(*hexStr)
	case *filePath != "":
		b, err := os.ReadFile(*filePath)
		if err != nil {
			return nil, err
		}
		return parseHex(string(b))
	case *clipboard:
		b, err := exec.Command("pbpaste").Output()
		if err != nil {
			return nil, err
		}
		return parseHex(string(b))
	default:
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		return parseHex(string(b))
	}
}

func readText() ([]byte, error) {
	switch {
	case *text != "":
		return []byte(*text), nil
	case *filePath != "":
		return os.ReadFile(*filePath)
	case *clipboard:
		return exec.Command("pbpaste").Output()
	default:
		return io.ReadAll(os.Stdin)
	}
}

func parseHex(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			return -1
		}
		return r
	}, s)
	return hex.DecodeString(clean)
}
