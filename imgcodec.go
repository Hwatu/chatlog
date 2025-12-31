  // imgcodec.go
  package main

  import (
  	"bytes"
  	"crypto/aes"
  	"encoding/binary"
  	"encoding/hex"
  	"errors"
  	"flag"
  	"fmt"
  	"os"
  )

  const (
  	headerV4 = 0x3256380708 // 0x07085632 小端写入
  )

  var (
  	mode = flag.String("mode", "decode", "decode|encode")
  	in   = flag.String("in", "", "输入文件路径")
  	out  = flag.String("out", "", "输出文件路径")
  	key  = flag.String("key", "", "Image Key（16 字节十六进制）")
  	xorK = flag.String("xor", "0x37", "XOR Key（1 字节十六进制，如0x37）")
  )

  func main() {
  	flag.Parse()
  	if *in == "" || *out == "" || *key == "" {
  		fmt.Fprintln(os.Stderr, "示例: go run imgcodec.go -mode decode -in msg.dat -out out.jpg -key 00112233445566778899aabbccddeeff")
  		os.Exit(1)
  	}

  	imgKey, err := hex.DecodeString(strip0x(*key))
  	check(err, "解析 Image Key 失败")
  	if len(imgKey) != 16 {
  		check(errors.New("Image Key 长度必须是16字节"), "")
  	}

  	xk, err := hex.DecodeString(strip0x(*xorK))
  	check(err, "解析 XOR Key 失败")
  	if len(xk) != 1 {
  		check(errors.New("XOR Key 必须是1字节"), "")
  	}
  	xorKey := xk[0]

  	data, err := os.ReadFile(*in)
  	check(err, "读取输入文件失败")

  	switch *mode {
  	case "decode":
  		plain, ext, err := decodeV4(data, imgKey, xorKey)
  		check(err, "解密失败")
  		if *out == "" && ext != "" {
  			*out = "out." + ext
  		}
  		check(os.WriteFile(*out, plain, 0644), "写出文件失败")
  		fmt.Printf("解密成功，类型: %s，写入: %s\n", ext, *out)
  	case "encode":
  		dat, err := encodeV4(data, imgKey, xorKey)
  		check(err, "加密失败")
  		check(os.WriteFile(*out, dat, 0644), "写出文件失败")
  		fmt.Printf("加密成功，写入: %s\n", *out)
  	default:
  		check(errors.New("mode 仅支持 decode|encode"), "")
  	}
  }

  // ===== 解密 =====
  func decodeV4(data, aesKey []byte, xorKey byte) ([]byte, string, error) {
  	if len(data) < 15 {
  		return nil, "", errors.New("dat 长度不足")
  	}
  	// header 6 bytes: 07085631/32，小端 uint48，这里直接跳过
  	aesLen := binary.LittleEndian.Uint32(data[6:10])
  	xorLen := binary.LittleEndian.Uint32(data[10:14])
  	body := data[15:]

  	aesPartLen := roundUp16(aesLen)
  	if aesPartLen > uint32(len(body)) {
  		aesPartLen = uint32(len(body))
  	}
  	aesPart := body[:aesPartLen]
  	midStart := aesPartLen
  	midEnd := uint32(len(body)) - xorLen
  	if midEnd > uint32(len(body)) {
  		return nil, "", errors.New("xor 长度非法")
  	}
  	mid := body[midStart:midEnd]
  	tail := body[midEnd:]

  	decAES, err := decryptECB(aesPart, aesKey)
  	if err != nil {
  		return nil, "", err
  	}
  	if len(decAES) > int(aesLen) {
  		decAES = decAES[:aesLen]
  	}

  	out := append([]byte{}, decAES...)
  	out = append(out, mid...)

  	if xorLen > 0 {
  		decTail := make([]byte, len(tail))
  		for i := range tail {
  			decTail[i] = tail[i] ^ xorKey
  		}
  		out = append(out, decTail...)
  	}

  	ext := detectExt(out)
  	return out, ext, nil
  }

  // ===== 加密（用于验证）=====
  func encodeV4(plain, aesKey []byte, xorKey byte) ([]byte, error) {
  	// 规则：前 1024 字节（含 padding）AES-ECB，其余末尾 512 字节 XOR（可调）
  	const aesLen = 1024
  	const xorLen = 512

  	aesPart := plain
  	if len(aesPart) > aesLen {
  		aesPart = aesPart[:aesLen]
  	}
  	aesEnc, err := encryptECB(pkcs7(aesPart, aes.BlockSize), aesKey)
  	if err != nil {
  		return nil, err
  	}

  	var mid []byte
  	var tail []byte
  	if len(plain) > aesLen {
  		mid = plain[aesLen:]
  		if len(mid) > xorLen {
  			tail = mid[len(mid)-xorLen:]
  			mid = mid[:len(mid)-xorLen]
  		}
  	}
  	encTail := make([]byte, len(tail))
  	for i := range tail {
  		encTail[i] = tail[i] ^ xorKey
  	}

  	buf := bytes.NewBuffer(nil)
  	// header 6 bytes
  	h := make([]byte, 8)
  	binary.LittleEndian.PutUint64(h, headerV4)
  	buf.Write(h[:6])
  	// aes length (真实未 padding 长度)
  	binary.Write(buf, binary.LittleEndian, uint32(len(aesPart)))
  	// xor length
  	binary.Write(buf, binary.LittleEndian, uint32(len(encTail)))
  	// 1 byte 固定 0x01
  	buf.WriteByte(0x01)

  	buf.Write(aesEnc)
  	buf.Write(mid)
  	buf.Write(encTail)

  	return buf.Bytes(), nil
  }

  // ===== 工具函数 =====
  func decryptECB(data, key []byte) ([]byte, error) {
  	if len(data)%aes.BlockSize != 0 {
  		return nil, errors.New("AES 段长度不是16倍数")
  	}
  	c, err := aes.NewCipher(key)
  	if err != nil {
  		return nil, err
  	}
  	out := make([]byte, len(data))
  	for i := 0; i < len(data); i += aes.BlockSize {
  		c.Decrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
  	}
  	// 去 PKCS7
  	if len(out) == 0 {
  		return out, nil
  	}
  	pad := int(out[len(out)-1])
  	if pad > 0 && pad <= aes.BlockSize && pad <= len(out) {
  		ok := true
  		for i := len(out) - pad; i < len(out); i++ {
  			if out[i] != byte(pad) {
  				ok = false
  				break
  			}
  		}
  		if ok {
  			out = out[:len(out)-pad]
  		}
  	}
  	return out, nil
  }

  func encryptECB(data, key []byte) ([]byte, error) {
  	if len(data)%aes.BlockSize != 0 {
  		return nil, errors.New("加密输入必须是16倍数")
  	}
  	c, err := aes.NewCipher(key)
  	if err != nil {
  		return nil, err
  	}
  	out := make([]byte, len(data))
  	for i := 0; i < len(data); i += aes.BlockSize {
  		c.Encrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
  	}
  	return out, nil
  }

  func pkcs7(data []byte, block int) []byte {
  	p := block - len(data)%block
  	if p == 0 {
  		p = block
  	}
  	pad := bytes.Repeat([]byte{byte(p)}, p)
  	return append(data, pad...)
  }

  func roundUp16(n uint32) uint32 {
  	return (n/16)*16 + 16
  }

  func detectExt(b []byte) string {
  	sigs := []struct {
  		pfx []byte
  		ext string
  	}{
  		{[]byte{0xFF, 0xD8, 0xFF}, "jpg"},
  		{[]byte{0x89, 0x50, 0x4E, 0x47}, "png"},
  		{[]byte{0x47, 0x49, 0x46, 0x38}, "gif"},
  		{[]byte{0x49, 0x49, 0x2A, 0x00}, "tiff"},
  		{[]byte{0x42, 0x4D}, "bmp"},
  		{[]byte{0x77, 0x78, 0x67, 0x66}, "wxgf"},
  	}
  	for _, s := range sigs {
  		if len(b) >= len(s.pfx) && bytes.Equal(b[:len(s.pfx)], s.pfx) {
  			return s.ext
  		}
  	}
  	return ""
  }

  func strip0x(s string) string {
  	if len(s) > 1 && (s[:2] == "0x" || s[:2] == "0X") {
  		return s[2:]
  	}
  	return s
  }

  func check(err error, msg string) {
  	if err != nil {
  		if msg != "" {
  			fmt.Fprintln(os.Stderr, msg+":", err)
  		} else {
  			fmt.Fprintln(os.Stderr, err)
  		}
  		os.Exit(1)
  	}
  }
