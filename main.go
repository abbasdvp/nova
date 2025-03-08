package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/term"
	"github.com/urfave/cli/v2"
)

const (
	ModeAES      = "aes"
	ModeChaCha20 = "chacha20"
)

var (
	version = "1.0.0"
)

func main() {
	if len(os.Args) > 1 {
		cliHandler()
	} else {
		interactiveHandler()
	}
}

// ######################## CLI Handler ########################
func cliHandler() {
	app := &cli.App{
		Name:    "Military Crypto",
		Version: version,
		Usage:   "ابزار پیشرفته رمزنگاری نظامی",
		Commands: []*cli.Command{
			{
				Name:  "encrypt",
				Usage: "رمزنگاری فایل",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Required: true},
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Required: true},
					&cli.StringFlag{Name: "algo", Aliases: []string{"a"}, Value: ModeAES},
				},
				Action: func(c *cli.Context) error {
					data, err := os.ReadFile(c.String("input"))
					if err != nil {
						return err
					}
					encrypted, err := encrypt(data, []byte(c.String("key")), c.String("algo"))
					if err != nil {
						return err
					}
					return os.WriteFile(c.String("input")+".enc", encrypted, 0644)
				},
			},
			{
				Name:  "decrypt",
				Usage: "رمزگشایی فایل",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Required: true},
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Required: true},
					&cli.StringFlag{Name: "algo", Aliases: []string{"a"}, Value: ModeAES},
				},
				Action: func(c *cli.Context) error {
					data, err := os.ReadFile(c.String("input"))
					if err != nil {
						return err
					}
					decrypted, err := decrypt(data, []byte(c.String("key")), c.String("algo"))
					if err != nil {
						return err
					}
					return os.WriteFile(strings.TrimSuffix(c.String("input"), ".enc"), decrypted, 0644)
				},
			},
			{
				Name:  "keygen",
				Usage: "تولید کلید امنیتی",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "type", Aliases: []string{"t"}, Value: "aes"},
				},
				Action: func(c *cli.Context) error {
					key, err := generateKey(c.String("type"))
					if err != nil {
						return err
					}
					fileName := c.String("type") + ".key"
					return os.WriteFile(fileName, key, 0400)
				},
			},
			{
				Name:  "sign",
				Usage: "امضای دیجیتال",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Required: true},
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Required: true},
				},
				Action: func(c *cli.Context) error {
					privateKey, err := os.ReadFile(c.String("key"))
					if err != nil {
						return err
					}
					signature, err := signFile(c.String("input"), privateKey)
					if err != nil {
						return err
					}
					return os.WriteFile(c.String("input")+".sig", signature, 0644)
				},
			},
			{
				Name:  "verify",
				Usage: "تأیید امضای دیجیتال",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "input", Aliases: []string{"i"}, Required: true},
					&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Required: true},
					&cli.StringFlag{Name: "signature", Aliases: []string{"s"}, Required: true},
				},
				Action: func(c *cli.Context) error {
					publicKey, err := os.ReadFile(c.String("key"))
					if err != nil {
						return err
					}
					signature, err := os.ReadFile(c.String("signature"))
					if err != nil {
						return err
					}
					valid, err := verifySignature(c.String("input"), publicKey, signature)
					if err != nil {
						return err
					}
					if valid {
						fmt.Println("امضا معتبر است!")
					} else {
						fmt.Println("امضا نامعتبر است!")
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		exitWithError(err)
	}
}

// ######################## Interactive Handler ########################
func interactiveHandler() {
	clearScreen()
	showBanner()

	for {
		showMainMenu()
		choice := getMenuChoice()

		switch choice {
		case 1:
			encryptInteractive()
		case 2:
			decryptInteractive()
		case 3:
			keygenInteractive()
		case 4:
			signInteractive()
		case 5:
			verifyInteractive()
		case 6:
			fmt.Println("\nخروج با موفقیت انجام شد!")
			os.Exit(0)
		default:
			showError("انتخاب نامعتبر!")
		}

		pause()
		clearScreen()
	}
}

// ######################## Core Crypto Functions ########################
func encrypt(data []byte, key []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case ModeAES:
		return aesEncrypt(data, key)
	case ModeChaCha20:
		return chachaEncrypt(data, key)
	default:
		return nil, errors.New("الگوریتم نامشخص")
	}
}

func decrypt(data []byte, key []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case ModeAES:
		return aesDecrypt(data, key)
	case ModeChaCha20:
		return chachaDecrypt(data, key)
	default:
		return nil, errors.New("الگوریتم نامشخص")
	}
}

func aesEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("متن رمز کوتاه است")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func chachaEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func chachaDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("متن رمز کوتاه است")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// ######################## Key Management ########################
func generateKey(keyType string) ([]byte, error) {
	switch keyType {
	case "aes":
		key := make([]byte, 32)
		_, err := rand.Read(key)
		return key, err
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv.Seed(), err
	case "curve25519":
		priv := make([]byte, curve25519.ScalarSize)
		if _, err := rand.Read(priv); err != nil {
			return nil, err
		}
		pub, err := curve25519.X25519(priv, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}
		return append(priv, pub...), nil
	default:
		return nil, errors.New("نوع کلید نامعتبر")
	}
}

// ######################## Digital Signature ########################
func signFile(filePath string, privateKey []byte) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(data)
	privateKey = ed25519.NewKeyFromSeed(privateKey)
	return ed25519.Sign(privateKey, hash[:]), nil
}

func verifySignature(filePath string, publicKey []byte, signature []byte) (bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(data)
	return ed25519.Verify(publicKey, hash[:], signature), nil
}

// ######################## UI Components ########################
func showMainMenu() {
	colorPrint("cyan", "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	colorPrint("cyan", "┃        "+colorText("yellow", "منوی اصلی")+"        ┃")
	colorPrint("cyan", "┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫")
	colorPrint("cyan", "┃ 1. رمزنگاری فایل           ┃")
	colorPrint("cyan", "┃ 2. رمزگشایی فایل           ┃")
	colorPrint("cyan", "┃ 3. تولید کلید امنیتی       ┃")
	colorPrint("cyan", "┃ 4. امضای دیجیتال           ┃")
	colorPrint("cyan", "┃ 5. تأیید امضای دیجیتال     ┃")
	colorPrint("cyan", "┃ 6. خروج                    ┃")
	colorPrint("cyan", "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	fmt.Print(colorText("cyan", "➤ انتخاب شما: "))
}

func getMenuChoice() int {
	var choice int
	fmt.Scanln(&choice)
	return choice
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func pause() {
	fmt.Print("\n↵ برای ادامه کلیدی را فشار دهید...")
	bufio.NewReader(os.Stdin).ReadBytes('\n') 
}

func exitWithError(err error) {
	fmt.Printf("\n%s %v\n", colorText("red", "✗ خطا:"), err)
	os.Exit(1)
}

func colorText(color string, text string) string {
	colorCodes := map[string]string{
		"red":    "\033[31m",
		"green":  "\033[32m",
		"yellow": "\033[33m",
		"cyan":   "\033[36m",
		"reset":  "\033[0m",
	}
	return colorCodes[color] + text + colorCodes["reset"]
}

func colorPrint(color string, text string) {
	fmt.Println(colorText(color, text))
}

func showBanner() {
	fmt.Println(colorText("yellow", `
   ▄▄▄▄▄    ▄  █ ████▄ █▄▄▄▄ 
  █     ▀▄ █   █ █   █ █  ▄▀ 
▄  ▀▀▀▀▄   ██▀▀█ █   █ █▀▀▌  
 ▀▄▄▄▄▀    █   █ ▀████ █  █  
              █            █  
             ▀            ▀   `))
	fmt.Println(colorText("cyan", "  ابزار رمزنگاری پیشرفته نظامی\n"))
}

func init() {
	if runtime.GOOS == "windows" {
		// غیرفعال کردن رنگ‌ها در ویندوز
		colorText = func(color string, text string) string { return text }
	}
}
