package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) > 1 {
		// اجرای حالت خط فرمان
		app.Run(os.Args)
	} else {
		// اجرای رابط کاربری تعاملی
		runInteractiveUI()
	}
}

func runInteractiveUI() {
	clearScreen()
	showBanner()

	for {
		showMainMenu()
		choice := getMenuChoice()

		switch choice {
		case 1:
			handleEncryptInteractive()
		case 2:
			handleDecryptInteractive()
		case 3:
			handleKeyGenerationInteractive()
		case 4:
			handleSignInteractive()
		case 5:
			handleVerifyInteractive()
		case 6:
			fmt.Println("\nخروج از برنامه...")
			os.Exit(0)
		default:
			fmt.Println("\n⚠️ انتخاب نامعتبر!")
		}

		pause()
		clearScreen()
	}
}

func showMainMenu() {
	fmt.Println(cyan("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"))
	fmt.Println(cyan("┃        ") + yellow("منوی اصلی") + cyan("        ┃"))
	fmt.Println(cyan("┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫"))
	fmt.Println(cyan("┃ 1. رمزنگاری فایل           ┃"))
	fmt.Println(cyan("┃ 2. رمزگشایی فایل           ┃"))
	fmt.Println(cyan("┃ 3. تولید کلید امنیتی       ┃"))
	fmt.Println(cyan("┃ 4. امضای دیجیتال           ┃"))
	fmt.Println(cyan("┃ 5. تأیید امضای دیجیتال     ┃"))
	fmt.Println(cyan("┃ 6. خروج                    ┃"))
	fmt.Println(cyan("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"))
	fmt.Print(cyan("➤ انتخاب شما: "))
}

func handleEncryptInteractive() {
	clearScreen()
	fmt.Println(green("»»» رمزنگاری فایل «««\n"))

	filePath := getInput("مسیر فایل ورودی: ")
	key := getSecureInput("کلید رمزنگاری (32 بایت): ")
	algorithm := selectAlgorithm()

	fmt.Print("\n" + yellow("در حال رمزنگاری..."))
	err := encryptFile(filePath, key, algorithm)
	if err != nil {
		showError(err)
		return
	}

	fmt.Println(green("\n✓ رمزنگاری با موفقیت انجام شد!"))
	fmt.Printf("فایل خروجی: %s.enc\n", filepath.Base(filePath))
}

func handleDecryptInteractive() {
	clearScreen()
	fmt.Println(green("»»» رمزگشایی فایل «««\n"))

	filePath := getInput("مسیر فایل رمزنگاری شده: ")
	key := getSecureInput("کلید رمزگشایی (32 بایت): ")
	algorithm := selectAlgorithm()

	fmt.Print("\n" + yellow("در حال رمزگشایی..."))
	err := decryptFile(filePath, key, algorithm)
	if err != nil {
		showError(err)
		return
	}

	fmt.Println(green("\n✓ رمزگشایی با موفقیت انجام شد!"))
	fmt.Printf("فایل خروجی: %s.dec\n", filepath.Base(filePath))
}

func selectAlgorithm() string {
	fmt.Println("\nالگوریتم رمزنگاری:")
	fmt.Println("1. AES-GCM (پیشنهادی)")
	fmt.Println("2. ChaCha20-Poly1305")
	choice := getMenuChoice()

	if choice == 2 {
		return ModeChaCha20
	}
	return ModeAES
}

func handleKeyGenerationInteractive() {
	clearScreen()
	fmt.Println(green("»»» تولید کلید امنیتی «««\n"))

	fmt.Println("نوع کلید:")
	fmt.Println("1. کلید رمزنگاری (AES/ChaCha20)")
	fmt.Println("2. کلید امضای دیجیتال (Ed25519)")
	fmt.Println("3. کلید تبادل (Curve25519)")
	choice := getMenuChoice()

	var keyType string
	switch choice {
	case 1:
		keyType = "encryption"
	case 2:
		keyType = "ed25519"
	case 3:
		keyType = "curve25519"
	default:
		showError(fmt.Errorf("انتخاب نامعتبر"))
		return
	}

	fmt.Print("\n" + yellow("در حال تولید کلید..."))
	key, err := generateKey(keyType)
	if err != nil {
		showError(err)
		return
	}

	fileName := fmt.Sprintf("%s.key", keyType)
	os.WriteFile(fileName, key, 0400)
	fmt.Println(green("\n✓ کلید با موفقیت تولید شد!"))
	fmt.Printf("فایل کلید: %s\n", fileName)
}

func handleSignInteractive() {
	clearScreen()
	fmt.Println(green("»»» امضای دیجیتال «««\n"))

	filePath := getInput("مسیر فایل: ")
	keyFile := getInput("مسیر فایل کلید خصوصی: ")

	fmt.Print("\n" + yellow("در حال امضا کردن..."))
	signature, err := signFile(filePath, keyFile)
	if err != nil {
		showError(err)
		return
	}

	sigFile := filePath + ".sig"
	os.WriteFile(sigFile, signature, 0644)
	fmt.Println(green("\n✓ امضا با موفقیت ایجاد شد!"))
	fmt.Printf("فایل امضا: %s\n", sigFile)
}

func handleVerifyInteractive() {
	clearScreen()
	fmt.Println(green("»»» تأیید امضای دیجیتال «««\n"))

	filePath := getInput("مسیر فایل: ")
	sigFile := getInput("مسیر فایل امضا: ")
	keyFile := getInput("مسیر فایل کلید عمومی: ")

	fmt.Print("\n" + yellow("در حال تأیید امضا..."))
	valid, err := verifySignature(filePath, sigFile, keyFile)
	if err != nil {
		showError(err)
		return
	}

	if valid {
		fmt.Println(green("\n✓ امضا معتبر است!"))
	} else {
		fmt.Println(red("\n✗ امضا نامعتبر است!"))
	}
}

// توابع کمکی برای رابط کاربری
func getMenuChoice() int {
	var choice int
	fmt.Scanln(&choice)
	return choice
}

func getInput(prompt string) string {
	fmt.Print(cyan(prompt))
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func getSecureInput(prompt string) []byte {
	fmt.Print(cyan(prompt))
	byteKey, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return byteKey
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func pause() {
	fmt.Print("\n↵ برای ادامه کلیدی را فشار دهید...")
	fmt.Scanln()
}

func showBanner() {
	fmt.Println(yellow(`
   ▄▄▄▄▄    ▄  █ ████▄ █▄▄▄▄ 
  █     ▀▄ █   █ █   █ █  ▄▀ 
▄  ▀▀▀▀▄   ██▀▀█ █   █ █▀▀▌  
 ▀▄▄▄▄▀    █   █ ▀████ █  █  
              █            █  
             ▀            ▀   `))
	fmt.Println(cyan("  ابزار رمزنگاری پیشرفته نظامی\n"))
}

// رنگ‌های ترمینال
func colorize(text string, colorCode string) string {
	return colorCode + text + "\033[0m"
}

func red(text string) string    { return colorize(text, "\033[31m") }
func green(text string) string  { return colorize(text, "\033[32m") }
func yellow(text string) string { return colorize(text, "\033[33m") }
func cyan(text string) string   { return colorize(text, "\033[36m") }

func showError(err error) {
	fmt.Println(red("\n✗ خطا: " + err.Error()))
}

// توابع رمزنگاری/رمزگشایی (مشابه نسخه قبلی)
// ... [کدهای رمزنگاری از نسخه قبلی اینجا قرار می‌گیرند]