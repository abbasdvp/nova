package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	ModeAES      = "aes"
	ModeChaCha20 = "chacha20"
)

var (
	version = "1.2.0"
)

func main() {
	myApp := app.New()
	window := myApp.NewWindow("Military Crypto Tool v" + version)
	window.Resize(fyne.NewSize(800, 600))

	tabs := container.NewAppTabs(
		createEncryptDecryptTab(window),
		createKeygenTab(window),
		createSignVerifyTab(window),
	)

	window.SetContent(tabs)
	window.ShowAndRun()
}

// ######################## Encryption/Decryption Tab ########################
func createEncryptDecryptTab(window fyne.Window) *container.TabItem {
	inputEntry := widget.NewEntry()
	outputEntry := widget.NewEntry()
	keyEntry := widget.NewEntry()
	algoSelect := widget.NewSelect([]string{ModeAES, ModeChaCha20}, nil)
	statusLabel := widget.NewLabel("")
	operationMode := "Encrypt"

	openFileBtn := widget.NewButton("Select Input File", func() {
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err == nil && reader != nil {
				inputPath := reader.URI().Path()
				inputEntry.SetText(inputPath)
				
				// Auto-generate output filename
				ext := filepath.Ext(inputPath)
				base := strings.TrimSuffix(inputPath, ext)
				if operationMode == "Encrypt" {
					outputEntry.SetText(base + ".enc")
				} else {
					outputEntry.SetText(base + ".dec")
				}
			}
		}, window)
	})

	processBtn := widget.NewButton("Encrypt", func() {
		go processCryptoOperation(inputEntry.Text, outputEntry.Text, 
			keyEntry.Text, algoSelect.Selected, operationMode, statusLabel)
	})

	toggleBtn := widget.NewButton("Switch to Decrypt", func() {
		if operationMode == "Encrypt" {
			operationMode = "Decrypt"
			processBtn.SetText("Decrypt")
			toggleBtn.SetText("Switch to Encrypt")
		} else {
			operationMode = "Encrypt"
			processBtn.SetText("Encrypt")
			toggleBtn.SetText("Switch to Decrypt")
		}
	})

	return container.NewTabItem("Encrypt/Decrypt",
		container.NewVBox(
			widget.NewLabel("Input File:"),
			container.NewHBox(inputEntry, openFileBtn),
			widget.NewLabel("Output File:"),
			outputEntry,
			widget.NewLabel("Encryption Key:"),
			keyEntry,
			widget.NewLabel("Algorithm:"),
			algoSelect,
			container.NewHBox(processBtn, toggleBtn),
			statusLabel,
		),
	)
}

// ######################## Key Generation Tab ########################
func createKeygenTab(window fyne.Window) *container.TabItem {
	keyType := widget.NewSelect([]string{"AES-256", "Ed25519", "Curve25519"}, nil)
	statusLabel := widget.NewLabel("")

	generateBtn := widget.NewButton("Generate Key", func() {
		if keyType.Selected == "" {
			statusLabel.SetText("Please select key type!")
			return
		}

		var key []byte
		var err error
		switch keyType.Selected {
		case "AES-256":
			key = make([]byte, 32)
			_, err = rand.Read(key)
		case "Ed25519":
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			key = priv.Seed()
		case "Curve25519":
			priv := make([]byte, curve25519.ScalarSize)
			if _, err = rand.Read(priv); err == nil {
				pub, err := curve25519.X25519(priv, curve25519.Basepoint)
				if err == nil {
					key = append(priv, pub...)
				}
			}
		}

		if err != nil {
			statusLabel.SetText("Generation failed: " + err.Error())
			return
		}

		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}

			if _, err := writer.Write(key); err != nil {
				statusLabel.SetText("Save failed: " + err.Error())
				return
			}

			statusLabel.SetText("Key saved to: " + writer.URI().Path())
		}, window)
	})

	return container.NewTabItem("Key Generation",
		container.NewVBox(
			widget.NewLabel("Key Type:"),
			keyType,
			generateBtn,
			statusLabel,
		),
	)
}

// ######################## Sign/Verify Tab ########################
func createSignVerifyTab(window fyne.Window) *container.TabItem {
	fileEntry := widget.NewEntry()
	keyEntry := widget.NewEntry()
	sigEntry := widget.NewEntry()
	statusLabel := widget.NewLabel("")

	signBtn := widget.NewButton("Sign File", func() {
		go func() {
			if fileEntry.Text == "" || keyEntry.Text == "" {
				statusLabel.SetText("All fields required!")
				return
			}

			privateKey, err := os.ReadFile(keyEntry.Text)
			if err != nil {
				statusLabel.SetText("Key read error: " + err.Error())
				return
			}

			signature, err := signFile(fileEntry.Text, privateKey)
			if err != nil {
				statusLabel.SetText("Signing failed: " + err.Error())
				return
			}

			sigPath := fileEntry.Text + ".sig"
			if err := os.WriteFile(sigPath, signature, 0644); err != nil {
				statusLabel.SetText("Save failed: " + err.Error())
				return
			}

			statusLabel.SetText("Signature saved to: " + sigPath)
		}()
	})

	verifyBtn := widget.NewButton("Verify File", func() {
		go func() {
			if fileEntry.Text == "" || keyEntry.Text == "" || sigEntry.Text == "" {
				statusLabel.SetText("All fields required!")
				return
			}

			publicKey, err := os.ReadFile(keyEntry.Text)
			if err != nil {
				statusLabel.SetText("Key read error: " + err.Error())
				return
			}

			signature, err := os.ReadFile(sigEntry.Text)
			if err != nil {
				statusLabel.SetText("Signature read error: " + err.Error())
				return
			}

			valid, err := verifySignature(fileEntry.Text, publicKey, signature)
			if err != nil {
				statusLabel.SetText("Verification error: " + err.Error())
				return
			}

			if valid {
				statusLabel.SetText("✅ Signature is valid!")
			} else {
				statusLabel.SetText("❌ Signature is invalid!")
			}
		}()
	})

	return container.NewTabItem("Digital Signature",
		container.NewVBox(
			widget.NewLabel("File to sign/verify:"),
			fileEntry,
			widget.NewLabel("Key file:"),
			keyEntry,
			widget.NewLabel("Signature file:"),
			sigEntry,
			container.NewHBox(signBtn, verifyBtn),
			statusLabel,
		),
	)
}

// ######################## Core Cryptographic Functions ########################
func processCryptoOperation(inputPath, outputPath, key, algorithm, mode string, status *widget.Label) {
	if inputPath == "" || outputPath == "" || key == "" {
		status.SetText("Error: All fields are required!")
		return
	}

	data, err := os.ReadFile(inputPath)
	if err != nil {
		status.SetText("Read error: " + err.Error())
		return
	}

	var result []byte
	switch mode {
	case "Encrypt":
		result, err = encrypt(data, []byte(key), algorithm)
	case "Decrypt":
		result, err = decrypt(data, []byte(key), algorithm)
	}

	if err != nil {
		status.SetText("Operation failed: " + err.Error())
		return
	}

	if err := os.WriteFile(outputPath, result, 0644); err != nil {
		status.SetText("Write error: " + err.Error())
		return
	}

	status.SetText("✅ Operation completed successfully!")
}

func encrypt(data []byte, key []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case ModeAES:
		return aesEncrypt(data, key)
	case ModeChaCha20:
		return chachaEncrypt(data, key)
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

func decrypt(data []byte, key []byte, algorithm string) ([]byte, error) {
	switch algorithm {
	case ModeAES:
		return aesDecrypt(data, key)
	case ModeChaCha20:
		return chachaDecrypt(data, key)
	default:
		return nil, errors.New("unsupported algorithm")
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
	if _, err = rand.Read(nonce); err != nil {
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
		return nil, errors.New("invalid ciphertext")
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
		return nil, errors.New("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func signFile(filePath string, privateKey []byte) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(data)
	priv := ed25519.NewKeyFromSeed(privateKey)
	return ed25519.Sign(priv, hash[:]), nil
}

func verifySignature(filePath string, publicKey []byte, signature []byte) (bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(data)
	return ed25519.Verify(publicKey, hash[:], signature), nil
}
