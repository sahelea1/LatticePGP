package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	circlsign "github.com/cloudflare/circl/sign"
	signschemes "github.com/cloudflare/circl/sign/schemes"
)

const (
	version = 2

	magicPub = "LPPB"
	magicSec = "LPSB"
	magicCT  = "LPCM"
	magicSig = "LPSG"

	pubBlock = "PUBLIC KEY BLOCK"
	secBlock = "SECRET KEY BLOCK"
	ctBlock  = "ENCRYPTED MESSAGE BLOCK"
	sigBlock = "SIGNATURE BLOCK"

	sigSchemeName = "ML-DSA-65"
	sigContext    = "LPGP-SIG-v2"
	encAAD        = "LPGP-ENC-v2"
)

var sigScheme = signschemes.ByName(sigSchemeName)

func main() {
	if sigScheme == nil {
		fatalf("signature scheme %q not available", sigSchemeName)
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		cmdKeygen()
	case "encrypt":
		cmdEncrypt()
	case "decrypt":
		cmdDecrypt()
	case "sign":
		cmdSign()
	case "verify":
		cmdVerify()
	case "help", "-h", "--help":
		usage()
	default:
		fatalf("unknown command: %s", os.Args[1])
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `lpgp — Post-Quantum Encryption & Signing

Algorithms:
  Encrypt: ML-KEM-768 + AES-256-GCM
  Sign   : ML-DSA-65

Usage:
  lpgp keygen  [-name BASENAME]
  lpgp encrypt -pubkey FILE [-in FILE] [-out FILE]
  lpgp decrypt -seckey FILE [-in FILE] [-out FILE]
  lpgp sign    -seckey FILE [-in FILE] [-out FILE]
  lpgp verify  -pubkey FILE -sig FILE [-in FILE]

If -in/-out are omitted, stdin/stdout are used.
`)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func mustRand(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		fatalf("crypto/rand failed: %v", err)
	}
	return b
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func readFileOrStdin(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeFileOrStdout(path string, data []byte, mode os.FileMode) error {
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, mode)
}

// ---------- strict record framing ----------

func encodeRecord(magic string, parts ...[]byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.WriteByte(version)
	buf.WriteByte(byte(len(parts)))
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		buf.Write(n[:])
		buf.Write(p)
	}
	return buf.Bytes()
}

func decodeRecord(data []byte, wantMagic string, wantParts int) ([][]byte, error) {
	if len(data) < 6 {
		return nil, errors.New("record too short")
	}
	if string(data[:4]) != wantMagic {
		return nil, errors.New("bad magic")
	}
	if int(data[4]) != version {
		return nil, fmt.Errorf("unsupported version %d", data[4])
	}
	if int(data[5]) != wantParts {
		return nil, errors.New("wrong part count")
	}

	parts := make([][]byte, 0, wantParts)
	rest := data[6:]
	for i := 0; i < wantParts; i++ {
		if len(rest) < 4 {
			return nil, errors.New("truncated record")
		}
		n := int(binary.BigEndian.Uint32(rest[:4]))
		rest = rest[4:]
		if n < 0 || len(rest) < n {
			return nil, errors.New("invalid record length")
		}
		parts = append(parts, append([]byte(nil), rest[:n]...))
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing garbage in record")
	}
	return parts, nil
}

// ---------- ascii armor ----------

func armor(blockType string, data []byte) string {
	b64 := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	sb.WriteString("-----BEGIN LPGP " + blockType + "-----\n")
	sb.WriteString("Version: LatticePGP v2\n\n")
	for i := 0; i < len(b64); i += 76 {
		j := i + 76
		if j > len(b64) {
			j = len(b64)
		}
		sb.WriteString(b64[i:j])
		sb.WriteByte('\n')
	}
	sb.WriteString("-----END LPGP " + blockType + "-----\n")
	return sb.String()
}

func dearmor(text string) (string, []byte, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) < 4 {
		return "", nil, errors.New("invalid armor")
	}
	begin := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(begin, "-----BEGIN LPGP ") || !strings.HasSuffix(begin, "-----") {
		return "", nil, errors.New("invalid armor begin line")
	}
	blockType := strings.TrimSuffix(strings.TrimPrefix(begin, "-----BEGIN LPGP "), "-----")

	i := 1
	for i < len(lines) && strings.TrimSpace(lines[i]) != "" {
		i++
	}
	if i >= len(lines) {
		return "", nil, errors.New("missing armor body")
	}
	i++ // skip blank line

	var body strings.Builder
	endLine := "-----END LPGP " + blockType + "-----"
	foundEnd := false

	for ; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if line == endLine {
			foundEnd = true
			break
		}
		if strings.HasPrefix(line, "-----END LPGP ") {
			return "", nil, errors.New("armor end type mismatch")
		}
		body.WriteString(line)
	}
	if !foundEnd {
		return "", nil, errors.New("missing armor end line")
	}

	raw, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil {
		return "", nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	return blockType, raw, nil
}

// ---------- keys ----------

type publicKeyBundle struct {
	kemPub []byte
	sigPub []byte
}

type secretKeyBundle struct {
	kemSeed []byte
	sigSec  []byte
}

func keygen() ([]byte, []byte, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	kemPub := dk.EncapsulationKey().Bytes()
	kemSeed := dk.Bytes()

	sigPub, sigSec, err := sigScheme.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	sigPubBytes, err := sigPub.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	sigSecBytes, err := sigSec.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	pub := encodeRecord(magicPub, kemPub, sigPubBytes)
	sec := encodeRecord(magicSec, kemSeed, sigSecBytes)
	return pub, sec, nil
}

func loadPublicKey(path string) (*publicKeyBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blockType, raw, err := dearmor(string(data))
	if err != nil {
		return nil, err
	}
	if blockType != pubBlock {
		return nil, errors.New("not a public key block")
	}
	parts, err := decodeRecord(raw, magicPub, 2)
	if err != nil {
		return nil, err
	}
	if _, err := mlkem.NewEncapsulationKey768(parts[0]); err != nil {
		return nil, fmt.Errorf("invalid ML-KEM public key: %w", err)
	}
	if _, err := sigScheme.UnmarshalBinaryPublicKey(parts[1]); err != nil {
		return nil, fmt.Errorf("invalid ML-DSA public key: %w", err)
	}
	return &publicKeyBundle{kemPub: parts[0], sigPub: parts[1]}, nil
}

func loadSecretKey(path string) (*secretKeyBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blockType, raw, err := dearmor(string(data))
	if err != nil {
		return nil, err
	}
	if blockType != secBlock {
		return nil, errors.New("not a secret key block")
	}
	parts, err := decodeRecord(raw, magicSec, 2)
	if err != nil {
		return nil, err
	}
	if _, err := mlkem.NewDecapsulationKey768(parts[0]); err != nil {
		return nil, fmt.Errorf("invalid ML-KEM secret key seed: %w", err)
	}
	if _, err := sigScheme.UnmarshalBinaryPrivateKey(parts[1]); err != nil {
		return nil, fmt.Errorf("invalid ML-DSA secret key: %w", err)
	}
	return &secretKeyBundle{kemSeed: parts[0], sigSec: parts[1]}, nil
}

// ---------- encrypt / decrypt ----------

func encryptMessage(pk *publicKeyBundle, plaintext []byte) ([]byte, error) {
	ek, err := mlkem.NewEncapsulationKey768(pk.kemPub)
	if err != nil {
		return nil, err
	}
	shared, kemCT := ek.Encapsulate()
	defer zero(shared)

	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := mustRand(gcm.NonceSize())
	aad := append([]byte(encAAD), kemCT...)
	aesCT := gcm.Seal(nil, nonce, plaintext, aad)

	return encodeRecord(magicCT, kemCT, nonce, aesCT), nil
}

func decryptMessage(sk *secretKeyBundle, blob []byte) ([]byte, error) {
	parts, err := decodeRecord(blob, magicCT, 3)
	if err != nil {
		return nil, err
	}
	kemCT, nonce, aesCT := parts[0], parts[1], parts[2]

	dk, err := mlkem.NewDecapsulationKey768(sk.kemSeed)
	if err != nil {
		return nil, err
	}
	shared, err := dk.Decapsulate(kemCT)
	if err != nil {
		return nil, err
	}
	defer zero(shared)

	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("bad nonce size")
	}

	aad := append([]byte(encAAD), kemCT...)
	return gcm.Open(nil, nonce, aesCT, aad)
}

// ---------- sign / verify ----------

func signMessage(sk *secretKeyBundle, msg []byte) ([]byte, error) {
	priv, err := sigScheme.UnmarshalBinaryPrivateKey(sk.sigSec)
	if err != nil {
		return nil, err
	}
	sig := sigScheme.Sign(priv, msg, &circlsign.SignatureOpts{Context: sigContext})
	return encodeRecord(magicSig, sig), nil
}

func verifyMessage(pk *publicKeyBundle, blob, msg []byte) (bool, error) {
	parts, err := decodeRecord(blob, magicSig, 1)
	if err != nil {
		return false, err
	}
	pub, err := sigScheme.UnmarshalBinaryPublicKey(pk.sigPub)
	if err != nil {
		return false, err
	}
	ok := sigScheme.Verify(pub, msg, parts[0], &circlsign.SignatureOpts{Context: sigContext})
	return ok, nil
}

// ---------- commands ----------

func cmdKeygen() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	name := fs.String("name", "lattice", "base name for key files")
	fs.Parse(os.Args[2:])

	pubRaw, secRaw, err := keygen()
	if err != nil {
		fatalf("keygen failed: %v", err)
	}

	pubPath := *name + ".lpub"
	secPath := *name + ".lsec"

	if err := os.WriteFile(pubPath, []byte(armor(pubBlock, pubRaw)), 0644); err != nil {
		fatalf("write public key: %v", err)
	}
	if err := os.WriteFile(secPath, []byte(armor(secBlock, secRaw)), 0600); err != nil {
		fatalf("write secret key: %v", err)
	}

	fp := sha256.Sum256(pubRaw)
	fmt.Printf("Public key : %s\n", pubPath)
	fmt.Printf("Secret key : %s\n", secPath)
	fmt.Printf("Fingerprint: %x\n", fp[:])
}

func cmdEncrypt() {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
	pubFile := fs.String("pubkey", "", "public key file")
	inFile := fs.String("in", "-", "input plaintext")
	outFile := fs.String("out", "-", "output ciphertext")
	fs.Parse(os.Args[2:])

	if *pubFile == "" {
		fatalf("-pubkey required")
	}

	pk, err := loadPublicKey(*pubFile)
	if err != nil {
		fatalf("load public key: %v", err)
	}

	plain, err := readFileOrStdin(*inFile)
	if err != nil {
		fatalf("read input: %v", err)
	}

	ct, err := encryptMessage(pk, plain)
	if err != nil {
		fatalf("encrypt: %v", err)
	}

	if err := writeFileOrStdout(*outFile, []byte(armor(ctBlock, ct)), 0644); err != nil {
		fatalf("write output: %v", err)
	}
}

func cmdDecrypt() {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	secFile := fs.String("seckey", "", "secret key file")
	inFile := fs.String("in", "-", "input ciphertext")
	outFile := fs.String("out", "-", "output plaintext")
	fs.Parse(os.Args[2:])

	if *secFile == "" {
		fatalf("-seckey required")
	}

	sk, err := loadSecretKey(*secFile)
	if err != nil {
		fatalf("load secret key: %v", err)
	}

	armored, err := readFileOrStdin(*inFile)
	if err != nil {
		fatalf("read input: %v", err)
	}
	blockType, raw, err := dearmor(string(armored))
	if err != nil {
		fatalf("parse armor: %v", err)
	}
	if blockType != ctBlock {
		fatalf("wrong block type: %s", blockType)
	}

	plain, err := decryptMessage(sk, raw)
	if err != nil {
		fatalf("decrypt: %v", err)
	}

	if err := writeFileOrStdout(*outFile, plain, 0644); err != nil {
		fatalf("write output: %v", err)
	}
}

func cmdSign() {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	secFile := fs.String("seckey", "", "secret key file")
	inFile := fs.String("in", "-", "input message")
	outFile := fs.String("out", "-", "output signature")
	fs.Parse(os.Args[2:])

	if *secFile == "" {
		fatalf("-seckey required")
	}

	sk, err := loadSecretKey(*secFile)
	if err != nil {
		fatalf("load secret key: %v", err)
	}

	msg, err := readFileOrStdin(*inFile)
	if err != nil {
		fatalf("read input: %v", err)
	}

	sig, err := signMessage(sk, msg)
	if err != nil {
		fatalf("sign: %v", err)
	}

	if err := writeFileOrStdout(*outFile, []byte(armor(sigBlock, sig)), 0644); err != nil {
		fatalf("write output: %v", err)
	}
}

func cmdVerify() {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubFile := fs.String("pubkey", "", "public key file")
	sigFile := fs.String("sig", "", "signature file")
	inFile := fs.String("in", "-", "input message")
	fs.Parse(os.Args[2:])

	if *pubFile == "" || *sigFile == "" {
		fatalf("-pubkey and -sig required")
	}

	pk, err := loadPublicKey(*pubFile)
	if err != nil {
		fatalf("load public key: %v", err)
	}

	msg, err := readFileOrStdin(*inFile)
	if err != nil {
		fatalf("read input: %v", err)
	}

	armoredSig, err := os.ReadFile(*sigFile)
	if err != nil {
		fatalf("read signature: %v", err)
	}
	blockType, raw, err := dearmor(string(armoredSig))
	if err != nil {
		fatalf("parse armor: %v", err)
	}
	if blockType != sigBlock {
		fatalf("wrong block type: %s", blockType)
	}

	ok, err := verifyMessage(pk, raw, msg)
	if err != nil {
		fatalf("verify: %v", err)
	}
	if !ok {
		fmt.Println("BAD SIGNATURE")
		os.Exit(1)
	}
	fmt.Println("GOOD SIGNATURE")
}
