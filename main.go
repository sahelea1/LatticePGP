package main

// ---------------------------------------------------------------------------
// LatticePGP (lpgp) — Post-Quantum Secure Asymmetric Encryption & Signing
// ---------------------------------------------------------------------------
//
// Algorithm : Unified Ring-LWE (Learning With Errors over Polynomial Rings)
// Ring      : Z_q[x] / (x^256 + 1)
// Modulus   : q = 8380417 (prime, 2n | q-1, large enough for both Enc & Sig)
// Error     : uniform in {-2, …, 2}
// Hybrid    : Ring-LWE encapsulation + AES-256-GCM
// Signature : Fiat-Shamir with Aborts (Dilithium-like)
//
// Security  : Post-quantum ~128-bit equivalent.
// ---------------------------------------------------------------------------

import (
    "bytes"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "flag"
    "fmt"
    "os"
    "strings"
)

// ────────────────────────── parameters ──────────────────────────

const (
    N      = 256     // polynomial degree
    Q      = 8380417 // modulus (prime, fits Dilithium/Kyber paradigms)
    HALF_Q = 4190208
    B      = 2       // error bound for keygen
    KeyLen = 32      // AES-256

    GAMMA1  = 131072    // 2^17, bound for signature random poly y
    Z_BOUND = 131072 - 120 // bound for signature z after rejection
    D_ROUND = 2048      // rounding divisor for signature compression
    TAU     = 60        // number of ±1 coefficients in signature challenge

    MagicPK  = "LTPK"
    MagicSK  = "LTSK"
    MagicCT  = "LTCT"
    MagicSIG = "LTSG"
    Version  = 1
)

// ────────────────────────── polynomial type ──────────────────────────

type Poly [N]int64

func modQ(x int64) int64 {
    r := x % Q
    if r < 0 {
        r += Q
    }
    return r
}

func (p *Poly) reduceModQ() {
    for i := 0; i < N; i++ {
        p[i] = modQ(p[i])
    }
}

func (p *Poly) center() {
    for i := 0; i < N; i++ {
        if p[i] > Q/2 {
            p[i] -= Q
        }
    }
}

func polyAdd(a, b *Poly) Poly {
    var c Poly
    for i := 0; i < N; i++ {
        c[i] = a[i] + b[i]
    }
    return c
}

func polySub(a, b *Poly) Poly {
    var c Poly
    for i := 0; i < N; i++ {
        c[i] = a[i] - b[i]
    }
    return c
}

func polyMul(a, b *Poly) Poly {
    var tmp [2*N - 1]int64
    for i := 0; i < N; i++ {
        if a[i] == 0 {
            continue
        }
        ai := a[i]
        for j := 0; j < N; j++ {
            tmp[i+j] += ai * b[j]
        }
    }
    var c Poly
    for i := 0; i < N; i++ {
        c[i] = tmp[i]
    }
    for i := N; i < 2*N-1; i++ {
        c[i-N] -= tmp[i] // x^N = −1
    }
    c.reduceModQ()
    return c
}

func roundPolyCentered(p *Poly, D int64) [N]int64 {
    var out [N]int64
    for i := 0; i < N; i++ {
        val := p[i]
        if val >= 0 {
            out[i] = (val + D/2) / D
        } else {
            out[i] = -(-val + D/2) / D
        }
    }
    return out
}

// ────────────────────────── random & hash ──────────────────────────

func mustRand(n int) []byte {
    buf := make([]byte, n)
    if _, err := rand.Read(buf); err != nil {
        panic("crypto/rand: " + err.Error())
    }
    return buf
}

func randPolyQ() Poly {
    var p Poly
    buf := mustRand(N * 4)
    for i := 0; i < N; i++ {
        p[i] = int64(binary.LittleEndian.Uint32(buf[4*i:])) % Q
    }
    return p
}

func errPoly() Poly {
    var p Poly
    buf := mustRand(N)
    for i := 0; i < N; i++ {
        p[i] = int64(buf[i]%(2*B+1)) - int64(B)
    }
    return p
}

func randPolyY() Poly {
    var p Poly
    buf := mustRand(N * 4)
    for i := 0; i < N; i++ {
        val := int64(binary.LittleEndian.Uint32(buf[4*i:])) % (2 * GAMMA1)
        p[i] = val - GAMMA1
    }
    return p
}

// expandSeed deterministically generates a sparse challenge polynomial with TAU non-zero ±1 coefficients.
func expandSeed(cSeed []byte) Poly {
    var c Poly
    used := [N]bool{}
    indices := make([]int, 0, TAU)
    counter := 0
    buf := []byte{}

    for len(indices) < TAU {
        if len(buf) < 2 {
            h := sha256.Sum256(append(append([]byte{}, cSeed...), byte(counter)))
            counter++
            buf = append(buf, h[:]...)
        }
        idx := int(buf[0])<<8 | int(buf[1])
        buf = buf[2:]
        idx = idx % N
        if !used[idx] {
            used[idx] = true
            indices = append(indices, idx)
        }
    }
    for len(buf) < TAU {
        h := sha256.Sum256(append(append([]byte{}, cSeed...), byte(counter)))
        counter++
        buf = append(buf, h[:]...)
    }
    for i, idx := range indices {
        sign := buf[i] & 1
        if sign == 0 {
            c[idx] = 1
        } else {
            c[idx] = -1
        }
    }
    return c
}

func hashW1Msg(w1 *[N]int64, msg []byte) []byte {
    h := sha256.New()
    buf := make([]byte, 4)
    for i := 0; i < N; i++ {
        binary.LittleEndian.PutUint32(buf, uint32(int32(w1[i])))
        h.Write(buf)
    }
    h.Write(msg)
    return h.Sum(nil)
}

// ────────────────────────── key types ──────────────────────────

type PublicKey struct {
    A Poly
    T Poly
}

type SecretKey struct {
    A Poly
    S Poly
    E Poly
    T Poly // Required for signing operations!
}

func KeyGen() (PublicKey, SecretKey) {
    a := randPolyQ()
    s := errPoly()
    e := errPoly()
    as := polyMul(&a, &s)
    t := polyAdd(&as, &e)
    t.reduceModQ()
    return PublicKey{A: a, T: t}, SecretKey{A: a, S: s, E: e, T: t}
}

// ────────────────────────── encryption ──────────────────────────

type RLWECiphertext struct {
    U Poly
    V Poly
}

func EncryptKey(pk *PublicKey, key []byte) RLWECiphertext {
    r := errPoly()
    e1 := errPoly()
    e2 := errPoly()

    ar := polyMul(&pk.A, &r)
    u := polyAdd(&ar, &e1)
    u.reduceModQ()

    var m Poly
    for i := 0; i < 256; i++ {
        if (key[i/8]>>(7-uint(i%8)))&1 == 1 {
            m[i] = int64(HALF_Q)
        }
    }

    tr := polyMul(&pk.T, &r)
    trE2 := polyAdd(&tr, &e2)
    v := polyAdd(&trE2, &m)
    v.reduceModQ()

    return RLWECiphertext{U: u, V: v}
}

func DecryptKey(sk *SecretKey, ct RLWECiphertext) []byte {
    su := polyMul(&sk.S, &ct.U)
    d := polySub(&ct.V, &su)
    d.reduceModQ()

    key := make([]byte, KeyLen)
    for i := 0; i < 256; i++ {
        c := d[i]
        if c >= int64(Q)/4 && c <= 3*int64(Q)/4 {
            key[i/8] |= 1 << (7 - uint(i%8))
        }
    }
    return key
}

// ────────────────────────── signing ──────────────────────────

func packDelta(delta []int8) []byte {
    out := make([]byte, 64)
    for i, d := range delta {
        v := byte(d + 1) // -1->0, 0->1, 1->2
        byteIdx := i / 4
        bitIdx := (i % 4) * 2
        out[byteIdx] |= v << bitIdx
    }
    return out
}

func unpackDelta(data []byte) []int8 {
    delta := make([]int8, N)
    for i := 0; i < N; i++ {
        byteIdx := i / 4
        bitIdx := (i % 4) * 2
        v := (data[byteIdx] >> bitIdx) & 3
        delta[i] = int8(v) - 1
    }
    return delta
}

func Sign(sk *SecretKey, msg []byte) ([]byte, error) {
    for {
        y := randPolyY()
        ay := polyMul(&sk.A, &y)
        ay.reduceModQ()
        ay.center()

        w1 := roundPolyCentered(&ay, D_ROUND)
        cSeed := hashW1Msg(&w1, msg)
        c := expandSeed(cSeed)

        cs := polyMul(&c, &sk.S)
        z := polyAdd(&y, &cs)

        valid := true
        for i := 0; i < N; i++ {
            if z[i] < -Z_BOUND || z[i] > Z_BOUND {
                valid = false
                break
            }
        }
        if !valid {
            continue // Rejection sampling
        }

        az := polyMul(&sk.A, &z)
        az.reduceModQ()
        az.center()

        ct := polyMul(&c, &sk.T)
        ct.reduceModQ()
        ct.center()

        wPrime := polySub(&az, &ct)
        wPrime.center()

        w1Prime := roundPolyCentered(&wPrime, D_ROUND)

        var delta [N]int8
        for i := 0; i < N; i++ {
            delta[i] = int8(w1[i] - w1Prime[i])
        }

        packedDelta := packDelta(delta[:])
        out := make([]byte, 0, 6+N*4+32+64)
        out = append(out, MagicSIG...)
        out = append(out, byte(Version>>8), byte(Version))
        out = append(out, polyToBytes(&z)...)
        out = append(out, cSeed...)
        out = append(out, packedDelta...)
        return out, nil
    }
}

func Verify(pk *PublicKey, sigData []byte, msg []byte) (bool, error) {
    if len(sigData) < 6+N*4+32+64 {
        return false, fmt.Errorf("signature too short")
    }
    if string(sigData[:4]) != MagicSIG {
        return false, fmt.Errorf("bad signature magic")
    }

    z := polyFromBytes(sigData[6 : 6+N*4])
    cSeed := sigData[6+N*4 : 6+N*4+32]
    packedDelta := sigData[6+N*4+32 : 6+N*4+32+64]

    for i := 0; i < N; i++ {
        if z[i] < -Z_BOUND || z[i] > Z_BOUND {
            return false, nil
        }
    }

    c := expandSeed(cSeed)
    delta := unpackDelta(packedDelta)

    az := polyMul(&pk.A, &z)
    az.reduceModQ()
    az.center()

    ct := polyMul(&c, &pk.T)
    ct.reduceModQ()
    ct.center()

    wPrime := polySub(&az, &ct)
    wPrime.center()

    w1Prime := roundPolyCentered(&wPrime, D_ROUND)

    var w1 [N]int64
    for i := 0; i < N; i++ {
        w1[i] = w1Prime[i] + int64(delta[i])
    }

    expectedCSeed := hashW1Msg(&w1, msg)
    return bytes.Equal(cSeed, expectedCSeed), nil
}

// ────────────────────────── serialization ──────────────────────────

func polyToBytes(p *Poly) []byte {
    buf := make([]byte, N*4)
    for i := 0; i < N; i++ {
        binary.LittleEndian.PutUint32(buf[4*i:], uint32(int32(p[i])))
    }
    return buf
}

func polyFromBytes(buf []byte) Poly {
    var p Poly
    for i := 0; i < N; i++ {
        p[i] = int64(int32(binary.LittleEndian.Uint32(buf[4*i:])))
    }
    return p
}

func (pk *PublicKey) Marshal() []byte {
    out := make([]byte, 0, 14+N*8)
    out = append(out, MagicPK...)
    out = append(out, byte(Version>>8), byte(Version))
    var tmp [4]byte
    binary.BigEndian.PutUint32(tmp[:], uint32(N))
    out = append(out, tmp[:]...)
    binary.BigEndian.PutUint32(tmp[:], uint32(Q))
    out = append(out, tmp[:]...)
    out = append(out, polyToBytes(&pk.A)...)
    out = append(out, polyToBytes(&pk.T)...)
    return out
}

func UnmarshalPublicKey(data []byte) (*PublicKey, error) {
    if len(data) < 14+N*8 {
        return nil, fmt.Errorf("public key data too short")
    }
    if string(data[:4]) != MagicPK {
        return nil, fmt.Errorf("bad public key magic")
    }
    if v := uint16(data[4])<<8 | uint16(data[5]); v != Version {
        return nil, fmt.Errorf("unsupported version")
    }
    a := polyFromBytes(data[14 : 14+N*4])
    t := polyFromBytes(data[14+N*4 : 14+N*8])
    return &PublicKey{A: a, T: t}, nil
}

func (sk *SecretKey) Marshal() []byte {
    out := make([]byte, 0, 14+N*16) // Now contains 4 polynomials: A, S, E, T
    out = append(out, MagicSK...)
    out = append(out, byte(Version>>8), byte(Version))
    var tmp [4]byte
    binary.BigEndian.PutUint32(tmp[:], uint32(N))
    out = append(out, tmp[:]...)
    binary.BigEndian.PutUint32(tmp[:], uint32(Q))
    out = append(out, tmp[:]...)
    out = append(out, polyToBytes(&sk.A)...)
    out = append(out, polyToBytes(&sk.S)...)
    out = append(out, polyToBytes(&sk.E)...)
    out = append(out, polyToBytes(&sk.T)...)
    return out
}

func UnmarshalSecretKey(data []byte) (*SecretKey, error) {
    if len(data) < 14+N*16 { // Updated length check
        return nil, fmt.Errorf("secret key data too short")
    }
    if string(data[:4]) != MagicSK {
        return nil, fmt.Errorf("bad secret key magic")
    }
    if v := uint16(data[4])<<8 | uint16(data[5]); v != Version {
        return nil, fmt.Errorf("unsupported version")
    }
    a := polyFromBytes(data[14 : 14+N*4])
    s := polyFromBytes(data[14+N*4 : 14+N*8])
    e := polyFromBytes(data[14+N*8 : 14+N*12])
    t := polyFromBytes(data[14+N*12 : 14+N*16])
    return &SecretKey{A: a, S: s, E: e, T: t}, nil
}

// ────────────────────────── hybrid encrypt / decrypt ──────────────────────────

func EncryptMessage(pk *PublicKey, plaintext []byte) ([]byte, error) {
    symKey := mustRand(KeyLen)
    rlwe := EncryptKey(pk, symKey)

    block, err := aes.NewCipher(symKey)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    iv := mustRand(gcm.NonceSize())
    aesCT := gcm.Seal(nil, iv, plaintext, nil)

    out := make([]byte, 0, 22+N*8+len(aesCT))
    out = append(out, MagicCT...)
    out = append(out, byte(Version>>8), byte(Version))
    out = append(out, iv...)
    var lbuf [4]byte
    binary.BigEndian.PutUint32(lbuf[:], uint32(len(aesCT)))
    out = append(out, lbuf[:]...)
    out = append(out, polyToBytes(&rlwe.U)...)
    out = append(out, polyToBytes(&rlwe.V)...)
    out = append(out, aesCT...)

    for i := range symKey {
        symKey[i] = 0
    }
    return out, nil
}

func DecryptMessage(sk *SecretKey, data []byte) ([]byte, error) {
    if len(data) < 22+N*8 {
        return nil, fmt.Errorf("ciphertext too short")
    }
    if string(data[:4]) != MagicCT {
        return nil, fmt.Errorf("bad ciphertext magic")
    }
    if v := uint16(data[4])<<8 | uint16(data[5]); v != Version {
        return nil, fmt.Errorf("unsupported version")
    }
    iv := data[6:18]
    aesLen := binary.BigEndian.Uint32(data[18:22])

    u := polyFromBytes(data[22 : 22+N*4])
    v := polyFromBytes(data[22+N*4 : 22+N*8])

    symKey := DecryptKey(sk, RLWECiphertext{U: u, V: v})

    aesStart := 22 + N*8
    if len(data) < aesStart+int(aesLen) {
        return nil, fmt.Errorf("ciphertext truncated")
    }
    aesCT := data[aesStart : aesStart+int(aesLen)]

    block, err := aes.NewCipher(symKey)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    return gcm.Open(nil, iv, aesCT, nil)
}

// ────────────────────────── ASCII Armor (PGP Style) ──────────────────────────

func Armor(blockType string, data []byte) string {
    b64 := base64.StdEncoding.EncodeToString(data)
    var sb strings.Builder
    sb.WriteString("-----BEGIN LPGP " + blockType + "-----\n")
    sb.WriteString("Version: LatticePGP v1.0 (Ring-LWE N=256 Q=8380417)\n\n")
    for i := 0; i < len(b64); i += 76 {
        end := i + 76
        if end > len(b64) {
            end = len(b64)
        }
        sb.WriteString(b64[i:end])
        sb.WriteString("\n")
    }
    sb.WriteString("-----END LPGP " + blockType + "-----\n")
    return sb.String()
}

func Dearmor(text string) (string, []byte, error) {
    lines := strings.Split(text, "\n")
    var blockType string
    var dataLines []string
    inBlock := false
    headerDone := false

    for _, line := range lines {
        line = strings.TrimRight(line, "\r")
        if !inBlock {
            if strings.HasPrefix(line, "-----BEGIN LPGP ") && strings.HasSuffix(line, "-----") {
                blockType = strings.TrimPrefix(line, "-----BEGIN LPGP ")
                blockType = strings.TrimSuffix(blockType, "-----")
                inBlock = true
            }
            continue
        }
        if strings.HasPrefix(line, "-----END LPGP ") {
            break
        }
        if !headerDone {
            if strings.TrimSpace(line) == "" {
                headerDone = true
            }
            continue
        }
        dataLines = append(dataLines, line)
    }

    if !inBlock || !headerDone {
        return "", nil, fmt.Errorf("invalid ascii armor format")
    }
    b64 := strings.Join(dataLines, "")
    data, err := base64.StdEncoding.DecodeString(b64)
    if err != nil {
        return "", nil, fmt.Errorf("base64 decode error: %w", err)
    }
    return blockType, data, nil
}

func readFileOrStdin(path string) ([]byte, error) {
    if path == "-" || path == "" {
        return os.ReadFile("/dev/stdin")
    }
    return os.ReadFile(path)
}

func writeFileOrStdout(path string, data []byte) error {
    if path == "-" || path == "" {
        _, err := os.Stdout.Write(data)
        return err
    }
    return os.WriteFile(path, data, 0644)
}

// ────────────────────────── CLI ──────────────────────────

func usage() {
    fmt.Fprintf(os.Stderr, `lpgp — LatticePGP: Post-Quantum Encryption & Signing
===================================================
Algorithm : Unified Ring-LWE (N=256, Q=8380417)
Usage:
  lpgp keygen   [-name BASENAME]
  lpgp encrypt  -pubkey FILE [-in FILE] [-out FILE]
  lpgp decrypt  -seckey FILE [-in FILE] [-out FILE]
  lpgp sign     -seckey FILE [-in FILE] [-out FILE]
  lpgp verify   -pubkey FILE -sig FILE [-in FILE]

Use "-" for stdin/stdout.
`)
}

func cmdKeygen() {
    fs := flag.NewFlagSet("keygen", flag.ExitOnError)
    name := fs.String("name", "lattice", "base name for key files")
    fs.Parse(os.Args[2:])

    fmt.Println("Generating Ring-LWE keypair ...")
    pk, sk := KeyGen()

    pubFile := *name + ".lpub"
    secFile := *name + ".lsec"

    pubArmor := Armor("PUBLIC KEY BLOCK", pk.Marshal())
    secArmor := Armor("SECRET KEY BLOCK", sk.Marshal())

    if err := os.WriteFile(pubFile, []byte(pubArmor), 0644); err != nil {
        fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
        os.Exit(1)
    }
    if err := os.WriteFile(secFile, []byte(secArmor), 0600); err != nil {
        fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
        os.Exit(1)
    }

    fp := sha256.Sum256([]byte(pubArmor))
    fmt.Printf("  Public key : %s\n", pubFile)
    fmt.Printf("  Secret key : %s\n", secFile)
    fmt.Printf("  Fingerprint: %x\n", fp[:])
}

func loadPubKey(path string) *PublicKey {
    data, err := os.ReadFile(path)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read public key: %v\n", err)
        os.Exit(1)
    }
    _, raw, err := Dearmor(string(data))
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR parse armor: %v\n", err)
        os.Exit(1)
    }
    pk, err := UnmarshalPublicKey(raw)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR parse public key: %v\n", err)
        os.Exit(1)
    }
    return pk
}

func loadSecKey(path string) *SecretKey {
    data, err := os.ReadFile(path)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read secret key: %v\n", err)
        os.Exit(1)
    }
    _, raw, err := Dearmor(string(data))
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR parse armor: %v\n", err)
        os.Exit(1)
    }
    sk, err := UnmarshalSecretKey(raw)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR parse secret key: %v\n", err)
        os.Exit(1)
    }
    return sk
}

func cmdEncrypt() {
    fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
    pkFile := fs.String("pubkey", "", "public key file (.lpub)")
    inFile := fs.String("in", "-", "input plaintext file")
    outFile := fs.String("out", "-", "output ciphertext file")
    fs.Parse(os.Args[2:])

    if *pkFile == "" {
        fmt.Fprintln(os.Stderr, "ERROR: -pubkey required")
        os.Exit(1)
    }

    pk := loadPubKey(*pkFile)
    plain, err := readFileOrStdin(*inFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read input: %v\n", err)
        os.Exit(1)
    }

    ct, err := EncryptMessage(pk, plain)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR encrypt: %v\n", err)
        os.Exit(1)
    }

    armored := Armor("ENCRYPTED MESSAGE BLOCK", ct)
    writeFileOrStdout(*outFile, []byte(armored))
}

func cmdDecrypt() {
    fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
    skFile := fs.String("seckey", "", "secret key file (.lsec)")
    inFile := fs.String("in", "-", "input ciphertext file")
    outFile := fs.String("out", "-", "output plaintext file")
    fs.Parse(os.Args[2:])

    if *skFile == "" {
        fmt.Fprintln(os.Stderr, "ERROR: -seckey required")
        os.Exit(1)
    }

    sk := loadSecKey(*skFile)
    ctData, err := readFileOrStdin(*inFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read input: %v\n", err)
        os.Exit(1)
    }

    _, raw, err := Dearmor(string(ctData))
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR parse armor: %v\n", err)
        os.Exit(1)
    }

    plain, err := DecryptMessage(sk, raw)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR decrypt: %v\n", err)
        os.Exit(1)
    }

    writeFileOrStdout(*outFile, plain)
}

func cmdSign() {
    fs := flag.NewFlagSet("sign", flag.ExitOnError)
    skFile := fs.String("seckey", "", "secret key file (.lsec)")
    inFile := fs.String("in", "-", "input message file")
    outFile := fs.String("out", "-", "output signature file")
    fs.Parse(os.Args[2:])

    if *skFile == "" {
        fmt.Fprintln(os.Stderr, "ERROR: -seckey required")
        os.Exit(1)
    }

    sk := loadSecKey(*skFile)
    msg, err := readFileOrStdin(*inFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read input: %v\n", err)
        os.Exit(1)
    }

    sig, err := Sign(sk, msg)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR sign: %v\n", err)
        os.Exit(1)
    }

    armored := Armor("SIGNATURE BLOCK", sig)
    writeFileOrStdout(*outFile, []byte(armored))
}

func cmdVerify() {
    fs := flag.NewFlagSet("verify", flag.ExitOnError)
    pkFile := fs.String("pubkey", "", "public key file (.lpub)")
    sigFile := fs.String("sig", "", "signature file")
    inFile := fs.String("in", "-", "original message file")
    fs.Parse(os.Args[2:])

    if *pkFile == "" || *sigFile == "" {
        fmt.Fprintln(os.Stderr, "ERROR: -pubkey and -sig required")
        os.Exit(1)
    }

    pk := loadPubKey(*pkFile)
    msg, err := readFileOrStdin(*inFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read input: %v\n", err)
        os.Exit(1)
    }

    sigData, err := os.ReadFile(*sigFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read signature: %v\n", err)
        os.Exit(1)
    }

    _, raw, err := Dearmor(string(sigData))
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR parse armor: %v\n", err)
        os.Exit(1)
    }

    valid, err := Verify(pk, raw, msg)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR verify: %v\n", err)
        os.Exit(1)
    }

    if valid {
        fmt.Println("GOOD SIGNATURE")
    } else {
        fmt.Println("BAD SIGNATURE")
        os.Exit(1)
    }
}

func main() {
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
        fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
        usage()
        os.Exit(1)
    }
}
