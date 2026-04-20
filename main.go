package main

// ---------------------------------------------------------------------------
// LatticePGP (lpgp) — Post-Quantum Secure Asymmetric Encryption
// ---------------------------------------------------------------------------
//
// Algorithm : Ring-LWE (Learning With Errors over Polynomial Rings)
// Ring      : Z_q[x] / (x^1024 + 1)
// Modulus   : q = 12289  (prime, 2n divides q-1)
// Error     : uniform in {-3, …, 3}
// Hybrid    : 256-bit key encapsulated via Ring-LWE, message via AES-256-GCM
//
// Security  : Post-quantum ~128-bit equivalent.  Hardness rests on the
//             Ring-LWE problem, which reduces to worst-case problems on
//             ideal lattices and is believed resistant to quantum attack.
//
// WARNING   : This is a clean-room educational / research implementation.
//             Do NOT use in production without a formal security audit.
// ---------------------------------------------------------------------------

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "flag"
    "fmt"
    "os"
)

// ────────────────────────── parameters ──────────────────────────

const (
    N      = 1024  // polynomial degree (power of 2)
    Q      = 12289 // modulus  (prime, 2N | Q-1)
    HALF_Q = 6144  // round(Q/2) — bit-encoding value
    B      = 3     // error bound: coefficients uniform in {-B … B}
    KeyLen = 32    // AES-256 key length in bytes

    MagicPK = "LTPK" // public-key file magic
    MagicSK = "LTSK" // secret-key file magic
    MagicCT = "LTCT" // ciphertext  file magic
    Version = 1
)

// ────────────────────────── polynomial type ──────────────────────────

// Poly represents an element of  Z_Q[x] / (x^N + 1).
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

// polyMul computes  a · b  in  Z_Q[x]/(x^N+1)  via schoolbook multiplication
// followed by reduction with x^N = −1.
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

// ────────────────────────── random sampling ──────────────────────────

func mustRand(n int) []byte {
    buf := make([]byte, n)
    if _, err := rand.Read(buf); err != nil {
        panic("crypto/rand: " + err.Error())
    }
    return buf
}

// randPolyQ returns a uniformly random polynomial with coefficients in [0, Q-1].
func randPolyQ() Poly {
    var p Poly
    buf := mustRand(N * 2)
    for i := 0; i < N; i++ {
        p[i] = int64(binary.LittleEndian.Uint16(buf[2*i:])) % Q
    }
    return p
}

// errPoly returns a small error polynomial with coefficients uniform in {-B … B}.
func errPoly() Poly {
    var p Poly
    buf := mustRand(N)
    for i := 0; i < N; i++ {
        p[i] = int64(buf[i]%(2*B+1)) - int64(B)
    }
    return p
}

// ────────────────────────── key types ──────────────────────────

type PublicKey struct {
    A Poly // public random polynomial
    T Poly // a·s + e  mod q
}

type SecretKey struct {
    A Poly // same public polynomial a
    S Poly // small secret polynomial
}

// KeyGen generates a Ring-LWE keypair.
//
//	1. a  ← uniform random poly mod q
//	2. s  ← small error poly          (secret)
//	3. e  ← small error poly
//	4. t  = a·s + e  mod q
//	5. PK = (a, t)   SK = (a, s)
func KeyGen() (PublicKey, SecretKey) {
    a := randPolyQ()
    s := errPoly()
    e := errPoly()
    as := polyMul(&a, &s) // assign to variable first
    t := polyAdd(&as, &e)
    t.reduceModQ()
    return PublicKey{A: a, T: t}, SecretKey{A: a, S: s}
}

// ────────────────────────── RLWE ciphertext ──────────────────────────

type RLWECiphertext struct {
    U Poly // a·r + e1  mod q
    V Poly // t·r + e2 + m  mod q
}

// EncryptKey encapsulates a 256-bit symmetric key under the public key.
//
//	1. r, e1, e2 ← small error polys
//	2. u = a·r + e1       mod q
//	3. v = t·r + e2 + m   mod q    (m encodes the 256 key bits)
func EncryptKey(pk *PublicKey, key []byte) RLWECiphertext {
    if len(key) != KeyLen {
        panic("key must be 32 bytes")
    }
    r := errPoly()
    e1 := errPoly()
    e2 := errPoly()

    ar := polyMul(&pk.A, &r)
    u := polyAdd(&ar, &e1)
    u.reduceModQ()

    // Encode 256 key bits into polynomial: bit i → coefficient i = HALF_Q if 1
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

// DecryptKey recovers the 256-bit symmetric key from an RLWE ciphertext.
//
//	d = v − s·u  mod q
//	  = e·r + e2 − s·e1 + m   mod q     (noise is small)
//	Each coefficient of m is either 0 or HALF_Q; threshold to recover bits.
func DecryptKey(sk *SecretKey, ct RLWECiphertext) []byte {
    su := polyMul(&sk.S, &ct.U)
    d := polySub(&ct.V, &su)
    d.reduceModQ()

    key := make([]byte, KeyLen)
    for i := 0; i < 256; i++ {
        c := d[i] // ∈ [0, Q-1]
        // If c is closer to Q/2 than to 0 (mod Q), the encoded bit is 1.
        if c >= int64(Q)/4 && c <= 3*int64(Q)/4 {
            key[i/8] |= 1 << (7 - uint(i%8))
        }
    }
    return key
}

// ────────────────────────── serialization ──────────────────────────

func polyToBytes(p *Poly) []byte {
    buf := make([]byte, N*2)
    for i := 0; i < N; i++ {
        binary.LittleEndian.PutUint16(buf[2*i:], uint16(modQ(p[i])))
    }
    return buf
}

func polyFromBytes(buf []byte) Poly {
    var p Poly
    for i := 0; i < N; i++ {
        p[i] = int64(binary.LittleEndian.Uint16(buf[2*i:]))
    }
    return p
}

func (pk *PublicKey) Marshal() []byte {
    out := make([]byte, 0, 14+N*4)
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
    if len(data) < 14 {
        return nil, fmt.Errorf("public key: data too short")
    }
    if string(data[:4]) != MagicPK {
        return nil, fmt.Errorf("public key: bad magic %q", data[:4])
    }
    if v := uint16(data[4])<<8 | uint16(data[5]); v != Version {
        return nil, fmt.Errorf("public key: unsupported version %d", v)
    }
    if n := int(binary.BigEndian.Uint32(data[6:10])); n != N {
        return nil, fmt.Errorf("public key: unsupported n=%d", n)
    }
    if q := int(binary.BigEndian.Uint32(data[10:14])); q != Q {
        return nil, fmt.Errorf("public key: unsupported q=%d", q)
    }
    need := 14 + N*4
    if len(data) < need {
        return nil, fmt.Errorf("public key: need %d bytes, got %d", need, len(data))
    }
    a := polyFromBytes(data[14 : 14+N*2])
    t := polyFromBytes(data[14+N*2 : 14+N*4])
    return &PublicKey{A: a, T: t}, nil
}

func (sk *SecretKey) Marshal() []byte {
    out := make([]byte, 0, 14+N*4)
    out = append(out, MagicSK...)
    out = append(out, byte(Version>>8), byte(Version))
    var tmp [4]byte
    binary.BigEndian.PutUint32(tmp[:], uint32(N))
    out = append(out, tmp[:]...)
    binary.BigEndian.PutUint32(tmp[:], uint32(Q))
    out = append(out, tmp[:]...)
    out = append(out, polyToBytes(&sk.A)...)
    out = append(out, polyToBytes(&sk.S)...)
    return out
}

func UnmarshalSecretKey(data []byte) (*SecretKey, error) {
    if len(data) < 14 {
        return nil, fmt.Errorf("secret key: data too short")
    }
    if string(data[:4]) != MagicSK {
        return nil, fmt.Errorf("secret key: bad magic %q", data[:4])
    }
    if v := uint16(data[4])<<8 | uint16(data[5]); v != Version {
        return nil, fmt.Errorf("secret key: unsupported version %d", v)
    }
    if n := int(binary.BigEndian.Uint32(data[6:10])); n != N {
        return nil, fmt.Errorf("secret key: unsupported n=%d", n)
    }
    if q := int(binary.BigEndian.Uint32(data[10:14])); q != Q {
        return nil, fmt.Errorf("secret key: unsupported q=%d", q)
    }
    need := 14 + N*4
    if len(data) < need {
        return nil, fmt.Errorf("secret key: need %d bytes, got %d", need, len(data))
    }
    a := polyFromBytes(data[14 : 14+N*2])
    s := polyFromBytes(data[14+N*2 : 14+N*4])
    return &SecretKey{A: a, S: s}, nil
}

// ────────────────────────── hybrid encrypt / decrypt ──────────────────────────

// Ciphertext file layout
//
//	[0:4]   magic "LTCT"
//	[4:6]   version (uint16 BE)
//	[6:18]  AES-GCM nonce  (12 bytes)
//	[18:22] AES ciphertext length incl. 16-byte tag  (uint32 BE)
//	[22:22+N*4]  RLWE ciphertext  (U poly || V poly)
//	[22+N*4 : …] AES-256-GCM ciphertext + tag

func EncryptMessage(pk *PublicKey, plaintext []byte) ([]byte, error) {
    // 1. Random symmetric key
    symKey := mustRand(KeyLen)

    // 2. Encapsulate key with Ring-LWE
    rlwe := EncryptKey(pk, symKey)

    // 3. Symmetric encryption with AES-256-GCM
    block, err := aes.NewCipher(symKey)
    if err != nil {
        return nil, fmt.Errorf("aes.NewCipher: %w", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("cipher.NewGCM: %w", err)
    }
    iv := mustRand(gcm.NonceSize()) // 12 bytes
    aesCT := gcm.Seal(nil, iv, plaintext, nil) // ciphertext || 16-byte tag

    // 4. Assemble output
    header := make([]byte, 0, 22)
    header = append(header, MagicCT...)
    header = append(header, byte(Version>>8), byte(Version))
    header = append(header, iv...)
    var lbuf [4]byte
    binary.BigEndian.PutUint32(lbuf[:], uint32(len(aesCT)))
    header = append(header, lbuf[:]...)

    rlweData := append(polyToBytes(&rlwe.U), polyToBytes(&rlwe.V)...)

    out := make([]byte, 0, len(header)+len(rlweData)+len(aesCT))
    out = append(out, header...)
    out = append(out, rlweData...)
    out = append(out, aesCT...)

    // scrub key from memory
    for i := range symKey {
        symKey[i] = 0
    }
    return out, nil
}

func DecryptMessage(sk *SecretKey, data []byte) ([]byte, error) {
    if len(data) < 22 {
        return nil, fmt.Errorf("ciphertext too short")
    }
    if string(data[:4]) != MagicCT {
        return nil, fmt.Errorf("bad magic %q", data[:4])
    }
    if v := uint16(data[4])<<8 | uint16(data[5]); v != Version {
        return nil, fmt.Errorf("unsupported version %d", v)
    }
    iv := data[6:18]
    aesLen := binary.BigEndian.Uint32(data[18:22])

    // Parse RLWE ciphertext
    rlweStart := 22
    rlweEnd := rlweStart + N*4
    if len(data) < rlweEnd {
        return nil, fmt.Errorf("ciphertext truncated (RLWE part)")
    }
    u := polyFromBytes(data[rlweStart : rlweStart+N*2])
    v := polyFromBytes(data[rlweStart+N*2 : rlweEnd])

    // Decapsulate symmetric key
    symKey := DecryptKey(sk, RLWECiphertext{U: u, V: v})

    // Symmetric decryption
    aesStart := rlweEnd
    if len(data) < aesStart+int(aesLen) {
        return nil, fmt.Errorf("ciphertext truncated (AES part)")
    }
    aesCT := data[aesStart : aesStart+int(aesLen)]

    block, err := aes.NewCipher(symKey)
    if err != nil {
        return nil, fmt.Errorf("aes.NewCipher: %w", err)
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("cipher.NewGCM: %w", err)
    }
    plain, err := gcm.Open(nil, iv, aesCT, nil)
    if err != nil {
        return nil, fmt.Errorf("AES-GCM open failed (wrong key?): %w", err)
    }
    return plain, nil
}

// ────────────────────────── CLI ──────────────────────────

func usage() {
    fmt.Fprintf(os.Stderr, `lpgp — LatticePGP: Post-Quantum Asymmetric Encryption
=====================================================
Algorithm : Ring-LWE   (n=%d, q=%d, err∈{-%d…%d})
Hybrid    : Ring-LWE encapsulation + AES-256-GCM
Security  : Post-quantum ~128-bit equivalent

Commands:
  keygen   Generate a new keypair
  encrypt  Encrypt a file with a public key
  decrypt  Decrypt a file with a secret key
  info     Show algorithm parameters

Usage:
  lpgp keygen   [-name BASENAME]
  lpgp encrypt  -pubkey FILE -in FILE -out FILE
  lpgp decrypt  -seckey FILE -in FILE -out FILE
  lpgp info
`, N, Q, B, B)
}

func cmdKeygen() {
    fs := flag.NewFlagSet("keygen", flag.ExitOnError)
    name := fs.String("name", "lattice", "base name for key files")
    fs.Parse(os.Args[2:])

    fmt.Println("Generating Ring-LWE keypair ...")
    pk, sk := KeyGen()

    pubFile := *name + ".lpub"
    secFile := *name + ".lsec"

    pubData := pk.Marshal()
    secData := sk.Marshal()

    if err := os.WriteFile(pubFile, pubData, 0644); err != nil {
        fmt.Fprintf(os.Stderr, "ERROR write public key: %v\n", err)
        os.Exit(1)
    }
    if err := os.WriteFile(secFile, secData, 0600); err != nil {
        fmt.Fprintf(os.Stderr, "ERROR write secret key: %v\n", err)
        os.Exit(1)
    }

    fp := sha256.Sum256(pubData)
    fmt.Printf("  Public key : %s  (%d bytes)\n", pubFile, len(pubData))
    fmt.Printf("  Secret key : %s  (%d bytes)\n", secFile, len(secData))
    fmt.Printf("  Fingerprint: %x\n", fp[:])
}

func cmdEncrypt() {
    fs := flag.NewFlagSet("encrypt", flag.ExitOnError)
    pkFile := fs.String("pubkey", "", "public key file (.lpub)")
    inFile := fs.String("in", "", "input plaintext file")
    outFile := fs.String("out", "", "output ciphertext file")
    fs.Parse(os.Args[2:])

    if *pkFile == "" || *inFile == "" || *outFile == "" {
        fmt.Fprintln(os.Stderr, "ERROR: -pubkey, -in, and -out are required")
        fs.Usage()
        os.Exit(1)
    }

    pkData, err := os.ReadFile(*pkFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read public key: %v\n", err)
        os.Exit(1)
    }
    pk, err := UnmarshalPublicKey(pkData)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR parse public key: %v\n", err)
        os.Exit(1)
    }

    plain, err := os.ReadFile(*inFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read input: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Encrypting %d bytes ...\n", len(plain))
    ct, err := EncryptMessage(pk, plain)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR encrypt: %v\n", err)
        os.Exit(1)
    }

    if err := os.WriteFile(*outFile, ct, 0644); err != nil {
        fmt.Fprintf(os.Stderr, "ERROR write output: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Done: %d -> %d bytes  (overhead %d)\n",
        len(plain), len(ct), len(ct)-len(plain))
}

func cmdDecrypt() {
    fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
    skFile := fs.String("seckey", "", "secret key file (.lsec)")
    inFile := fs.String("in", "", "input ciphertext file")
    outFile := fs.String("out", "", "output plaintext file")
    fs.Parse(os.Args[2:])

    if *skFile == "" || *inFile == "" || *outFile == "" {
        fmt.Fprintln(os.Stderr, "ERROR: -seckey, -in, and -out are required")
        fs.Usage()
        os.Exit(1)
    }

    skData, err := os.ReadFile(*skFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read secret key: %v\n", err)
        os.Exit(1)
    }
    sk, err := UnmarshalSecretKey(skData)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR parse secret key: %v\n", err)
        os.Exit(1)
    }

    ct, err := os.ReadFile(*inFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR read input: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("Decrypting ...")
    plain, err := DecryptMessage(sk, ct)
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR decrypt: %v\n", err)
        os.Exit(1)
    }

    if err := os.WriteFile(*outFile, plain, 0644); err != nil {
        fmt.Fprintf(os.Stderr, "ERROR write output: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Done: %d -> %d bytes\n", len(ct), len(plain))
}

func cmdInfo() {
    pubSize := 14 + N*4
    secSize := 14 + N*4
    rlweOverhead := N*4 + 22 + 16 // 2 polys + header + GCM tag

    fmt.Printf(`==============================================
 LatticePGP - Algorithm Information
==============================================
  Scheme       Ring-LWE
  Ring         Z_q[x] / (x^%d + 1)
  Modulus q    %d  (prime, 2n | q-1)
  Error bound  B = %d  (uniform in {-%d ... %d})
  Symmetric    AES-256-GCM
  PQ Security  ~128-bit equivalent
==============================================
  Public key   %5d bytes  (%.1f KB)
  Secret key   %5d bytes  (%.1f KB)
  CT overhead  ~%d bytes (RLWE+header+tag)
==============================================
  Decryption noise analysis (per coefficient):
    sigma(e*r)  ~ 128    sigma(s*e1) ~ 128    sigma(e2) ~ 2
    Total sigma ~ 181
    Threshold = q/4 = 3072  ->  ~17*sigma margin
    Failure probability < 10^-50
==============================================
`, N, Q, B, B, B,
        pubSize, float64(pubSize)/1024,
        secSize, float64(secSize)/1024,
        rlweOverhead)
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
    case "info":
        cmdInfo()
    case "help", "-h", "--help":
        usage()
    default:
        fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
        usage()
        os.Exit(1)
    }
}
