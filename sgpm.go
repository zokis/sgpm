package main

import (
  "os"
  "fmt"
  "strconv"
  "strings"
  "encoding/hex"
  "crypto/cipher"
  "github.com/zokis/dwarfdb"
  "github.com/zokis/gopassgen"
  "github.com/atotto/clipboard"
  "github.com/gcmurphy/getpass"
  "gopkg.in/alecthomas/kingpin.v2"
  "code.google.com/p/go.crypto/blowfish"
)

const (
  _GET = "get"
  _NEW = "new"
  _FIND = "find"
  _DEL = "del"
  _GEN = "gen"
  _CHANGE = "0x405f52f666146d5e05c51d1e0e245bd9"
)

var (
  app = kingpin.New("sgpm", "Simple Go Password Manager")

  cGet = app.Command("get", "get")
  gKey = cGet.Arg("key", "Key to get a password").String()

  cNew = app.Command("new", "new password")
  nKey = cNew.Arg("key", "Key for the new password").String()

  cFind = app.Command("find", "find a key")
  fKey = cFind.Arg("key", "Key to find").String()

  cDel = app.Command("del", "delete")
  dKey = cDel.Arg("key", "Key to delete a password").String()

  cGen = app.Command("gen", "gen password")
  gLen = cGen.Arg("length", "password length").Default("13").Int()
)

func blowfishChecksizeAndPad(pt []byte) []byte {
  mod := len(pt) % blowfish.BlockSize
  if mod != 0 {
    for i := 0; i < (blowfish.BlockSize - mod); i++ {
      pt = append(pt, 0)
    }
  }
  return pt
}
func blowfishDecrypt(et, key []byte) []byte {
  dcipher, err := blowfish.NewCipher(key)
  if err != nil {
    panic(err)
  }
  decrypted := et[blowfish.BlockSize:]
  if len(decrypted) % blowfish.BlockSize != 0 {
    panic("decrypted is not a multiple of blowfish.BlockSize")
  }
  dcbc := cipher.NewCBCDecrypter(dcipher, et[:blowfish.BlockSize])
  dcbc.CryptBlocks(decrypted, decrypted)
  return decrypted
}
func blowfishEncrypt(ppt, key []byte) []byte {
  ecipher, err := blowfish.NewCipher(key)
  if err != nil {
    panic(err)
  }
  ciphertext := make([]byte, blowfish.BlockSize+len(ppt))
  ecbc := cipher.NewCBCEncrypter(ecipher, ciphertext[:blowfish.BlockSize])
  ecbc.CryptBlocks(ciphertext[blowfish.BlockSize:], ppt)
  return ciphertext
}
func decryptPass(pass, secretkey string) string {
  return string(blowfishDecrypt([]byte(pass), []byte(secretkey))[:])
}
func encryptPass(pass, secretkey string) string {
  return string(blowfishEncrypt(blowfishChecksizeAndPad([]byte(pass)), []byte(secretkey))[:])
}

func ksa(key []byte) []byte {
  s := make([]byte, 256)
  for i := range s {
    s[i] = byte(i)
  }
  j := byte(0)
  for i := range s {
    j += s[i] + key[i%len(key)]
    s[i], s[j] = s[j], s[i]
  }
  return s
}
func prga(message, s []byte) []byte {
  text := make([]byte, len(message))
  i, j := byte(0), byte(0)
  for m := range message {
    i++
    j += s[i]
    s[i], s[j] = s[j], s[i]
    k := s[s[i]+s[j]]
    text[m] = message[m] ^ k
  }
  return text
}
func rc4(message, key []byte) []byte { return prga(message, ksa(key)) }
func encode(text, key string) string { return hex.EncodeToString(rc4([]byte(text), []byte(key))) }
func decode(text, key string) string {
  x, err := hex.DecodeString(text)
  if err == nil {
    return string(rc4(x, []byte(key)))
  }
  panic(err)
}
func encodeC(text string) string { return encode(text, _CHANGE) }
func decodeC(text string) string { return decode(text, _CHANGE) }

func getSecretKey(c int) string {
  secretkey, err := getpass.GetPassWithOptions("Secret Key: ", c, getpass.DefaultMaxPass)
  if err != nil {
    os.Exit(0)
  }
  return secretkey
}

func main() {
  var aciton, key, norKey, path, secretkey, securityKey, securityPass string
  switch kingpin.MustParse(app.Parse(os.Args[1:])) {
    case cGet.FullCommand():
      aciton = _GET
      key = encodeC(string(*gKey))
    case cNew.FullCommand():
      aciton = _NEW
      key = encodeC(string(*nKey))
    case cFind.FullCommand():
      aciton = _FIND
      key = encodeC(string(*fKey))
    case cDel.FullCommand():
      aciton = _DEL
      key = encodeC(string(*dKey))
    case cGen.FullCommand():
      fmt.Printf("%s\n", gopassgen.NewPassword(gopassgen.OptionLength(*gLen)))
      os.Exit(0)
  }

  defaultDB := "sgpm.dwarf"
  if path = os.Getenv("SGPM_DB_PATH"); len(path) <= 0 {
    fmt.Printf("Database [" + defaultDB + "]: ")
    fmt.Scanf("%s", &path)
    if len(path) <= 0 {
      path = defaultDB
    }
  }
  ddb := dwarfdb.DwarfDBLoad(path, true)
  if norKey = encodeC(os.Getenv("SGPM_NOR_KEY")); len(norKey) <= 0 {
    norKey = encodeC("0x2b4674dca78cfde8d3d5a0d100996c941038ef71100")
  }
  if securityKey = encodeC(os.Getenv("SGPM_KEY")); len(securityKey) <= 0 {
    securityKey = encodeC("0x117498f0ea387cea4b00f77e8693ff9367a6L6")
  }
  if securityPass = encodeC(os.Getenv("SGPM_PASS")); len(securityPass) <= 0 {
    securityPass = encodeC("0x27690b1e0e5bf93eb514035c824b85d3c274c")
  }
  pass, err := ddb.Get(securityKey)
  if err == nil {
    secretkey = getSecretKey(0)
    if !strings.Contains(decryptPass(pass.(string), secretkey), securityPass) {
      nor, norErr := ddb.Get(norKey)
      newNor, cErr := strconv.ParseInt(nor.(string), 2, 64)
      delDB := false
      if norErr == nil {
        if newNor > 3 {
          delDB = true
        } else {
          if cErr == nil{
            ddb.Set(norKey, strconv.FormatInt(int64(newNor + 1), 2))
          } else {
            delDB = true
          }
        }
      }
      if delDB {
        ddb.DelDB()
        fmt.Println("the database was destroyed")
      }
      os.Exit(0)
    }
  } else {
    fmt.Println("New Database")
    secretkey = getSecretKey(1)
    ddb.Set(securityKey, encryptPass(securityPass, secretkey))
  }
  ddb.Set(norKey, "1")
  if key == "" {
    fmt.Printf("Key: ")
    fmt.Scanf("%s", &key)
  }
  if aciton == _FIND {
    keys := ddb.GetAll()
    key := decodeC(key)
    for i := 0; i < len(keys); i++ {
      ckey := keys[i]
      dkey := decodeC(keys[i])
      if ckey != securityKey && ckey != norKey && strings.Contains(dkey, key) {
        fmt.Printf("%s\n", decodeC(ckey))
      }
    }
  } else if aciton == _GET {
    pass, err := ddb.Get(key)
    if err == nil {
      dp := decryptPass(pass.(string), secretkey)
      if err := clipboard.WriteAll(dp); err != nil {
        fmt.Println("an error occurred while copying the password to the clipboard")
      }
    }
  } else if aciton == _NEW {
    var pass string
    passOk := false
    for !passOk {
      pass, err = getpass.GetPassWithOptions("Password: ", 1, getpass.DefaultMaxPass)
      passOk = err == nil
    }
    ddb.Set(key, encryptPass(pass, secretkey))
  } else if aciton == _DEL {
    ddb.Rem(key)
  }
  os.Exit(0)
}
