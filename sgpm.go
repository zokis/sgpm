package main

import (
  "code.google.com/p/go.crypto/blowfish"
  "crypto/cipher"
  "fmt"
  "github.com/gcmurphy/getpass"
  "github.com/zokis/dwarfdb"
  "os"
  "strings"
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
  if len(decrypted)%blowfish.BlockSize != 0 {
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

func getSecretKey() string {
  secretkey, err := getpass.GetPassWithOptions("Secret Key: ", 1, getpass.DefaultMaxPass)
  if err != nil {
    os.Exit(0)
  }
  return secretkey
}

func stringInSlice(a string, list []string) bool {
  for _, b := range list {
    if b == a {
      return true
    }
  }
  return false
}

func main() {
  var aciton, path, key, security_pass, security_key string
  default_db := "sgpm.dwarf"

  secretkey := getSecretKey()

  if path = os.Getenv("SGPM_DB_PATH"); len(path) <= 0 {
    fmt.Printf("Database [" + default_db + "]: ")
    fmt.Scanf("%s", &path)
    if len(path) <= 0 {
      path = default_db
    }
  }

  ddb := dwarfdb.DwarfDBLoad(path, true)

  if security_pass = os.Getenv("SGPM_PASS"); len(security_pass) <= 0 {
    security_pass = "3a7d5d293e2d2d3c285b7b7c7d5d293e2d2d3c285b7b3a"
  }
  if security_key = os.Getenv("SGPM_KEY"); len(security_key) <= 0 {
    security_key = "2e2d3e295d7d7b5b283c2d7c2d3e295d7d7b5b283c2d2e"
  }

  pass, err := ddb.Get(security_key)
  if err == nil {
    if !strings.Contains(decryptPass(pass.(string), secretkey), security_pass) {
      os.Exit(0)
    }
  } else {
    fmt.Printf("New Database")
    ddb.Set(security_key, encryptPass(security_pass, secretkey))
  }

  actions := []string{"del", "find", "get", "new"}
  aciton_ok := false
  for !aciton_ok {
    fmt.Printf("Aciton [" + strings.Join(actions, " ") + "]: ")
    fmt.Scanf("%s", &aciton)
    if stringInSlice(aciton, actions) {
      aciton_ok = true
    }
  }

  fmt.Printf("Key: ")
  fmt.Scanf("%s", &key)

  if aciton == "find" {
    keys := ddb.GetAll()
    for i := 0; i < len(keys); i++ {
      ckey := keys[i]
      if strings.Contains(ckey, key) {
        if ckey != security_key {
          fmt.Printf("%s\n", ckey)
        }
      }
    }
  } else if aciton == "get" {
    pass, err := ddb.Get(key)
    if err == nil {
      fmt.Println(decryptPass(pass.(string), secretkey))
    }
  } else if aciton == "new" {
    var pass string
    var err error
    pass_ok := false

    for !pass_ok {
      pass, err = getpass.GetPassWithOptions("Password: ", 1, getpass.DefaultMaxPass)
      if err == nil {
        pass_ok = true
      }
    }
    ddb.Set(key, encryptPass(pass, secretkey))
  } else if aciton == "del" {
    ddb.Rem(key)
  }
  os.Exit(0)
}
