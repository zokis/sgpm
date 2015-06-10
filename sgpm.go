package main

import (
  "os"
  "fmt"
  "strconv"
  "strings"
  "crypto/cipher"
  "github.com/zokis/dwarfdb"
  "github.com/zokis/gopassgen"
  "github.com/gcmurphy/getpass"
  "code.google.com/p/go.crypto/blowfish"
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
  var aciton, key, norKey, path, securityKey, securityPass string
  actions := []string{"del", "find", "get", "new", "gen"}
  acitonOk := false
  args := os.Args
  if len(args) >= 2 {
    aciton = args[1]
    if stringInSlice(aciton, actions) {
      acitonOk = true
    }
    if len(args) >= 3 {
      key = args[2]
    }
  }

  defaultDB := "sgpm.dwarf"
  secretkey := getSecretKey()

  if path = os.Getenv("SGPM_DB_PATH"); len(path) <= 0 {
    fmt.Printf("Database [" + defaultDB + "]: ")
    fmt.Scanf("%s", &path)
    if len(path) <= 0 {
      path = defaultDB
    }
  }

  ddb := dwarfdb.DwarfDBLoad(path, true)

  if norKey = os.Getenv("SGPM_NOR_KEY"); len(norKey) <= 0 {
    norKey = "2d2d5b4e5d5b4f5d5b525d7c5b485d5b455d5b585d2d2d"
  }
  if securityPass = os.Getenv("SGPM_PASS"); len(securityPass) <= 0 {
    securityPass = "3a7d5d293e2d2d3c285b7b7c7d5d293e2d2d3c285b7b3a"
  }
  if securityKey = os.Getenv("SGPM_KEY"); len(securityKey) <= 0 {
    securityKey = "2e2d3e295d7d7b5b283c2d7c2d3e295d7d7b5b283c2d2e"
  }

  pass, err := ddb.Get(securityKey)
  if err == nil {
    if !strings.Contains(decryptPass(pass.(string), secretkey), securityPass) {
      nor, norErr := ddb.Get(norKey)
      norStr := nor.(string)
      if norErr == nil {
        if norStr == "3" {
          if ddb.DelDB() {
            fmt.Println("the database was destroyed")
          }
        } else {
          newNor, atoiErr := strconv.Atoi(norStr)
          if atoiErr == nil{
            ddb.Set(norKey, strconv.Itoa(newNor + 1))
          } else {
            ddb.Set(norKey, "1")
          }
        }
      }
      os.Exit(0)
    }
  } else {
    fmt.Println("New Database")
    ddb.Set(securityKey, encryptPass(securityPass, secretkey))
  }
  ddb.Set(norKey, "0")

  for !acitonOk {
    fmt.Printf("Aciton [" + strings.Join(actions, " ") + "]: ")
    fmt.Scanf("%s", &aciton)
    if stringInSlice(aciton, actions) {
      acitonOk = true
    }
  }

  if aciton != "gen" && key == "" {
    fmt.Printf("Key: ")
    fmt.Scanf("%s", &key)
  }

  if aciton == "find" {
    keys := ddb.GetAll()
    for i := 0; i < len(keys); i++ {
      ckey := keys[i]
      if strings.Contains(ckey, key) {
        if ckey != securityKey {
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
    passOk := false

    for !passOk {
      pass, err = getpass.GetPassWithOptions("Password: ", 1, getpass.DefaultMaxPass)
      if err == nil {
        passOk = true
      }
    }
    ddb.Set(key, encryptPass(pass, secretkey))
  } else if aciton == "del" {
    ddb.Rem(key)
  }
  os.Exit(0)
}
