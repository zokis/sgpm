package main

import (
  "os"
  "fmt"
  "strconv"
  "strings"
  "crypto/cipher"
  "github.com/zokis/dwarfdb"
  "github.com/zokis/gopassgen"
  "github.com/atotto/clipboard"
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

func getSecretKey(c int) string {
  secretkey, err := getpass.GetPassWithOptions("Secret Key: ", c, getpass.DefaultMaxPass)
  if err != nil {
    os.Exit(0)
  }
  return secretkey
}

func stringInSlice(s string, list []string) bool {
  for k, e := range list {
    if e == s {
      return k + 1
    }
  }
  return 0
}

func main() {
  var aciton, key, norKey, path, securityKey, securityPass string
  acitonOk := false
  copy := true
  keyInt := 13
  _C := "-C"
  _E := ""
  _DEL := "del"
  _FIND := "find"
  _GEN := "gen"
  _GET := "get"
  _NEW := "new"
  actions := []string{_DEL, _FIND, _GEN, _GET, _NEW}
  args := os.Args[1:]

  if stringInSlice(_C, args) > 0 {
    copy = false
  }
  if len(args) >= 1 {
    aciton = args[0]
    if stringInSlice(aciton, actions) > 0 {
      acitonOk = true
    }
    if len(args) >= 2 {
      key = args[1]
      if key == _C {
        key = _E
      }
    }
  }
  if aciton == _GEN {
    if key != _E {
      var err error
      keyInt, err = strconv.Atoi(key)
      if err != nil {
        keyInt = 13
      }
    }
    fmt.Printf("%s\n", gopassgen.NewPassword(gopassgen.OptionLength(keyInt)))
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
  if norKey = os.Getenv("SGPM_NOR_KEY"); len(norKey) <= 0 {
    norKey = "0x2b4674dca78cfde8d3d5a0d100996c941038ef71100"
  }
  if securityPass = os.Getenv("SGPM_PASS"); len(securityPass) <= 0 {
    securityPass = "0x27690b1e0e5bf93eb514035c824b85d3c274c"
  }
  if securityKey = os.Getenv("SGPM_KEY"); len(securityKey) <= 0 {
    securityKey = "0x117498f0ea387cea4b00f77e8693ff9367a6L6"
  }
  secretkey := getSecretKey(0)
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
    acitonOk = stringInSlice(aciton, actions) > 0
  }
  if aciton != _GEN && key == _E {
    fmt.Printf("Key: ")
    fmt.Scanf("%s", &key)
  }
  if aciton == _FIND {
    keys := ddb.GetAll()
    for i := 0; i < len(keys); i++ {
      ckey := keys[i]
      if ckey != securityKey && ckey != norKey && strings.Contains(ckey, key) {
        fmt.Printf("%s\n", ckey)
      }
    }
  } else if aciton == _GET {
    pass, err := ddb.Get(key)
    if err == nil {
      dp := decryptPass(pass.(string), secretkey)
      if copy {
        if err := clipboard.WriteAll(string(dp)); err != nil {
          fmt.Println("an error occurred while copying the password to the clipboard")
        }
      } else {
        fmt.Println(dp)
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
  } else if aciton == _GEN {
    fmt.Printf("%s\n", gopassgen.NewPassword(gopassgen.OptionLength(13)))
  }
  os.Exit(0)
}
