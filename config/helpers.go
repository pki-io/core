package config

import (
    "os"
)

func Exists(name string) (bool, error) {
  if f, err := os.Open(name); err != nil {
      if os.IsNotExist(err) {
          return false, nil
      } else {
          return false, err
      }
  } else {
      f.Close()
      return true, nil
  }
}
