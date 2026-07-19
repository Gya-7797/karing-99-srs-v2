package main

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/sagernet/sing-box/common/srs"
    C "github.com/sagernet/sing-box/constant"
    "github.com/sagernet/sing-box/option"
)

func main() {
    if len(os.Args) != 3 {
        fmt.Fprintln(os.Stderr, "usage: srscompiler input.json output.srs")
        os.Exit(2)
    }
    input, err := os.ReadFile(os.Args[1])
    if err != nil { panic(err) }
    var plain option.PlainRuleSet
    if err := json.Unmarshal(input, &plain); err != nil { panic(err) }
    version := uint8(0)
    var v struct{ Version uint8 `json:"version"` }
    _ = json.Unmarshal(input, &v)
    version = v.Version
    if version == 0 { version = C.RuleSetVersionCurrent }
    out, err := os.Create(os.Args[2])
    if err != nil { panic(err) }
    defer out.Close()
    if err := srs.Write(out, plain, version); err != nil { panic(err) }
}
