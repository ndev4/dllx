# dllx

Lists the DLLs a Windows executable or DLL depends on, like `ldd`, without loading or running it.

## Build

```
cargo build --release
```

The binary is `target/release/dllx.exe`.

## Usage

```
dllx [OPTION]... FILE...

      --posix-paths    print paths as /c/... instead of C:\...
      --delay          also list delay-loaded DLLs, marked [delay]
      --pretty         line up the => arrows
  -h, --help           show this help and exit
  -V, --version        show the version and exit
```

```
$ dllx --pretty version.dll
	msvcrt.dll     => C:\Windows\System32\msvcrt.dll (0x110100000)
	ntdll.dll      => C:\Windows\System32\ntdll.dll (0x180000000)
	kernelbase.dll => C:\Windows\System32\KernelBase.dll (0x180000000)
	kernel32.dll   => C:\Windows\System32\kernel32.dll (0x180000000)
```
