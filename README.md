# Exploring the Windows Data Protection API (DPAPI) from [Zig](https://ziglang.org/)

This project features a little command line utility which reads encrypted data from stdin and writes to stdout.

The [Microsoft Windows Data Protection API (DPAPI)](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/) features functions for encrypting/wrapping/protecting and decrypting/unwrapping/unprotecting data, namely [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) and [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata). These functions are defined in `dpapi.h`. 

## Compiling and running

The following command compiles a small CLI application (18kB on Windows):

```shell
zig build -Doptimize=ReleaseSmall
```

Then you pipe the contents of an encrypted file into the executable, and process the output like you wish. For example, on Windows, the Azure CLI stores all management tokens as JSON structure in an encrypted file in my `.azure` directory. The following pipeline pipes that file into the decryption utility and uses [JQ](https://jqlang.github.io/jq/) to pretty-print parts of the JSON.

```shell
type %USERPROFILE%\.azure\msal_token_cache.bin | .\zig-out\bin\dpapi-unprotect.exe  | jq.exe ".RefreshToken"
```

## Alternative in NET

The C# version would be along these lines (using `System.Security.dll`):

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

internal class Program
{
    static void Main(string[] args)
    {
        var input = "Hallo, Welt!";
        byte[] wrapped = Encrypt(input);
        File.WriteAllBytes(@"C:\Users\chgeuer\Desktop\zig2\dpapi_encrypted.bin", wrapped);

        Console.WriteLine(Convert.ToBase64String(wrapped));
        Console.WriteLine(Decrypt(wrapped));
    }

    private static byte[] Encrypt(string userData) =>
        ProtectedData.Protect(
            userData: Encoding.UTF8.GetBytes(userData),
            optionalEntropy: null,
            scope: DataProtectionScope.CurrentUser);

    private static string Decrypt(byte[] wrapped) =>
        Encoding.UTF8.GetString(
            ProtectedData.Unprotect(
                encryptedData: wrapped,
                optionalEntropy: null, 
                scope: DataProtectionScope.CurrentUser));
}
```