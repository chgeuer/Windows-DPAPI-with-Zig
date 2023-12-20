# Exploring the Windows Data Protection API (DPAPI) Zig

The DPAPI features functions for encrypting/wrapping/protecting and decrypting/unwrapping/unprotecting data, namely [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) and [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata). 

This project features a little command line utility which reads encrypted data from stdin and writes to stdout.

These functions are implemented in `dpapi.h`. 

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