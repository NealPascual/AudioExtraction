﻿using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public class AudioExtraction
{
    public static void Main()
    {
        //FileEncrypt(@"C:\Users\neal.pascual\Desktop\test\sample_wav_10.wav", "nealpascual");
        //FileEncrypt(@"C:\Users\neal.pascual\Desktop\test\in.txt", "nealpascual");
        FileDecrypt(@"C:\Users\neal.pascual\Desktop\test\in.txt", "nealpascual");
        //FileDecrypt(@"C:\Users\neal.pascual\Desktop\test\sample_wav_10.wav", "nealpascual");
    }
    //  Call this function to remove the key from memory after use for security
    [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
    public static extern bool ZeroMemory(IntPtr Destination, int Length);


    public static byte[] GenerateRandomSalt()
    {
        byte[] data = new byte[32];

        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            for (int i = 0; i < 10; i++)
            {
                // Fille the buffer with the generated data
                rng.GetBytes(data);
            }
        }

        return data;
    }

    private static void FileEncrypt(string inputFile, string password)
    {
        //http://stackoverflow.com/questions/27645527/aes-encryption-on-large-files

        //generate random salt
        byte[] salt = GenerateRandomSalt();

        //create output file name
        FileStream fsCrypt = new FileStream(inputFile + ".aes", FileMode.Create);
        //FileStream fsCrypt = new FileStream(@"C:\Users\neal.pascual\Desktop\test\encrypted.txt", FileMode.Create);

        //convert password string to byte arrray
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        //Set Rijndael symmetric encryption algorithm
        RijndaelManaged AES = new RijndaelManaged();
        AES.KeySize = 256;
        AES.BlockSize = 128;
        AES.Padding = PaddingMode.PKCS7;

        //http://stackoverflow.com/questions/2659214/why-do-i-need-to-use-the-rfc2898derivebytes-class-in-net-instead-of-directly
        //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
        var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
        AES.Key = key.GetBytes(AES.KeySize / 8);
        AES.IV = key.GetBytes(AES.BlockSize / 8);

        //Cipher modes: http://security.stackexchange.com/questions/52665/which-is-the-best-cipher-mode-and-padding-mode-for-aes-encryption
        AES.Mode = CipherMode.CFB;

        // write salt to the begining of the output file, so in this case can be random every time
        fsCrypt.Write(salt, 0, salt.Length);

        CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

        FileStream fsIn = new FileStream(inputFile, FileMode.Open);

        //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
        byte[] buffer = new byte[1048576];
        int read;

        try
        {
            while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
            {
                //Application.DoEvents(); // -> for responsive GUI, using Task will be better!
                cs.Write(buffer, 0, read);
            }

            // Close up
            fsIn.Close();
            //fsCrypt.Close(); //temp
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
        finally
        {
            cs.Close();
            fsCrypt.Close();

            File.Delete(inputFile);
            FileInfo fi = new FileInfo(inputFile + ".aes");
            fi.MoveTo(inputFile);
        }
    }

    private static void FileDecrypt(string inputFile, string password) // string outputFile,
    {
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        byte[] salt = new byte[32];

        FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
        fsCrypt.Read(salt, 0, salt.Length);

        RijndaelManaged AES = new RijndaelManaged();
        AES.KeySize = 256;
        AES.BlockSize = 128;
        var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
        AES.Key = key.GetBytes(AES.KeySize / 8);
        AES.IV = key.GetBytes(AES.BlockSize / 8);
        AES.Padding = PaddingMode.PKCS7;
        AES.Mode = CipherMode.CFB;

        CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

        FileStream fsOut = new FileStream(inputFile + ".aes", FileMode.Create);

        int read;
        byte[] buffer = new byte[1048576];

        try
        {
            while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
            {
                fsOut.Write(buffer, 0, read);
            }
        }
        catch (CryptographicException ex_CryptographicException)
        {
            Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }

        try
        {
            cs.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
        }
        finally
        {
            fsOut.Close();
            fsCrypt.Close();

            File.Delete(inputFile);
            FileInfo fi = new FileInfo(inputFile + ".aes");
            fi.MoveTo(inputFile);
        }
    }
}