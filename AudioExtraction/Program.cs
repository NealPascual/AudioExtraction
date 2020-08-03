using System;
using System.Configuration;
using System.IO;
using System.Security.Cryptography;

public class AudioExtraction
{
    public static void Main(string[] args)
    {
        string FilePath = args[0];
        string StoragePath = ConfigurationManager.AppSettings["storagePath"];
        string ActionType = args[1];
                

        var password = ConfigurationManager.AppSettings["pass"];

        try
        {
            if (ActionType.ToLower() == "encrypt" && FilePath != null)
            {
                FileEncrypt(FilePath, StoragePath, password);
                Console.WriteLine("Encryption Successful.");
                Console.ReadKey();
            }
            else if (ActionType.ToLower() == "decrypt" && FilePath != null)
            {
                FileDecrypt(FilePath, StoragePath, password);
                Console.WriteLine("Decryption Successful.");
                Console.ReadKey();
            }
            else
                Console.WriteLine("Invalid arguments");


        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            Console.ReadKey();
        }

    }

    public static byte[] GenerateRandomSalt()
    {
        byte[] data = new byte[32];

        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            for (int i = 0; i < 10; i++)
            {
                // Fill the buffer with the generated data
                rng.GetBytes(data);
            }
        }

        return data;
    }

    private static void FileEncrypt(string inputFile, string storagePath, string password)
    {

        //generate random salt
        byte[] salt = GenerateRandomSalt();

        //storagePath = (storagePath == null) ? inputFile + ".aes" : storagePath;
        if (storagePath == "")
            storagePath = inputFile + ".aes";
        else
        {
            if (storagePath.LastIndexOf(@"\") == storagePath.Length - 1)
                storagePath += inputFile.Substring(inputFile.LastIndexOf(@"\") + 1);
            else
                storagePath += @"\" + inputFile.Substring(inputFile.LastIndexOf(@"\") + 1);
        }

        //create output file name
        FileStream fsCrypt = new FileStream(storagePath, FileMode.Create);

        //convert password string to byte arrray
        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        //Set Rijndael symmetric encryption algorithm
        RijndaelManaged AES = new RijndaelManaged();
        AES.KeySize = 256;
        AES.BlockSize = 128;
        AES.Padding = PaddingMode.PKCS7;

        var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
        AES.Key = key.GetBytes(AES.KeySize / 8);
        AES.IV = key.GetBytes(AES.BlockSize / 8);

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
                cs.Write(buffer, 0, read);
            }

            // Close up
            fsIn.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
        finally
        {
            cs.Close();
            fsCrypt.Close();
        }
    }

    private static void FileDecrypt(string inputFile, string storagePath, string password)
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


        //storagePath = (storagePath == null) ? inputFile.Substring(0, inputFile.LastIndexOf(".")) : storagePath;
        if (storagePath == "")
            storagePath = inputFile.Substring(0, inputFile.LastIndexOf(".")) + inputFile.Substring(inputFile.LastIndexOf(".")) + ".aes";
        else
        {
            if (storagePath.LastIndexOf(@"\") == storagePath.Length - 1)
                storagePath += inputFile.Substring(inputFile.LastIndexOf(@"\") + 1);
            else
                storagePath += @"\" + inputFile.Substring(inputFile.LastIndexOf(@"\") + 1);
        }

        FileStream fsOut = new FileStream(storagePath, FileMode.Create);

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
        }
    }
}