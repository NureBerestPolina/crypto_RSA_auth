using System.Security.Cryptography;
using System.Text;

namespace RSA_auth.Services
{
    public class RsaService : IRsaService
    {
        private readonly RSACryptoServiceProvider _rsa;
        private readonly IConfiguration _configuration;
        public RsaService(IConfiguration configuration)
        {
            _rsa = new RSACryptoServiceProvider();
            _configuration = configuration;
            Configure();
        }
        public string DecryptData(string data)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(data);
            byte[] decryptedData = _rsa.Decrypt(dataToDecrypt,
           RSAEncryptionPadding.Pkcs1);
            return Encoding.UTF8.GetString(decryptedData);
        }
        public string GetPublicKey()
        {
            var rsaPublicKeyBytes = _rsa.ExportRSAPublicKeyPem();
            return rsaPublicKeyBytes;
        }
        private void Configure()
        {
            var rsaPublicKey = _configuration["RsaKeys:PublicKey"];
            var rsaPrivateKey = _configuration["RsaKeys:PrivateKey"];
            _rsa.ImportFromPem(rsaPublicKey);
            _rsa.ImportFromPem(rsaPrivateKey);
        }
    }
}
