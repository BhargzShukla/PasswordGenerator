using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Text;
using System.Security.Cryptography;

namespace PasswordGenerator
{
    class Request
    {
        public int PasswordLength { get; set; }
        public bool Uppercase { get; set; } = false;
        public bool Symbols { get; set; } = false;
        public bool Numbers { get; set; } = false;
    }

    class Response
    {
        public string Password { get; set; }
        public double Strength { get; set; }
    }

    class Error
    {
        public int ErrorCode { get; set; }
        public string Message { get; set; }
    }

    class Generator
    {
        private readonly char[] lowercase = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        private readonly char[] uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
        private readonly char[] numbers = "0123456789".ToCharArray();
        private readonly char[] symbols = "~`!@#$%^&*()-=_+[]{};:,./<>?|".ToCharArray();

        public string GetPassword(int passwordLength, char[] pool)
        {

            byte[] data = new byte[4 * passwordLength];
            StringBuilder passwordBuilder = new StringBuilder();

            using (var crypto = RandomNumberGenerator.Create())
            {
                crypto.GetBytes(data);
            }

            for (int i = 0; i < passwordLength; i++)
            {
                var rnd = BitConverter.ToUInt32(data, i * 4);
                var idx = rnd % pool.Length;
                passwordBuilder.Append(pool[idx]);
            }

            return passwordBuilder.ToString();
        }

        public double GetPasswordStrength(int passwordLength, int poolLength)
        {
            return passwordLength * (Math.Log10(poolLength) / Math.Log10(2));
        }

        public char[] GetPool(Request req)
        {
            StringBuilder poolBuilder = new StringBuilder().Append(lowercase);

            if (req.Uppercase) poolBuilder.Append(uppercase);
            if (req.Numbers) poolBuilder.Append(numbers);
            if (req.Symbols) poolBuilder.Append(symbols);

            return poolBuilder.ToString().ToCharArray();
        }
    }

    public static class PasswordGenerator
    {
        private static Generator _generator = new Generator();

        [FunctionName("PasswordGenerator")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            Request request = JsonConvert.DeserializeObject<Request>(requestBody);

            if (request.PasswordLength < 8 || request.PasswordLength > 64)
            {
                log.LogError("Password length must be between 8 and 64.");
                return new BadRequestObjectResult(new Error()
                {
                    ErrorCode = StatusCodes.Status400BadRequest,
                    Message = "Password length must be between 8 & 64."
                });
            }

            char[] pool = _generator.GetPool(request);
            string password = _generator.GetPassword(request.PasswordLength, pool);
            double passwordStrength = _generator.GetPasswordStrength(password.Length, pool.Length);

            return new OkObjectResult(new Response()
            {
                Password = password,
                Strength = passwordStrength
            });
        }
    }
}
