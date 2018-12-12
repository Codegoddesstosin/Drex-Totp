using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Description;
using Witts_Stratts.Framework;

namespace Witts_Stratts.Web.Controllers
{
    [RoutePrefix("api/otp")]
    public class OtpController : ApiController
    {
        private static readonly string SecretKey = ConfigurationManager.AppSettings["SECRET_KEY"];
        [HttpGet]
        [ResponseType(typeof(string))]
        [Route("generateotp")]
        public string GenerateOtp()
        {
            var otp = new OneTimePassword(SecretKey);
            var otpCode = otp.GetCode().ToString("000000");
            return otpCode;
        }

        [HttpPost]
        [ResponseType(typeof(string))]
        [Route("verifyotp")]
        public string VerifyOtp(Data data)
        {
            var otp = new OneTimePassword(SecretKey);
            var isValid = otp.IsCodeValid(data.OtpCode);

            return isValid ? "The code you supplied is valid" : "The code you supplied is invalid";
        }
    }

    public class Data
    {
        public string OtpCode { get; set; }
    }
}