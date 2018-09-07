using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace WidevineDotnet.Controllers
{

    [Route("[controller]")]
    [ApiController]
    public class ProxyController : ControllerBase
    {
        private readonly ILogger _logger;
        private IConfiguration _configuration;

        public ProxyController(ILogger<ProxyController> logger, IConfiguration Configuration)
        {
            _logger = logger;
            _configuration = Configuration;
        }

        // Provider Information 
        // Replace PROVIDER and _KEY and _IV with your provider credentials
        private readonly byte[] _KEY = Util.HexadecimalStringToByteArray("1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9");
        private readonly byte[] _IV = Util.HexadecimalStringToByteArray("d58ce954203b7c9a9a9d467f59839249");
        private const string PROVIDER = "widevine_test";

        // License Values 
        private const string LICENSE_SERVER_URL = "https://license.uat.widevine.com/cenc/getlicense";
        private const string ALLOWED_TRACK_TYPES = "SD_HD";

        private bool parseonly = false;
        private string contentId = "";
        private string keyId = "";


        // GET proxy
        [HttpGet]
        public ActionResult<string> Get()
        {
            return "GET Not SupportedNone";
        }

        // POST proxy
        [HttpPost]
        public async Task<IActionResult> Post()
        {
            string payload = Util.ConvertToBase64(HttpContext.Request.Body);
            if (string.IsNullOrEmpty(payload))
            {
                _logger.LogError("BadRequest, body is empty");
                return BadRequest("BadRequest, body is empty");
            }
            this.parseonly = false;
            this.contentId = "";
            this.keyId = "";
            if (Request.Query.ContainsKey("parseonly"))
            {
                this.parseonly = true;
            }
            if (Request.Query.ContainsKey("contentId"))
            {
                this.contentId = Request.Query["contentId"].ToString();
            }
            if (Request.Query.ContainsKey("keyId"))
            {
                this.keyId = Request.Query["keyId"].ToString();
            }

            string response;
            if (payload.Length < 50)
            {
                response = await this.SendRequest(this.BuildCertificateRequest(payload));
            }
            else
            {
                response = await this.SendRequest(this.BuildLicenseServerRequest(payload));
            }

            byte[] responseBytes = this.ProcessLicenseResponse(response);
            if (responseBytes.Length == 0)
            {
                return Content(response, "application/x-javascript");
            }
            else
            {
                return File(responseBytes, "application/octet-stream");
            }
        }


        private async Task<string> SendRequest(string request)
        {
            // Send HTTP request to Widevine 
            HttpClient client = new HttpClient();
            var url = ProxyController.LICENSE_SERVER_URL + "/" + ProxyController.PROVIDER;
            HttpResponseMessage response = await client.PostAsync(url, new StringContent(request));
            string payload;
            if (response.IsSuccessStatusCode)
            {
                payload = await response.Content.ReadAsStringAsync();
            }
            else
            {
                string msg = await response.Content.ReadAsStringAsync();
                _logger.LogError(msg);
                throw new Exception(response.StatusCode + " message:" + msg);
            }
            return payload;
        }


        private string BuildCertificateRequest(string payload)
        {
            // Builds JSON requests to be sent to the license server. 
            string message = this.BuildCertificateMessage(payload);
            var certificate_request = new
            {
                request = Util.Base64Encode(message),
                signature = this.GenerateSignature(message),
                signer = ProxyController.PROVIDER
            };
            return Util.JsonDump(certificate_request);
        }


        private string BuildCertificateMessage(string payload)
        {
            // Build a certificate request to be sent to Widevine Service. 
            var request = new
            {
                payload = payload
            };
            return Util.JsonDump(request);
        }


        private string BuildLicenseServerRequest(string payload)
        {
            // Builds JSON requests to be sent to the license server. 
            string message = this.BuildLicenseMessage(payload);
            var license_server_request = new
            {
                request = Util.Base64Encode(message),
                signature = this.GenerateSignature(message),
                signer = ProxyController.PROVIDER
            };
            return Util.JsonDump(license_server_request);
        }


        private string BuildLicenseMessage(string payload)
        {
            string contentId64 = "";
            if (!string.IsNullOrEmpty(this.contentId))
            {
                contentId64 = Util.Base64Encode(this.contentId);
            }

            // Build a license request to be sent to Widevine Service. 
            var request = new
            {
                payload = payload,
                provider = ProxyController.PROVIDER,
                allowed_track_types = ProxyController.ALLOWED_TRACK_TYPES,
                parse_only = this.parseonly,
                content_id = contentId64
            };
            return Util.JsonDump(request);
        }


        private byte[] ProcessLicenseResponse(string response)
        {
            // Decode License Response and pass to player 
            _logger.LogInformation("license_response", response);
            JObject responseObj = JObject.Parse(response);
            if (responseObj["status"].ToString() == "OK")
            {
                //Trace devices that not send security_level
                if (responseObj.ContainsKey("message_type") &&
                    responseObj["message_type"].ToString() != "SERVICE_CERTIFICATE")
                {
                    if (!responseObj.ContainsKey("security_level") ||
                        string.IsNullOrEmpty(responseObj["security_level"].ToString()))
                    {
                        _logger.LogError("No security_level", response);
                    }
                }

                if (responseObj.ContainsKey("license"))
                {
                    byte[] license_decoded = System.Convert.FromBase64String(responseObj["license"].ToString());
                    return license_decoded;
                }
                else
                {
                    //"PARSE_ONLY request, no 'license' found."
                    return new byte[] { };
                }
            }
            _logger.LogInformation("Widevine error", response);
            throw new Exception("Widevine error" + response);
        }


        private string GenerateSignature(string text_to_sign)
        {
            // Ingest License Request and Encrypt 
            byte[] hash;
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(text_to_sign));
            }
            hash = Util.PaddningBytes(hash);
            byte[] signature = Util.EncryptStringToBytes_Aes(hash, this._KEY, this._IV);
            string signatureBase64 = Convert.ToBase64String(signature);
            return signatureBase64;
        }
    }
}