using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace WidevineDotnet.Controllers
{

    [Route("[controller]")]
    [ApiController]
    public class ProxyController : ControllerBase
    {
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;

        // Provider Information 
        // Replace PROVIDER and _KEY and _IV with your provider credentials in appsettings
        private readonly byte[] _KEY;
        private readonly byte[] _IV;
        private readonly string _PROVIDER;

        // License Values 
        private readonly string _LICENSE_SERVER_URL;
        private readonly string _ALLOWED_TRACK_TYPES;

        // From query string if applied
        private string contentId = "";
        private string keyId = "";

        public ProxyController(ILogger<ProxyController> logger, IConfiguration Configuration)
        {
            _logger = logger;
            _configuration = Configuration;

            _KEY = Util.HexStringToByteArray(_configuration["PROVIDER_KEY"]);
            _IV = Util.HexStringToByteArray(_configuration["PROVIDER_IV"]);
            _PROVIDER = _configuration["PROVIDER"];
            _LICENSE_SERVER_URL = _configuration["LICENSE_SERVER_URL_TEST"];
            _ALLOWED_TRACK_TYPES = _configuration["ALLOWED_TRACK_TYPES"];
        }


        // GET proxy
        [HttpGet]
        public ActionResult<string> Get()
        {
            return "The Proxy accepts POST requests from CDM players using the Widevine License Exchange protocol.";
        }

        // POST proxy
        [HttpPost]
        public async Task<IActionResult> Post()
        {
            string payload = Util.ConvertToBase64(HttpContext.Request.Body);
            if (string.IsNullOrEmpty(payload))
            {
                return BadRequest("body is empty");
            }
            contentId = Request.Query.ContainsKey("contentId") ?
                Request.Query["contentId"].ToString() : "";
            keyId = Request.Query.ContainsKey("keyId") ?
                Request.Query["keyId"].ToString() : "";

            string response;
            if (payload.Length < 50)
            {
                response = await SendRequest(BuildCertificateRequest(payload));
            }
            else
            {
                response = await SendRequest(BuildLicenseServerRequest(payload));
            }

            byte[] responseBytes = ProcessLicenseResponse(response);
            if (responseBytes.Length == 0)  // "PARSE_ONLY request
            {
                return Content(response, "application/x-javascript");
            }
            else
            {
                return File(responseBytes, "application/octet-stream");
            }
        }

        /// <summary>
        /// Send HTTP request to Widevine.
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        private async Task<string> SendRequest(string request)
        {
            HttpClient client = new HttpClient();
            var url = _LICENSE_SERVER_URL + "/" + _PROVIDER;
            HttpResponseMessage response = await client.PostAsync(url, new StringContent(request));
            string payload = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                var exception = new Exception("SendRequest StatusCode: " + 
                    response.StatusCode + "Message: " +payload);
                _logger.LogError(exception, payload);
                throw exception;
            }
            return payload;
        }

        /// <summary>
        /// Builds JSON requests to be sent to the license server.
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        private string BuildCertificateRequest(string payload)
        {
            string message = BuildCertificateMessage(payload);
            var certificate_request = new
            {
                request = Util.Base64Encode(message),
                signature = GenerateSignature(message),
                signer = _PROVIDER
            };
            return JsonConvert.SerializeObject(certificate_request);
        }

        /// <summary>
        /// Build a certificate request to be sent to Widevine Service. 
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        private string BuildCertificateMessage(string payload)
        {
            var request = new
            {
                payload = payload
            };
            return JsonConvert.SerializeObject(request);
        }

        /// <summary>
        /// Builds JSON requests to be sent to the license server. 
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        private string BuildLicenseServerRequest(string payload)
        {
            string message = BuildLicenseMessage(payload);
            var license_server_request = new
            {
                request = Util.Base64Encode(message),
                signature = GenerateSignature(message),
                signer = _PROVIDER
            };
            return JsonConvert.SerializeObject(license_server_request);
        }

        /// <summary>
        /// Build a license request to be sent to Widevine Service. 
        /// Policy overrides and license configurations <see cref="!:https://storage.googleapis.com/wvdocs/Widevine_DRM_Proxy_Integration.pdf">HERE</see>
        /// </summary>
        /// <param name="payload"></param>
        /// <returns></returns>
        private string BuildLicenseMessage(string payload)
        {
            string contentId64 = string.IsNullOrEmpty(contentId) ? "" : Util.Base64Encode(contentId);
            // Add content_key_specs and policy_overrides here
            var request = new
            {
                payload = payload,
                provider = _PROVIDER,
                allowed_track_types = _ALLOWED_TRACK_TYPES,
                parse_only = Request.Query.ContainsKey("parseonly"),
                content_id = contentId64
            };
            return JsonConvert.SerializeObject(request);
        }

        /// <summary>
        /// Decode License Response and pass to player.
        /// </summary>
        /// <param name="response"></param>
        /// <returns></returns>
        private byte[] ProcessLicenseResponse(string response)
        {
            JObject responseObj = JObject.Parse(response);
            if (responseObj.ContainsKey("status") && responseObj["status"].ToString() == "OK")
            {
                Trace_devices_not_sending_security_level(responseObj);

                if (responseObj.ContainsKey("license"))
                {
                    byte[] license_decoded = System.Convert.FromBase64String(responseObj["license"].ToString());

                    // Log without license
                    responseObj.Remove("license");
                    // Use warning to not be mixed with ASP.NET unrelevant info logs.
                    _logger.LogWarning(responseObj["message_type"].ToString() + " response");
                    _logger.LogWarning(JsonConvert.SerializeObject(responseObj));

                    return license_decoded;
                }
                else
                {
                    // Use warning to not be mixed with ASP.NET unrelevant info logs.
                    _logger.LogWarning("PARSE_ONLY request", response);
                    _logger.LogWarning(response);

                    // "PARSE_ONLY request, no 'license' found."
                    return new byte[] { };
                }
            }
            var errorMsg = "ProcessLicenseResponse Status: " + (responseObj.ContainsKey("status") ?
                responseObj["status"].ToString() : "No Status");
            var exception = new Exception(errorMsg);
            _logger.LogError(exception, response);
            throw exception;
        }

        /// <summary>
        /// Ingest License Request and Encrypt
        /// </summary>
        /// <param name="text_to_sign"></param>
        /// <returns></returns>
        private string GenerateSignature(string text_to_sign)
        {
            byte[] hash;
            using (SHA1Managed sha1 = new SHA1Managed())
            {
                hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(text_to_sign));
            }
            hash = Util.PaddningBytes(hash);
            byte[] signature = Util.EncryptAes(hash, _KEY, _IV);
            string signatureBase64 = Convert.ToBase64String(signature);
            return signatureBase64;
        }

        /// <summary>
        /// Some devices don't send security level, trace this 
        /// </summary>
        /// <param name="responseObj"></param>
        private void Trace_devices_not_sending_security_level(JObject responseObj)
        {
            if (responseObj.ContainsKey("message_type") &&
                                responseObj["message_type"].ToString() != "SERVICE_CERTIFICATE")
            {
                if (!responseObj.ContainsKey("security_level") ||
                    string.IsNullOrEmpty(responseObj["security_level"].ToString()))
                {
                    _logger.LogError("No security_level");
                }
            }
        }
    }


    [Route("[controller]")]
    [ApiController]
    public class ErrorController : Controller
    {
        [Route("")]
        public IActionResult Get()
        {
            var message = "";
            var exceptionFeature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();

            if (exceptionFeature != null)
            {
                Exception exceptionThatOccurred = exceptionFeature.Error;
                message = exceptionThatOccurred.Message;
            }

            return StatusCode(StatusCodes.Status500InternalServerError, message);
        }
    }
}