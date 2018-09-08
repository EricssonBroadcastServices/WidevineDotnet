# WidevineDotnet
Reference Widevine DRM proxy built to run via ASP.NET Core implementation.
The Proxy accepts POST requests from CDM players using the 
Widevine License Exchange protocol.

WidevineDotnet can easily be deployed to Azure Web Apps, and we get Azure wildcard ssl certificate for *.azurewebsites.net.


## Table of Contents
-  **[Release notes](CHANGELOG.md)**
-  **[How to deploy to Azure Web Apps](https://docs.microsoft.com/en-us/azure/app-service/app-service-web-get-started-dotnet)**
-  **[ASP.NET Core Logging](https://www.youtube.com/watch?v=icwD6xkyrsc)**
-  **[How to become a Widevine Implementation Partner (CWIP)](https://www.widevine.com/getting_started.html)**
-  **[Widevine DRM Getting Started](https://storage.googleapis.com/wvdocs/Widevine_DRM_Getting_Started.pdf)**
-  **[Widevine DRM Proxy Integration](https://storage.googleapis.com/wvdocs/Widevine_DRM_Proxy_Integration.pdf)**
-  **[Python-based sample proxy scripts](https://storage.googleapis.com/wvdocs/wv-proxy-sample.tgz)** (WidevineDotnet is based on this sample)

</br>

**Replace PROVIDER and _KEY and _IV with your provider credentials in appsettings**
- "PROVIDER": "widevine_test"
- "PROVIDER_IV": "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9"
- "PROVIDER_KEY": "d58ce954203b7c9a9a9d467f59839249"
- "LICENSE_SERVER_URL_TEST": "https://license.uat.widevine.com/cenc/getlicense"
- "LICENSE_SERVER_URL_PROD": "https://license.widevine.com/cenc/getlicense"

</br>
Many test streams are encrypted with above test provider, e.g. shaka-demo-assets

https://storage.googleapis.com/shaka-demo-assets/sintel-widevine/dash.mpd