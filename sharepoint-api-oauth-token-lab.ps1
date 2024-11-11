# ---------------------------------------------
#region Overview
# ---------------------------------------------
<#
This script demonstrates how to access the SharePoint and Graph APIs using bearer tokens obtained from Entra ID.
It was designed for learning and testing API connectivity.

Four scenarios are covered:
1. Accessing the SharePoint API using a bearer token obtained with a JWT.
2. Accessing the SharePoint API using a bearer token obtained with a client secret (fails by design).
3. Accessing the Graph API using a bearer token obtained with a JWT.
4. Accessing the Graph API using a bearer token obtained with a client secret.

Helper functions are used to:
- Convert input to a Base64Url-safe encoded string.
- Generate a JSON Web Token (JWT) with a specified header and payload.
- Retrieve a bearer token from a token endpoint using client secret or certificate-based authentication.
- Retrieve data from a specified REST API endpoint using a bearer token.

Ensure that the necessary API permissions are configured on the Entra ID app registration, and any SharePoint site permissions have been granted accordingly.
#>


# ---------------------------------------------
#region How to use this script
# ---------------------------------------------
<#
1. Replace the placeholder values in the "Configure Variables" section at the bottom with your required values.
2. Run the script in a PowerShell environment.
3. Review the output to see the responses from the SharePoint and Graph APIs.
#>
#endregion


# ---------------------------------------------
#region License Information
# ---------------------------------------------
<#
MIT License

Copyright (c) 2024 ethorneloe

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>
#endregion


# ---------------------------------------------
#region Helper Functions
# ---------------------------------------------
function ConvertTo-Base64UrlSafe {
     <#
     .SYNOPSIS
     Converts input to a Base64Url-safe encoded string.

     .DESCRIPTION
     The ConvertTo-Base64UrlSafe function takes an input object, which can be a string, byte array, or any object that can be converted to JSON, and returns a Base64Url-safe encoded string.
     This encoding ensures the output is safe to use in URLs and filenames by replacing certain characters that have special meanings in URLs and filesystems.

     .PARAMETER InputObject
     The input object to encode. This parameter can accept strings, byte arrays, or other objects. If the input is not a byte array, the function will convert the input to a JSON string before encoding.

     .EXAMPLE
     $EncodedString = ConvertTo-Base64UrlSafe -InputObject "Hello, World!"
     This example encodes a simple string to a Base64Url-safe format.

     .EXAMPLE
     $Object = @{name="John"; age=30}
     $EncodedString = ConvertTo-Base64UrlSafe -InputObject $Object
     This example converts a hashtable to a JSON string, then encodes it to a Base64Url-safe format.

     .INPUTS
     String, Byte[], Object
     You can input a string directly, provide a byte array, or pass any object that can be serialized to JSON.

     .OUTPUTS
     String
     Outputs a Base64Url-safe encoded string.
     #>

     param(
          [Parameter(Mandatory = $true)]
          [object] $InputObject
     )

     $ByteArray = $null
     if ($InputObject -is [byte[]]) {
          $ByteArray = $InputObject
     }
     elseif ($InputObject -is [string]) {
          $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($InputObject)
     }
     else {
          $ByteArray = [System.Text.Encoding]::UTF8.GetBytes(($InputObject | ConvertTo-Json))
     }

     # Modify the Base64 encoding to be URL safe by replacing '+', '/', and removing padding '=' characters.
     return [Convert]::ToBase64String($ByteArray) -replace '\+', '-' -replace '/', '_' -replace '=+$', ''
}


function Get-CertificateX5t {
     <#
     .SYNOPSIS
     Calculates the x5t value of a given X509 certificate.

     .DESCRIPTION
     The Get-CertificateX5t function calculates the x5t value of a given X509 certificate. The x5t value is a base64url-safe encoded SHA-1 hash of the certificate's raw data.

     .PARAMETER Certificate
     Specifies the X509 certificate for which to calculate the x5t value.

     .EXAMPLE
     $certificate = Get-Item -Path "C:\Certificates\MyCertificate.cer"
     $x5t = Get-CertificateX5t -Certificate $certificate
     Write-Host "x5t value: $x5t"

     .NOTES
     This function requires the "ConvertTo-Base64UrlSafe" function to be available.

     .LINK
     https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=net-5.0
     #>

     param (
          [Parameter(Mandatory = $true)]
          [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
     )
     $Sha1 = [System.Security.Cryptography.SHA1]::Create()
     $Hash = $Sha1.ComputeHash($Certificate.RawData)
     return ConvertTo-Base64UrlSafe -InputObject $Hash
}


function New-JsonWebToken {
     <#
     .SYNOPSIS
     Generates a JSON Web Token (JWT) using specified header and payload objects and signs it with a private RSA key.

     .DESCRIPTION
     The New-JsonWebToken function takes a header and payload as hashtables, converts them to a JSON format,
     encodes them in Base64Url-safe format, and signs the resulting token using the RSA-SHA256 algorithm.
     The function supports signing with a private key provided as a PEM file, a PEM string, or a certificate from the Windows Certificate Store.

     .PARAMETER HeaderParameters
     A hashtable representing the JWT header. Typically includes the type of token (JWT)
     and the signing algorithm (RS256).

     .PARAMETER PayloadParameters
     A hashtable representing the JWT payload. Contains claims such as issuer, subject,
     expiration time, etc.

     .PARAMETER PrivateKeyFilePath
     The filesystem path to the RSA private key (in PEM format) used for signing the JWT.
     This parameter cannot be used in conjunction with PrivateKeyString or CertificateThumbprint.

     .PARAMETER PrivateKeyString
     A string containing the RSA private key (in PEM format) used for signing the JWT.
     This parameter cannot be used in conjunction with PrivateKeyFilePath or CertificateThumbprint.

     .PARAMETER CertThumbprint
     The thumbprint of the certificate in the certificate store used for signing the JWT.
     This parameter cannot be used in conjunction with PrivateKeyFilePath or PrivateKeyString.

     .PARAMETER CertStoreLocation
     The certificate store location where the certificate is located (e.g., CurrentUser\My).
     This parameter is used only when CertThumbprint is specified.

     .EXAMPLE
     $Header = @{ alg = "RS256"; typ = "JWT" }
     $Payload = @{ sub = "1234567890"; name = "John Doe"; iat = 1516239022 }
     $JwtToken = New-JsonWebToken -HeaderParameters $Header -PayloadParameters $Payload -PrivateKeyFilePath "C:\Path\To\privateKey.pem"

     This example generates a JWT with the specified header and payload, signed with the RSA private key located at the given path.

     .EXAMPLE
     $Header = @{ alg = "RS256"; typ = "JWT" }
     $Payload = @{ iss = "issuer-id"; sub = "subject-id"; aud = "https://example.com/token"; exp = 3600; iat = 1616239022 }
     $CertThumbprint = "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
     $JwtToken = New-JsonWebToken -HeaderParameters $Header -PayloadParameters $Payload -CertThumbprint $CertThumbprint -CertStoreLocation "LocalMachine\My"

     This example generates a JWT signed with the private key from the specified certificate in the LocalMachine\My store.

     .OUTPUTS
     String
     The function outputs the generated JWT as a string.

     .NOTES
     Requires the ConvertTo-Base64UrlSafe function.
     #>

     [CmdletBinding(DefaultParameterSetName = 'Path', SupportsShouldProcess = $true)]
     [OutputType([System.String])]
     param(
          [Parameter(Mandatory = $true)]
          [hashtable] $HeaderParameters,

          [Parameter(Mandatory = $true)]
          [hashtable] $PayloadParameters,

          # Parameter Set: Path
          [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
          [string] $PrivateKeyFilePath,

          # Parameter Set: String
          [Parameter(Mandatory = $true, ParameterSetName = 'String')]
          [string] $PrivateKeyString,

          # Parameter Set: Cert
          [Parameter(Mandatory = $true, ParameterSetName = 'Cert')]
          [string] $CertThumbprint,

          [Parameter(Mandatory = $false, ParameterSetName = 'Cert')]
          [string] $CertStoreLocation = "CurrentUser\My"
     )

     if ($PSCmdlet.ShouldProcess("New JWT Generation", "Generating a new JSON Web Token")) {
          try {
               # Encode Header and Payload to JSON
               $HeaderJson = $HeaderParameters | ConvertTo-Json -Compress
               $PayloadJson = $PayloadParameters | ConvertTo-Json -Compress

               # Convert to Base64URL
               $HeaderEncoded = ConvertTo-Base64UrlSafe -InputObject $HeaderJson
               $PayloadEncoded = ConvertTo-Base64UrlSafe -InputObject $PayloadJson

               # Initialize RSA object
               $RsaKey = [System.Security.Cryptography.RSA]::Create()

               switch ($PSCmdlet.ParameterSetName) {
                    'Path' {
                         # Load RSA Private Key from PEM File
                         if (-not (Test-Path -Path $PrivateKeyFilePath)) {
                              throw "Private key file not found at path: $PrivateKeyFilePath"
                         }
                         $PemContent = Get-Content -Path $PrivateKeyFilePath -Raw
                         $RsaKey.ImportFromPem($PemContent)
                    }
                    'String' {
                         # Load RSA Private Key from PEM String
                         $RsaKey.ImportFromPem($PrivateKeyString)
                    }
                    'Cert' {
                         # Retrieve Certificate from Certificate Store
                         $CertPath = "Cert:\$CertStoreLocation\$CertThumbprint"
                         $Cert = Get-Item -Path $CertPath -ErrorAction SilentlyContinue
                         if (-not $Cert) {
                              throw "Certificate with thumbprint '$CertThumbprint' not found in store '$CertStoreLocation'."
                         }

                         if (-not $Cert.HasPrivateKey) {
                              throw "Certificate with thumbprint '$CertThumbprint' does not have a private key."
                         }

                         # Get RSA Private Key from Certificate
                         $RsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
                         if (-not $RsaKey) {
                              throw "Failed to retrieve RSA private key from certificate with thumbprint '$CertThumbprint'."
                         }

                         # Compute x5t (Base64Url-encoded SHA-1 thumbprint)
                         $X5t = Get-CertificateX5t -Certificate $Cert

                         # Include x5t in Header if not already present
                         if (-not $HeaderParameters.ContainsKey('x5t')) {
                              $HeaderParameters['x5t'] = $X5t
                              # Re-encode header after adding x5t
                              $HeaderJson = $HeaderParameters | ConvertTo-Json -Compress
                              $HeaderEncoded = ConvertTo-Base64UrlSafe -InputObject $HeaderJson
                         }
                    }
                    default {
                         throw "Unsupported parameter set: $($PSCmdlet.ParameterSetName)"
                    }
               }

               # Prepare the data to be signed
               $DataToSign = [System.Text.Encoding]::UTF8.GetBytes("$HeaderEncoded.$PayloadEncoded")

               # Sign the data using RS256 (RSA SHA-256)
               $SignatureBytes = $RsaKey.SignData(
                    $DataToSign,
                    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
               )

               # Convert the signature to Base64URL
               $SignatureEncoded = ConvertTo-Base64UrlSafe -InputObject $SignatureBytes

               # Construct the final JWT
               $JwtToken = "$HeaderEncoded.$PayloadEncoded.$SignatureEncoded"
          }
          catch {
               Write-Error "Error generating JWT: $_"
               return $null
          }

          return $JwtToken
     }
}


function Get-BearerToken {
     <#
     .SYNOPSIS
     Retrieves a bearer token using either client secret or certificate-based authentication.

     .DESCRIPTION
     This function obtains a bearer token from the provided URL ($TokenEndpointUrl) using either a client secret or a certificate.

     .PARAMETER TokenScope
     The scope for which the token is requested.

     .PARAMETER TokenEndpointUrl
     The URL to request the token from.

     .PARAMETER AppClientSecret
     The client secret for client secret-based authentication. Mandatory for the 'ClientSecret' parameter set.

     .PARAMETER AuthCertThumbprint
     The thumbprint of the certificate for certificate-based authentication. Mandatory for the 'Certificate' parameter set.

     .PARAMETER AuthCertStoreLocation
     The certificate store location for certificate-based authentication. Mandatory for the 'Certificate' parameter set.

     .EXAMPLE
     Get-BearerToken -TokenScope "https://graph.microsoft.com/.default" -TokenEndpointUrl "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" -AppClientSecret "yourSecret"

     .EXAMPLE
     Get-BearerToken -TokenScope "https://graph.microsoft.com/.default" -TokenEndpointUrl "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token" -AuthCertThumbprint "ABC123" -AuthCertStoreLocation "CurrentUser\My"

     .NOTES
     Ensure that the necessary API permissions are configured on the app registration, and any SharePoint site permissions have been granted accordingly.
     Securely manage sensitive information like client secrets.
     Requires the New-JsonWebToken function.
     #>
     [CmdletBinding()]
     param (
          [Parameter(Mandatory = $true)]
          [string]$ClientId,

          [Parameter(Mandatory = $true)]
          [string]$TokenScope,

          [Parameter(Mandatory = $true)]
          [string]$TokenEndpointUrl,

          [Parameter(ParameterSetName = "ClientSecret", Mandatory = $true)]
          [string]$ClientSecret,

          [Parameter(ParameterSetName = "Certificate", Mandatory = $true)]
          [string]$AuthCertThumbprint,

          [Parameter(ParameterSetName = "Certificate", Mandatory = $true)]
          [string]$AuthCertStoreLocation
     )

     # Initialize the body hashtable with common parameters
     $TokenRequestBody = @{
          client_id  = $ClientId
          scope      = $TokenScope
          grant_type = "client_credentials"
     }

     if ($PSCmdlet.ParameterSetName -eq "ClientSecret") {
          # Use client secret-based authentication
          $TokenRequestBody.client_secret = $ClientSecret
     }
     elseif ($PSCmdlet.ParameterSetName -eq "Certificate") {
          # Verify certificate exists
          $CertPath = "Cert:\$AuthCertStoreLocation"
          $AuthCert = Get-ChildItem -Path $CertPath | Where-Object { $_.Thumbprint -eq $AuthCertThumbprint }
          if (-not $AuthCert) {
               Write-Error "Certificate with thumbprint $AuthCertThumbprint not found in store $AuthCertStoreLocation."
               return $null
          }

          # Define JWT header
          $JwtHeaderParams = @{
               alg = "RS256"
               typ = "JWT"
          }

          # Define JWT payload
          $JwtPayloadParams = @{
               iat = [System.DateTimeOffset]::UtcNow.AddSeconds(-10).ToUnixTimeSeconds() # Issue time
               exp = [System.DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()     # Expiration time
               iss = $ClientId                                                           # Issuer
               sub = $ClientId                                                           # Subject
               aud = $TokenEndpointUrl                                                   # Audience
          }

          # Generate JWT
          $JwtAssertion = New-JsonWebToken -HeaderParameters $JwtHeaderParams -PayloadParameters $JwtPayloadParams `
               -CertThumbprint $AuthCertThumbprint `
               -CertStoreLocation $AuthCertStoreLocation

          # Add JWT assertions to the body
          $TokenRequestBody.client_assertion = $JwtAssertion
          $TokenRequestBody.client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
     }

     try {
          # Splatting parameters for Invoke-RestMethod
          $RestMethodParams = @{
               Method      = 'Post'
               Uri         = $TokenEndpointUrl
               ContentType = 'application/x-www-form-urlencoded'
               Body        = $TokenRequestBody
          }

          $TokenResponse = Invoke-RestMethod @RestMethodParams
          return $TokenResponse.access_token
     }
     catch {
          Write-Error "Failed to obtain bearer token: $_"
          return $null
     }
}


function Get-ApiData {
     <#
     .SYNOPSIS
     Retrieves data from a specified REST API endpoint using a bearer token.

     .DESCRIPTION
     The Get-ApiData function makes a GET request to the provided API URL using the given bearer token.
     Optionally, custom headers can be supplied. If no custom headers are provided, default headers are used.
     This function utilizes splatting to pass parameters to Invoke-RestMethod, improving readability and ease of maintenance.

     .PARAMETER ApiUrl
     The URL of the API endpoint to send the GET request to.

     .PARAMETER BearerToken
     The bearer token used for authorization in the API request.

     .PARAMETER CustomHeaders
     (Optional) A hashtable of custom headers to include in the API request.
     If not provided, the function uses default headers:
        - Authorization: Bearer token
        - Accept: application/json;odata=verbose

     .EXAMPLE
     # Retrieve data from a SharePoint API endpoint using a bearer token
     $apiResponse = Get-ApiData -ApiUrl "https://v2rqy.sharepoint.com/sites/test/_api/web/lists/getbytitle('test-list')/items" -BearerToken $SharePointTokenWithJwt
     Write-Output $apiResponse

     .EXAMPLE
     # Retrieve data from a Graph API endpoint using a bearer token and custom headers
     $customHeaders = @{
          "Custom-Header1" = "Value1"
          "Custom-Header2" = "Value2"
     }
     $apiResponse = Get-ApiData -ApiUrl "https://graph.microsoft.com/v1.0/sites/.../lists/test-list/items" -BearerToken $GraphTokenWithJwt -CustomHeaders $customHeaders
     Write-Output $apiResponse

     .OUTPUTS
     The response from the API, typically in JSON format.
     #>
     param (
          [string]$ApiUrl,
          [string]$BearerToken,
          [hashtable]$CustomHeaders  # Optional parameter for custom headers
     )

     if ($CustomHeaders) {
          $RequestHeaders = $CustomHeaders
     }
     else {
          # Default headers
          $RequestHeaders = @{
               Authorization = "Bearer $BearerToken"
          }
     }

     try {
          # Splatting parameters for Invoke-RestMethod
          $ApiDataParams = @{
               Method  = 'Get'
               Uri     = $ApiUrl
               Headers = $RequestHeaders
          }

          $ApiResponse = Invoke-RestMethod @ApiDataParams
          return $ApiResponse
     }
     catch {
          Write-Error "Failed to retrieve data from API: $_"
          return $null
     }
}
#endregion


# -------------------------------------------------
#region Configure Variables
# -------------------------------------------------
# Replace placeholders with your actual values
$ClientId = ""  # Your client ID
$TenantId = ""  # Your tenant ID
$SharepointApiScope = "https://<yourTenantName>.sharepoint.com/.default"  # This scope makes use of the API permissions configure on the app reg.
$GraphApiScope = "https://graph.microsoft.com/.default"  # This scope makes use of the API permissions configure on the app reg.
$AuthCertThumbprint = "" # Cert thumb associated with the app registration on your local Windows machine.
$AuthCertStoreLocation = "CurrentUser\My" # Certificate store location on your local Windows machine (For example "CurrentUser\My" or "LocalMachine\My").
$ClientSecret = "" # Only use for testing purposes.
$TokenEndpointUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" # Token URL for obtaining a bearer token from Entra ID.
$SharePointApiEndpoint = "" # SharePoint API endpoint you want to access
$GraphApiEndpoint = "" # Graph API endpoint you want to access
#endregion


# ---------------------------------------------
#region Test API Connectivity
# ---------------------------------------------


# ---------------------------------------------
# Access SharePoint API Using JWT
# ---------------------------------------------
$SharePointTokenWithJwtParams = @{
     ClientId              = $ClientId
     TokenScope            = $SharepointApiScope
     TokenEndpointUrl      = $TokenEndpointUrl
     AuthCertThumbprint    = $AuthCertThumbprint
     AuthCertStoreLocation = $AuthCertStoreLocation
}

$SharePointTokenWithJwt = Get-BearerToken @SharePointTokenWithJwtParams

if ($SharePointTokenWithJwt) {
     $SharePointApiResponseWithJwt = Get-ApiData -ApiUrl $SharePointApiEndpoint -BearerToken $SharePointTokenWithJwt
     Write-Output $SharePointApiResponseWithJwt
}


# ---------------------------------------------
# Access SharePoint API Using Client Secret
# ---------------------------------------------
$SharepointTokenWithClientSecretParams = @{
     ClientId         = $ClientId
     TokenScope       = $SharepointApiScope
     TokenEndpointUrl = $TokenEndpointUrl
     ClientSecret     = $ClientSecret
}

# This will fail as the SharePoint REST API does not accept tokens obtained with client secrets. It requires a signed client-assertion JWT.
# The exception will be something like "Unsupported app only token."
$SharepointTokenWithClientSecret = Get-BearerToken @SharepointTokenWithClientSecretParams
if ($SharepointTokenWithClientSecret) {
     $SharePointApiResponseWithClientSecret = Get-ApiData -ApiUrl $SharePointApiEndpoint -BearerToken $SharepointTokenWithClientSecret
     Write-Output $SharePointApiResponseWithClientSecret
}


# ---------------------------------------------
# Access Graph API with JWT
# ---------------------------------------------
$GraphTokenWithJwtParams = @{
     ClientId              = $ClientId
     TokenScope            = $GraphApiScope
     TokenEndpointUrl      = $TokenEndpointUrl
     AuthCertThumbprint    = $AuthCertThumbprint
     AuthCertStoreLocation = $AuthCertStoreLocation
}

$GraphTokenWithJwt = Get-BearerToken @GraphTokenWithJwtParams

if ($GraphTokenWithJwt) {
     $GraphApiResponseWithJwt = Get-ApiData -ApiUrl $GraphApiEndpoint -BearerToken $GraphTokenWithJwt
     Write-Output $GraphApiResponseWithJwt
}


# ---------------------------------------------
# Access Graph API with Client Secret
# ---------------------------------------------
$GraphTokenWithClientSecretParams = @{
     ClientId         = $ClientId
     TokenScope       = $GraphApiScope
     TokenEndpointUrl = $TokenEndpointUrl
     ClientSecret     = $ClientSecret
}

$GraphTokenWithClientSecret = Get-BearerToken @GraphTokenWithClientSecretParams

if ($GraphTokenWithClientSecret) {
     $GraphApiResponseWithClientSecret = Get-ApiData -ApiUrl $GraphApiEndpoint -BearerToken $GraphTokenWithClientSecret
     Write-Output $GraphApiResponseWithClientSecret
}
#endregion
