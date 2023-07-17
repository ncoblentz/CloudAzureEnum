# Cloud Azure Enum

During a penetration test, a Microsoft Azure Client ID and Client Secret or an Access Token may be exposed. These resources help you enumerate services available to that account.

## Authenticating with a Client ID and Client Secret

- https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#get-a-token

### For a Specific Application Scope

You need:
- Tenant ID GUID
- Application ID GUID
- Client ID
- Client Secret

```
POST /53...TENANT GUID HERE...891b/oauth2/v2.0/token HTTP/2
Host: login.microsoftonline.com
Content-Length: 180

client_id=f45...CLIENT ID HERE...52c9d
&scope=api://f1...APPLICATION GUID HERE...12/.default
&client_secret=~q...CLIENT SECRET HERE...cFi
&grant_type=client_credentials
```

### For the Graph API

You need:
- Tenant ID GUID
- Client ID
- Client Secret

```
POST /53...TENANT GUID HERE...891b/oauth2/v2.0/token HTTP/2
Host: login.microsoftonline.com
Content-Length: 195

client_id=f45...CLIENT ID HERE...52c9d
&scope=https://graph.microsoft.com/.default
&client_secret=~q...CLIENT SECRET HERE...cFi
&grant_type=client_credentials
```

### The Response

```
HTTP/2 200 OK
Cache-Control: no-store, no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
P3p: CP="DSP CUR OTPi IND OTRi ONL FIN"
X-Ms-Httpver: 2
X-Xss-Protection: 0
Set-Cookie: x-ms-gateway-slice=estsfd; path=/; secure; httponly
Set-Cookie: stsservicecookie=estsfd; path=/; secure; httponly
Date: Mon, 17 Jul 2023 20:25:23 GMT
Content-Length: 1295

{"token_type":"Bearer","expires_in":3599,"ext_expires_in":3599,"access_token":"eyJ...ACCESS TOKEN HERE...EHlCcA1g"}
```

### Access Token/JWT Characteristics

- https://learn.microsoft.com/en-us/azure/active-directory/develop/id-token-claims-reference

|JWT Field|What is it?|Examples|
|---|---|---|
|`aud`|Audience - Which application or API should accept this token|GUID of the application from the scope section: `f1...APPLICATION GUID HERE...12`<br/>Azure API from the scope section: `https://graph.microsoft.com`|
|`oid`/`sub`|Azure User ID|`REDACTED-a77b-4ea6-ba32-fREDACTED49b`|
|`tid`|Tenant ID|`REDACTED-3e8f-4792-977f-0REDACTED91b`|
|`roles`|permissions granted to that user|

```
Headers = {
  "typ": "JWT",
  "alg": "RS256",
  "kid": "-KI...REDACTED...Gew"
}

Payload = {
  "aud": "REDACTED-7cd7-4a95-b8ac-5REDACTED4f6",
  "iss": "https://login.microsoftonline.com/REDACTED-3e8f-4792-977f-0REDACTED91b/v2.0",
  "iat": 1689625224,
  "nbf": 1689625224,
  "exp": 1689629124,
  "aio": "AS...REDACTED...+I+8=",
  "azp": "f4...REDACTED7c52c9d",
  "azpacr": "1",
  "oid": "REDACTED-a77b-4ea6-ba32-fREDACTED49b",
  "rh": "0.A...REDACTED...YnAAA.",
  "roles": [
    "Example.Portal.SubscriberExample"
  ],
  "sub": "REDACTED-a77b-4ea6-ba32-fREDACTED49b",
  "tid": "REDACTED-3e8f-4792-977f-0REDACTED91b",
  "uti": "n_...REDACTED...LPAA",
  "ver": "2.0"
}

Signature = "cCexT...REDACTED...qtEHlCcA1g"
```

## Enumerating Access Using An Access Token Using Burp Suite

Use Burp Suite's Intruder (or use something like FFUF or Turbo Intruder) and set up a request like the following

```
GET §/v1.0/applications§ HTTP/1.1
Host: graph.microsoft.com
Connection: close
Authorization: Bearer ey...ACCESS TOKEN HERE...jufG_Q

```

For payloads, use: [endpoints.txt](endpoints.txt). Thank you https://github.com/baswijdenes/ListOfMicrosoftGraphApiEndpoints for creating that list.

Make the following substitutions
|Field In endpoints.txt|Value|
|---|---|
|`{user-id}`|`sub` from JWT|
|`{tenant-id}`|`tid` from JWT or path parameter in client credentials grant|
|`{application-id}`|GUID from `scope=api://...` or `aud` from the JWT if its a GUID|
|other fields|Look through any other information disclosed by the application and substitute other fields|

Delete `https://graph.microsoft.com` from each line of `endpoints.txt`, copy and paste the payloads into intruder, uncheck "URL-encode these characters", and launch the attack. Carefully review not just the `200 OK` responses but all the resposnes. There are some information disclosure issues in the error messages.