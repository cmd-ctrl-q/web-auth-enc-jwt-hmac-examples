



[link](https://developer.amazon.com/docs/login-with-amazon/authorization-code-grant.html)


### Authorization Response 
To request authorization, the client (website) must redirect the user-agent (browser) to make a secure HTTP call to https://www.amazon.com/ap/oa with the following parameters. If you are using the Authorization header to request access tokens, note that it should be a base-64 encoding of client_id:client:secret.

### Authorization Token Request
After the client (website) receives an Authorization Response with a valid authorization code, it can use that code to obtain an access token. With an access token, the client can read a customer profile. To request an access token, the client makes a secure HTTP POST to https://api.amazon.com/auth/o2/token with the following parameters:

