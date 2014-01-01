# RNPinnedCertValidator

RNPinnedCertValidator simplifies validating ["pinned" SSL certificates](https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning). A pinned certificate means that your app only trusts a specific list of certificates rather than the entire trusted root store for the device. This improves security by limiting the number of trusted certificates, and frustrates attacks that modify the trusted root store.

## Usage

1. Put your trusted certificate in your bundle.
2. Create a validator with `-initWithCertificatePath:`.
3. In `-connection:willSendRequestForAuthenticationChallenge:`, call `[validator validateChallenge:challenge]`.
 
If you don't have your certificate in a handy file, pull it from your server:

``` 
openssl s_client -connect myserver:443 </dev/null 2>/dev/null | openssl x509 -outform DER > myserver.cer
```

See the PinnedCertExample project for an example of how to do this.
