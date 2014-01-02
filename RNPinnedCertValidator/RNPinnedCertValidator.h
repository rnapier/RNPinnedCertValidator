//
//  RNPinnedCertValidator.h
//  RNPinnedCertValidator
//
//  Created by Rob Napier on 1/1/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

/**
 Pinned certificate validator.
 
  1. Put your trusted certificate in your bundle.
  2. Create a validator with -initWithCertificatePath:.
  3. In -connection:willSendRequestForAuthenticationChallenge:, call [validator validateChallenge:challenge]

 If you don't have your certificate in a handy file, pull it from your server:
 
  openssl s_client -connect myserver:443 </dev/null 2>/dev/null | openssl x509 -outform DER > myserver.cer

 */

#import <Foundation/Foundation.h>
@import Security;

@interface RNPinnedCertValidator : NSObject
/**
 Array of trusted SecCertificateRef
 */
@property (nonatomic, readwrite, copy) NSArray *trustedCertificates;

/**
 Load one certificate from disk and trust it.
 */
- (instancetype)initWithCertificatePath:(NSString *)path;

/**
 Validate a challenge for -connection:willSendRequestForAuthenticationChallenge:
 Sends useCredential:forAuthenticationChallenge or cancelAuthenticationChallenge: as appropriate.
 */
- (void)validateChallenge:(NSURLAuthenticationChallenge *)challenge;

@end
