//
//  RNPinnedCertValidator.m
//  RNPinnedCertValidator
//
//  Created by Rob Napier on 1/1/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

#import "RNPinnedCertValidator.h"

@implementation RNPinnedCertValidator

- (id)initWithCertificatePath:(NSString *)path
{
  self = [super init];
  if (self) {
    SecCertificateRef certificate = SecCertificateCreateWithData(NULL,
                                                                 (__bridge CFDataRef)([NSData dataWithContentsOfFile:path]));
    _trustedCertificates = @[CFBridgingRelease(certificate)];
  }
  return self;
}

- (void)validateChallenge:(NSURLAuthenticationChallenge *)challenge {
  SecTrustRef trust = challenge.protectionSpace.serverTrust;

  // disables trusting any anchors other than the ones in trustedCertificates
  SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)self.trustedCertificates);

  SecTrustResultType result;
  OSStatus status = SecTrustEvaluate(trust, &result);
  if (status == errSecSuccess &&
      (result == kSecTrustResultProceed ||
       result == kSecTrustResultUnspecified)) {

        NSURLCredential *cred = [NSURLCredential credentialForTrust:trust];
        [challenge.sender useCredential:cred forAuthenticationChallenge:challenge];
      }
  else {
    [challenge.sender cancelAuthenticationChallenge:challenge];
  }
}

@end
