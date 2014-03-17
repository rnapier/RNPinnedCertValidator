//
//  RNPinnedCertValidator.m
//  RNPinnedCertValidator
//
//  Created by Rob Napier on 1/1/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

#import "RNPinnedCertValidator.h"

#if __IPHONE_OS_VERSION_MAX_ALLOWED < 70000
typedef NS_ENUM(NSInteger, NSURLSessionAuthChallengeDisposition) {
    NSURLSessionAuthChallengeUseCredential = 0,                    /* Use the specified credential, which may be nil */
    NSURLSessionAuthChallengeCancelAuthenticationChallenge = 2     /* The entire request will be canceled; the credential parameter is ignored. */
};
#endif

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

- (void)validateChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    SecTrustRef trust = challenge.protectionSpace.serverTrust;
    
    // disables trusting any anchors other than the ones in trustedCertificates
    SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)self.trustedCertificates);
    
    SecTrustResultType result;
    OSStatus status = SecTrustEvaluate(trust, &result);
    if (status == errSecSuccess &&
        (result == kSecTrustResultProceed ||
         result == kSecTrustResultUnspecified)) {
            
            NSURLCredential *cred = [NSURLCredential credentialForTrust:trust];
            if (completionHandler)
                completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
        }
    else {
        if (completionHandler)
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    }
}

- (void)validateChallenge:(NSURLAuthenticationChallenge *)challenge {

    void (^completion)(NSURLSessionAuthChallengeDisposition, NSURLCredential*) = ^(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *cred) {
        if (disposition == NSURLSessionAuthChallengeUseCredential) {
            [challenge.sender useCredential:cred forAuthenticationChallenge:challenge];
        }
        else {
            [challenge.sender cancelAuthenticationChallenge:challenge];
        }
    };
    
    [self validateChallenge:challenge completionHandler:completion];
}

@end
