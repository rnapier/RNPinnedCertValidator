//
//  RNPinnedCertValidatorTests.m
//  RNPinnedCertValidatorTests
//
//  Created by Rob Napier on 1/1/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "RNPinnedCertValidator.h"

@interface RNPinnedCertValidatorTests : XCTestCase
@end

@interface MockAuthenticationChallengeSender : NSObject <NSURLAuthenticationChallengeSender>
@property BOOL receivedCancel;
@property BOOL receivedContinue;
@property BOOL receivedUse;
@property BOOL receivedPerform;
@property BOOL receivedReject;
@end

@implementation MockAuthenticationChallengeSender

- (void)cancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
  self.receivedCancel = YES;
}

- (void)continueWithoutCredentialForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
  self.receivedContinue = YES;
}

- (void)useCredential:(NSURLCredential *)credential forAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
  self.receivedUse = YES;
}

- (void)performDefaultHandlingForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
  self.receivedPerform = YES;
}

- (void)rejectProtectionSpaceAndContinueWithChallenge:(NSURLAuthenticationChallenge *)challenge {
  self.receivedReject = YES;
}

@end

@interface MockProtectionSpace : NSURLProtectionSpace
- (void)setServerTrust:(SecTrustRef)trust;
@end


@implementation MockProtectionSpace {
  SecTrustRef _trust;
}

- (SecTrustRef)serverTrust {
  return _trust;
}

- (void)setServerTrust:(SecTrustRef)trust {
  if (trust) {
    CFRetain(trust);
  }

  if (_trust) {
    CFRelease(_trust);
  }

  _trust = trust;
}

- (void)dealloc {
  if (_trust) {
    CFRelease(_trust);
    _trust = NULL;
  }
}

@end

@implementation RNPinnedCertValidatorTests

- (void)setUp {
  [super setUp];
}

- (void)tearDown {
  [super tearDown];
}

- (void)testGood {
  NSString *goodCertPath = [[NSBundle bundleForClass:[self class]] pathForResource:@"www.example.com" ofType:@"cer"];
  RNPinnedCertValidator *validator = [[RNPinnedCertValidator alloc] initWithCertificatePath:goodCertPath];
  SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)([NSData dataWithContentsOfFile:goodCertPath]));

  SecPolicyRef policy = SecPolicyCreateSSL(true, CFSTR("www.example.com"));
  SecTrustRef trust;
  SecTrustCreateWithCertificates(certificate, policy, &trust);

  MockProtectionSpace *protectionSpace = [[MockProtectionSpace alloc] initWithHost:@"www.example.com"
                                                                                port:0
                                                                            protocol:@"https"
                                                                               realm:nil
                                                                authenticationMethod:NSURLAuthenticationMethodServerTrust];
  protectionSpace.serverTrust = trust;

  MockAuthenticationChallengeSender *sender = [MockAuthenticationChallengeSender new];

  NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:protectionSpace
                                                                                       proposedCredential:nil
                                                                                     previousFailureCount:0
                                                                                          failureResponse:nil
                                                                                                    error:NULL
                                                                                                   sender:sender];
  [validator validateChallenge:challenge];

  XCTAssertTrue([sender receivedUse], @"Certificate should trust itself.");

  CFRelease(certificate);
  CFRelease(policy);
  CFRelease(trust);
}

@end
