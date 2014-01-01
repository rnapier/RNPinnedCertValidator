//
//  RNPinnedCertValidatorTests.m
//  RNPinnedCertValidatorTests
//
//  Created by Rob Napier on 1/1/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

//  www.google.com.cer -- Google's certificate
//  www.example.com.cer -- Self-signed cert
//  www.example.com-Expired.cer -- Self-signed cert, expired
//  CA.cer -- "Robert Napier's CA"
//  www.example.com-CA.cer -- Cert for www.example.com signed by CA.cer


#import <XCTest/XCTest.h>
#import "RNPinnedCertValidator.h"

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

@interface RNPinnedCertValidatorTests : XCTestCase
@property MockAuthenticationChallengeSender *senderProbe;
@end

@implementation RNPinnedCertValidatorTests

- (void)setUp {
  [super setUp];
  self.senderProbe = [MockAuthenticationChallengeSender new];
}

- (void)tearDown {
  [super tearDown];
}

- (NSString *)certPathForName:(NSString *)name {
  return [[NSBundle bundleForClass:[self class]] pathForResource:name ofType:@"cer"];
}

- (NSString *)goodCertPath {
  return [self certPathForName:@"www.example.com"];
}

- (NSString *)expiredCertPath {
  return [self certPathForName:@"www.example.com-Expired"];
}

- (NSString *)googleCertPath {
  return [self certPathForName:@"www.google.com"];
}

- (NSString *)CACertPath {
  return [self certPathForName:@"CA"];
}

- (NSString *)CASignedCertPath {
  return [self certPathForName:@"www.example.com-CA"];
}

- (NSURLAuthenticationChallenge *)challengeForCertificate:(SecCertificateRef)certificate {
  return [self challengeForCertificate:certificate host:@"www.example.com"];
}

- (NSURLAuthenticationChallenge *)challengeForCertificate:(SecCertificateRef)certificate host:(NSString *)host {
  SecPolicyRef policy = SecPolicyCreateSSL(true, (__bridge CFStringRef)host);
  SecTrustRef trust;
  SecTrustCreateWithCertificates(certificate, policy, &trust);

  MockProtectionSpace *protectionSpace = [[MockProtectionSpace alloc] initWithHost:host
                                                                              port:0
                                                                          protocol:@"https"
                                                                             realm:nil
                                                              authenticationMethod:NSURLAuthenticationMethodServerTrust];
  protectionSpace.serverTrust = trust;

  return [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:protectionSpace
                                                    proposedCredential:nil
                                                  previousFailureCount:0
                                                       failureResponse:nil
                                                                 error:NULL
                                                                sender:self.senderProbe];
  CFRelease(policy);
  CFRelease(trust);
}

// validateChallenge: should send "use" if the received certificate is the only member of the trusted list, and the certificate is valid.
- (void)testGoodVsItself {
  RNPinnedCertValidator *validator = [[RNPinnedCertValidator alloc] initWithCertificatePath:[self goodCertPath]];
  SecCertificateRef certificate = SecCertificateCreateWithData(NULL,
                                                               (__bridge CFDataRef)([NSData dataWithContentsOfFile:[self goodCertPath]]));

  [validator validateChallenge:[self challengeForCertificate:certificate]];

  XCTAssertTrue([self.senderProbe receivedUse], @"Certificate should trust itself.");

  CFRelease(certificate);
}



// validateChallenge: should send "cancel" if the received certificate is not a member of the trusted list
- (void)testUntrusted {
  RNPinnedCertValidator *validator = [[RNPinnedCertValidator alloc] initWithCertificatePath:[self googleCertPath]];

  SecCertificateRef certificate = SecCertificateCreateWithData(NULL,
                                                               (__bridge CFDataRef)([NSData dataWithContentsOfFile:[self expiredCertPath]]));

  [validator validateChallenge:[self challengeForCertificate:certificate]];

  XCTAssertTrue([self.senderProbe receivedCancel], @"Certificate should not trust untrusted cert.");

  CFRelease(certificate);
}


// validateChallenge: should send "cancel" if the received certificate is the only member of the trusted list, and the certificate is expired.
- (void)testExpiredVsItself {
  RNPinnedCertValidator *validator = [[RNPinnedCertValidator alloc] initWithCertificatePath:[self expiredCertPath]];

  SecCertificateRef certificate = SecCertificateCreateWithData(NULL,
                                                               (__bridge CFDataRef)([NSData dataWithContentsOfFile:[self expiredCertPath]]));

  [validator validateChallenge:[self challengeForCertificate:certificate]];

  XCTAssertTrue([self.senderProbe receivedCancel], @"Certificate should not trust expired cert.");

  CFRelease(certificate);
}

// validateChallenge: should send "use" if the received certificate is a valid member of the trusted certificates.
- (void)testExpiredVsList {
  RNPinnedCertValidator *validator = [RNPinnedCertValidator new];

  SecCertificateRef goodCertificate = SecCertificateCreateWithData(NULL,
                                                                   (__bridge CFDataRef)([NSData dataWithContentsOfFile:[self goodCertPath]]));
  SecCertificateRef googleCertificate = SecCertificateCreateWithData(NULL,
                                                                    (__bridge CFDataRef)([NSData dataWithContentsOfFile:[self googleCertPath]]));

  NSArray *certs = @[(__bridge id)goodCertificate, (__bridge id)googleCertificate];

  validator.trustedCertificates = certs;

  [validator validateChallenge:[self challengeForCertificate:goodCertificate]];

  XCTAssertTrue([self.senderProbe receivedUse], @"Certificate should trust itself in list.");

  CFRelease(goodCertificate);
  CFRelease(googleCertificate);
}

// validateChallenge: should send "use" if the received certificate is signed by a member of the trust list.
- (void)testSignedChain {
  RNPinnedCertValidator *validator = [[RNPinnedCertValidator alloc] initWithCertificatePath:[self CACertPath]];
  SecCertificateRef certificate = SecCertificateCreateWithData(NULL,
                                                               (__bridge CFDataRef)([NSData dataWithContentsOfFile:[self CASignedCertPath]]));

  [validator validateChallenge:[self challengeForCertificate:certificate]];

  XCTAssertTrue([self.senderProbe receivedUse], @"Cert chains should be honored.");

  CFRelease(certificate);
}

// validateChallenge: should send "cancel" if the received certificate does not match the hostname.
- (void)testNameMismatch {
  RNPinnedCertValidator *validator = [[RNPinnedCertValidator alloc] initWithCertificatePath:[self goodCertPath]];
  SecCertificateRef certificate = SecCertificateCreateWithData(NULL,
                                                               (__bridge CFDataRef)([NSData dataWithContentsOfFile:[self goodCertPath]]));

  [validator validateChallenge:[self challengeForCertificate:certificate host:@"www.example.org"]];

  XCTAssertTrue([self.senderProbe receivedCancel], @"Name mismatches should not be honored.");

  CFRelease(certificate);
}

@end
