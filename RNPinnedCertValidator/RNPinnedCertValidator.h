//
//  RNPinnedCertValidator.h
//  RNPinnedCertValidator
//
//  Created by Rob Napier on 1/1/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

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
 Sends useCredential:forAuthenciationChalleng or cancelAuthenticationChallenge: as appropriate.
 */
- (void)validateChallenge:(NSURLAuthenticationChallenge *)challenge;

@end
