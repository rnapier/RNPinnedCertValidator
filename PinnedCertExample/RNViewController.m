//
//  RNViewController.m
//  PinnedCertExample
//
//  Created by Rob Napier on 1/1/14.
//  Copyright (c) 2014 Rob Napier. All rights reserved.
//

// To try this out, tap "Trust example.com" to only trust our www.example.com certificate. Tap "Trust google" to only
// trust Google's cert (it's only good until Apr 9, 2014, so after that you'll need to regenerate:

// openssl s_client -connect www.google.com:443 </dev/null 2>/dev/null | openssl x509 -outform DER > www.google.com.cer

#import "RNViewController.h"
#import "RNPinnedCertValidator.h"

@interface RNViewController () <NSURLConnectionDelegate, NSURLConnectionDataDelegate>
@property (weak, nonatomic) IBOutlet UIWebView *webView;
@property (nonatomic, readwrite, strong) NSURLConnection *connection;
@property (nonatomic, readwrite, strong) NSMutableData *data;
@property (nonatomic, readwrite, strong) RNPinnedCertValidator *validator;
@end

@implementation RNViewController

- (void)runForCertName:(NSString *)name {
  self.data = [NSMutableData new];

/*************************************************************************************************************
 * Here is where we create our validator object (we could do it right before using it; you don't need an ivar)
 *************************************************************************************************************/
  self.validator = [[RNPinnedCertValidator alloc] initWithCertificatePath:[[NSBundle mainBundle] pathForResource:name
                                                                                                          ofType:@"cer"]];

  // Now start the connection
  self.connection = [NSURLConnection connectionWithRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.google.com"]]
                                                  delegate:self];
}

/************************************
 * Here is where we use the validator
 ************************************/
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
  [self.validator validateChallenge:challenge];
}


/***************************************************
 * Everything else is standard NSURLConnection stuff
 ***************************************************/

- (IBAction)trustExample:(id)sender {
  [self runForCertName:@"www.example.com"];
}

- (IBAction)trustGoogle:(id)sender {
  [self runForCertName:@"www.google.com"];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
  [self.webView loadHTMLString:[error localizedDescription] baseURL:nil];
  self.connection = nil;
}


- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
  [self.data appendData:data];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
  [self.webView loadHTMLString:[[NSString alloc] initWithData:self.data encoding:NSUTF8StringEncoding] baseURL:nil];
  self.data = nil;
}

@end
