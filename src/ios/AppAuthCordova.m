/********* AppAuthCordova.m Cordova Plugin Implementation *******/

#import <Cordova/CDV.h>
#import <AppAuth/AppAuth.h>

@interface AppAuthCordova : CDVPlugin {
  // Member variables go here.
}

- (void)authorize:(CDVInvokedUrlCommand*)command;
@end

@implementation AppAuthCordova

- (void)authorize:(CDVInvokedUrlCommand*)command
{
    NSString* issuer = [command.arguments objectAtIndex:0];
    NSString* redirectUrl = [command.arguments objectAtIndex:1];
    NSString* clientId = [command.arguments objectAtIndex:2];
    NSString* clientSecret = [command.arguments objectAtIndex:3];
    NSArray* scopes = [command.arguments objectAtIndex:4];
    NSDictionary *_Nullable additionalParameters = [command.arguments objectAtIndex:5];
    NSDictionary *_Nullable serviceConfiguration = [command.arguments objectAtIndex:6];
    BOOL* useNonce = [command.arguments objectAtIndex:7];
    BOOL* usePKCE = [command.arguments objectAtIndex:8];
    NSString* callbackId = command.callbackId;
    
    // if we have manually provided configuration, we can use it and skip the OIDC well-known discovery endpoint call
    if (serviceConfiguration) {
        OIDServiceConfiguration *configuration = [self createServiceConfiguration:serviceConfiguration];
        [self authorizeWithConfiguration: configuration
                             redirectUrl: redirectUrl
                                clientId: clientId
                            clientSecret: clientSecret
                                  scopes: scopes
                                useNonce: useNonce
                                 usePKCE: usePKCE
                    additionalParameters: additionalParameters
                              callbackId: callbackId];
    } else {
        [OIDAuthorizationService discoverServiceConfigurationForIssuer:[NSURL URLWithString:issuer]
                                                            completion:^(OIDServiceConfiguration *_Nullable configuration, NSError *_Nullable error) {
                                                                if (!configuration) {
                                                                    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
                                                                    [self.commandDelegate sendPluginResult:result callbackId:callbackId];
                                                                    return;
                                                                }
                                                                [self authorizeWithConfiguration: configuration
                                                                                     redirectUrl: redirectUrl
                                                                                        clientId: clientId
                                                                                    clientSecret: clientSecret
                                                                                          scopes: scopes
                                                                                        useNonce: useNonce
                                                                                         usePKCE: usePKCE
                                                                            additionalParameters: additionalParameters
                                                                                      callbackId: callbackId];
                                                            }];
    }
}

/*
 * Create a OIDServiceConfiguration from passed serviceConfiguration dictionary
 */
- (OIDServiceConfiguration *) createServiceConfiguration: (NSDictionary *) serviceConfiguration {
    NSURL *authorizationEndpoint = [NSURL URLWithString: [serviceConfiguration objectForKey:@"authorizationEndpoint"]];
    NSURL *tokenEndpoint = [NSURL URLWithString: [serviceConfiguration objectForKey:@"tokenEndpoint"]];
    NSURL *registrationEndpoint = [NSURL URLWithString: [serviceConfiguration objectForKey:@"registrationEndpoint"]];
    
    OIDServiceConfiguration *configuration =
    [[OIDServiceConfiguration alloc]
     initWithAuthorizationEndpoint:authorizationEndpoint
     tokenEndpoint:tokenEndpoint
     registrationEndpoint:registrationEndpoint];
    
    return configuration;
}

+ (nullable NSString *)generateCodeVerifier {
    return [OIDTokenUtilities randomURLSafeStringWithSize:kCodeVerifierBytes];
}

+ (nullable NSString *)generateState {
    return [OIDTokenUtilities randomURLSafeStringWithSize:kStateSizeBytes];
}

+ (nullable NSString *)codeChallengeS256ForVerifier:(NSString *)codeVerifier {
    if (!codeVerifier) {
        return nil;
    }
    // generates the code_challenge per spec https://tools.ietf.org/html/rfc7636#section-4.2
    // code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    // NB. the ASCII conversion on the code_verifier entropy was done at time of generation.
    NSData *sha265Verifier = [OIDTokenUtilities sha265:codeVerifier];
    return [OIDTokenUtilities encodeBase64urlNoPadding:sha265Verifier];
}

/*
 * Authorize a user in exchange for a token with provided OIDServiceConfiguration
 */
- (void)authorizeWithConfiguration: (OIDServiceConfiguration *) configuration
                       redirectUrl: (NSString *) redirectUrl
                          clientId: (NSString *) clientId
                      clientSecret: (NSString *) clientSecret
                            scopes: (NSArray *) scopes
                          useNonce: (BOOL *) useNonce
                           usePKCE: (BOOL *) usePKCE
              additionalParameters: (NSDictionary *_Nullable) additionalParameters
                        callbackId: (NSString *) callbackId
{
    
    NSString *codeVerifier = usePKCE ? [[self class] generateCodeVerifier] : nil;
    NSString *codeChallenge = usePKCE ? [[self class] codeChallengeS256ForVerifier:codeVerifier] : nil;
    NSString *nonce = useNonce ? [[self class] generateState] : nil;
    
    // builds authentication request
    OIDAuthorizationRequest *request =
    [[OIDAuthorizationRequest alloc] initWithConfiguration:configuration
                                                  clientId:clientId
                                              clientSecret:clientSecret
                                                     scope:[OIDScopeUtilities scopesWithArray:scopes]
                                               redirectURL:[NSURL URLWithString:redirectUrl]
                                              responseType:OIDResponseTypeCode
                                                     state:[[self class] generateState]
                                                     nonce:nonce
                                              codeVerifier:codeVerifier
                                             codeChallenge:codeChallenge
                                       codeChallengeMethod: usePKCE ? OIDOAuthorizationRequestCodeChallengeMethodS256 : nil
                                      additionalParameters:additionalParameters];
    
    // performs authentication request
    id<UIApplicationDelegate, RNAppAuthAuthorizationFlowManager> appDelegate = (id<UIApplicationDelegate, RNAppAuthAuthorizationFlowManager>)[UIApplication sharedApplication].delegate;
    if (![[appDelegate class] conformsToProtocol:@protocol(RNAppAuthAuthorizationFlowManager)]) {
        [NSException raise:@"RNAppAuth Missing protocol conformance"
                    format:@"%@ does not conform to RNAppAuthAuthorizationFlowManager", appDelegate];
    }
    appDelegate.authorizationFlowManagerDelegate = self;
    __weak typeof(self) weakSelf = self;
    _currentSession = [OIDAuthState authStateByPresentingAuthorizationRequest:request
                                                     presentingViewController:appDelegate.window.rootViewController
                                                                     callback:^(OIDAuthState *_Nullable authState,
                                                                                NSError *_Nullable error) {
                                                                         typeof(self) strongSelf = weakSelf;
                                                                         strongSelf->_currentSession = nil;
                                                                         if (authState) {
                                                                             
                                                                             CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:
                                                                                                        [self formatResponse:authState.lastTokenResponse
                                                                                                                                                withAuthResponse:authState.lastAuthorizationResponse]]
                                                                             [self.commandDelegate sendPluginResult:result callbackId:callbackId];
                                                                         } else {
                                                                             CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR];
                                                                             [self.commandDelegate sendPluginResult:result callbackId:callbackId];
                                                                         }
                                                                     }]; // end [OIDAuthState authStateByPresentingAuthorizationRequest:request
}

/*
 * Take raw OIDTokenResponse and turn it to a token response format to pass to JavaScript caller
 */
- (NSDictionary*)formatResponse: (OIDTokenResponse*) response {
    NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
    dateFormat.timeZone = [NSTimeZone timeZoneWithAbbreviation: @"UTC"];
    [dateFormat setLocale:[NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"]];
    [dateFormat setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    
    return @{@"accessToken": response.accessToken ? response.accessToken : @"",
             @"accessTokenExpirationDate": response.accessTokenExpirationDate ? [dateFormat stringFromDate:response.accessTokenExpirationDate] : @"",
             @"additionalParameters": response.additionalParameters,
             @"idToken": response.idToken ? response.idToken : @"",
             @"refreshToken": response.refreshToken ? response.refreshToken : @"",
             @"tokenType": response.tokenType ? response.tokenType : @"",
             };
}

/*
 * Take raw OIDTokenResponse and additional paramaeters from an OIDAuthorizationResponse
 *  and turn them into an extended token response format to pass to JavaScript caller
 */
- (NSDictionary*)formatResponse: (OIDTokenResponse*) response
               withAuthResponse:(OIDAuthorizationResponse*) authResponse {
    NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
    dateFormat.timeZone = [NSTimeZone timeZoneWithAbbreviation: @"UTC"];
    [dateFormat setLocale:[NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"]];
    [dateFormat setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    
    return @{@"accessToken": response.accessToken ? response.accessToken : @"",
             @"accessTokenExpirationDate": response.accessTokenExpirationDate ? [dateFormat stringFromDate:response.accessTokenExpirationDate] : @"",
             @"authorizeAdditionalParameters": authResponse.additionalParameters,
             @"tokenAdditionalParameters": response.additionalParameters,
             @"additionalParameters": authResponse.additionalParameters, /* DEPRECATED */
             @"idToken": response.idToken ? response.idToken : @"",
             @"refreshToken": response.refreshToken ? response.refreshToken : @"",
             @"tokenType": response.tokenType ? response.tokenType : @"",
             @"scopes": authResponse.scope ? [authResponse.scope componentsSeparatedByString:@" "] : [NSArray new],
             };
}

@end
