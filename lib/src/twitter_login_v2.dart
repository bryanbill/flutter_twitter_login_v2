import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:twitter_oauth_v2/schemes/access_token_v2.dart';
import 'package:twitter_oauth_v2/schemes/authorization_code_v2.dart';
import 'package:twitter_oauth_v2/src/scope.dart';
import 'package:http/http.dart' as http;

class TwitterLoginV2 {
  /// Oauth Client Id
  final String clientId;

  final String clientSecret;

  /// Callback URL
  final String redirectURI;

  /// constructor
  TwitterLoginV2({
    required this.clientId,
    required this.clientSecret,
    required this.redirectURI,
  }) {
    if (this.clientId.isEmpty) {
      throw Exception('clientId is empty');
    }
    if (this.redirectURI.isEmpty) {
      throw Exception('redirectURI is empty');
    }
  }

  Future<AccessTokenV2> refreshAccessToken(
    final String refreshToken,
  ) async {
    final response = await http.post(
      Uri.https('api.twitter.com', '/2/oauth2/token'),
      headers: _buildAuthorizationHeader(
        clientId: clientId,
        clientSecret: clientSecret,
      ),
      body: {
        'grant_type': 'refresh_token',
        'refresh_token': refreshToken,
      },
    );

    return AccessTokenV2.fromJson(jsonDecode(response.body));
  }

  Future<AccessTokenV2> loginV2(
      {bool forceLogin = false, List<Scope>? scopes}) async {
    final String codeVerifier = _generateSecureAlphaNumeric(80);
    final String codeChallenge = _generateCodeChallenge(codeVerifier);

    final authorizationCode = await AuthorizationCodeV2.getAuthorizationCode(
        scope: scopes,
        state: _generateSecureAlphaNumeric(25),
        codeChallenge: codeChallenge,
        clientId: clientId,
        redirectURI: redirectURI);

    return await AccessTokenV2.getAccessToken(
      clientId: clientId,
      header: _buildAuthorizationHeader(
          clientId: clientId, clientSecret: clientSecret),
      authorizationCode: authorizationCode.code,
      codeVerifier: codeVerifier,
      redirectURI: redirectURI,
    );
  }

  Map<String, String> _buildAuthorizationHeader({
    required String clientId,
    required String clientSecret,
  }) {
    final credentials = base64.encode(utf8.encode('$clientId:$clientSecret'));

    return {'Authorization': 'Basic $credentials'};
  }

  String _generateSecureAlphaNumeric(final int length) {
    final random = Random.secure();
    final values = List<int>.generate(length, (i) => random.nextInt(255));

    return base64UrlEncode(values);
  }

  String _generateCodeChallenge(String codeVerifier) {
    final digest = sha256.convert(utf8.encode(codeVerifier));
    final codeChallenge = base64UrlEncode(digest.bytes);

    if (codeChallenge.endsWith('=')) {
      //! Since code challenge must contain only chars in the range
      //! ALPHA | DIGIT | "-" | "." | "_" | "~"
      //! (see https://tools.ietf.org/html/rfc7636#section-4.2)
      return codeChallenge.substring(0, codeChallenge.length - 1);
    }

    return codeChallenge;
  }
}
