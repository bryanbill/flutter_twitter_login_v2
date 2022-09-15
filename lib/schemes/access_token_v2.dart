import 'package:twitter_oauth_v2/src/utils.dart';

/// The access token for Twitter API.
class AccessTokenV2 {
  final String? tokenType;
  final DateTime? expiresAt;
  final String? accessToken;
  final String? refreshToken;
  final String? scope;

  AccessTokenV2(Map<String, dynamic> params)
      : this.tokenType = params.get<String>('token_type'),
        this.expiresAt = DateTime.now()
            .add(Duration(seconds: params.get<int>('expires_in') ?? 0)),
        this.accessToken = params.get<String>('access_token'),
        this.refreshToken = params.get<String>('refresh_token'),
        this.scope = params.get<String>('scope');

  Map<String, dynamic> toJson() {
    return {
      'tokenType': tokenType,
      'expiresAt': expiresAt,
      'accessToken': accessToken,
      'scope': scope,
    };
  }

  static Future<AccessTokenV2> getAccessToken({
    required String clientId,
    required Map<String, String> header,
    required String authorizationCode,
    required String codeVerifier,
    required String redirectURI,
  }) async {
    final body = {
      "grant_type": "authorization_code",
      "client_id": clientId,
      "code": authorizationCode,
      "redirect_uri": redirectURI,
      "code_verifier": codeVerifier,
    };
    final params = await httpPost(
      ACCESS_TOKEN_URI,
      body,
      header,
    );
    if (params == null) {
      throw Exception('Unexpected Response');
    }
    return AccessTokenV2(params);
  }

  factory AccessTokenV2.fromJson(Map<String, dynamic> json) {
    return AccessTokenV2({
      'tokenType': json['token_type'],
      'expiresAt': json['expires_in'],
      'accessToken': json['access_token'],
      'refreshToken': json['refresh_token'],
      'scope': json['scope'],
    });
  }
}
