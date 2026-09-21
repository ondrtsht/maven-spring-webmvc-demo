package com.example.demo.dto;

/**
 * WebAuthn (FIDO2/パスキー) 通信で使用するデータ転送オブジェクト (DTO) 群。
 * <p>
 * W3C WebAuthentication (WebAuthn) Level 3 仕様および SimpleWebAuthn フロントエンドライブラリが
 * 生成する {@code PublicKeyCredential} オブジェクトのJSON構造に準拠しています。
 * </p>
 */
public class WebAuthnDto {

    /**
     * パスキー新規登録の検証リクエスト DTO。
     * 
     * @param username 登録対象のユーザー識別子
     * @param response ブラウザの {@code navigator.credentials.create()} から返却された認証器レスポンス
     */
    public record RegistrationVerifyRequest(
            String username,
            AuthenticatorResponse response
    ) {}

    /**
     * W3C PublicKeyCredential オブジェクトのルート構造。
     * 
     * @param id Base64URL エンコードされた Credential ID
     * @param rawId バイナリ形式の Credential ID (Base64URL)
     * @param type 認証情報のタイプ（通常は "public-key"）
     * @param response 認証アテステーション（証明）データ
     */
    public record AuthenticatorResponse(
            String id,
            String rawId,
            String type,
            AuthenticatorAttestationResponse response
    ) {}

    /**
     * 登録時のアテステーションデータ（証明情報）。
     * 
     * @param attestationObject Base64URL エンコードされた Attestation Object (CBOR形式)
     * @param clientDataJSON Base64URL エンコードされた Client Data JSON
     */
    public record AuthenticatorAttestationResponse(
            String attestationObject,
            String clientDataJSON
    ) {}

    /**
     * パスキーログイン（認証）の検証リクエスト DTO。
     * 
     * @param id Base64URL エンコードされた Credential ID
     * @param rawId バイナリ形式の Credential ID (Base64URL)
     * @param type 認証情報のタイプ（通常は "public-key"）
     * @param response 認証アサーション（主張）データ
     */
    public record AuthenticationVerifyRequest(
            String id,
            String rawId,
            String type,
            AuthenticatorAssertionResponse response
    ) {}

    /**
     * ログイン時のアサーションデータ（署名情報）。
     * 
     * @param authenticatorData Base64URL エンコードされた Authenticator Data (バイナリ)
     * @param clientDataJSON Base64URL エンコードされた Client Data JSON
     * @param signature 認証器によって生成された電子署名 (Base64URL)
     * @param userHandle ユーザーハンドル (Base64URL、存在しない場合は null)
     */
    public record AuthenticatorAssertionResponse(
            String authenticatorData,
            String clientDataJSON,
            String signature,
            String userHandle
    ) {}

    /**
     * 登録済みパスキー（デバイス）の参照用レスポンス DTO。
     * 
     * @param credentialId 認証情報ID (Base64URL)
     * @param userVerifiedName ユーザーが設定したパスキーの表示名
     * @param counter サインイン回数（リプレイ攻撃防止用の記名カウンター）
     */
    public record CredentialResponse(
            String credentialId,
            String userVerifiedName,
            long counter
    ) {}

    /**
     * パスキー（デバイス）の表示名更新用リクエスト DTO。
     * 
     * @param credentialId 更新対象の認証情報ID
     * @param userVerifiedName 新しい表示名
     */
    public record UpdateCredentialRequest(
            String credentialId,
            String userVerifiedName
    ) {
        /**
         * {@code request.name()} 形式でのプロパティアクセスとの互換性を保つためのアクセサメソッド。
         * 
         * @return 設定されたパスキー表示名
         */
        public String name() {
            return userVerifiedName;
        }
    }
}