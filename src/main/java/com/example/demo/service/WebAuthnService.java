package com.example.demo.service;

import com.example.demo.dto.WebAuthnDto;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.UncheckedIOException;
import java.util.*;

/**
 * WebAuthn (FIDO2) の仕様に基づき、パスキーの登録・ログインオプション生成および検証ロジックを提供するサービス。
 */
@Service
public class WebAuthnService {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnService.class);

    private static final String SESSION_REG_CHALLENGE = "WEBAUTHN_REG_CHALLENGE";
    private static final String SESSION_AUTH_CHALLENGE = "WEBAUTHN_AUTH_CHALLENGE";

    // ローカル開発環境用の判定定数（本番環境では設定ファイル等から注入を推奨）
    private static final String RP_ID = "localhost";
    private static final String ORIGIN = "http://localhost:8080";

    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;
    
    // インメモリでの模擬データベース (ユーザー名 -> 登録キーリスト)
    private final Map<String, List<CredentialStoreMock>> mockDb = new HashMap<>();

    /**
     * コンストラクタ。
     * 
     * @param webAuthnManager WebAuthn4j のマネージャーインスタンス
     */
    public WebAuthnService(WebAuthnManager webAuthnManager) {
        this.webAuthnManager = webAuthnManager;
        this.objectConverter = new ObjectConverter();
    }

    /**
     * パスキー登録に必要なオプション (PublicKeyCredentialCreationOptions) を生成し、JSON文字列で返却します。
     * 
     * @param username 対象のユーザー名
     * @param isUpgrade 自動アップグレード登録（すでにログイン済みの状態からの登録）かどうか
     * @param session チャレンジ値を保管するための HTTP セッション
     * @return 登録オプションの JSON 文字列
     * @throws RuntimeException JSON シリアライズに失敗した場合
     */
    public String generateRegisterOptionsJson(String username, boolean isUpgrade, HttpSession session) {
        log.info("Generating registration options for user: {}, isUpgrade: {}", username, isUpgrade);

        // 1. チャレンジを生成してセッションに一時保存（リプレイ攻撃対策）
        Challenge challenge = new DefaultChallenge();
        session.setAttribute(SESSION_REG_CHALLENGE, challenge);

        // 2. Relying Party (RP) と User のエンティティ情報を構築
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(
                username.getBytes(),
                username,
                username
        );

        // 3. 認証器の選択要件を設定（内蔵認証器 PLATFORM を指定）
        AuthenticatorSelectionCriteria selection = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM,
                false,
                isUpgrade ? UserVerificationRequirement.DISCOURAGED : UserVerificationRequirement.PREFERRED
        );

        // 4. 対応する公開鍵暗号アルゴリズム（ES256, RS256）を指定
        List<PublicKeyCredentialParameters> pubKeyCredParams = Arrays.asList(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
        );

        // 5. 登録オプション全体の作成
        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(RP_ID, "Example App"),
                user,
                challenge,
                pubKeyCredParams,
                60000L, // タイムアウト 60秒
                Collections.emptyList(),
                selection,
                AttestationConveyancePreference.NONE,
                new AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>()
        );

        try {
            String json = objectConverter.getJsonMapper().writeValueAsString(options);
            log.debug("Successfully serialized registration options JSON for user: {}", username);
            return json;
        } catch (DataConversionException | UncheckedIOException e) {
            log.error("Error occurred while serializing registration options for user: {}", username, e);
            throw new RuntimeException("Failed to serialize registration options", e);
        }
    }

    /**
     * ブラウザから送信された登録データを検証し、成功した場合は模擬DBに保存します。
     * 
     * @param username 登録を行うユーザー名
     * @param request ブラウザから送信された DTO
     * @param session チャレンジ検証用の HTTP セッション
     * @throws IllegalStateException セッションにチャレンジが存在しない場合
     * @throws IllegalArgumentException リクエストのペイロード構造が不正または必須項目が欠如している場合
     */
    @SuppressWarnings("deprecation")
    public void verifyRegistration(String username, WebAuthnDto.RegistrationVerifyRequest request, HttpSession session) {
        log.info("Starting WebAuthn registration verification process for user: {}", username);

        // 1. セッションからのチャレンジ取得確認
        Challenge challenge = (Challenge) session.getAttribute(SESSION_REG_CHALLENGE);
        if (challenge == null) {
            log.warn("Registration failed for user {}: Challenge not found in session (Session timeout or invalid state).", username);
            throw new IllegalStateException("Challenge not found in session. Please restart registration process.");
        }

        ServerProperty serverProperty = new ServerProperty(
                new Origin(ORIGIN),
                RP_ID,
                challenge
        );

        // 2. DTO構造およびヌルチェック (W3C/SimpleWebAuthn 2重ネストデータ構造の安全対策)
        if (request == null || request.response() == null || request.response().response() == null) {
            log.error("Registration failed for user {}: Payload is null or invalid nest structure.", username);
            throw new IllegalArgumentException("Registration response payload must not be null.");
        }

        var attestationResp = request.response().response();
        if (attestationResp.attestationObject() == null || attestationResp.clientDataJSON() == null) {
            log.error("Registration failed for user {}: attestationObject or clientDataJSON is missing.", username);
            throw new IllegalArgumentException("attestationObject or clientDataJSON is missing.");
        }

        // 3. Base64URL データのデコード処理
        byte[] attestationObject;
        byte[] clientDataJSON;
        try {
            attestationObject = Base64UrlUtil.decode(attestationResp.attestationObject());
            clientDataJSON = Base64UrlUtil.decode(attestationResp.clientDataJSON());
        } catch (IllegalArgumentException e) {
            log.error("Registration failed for user {}: Base64URL decoding failed for attestation data.", username, e);
            throw new IllegalArgumentException("Invalid Base64URL encoding in registration data.", e);
        }

        // 4. WebAuthn4j によるデータ検証
        RegistrationRequest regRequest = new RegistrationRequest(attestationObject, clientDataJSON);
        RegistrationParameters regParameters = new RegistrationParameters(serverProperty, null, false, true);

        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parse(regRequest);
            webAuthnManager.verify(registrationData, regParameters);
            log.info("WebAuthn cryptographic verification passed for user: {}", username);
        } catch (Exception e) {
            log.error("WebAuthn verification error occurred for user: {}. Verification failed.", username, e);
            throw e; // 上位の Controller または GlobalExceptionHandler に委託
        }

        // 5. 認証情報の永続化（模擬DBへの格納）
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                registrationData.getAttestationObject(),
                registrationData.getCollectedClientData(),
                registrationData.getClientExtensions(),
                registrationData.getTransports()
        );

        CredentialStoreMock mockRecord = new CredentialStoreMock(
                request.response().id(), // ルート要素から Credential ID を取得
                credentialRecord,
                "My Passkey"
        );

        mockDb.computeIfAbsent(username, k -> new ArrayList<>()).add(mockRecord);
        log.info("Passkey successfully registered and saved in mock DB for user: {}. Credential ID: {}", username, request.response().id());

        // 使用済みチャレンジの消去
        session.removeAttribute(SESSION_REG_CHALLENGE);
    }

    /**
     * ログインに必要なオプション (PublicKeyCredentialRequestOptions) を生成し、JSON文字列で返却します。
     * 
     * @param isAutofill 条件付きUI (Autofill) 用のオプション生成かどうか
     * @param session チャレンジ保存用セッション
     * @return ログインオプション JSON
     */
    public String generateLoginOptionsJson(boolean isAutofill, HttpSession session) {
        log.info("Generating login options. isAutofill: {}", isAutofill);

        Challenge challenge = new DefaultChallenge();
        session.setAttribute(SESSION_AUTH_CHALLENGE, challenge);

        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions(
                challenge,
                60000L,
                RP_ID,
                isAutofill ? null : Collections.emptyList(),
                UserVerificationRequirement.PREFERRED,
                new AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>()
        );

        try {
            String json = objectConverter.getJsonMapper().writeValueAsString(options);
            log.debug("Successfully serialized login options JSON.");
            return json;
        } catch (DataConversionException | UncheckedIOException e) {
            log.error("Error occurred while serializing login options", e);
            throw new RuntimeException("Failed to serialize login options", e);
        }
    }

    /**
     * パスキーによるログイン処理（アサーション検証）を実行します。
     * 
     * @param request ブラウザから受け取ったログインアサーション検証リクエスト
     * @param session チャレンジ確認用セッション
     * @return 認証に成功したユーザー名
     */
    @SuppressWarnings("deprecation")
    public String verifyLogin(WebAuthnDto.AuthenticationVerifyRequest request, HttpSession session) {
        log.info("Starting WebAuthn login verification for Credential ID: {}", request.id());

        // 1. チャレンジの検証
        Challenge challenge = (Challenge) session.getAttribute(SESSION_AUTH_CHALLENGE);
        if (challenge == null) {
            log.warn("Login failed: Authentication challenge not found in session.");
            throw new IllegalStateException("Authentication challenge not found in session.");
        }

        ServerProperty serverProperty = new ServerProperty(
                new Origin(ORIGIN),
                RP_ID,
                challenge
        );

        // 2. DBから対象 Credential の検索
        CredentialStoreMock mockStore = findCredentialRecordById(request.id());
        if (mockStore == null) {
            log.warn("Login failed: Unknown Credential ID [{}]", request.id());
            throw new IllegalArgumentException("Credential not found in database.");
        }

        // 3. データ解読と WebAuthn4j による検証
        byte[] credentialId = Base64UrlUtil.decode(request.id());
        byte[] authenticatorData = Base64UrlUtil.decode(request.response().authenticatorData());
        byte[] clientDataJSON = Base64UrlUtil.decode(request.response().clientDataJSON());
        byte[] signature = Base64UrlUtil.decode(request.response().signature());

        AuthenticationRequest authRequest = new AuthenticationRequest(
                credentialId,
                authenticatorData,
                clientDataJSON,
                signature
        );

        AuthenticationParameters authParameters = new AuthenticationParameters(
                serverProperty,
                mockStore.getCredentialRecord(),
                null,
                false,
                true
        );

        try {
            AuthenticationData authData = webAuthnManager.parse(authRequest);
            webAuthnManager.verify(authData, authParameters);
            log.info("Login successful for user [{}] with Credential ID [{}]", mockStore.getUsername(), request.id());
        } catch (Exception e) {
            log.error("Cryptographic signature verification failed for Credential ID [{}]", request.id(), e);
            throw e;
        }

        session.removeAttribute(SESSION_AUTH_CHALLENGE);
        return mockStore.getUsername();
    }

    /**
     * 指定ユーザーの登録済みキー一覧を取得します。
     */
    public List<WebAuthnDto.CredentialResponse> getCredentials(String username) {
        log.debug("Fetching credentials list for user: {}", username);
        List<CredentialStoreMock> records = mockDb.getOrDefault(username, Collections.emptyList());
        List<WebAuthnDto.CredentialResponse> result = new ArrayList<>();
        for (CredentialStoreMock r : records) {
            result.add(new WebAuthnDto.CredentialResponse(r.getCredentialId(), r.getUserVerifiedName(), r.getCredentialRecord().getCounter()));
        }
        return result;
    }

    /**
     * パスキーの表示名を更新します。
     */
    public void updateCredential(String username, String credentialId, String newName) {
        log.info("Updating credential name for user [{}], Credential ID [{}], newName [{}]", username, credentialId, newName);
        List<CredentialStoreMock> records = mockDb.getOrDefault(username, Collections.emptyList());
        records.stream()
                .filter(r -> r.getCredentialId().equals(credentialId))
                .findFirst()
                .ifPresentOrElse(
                        r -> r.setUserVerifiedName(newName),
                        () -> log.warn("Credential ID [{}] not found for update for user [{}]", credentialId, username)
                );
    }

    /**
     * パスキーを削除します。
     */
    public void deleteCredential(String username, String credentialId) {
        log.info("Deleting credential for user [{}], Credential ID [{}]", username, credentialId);
        List<CredentialStoreMock> records = mockDb.getOrDefault(username, Collections.emptyList());
        boolean removed = records.removeIf(r -> r.getCredentialId().equals(credentialId));
        if (!removed) {
            log.warn("Credential ID [{}] was not found for deletion for user [{}]", credentialId, username);
        }
    }

    /**
     * Credential ID から全ユーザーを対象に模擬DBを探索します。
     */
    private CredentialStoreMock findCredentialRecordById(String credentialId) {
        for (Map.Entry<String, List<CredentialStoreMock>> entry : mockDb.entrySet()) {
            for (CredentialStoreMock record : entry.getValue()) {
                if (record.getCredentialId().equals(credentialId)) {
                    record.setUsername(entry.getKey());
                    return record;
                }
            }
        }
        return null;
    }

    /**
     * 模擬DB保存用内部クラス。
     */
    private static class CredentialStoreMock {
        private String username;
        private final String credentialId;
        private final CredentialRecord credentialRecord;
        private String userVerifiedName;

        public CredentialStoreMock(String credentialId, CredentialRecord credentialRecord, String userVerifiedName) {
            this.credentialId = credentialId;
            this.credentialRecord = credentialRecord;
            this.userVerifiedName = userVerifiedName;
        }

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getCredentialId() { return credentialId; }
        public CredentialRecord getCredentialRecord() { return credentialRecord; }
        public String getUserVerifiedName() { return userVerifiedName; }
        public void setUserVerifiedName(String userVerifiedName) { this.userVerifiedName = userVerifiedName; }
    }
}