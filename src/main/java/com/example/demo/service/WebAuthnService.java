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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.UncheckedIOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * WebAuthn (FIDO2) の仕様に基づき、パスキーの登録・ログインオプション生成および検証ロジックを提供するサービス。
 */
@Service
public class WebAuthnService {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnService.class);

    /** 登録用のチャレンジを HTTP セッションに保持するためのキー名称 */
    private static final String SESSION_REG_CHALLENGE = "WEBAUTHN_REG_CHALLENGE";

    /** 認証（ログイン）用のチャレンジを HTTP セッションに保持するためのキー名称 */
    private static final String SESSION_AUTH_CHALLENGE = "WEBAUTHN_AUTH_CHALLENGE";

    /** Relying Party (RP) の識別子（例: ドメイン名） */
    private final String rpId;

    /** リクエスト元の Origin URL（例: http://localhost:8080） */
    private final String origin;

    /** WebAuthn4j の検証マネージャー */
    private final WebAuthnManager webAuthnManager;

    /** JSON シリアライズ/デシリアライズ用コンバーター */
    private final ObjectConverter objectConverter;

    /**
     * インメモリでの模擬データベース (ユーザー名 -> 登録キーリスト)。
     * スレッドセーフを確保するため ConcurrentHashMap を採用。
     */
    private final Map<String, List<CredentialStoreMock>> mockDb = new ConcurrentHashMap<>();

    /**
     * Credential ID による高速検索用インデックス ($O(1)$ 検索用)。
     */
    private final Map<String, CredentialStoreMock> credentialIndex = new ConcurrentHashMap<>();

    /**
     * 単体テストおよび従来の1引数呼び出し用コンストラクタ。
     *
     * @param webAuthnManager WebAuthn4j のマネージャーインスタンス
     */
    public WebAuthnService(WebAuthnManager webAuthnManager) {
        this(webAuthnManager, "localhost", "http://localhost:8080");
    }

    /**
     * Spring 依存注入（設定値指定可能）用コンストラクタ。
     *
     * @param webAuthnManager WebAuthn4j のマネージャーインスタンス
     * @param rpId            Relying Party ID (ドメイン名)
     * @param origin          リクエスト元の Origin URL
     */
    @Autowired
    public WebAuthnService(
            WebAuthnManager webAuthnManager,
            @Value("${webauthn.rp-id:localhost}") String rpId,
            @Value("${webauthn.origin:http://localhost:8080}") String origin) {
        this.webAuthnManager = webAuthnManager;
        this.objectConverter = new ObjectConverter();
        this.rpId = rpId;
        this.origin = origin;
    }

    /**
     * パスキー登録に必要なオプション (PublicKeyCredentialCreationOptions) を生成し、JSON文字列で返却します。
     *
     * @param username  対象のユーザー名
     * @param isUpgrade 自動アップグレード登録（すでにログイン済みの状態からの登録）かどうか
     * @param session   チャレンジ値を保管するための HTTP セッション
     * @return 登録オプションの JSON 文字列
     * @throws RuntimeException JSON シリアライズに失敗した場合
     */
    public String generateRegisterOptionsJson(String username, boolean isUpgrade, HttpSession session) {
        // [調整] 高頻度な呼び出しのため DEBUG に変更
        log.debug("Generating registration options for user: {}, isUpgrade: {}", username, isUpgrade);

        // 1. チャレンジを生成してセッションに一時保存（リプレイ攻撃対策）
        Challenge challenge = new DefaultChallenge();
        session.setAttribute(SESSION_REG_CHALLENGE, challenge);

        // 2. Relying Party (RP) と User のエンティティ情報を構築
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(
                username.getBytes(),
                username,
                username);

        // 3. 認証器の選択要件を設定（内蔵認証器 PLATFORM を指定）
        AuthenticatorSelectionCriteria selection = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM,
                false,
                isUpgrade ? UserVerificationRequirement.DISCOURAGED : UserVerificationRequirement.PREFERRED);

        // 4. 対応する公開鍵暗号アルゴリズム（ES256, RS256）を指定
        List<PublicKeyCredentialParameters> pubKeyCredParams = Arrays.asList(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));

        // 5. 登録オプション全体の作成
        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "Example App"),
                user,
                challenge,
                pubKeyCredParams,
                60000L, // タイムアウト 60秒
                Collections.emptyList(),
                selection,
                AttestationConveyancePreference.NONE,
                new AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>());

        try {
            String json = objectConverter.getJsonMapper().writeValueAsString(options);
            log.trace("Successfully serialized registration options JSON: {}", json);
            return json;
        } catch (DataConversionException | UncheckedIOException e) {
            // [調整] システム障害レベルの変換エラーは ERROR
            log.error("Failed to serialize registration options for user: {}", username, e);
            throw new RuntimeException("Failed to serialize registration options", e);
        }
    }

    /**
     * ブラウザから送信された登録データを検証し、成功した場合は模擬DBに保存します。
     *
     * @param username 登録を行うユーザー名
     * @param request  ブラウザから送信された DTO
     * @param session  チャレンジ検証用の HTTP セッション
     * @throws IllegalStateException    セッションにチャレンジが存在しない場合
     * @throws IllegalArgumentException リクエストのペイロード構造が不正または必須項目が欠如している場合
     */
    @SuppressWarnings("deprecation")
    public void verifyRegistration(String username, WebAuthnDto.RegistrationVerifyRequest request,
            HttpSession session) {
        log.debug("Processing registration verification for user: {}", username);

        // 1. セッションからのチャレンジ取得・確認および即時削除（ワンタイム化によるリプレイ攻撃対策）
        Challenge challenge = (Challenge) session.getAttribute(SESSION_REG_CHALLENGE);
        session.removeAttribute(SESSION_REG_CHALLENGE);

        if (challenge == null) {
            // [調整] セッション切れ等はクライアント由来のエラーのため WARN
            log.warn("Registration failed for user [{}]: Challenge not found in session.", username);
            throw new IllegalStateException("Challenge not found in session. Please restart registration process.");
        }

        ServerProperty serverProperty = new ServerProperty(
                new Origin(origin),
                rpId,
                challenge);

        // 2. DTO構造およびヌルチェック (W3C/SimpleWebAuthn 2重ネストデータ構造の安全対策)
        if (request == null || request.response() == null || request.response().response() == null) {
            log.warn("Registration failed for user [{}]: Payload is null or invalid nest structure.", username);
            throw new IllegalArgumentException("Registration response payload must not be null.");
        }

        var attestationResp = request.response().response();
        if (attestationResp.attestationObject() == null || attestationResp.clientDataJSON() == null) {
            log.warn("Registration failed for user [{}]: attestationObject or clientDataJSON is missing.", username);
            throw new IllegalArgumentException("attestationObject or clientDataJSON is missing.");
        }

        // 3. Base64URL データのデコード処理
        byte[] attestationObject;
        byte[] clientDataJSON;
        try {
            attestationObject = Base64UrlUtil.decode(attestationResp.attestationObject());
            clientDataJSON = Base64UrlUtil.decode(attestationResp.clientDataJSON());
        } catch (IllegalArgumentException e) {
            log.warn("Registration failed for user [{}]: Invalid Base64URL encoding.", username, e);
            throw new IllegalArgumentException("Invalid Base64URL encoding in registration data.", e);
        }

        // 4. WebAuthn4j によるデータ検証
        RegistrationRequest regRequest = new RegistrationRequest(attestationObject, clientDataJSON);
        RegistrationParameters regParameters = new RegistrationParameters(serverProperty, null, false, true);

        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parse(regRequest);
            webAuthnManager.verify(registrationData, regParameters);
        } catch (Exception e) {
            // [調整] 署名検証失敗は不正アクセス試行またはユーザー操作中断の可能性が高いため WARN に留める
            log.warn("WebAuthn verification failed for user [{}]: {}", username, e.getMessage());
            throw e;
        }

        // 5. 認証情報の永続化（模擬DBへの格納とインデックス登録）
        CredentialRecord credentialRecord = new CredentialRecordImpl(
                registrationData.getAttestationObject(),
                registrationData.getCollectedClientData(),
                registrationData.getClientExtensions(),
                registrationData.getTransports());

        String credId = request.response().id(); // ルート要素から Credential ID を取得
        CredentialStoreMock mockRecord = new CredentialStoreMock(username, credId, credentialRecord, "My Passkey");

        List<CredentialStoreMock> userRecords = mockDb.computeIfAbsent(username, k -> new CopyOnWriteArrayList<>());
        // 同一 Credential ID がすでに存在する場合は置換
        userRecords.removeIf(r -> r.getCredentialId().equals(credId));
        userRecords.add(mockRecord);
        credentialIndex.put(credId, mockRecord);

        // [調整] 重要な状態変化（登録成功）は INFO でログ出力
        log.info("Passkey successfully registered for user [{}]. Credential ID: [{}]", username,
                maskCredentialId(credId));
    }

    /**
     * ログインに必要なオプション (PublicKeyCredentialRequestOptions) を生成し、JSON文字列で返却します。
     *
     * @param isAutofill 条件付きUI (Autofill) 用のオプション生成かどうか
     * @param session    チャレンジ保存用セッション
     * @return ログインオプション JSON
     */
    public String generateLoginOptionsJson(boolean isAutofill, HttpSession session) {
        // [調整] 高頻度なリクエストのため DEBUG
        log.debug("Generating login options. isAutofill: {}", isAutofill);

        Challenge challenge = new DefaultChallenge();
        session.setAttribute(SESSION_AUTH_CHALLENGE, challenge);

        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions(
                challenge,
                60000L,
                rpId,
                isAutofill ? null : Collections.emptyList(),
                UserVerificationRequirement.PREFERRED,
                new AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>());

        try {
            String json = objectConverter.getJsonMapper().writeValueAsString(options);
            log.trace("Successfully serialized login options JSON: {}", json);
            return json;
        } catch (DataConversionException | UncheckedIOException e) {
            log.error("Failed to serialize login options", e);
            throw new RuntimeException("Failed to serialize login options", e);
        }
    }

    /**
     * パスキーによるログイン処理（アサーション検証）を実行します。
     *
     * @param request ブラウザから受け取ったログインアサーション検証リクエスト
     * @param session チャレンジ確認用セッション
     * @return 認証に成功したユーザー名
     * @throws IllegalStateException    チャレンジがセッションに存在しない場合
     * @throws IllegalArgumentException 対象の Credential ID が DB に登録されていない場合
     */
    @SuppressWarnings("deprecation")
    public String verifyLogin(WebAuthnDto.AuthenticationVerifyRequest request, HttpSession session) {
        log.debug("Processing login verification for Credential ID: [{}]", maskCredentialId(request.id()));

        // 1. セッションからのチャレンジ取得および即時破棄（ワンタイム化）
        Challenge challenge = (Challenge) session.getAttribute(SESSION_AUTH_CHALLENGE);
        session.removeAttribute(SESSION_AUTH_CHALLENGE);

        if (challenge == null) {
            log.warn("Login failed: Authentication challenge not found in session.");
            throw new IllegalStateException("Authentication challenge not found in session.");
        }

        ServerProperty serverProperty = new ServerProperty(
                new Origin(origin),
                rpId,
                challenge);

        // 2. DBから対象 Credential の高速検索 (インデックス参照により O(1))
        CredentialStoreMock mockStore = credentialIndex.get(request.id());
        if (mockStore == null) {
            log.warn("Login failed: Unknown Credential ID [{}]", maskCredentialId(request.id()));
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
                signature);

        AuthenticationParameters authParameters = new AuthenticationParameters(
                serverProperty,
                mockStore.getCredentialRecord(),
                null,
                false,
                true);

        try {
            AuthenticationData authData = webAuthnManager.parse(authRequest);
            webAuthnManager.verify(authData, authParameters);
            // [調整] 重要なセキュリティイベント（認証成功）は INFO で明確に記録
            log.info("Passkey login successful for user [{}] with Credential ID [{}]", mockStore.getUsername(),
                    maskCredentialId(request.id()));
        } catch (Exception e) {
            log.warn("Cryptographic signature verification failed for user [{}] (Credential ID: [{}]): {}",
                    mockStore.getUsername(), maskCredentialId(request.id()), e.getMessage());
            throw e;
        }

        return mockStore.getUsername();
    }

    /**
     * 指定ユーザーの登録済みキー一覧を取得します。
     *
     * @param username 検索対象のユーザー名
     * @return ユーザーに紐づく認証情報のレスポンスDTOリスト
     */
    public List<WebAuthnDto.CredentialResponse> getCredentials(String username) {
        log.debug("Fetching credentials list for user: {}", username);
        List<CredentialStoreMock> records = mockDb.getOrDefault(username, Collections.emptyList());
        List<WebAuthnDto.CredentialResponse> result = new ArrayList<>();
        for (CredentialStoreMock r : records) {
            result.add(new WebAuthnDto.CredentialResponse(r.getCredentialId(), r.getUserVerifiedName(),
                    r.getCredentialRecord().getCounter()));
        }
        return result;
    }

    /**
     * パスキーの表示名を更新します。
     *
     * @param username     対象のユーザー名
     * @param credentialId 対象の Credential ID
     * @param newName      設定する新しい表示名
     */
    public void updateCredential(String username, String credentialId, String newName) {
        log.info("Updating credential name for user [{}], Credential ID [{}]", username,
                maskCredentialId(credentialId));
        CredentialStoreMock mock = credentialIndex.get(credentialId);
        if (mock != null && username.equals(mock.getUsername())) {
            mock.setUserVerifiedName(newName);
        } else {
            log.warn("Credential ID [{}] not found for update for user [{}]", maskCredentialId(credentialId), username);
        }
    }

    /**
     * パスキーを削除します。
     *
     * @param username     対象のユーザー名
     * @param credentialId 削除対象の Credential ID
     */
    public void deleteCredential(String username, String credentialId) {
        log.info("Deleting credential for user [{}], Credential ID [{}]", username, maskCredentialId(credentialId));
        List<CredentialStoreMock> records = mockDb.getOrDefault(username, Collections.emptyList());
        boolean removed = records.removeIf(r -> r.getCredentialId().equals(credentialId));
        if (removed) {
            credentialIndex.remove(credentialId);
        } else {
            log.warn("Credential ID [{}] was not found for deletion for user [{}]", maskCredentialId(credentialId),
                    username);
        }
    }

    /**
     * ログ出力用に Credential ID を一部マスク処理します。
     */
    private String maskCredentialId(String credId) {
        if (credId == null || credId.length() <= 8) {
            return "***";
        }
        return credId.substring(0, 4) + "..." + credId.substring(credId.length() - 4);
    }

    /**
     * 模擬DB保存用内部クラス。
     */
    private static class CredentialStoreMock {

        /** 所有するユーザー名 */
        private final String username;

        /** クレデンシャルID */
        private final String credentialId;

        /** WebAuthn4j が管理する公開鍵・カウンター情報等のオブジェクト */
        private final CredentialRecord credentialRecord;

        /** ユーザーが設定したキーの表示用名称 */
        private String userVerifiedName;

        /**
         * 模擬ストアレコードのコンストラクタ。
         *
         * @param username         ユーザー名
         * @param credentialId     クレデンシャルID
         * @param credentialRecord 認証情報レコード
         * @param userVerifiedName ユーザー設定の表示名
         */
        public CredentialStoreMock(String username, String credentialId, CredentialRecord credentialRecord,
                String userVerifiedName) {
            this.username = username;
            this.credentialId = credentialId;
            this.credentialRecord = credentialRecord;
            this.userVerifiedName = userVerifiedName;
        }

        public String getUsername() {
            return username;
        }

        public String getCredentialId() {
            return credentialId;
        }

        public CredentialRecord getCredentialRecord() {
            return credentialRecord;
        }

        public String getUserVerifiedName() {
            return userVerifiedName;
        }

        public void setUserVerifiedName(String userVerifiedName) {
            this.userVerifiedName = userVerifiedName;
        }
    }
}