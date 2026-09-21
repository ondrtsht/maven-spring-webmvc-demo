package com.example.demo.controller;

import com.example.demo.dto.WebAuthnDto;
import com.example.demo.service.WebAuthnService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpSession;
import java.util.List;

/**
 * WebAuthn 関連の REST API エンドポイントを提供するコントローラー。
 */
@RestController
@RequestMapping("/api/auth/webauthn")
public class WebAuthnAPIController {

    private static final Logger log = LoggerFactory.getLogger(WebAuthnAPIController.class);

    private final WebAuthnService webAuthnService;

    /**
     * コンストラクタ。
     * 
     * @param webAuthnService WebAuthnビジネスロジックサービス
     */
    public WebAuthnAPIController(WebAuthnService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }

    /**
     * セッションから現在ログイン中のユーザー名を取得するユーティリティ。
     * 
     * @param session HTTP セッション
     * @return ログインユーザー名（未ログイン時は null）
     */
    private String getLoginUser(HttpSession session) {
        return (String) session.getAttribute(LoginController.SESSION_USER_KEY);
    }

    // 1. 新規登録（ログイン後）

    /**
     * パスキー登録に必要なオプション(PublicKeyCredentialCreationOptions)を取得します。
     * 
     * @param session HTTPセッション
     * @return 登録オプションJSON (未認証時は 401 UNAUTHORIZED)
     */
    @PostMapping(value = "/register/options", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getRegisterOptions(HttpSession session) {
        String username = getLoginUser(session);
        if (username == null) {
            log.warn("WebAuthn register options requested by unauthenticated user.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        log.info("Generating WebAuthn register options for user: {}", username);
        try {
            String optionsJson = webAuthnService.generateRegisterOptionsJson(username, false, session);
            return ResponseEntity.ok(optionsJson);
        } catch (Exception e) {
            log.error("Failed to generate register options for user: {}", username, e);
            throw e;
        }
    }

    /**
     * ブラウザで生成された登録アテステーションを検証します。
     * 
     * @param request 登録検証用データ DTO
     * @param session HTTPセッション
     * @return レスポンス (200 OK または 401 UNAUTHORIZED)
     */
    @PostMapping("/register/verify")
    public ResponseEntity<Void> verifyRegister(@RequestBody WebAuthnDto.RegistrationVerifyRequest request, HttpSession session) {
        String username = getLoginUser(session);
        if (username == null) {
            log.warn("WebAuthn register verification requested by unauthenticated user.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        log.info("Verifying WebAuthn registration for user: {}", username);
        try {
            webAuthnService.verifyRegistration(username, request, session);
            log.info("WebAuthn registration successfully verified for user: {}", username);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("Failed to verify WebAuthn registration for user: {}", username, e);
            throw e;
        }
    }

    // 2. パスキーログイン（ログイン前）

    /**
     * パスキーログインに必要なオプション(PublicKeyCredentialRequestOptions)を取得します。
     * 
     * @param session HTTPセッション
     * @return ログインオプションJSON
     */
    @PostMapping(value = "/login/options", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getLoginOptions(HttpSession session) {
        log.info("Generating WebAuthn login options.");
        try {
            String optionsJson = webAuthnService.generateLoginOptionsJson(false, session);
            return ResponseEntity.ok(optionsJson);
        } catch (Exception e) {
            log.error("Failed to generate login options.", e);
            throw e;
        }
    }

    /**
     * ブラウザから送信されたログインアサーション(署名)を検証します。
     * 
     * @param request ログイン検証用 DTO
     * @param session HTTPセッション
     * @return 認証されたユーザー名
     */
    @PostMapping("/login/verify")
    public ResponseEntity<String> verifyLogin(@RequestBody WebAuthnDto.AuthenticationVerifyRequest request, HttpSession session) {
        log.info("Verifying WebAuthn login for credential ID: {}", request.id());
        try {
            String authenticatedUsername = webAuthnService.verifyLogin(request, session);
            session.setAttribute(LoginController.SESSION_USER_KEY, authenticatedUsername);
            log.info("WebAuthn login successful for user: {}", authenticatedUsername);
            return ResponseEntity.ok(authenticatedUsername);
        } catch (Exception e) {
            log.error("Failed to verify WebAuthn login for credential ID: {}", request.id(), e);
            throw e;
        }
    }

    // 3. 自動登録（ログイン直後）

    /**
     * 既存ユーザーのログイン後自動登録(アップグレード)用オプションを取得します。
     * 
     * @param session HTTPセッション
     * @return 登録オプションJSON
     */
    @PostMapping(value = "/upgrade/options", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getUpgradeOptions(HttpSession session) {
        String username = getLoginUser(session);
        if (username == null) {
            log.warn("WebAuthn upgrade options requested by unauthenticated user.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        log.info("Generating WebAuthn upgrade options for user: {}", username);
        try {
            String optionsJson = webAuthnService.generateRegisterOptionsJson(username, true, session);
            return ResponseEntity.ok(optionsJson);
        } catch (Exception e) {
            log.error("Failed to generate upgrade options for user: {}", username, e);
            throw e;
        }
    }

    // 4. 条件付きUI（ログイン前）

    /**
     * 条件付きUI (Autofill) 用のログインオプションを取得します。
     * 
     * @param session HTTPセッション
     * @return ログインオプションJSON
     */
    @PostMapping(value = "/login/autofill-options", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getAutofillOptions(HttpSession session) {
        log.info("Generating WebAuthn autofill login options.");
        try {
            String optionsJson = webAuthnService.generateLoginOptionsJson(true, session);
            return ResponseEntity.ok(optionsJson);
        } catch (Exception e) {
            log.error("Failed to generate autofill login options.", e);
            throw e;
        }
    }

    // 5. デバイス管理（ログイン後）

    /**
     * ユーザーの登録済みパスキー一覧を取得します (`/credentials` および `/passkeys` の両エンドポイントに対応)。
     * 
     * @param paramUsername クエリパラメータで指定されたユーザー名（任意）
     * @param session HTTPセッション
     * @return パスキー一覧リスト
     */
    @GetMapping({"/credentials", "/passkeys"})
    public ResponseEntity<List<WebAuthnDto.CredentialResponse>> getCredentials(
            @RequestParam(value = "username", required = false) String paramUsername,
            HttpSession session) {
        // 優先順位: 1. セッションユーザー 2. リクエストパラメータ 3. デフォルト補完 ("user1")
        String username = getLoginUser(session);
        if (username == null) {
            username = (paramUsername != null && !paramUsername.isBlank()) ? paramUsername : "user1";
            log.warn("Session user not found. Falling back to username: {}", username);
        }

        log.info("Fetching credentials for user: {}", username);
        try {
            List<WebAuthnDto.CredentialResponse> credentials = webAuthnService.getCredentials(username);
            return ResponseEntity.ok(credentials);
        } catch (Exception e) {
            log.error("Failed to fetch credentials for user: {}", username, e);
            throw e;
        }
    }

    /**
     * パスキーの表示名を更新します (PATCH および PUT に両対応)。
     * 
     * @param credentialId パス変数から渡される Key ID (任意)
     * @param request リクエストボディ (Credential ID および新名称を含む)
     * @param session HTTPセッション
     * @return レスポンス (200 OK)
     */
    @RequestMapping(value = {"/credentials/{credentialId}", "/passkeys"}, method = {RequestMethod.PATCH, RequestMethod.PUT})
    public ResponseEntity<Void> updateCredential(
            @PathVariable(required = false) String credentialId,
            @RequestBody WebAuthnDto.UpdateCredentialRequest request,
            HttpSession session) {
        String username = getLoginUser(session);
        if (username == null) {
            username = "user1";
            log.warn("Session user not found for credential update. Falling back to 'user1'.");
        }

        // URLパスで ID が指定されていない場合は、Body から補完
        String targetId = (credentialId != null) ? credentialId : request.credentialId();

        log.info("Updating credential [{}] for user: {}", targetId, username);
        try {
            webAuthnService.updateCredential(username, targetId, request.userVerifiedName());
            log.info("Successfully updated credential [{}] for user: {}", targetId, username);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("Failed to update credential [{}] for user: {}", targetId, username, e);
            throw e;
        }
    }

    /**
     * 登録済みのパスキーを削除します。
     * 
     * @param credentialId 削除対象の Credential ID
     * @param session HTTPセッション
     * @return レスポンス (200 OK)
     */
    @DeleteMapping({"/credentials/{credentialId}", "/passkeys/{credentialId}"})
    public ResponseEntity<Void> deleteCredential(@PathVariable String credentialId, HttpSession session) {
        String username = getLoginUser(session);
        if (username == null) {
            username = "user1";
            log.warn("Session user not found for credential deletion. Falling back to 'user1'.");
        }

        log.info("Deleting credential [{}] for user: {}", credentialId, username);
        try {
            webAuthnService.deleteCredential(username, credentialId);
            log.info("Successfully deleted credential [{}] for user: {}", credentialId, username);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("Failed to delete credential [{}] for user: {}", credentialId, username, e);
            throw e;
        }
    }
}