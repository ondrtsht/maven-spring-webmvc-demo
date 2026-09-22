package com.example.demo.config;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.ObjectConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebAuthnConfig {

    @Bean
    public ObjectConverter objectConverter() {
        return new ObjectConverter();
    }

    @Bean
    public WebAuthnManager webAuthnManager(ObjectConverter objectConverter) {
        // WebAuthn の attestation（認証器の製造元・モデル等の真正性）を
        // サーバー側で厳密に検証するかどうかは、サービスのセキュリティ設計項目。
        //
        // 本サービスは一般公開を想定し、特定メーカー・特定モデルの認証器を
        // 信頼リストで制限するのではなく、幅広い WebAuthn / Passkey 認証器を
        // 利用可能とする方針のため、attestation の厳密な検証は行わない。
        //
        // これは WebAuthn の challenge / origin / RP ID / credential / 公開鍵 /
        // 署名等の基本的な検証を省略するものではなく、認証器の「製造元・モデルを
        // 証明する情報」を信頼するかどうかに関する設計判断である。
        //
        // 特定の認証器を組織として管理するエンタープライズ用途など、
        // attestation による認証器の信頼性確認が要件となる場合は、
        // Strict な WebAuthnManager と適切な AttestationStatementVerifier /
        // CertPathTrustworthinessVerifier の構成を検討する。
        return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter);
    }
}