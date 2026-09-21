package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpSession;

@Controller
public class LoginController {

    public static final String SESSION_USER_KEY = "LOGIN_USER";

    /**
     * ログイン画面
     * GET /login
     */
    @GetMapping("/login")
    public String loginPage(HttpSession session) {
        // すでにログイン済みの場合はダッシュボードへリダイレクト
        if (session.getAttribute(SESSION_USER_KEY) != null) {
            return "redirect:/dashboard";
        }
        return "login";
    }

    /**
     * 通常ログイン (パスワード不要・ユーザー名のみでログイン)
     */
    @PostMapping("/login")
    public String login(@RequestParam("username") String username, HttpSession session) {
        if (username == null || username.isBlank()) {
            return "redirect:/login?error=empty";
        }

        // セッションにユーザー情報を保存（ログイン状態にする）
        session.setAttribute("LOGIN_USER", username);

        // ログイン後のダッシュボードへリダイレクト
        return "redirect:/dashboard";
    }

    /**
     * ② パスワードログイン直後のプロンプト（ダッシュボード）
     * GET /dashboard
     */
    @GetMapping("/dashboard")
    public String dashboardPage(HttpSession session, Model model) {
        String username = (String) session.getAttribute(SESSION_USER_KEY);
        if (username == null) {
            return "redirect:/login";
        }

        model.addAttribute("username", username);

        // ログイン中のユーザーがパスキーを未登録かどうかを判定
        boolean hasNoPasskey = checkIfUserHasNoPasskey(username);
        model.addAttribute("showPasskeyUpgradePrompt", hasNoPasskey);

        return "dashboard";
    }

    /**
     * ③ & ④ パスキー新規追加・一覧管理画面
     * GET /settings/passkeys
     */
    @GetMapping("/settings/passkeys")
    public String passkeySettingsPage(HttpSession session) {
        if (session.getAttribute(SESSION_USER_KEY) == null) {
            return "redirect:/login";
        }
        return "settings/passkeys";
    }

    /**
     * ⑤ リカバリー（代替認証）画面
     * GET /recovery
     */
    @GetMapping("/recovery")
    public String recoveryPage() {
        return "recovery";
    }

    /**
     * ログアウト処理
     * GET /logout
     */
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate(); // セッション破棄
        return "redirect:/login";
    }

    private boolean checkIfUserHasNoPasskey(String username) {
        // DB等の判定ロジック（モック）
        return true;
    }
}