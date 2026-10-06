package com.example.authserver.service;

/**
 * パスワード再設定のリンクを利用者へ届ける。
 *
 * <p>実装はプロファイルで切り替える：{@code dev} はログで模擬（{@link LoggingPasswordResetNotifier}）、
 * それ以外は送らない（{@link DisabledPasswordResetNotifier}）。メール送信を足すときは実装を1つ足す。</p>
 */
public interface PasswordResetNotifier {

    /**
     * @param username   宛先の利用者（このデモではメールアドレスを兼ねる）
     * @param resetLink  再設定トークンを含むリンク。★ログ・例外メッセージに出さない
     */
    void send(String username, String resetLink);
}
