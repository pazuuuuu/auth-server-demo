package com.example.authserver.config;

import com.example.authserver.data.User;
import com.example.authserver.data.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class UserConfig {

    private static final Logger log = LoggerFactory.getLogger(UserConfig.class);

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 開発用のデモ利用者（user）。{@code dev} プロファイルで、環境変数 DEMO_USER_PASSWORD があるときだけ作る。
     */
    @Bean
    @Profile("dev")
    public ApplicationRunner dataLoader(UserRepository userRepository, PasswordEncoder passwordEncoder,
            @Value("${app.demo-user.password:}") String demoPassword) {
        return args -> {
            if (demoPassword.isBlank()) {
                log.warn("DEMO_USER_PASSWORD is not set; the demo user is not created");
                return;
            }
            if (userRepository.findById("user").isEmpty()) {
                userRepository.save(new User("user", passwordEncoder.encode(demoPassword), true));
            }
        };
    }
}
