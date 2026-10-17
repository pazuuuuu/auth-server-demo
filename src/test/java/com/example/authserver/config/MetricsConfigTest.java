package com.example.authserver.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** 管理用ポートを利用者向けのポートと同じにしたら起動しない（docs/SLO.md §6.1）。 */
class MetricsConfigTest {

    @Test
    void 管理用ポートが無いか利用者向けと同じなら起動しない() {
        assertThatThrownBy(() -> MetricsConfig.requireSeparateManagementPort("8080", "")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> MetricsConfig.requireSeparateManagementPort("8080", null)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> MetricsConfig.requireSeparateManagementPort("8080", "8080")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> MetricsConfig.requireSeparateManagementPort("9000", " 9000 ")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void 別のポートか空いているポートなら起動する() {
        assertThatCode(() -> MetricsConfig.requireSeparateManagementPort("8080", "8081")).doesNotThrowAnyException();
        assertThatCode(() -> MetricsConfig.requireSeparateManagementPort("0", "0")).doesNotThrowAnyException();
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(MetricsConfig.class)
            .withBean(MeterRegistry.class, SimpleMeterRegistry::new);

    @Test
    void 設定が同じポートならアプリの起動そのものが止まる() {
        runner.withPropertyValues("server.port=8080", "management.server.port=8080")
                .run(context -> assertThat(context).hasFailed());
        runner.withPropertyValues("server.port=8080")
                .run(context -> assertThat(context).hasFailed());
        runner.withPropertyValues("server.port=8080", "management.server.port=8081")
                .run(context -> assertThat(context).hasNotFailed());
    }
}
