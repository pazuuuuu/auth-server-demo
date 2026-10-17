package com.example.authserver.config;

import org.junit.jupiter.api.Test;

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
}
