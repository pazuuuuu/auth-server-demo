package com.example.authserver.config;

import com.example.authserver.web.SliMetricsFilter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class MetricsConfig {

    /**
     * 管理用ポートが利用者向けのポートと分かれていなければ起動しない（docs/SLO.md §6.1）。
     * 同じだと health・prometheus が認証なしで利用者向けのポートに出る（SecurityConfig#managementSecurityFilterChain）。
     */
    public MetricsConfig(@Value("${server.port:8080}") String serverPort,
            @Value("${management.server.port:}") String managementPort) {
        requireSeparateManagementPort(serverPort, managementPort);
    }

    /** Spring Security（order -100）より前に置き、フィルタが応答した要求と、その中で落ちた 5xx も数える。 */
    @Bean
    public FilterRegistrationBean<SliMetricsFilter> sliMetricsFilter(MeterRegistry registry) {
        FilterRegistrationBean<SliMetricsFilter> bean = new FilterRegistrationBean<>(new SliMetricsFilter(registry));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return bean;
    }

    /** 0（空いているポートを使う・テスト）はどちらも別々に割り当てられるので通す。 */
    static void requireSeparateManagementPort(String serverPort, String managementPort) {
        String server = serverPort == null ? "" : serverPort.trim();
        String management = managementPort == null ? "" : managementPort.trim();
        if (management.isEmpty() || (management.equals(server) && !"0".equals(management))) {
            throw new IllegalStateException("management.server.port (MANAGEMENT_PORT) must be set to a port other than server.port ("
                    + server + "); otherwise /actuator/health and /actuator/prometheus are served on the public port");
        }
    }
}
