package com.example.authserver.config;

import com.example.authserver.web.SliMetricsFilter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class MetricsConfig {

    /** Spring Security（order -100）より前に置き、フィルタが応答した要求と、その中で落ちた 5xx も数える。 */
    @Bean
    public FilterRegistrationBean<SliMetricsFilter> sliMetricsFilter(MeterRegistry registry) {
        FilterRegistrationBean<SliMetricsFilter> bean = new FilterRegistrationBean<>(new SliMetricsFilter(registry));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return bean;
    }
}
