package com.example.authserver.web;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

/**
 * SLI の計測（docs/SLO.md §2.2・§6）。CUJ のエンドポイントごとに、応答時間と状態コードの種類を {@value #METRIC} に記録する。
 *
 * <p>Boot 標準の {@code http.server.requests} は使わない。{@code /login}（POST）・{@code /oauth2/token} などは
 * Spring Security のフィルタが応答し DispatcherServlet まで届かないため、{@code uri} タグが区別できない（UNKNOWN になる）。
 * そこで Spring Security より前に置いたこのフィルタで、決めた一覧（{@link #ENDPOINTS}）に当たる要求だけを数える。
 * 一覧に無いパスは数えない＝タグの種類が増えない（パスをそのままタグにしない）。</p>
 *
 * <p>ヒストグラムの境界は SLO のしきい値（300 ms・1 s）だけにして、系列を増やさない。</p>
 */
public class SliMetricsFilter extends OncePerRequestFilter {

    public static final String METRIC = "authserver.http.requests";

    static final Duration[] SLO_BOUNDARIES = {Duration.ofMillis(300), Duration.ofSeconds(1)};

    /** "METHOD path" → endpoint タグ。CUJ（docs/SLO.md §1）と対応する。 */
    static final Map<String, String> ENDPOINTS = Map.ofEntries(
            Map.entry("POST /login", "login"),                                         // CUJ-1
            Map.entry("POST /webauthn/authenticate/options", "webauthn_options"),      // CUJ-2
            Map.entry("POST /login/webauthn", "webauthn_login"),                       // CUJ-2
            Map.entry("GET /oauth2/authorize", "authorize"),                           // CUJ-3
            Map.entry("POST /oauth2/authorize", "authorize"),                          // CUJ-3（同意の送信）
            Map.entry("POST /oauth2/token", "token"),                                  // CUJ-4
            Map.entry("GET /.well-known/openid-configuration", "discovery"),           // CUJ-5
            Map.entry("GET /oauth2/jwks", "jwks"),                                     // CUJ-5
            Map.entry("POST /forgot-password", "forgot_password"),                     // CUJ-6
            Map.entry("POST /reset-password", "reset_password"));                      // CUJ-6

    private final MeterRegistry registry;

    public SliMetricsFilter(MeterRegistry registry) {
        this.registry = registry;
    }

    static String endpointOf(HttpServletRequest request) {
        String path = request.getRequestURI().substring(request.getContextPath().length());
        return ENDPOINTS.get(request.getMethod() + " " + path);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return endpointOf(request) == null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String endpoint = endpointOf(request);
        long start = System.nanoTime();
        int status = 500;
        try {
            chain.doFilter(request, response);
            status = response.getStatus();
        } finally {
            Timer.builder(METRIC)
                    .description("CUJ endpoints for SLIs (docs/SLO.md)")
                    .tag("endpoint", endpoint)
                    .tag("status_class", (status / 100) + "xx")
                    .serviceLevelObjectives(SLO_BOUNDARIES)
                    .register(registry)
                    .record(Duration.ofNanos(System.nanoTime() - start));
        }
    }
}
