package com.example.authserver.web;

import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** SLI の数え方（docs/SLO.md §2）。決めた CUJ のエンドポイントだけを、状態コードの種類で分けて数える。 */
class SliMetricsFilterTest {

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final SliMetricsFilter filter = new SliMetricsFilter(registry);

    @Test
    void トークンエンドポイントの応答を状態コードの種類つきで数える() throws Exception {
        run("POST", "/oauth2/token", 400);
        run("POST", "/oauth2/token", 200);
        run("POST", "/oauth2/token", 200);

        assertThat(timer("token", "2xx").count()).isEqualTo(2);
        assertThat(timer("token", "4xx").count()).isEqualTo(1);
    }

    @Test
    void 途中で例外が出た要求は5xxとして数え例外はそのまま返す() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        MockFilterChain chain = new MockFilterChain(new jakarta.servlet.http.HttpServlet() {
            @Override
            protected void service(jakarta.servlet.http.HttpServletRequest req, jakarta.servlet.http.HttpServletResponse res)
                    throws ServletException {
                throw new ServletException("boom");
            }
        });

        assertThatThrownBy(() -> filter.doFilter(request, new MockHttpServletResponse(), chain))
                .isInstanceOf(ServletException.class);
        assertThat(timer("login", "5xx").count()).isEqualTo(1);
    }

    @Test
    void 一覧に無いパスやメソッドは数えずパスをタグにしない() throws Exception {
        run("GET", "/login", 200);
        run("GET", "/css/style.css", 200);
        run("POST", "/oauth2/token/../../etc", 400);
        run("GET", "/oauth2/token", 405);

        assertThat(registry.find(SliMetricsFilter.METRIC).timers()).isEmpty();
    }

    @Test
    void SLOのしきい値をヒストグラムの境界にする() throws Exception {
        run("GET", "/oauth2/jwks", 200);

        assertThat(timer("jwks", "2xx").takeSnapshot().histogramCounts())
                .extracting(c -> c.bucket(java.util.concurrent.TimeUnit.MILLISECONDS))
                .containsExactly(300.0, 1000.0);
    }

    private void run(String method, String path, int status) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> ((MockHttpServletResponse) res).setStatus(status));
    }

    private Timer timer(String endpoint, String statusClass) {
        return registry.get(SliMetricsFilter.METRIC).tag("endpoint", endpoint).tag("status_class", statusClass).timer();
    }
}
