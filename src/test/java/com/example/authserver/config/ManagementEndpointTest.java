package com.example.authserver.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 計測用のエンドポイントは管理用ポートだけで公開し、利用者向けのポートには出さない（docs/SLO.md §6）。
 * 管理用ポートでも health と prometheus 以外（env・beans 等）は出さない。
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureObservability(tracing = false) // テストでは既定で指標の出力が止まるので、本番と同じく出す
class ManagementEndpointTest {

    @LocalServerPort
    int port;

    @LocalManagementPort
    int managementPort;

    @Autowired
    TestRestTemplate rest;

    @Test
    void 利用者向けのポートには計測用のエンドポイントを出さない() throws Exception {
        // リダイレクトを追わない（ログイン画面の 200 を「出ている」と取り違えない）
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        for (String path : new String[] {"/actuator/prometheus", "/actuator/health", "/actuator/env", "/actuator"}) {
            HttpResponse<String> res = client.send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(res.statusCode()).as(path).isNotEqualTo(200);
            assertThat(res.body()).as(path).doesNotContain("authserver_http_requests").doesNotContain("jvm_");
        }
    }

    @Test
    void 管理用ポートでSLIの指標を取れる() {
        rest.getForEntity("http://127.0.0.1:" + port + "/oauth2/jwks", String.class);

        ResponseEntity<String> res = rest.getForEntity("http://127.0.0.1:" + managementPort + "/actuator/prometheus", String.class);

        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(res.getBody())
                .contains("authserver_http_requests_seconds_count{endpoint=\"jwks\",status_class=\"2xx\"")
                .contains("authserver_http_requests_seconds_bucket{endpoint=\"jwks\",status_class=\"2xx\",le=\"0.3\"")
                .contains("authserver_http_requests_seconds_bucket{endpoint=\"jwks\",status_class=\"2xx\",le=\"1.0\"");
    }

    @Test
    void 管理用ポートでもhealthとprometheus以外は出さない() {
        assertThat(rest.getForEntity("http://127.0.0.1:" + managementPort + "/actuator/health", String.class).getStatusCode())
                .isEqualTo(HttpStatus.OK);
        for (String path : new String[] {"/actuator/env", "/actuator/beans", "/actuator/configprops", "/actuator/heapdump"}) {
            assertThat(rest.getForEntity("http://127.0.0.1:" + managementPort + path, String.class).getStatusCode())
                    .as(path).isNotEqualTo(HttpStatus.OK);
        }
        assertThat(rest.getForEntity("http://127.0.0.1:" + managementPort + "/actuator/health", String.class).getBody())
                .doesNotContain("components").doesNotContain("db");
    }
}
