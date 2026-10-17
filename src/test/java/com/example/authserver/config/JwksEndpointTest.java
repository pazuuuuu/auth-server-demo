package com.example.authserver.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** JWKS は署名鍵の kid を出し、秘密鍵の成分（d・p・q 等）は出さない。 */
@SpringBootTest
@AutoConfigureMockMvc
class JwksEndpointTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    SigningKeys signingKeys;

    @Test
    void JWKSに今の鍵のkidが載り秘密鍵の成分は出さない() throws Exception {
        mvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys", hasSize(1)))
                .andExpect(jsonPath("$.keys[0].kid").value(signingKeys.currentKeyId()))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist());
    }
}
