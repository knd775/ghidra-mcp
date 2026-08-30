package com.xebyte.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP client for the reference builder's internal control plane.
 *
 * <p>The builder listens on the compose network only (no host ports). This
 * is the substitute for {@code docker exec}: a long-lived container with a
 * warm source cache, without mounting docker.sock into the process that
 * parses untrusted binaries.
 */
public interface BuilderClient {

    Map<String, Object> build(String toolchain, URI url, Map<String, Object> request, Duration timeout)
            throws IOException;

    final class Http implements BuilderClient {
        private final String authToken;

        public Http(String authToken) {
            this.authToken = authToken == null ? "" : authToken;
        }

        @Override
        public Map<String, Object> build(String toolchain, URI url, Map<String, Object> request,
                                         Duration timeout) throws IOException {
            URI target = url.resolve("/build");
            byte[] body = JsonHelper.toJson(request).getBytes(StandardCharsets.UTF_8);
            HttpURLConnection conn = (HttpURLConnection) target.toURL().openConnection();
            try {
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setConnectTimeout((int) Math.min(timeout.toMillis(), 15_000));
                conn.setReadTimeout((int) timeout.toMillis());
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", Integer.toString(body.length));
                if (!authToken.isBlank()) {
                    conn.setRequestProperty("Authorization", "Bearer " + authToken);
                }
                try {
                    try (OutputStream out = conn.getOutputStream()) {
                        out.write(body);
                    }
                } catch (IOException e) {
                    throw unreachable(toolchain, url, e);
                }
                int code;
                try {
                    code = conn.getResponseCode();
                } catch (IOException e) {
                    throw unreachable(toolchain, url, e);
                }
                InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
                if (in == null) {
                    throw new IOException("builder " + toolchain + " at " + url
                            + " returned HTTP " + code + " with no body");
                }
                byte[] raw = in.readAllBytes();
                String text = new String(raw, StandardCharsets.UTF_8);
                Map<String, Object> parsed = JsonHelper.parseJson(text);
                if (parsed == null || parsed.isEmpty()) {
                    throw new IOException("builder " + toolchain + " returned a non-JSON body: " + text);
                }
                parsed.put("_http_status", code);
                return parsed;
            } finally {
                conn.disconnect();
            }
        }

        private static IOException unreachable(String toolchain, URI url, IOException cause) {
            return new IOException("toolchain " + toolchain + ": builder at " + url
                    + " is not reachable. Start the ghidra-builder service on the compose "
                    + "network. " + cause.getMessage(), cause);
        }
    }

    /** Records calls; used by offline tests so dry_run cannot hide a real build. */
    final class Recording implements BuilderClient {
        public final List<Map<String, Object>> calls = new java.util.concurrent.CopyOnWriteArrayList<>();
        private Map<String, Object> response = Map.of("ok", true);

        public void setResponse(Map<String, Object> response) {
            this.response = response;
        }

        @Override
        public Map<String, Object> build(String toolchain, URI url, Map<String, Object> request,
                                         Duration timeout) {
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("toolchain", toolchain);
            rec.put("url", url == null ? "" : url.toString());
            rec.put("request", request);
            calls.add(rec);
            return response;
        }
    }
}
