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
 * <p>The builder listens on the compose network only (no host ports, no
 * Docker socket). {@code POST /build} returns a job id immediately;
 * {@code GET /build/{id}} is how a caller that cannot wait out an MCP hop
 * retrieves the result. This is the substitute for {@code docker exec}: a
 * long-lived container with a warm source cache, without giving the process
 * that parses untrusted binaries root on the host.
 */
public interface BuilderClient {

    Map<String, Object> submit(String toolchain, URI url, Map<String, Object> request)
            throws IOException;

    Map<String, Object> jobStatus(String toolchain, URI url, String jobId) throws IOException;

    /**
     * Packed identities and stubs. This is what can be built; Java does not
     * keep a parallel list.
     */
    Map<String, Object> health(URI url) throws IOException;

    final class Http implements BuilderClient {
        private static final Duration HOP = Duration.ofSeconds(15);

        @Override
        public Map<String, Object> submit(String toolchain, URI url, Map<String, Object> request)
                throws IOException {
            URI target = url.resolve("/build");
            byte[] body = JsonHelper.toJson(request).getBytes(StandardCharsets.UTF_8);
            HttpURLConnection conn = (HttpURLConnection) target.toURL().openConnection();
            try {
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setConnectTimeout((int) HOP.toMillis());
                conn.setReadTimeout((int) HOP.toMillis());
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Content-Length", Integer.toString(body.length));
                try {
                    try (OutputStream out = conn.getOutputStream()) {
                        out.write(body);
                    }
                } catch (IOException e) {
                    throw unreachable(toolchain, url, e);
                }
                return read(toolchain, url, conn);
            } finally {
                conn.disconnect();
            }
        }

        @Override
        public Map<String, Object> jobStatus(String toolchain, URI url, String jobId)
                throws IOException {
            String path = (jobId == null || jobId.isBlank())
                    ? "/builds"
                    : "/build/" + jobId;
            return get(toolchain, url, path);
        }

        @Override
        public Map<String, Object> health(URI url) throws IOException {
            return get("health", url, "/health");
        }

        private static Map<String, Object> get(String toolchain, URI url, String path)
                throws IOException {
            URI target = url.resolve(path);
            HttpURLConnection conn = (HttpURLConnection) target.toURL().openConnection();
            try {
                conn.setRequestMethod("GET");
                conn.setConnectTimeout((int) HOP.toMillis());
                conn.setReadTimeout((int) HOP.toMillis());
                try {
                    conn.getResponseCode();
                } catch (IOException e) {
                    throw unreachable(toolchain, url, e);
                }
                return read(toolchain, url, conn);
            } finally {
                conn.disconnect();
            }
        }

        private static Map<String, Object> read(String toolchain, URI url, HttpURLConnection conn)
                throws IOException {
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
        public final List<String> statusCalls = new java.util.concurrent.CopyOnWriteArrayList<>();
        public final List<URI> healthCalls = new java.util.concurrent.CopyOnWriteArrayList<>();
        private Map<String, Object> response = Map.of("ok", true);
        private Map<String, Object> statusResponse;
        private Map<String, Object> healthResponse = defaultHealth();
        private IOException healthError;

        public void setResponse(Map<String, Object> response) {
            this.response = response;
        }

        public void setStatusResponse(Map<String, Object> statusResponse) {
            this.statusResponse = statusResponse;
        }

        public void setHealthResponse(Map<String, Object> healthResponse) {
            this.healthResponse = healthResponse;
            this.healthError = null;
        }

        public void setHealthError(IOException healthError) {
            this.healthError = healthError;
        }

        public static Map<String, Object> defaultHealth() {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("ok", true);
            body.put("identities", List.copyOf(ReferenceBuild.DEFAULT_TOOLCHAINS));
            body.put("stubs", List.of("pico-sdk"));
            body.put("uid", 1000);
            return body;
        }

        @Override
        public Map<String, Object> submit(String toolchain, URI url, Map<String, Object> request) {
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("toolchain", toolchain);
            rec.put("url", url == null ? "" : url.toString());
            rec.put("request", request);
            calls.add(rec);
            return response;
        }

        @Override
        public Map<String, Object> jobStatus(String toolchain, URI url, String jobId) {
            statusCalls.add(jobId == null ? "" : jobId);
            if (jobId == null || jobId.isBlank()) {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("ok", true);
                body.put("jobs", List.of());
                body.put("count", 0);
                return body;
            }
            if (statusResponse != null) {
                return statusResponse;
            }
            Map<String, Object> queued = new LinkedHashMap<>();
            queued.put("ok", true);
            queued.put("job_id", jobId);
            queued.put("status", "queued");
            return queued;
        }

        @Override
        public Map<String, Object> health(URI url) throws IOException {
            healthCalls.add(url);
            if (healthError != null) throw healthError;
            return new LinkedHashMap<>(healthResponse);
        }
    }
}
