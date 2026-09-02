package com.xebyte.core;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Background execution for BSim CLI operations, with a bounded inline wait.
 *
 * <p>Every BSim tool spawns at least one fresh JVM ({@code support/bsim} or
 * {@code analyzeHeadless}), so even the cheap operations run tens of seconds
 * and ingest/query run minutes. A synchronous handler therefore outlives any
 * HTTP hop with a fixed response budget (Cloudflare tunnel and MCP gateway
 * clients give up around 60-100s), and the caller sees a fabricated transport
 * error — {@code -32603 Internal Error, data: null} — while the operation
 * keeps running invisibly server-side. Measured live 2026-08-29: every real
 * {@code bsim_ingest} failed that way while dry-run "passed", because dry-run
 * short-circuits before the CLI runs.
 *
 * <p>So the handlers submit their CLI-heavy body here and wait inline up to a
 * caller-bounded number of seconds. Fast operations return their normal
 * response, indistinguishable from the synchronous behavior; slow ones return
 * a job ticket, and {@code bsim_job_status} serves the result when it lands.
 *
 * <p>Jobs run on a single worker thread, FIFO. That is deliberate for H2
 * {@code file:} databases (single-writer, and {@link BSimCli#LOCK} already
 * serializes those CLI runs). PostgreSQL is a network service: GUI clients
 * query it concurrently with MCP. The worker is still one-wide because each
 * call spawns a JVM, not because Postgres needs the H2 lock.
 */
public class BSimJobs {

    private static final Logger LOG = Logger.getLogger(BSimJobs.class.getName());

    /** Completed jobs retained for status queries. */
    static final int RETAINED_JOBS = 64;

    /**
     * Ceiling for the inline wait. Below the ~60s budget of the tightest
     * observed hop (MCP gateway) with margin for bridge/transport overhead.
     */
    public static final int MAX_WAIT_SECONDS = 55;

    /** Job lifecycle states, serialized lowercase into status payloads. */
    public enum State { QUEUED, RUNNING, DONE }

    /** One submitted BSim operation. */
    public static final class Job {
        final String id;
        final String tool;
        final Map<String, Object> request;
        final long submittedMs;
        volatile long startedMs;
        volatile long finishedMs;
        volatile State state = State.QUEUED;
        volatile Response result;
        final CountDownLatch done = new CountDownLatch(1);

        Job(String id, String tool, Map<String, Object> request) {
            this.id = id;
            this.tool = tool;
            this.request = request;
            this.submittedMs = System.currentTimeMillis();
        }

        public String id() {
            return id;
        }

        /** The job's result, or {@code null} until it finishes. */
        public Response result() {
            return result;
        }
    }

    private final ExecutorService worker;
    private final Map<String, Job> jobs = new LinkedHashMap<>();
    private final Deque<String> finishedOrder = new ArrayDeque<>();
    private final AtomicLong counter = new AtomicLong();

    public BSimJobs() {
        this.worker = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "BSim-Job-Worker");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Queue a BSim operation. {@code request} is a caller-facing summary of
     * the submitted parameters (never credentials) echoed by status queries.
     */
    public Job submit(String tool, Map<String, Object> request, Callable<Response> body) {
        String id = "bsim-" + counter.incrementAndGet() + "-"
                + Integer.toHexString((int) (System.nanoTime() & 0xffff));
        Job job = new Job(id, tool, request);
        synchronized (jobs) {
            jobs.put(id, job);
        }
        LOG.info(() -> "BSim job " + id + " queued: " + tool);
        worker.execute(() -> run(job, body));
        return job;
    }

    private void run(Job job, Callable<Response> body) {
        job.startedMs = System.currentTimeMillis();
        job.state = State.RUNNING;
        Response result;
        try {
            result = body.call();
        } catch (Throwable e) {
            // The job body is the same code that used to run inline, so an
            // exception here is exactly what the synchronous catch blocks
            // used to turn into Response.err — do the same, plus a log.
            // Errors are caught too: a LinkageError escaping here would kill
            // the single worker thread and leave the job "running" forever,
            // with every later job queued behind a ticket nobody can redeem.
            LOG.log(Level.WARNING, "BSim job " + job.id + " (" + job.tool + ") threw", e);
            String msg = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            result = Response.err(msg);
        }
        job.result = result;
        job.finishedMs = System.currentTimeMillis();
        job.state = State.DONE;
        job.done.countDown();
        long tookMs = job.finishedMs - job.startedMs;
        boolean failed = result instanceof Response.Err;
        LOG.info(() -> "BSim job " + job.id + " (" + job.tool + ") finished in " + tookMs
                + "ms: " + (failed ? "error" : "success"));
        synchronized (jobs) {
            finishedOrder.addLast(job.id);
            while (finishedOrder.size() > RETAINED_JOBS) {
                jobs.remove(finishedOrder.removeFirst());
            }
        }
    }

    /**
     * Wait up to {@code waitSeconds} (clamped to {@code 0..MAX_WAIT_SECONDS})
     * for the job. If it finishes in time, return its own result so fast
     * operations behave exactly as they did synchronously; otherwise return a
     * ticket naming {@code bsim_job_status}.
     */
    public Response awaitOrTicket(Job job, int waitSeconds) {
        int wait = Math.max(0, Math.min(MAX_WAIT_SECONDS, waitSeconds));
        try {
            if (job.done.await(wait, TimeUnit.SECONDS)) {
                return job.result;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return ticket(job);
    }

    private Response ticket(Job job) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "started");
        body.put("job_id", job.id);
        body.put("tool", job.tool);
        body.put("state", job.state.name().toLowerCase());
        body.put("submitted_ms_ago", System.currentTimeMillis() - job.submittedMs);
        body.put("hint", "The operation continues server-side; BSim CLI runs spawn a "
                + "separate JVM and routinely take minutes. Poll "
                + "bsim_job_status(job_id=\"" + job.id + "\") for the result.");
        return Response.ok(body);
    }

    /** Status of one job ({@code jobId} set) or every retained job (blank). */
    public Response status(String jobId) {
        if (jobId == null || jobId.isBlank()) {
            List<Map<String, Object>> rows = new ArrayList<>();
            synchronized (jobs) {
                for (Job job : jobs.values()) {
                    rows.add(describe(job, false));
                }
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("jobs", rows);
            body.put("count", rows.size());
            return Response.ok(body);
        }
        Job job;
        synchronized (jobs) {
            job = jobs.get(jobId);
        }
        if (job == null) {
            return Response.err("No BSim job with id '" + jobId + "'. Finished jobs are "
                    + "retained for the last " + RETAINED_JOBS + " operations; list them "
                    + "with bsim_job_status(job_id=\"\").", "job_not_found");
        }
        return Response.ok(describe(job, true));
    }

    private Map<String, Object> describe(Job job, boolean includeResult) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("job_id", job.id);
        row.put("tool", job.tool);
        row.put("state", job.state.name().toLowerCase());
        row.put("request", job.request);
        row.put("submitted_ms_ago", System.currentTimeMillis() - job.submittedMs);
        if (job.state == State.DONE) {
            row.put("took_ms", job.finishedMs - job.startedMs);
            Response result = job.result;
            row.put("ok", !(result instanceof Response.Err));
            if (includeResult && result != null) {
                row.put("result", JsonHelper.parseJson(result.toJson()));
            }
        } else if (job.state == State.RUNNING) {
            row.put("running_ms", System.currentTimeMillis() - job.startedMs);
        }
        return row;
    }
}
