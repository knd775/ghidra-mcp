package com.xebyte.offline;

import com.xebyte.core.BSimJobs;
import com.xebyte.core.Response;
import junit.framework.TestCase;

import java.util.Map;

/**
 * The job worker is a single thread. Anything escaping {@code run} kills it
 * and leaves the job in {@code RUNNING} forever, so both exceptions and
 * errors must come back as a failed job (measured 2026-09-01: a
 * {@code NoClassDefFoundError} inside {@code bsim_ingest} left the job
 * "running" until the 45 s wait expired).
 */
public class BSimJobsTest extends TestCase {

    public void testExceptionBecomesFailedJob() {
        BSimJobs jobs = new BSimJobs();
        BSimJobs.Job job = jobs.submit("bsim_ingest", Map.of(), () -> {
            throw new IllegalStateException("planned failure");
        });
        Response r = jobs.awaitOrTicket(job, 5);
        assertTrue(r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("planned failure"));
    }

    public void testErrorBecomesFailedJobAndWorkerSurvives() {
        BSimJobs jobs = new BSimJobs();
        BSimJobs.Job job = jobs.submit("bsim_ingest", Map.of(), () -> {
            throw new NoClassDefFoundError("ghidra/graph/GEdge");
        });
        Response r = jobs.awaitOrTicket(job, 5);
        assertTrue(r.toJson(), r instanceof Response.Err);
        assertTrue(r.toJson(), r.toJson().contains("ghidra/graph/GEdge"));
        assertTrue(jobs.status(job.id()).toJson().contains("done"));

        // The next job must still run: the worker was not lost with the Error.
        BSimJobs.Job next = jobs.submit("bsim_query", Map.of(), () -> new Response.Ok(Map.of("after", 1)));
        Response r2 = jobs.awaitOrTicket(next, 5);
        assertFalse(r2.toJson(), r2 instanceof Response.Err);
        assertTrue(r2.toJson(), r2.toJson().contains("after"));
    }
}
