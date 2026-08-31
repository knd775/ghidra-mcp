package com.xebyte.core;

import ghidra.program.model.listing.Program;

import java.util.List;

/**
 * Pulls listing-level corroboration rows out of an open program. Production
 * uses {@link CorroborationExtract#INSTANCE}; tests inject a fake so ingest
 * and {@code corroborate_match} can be exercised without a real Listing.
 */
public interface CorroborationExtractor {

    List<CorroborationEvidence.FunctionRow> extractAll(Program program);

    CorroborationEvidence.FunctionRow extractOne(Program program, String functionOrAddress);
}
