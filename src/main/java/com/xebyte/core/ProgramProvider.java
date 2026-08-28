/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.core;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.File;

/**
 * Interface for providing access to Ghidra programs.
 *
 * This abstraction allows the MCP core to work in both GUI mode
 * (via ProgramManager) and headless mode (via direct program management).
 */
public interface ProgramProvider {

    /**
     * Get the currently active program.
     *
     * @return The current program, or null if no program is open
     */
    Program getCurrentProgram();

    /**
     * Get a program by its name.
     *
     * @param name The program name to look up
     * @return The matching program, or null if not found
     */
    Program getProgram(String name);

    /**
     * Get all currently open programs.
     *
     * @return Array of all open programs (may be empty, never null)
     */
    Program[] getAllOpenPrograms();

    /**
     * Set the current program.
     *
     * @param program The program to make current
     */
    void setCurrentProgram(Program program);

    /**
     * Close a program when the provider owns the program lifecycle.
     *
     * <p>GUI providers usually close through Ghidra's ProgramManager, so the
     * default is a no-op. Headless providers should override this.
     *
     * @param program The program to close
     * @return true if the provider closed the program
     */
    default boolean closeProgram(Program program) {
        return false;
    }

    /**
     * Check if any program is currently open.
     *
     * @return true if at least one program is open
     */
    default boolean hasOpenProgram() {
        return getCurrentProgram() != null;
    }

    /**
     * Get the project this provider is serving programs from.
     *
     * <p>GUI providers override this from their PluginTool. Headless providers
     * own a Project directly. Project-level tools must go through here rather
     * than reaching for PluginTool, or they become GUI-only.
     *
     * @return The active project, or null if this provider has no direct handle
     */
    default Project getProject() {
        return null;
    }

    /**
     * Create (or reuse) each segment of {@code folderPath} under the open
     * project. Returns null when no project is open.
     */
    default DomainFolder ensureProjectFolder(String folderPath) throws Exception {
        Project project = getProject();
        if (project == null) {
            return null;
        }
        DomainFolder current = project.getProjectData().getRootFolder();
        if (folderPath == null || folderPath.isBlank() || folderPath.equals("/")) {
            return current;
        }
        String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
        for (String part : cleanPath.split("/")) {
            if (part.isEmpty()) {
                continue;
            }
            DomainFolder next = current.getFolder(part);
            if (next == null) {
                next = current.createFolder(part);
            }
            current = next;
        }
        return current;
    }

    /**
     * Delete a DomainFile by project path. Returns false when no project is
     * open or the path does not exist.
     */
    default boolean deleteProjectFile(String path) throws Exception {
        Project project = getProject();
        if (project == null || path == null || path.isBlank()) {
            return false;
        }
        DomainFile domainFile = project.getProjectData().getFile(path);
        if (domainFile == null) {
            return false;
        }
        domainFile.delete();
        return true;
    }

    /**
     * Open a program DomainFile from the project. GUI providers keep
     * {@code okToUpgrade=false}; headless overrides to match its other open
     * paths. Returns null when no project is open or the path is missing.
     */
    default Program openProjectFile(String path) throws Exception {
        Project project = getProject();
        if (project == null || path == null || path.isBlank()) {
            return null;
        }
        DomainFile domainFile = project.getProjectData().getFile(path);
        if (domainFile == null) {
            return null;
        }
        return (Program) domainFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
    }

    /**
     * Import a binary into the open project. Shares {@link ProgramImporter}
     * loader-selection with headless {@code /load_program}. Fails if no
     * project is open.
     */
    default ProgramImporter.Result importBinaryFile(File file, String folderPath,
            String languageId, String compilerSpecId, String format) {
        Project project = getProject();
        if (project == null) {
            return ProgramImporter.Result.fail("No project is currently open");
        }
        return ProgramImporter.importFile(file, project, folderPath,
            languageId, compilerSpecId, format, this, TaskMonitor.DUMMY);
    }

    /**
     * Get a program by name, falling back to current program if name is null or empty.
     *
     * @param name The program name (may be null)
     * @return The resolved program
     */
    default Program resolveProgram(String name) {
        if (name == null || name.isEmpty()) {
            return getCurrentProgram();
        }
        Program program = getProgram(name);
        return program != null ? program : getCurrentProgram();
    }
}
