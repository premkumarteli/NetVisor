# Project Standing Instructions & Guidelines

## Project Logbook Rule

There is an existing project logbook at `C:\Users\prem\Network\docs\project-logbook.md`. Do NOT create a new changelog file. Keep appending to this exact file after every task you complete, using its established format:

```markdown
## YYYY-MM-DD - Short Title

**Work completed**
- What was implemented or changed.

**Problem found**
- What failed, looked unclear, or required investigation.

**Solution or learning**
- What fixed the issue or what should be done next.

**Evidence**
- Commit, screenshot, command output, test, or file reference.
```

### Rules for Updating the Logbook:
1. **Placement & Chronology:** Add the new entry directly above the `## Template for Future Daily Entries` section at the bottom of the file — keep entries in chronological order (oldest first, as the file currently is), not newest-first.
2. **Multiple Entries:** If multiple distinct pieces of work happen in one day, either merge them into one entry with clear sub-bullets, or add multiple entries for that date — follow whichever the existing file already does for days with multiple entries.
3. **Real Evidence:** "Evidence" must be real: actual test output counts, actual command output, actual file names touched — never "should pass" or "should work" without having actually run it.
4. **Honest Reporting:** If something was found broken or incomplete during work but not fully fixed in that session, log it honestly under "Problem found" and note the open status — don't mark things done that aren't.
5. **Automatic Execution:** Do this automatically as part of finishing each task, without being asked. At the end of your response, always mention: `"Logged to project-logbook.md."`
