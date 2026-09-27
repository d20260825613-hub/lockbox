#!/usr/bin/env node
/**
 * Entry point for the installed `lockbox` command.
 *
 * `src/cli.js` detects whether it was imported or run directly, so importing
 * `run` here does not start a second CLI.
 *
 * The handlers are installed here too, not only in the module's direct-run
 * block: when `lockbox` is on PATH this file is the entry point and that block
 * never fires, so the installed command would get no EPIPE or SIGINT handling.
 * `installCliHandlers` is idempotent, so the module asking as well costs nothing.
 */
import { installHandlers, run } from '../src/cli.js';

installHandlers();

process.exitCode = await run(process.argv.slice(2));
