#!/usr/bin/env node
/**
 * Entry point for the installed `lockbox` command.
 *
 * Two lines on purpose: `src/cli.js` detects whether it was imported or run
 * directly, so importing `run` here does not start a second CLI.
 */
import { run } from '../src/cli.js';

process.exitCode = await run(process.argv.slice(2));
