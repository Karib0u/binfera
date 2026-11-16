// The browser build has no project database: notes stay in this browser's storage. The desktop build
// swaps this module for client.native.ts (see vite.config.ts).
import type { Desktop, ProjectClient } from "./types";

export const project: ProjectClient | null = null;

export const desktop: Desktop | null = null;

/** Desktop only: turns the window's native file drops into the page's usual drag and drop events. */
export const installNativeDrop = (): void => {};

/** Desktop only: Cmd/Ctrl + - 0 zoom the page, which a webview does not do by itself. */
export const installZoom = (): void => {};
