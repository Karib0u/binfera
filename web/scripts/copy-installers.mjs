// Publishes the command-line install scripts with the site, so they are served from the same
// origin: https://binfera.io/install.sh and https://binfera.io/install.ps1.
import { copyFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

for (const name of ["install.sh", "install.ps1"]) {
  await copyFile(fileURLToPath(new URL(`../../scripts/${name}`, import.meta.url)), fileURLToPath(new URL(`../dist/${name}`, import.meta.url)));
}
