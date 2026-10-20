# Release-gated automation exception

The upstream is the official Uderzo release table, not a GitHub repository. Daily and manual source sync read official metadata only; there is no source tree to merge. Existing 19 known versions are baseline only, not replayed. Changed official identities and older versions fail closed.

Automatic build and publication are blocked because modification/redistribution permission and the new downstream SemVer mapping are not established. A formal upstream version alone does not settle these requirements. No binary is downloaded by the daily check.

Manual interfaces remain separate: `source-sync.yml` checks upstream; `auto-update.yml` builds the official latest with unchanged compatibility and Windows Chinese-menu checks but never finalizes; `releases.yml` validates pinned versions without publishing; `manual-promote.yml` explains and enforces the unresolved rights gate without rebuilding. It intentionally cannot publish until a separately reviewed rights/provenance implementation exists. Original publisher private-only, source-SHA, checksum, Windows-runtime and no-overwrite guards are unchanged. Historical releases/assets are never deleted or replaced.

Do not call this fully autonomous publication. GUI startup checks still do not establish full interactive, scan, or DPI compatibility.
