# Public API

What SharpDTLS exposes is written down, and a removal from it does not build until it is written down too, an addition warns until it is. Two checks do this, both on every `dotnet build` of the library:

- **The API files.** `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt` in `src/SharpDTLS` list
  every public type and member that all three target frameworks share. What only some of them offer
  is in `src/SharpDTLS/PublicAPI/<framework>/`: the `Span` and `Memory` overrides of `TlsStream` that
  net8.0 and net10.0 have and netstandard2.0's `Stream` does not. Shipped is the API as released;
  Unshipped is what changed since. A public symbol missing from them is a warning, RS0016, until it is
  listed - an addition breaks no one - and a listed one that is gone fails the build with RS0017.
- **Package validation.** The package being built is checked for its target frameworks agreeing
  with one another: what netstandard2.0 offers, net8.0 and net10.0 have to offer too. Once SharpDTLS
  has a release, it is compared with that release as well, and every binary or source breaking
  change fails the build with a CP error.

## Adding to the API

List what the RS0016 warnings name: accept their fix in the IDE ("Add to public API"), or from the command line:

```
dotnet format analyzers src/SharpDTLS/SharpDTLS.csproj --diagnostics RS0016 --severity warn
```

That writes into the `PublicAPI.Unshipped.txt` next to the project, which is right for anything
every framework has. A member inside `#if !NETSTANDARD2_0` (or similar) belongs in the
`PublicAPI.Unshipped.txt` of each framework it exists on instead; the RS0016 warning says which
framework it was reported for. A framework without a folder of its own gets one with both files.

A member that only some frameworks have should be added to the others too where they can have it,
rather than in place of something they already have, so that the frameworks keep agreeing.

## Removing or changing the API

RS0017 names what disappeared. Moving its line from Shipped to Unshipped with a `*REMOVED*` prefix
records the removal; a member whose signature changed is a removal of the old line and an addition
of the new one.

If package validation then reports a CP error, the change breaks code built against another
framework or, once there is one, the last release. When that is intended, record it:

```
dotnet build src/SharpDTLS/SharpDTLS.csproj -c Release -p:ApiCompatGenerateSuppressionFile=true
```

That writes `src/SharpDTLS/CompatibilitySuppressions.xml`. Say in the pull request what broke.

Validation runs as part of the build, because the build packs. `dotnet pack` on its own does not
rebuild and validates whatever binaries are already in `bin`.

## Releasing

1. Move every line of each `PublicAPI.Unshipped.txt`, the per-framework ones too, into the
   `PublicAPI.Shipped.txt` beside it, dropping the `*REMOVED*` lines together with the shipped
   lines they remove.
2. Once the release is on nuget.org, set `PackageValidationBaselineVersion` in `SharpDTLS.csproj`
   to it (the first release adds the property), and delete or regenerate
   `CompatibilitySuppressions.xml` if there is one.
