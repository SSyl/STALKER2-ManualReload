# ManualReload

S.T.A.L.K.E.R. 2 mod that removes the automatic reload. Pulling the trigger on an empty
magazine plays the dry-fire click. The game already does this when you have no ammo for the
weapon. Press Reload to reload. Reloading early and the +1 chamber reload are unchanged.

## Installing

The same DLL works with either loader. Install only one copy.

- **UE4SS:** put `main.dll` in `Stalker2/Binaries/Win64/ue4ss/Mods/ManualReload/dlls/` and add an
  empty `enabled.txt` in `Mods/ManualReload/`.
- **Ultimate ASI Loader:** rename `main.dll` to `ManualReload.asi` and put it in
  `Stalker2/Binaries/Win64/`. If no other mod has installed the loader, get the x64 build from
  [its releases](https://github.com/ThirteenAG/Ultimate-ASI-Loader/releases) and install it as
  `dsound.dll` in the same folder.

Each launch writes `ManualReload.log` next to the DLL with the result. If the patch fails for
any reason, the game is left untouched and auto-reload works as in vanilla.

## What it patches

The player's fire handler asks a native getter for the weapon's `EShootingAvailability` and
branches on the result:

```
cmp eax, 3                ; NoAmmoLoaded: magazine empty, ammo in inventory
je  <reload block>        ; -> calls Reload (the auto-reload)
cmp eax, 4                ; NoAmmo
je  <dry fire>            ; -> click
cmp byte [reg+disp32], 5  ; Jammed
```

The mod rewrites the first `je` to jump to the second `je`'s target, so `NoAmmoLoaded` takes
the dry-fire path. The change only affects the player, because the reload block and the
dry-fire routine both return early for any other owner. The manual reload key reaches reload
through input handling and never passes through this branch.

The signature (`src/patch.cpp`) wildcards both jump targets, the jam-check struct offset and its
register. It must match exactly once, both targets must sit inside the same function (`.pdata`),
and the bytes are re-checked right before the write.

Found on Steam build 26123434 (exe PE timestamp `0x2B1AEEBF`), where the branch is at RVA
`0xF320D4` inside the fire handler at RVA `0xF31C40`.

## Building

```
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
```

This produces `build/Release/main.dll` and `build/Release/ManualReloadScan.exe`.

## After a game update

1. Run `ManualReloadScan.exe "<game>/Stalker2/Binaries/Win64/Stalker2-Win64-Shipping.exe"`.
   `ReadyToPatch` (exit code 0) means the mod still applies. Confirm in game anyway.
2. If it reports `NotFound`, `Ambiguous` or `ValidationFailed`, first check the enum in a fresh
   UE4SS UHT dump (`Stalker2/Public/EShootingAvailability.h`). If `NoAmmoLoaded`, `NoAmmo` or
   `Jammed` changed value, update the `0x03` / `0x04` / `0x05` bytes in `MatchesAt`.
3. If the values are the same, the code around the branch changed. To find the branch again:
   - Find the native `Reload` implementation. The `Reload` UFunction's exec thunk (found
     through the `"Reload"` name and the `{name, thunk}` table next to it in `.rdata`) jumps
     through an `AObj` vtable slot, which in this build was `0xc30` and forwarded to `0xc28`.
     The player class overrides `0xc28`.
   - Attach a debugger with a logging breakpoint on the player's `0xc28` implementation, then
     fire on an empty magazine with ammo in the inventory. The auto-reload stack comes from the
     player trigger state machine, and the fire handler is the frame that tail-jumps into
     `Reload`. A Reload-key press shows a different stack, which comes from input handling.
   - In the fire handler, find the call to the shooting-availability getter and the compare
     chain on its result, then update `MatchesAt` to match the new bytes.
4. Test in game: dry fire on an empty magazine with ammo, early reload, the +1 reload, normal
   firing and a jammed weapon.
