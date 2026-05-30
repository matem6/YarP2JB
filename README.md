# p2jb-yarpe

**PlayStation 5 jailbreak (firmware 9.00 – 12.70)**
— a port of Gezine's
[p2jb](https://github.com/Gezine/Luac0re) kernel exploit (cr_ref
overflow via `kqueueex`) to [yarpe](https://github.com/Helloyunho/yarpe),
Helloyunho's Ren'Py userland exploit, running inside
**Arcade Spirits: The New Challengers**.

Confirmed working end-to-end on **both** editions of the game:
jailbreak + GPU-DMA debug menu + in-place ELF loader. Closing the game
after completion does not kernel-panic the console.

> **Firmware support:** offsets cover **9.00 – 12.70**. Validated
> end-to-end on **11.60** (PS5 edition) and **10.40** (PS4 edition on PS5).

---

## How it works

The payload triggers a 32-bit `cr_ref` overflow in the PS5 kernel
(via ~2³² `kqueueex` syscalls), uses the resulting use-after-free to
build kernel read/write primitives (pipe-based + IPv6), escalates the
host process to root, and enables the Debug Settings menu via **GPU PM4
DMA** writes on the read-only kernel `.data` segment.

It then loads `elfldr-ps5.elf` **in place**: a normal region is
pre-allocated before the leak and, after the jailbreak, made RWX by
patching its `vm_map_entry` protection byte through the kernel R/W —
no new mapping, so it bypasses the per-process `vm_map_entry` limit
that otherwise blocks a second payload. On the PS4 edition the process
`sysent` is temporarily swapped to a PS5-native one so the PS5 ELF's
syscalls resolve correctly. The loader then listens on TCP `:9021`
for ELFs to run on the jailbroken PS5.

---

## Requirements

### PS5 setup (yarpe)

This payload runs **inside** yarpe, the Ren'Py userland exploit, in
*Arcade Spirits: The New Challengers* (yarpe by
[Helloyunho](https://github.com/Helloyunho/yarpe)).

The exploit save is provided in this release — you don't need to build
it. Get it onto the PS5 in one of two ways:

- **Restore the provided system backup image** — it already includes
  the exploit save. Simplest path.
- **Install the provided save into the game's save slot** manually:
  - **Jailbroken console:** replace the save directly (e.g. Apollo
    Save Tool).
  - **Non-jailbroken, PSN-activated account:** import the save via USB —
    see [yarpe's docs](https://github.com/Helloyunho/yarpe#psnor-fake-activated)
    for the decrypt / re-encrypt steps.

Then launch the game and **load the save** — that's the exploit entry
point. yarpe listens on **TCP `:9025`** for a Python script. yarpe is a
*userland* exploit; this payload is what takes it to the kernel.

The provided save already includes the updated ELF loader at
`/saves/yarpe/elfldr-ps5.elf` — you don't need to add it yourself.

### Hardware

- PlayStation 5 with *Arcade Spirits: The New Challengers* installed —
  PS5 edition (PPSA06409 / PPSA06410) or PS4 edition
  (CUSA32096 / CUSA32097).
- A PC on the same LAN as the PS5.
- A USB stick for transferring the save (method depends on whether the
  console is jailbroken).

### Software (on PC)

- Any TCP socket client — `nc`, or
  [Al-Azif/hermes-link](https://github.com/Al-Azif/hermes-link) — to
  send the payload to `:9025` and ELFs to the loader on `:9021`.

### Files

- `p2jb.py` — the jailbreak payload (this repo).
- **Exploit save / system backup image** — provided in this release;
  already includes the updated ELF loader (`elfldr-ps5.elf`).

---

## Usage

### 1. Send the payload

With the exploit save loaded in the game (yarpe listening on `:9025`):

```sh
nc <ps5-ip> 9025 < p2jb.py
```

### 2. Wait for the leak

The `cr_ref` leak dominates the runtime:

- **PS5 edition:** ~45 min.
- **PS4 edition:** ~52 min.

On-screen notifications mark progress (`Stage 0 … Stage 9`). Don't
interact with the PS5 while it runs. A stall would surface as a
`FATAL` / `please retry` log line — if the leak fails, just reload the
save and send the payload again.

### 3. Look for completion

When it's done the console shows the debug menu enabled and the ELF
loader running. From there, any ELF you send to `:9021` runs on the
jailbroken PS5:

```sh
nc <ps5-ip> 9021 < your_payload.elf
```

[hermes-link](https://github.com/Al-Azif/hermes-link) handles the
loader's TCP protocol for you.

---

## Known limitations

- **One run per boot.** The triple-free is a point of no return; a
  failed or completed run needs the save reloaded (and, if the game
  was torn down, a fresh launch).

---

## Credits

- **`p2jb` PoC (PS5 `cr_ref` overflow via `kqueueex`)** — Gezine.
  [Luac0re](https://github.com/Gezine/Luac0re).
- **lapse / netcontrol** — TheFlow and the PS5 lapse work; source of
  the kqueue leak and UIO/IOV kernel R/W primitives, the IPv6 R/W, and
  the GPU PM4 DMA debug-menu apply flow reused here.
- **yarpe (Ren'Py userland exploit)** — Helloyunho.
  [Helloyunho/yarpe](https://github.com/Helloyunho/yarpe).
- **NineS / ps5-payload-dev** — John Törnblom; the in-place ELF
  execution technique (`vm_map_entry` protection patch) and the
  `elfldr-ps5.elf` loader.
- **Dr.Yenyen** — built the system backup image bundling the exploit
  saves, and testing on real hardware.
- **[Sonic-Iso](https://git.etawen.dev/soniciso)** — testing on real
  hardware.
- **Claude (Anthropic)** — AI assistant used throughout the port.

---

## License

MIT — see [LICENSE](LICENSE).
