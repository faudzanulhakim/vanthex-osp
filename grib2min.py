#!/usr/bin/env python3
"""Minimal GRIB2 decoder (v1.21.0, Fase 5 program OSIRIS).

Stdlib only. Decodes exactly what the GFS wind path needs and fails
CLOSED on everything else — no guessing:

- Sections 0-8 (section 2 local-use skipped, section 6 bitmap
  optional). Grid template 3.0 (regular lat/lon) ONLY.
- Product template 4.0 ONLY (parameter category/number, fixed
  surface, forecast time in hours).
- Data templates:
  * 5.0 simple packing: value = (R + X * 2**E) / 10**D.
  * 5.3 complex packing + spatial differencing (what NOMADS
    filter_gfs_1p00.pl emits for GFS — proven on real NOMADS
    1.00 deg files, 2026-10-24 12Z: 49-byte section 5, template
    5.3, Ni=360 Nj=181). Group
    widths/lengths/reference values per data template 7.3,
    spatial differencing order 0/1/2 undone recursively.
  Anything else (5.1, 5.2, 5.4, JPEG, PNG, IEEE) raises
  GRIB2Error — never a guessed grid.
- Scanning: i/j direction bits + adjacent-direction bit are
  honoured; boustrophedon (alternating row direction) is NOT
  supported and fails closed.
- Bitmaps: absent, indicator 0, or explicit bits are supported;
  indicator 255 reuses the previous message's explicit bitmap
  (tracked across messages in one file). A 255 with no previous
  bitmap is accepted ONLY when the message holds the full grid
  (npoints == Ni*Nj, i.e. nothing is missing — the NOMADS
  quirk); otherwise it fails closed. Complex packing with a
  real bitmap (missing points) fails closed: undifferencing
  across missing values is not defined here.
- Missing-value management other than 0 (none) fails closed.

Template 5.3 layout, verified against the real NOMADS file
(2026-10-24 12Z, UGRD/VGRD 10 m, 1440x721) and the NCEP
template 5.3 / 7.3 documents:
  Section 5 (49 bytes): R@11, E@15, D@17, nbits@19 (bits per
  group reference value), origType@20, splitMethod@21,
  mgmt@22, primMiss@23-26, secMiss@27-30, NG@31-34,
  refW@35, widthBits@36, refL@37-40, lenInc@41,
  lastLen@42-45, scaledLenBits@46, spatialOrder@47,
  extraOctets@48 (octets per extra descriptor value).
  Section 7: [extra descriptors: (order+1) values x
  extraOctets bytes, sign-magnitude (first bit = sign)]
  [NG group reference values X1, nbits each, padded to a
  byte boundary] [NG group widths, widthBits each, + refW,
  padded to a byte boundary] [NG scaled group lengths,
  scaledLenBits each, length = refL + K*lenInc — the last
  streamed length MUST equal the section 5 lastLen value —
  padded to a byte boundary] [group data: length[i] values
  of width[i] bits each, value = X1[i] + stored].
  Reconstruction (order 2): f[0]=h1, f[1]=h2 from extras;
  for i>=2: h[i]=packed[i]+hmin, g[i]=h[i]+g[i-1],
  f[i]=g[i]+f[i-1]. The first `order` packed values are
  dummies (0) and are discarded. Physical value =
  (R + f*2**E) / 10**D.
  Structural proof on the real file: sum(lengths) ==
  1038240 == Ni*Nj exactly for BOTH messages, streamed last
  lengths match section 5 (54, 110), trailing slack is pure
  byte padding (4 and 3 bits), and the decoded field is
  smooth and in physical range (see tests/test_v1210.py).
"""

import array
import datetime as _dt
import struct


class GRIB2Error(ValueError):
    pass


def _u16(b, off):
    return struct.unpack_from(">H", b, off)[0]


def _u32(b, off):
    return struct.unpack_from(">I", b, off)[0]


def _i16(b, off):
    return struct.unpack_from(">h", b, off)[0]


def _i32(b, off):
    return struct.unpack_from(">i", b, off)[0]


def _f32(b, off):
    return struct.unpack_from(">f", b, off)[0]


class _BitReader:
    """MSB-first bit reader over a bytes object."""

    def __init__(self, data, bitpos=0):
        self._d = data
        self.pos = bitpos

    def read(self, n):
        if n == 0:
            return 0
        if self.pos + n > len(self._d) * 8:
            raise GRIB2Error("packed data truncated")
        v = 0
        d = self._d
        pos = self.pos
        for _ in range(n):
            v = (v << 1) | ((d[pos // 8] >> (7 - pos % 8)) & 1)
            pos += 1
        self.pos = pos
        return v

    def align_byte(self):
        if self.pos % 8:
            self.pos += 8 - self.pos % 8


def _unpack_bits(data, nbits, count):
    """Simple-packing bit stream -> list of unsigned ints."""
    if nbits == 0:
        return [0] * count
    if nbits > 32:
        raise GRIB2Error("bits per value %d exceeds 32" % nbits)
    br = _BitReader(data)
    return [br.read(nbits) for _ in range(count)]


def _sign_magnitude(raw):
    """Sign-magnitude integer: first bit = sign (1 = negative)."""
    if not raw:
        raise GRIB2Error("empty extra descriptor")
    v = int.from_bytes(raw, "big")
    nbits = len(raw) * 8
    sign = (v >> (nbits - 1)) & 1
    mag = v & ((1 << (nbits - 1)) - 1)
    return -mag if sign else mag


def _decode_complex_53(sec5, payload, npoints_data):
    """Decode a template 5.3 section 7 payload. Returns the list of
    original scaled integers (length npoints_data)."""
    if len(sec5) != 49:
        raise GRIB2Error("template 5.3 section 5 must be 49 bytes, "
                         "got %d" % len(sec5))
    nbits = sec5[19]
    orig_type = sec5[20]
    mgmt = sec5[22]
    ngroups = _u32(sec5, 31)
    ref_w = sec5[35]
    width_bits = sec5[36]
    ref_l = _u32(sec5, 37)
    len_inc = sec5[41]
    last_len = _u32(sec5, 42)
    scaled_len_bits = sec5[46]
    order = sec5[47]
    extra_octets = sec5[48]
    if orig_type != 0:
        raise GRIB2Error("template 5.3 original field values must "
                         "be floating point (type 0), got %d"
                         % orig_type)
    if mgmt != 0:
        raise GRIB2Error("template 5.3 missing value management "
                         "%d unsupported (only 0 = none)" % mgmt)
    if order not in (0, 1, 2):
        raise GRIB2Error("template 5.3 spatial differencing order "
                         "%d unsupported" % order)
    if nbits > 32 or width_bits > 32 or scaled_len_bits > 32:
        raise GRIB2Error("template 5.3 bit width out of range")
    if ngroups <= 0:
        raise GRIB2Error("template 5.3 group count %d" % ngroups)
    # ---- extra descriptors: (order+1) values x extra_octets bytes
    n_extra = order + 1
    extra_bytes = n_extra * extra_octets
    if extra_bytes > len(payload):
        raise GRIB2Error("template 5.3 extra descriptors truncated")
    extras = []
    for i in range(n_extra):
        chunk = payload[i * extra_octets:(i + 1) * extra_octets]
        extras.append(_sign_magnitude(chunk))
    if order == 0:
        seeds, hmin = [], None
    elif order == 1:
        seeds, hmin = extras[:1], extras[1]
    else:
        seeds, hmin = extras[:2], extras[2]
    # ---- group reference values X1 (nbits each, byte-padded)
    br = _BitReader(payload, extra_bytes * 8)
    refs = [br.read(nbits) for _ in range(ngroups)]
    br.align_byte()
    # ---- group widths (byte-padded: the encoder aligns every
    # descriptor stream; proven by the VGRD message, whose width
    # stream is 125844 bits = 4 mod 8 — without this pad the
    # length stream misaligns and the length sum fails)
    widths = [ref_w + br.read(width_bits) for _ in range(ngroups)]
    br.align_byte()
    # ---- group lengths: ALL NG lengths are in the stream (the
    # octets 43-46 value duplicates the streamed last length —
    # proven: both real messages stream it, 54 and 110 — and it
    # is validated below, never trusted blindly). Length stream
    # is byte-padded before the data.
    lengths = [ref_l + br.read(scaled_len_bits) * len_inc
               for _ in range(ngroups)]
    if lengths[-1] != last_len:
        raise GRIB2Error("template 5.3 streamed last group length "
                         "%d != section 5 value %d"
                         % (lengths[-1], last_len))
    if sum(lengths) != npoints_data:
        raise GRIB2Error("template 5.3 group lengths sum %d != "
                         "data points %d"
                         % (sum(lengths), npoints_data))
    br.align_byte()
    # ---- group data: value = X1[group] + stored deviation
    packed = []
    for i in range(ngroups):
        w = widths[i]
        base = refs[i]
        if w == 0:
            packed.extend([base] * lengths[i])
        else:
            for _ in range(lengths[i]):
                packed.append(base + br.read(w))
    if len(packed) != npoints_data:
        raise GRIB2Error("template 5.3 unpacked %d values, expected "
                         "%d" % (len(packed), npoints_data))
    if br.pos > len(payload) * 8:
        raise GRIB2Error("template 5.3 data overruns section 7")
    slack = len(payload) * 8 - br.pos
    if slack >= 8:
        raise GRIB2Error("template 5.3 trailing %d bits after data "
                         "(expected byte padding < 8)" % slack)
    # ---- undo spatial differencing
    if order == 0:
        return packed
    out = [0] * npoints_data
    for i, s in enumerate(seeds):
        out[i] = s
    if order == 1:
        g_prev = seeds[0]
        f_prev = seeds[0]
        for i in range(1, npoints_data):
            g = packed[i] + hmin + g_prev
            f = g + f_prev
            out[i] = f
            g_prev, f_prev = g, f
    else:
        # Order 2: g[0] = f[0], g[1] = f[1] - f[0] (NOT f[1]:
        # seeding g_prev with f[1] injects a constant error into
        # g[1] that the double cumulative sum then grows
        # linearly to ~3e9 over a million points — this exact
        # bug was caught by the range check on the real file).
        g_prev = seeds[1] - seeds[0]
        f_prev = seeds[1]
        for i in range(2, npoints_data):
            h = packed[i] + hmin
            g = h + g_prev
            f = g + f_prev
            out[i] = f
            g_prev, f_prev = g, f
    return out


def _parse_message(msg, start, prev_bitmap=None):
    """Parse one GRIB2 message at offset start. Returns
    (message_dict, next_offset). Raises GRIB2Error on any defect."""
    if msg[start:start + 4] != b"GRIB":
        raise GRIB2Error("missing GRIB magic at offset %d" % start)
    if msg[start + 7] != 2:
        raise GRIB2Error("unsupported GRIB edition %d"
                         % msg[start + 7])
    total = struct.unpack_from(">Q", msg, start + 8)[0]
    end = start + total
    if total < 16 or end > len(msg):
        raise GRIB2Error("message length %d out of range" % total)
    if msg[end - 4:end] != b"7777":
        raise GRIB2Error("message does not end with 7777")
    discipline = msg[start + 6]
    pos = start + 16
    sec1 = sec3 = sec4 = sec5 = sec6 = sec7 = None
    while pos < end - 4:
        if pos + 5 > end:
            raise GRIB2Error("truncated section header")
        slen = _u32(msg, pos)
        snum = msg[pos + 4]
        if slen < 5 or pos + slen > end - 4:
            raise GRIB2Error("section %d length %d out of range"
                             % (snum, slen))
        body = msg[pos:pos + slen]
        if snum == 1:
            sec1 = body
        elif snum == 2:
            pass  # local use: skipped by design
        elif snum == 3:
            sec3 = body
        elif snum == 4:
            sec4 = body
        elif snum == 5:
            sec5 = body
        elif snum == 6:
            sec6 = body
        elif snum == 7:
            sec7 = body
        else:
            raise GRIB2Error("unknown section %d" % snum)
        pos += slen
    if sec1 is None or sec3 is None or sec4 is None \
            or sec5 is None or sec7 is None:
        raise GRIB2Error("message missing a required section "
                         "(1/3/4/5/7)")
    # ---- section 1: reference time
    try:
        year = _u16(sec1, 12)
        month, day, hour, minute = sec1[14], sec1[15], sec1[16], sec1[17]
        ref = _dt.datetime(year, month, day, hour, minute,
                           tzinfo=_dt.timezone.utc)
    except Exception as e:  # noqa: BLE001
        raise GRIB2Error("bad reference time: %s" % (e,))
    # ---- section 3: grid, template 3.0 only
    if _u16(sec3, 12) != 0:
        raise GRIB2Error("unsupported grid template %d"
                         % _u16(sec3, 12))
    npoints_grid = _u32(sec3, 6)
    ni = _u32(sec3, 30)
    nj = _u32(sec3, 34)
    la1 = _i32(sec3, 46) / 1e6
    lo1 = _i32(sec3, 50) / 1e6
    la2 = _i32(sec3, 55) / 1e6
    lo2 = _i32(sec3, 59) / 1e6
    di = _u32(sec3, 63) / 1e6
    dj = _u32(sec3, 67) / 1e6
    scan = sec3[71]
    if scan & 0x10:
        raise GRIB2Error("boustrophedon scanning (bit 4) unsupported")
    i_neg = bool(scan & 0x80)
    j_neg = bool(scan & 0x40)
    adj_j = bool(scan & 0x20)
    if ni <= 0 or nj <= 0 or ni * nj != npoints_grid:
        raise GRIB2Error("grid size mismatch: Ni=%d Nj=%d points=%d"
                         % (ni, nj, npoints_grid))
    if di == 0 or dj == 0:
        raise GRIB2Error("zero grid spacing")
    # ---- section 4: product, template 4.0 only
    if _u16(sec4, 7) != 0:
        raise GRIB2Error("unsupported product template %d"
                         % _u16(sec4, 7))
    category = sec4[9]
    number = sec4[10]
    time_unit = sec4[17]
    ftime = _u32(sec4, 18)
    surf_type = sec4[22]
    surf_scale = sec4[23]
    surf_value = _u32(sec4, 24)
    if surf_scale != 0:
        surf_value = surf_value / (10 ** surf_scale)
    if time_unit == 1:
        fhour = ftime
    else:
        raise GRIB2Error("unsupported forecast time unit %d"
                         % time_unit)
    # ---- section 5: representation, templates 5.0 / 5.3 only
    npoints_data = _u32(sec5, 5)
    data_template = _u16(sec5, 9)
    ref_val = _f32(sec5, 11)
    escale = _i16(sec5, 15)
    dscale = _i16(sec5, 17)
    nbits = sec5[19]
    if data_template not in (0, 3):
        raise GRIB2Error("unsupported data template %d (only 5.0 "
                         "simple packing and 5.3 complex packing + "
                         "spatial differencing)" % data_template)
    # ---- section 6: bitmap (optional)
    bitmap = None
    if sec6 is not None:
        indicator = sec6[5]
        if indicator == 255:
            if prev_bitmap is not None:
                bitmap = prev_bitmap
            elif npoints_data == ni * nj:
                bitmap = None  # NOMADS quirk: 255, no previous,
                # but the full grid is present, so nothing is
                # missing; anything else fails closed below.
            else:
                raise GRIB2Error("bitmap 255 without a previous "
                                 "bitmap and %d < %d grid points"
                                 % (npoints_data, ni * nj))
        elif len(sec6) > 6:
            bitmap = sec6[6:]
        elif indicator == 0:
            bitmap = None
        else:
            raise GRIB2Error("unsupported bitmap indicator %d"
                             % indicator)
    if bitmap is not None:
        npresent = sum(bin(b).count("1") for b in bitmap)
        if npresent != npoints_data:
            raise GRIB2Error("bitmap present count %d != data points "
                             "%d" % (npresent, npoints_data))
    elif npoints_data != ni * nj:
        raise GRIB2Error("data points %d != grid points %d"
                         % (npoints_data, ni * nj))
    # ---- section 7: packed data
    raw = sec7[5:]
    if data_template == 0:
        ints = _unpack_bits(raw, nbits, npoints_data)
        if nbits == 0:
            values = [ref_val / (10.0 ** dscale)] * npoints_data
        else:
            pow2 = 2.0 ** escale
            div = 10.0 ** dscale
            values = [(ref_val + x * pow2) / div for x in ints]
    else:
        if bitmap is not None:
            raise GRIB2Error("template 5.3 with a bitmap (missing "
                             "points) unsupported: undifferencing "
                             "across missing values is undefined")
        ints = _decode_complex_53(sec5, raw, npoints_data)
        pow2 = 2.0 ** escale
        div = 10.0 ** dscale
        values = [(ref_val + x * pow2) / div for x in ints]
    # rank lookup for the simple-packing bitmap case (storage idx ->
    # value rank, -1 if missing); None when no bitmap.
    rank = None
    if bitmap is not None:
        rank = array.array("i", [-1]) * (ni * nj)
        r = 0
        for idx in range(ni * nj):
            if (bitmap[idx // 8] >> (7 - idx % 8)) & 1:
                rank[idx] = r
                r += 1
    return {
        "discipline": discipline,
        "ref_time": ref,
        "grid": {"ni": ni, "nj": nj, "la1": la1, "lo1": lo1,
                 "la2": la2, "lo2": lo2, "di": di, "dj": dj,
                 "i_neg": i_neg, "j_neg": j_neg, "adj_j": adj_j},
        "param": {"category": category, "number": number,
                  "surface_type": surf_type,
                  "surface_value": surf_value,
                  "forecast_hour": fhour},
        "values": values,
        "bitmap": bitmap,
        "rank": rank,
    }, end


def decode_messages(data):
    """Decode every GRIB2 message in data. Returns a list of message
    dicts (see _parse_message). Raises GRIB2Error on the first
    defect — a partially decoded file is never returned."""
    out = []
    pos = 0
    prev_bitmap = None
    while pos < len(data):
        if data[pos:pos + 4] != b"GRIB":
            raise GRIB2Error("expected GRIB magic at offset %d" % pos)
        msg, nxt = _parse_message(data, pos, prev_bitmap)
        if msg["bitmap"] is not None:
            prev_bitmap = msg["bitmap"]
        out.append(msg)
        pos = nxt
    if not out:
        raise GRIB2Error("no GRIB2 messages found")
    return out


def _storage_index(grid, row, col):
    """Storage-order index for grid (row, col): row advances along
    j, col along i; adjacency bit picks the major axis."""
    ni, nj = grid["ni"], grid["nj"]
    if not (0 <= row < nj and 0 <= col < ni):
        raise GRIB2Error("grid index out of range")
    if grid["adj_j"]:
        return col * nj + row
    return row * ni + col


def storage_value(msg, row, col):
    """Value at grid (row, col); None when the bitmap marks it
    missing."""
    idx = _storage_index(msg["grid"], row, col)
    if msg["bitmap"] is None:
        return msg["values"][idx]
    rank = msg["rank"][idx]
    if rank < 0:
        return None
    return msg["values"][rank]


def grid_position(grid, row, col):
    """Grid (row, col) -> (lat, lon in [0, 360)).

    The natural row/column order runs from the first grid point
    (la1, lo1) toward the last (la2, lo2); the scanning bits
    REVERSE that order when set. (For GFS: la1=90, la2=-90,
    scan=0 -> rows run 90 -> -90, NOT 90 -> 270. A naive
    la1 + row*dj implementation gets this backwards.)"""
    ni, nj = grid["ni"], grid["nj"]
    la1, la2, dj = grid["la1"], grid["la2"], grid["dj"]
    lo1, lo2, di = grid["lo1"], grid["lo2"], grid["di"]
    if abs(la1 + (nj - 1) * dj - la2) < 0.01:
        j_sign = 1
    elif abs(la1 - (nj - 1) * dj - la2) < 0.01:
        j_sign = -1
    else:
        j_sign = 1 if la2 >= la1 else -1
    if grid["j_neg"]:
        j_sign = -j_sign
    east = (lo2 - lo1) % 360.0
    west = (lo1 - lo2) % 360.0
    span = (ni - 1) * di
    if abs(east - span) < 0.01:
        i_sign = 1
    elif abs(west - span) < 0.01:
        i_sign = -1
    else:
        i_sign = 1 if lo2 >= lo1 else -1
    if grid["i_neg"]:
        i_sign = -i_sign
    lat = la1 + j_sign * row * dj
    lon = (lo1 + i_sign * col * di) % 360.0
    return lat, lon


def decode_gfs_uv(data, thin_step=1):
    """Decode a NOMADS-filtered GFS file holding exactly UGRD + VGRD
    at 10 m above ground. Returns (info, u_rows, v_rows) where rows
    run north->south and columns west->east starting at lon 0
    (caller rotates to -180..180 if needed). With thin_step > 1 only
    every thin_step-th row/column is kept (2 -> 180x91 for the
    1.00 deg global grid).
      info: {cycle (datetime), fhour, ni, nj, la_top, lo_start,
             di, dj, thin_step}
    Raises GRIB2Error unless the file holds exactly one UGRD and
    one VGRD message on the same grid, cycle and forecast hour."""
    msgs = decode_messages(data)
    by_param = {}
    for m in msgs:
        p = m["param"]
        if p["category"] != 2 or p["number"] not in (2, 3):
            raise GRIB2Error("unexpected parameter category %d "
                             "number %d" % (p["category"], p["number"]))
        if p["surface_type"] != 103 or p["surface_value"] != 10:
            raise GRIB2Error("unexpected surface type %s value %s"
                             % (p["surface_type"], p["surface_value"]))
        if p["number"] in by_param:
            raise GRIB2Error("duplicate parameter number %d"
                             % p["number"])
        by_param[p["number"]] = m
    if 2 not in by_param or 3 not in by_param:
        raise GRIB2Error("file must hold UGRD (2) + VGRD (3); got %s"
                         % sorted(by_param))
    mu, mv = by_param[2], by_param[3]
    if mu["grid"] != mv["grid"]:
        raise GRIB2Error("UGRD/VGRD grids differ")
    if mu["ref_time"] != mv["ref_time"] \
            or mu["param"]["forecast_hour"] \
            != mv["param"]["forecast_hour"]:
        raise GRIB2Error("UGRD/VGRD cycle/forecast differ")
    g = mu["grid"]
    ni, nj = g["ni"], g["nj"]
    # Canonical axes: latitudes descending (north->south),
    # longitudes ascending from 0. Map each canonical coordinate
    # back to its storage (row, col) via the scanning signs.
    lats_all = [grid_position(g, r, 0)[0] for r in range(nj)]
    lons_all = [grid_position(g, 0, c)[1] for c in range(ni)]
    row_of_lat = {}
    for r, la in enumerate(lats_all):
        row_of_lat.setdefault(round(la, 6), r)
    col_of_lon = {}
    for c, lo in enumerate(lons_all):
        col_of_lon.setdefault(round(lo, 6), c)
    lats = sorted(set(round(x, 6) for x in lats_all), reverse=True)
    lons = sorted(set(round(x, 6) for x in lons_all))
    lats = lats[::thin_step]
    lons = lons[::thin_step]
    u_rows, v_rows = [], []
    for la in lats:
        u_row, v_row = [], []
        for lo in lons:
            r = row_of_lat[la]
            c = col_of_lon[lo]
            u_row.append(storage_value(mu, r, c))
            v_row.append(storage_value(mv, r, c))
        u_rows.append(u_row)
        v_rows.append(v_row)
    info = {"cycle": mu["ref_time"],
            "fhour": mu["param"]["forecast_hour"],
            "ni": ni, "nj": nj,
            "la_top": lats[0], "lo_start": lons[0],
            "di": g["di"] * thin_step, "dj": g["dj"] * thin_step,
            "thin_step": thin_step}
    return info, u_rows, v_rows
