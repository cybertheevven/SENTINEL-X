"""Brand assets (inline SVG so reports stay self-contained and offline)."""

LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="{size}" height="{size}" role="img" '
    'aria-label="SENTINEL-X logo"><path d="M60 8 L104 24 V60 C104 86 84 104 60 114 C36 104 16 86 16 60 V24 Z" '
    'fill="#06121f" stroke="#19e3d1" stroke-width="4"/><path d="M26 60 C40 40 80 40 94 60 C80 80 40 80 26 60 Z" '
    'fill="none" stroke="#19e3d1" stroke-width="4"/><circle cx="60" cy="60" r="13" fill="none" stroke="#19e3d1" '
    'stroke-width="4"/><circle cx="60" cy="60" r="5" fill="#19e3d1"/><g stroke="#19e3d1" stroke-width="3" '
    'stroke-linecap="round"><path d="M60 30 V22"/><path d="M38 36 L33 30"/><path d="M82 36 L87 30"/></g></svg>'
)


def logo(size: int = 48) -> str:
    return LOGO_SVG.format(size=size)
