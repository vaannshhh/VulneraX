"""
VulneraX — GUI Styles & Theme Tokens
======================================
Central design system: all colours, fonts, and spacing constants.
Import this module from every GUI panel to ensure visual consistency.
"""

# ─────────────────────────────────────────────────────────────────
#  Colour Palette — Dark Cyberpunk
# ─────────────────────────────────────────────────────────────────
BG_PRIMARY      = "#0d0f14"   # Deep background
BG_SECONDARY    = "#151820"   # Card / panel background
BG_TERTIARY     = "#1c2030"   # Input / textbox background
BG_HOVER        = "#222740"   # Hover state

BORDER          = "#2a2f40"   # Subtle border

ACCENT_PURPLE   = "#7c3aed"   # Primary accent — buttons, highlights
ACCENT_GREEN    = "#00ff9d"   # Success / positive — active state, "found"
ACCENT_RED      = "#ff3366"   # Critical severity / error
ACCENT_ORANGE   = "#ff6b35"   # High severity
ACCENT_YELLOW   = "#ffd700"   # Medium severity / warning
ACCENT_CYAN     = "#00ced1"   # Low severity / info

TEXT_PRIMARY    = "#e2e8f0"   # Main body text
TEXT_SECONDARY  = "#94a3b8"   # Muted / secondary labels
TEXT_MUTED      = "#4a5568"   # Disabled / placeholder

# ─────────────────────────────────────────────────────────────────
#  Severity → Colour Mapping
# ─────────────────────────────────────────────────────────────────
SEVERITY_COLORS: dict[str, str] = {
    "critical": ACCENT_RED,
    "high":     ACCENT_ORANGE,
    "medium":   ACCENT_YELLOW,
    "low":      ACCENT_CYAN,
    "info":     TEXT_MUTED,
}

# ─────────────────────────────────────────────────────────────────
#  Log line → colour mapping (for CTkTextbox colour tags)
# ─────────────────────────────────────────────────────────────────
LOG_COLORS: dict[str, str] = {
    "success":  ACCENT_GREEN,    # [✔] [+]
    "error":    ACCENT_RED,      # [!] [✘]
    "warning":  ACCENT_YELLOW,   # [-]
    "info":     TEXT_SECONDARY,  # [*]
    "muted":    TEXT_MUTED,      # default
}

# ─────────────────────────────────────────────────────────────────
#  Typography
# ─────────────────────────────────────────────────────────────────
FONT_FAMILY_UI      = "Segoe UI"
FONT_FAMILY_MONO    = "Consolas"

FONT_TITLE          = ("Segoe UI", 22, "bold")
FONT_SUBTITLE       = ("Segoe UI", 14, "bold")
FONT_BODY           = ("Segoe UI", 13)
FONT_SMALL          = ("Segoe UI", 11)
FONT_MONO           = ("Consolas", 12)
FONT_MONO_SM        = ("Consolas", 11)

# ─────────────────────────────────────────────────────────────────
#  Spacing & Sizing
# ─────────────────────────────────────────────────────────────────
PAD_SM   = 6
PAD_MD   = 12
PAD_LG   = 20
PAD_XL   = 30

CORNER_SM  = 6
CORNER_MD  = 10
CORNER_LG  = 14

BUTTON_HEIGHT   = 42
INPUT_HEIGHT    = 42

# ─────────────────────────────────────────────────────────────────
#  CustomTkinter theme overrides
# ─────────────────────────────────────────────────────────────────
CTK_BUTTON = {
    "fg_color":           ACCENT_PURPLE,
    "hover_color":        "#6d28d9",
    "text_color":         "#ffffff",
    "corner_radius":      CORNER_MD,
    "height":             BUTTON_HEIGHT,
    "font":               FONT_SUBTITLE,
}

CTK_BUTTON_OUTLINE = {
    "fg_color":           "transparent",
    "border_color":       ACCENT_PURPLE,
    "border_width":       1,
    "hover_color":        "#1a0a2e",
    "text_color":         ACCENT_PURPLE,
    "corner_radius":      CORNER_MD,
    "height":             BUTTON_HEIGHT,
    "font":               FONT_BODY,
}

CTK_ENTRY = {
    "fg_color":           BG_TERTIARY,
    "border_color":       BORDER,
    "text_color":         TEXT_PRIMARY,
    "placeholder_text_color": TEXT_MUTED,
    "corner_radius":      CORNER_MD,
    "height":             INPUT_HEIGHT,
    "font":               FONT_BODY,
}

CTK_FRAME = {
    "fg_color":    BG_SECONDARY,
    "corner_radius": CORNER_LG,
    "border_width":  1,
    "border_color":  BORDER,
}

CTK_LABEL_TITLE = {
    "text_color": TEXT_PRIMARY,
    "font":       FONT_TITLE,
}

CTK_LABEL_MUTED = {
    "text_color": TEXT_MUTED,
    "font":       FONT_SMALL,
}
