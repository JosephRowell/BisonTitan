#!/usr/bin/env python3
"""
BisonTitan Icon Generator
Generates icon.ico with bison/titan security theme.

Usage:
    python generate_icon.py

Requirements:
    pip install Pillow

Output:
    icon.ico (256x256, 128x128, 64x64, 48x48, 32x32, 16x16)
"""

import math
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("ERROR: Pillow not installed")
    print("Install with: pip install Pillow")
    exit(1)


def create_bison_icon(size: int = 256) -> Image.Image:
    """
    Create a BisonTitan icon with bison/shield security theme.

    Design:
    - Dark background with gradient
    - Shield shape (security)
    - Stylized bison head silhouette
    - Accent colors: deep blue, gold/amber
    """
    # Create RGBA image
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Colors
    bg_dark = (15, 23, 42)        # Slate 900
    bg_mid = (30, 41, 59)         # Slate 800
    accent_gold = (245, 158, 11)  # Amber 500
    accent_blue = (59, 130, 246)  # Blue 500
    white = (255, 255, 255)

    # Padding
    pad = size // 16

    # ==========================================================================
    # Draw shield background
    # ==========================================================================
    shield_points = [
        (size // 2, pad),                           # Top center
        (size - pad, size // 4),                    # Top right
        (size - pad, size // 2 + size // 8),        # Mid right
        (size // 2, size - pad),                    # Bottom center (point)
        (pad, size // 2 + size // 8),               # Mid left
        (pad, size // 4),                           # Top left
    ]

    # Draw shield with gradient effect (multiple layers)
    for i, alpha in enumerate([255, 230, 200]):
        offset = i * 2
        adjusted_points = [
            (x + (offset if x < size//2 else -offset),
             y + offset)
            for x, y in shield_points
        ]
        color = (*bg_dark[:3], alpha) if i == 0 else (*bg_mid[:3], alpha)
        draw.polygon(adjusted_points, fill=color)

    # Shield border (gold accent)
    draw.polygon(shield_points, outline=accent_gold, width=max(2, size // 64))

    # ==========================================================================
    # Draw stylized bison head
    # ==========================================================================
    cx, cy = size // 2, size // 2  # Center
    head_size = size // 3

    # Bison head - simplified geometric shape
    # Main head oval
    head_left = cx - head_size // 2
    head_top = cy - head_size // 3
    head_right = cx + head_size // 2
    head_bottom = cy + head_size // 2

    draw.ellipse(
        [head_left, head_top, head_right, head_bottom],
        fill=accent_gold,
        outline=white,
        width=max(1, size // 128)
    )

    # Horns (curved lines)
    horn_width = max(3, size // 40)

    # Left horn
    left_horn = [
        (cx - head_size // 3, cy - head_size // 6),
        (cx - head_size // 2 - size // 10, cy - head_size // 3),
        (cx - head_size // 2 - size // 8, cy - head_size // 2),
    ]
    draw.line(left_horn, fill=white, width=horn_width)

    # Right horn
    right_horn = [
        (cx + head_size // 3, cy - head_size // 6),
        (cx + head_size // 2 + size // 10, cy - head_size // 3),
        (cx + head_size // 2 + size // 8, cy - head_size // 2),
    ]
    draw.line(right_horn, fill=white, width=horn_width)

    # Eyes (small circles)
    eye_size = max(4, size // 32)
    eye_y = cy - head_size // 8

    # Left eye
    draw.ellipse(
        [cx - head_size // 4 - eye_size, eye_y - eye_size,
         cx - head_size // 4 + eye_size, eye_y + eye_size],
        fill=bg_dark
    )

    # Right eye
    draw.ellipse(
        [cx + head_size // 4 - eye_size, eye_y - eye_size,
         cx + head_size // 4 + eye_size, eye_y + eye_size],
        fill=bg_dark
    )

    # Nose/snout
    snout_top = cy + head_size // 8
    snout_size = head_size // 4
    draw.ellipse(
        [cx - snout_size, snout_top,
         cx + snout_size, snout_top + snout_size],
        fill=(200, 130, 10),  # Darker gold
        outline=bg_dark,
        width=max(1, size // 128)
    )

    # Nostrils
    nostril_size = max(2, size // 64)
    draw.ellipse(
        [cx - snout_size // 2 - nostril_size, snout_top + snout_size // 2 - nostril_size,
         cx - snout_size // 2 + nostril_size, snout_top + snout_size // 2 + nostril_size],
        fill=bg_dark
    )
    draw.ellipse(
        [cx + snout_size // 2 - nostril_size, snout_top + snout_size // 2 - nostril_size,
         cx + snout_size // 2 + nostril_size, snout_top + snout_size // 2 + nostril_size],
        fill=bg_dark
    )

    # ==========================================================================
    # Add "BT" text at bottom (optional, for smaller sizes)
    # ==========================================================================
    if size >= 64:
        try:
            # Try to use a bold font
            font_size = size // 8
            try:
                font = ImageFont.truetype("arial.ttf", font_size)
            except (OSError, IOError):
                try:
                    font = ImageFont.truetype("Arial Bold.ttf", font_size)
                except (OSError, IOError):
                    font = ImageFont.load_default()

            text = "BT"
            bbox = draw.textbbox((0, 0), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_x = (size - text_width) // 2
            text_y = size - pad - font_size - size // 16

            # Draw text with outline
            outline_color = bg_dark
            for dx, dy in [(-1, -1), (-1, 1), (1, -1), (1, 1)]:
                draw.text((text_x + dx, text_y + dy), text, font=font, fill=outline_color)
            draw.text((text_x, text_y), text, font=font, fill=white)

        except Exception:
            pass  # Skip text if font issues

    return img


def create_ico_file(output_path: Path):
    """Create .ico file with multiple sizes."""
    sizes = [256, 128, 64, 48, 32, 16]
    images = []

    print("Generating icon sizes...")
    for size in sizes:
        print(f"  - {size}x{size}")
        img = create_bison_icon(size)
        images.append(img)

    # Save as ICO with all sizes
    print(f"\nSaving to: {output_path}")
    images[0].save(
        output_path,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[1:]
    )
    print("Done!")


def create_png_file(output_path: Path, size: int = 256):
    """Create a PNG file (for web/documentation)."""
    img = create_bison_icon(size)
    img.save(output_path, format="PNG")
    print(f"Saved PNG: {output_path}")


def main():
    """Generate all icon files."""
    assets_dir = Path(__file__).parent

    # Generate ICO for Windows executable
    ico_path = assets_dir / "icon.ico"
    create_ico_file(ico_path)

    # Generate PNG for documentation/web
    png_path = assets_dir / "icon.png"
    create_png_file(png_path, 256)

    # Generate favicon for web
    favicon_path = assets_dir / "favicon.ico"
    small_sizes = [48, 32, 16]
    images = [create_bison_icon(s) for s in small_sizes]
    images[0].save(
        favicon_path,
        format="ICO",
        sizes=[(s, s) for s in small_sizes],
        append_images=images[1:]
    )
    print(f"Saved favicon: {favicon_path}")

    print("\n" + "=" * 50)
    print("Icon generation complete!")
    print("=" * 50)
    print(f"\nFiles created in: {assets_dir}")
    print("  - icon.ico     (for PyInstaller exe)")
    print("  - icon.png     (for documentation)")
    print("  - favicon.ico  (for web)")


if __name__ == "__main__":
    main()
