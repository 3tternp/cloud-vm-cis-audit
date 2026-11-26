"""Generate assets/icon.{png,ico}, icon_64.png (cloud with a check mark). Requires Pillow."""
from pathlib import Path
from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "assets"
OUT.mkdir(exist_ok=True)
S = 1024
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.rounded_rectangle((0, 0, S - 1, S - 1), radius=220, fill=(16, 42, 82, 255))
W = (240, 246, 255, 255)
d.ellipse((190, 400, 520, 730), fill=W)        # cloud puffs
d.ellipse((330, 270, 700, 640), fill=W)
d.ellipse((560, 380, 860, 680), fill=W)
d.rounded_rectangle((260, 520, 790, 730), radius=105, fill=W)
G = (34, 168, 99, 255)
d.line([(405, 600), (500, 690), (665, 505)], fill=G, width=62, joint="curve")
for p in ((405, 600), (500, 690), (665, 505)):
    d.ellipse((p[0] - 31, p[1] - 31, p[0] + 31, p[1] + 31), fill=G)
img.resize((256, 256), Image.LANCZOS).save(OUT / "icon.png")
img.resize((64, 64), Image.LANCZOS).save(OUT / "icon_64.png")
img.save(OUT / "icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icons written to", OUT)
