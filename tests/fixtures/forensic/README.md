Files for tests/forensic.spec.js.

- library-q75.jpg — a photo from tests/fixtures/pics re-saved by Pillow at quality 75 (standard IJG tables, no EXIF).
- edited-crop.jpg — a photo cropped after "capture": the EXIF keeps the thumbnail of the uncropped picture, Software is
  Photoshop, DateTime differs from DateTimeOriginal (+02:00), GPS on the Eiffel Tower with the GPS clock at 2024-06-21 11:52 UTC
  and the camera facing 170°.
- night-claim.jpg — GPS clock 2024-06-21 23:30 UTC in Paris (the sun is below the horizon).
- copy-move.png / copy-move-q90.jpg — pics/p04.jpg with its round window copied 240 px right and 134 px down.
- invoice.pdf.lnk — a shortcut built to the MS-SHLLINK spec: target powershell.exe with a download cradle, minimised,
  volume serial 1A2B-3C4D, NetBIOS name desktop-7f3k2a, version-1 object ID carrying MAC 00:0c:29:4f:8e:35 (VMware).
- launcher-w32.exe — the Windows launcher shipped in distlib (Python packaging): PDB path, Rich header, version info.
  Reference values from pefile: imphash af457a899dff0be8f96c758b66fd5f37, Rich header hash 24f28c9802bcb7fe3063fd33a3a0e3e5.
- packed-tokyo.zip — made with Info-ZIP on Linux as root, TZ=Asia/Tokyo (DOS local times 9 hours ahead of the UT extra field).
