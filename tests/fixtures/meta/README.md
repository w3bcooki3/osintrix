Files for the metadata reader's tests.

- Real camera and phone files, unchanged: `iphone11pro.heic`, `exif-at-eof.heic`, `iphone6-gps.mov`, `gps.mp4`, `htc-desire.webp`, `fuji-iptc-gps.jpg`, `iptc-122.jpg`, `id3.mp3` — from the metadata-extractor sample collection (github.com/drewnoakes/metadata-extractor-images).
- `iphone6-gps.jpg` and `canon-lightroom-xmp-iptc.jpg`: the original files' metadata segments (EXIF, XMP, IPTC) unchanged, on a 16 × 16 picture to keep them small.
- `libreoffice.docx`, `libreoffice.pdf`: written by LibreOffice 24.2. `objstm.pdf`: the same PDF rewritten by qpdf with object streams, so its document information is compressed.
- `sd-generated.png`: a PNG with the settings text AUTOMATIC1111 (Stable Diffusion) writes. `exif-chunk.png`: a PNG with an eXIf chunk, as phones and editors write them.
