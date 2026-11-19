Office files with known metadata, made for the metadata tests: invoice.odt,
payouts.ods and deck.odp were written with odfpy, then saved by LibreOffice as
invoice.doc, payouts.xls and deck.ppt (Compound File Binary) and invoice-lo.odt.
The expected values in tests/osint2.spec.js were read from the same files with
olefile (Python), an independent reader. All names and numbers are invented.
