# Reproducing the frozen implementation

Product commit: 95b01a407375544006f066de2743e79a6599e171 in public repository 9873199/pymysql-authorized-infile.
Initial commit: 7b9584ff127fac3138668b01a321ebace725663c, verified ancestor.
Native Windows x64, CPython 3.14.3. No container or external MySQL service was used in this independent replay.
Install pytest using the retained dependency lock; import pymysql from a clean checkout of the product commit.
Place each revision's support files together and add the checkout and that support directory to PYTHONPATH.
Run the argv arrays in the retained command JSON records, replacing only machine-local Python/cache paths.

acceptance-r1: upstream converters/err/charset 17 passed; product's new protocol tests 32 passed with -W error.
acceptance-r1 independent close-before-drain expectations were stricter than the prompt. Three affected failures are excluded.
acceptance-r2 replaces those groups: boundary 12 passed, 2 failed (one stream identity reuse cause); lifetime 5 passed, one warning.
alias-observation outputs two identical generated-data uploads from the same stream, with caller rewind between result sets.
exception-r1: two tests fail after valid ERR1105 during fetchone or close, with grant_revoked=False and no stream reads/closes.
No later data leak is claimed from that residual authority observation.

Native model actions 804-805 report 32 passed; 782-783 report a combined 58 including those 32, not 58 old plus 32 new.
The real database suite was not validated: original session has missing service/certificate errors. This is a scope limit.
The 75-second continuous video runs the clean replay in a separate ordinary verification console and keeps real failed tests visible.
The independent helpers never modify the frozen source or native trajectory; replay-proof.json records unchanged hashes.
