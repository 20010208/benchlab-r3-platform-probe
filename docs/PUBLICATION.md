# Publication boundary and hygiene (no publication has occurred; nothing here is an approval to publish)

## What this repository contains

Only newly written operations material: the wrapper, the hash-locked dependency file, the workflow (not installed), the tests, and documentation.
It contains **no** credentials of any kind, no participant-site configuration or address, no cloud keys, no private datasets, no generated artefacts, no candidate source, no weights, no ledger contents, no feed snapshots, and no local filesystem paths.
All commits in this repository use a neutral identity (`benchlab-r3-ops <r3-ops@users.noreply.invalid>`). The test suite scans every file and the commit identities for these classes.

## What is NOT in this repository and must be decided separately

| Item | Status |
|---|---|
| The frozen candidate (`422f73d5…`) | Exists only in a local clone. R3 reconstructs it at run time from the official upstream commit (fetched by exact SHA) **plus** a thin bundle/remote holding the user's candidate commits. Where that history is published is a **PM decision**; nothing was published. |
| The organizer's unchanged starter-kit files | Never republished by R3 (fetched from upstream at the pinned commit). 5 organizer-derived files that the user modified (`submission_pack/Dockerfile`, `README.md`, `model.py`, `requirements.txt`, `submission.json`) are inside the user's candidate commits and therefore inside any published candidate history. Whether redistributing those derivatives is permitted under the organizer's preliminary licence is **unknown** and should be confirmed with the organizer. |
| Licence for the R3 code | Not chosen. The competition's open-source expectation applies to submissions; it was not found in the kit documents and is not assumed. |
| The independent mirror / external anchor | Must exist outside the repository for coordinated-rewrite detection. |

## Existing candidate-history privacy caveats (reported, not remediable here)

The frozen candidate's existing history cannot be rewritten or sanitised: changing it changes the freeze SHA and creates a different candidate.

* The user's candidate commits (10 commits between the upstream commit and the freeze commit) carry the user's personal name and email address in the commit metadata. Publishing any bundle or remote that contains them publishes that metadata.
* One evidence document inside the frozen history contains a local absolute filesystem path that includes the user's account name.
* Other contributors' commit metadata already exists in the public upstream repository.

Decision options for the PM: publish the candidate history as it is (accepting the above), keep the candidate repository private and give the workflow read access through a narrowly scoped credential (this contradicts the "no secrets" design and needs a new audit), or do not use GitHub-hosted shadow operations.

## Public-by-design material once activated

The ledger branch (records, journal, forecasts and gzip copies of the public feeds the model saw) is public if the repository is public. The feeds are public NOAA/NASA data; their reuse terms were not verified. Forecasts become visible when committed, before their truth exists, which is intentional for credibility.
