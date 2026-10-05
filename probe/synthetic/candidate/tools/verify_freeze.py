"""SYNTHETIC stand-in (platform tests only): identity fields for the synthetic fixture.  Real freeze verification is NOT exercised here."""


def candidate_fields(root, expect_sha, tag):
    return dict(candidate_freeze_sha=expect_sha, candidate_tag=tag, synthetic=True)
