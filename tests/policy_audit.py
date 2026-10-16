"""Read-only semantic policy comparison. Run on Linux with python3-setools."""
import json
import sys
import setools


def compare(before_path, after_path):
    before = setools.SELinuxPolicy(before_path)
    after = setools.SELinuxPolicy(after_path)
    old_permissive = sorted(str(t) for t in before.types() if t.ispermissive)
    new_permissive = sorted(str(t) for t in after.types() if t.ispermissive)
    assert old_permissive == new_permissive, "Permissive domains changed"
    old_types = {str(t): sorted(str(a) for a in t.attributes()) for t in before.types()}
    new_types = {str(t): sorted(str(a) for a in t.attributes()) for t in after.types()}
    assert old_types == new_types, "Type attributes changed"
    old = {str(rule) for rule in before.terules()}
    new = {str(rule) for rule in after.terules()}
    app_types = ["untrusted_app", "untrusted_app_25", "untrusted_app_27", "untrusted_app_29",
                 "untrusted_app_30", "app_zygote", "isolated_app"]
    checked = []
    present = {str(t) for t in before.types()} & {str(t) for t in after.types()}
    for domain in app_types:
        if domain not in present:
            continue
        original = {str(r) for r in setools.TERuleQuery(before, source=domain).results()}
        updated = {str(r) for r in setools.TERuleQuery(after, source=domain).results()}
        assert original == updated, "App permissions changed: " + domain
        checked.append(domain)
    return {"permissive_domains_unchanged": True, "permissive_domains": new_permissive,
            "type_attributes_unchanged": True,
            "app_domains_unchanged": checked, "removed_rules": sorted(old-new),
            "added_rules": sorted(new-old)}


if __name__ == "__main__":
    print(json.dumps(compare(sys.argv[1], sys.argv[2]), indent=2))
