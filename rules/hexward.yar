// Hexward built-in rules.
//
// Every rule sets three meta fields:
//   name        detection name, format Type/Platform.Family!variant
//   severity    "high", "medium" or "low"
//   description one plain sentence a person can understand
//
// Real-world coverage comes from rule packs loaded at runtime (see README).
// The rules here prove the pipeline works and stay harmless.

rule Hexward_Test_Marker
{
    meta:
        name = "Test/Any.HexwardMarker!a"
        severity = "high"
        description = "Hexward's harmless test marker. It checks that rule scanning works."

    strings:
        $marker = "HEXWARD-HARMLESS-TEST-MARKER-7f3a9c"

    condition:
        $marker at 0
}
