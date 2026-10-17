// Fichier genere par tools/gen_vectors.py : ne pas modifier a la main.
// Implementation de reference : voir le script, ecrit d'apres la version Go.

struct Vector {
    secret: &'static str,
    now: i64,
    difficulty: u32,
    ip: &'static str,
    conn_id: &'static str,
    clearance_ip: &'static str,
    challenge_salt: &'static str,
    clearance_salt: &'static str,
    challenge: &'static str,
    signature: &'static str,
    payload_json: &'static str,
    nonce: u64,
    leading_zero_bits: u32,
    clearance: &'static str,
}

const VECTORS: Vector = Vector {
    secret: r#"0123456789abcdef0123456789abcdef"#,
    now: 1700000000,
    difficulty: 18,
    ip: r#"1.2.3.4"#,
    conn_id: r#"99"#,
    clearance_ip: r#"10.0.0.1"#,
    challenge_salt: r#"cwF77M5sHnC9DfD1DRt0SHPnuUmh0MDgo4PIv6SgR5I"#,
    clearance_salt: r#"cwF77M5sHnC9DfD1DRt0SA"#,
    challenge: r#"eyJ0cyI6MTcwMDAwMDAwMCwiZXhwIjoxNzAwMDAwMDYwLCJkaWZmIjoxOCwic2FsdCI6ImN3Rjc3TTVzSG5DOURmRDFEUnQwU0hQbnVVbWgwTURnbzRQSXY2U2dSNUkiLCJjdHgiOiIxLjIuMy40IiwiY2lkIjoiOTkifQ"#,
    signature: r#"rbmz-geYMagdTDgO6FdmjWRGuZc-P8dVt6L3f6Gnins"#,
    payload_json: r#"{"ts":1700000000,"exp":1700000060,"diff":18,"salt":"cwF77M5sHnC9DfD1DRt0SHPnuUmh0MDgo4PIv6SgR5I","ctx":"1.2.3.4","cid":"99"}"#,
    nonce: 583662,
    leading_zero_bits: 20,
    clearance: r#"AAAAAGVT-AhzAXvszmwecL0N8PUNG3RIMTAuMC4wLjE.BO5jqrbKwHdOqWvqvNTzMuETOzlDQ8LSwwHvohBW7JE"#,
};
