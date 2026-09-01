//! Diagnostic: dump exactly what each eID directory returns for an id code.
//!
//! ```bash
//! cargo run -p umbrik-ldap --example probe -- 38001085718
//! ```
//!
//! Prints every entry with its DN and attribute sizes, *before* umbrik's selection rules are
//! applied. Use it when a lookup returns nothing to tell the three failure modes apart: a TLS
//! handshake failure, a directory that genuinely has no entry, or an entry that umbrik filtered
//! out (a signing certificate, or Mobile-ID).
use ldap3::{LdapConn, Scope, SearchEntry};

fn main() {
    let id = std::env::args().nth(1).expect("id code");
    for (url, base) in [
        ("ldaps://esteid.ldap.sk.ee", "c=EE"),
        ("ldaps://ldap.eidpki.ee", "dc=ldap,dc=eidpki,dc=ee"),
    ] {
        println!("== {url} (base {base})");
        let mut conn = match LdapConn::new(url) {
            Ok(c) => c,
            Err(e) => {
                println!("   connect failed: {e}");
                continue;
            }
        };
        let filter = format!("(serialNumber=PNOEE-{id})");
        match conn.search(
            base,
            Scope::Subtree,
            &filter,
            vec!["userCertificate;binary"],
        ) {
            Ok(r) => match r.success() {
                Ok((rows, _)) => {
                    println!("   {} entries", rows.len());
                    for row in rows {
                        let e = SearchEntry::construct(row);
                        println!("   dn: {}", e.dn);
                        for (k, v) in &e.attrs {
                            println!(
                                "      attrs[{k}] = {} values, first {} chars",
                                v.len(),
                                v.first().map(|s| s.len()).unwrap_or(0)
                            );
                        }
                        for (k, v) in &e.bin_attrs {
                            println!(
                                "      bin_attrs[{k}] = {} values, first {} bytes",
                                v.len(),
                                v.first().map(|b| b.len()).unwrap_or(0)
                            );
                        }
                    }
                }
                Err(e) => println!("   search rejected: {e}"),
            },
            Err(e) => println!("   search failed: {e}"),
        }
        let _ = conn.unbind();
    }
}
