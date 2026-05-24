// DDD role: ValueObject

package secret_storage

// #Handle is the opaque URI that uniquely identifies a Secret without
// exposing its plaintext material.
//
// Format: vault://<namespace-label>/<category>/<name>
//   - namespace-label: matches #NamespaceLabel (lowercase, DNS-safe)
//   - category:        matches #CategoryName (lowercase slug)
//   - name:            matches the Secret.name pattern
//
// A Handle is sufficient to invoke any Proxy Tool; it is insufficient to
// reveal plaintext — that requires an explicit vault.reveal with operator
// confirmation.
//
// The pattern anchors [ns], [cat], and [name] as non-empty path segments
// containing only lowercase letters, digits, and hyphens.
#Handle: =~ "^vault://[a-z][a-z0-9-]{1,61}[a-z0-9]/[a-z][a-z0-9-]*/[a-z][a-z0-9-]{1,62}[a-z0-9]$"

// #NamespaceLabel is the validated label component of a Handle or Namespace.
// Starts with a lowercase letter, ends with a letter or digit, may contain
// hyphens in the interior, total length 3–63 characters.
#NamespaceLabel: =~ "^[a-z][a-z0-9-]{1,61}[a-z0-9]$"

// #CategoryName is the validated slug for a category segment within a Handle.
// Lowercase, may contain hyphens; minimum 1 character.
#CategoryName: =~ "^[a-z][a-z0-9-]*$"
