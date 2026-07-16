//! Out-of-band transfer of the invitation artifact (design §8.2 step 2).
//!
//! The invitation is a bearer credential, so it travels through an
//! authenticated/confidential channel or an in-person QR flow — never a
//! world-readable file. Writing to disk therefore uses mode 0600 (owner
//! read/write only). QR rendering is a display concern layered on the same
//! JSON by the CLI.
//!
//! What you write:
//! ```no_run
//! use axon_pairing::transfer::{write_invitation_file, read_invitation_file};
//! # let invitation: axon_pairing::invitation::Invitation = unimplemented!();
//! write_invitation_file("/tmp/invite.json", &invitation)?;
//! let back = read_invitation_file("/tmp/invite.json")?;
//! # Ok::<(), std::io::Error>(())
//! ```

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::Path;

use crate::invitation::Invitation;

/// Serializes an invitation to `writer` as JSON (for stdin/pipe transfer).
pub fn write_invitation<W: Write>(writer: &mut W, invitation: &Invitation) -> io::Result<()> {
    let json = serde_json::to_vec(invitation)?;
    writer.write_all(&json)
}

/// Reads an invitation from `reader` (for stdin/pipe transfer).
pub fn read_invitation<R: Read>(reader: &mut R) -> io::Result<Invitation> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Writes the invitation to `path`, creating it mode 0600 (owner-only) on Unix
/// so the bearer secret is never world- or group-readable. Fails if the file
/// already exists, to avoid clobbering another invitation.
pub fn write_invitation_file(path: impl AsRef<Path>, invitation: &Invitation) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    write_invitation(&mut file, invitation)
}

/// Reads an invitation from `path`.
pub fn read_invitation_file(path: impl AsRef<Path>) -> io::Result<Invitation> {
    let mut file = std::fs::File::open(path)?;
    read_invitation(&mut file)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn invitation() -> Invitation {
        Invitation::create(
            "https://inviter.example/bootstrap".to_owned(),
            "aa".repeat(32),
            "kid".to_owned(),
            1_000,
            900,
            5,
        )
        .0
    }

    #[test]
    fn round_trips_through_a_reader_writer() {
        let inv = invitation();
        let mut buf = Vec::new();
        write_invitation(&mut buf, &inv).unwrap();
        let back = read_invitation(&mut buf.as_slice()).unwrap();
        assert_eq!(back.secret, inv.secret);
        assert_eq!(back.endpoint, inv.endpoint);
    }

    #[test]
    fn file_is_owner_only_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invite.json");
        let inv = invitation();
        write_invitation_file(&path, &inv).unwrap();

        let back = read_invitation_file(&path).unwrap();
        assert_eq!(back.secret, inv.secret);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "invitation file must be owner-only");
        }
    }

    #[test]
    fn refuses_to_clobber_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invite.json");
        write_invitation_file(&path, &invitation()).unwrap();
        // A second write to the same path must fail rather than overwrite.
        assert!(write_invitation_file(&path, &invitation()).is_err());
    }
}
