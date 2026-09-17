//! One official upstream resolution, shared by validation, packaging and source.
//!
//! Release metadata selects inputs once. Downloaded archives are checked against
//! that metadata and extracted unchanged; generated evidence never selects the
//! next operation's version (blueprint §9.7).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::{elf, sha256, util};

const API: &str = "https://api.github.com/repos/SagerNet/sing-box";

pub struct Release {
    pub tag: String,
    pub version: String,
    pub commit: String,
    pub android: Asset,
    pub host: Asset,
}

pub struct Asset {
    name: String,
    url: String,
    size: u64,
    digest: String,
}

pub struct Artifact {
    pub binary: PathBuf,
    pub license: PathBuf,
    pub evidence: toml::Value,
    _extract: Extraction,
}

struct Extraction(PathBuf);

impl Drop for Extraction {
    fn drop(&mut self) {
        // Exclusively created by this operation; no caller tracks cleanup.
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!(
                "cannot remove owned engine extraction {}: {error}",
                self.0.display()
            );
        }
    }
}

impl Release {
    pub fn resolve() -> Result<Self, String> {
        let metadata = api_json(&format!("{API}/releases/latest"))?;
        let tag = string(&metadata, "tag_name")?;
        // The commit endpoint resolves lightweight and annotated tags alike.
        // release.target_commitish can be a moving branch such as "testing".
        let commit = api_json(&format!("{API}/commits/{tag}"))?;
        Self::from_metadata(&metadata, string(&commit, "sha")?)
    }

    fn from_metadata(metadata: &Value, commit: &str) -> Result<Self, String> {
        if metadata["draft"] != false || metadata["prerelease"] != false {
            return Err("official latest release is not a published stable release".into());
        }
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("official release tag did not resolve to a commit SHA".into());
        }
        let tag = string(metadata, "tag_name")?;
        let version = tag
            .strip_prefix('v')
            .ok_or("official release tag has no v prefix")?;
        if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Err("official stable release tag is not a numeric version".into());
        }
        let assets = metadata["assets"]
            .as_array()
            .ok_or("official release has no assets")?;
        let asset = |platform: &str| -> Result<Asset, String> {
            let name = format!("sing-box-{version}-{platform}.tar.gz");
            let value = assets
                .iter()
                .find(|asset| asset["name"] == name)
                .ok_or_else(|| format!("official release {tag} has no {name} asset"))?;
            let digest = string(value, "digest")?
                .strip_prefix("sha256:")
                .filter(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or_else(|| format!("official asset {name} has no published SHA-256 digest"))?;
            Ok(Asset {
                name,
                url: string(value, "browser_download_url")?.to_string(),
                size: value["size"]
                    .as_u64()
                    .ok_or("official asset has no byte size")?,
                digest: digest.to_ascii_lowercase(),
            })
        };
        Ok(Self {
            tag: tag.to_string(),
            version: version.to_string(),
            commit: commit.to_string(),
            android: asset("android-arm64")?,
            host: asset("linux-amd64")?,
        })
    }

    /// Rebuild an official release from a freeze list. Never contacts
    /// `/releases/latest`.
    pub fn from_freeze(engine: &toml::Value) -> Result<Self, String> {
        let tag = freeze_string(engine, "tag")?;
        let version = freeze_string(engine, "version")?;
        let commit = freeze_string(engine, "commit")?;
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("freeze engine commit is not a 40-character SHA".into());
        }
        Ok(Self {
            tag: tag.to_string(),
            version: version.to_string(),
            commit: commit.to_string(),
            android: Asset::from_freeze(
                engine
                    .get("android")
                    .ok_or("freeze engine has no android asset")?,
            )?,
            host: Asset::from_freeze(
                engine
                    .get("host")
                    .ok_or("freeze engine has no host asset")?,
            )?,
        })
    }

    pub fn freeze_table(&self) -> toml::Value {
        toml::Value::Table(toml::Table::from_iter([
            ("tag".into(), self.tag.clone().into()),
            ("version".into(), self.version.clone().into()),
            ("commit".into(), self.commit.clone().into()),
            ("android".into(), self.android.freeze_table()),
            ("host".into(), self.host.freeze_table()),
        ]))
    }

    pub fn source_url(&self) -> String {
        format!(
            "https://github.com/SagerNet/sing-box/archive/{}.tar.gz",
            self.commit
        )
    }

    pub fn corresponding_source(
        &self,
        cache: &Path,
        destination: &Path,
    ) -> Result<(PathBuf, [u8; 32]), String> {
        let cached = cache.join(format!("{}.tar.gz", self.commit));
        download(&self.source_url(), &cached)?;
        let listing = Command::new("tar")
            .arg("-tzf")
            .arg(&cached)
            .output()
            .map_err(|error| format!("inspect Corresponding Source archive: {error}"))?;
        if !listing.status.success() {
            return Err("Corresponding Source is not a readable tar archive".into());
        }
        validate_source_members(&String::from_utf8_lossy(&listing.stdout), &self.commit)?;
        let bytes = util::read_bytes(&cached)?;
        let output = destination.join(format!("sing-box-v{}-source.tar.gz", self.version));
        util::write_bytes(&output, &bytes)?;
        Ok((output, sha256::digest(&bytes)))
    }

    pub fn evidence(&self, android: &Artifact, host: &Artifact) -> toml::Value {
        toml::Value::Table(toml::Table::from_iter([
            ("tag".into(), self.tag.clone().into()),
            ("version".into(), self.version.clone().into()),
            ("upstream_commit".into(), self.commit.clone().into()),
            ("source_archive_url".into(), self.source_url().into()),
            ("android".into(), android.evidence.clone()),
            ("host_check".into(), host.evidence.clone()),
        ]))
    }
}

impl Asset {
    pub fn acquire(&self, cache: &Path) -> Result<Artifact, String> {
        let archive_path = cache.join(&self.digest).join(&self.name);
        download(&self.url, &archive_path)?;
        let bytes = util::read_bytes(&archive_path)?;
        self.verify(&bytes)?;
        // Extract each operation from the verified archive. A cached extracted
        // binary is not an independent trusted input now that hashes are evidence.
        let extract = Extraction(util::work_dir(cache, "extract")?);
        let directory = self
            .name
            .strip_suffix(".tar.gz")
            .expect("asset selection fixes suffix");
        let binary_member = format!("{directory}/sing-box");
        let license_member = format!("{directory}/LICENSE");
        util::run(
            Command::new("tar")
                .arg("-xzf")
                .arg(&archive_path)
                .arg("-C")
                .arg(&extract.0)
                .arg(&binary_member)
                .arg(&license_member),
            "official engine extraction",
        )?;
        let binary = extract.0.join(&binary_member);
        let binary_bytes = util::read_bytes(&binary)?;
        let aligns = elf::load_aligns(&binary_bytes)?;
        let evidence = toml::Value::Table(toml::Table::from_iter([
            ("asset".into(), self.name.clone().into()),
            ("archive_url".into(), self.url.clone().into()),
            ("archive_sha256".into(), self.digest.clone().into()),
            ("archive_size".into(), (bytes.len() as i64).into()),
            (
                "binary_sha256".into(),
                sha256::hex(&sha256::digest(&binary_bytes)).into(),
            ),
            ("binary_size".into(), (binary_bytes.len() as i64).into()),
            (
                "load_alignments".into(),
                toml::Value::Array(
                    aligns
                        .iter()
                        .map(|align| format!("{align:#x}").into())
                        .collect(),
                ),
            ),
        ]));
        println!(
            "engine: {} verified, ELF LOAD alignments {aligns:x?}",
            self.name
        );
        Ok(Artifact {
            binary,
            license: extract.0.join(license_member),
            evidence,
            _extract: extract,
        })
    }

    fn verify(&self, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() as u64 != self.size {
            return Err(format!(
                "{} size does not match official release metadata",
                self.name
            ));
        }
        if sha256::hex(&sha256::digest(bytes)) != self.digest {
            return Err(format!(
                "{} SHA-256 does not match official release metadata",
                self.name
            ));
        }
        Ok(())
    }

    pub(crate) fn freeze_table(&self) -> toml::Value {
        toml::Value::Table(toml::Table::from_iter([
            ("name".into(), self.name.clone().into()),
            ("url".into(), self.url.clone().into()),
            ("size".into(), (self.size as i64).into()),
            ("sha256".into(), self.digest.clone().into()),
        ]))
    }

    pub(crate) fn from_freeze(value: &toml::Value) -> Result<Self, String> {
        let name = freeze_string(value, "name")?.to_string();
        let url = freeze_string(value, "url")?.to_string();
        if url.contains("/releases/latest") {
            return Err(format!(
                "freeze asset {name} still names /releases/latest; freeze must pin a download URL"
            ));
        }
        let digest = freeze_string(value, "sha256")?.to_ascii_lowercase();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("freeze asset {name} SHA-256 is not 64 hex digits"));
        }
        let size = value
            .get("size")
            .and_then(toml::Value::as_integer)
            .ok_or_else(|| format!("freeze asset {name} has no integer size"))?;
        if size < 0 {
            return Err(format!("freeze asset {name} size is negative"));
        }
        Ok(Self {
            name,
            url,
            size: size as u64,
            digest,
        })
    }
}

fn validate_source_members(listing: &str, commit: &str) -> Result<(), String> {
    let prefix = format!("sing-box-{commit}/");
    let members = listing.lines().collect::<Vec<_>>();
    if members
        .iter()
        .any(|name| !name.starts_with(&prefix) || name.split('/').any(|part| part == ".."))
    {
        return Err("Corresponding Source archive does not have the resolved commit root".into());
    }
    for required in ["Makefile", "go.mod", "go.sum", "LICENSE"] {
        if !members.contains(&format!("{prefix}{required}").as_str()) {
            return Err(format!(
                "Corresponding Source archive is missing {required}"
            ));
        }
    }
    Ok(())
}

fn freeze_string<'a>(value: &'a toml::Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("freeze table has no string {key}"))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("official release metadata has no string {key}"))
}

pub(crate) fn api_json(url: &str) -> Result<Value, String> {
    let mut command = Command::new("curl");
    command.args([
        "-fsSL",
        "--retry",
        "3",
        "-H",
        "Accept: application/vnd.github+json",
    ]);
    if let Ok(token) = std::env::var("GH_TOKEN") {
        command
            .arg("-H")
            .arg(format!("Authorization: Bearer {token}"));
    }
    let output = command
        .arg(url)
        .output()
        .map_err(|error| format!("official release API: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "official release API failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("official release API JSON: {error}"))
}

fn download(url: &str, path: &Path) -> Result<(), String> {
    if path.is_file() {
        return Ok(());
    }
    std::fs::create_dir_all(path.parent().ok_or("download has no parent directory")?)
        .map_err(|error| format!("create download directory: {error}"))?;
    let partial = path.with_extension(format!("partial-{}", std::process::id()));
    util::run(
        Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&partial)
            .arg(url),
        "official engine download",
    )?;
    std::fs::rename(&partial, path).map_err(|error| format!("commit engine download: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn metadata() -> Value {
        let asset = |platform| {
            json!({"name":format!("sing-box-1.2.3-{platform}.tar.gz"),
            "browser_download_url":format!("https://example.invalid/{platform}"), "size":3,
            "digest":format!("sha256:{}", sha256::hex(&sha256::digest(b"abc")))})
        };
        json!({"tag_name":"v1.2.3","target_commitish":"moving-branch","draft":false,"prerelease":false,
            "assets":[asset("android-arm64"),asset("linux-amd64")]})
    }

    #[test]
    fn one_resolution_binds_both_assets_and_source_to_the_resolved_commit() {
        let mut metadata = metadata();
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let release = Release::from_metadata(&metadata, commit).unwrap();
        metadata["tag_name"] = "v9.9.9".into();
        assert!(release.android.name.contains(&release.version));
        assert!(release.host.name.contains(&release.version));
        assert!(release.source_url().contains(commit));
        assert!(!release.source_url().contains("moving-branch"));
        assert_eq!(release.tag, "v1.2.3");
        release.android.verify(b"abc").unwrap();
        assert!(release.android.verify(b"abd").is_err());
        assert!(release.android.verify(b"ab").is_err());
    }

    #[test]
    fn absent_asset_digest_is_an_error_instead_of_an_unverified_download() {
        let mut metadata = metadata();
        metadata["assets"][0]["digest"] = Value::Null;
        assert!(
            Release::from_metadata(&metadata, "0123456789abcdef0123456789abcdef01234567").is_err()
        );
    }

    #[test]
    fn corresponding_source_requires_the_commit_root_and_build_inputs() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let listing = ["Makefile", "go.mod", "go.sum", "LICENSE"]
            .map(|file| format!("sing-box-{commit}/{file}\n"))
            .concat();
        validate_source_members(&listing, commit).unwrap();
        assert!(validate_source_members("not a source archive", commit).is_err());
        assert!(validate_source_members(&listing.replace("go.mod", "missing"), commit).is_err());
        assert!(
            validate_source_members(&format!("{listing}sing-box-{commit}/../other\n"), commit)
                .is_err()
        );
    }

    #[test]
    fn freeze_reconstructs_the_release_and_rejects_latest() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let digest = sha256::hex(&sha256::digest(b"abc"));
        let engine: toml::Value = toml::from_str(&format!(
            "tag = \"v1.2.3\"\nversion = \"1.2.3\"\ncommit = \"{commit}\"\n\
             [android]\nname = \"sing-box-1.2.3-android-arm64.tar.gz\"\n\
             url = \"https://example.invalid/android.tar.gz\"\nsize = 3\nsha256 = \"{digest}\"\n\
             [host]\nname = \"sing-box-1.2.3-linux-amd64.tar.gz\"\n\
             url = \"https://example.invalid/host.tar.gz\"\nsize = 3\nsha256 = \"{digest}\"\n"
        ))
        .unwrap();
        let release = Release::from_freeze(&engine).unwrap();
        assert_eq!(release.tag, "v1.2.3");
        assert!(release.source_url().contains(commit));
        release.android.verify(b"abc").unwrap();

        let mut latest = engine.clone();
        latest["android"]["url"] =
            toml::Value::String("https://github.com/SagerNet/sing-box/releases/latest".into());
        assert!(Release::from_freeze(&latest).is_err());
    }

    #[test]
    fn extraction_lifetime_owns_cleanup() {
        let path = util::work_dir(&std::env::temp_dir(), "flux-extraction-test").unwrap();
        {
            let _owner = Extraction(path.clone());
            assert!(path.is_dir());
        }
        assert!(!path.exists());
    }
}
