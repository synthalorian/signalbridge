use std::env;
use std::fs;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

const VERSION: &str = "SIGNAL1";
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Envelope {
    timestamp: u64,
    id: String,
    channel: String,
    sender: String,
    payload: String,
    checksum: String,
}

fn fnv1a64(data: &str) -> u64 {
    data.bytes().fold(FNV_OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    })
}

fn checksum_parts(timestamp: u64, channel: &str, sender: &str, payload: &str) -> u64 {
    fnv1a64(&format!("{VERSION}|{timestamp}|{channel}|{sender}|{payload}"))
}

fn escape_field(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('|', "%7C")
        .replace('\n', "%0A")
        .replace('\r', "%0D")
}

fn unescape_field(value: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        let a = chars.next().ok_or("dangling percent escape")?;
        let b = chars.next().ok_or("truncated percent escape")?;
        match (a, b) {
            ('2', '5') => out.push('%'),
            ('7', 'C') => out.push('|'),
            ('0', 'A') => out.push('\n'),
            ('0', 'D') => out.push('\r'),
            _ => return Err(format!("unknown escape %{a}{b}")),
        }
    }
    Ok(out)
}

fn mint(timestamp: u64, channel: &str, sender: &str, payload: &str) -> Envelope {
    let checksum = checksum_parts(timestamp, channel, sender, payload);
    Envelope {
        timestamp,
        id: format!("{checksum:016x}")[..8].to_string(),
        channel: channel.to_string(),
        sender: sender.to_string(),
        payload: payload.to_string(),
        checksum: format!("{checksum:016x}"),
    }
}

fn encode(envelope: &Envelope) -> String {
    format!(
        "{VERSION}|{}|{}|{}|{}|{}|{}",
        envelope.timestamp,
        envelope.id,
        escape_field(&envelope.channel),
        escape_field(&envelope.sender),
        escape_field(&envelope.payload),
        envelope.checksum
    )
}

fn decode(line: &str) -> Result<Envelope, String> {
    let parts: Vec<&str> = line.trim().split('|').collect();
    if parts.len() != 7 {
        return Err(format!("expected 7 SIGNAL1 fields, got {}", parts.len()));
    }
    if parts[0] != VERSION {
        return Err(format!("unsupported envelope version {}", parts[0]));
    }
    let timestamp = parts[1]
        .parse::<u64>()
        .map_err(|_| "timestamp must be an unsigned integer".to_string())?;
    let envelope = Envelope {
        timestamp,
        id: parts[2].to_string(),
        channel: unescape_field(parts[3])?,
        sender: unescape_field(parts[4])?,
        payload: unescape_field(parts[5])?,
        checksum: parts[6].to_string(),
    };
    verify(&envelope)?;
    Ok(envelope)
}

fn verify(envelope: &Envelope) -> Result<(), String> {
    let expected = checksum_parts(
        envelope.timestamp,
        &envelope.channel,
        &envelope.sender,
        &envelope.payload,
    );
    let expected_hex = format!("{expected:016x}");
    if envelope.checksum != expected_hex {
        return Err(format!(
            "checksum mismatch: expected {expected_hex}, got {}",
            envelope.checksum
        ));
    }
    if envelope.id != expected_hex[..8] {
        return Err(format!(
            "id mismatch: expected {}, got {}",
            &expected_hex[..8],
            envelope.id
        ));
    }
    Ok(())
}

fn unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock is before Unix epoch: {e}"))
}

fn usage() {
    eprintln!(
        "signalbridge — tamper-evident local handoff envelopes\n\n\
         USAGE:\n\
           signalbridge send [--channel NAME] [--sender NAME] <payload...>\n\
           signalbridge verify <SIGNAL1|...>\n\
           signalbridge tail <envelope-log>\n\n\
         FORMAT:\n\
           SIGNAL1|unix_timestamp|id|channel|sender|payload|fnv1a64_checksum"
    );
}

fn run_send(args: &[String]) -> Result<(), String> {
    let mut channel = "ops".to_string();
    let mut sender = "local".to_string();
    let mut payload = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--channel" => {
                i += 1;
                channel = args.get(i).ok_or("--channel requires a value")?.clone();
            }
            "--sender" => {
                i += 1;
                sender = args.get(i).ok_or("--sender requires a value")?.clone();
            }
            flag if flag.starts_with("--") => return Err(format!("unknown flag {flag}")),
            value => payload.push(value.to_string()),
        }
        i += 1;
    }
    if channel.is_empty() || sender.is_empty() {
        return Err("channel and sender cannot be empty".to_string());
    }
    if payload.is_empty() {
        return Err("send requires a payload".to_string());
    }
    let envelope = mint(unix_time()?, &channel, &sender, &payload.join(" "));
    println!("{}", encode(&envelope));
    Ok(())
}

fn run_tail(path: &str) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let mut shown = 0usize;
    for line in text.lines().rev().filter(|line| !line.trim().is_empty()) {
        let envelope = decode(line).map_err(|e| format!("invalid envelope in {path}: {e}"))?;
        println!("OK {} #{} {}", envelope.channel, envelope.id, envelope.payload);
        shown += 1;
        if shown == 10 {
            break;
        }
    }
    if shown == 0 {
        println!("no envelopes in {path}");
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("send") => run_send(&args[1..]),
        Some("verify") => {
            let line = args.get(1).ok_or("verify requires an envelope")?;
            let envelope = decode(line)?;
            println!("VALID {} #{} from {}", envelope.channel, envelope.id, envelope.sender);
            Ok(())
        }
        Some("tail") => run_tail(args.get(1).ok_or("tail requires a log path")?),
        Some("--help") | Some("-h") | None => {
            usage();
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other}; try --help")),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("signalbridge: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_fields_round_trip() {
        let original = "ops|night\n100% sure\r";
        assert_eq!(unescape_field(&escape_field(original)).unwrap(), original);
    }

    #[test]
    fn envelope_round_trip_and_verify() {
        let envelope = mint(1_700_000_000, "ops", "synth", "deploy | at 2\nam");
        let decoded = decode(&encode(&envelope)).unwrap();
        assert_eq!(decoded, envelope);
        verify(&decoded).unwrap();
    }

    #[test]
    fn tampering_is_detected() {
        let mut line = encode(&mint(42, "ops", "synth", "safe"));
        line = line.replace("safe", "evil");
        assert!(decode(&line).unwrap_err().contains("checksum mismatch"));
    }

    #[test]
    fn rejects_wrong_version() {
        let error = decode("SIGNAL2|1|x|a|b|c|d").unwrap_err();
        assert!(error.contains("unsupported envelope version"));
    }
}
