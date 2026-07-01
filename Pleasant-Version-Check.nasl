#
# Pleasant Password Server - /Version build check (Stable baseline)
# Fingerprint + KB caching edition
# Author: Kingston Damour (2026)
#

if (description)
{
  script_id(900001);
  script_version("1.2");
  script_name("Pleasant Password Server /Version Build Check (Stable Baseline, Fingerprint, KB Cache)");
  script_summary("Queries /Version, fingerprints the service, caches version in KB, compares against Stable baseline.");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");

  script_set_attribute(attribute:"synopsis",
    value:"The remote Pleasant Password Server appears to be running a build older than the Stable baseline.");

  script_set_attribute(attribute:"description",
    value:
      "This plugin requests /Version, fingerprints the response to ensure the service resembles Pleasant Password Server, "
      "extracts the Build version, stores it in the Nessus KB, and flags the host if it is older than the Stable baseline. "
      "NASL plugins generally avoid reaching out to vendor sites at scan time because outbound access may not be available in on-prem deployments."
  );

  script_set_attribute(attribute:"solution",
    value:"Upgrade Pleasant Password Server to the current Stable release (or later).");

  script_set_attribute(attribute:"risk_factor", value:"High");

  script_require_ports("Services/www", 80);
  script_require_ports("Services/www", 443);

  exit(0);
}

include("compat.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

# --- Settings / policy ---
stable_baseline = "9.1.11.0"; # Treat as "Vendor Stable" baseline in feed terms
path = "/Version";

# KB keys
kb_base = "www/pleasant_password_server";
kb_ver  = kb_base + "/build_version";
kb_path = kb_base + "/version_path";
kb_port = kb_base + "/version_port";

# --- Helpers ---
function normalize4(v)
{
  local_var parts, i, out;

  parts = split(v, sep:".");
  out = "";

  for (i = 0; i < 4; i++)
  {
    if (i > 0) out += ".";
    if (i <= max_index(parts)) out += string(int(parts[i]));
    else out += "0";
  }

  return out;
}

function vercmp(a, b)
{
  local_var aa, bb, i, ai, bi;

  a = normalize4(a);
  b = normalize4(b);

  aa = split(a, sep:".");
  bb = split(b, sep:".");

  for (i = 0; i < 4; i++)
  {
    ai = int(aa[i]);
    bi = int(bb[i]);

    if (ai < bi) return -1;
    if (ai > bi) return 1;
  }

  return 0;
}

function looks_like_pleasant(body)
{
  # Fingerprinting approach:
  # - Must contain Build:
  # - Should contain at least one Pleasant-ish marker
  # Keep markers loose to reduce false negatives if branding text changes.

  if (!preg(pattern:"Build:[ ]*[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?", string:body))
    return FALSE;

  if (preg(pattern:"Pleasant", string:body) ||
      preg(pattern:"Password[ ]*Server", string:body) ||
      preg(pattern:"pleasantpassword", string:tolower(body)))
    return TRUE;

  # If we can’t find any product marker, fail safe (avoid false positives).
  return FALSE;
}

# --- KB reuse (if another plugin already found it, or we ran earlier) ---
cached = get_kb_item(kb_ver);
if (!isnull(cached))
{
  installed_ver = cached;
  # If we have a cached version, we can still report outdated without re-fetching evidence.
  if (vercmp(installed_ver, stable_baseline) < 0)
  {
    report = string(
      "Pleasant Password Server appears outdated (below Stable baseline), based on cached KB data.\n",
      "Installed build (KB) : ", normalize4(installed_ver), "\n",
      "Stable baseline      : ", normalize4(stable_baseline), "\n"
    );
    security_message(port:get_http_port(default:80), data:report);
  }
  exit(0);
}

# --- Main ---
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

req = http_get(item:path, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if (isnull(res)) exit(0);

# Basic HTTP sanity
if (!preg(pattern:"^HTTP/1\\.[01] 200", string:res)) exit(0);

p = strstr(res, "\r\n\r\n");
if (!p) exit(0);

body = substr(p, 4);

# Fingerprint before parsing version
if (!looks_like_pleasant(body)) exit(0);

# Accept 3-part or 4-part build strings:
m = eregmatch(pattern:"Build:[ ]*([0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)", string:body);
if (isnull(m)) exit(0);

installed_ver = m[1];

# --- KB cache ---
set_kb_item(name:kb_ver,  value:installed_ver);
set_kb_item(name:kb_path, value:path);
set_kb_item(name:kb_port, value:port);

# --- Compare against Stable baseline ---
if (vercmp(installed_ver, stable_baseline) < 0)
{
  report = string(
    "Pleasant Password Server appears to be outdated (below Stable baseline).\n",
    "Installed build : ", normalize4(installed_ver), "\n",
    "Stable baseline : ", normalize4(stable_baseline), "\n",
    "Evidence (GET ", path, " on port ", port, "):\n",
    chomp(body), "\n"
  );

  security_message(port:port, data:report);
}

exit(0);
