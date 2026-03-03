"""
Scenarios
---------
Pre-built network topologies to run games on.
Each returns a Network ready to plug into the SimulationEngine.
"""

from env.network import (
    Network, Node, Edge, NodeType, NodeState, Team,
    Service, Vulnerability
)


def _svc(name, port, version="1.0", running=True) -> Service:
    return Service(name=name, port=port, version=version, running=running)

def _vuln(cve, cvss, service) -> Vulnerability:
    return Vulnerability(cve_id=cve, cvss=cvss, service=service)


# ---------------------------------------------------------------------------
# Scenario 1: Small Corporate Network
# ---------------------------------------------------------------------------

def corporate_network() -> tuple[Network, str]:
    """
    Classic attacker-enters-via-DMZ scenario.
    Topology:
        internet → dmz_web → internal_router → [workstation1, workstation2, db_server]
        internal_router → file_server
    Red starts at 'internet' node.
    """
    net = Network(name="Corporate Network")

    nodes = [
        Node("internet",   "Internet",        NodeType.ROUTER,
             services=[_svc("http", 80)],
             vulnerabilities=[],
             value=0,
             state=NodeState(owner=Team.RED, compromised=True)),  # red's entry point

        Node("dmz_web",    "DMZ Web Server",  NodeType.DMZ,
             services=[_svc("http", 80), _svc("https", 443), _svc("ssh", 22)],
             vulnerabilities=[
                 _vuln("CVE-2021-44228", 10.0, "http"),   # Log4Shell
                 _vuln("CVE-2022-1388",   9.8, "http"),
             ],
             value=3),

        Node("dmz_mail",   "DMZ Mail Server", NodeType.DMZ,
             services=[_svc("smtp", 25), _svc("imap", 143)],
             vulnerabilities=[
                 _vuln("CVE-2021-34527", 8.8, "smtp"),    # PrintNightmare (illustrative)
             ],
             value=2),

        Node("fw_internal","Internal Firewall",NodeType.FIREWALL,
             services=[],
             vulnerabilities=[
                 _vuln("CVE-2022-0778", 7.5, "tls"),
             ],
             value=4),

        Node("workstation1","HR Workstation",  NodeType.WORKSTATION,
             services=[_svc("rdp", 3389), _svc("smb", 445)],
             vulnerabilities=[
                 _vuln("CVE-2017-0144", 9.3, "smb"),      # EternalBlue
             ],
             value=2),

        Node("workstation2","Dev Workstation", NodeType.WORKSTATION,
             services=[_svc("ssh", 22), _svc("http", 8080)],
             vulnerabilities=[
                 _vuln("CVE-2021-3156", 7.8, "sudo"),     # Sudo Baron Samedit
             ],
             value=3),

        Node("db_server",  "Database Server",  NodeType.DATABASE,
             services=[_svc("mysql", 3306), _svc("ssh", 22)],
             vulnerabilities=[
                 _vuln("CVE-2022-21699", 8.0, "mysql"),
             ],
             value=8),          # crown jewel

        Node("file_server","File Server",      NodeType.SERVER,
             services=[_svc("smb", 445), _svc("ftp", 21)],
             vulnerabilities=[
                 _vuln("CVE-2021-26084", 9.8, "smb"),
             ],
             value=5),

        Node("ad_server",  "Active Directory", NodeType.SERVER,
             services=[_svc("ldap", 389), _svc("kerberos", 88)],
             vulnerabilities=[
                 _vuln("CVE-2021-42278", 8.8, "kerberos"), # noPac
                 _vuln("CVE-2020-1472",  10.0,"netlogon"),  # Zerologon
             ],
             value=10,          # ultimate prize
             state=NodeState(patch_level=1)),
    ]

    edges = [
        Edge("internet",    "dmz_web",     bandwidth=1000),
        Edge("internet",    "dmz_mail",    bandwidth=1000),
        Edge("dmz_web",     "fw_internal", bandwidth=100),
        Edge("dmz_mail",    "fw_internal", bandwidth=100),
        Edge("fw_internal", "workstation1",bandwidth=100, monitored=True),
        Edge("fw_internal", "workstation2",bandwidth=100),
        Edge("fw_internal", "db_server",   bandwidth=100, monitored=True),
        Edge("fw_internal", "file_server", bandwidth=100),
        Edge("workstation1","db_server",   bandwidth=100),
        Edge("workstation2","db_server",   bandwidth=100),
        Edge("workstation2","ad_server",   bandwidth=100),
        Edge("file_server", "ad_server",   bandwidth=100),
        Edge("db_server",   "ad_server",   bandwidth=100),
    ]

    for n in nodes:
        net.add_node(n)
    for e in edges:
        net.add_edge(e)

    return net, "internet"   # start_node for red


# ---------------------------------------------------------------------------
# Scenario 2: Industrial Control System (ICS/OT)
# ---------------------------------------------------------------------------

def ics_network() -> tuple[Network, str]:
    """
    IT/OT convergence scenario. Red tries to reach PLCs.
    """
    net = Network(name="ICS/OT Network")

    nodes = [
        Node("corp_laptop",  "Corp Laptop",      NodeType.WORKSTATION,
             services=[_svc("rdp", 3389)],
             vulnerabilities=[_vuln("CVE-2021-34527", 7.8, "rdp")],
             value=1,
             state=NodeState(owner=Team.RED, compromised=True)),

        Node("it_server",    "IT Jump Server",   NodeType.SERVER,
             services=[_svc("ssh", 22), _svc("rdp", 3389)],
             vulnerabilities=[_vuln("CVE-2019-0708", 9.8, "rdp")],  # BlueKeep
             value=3),

        Node("historian",    "Data Historian",   NodeType.SERVER,
             services=[_svc("opc-ua", 4840)],
             vulnerabilities=[_vuln("CVE-2022-34870", 8.5, "opc-ua")],
             value=6),

        Node("hmi",          "HMI Workstation",  NodeType.WORKSTATION,
             services=[_svc("vnc", 5900)],
             vulnerabilities=[_vuln("CVE-2021-44228", 9.0, "vnc")],
             value=7),

        Node("plc_pump",     "Pump PLC",         NodeType.SERVER,
             services=[_svc("modbus", 502)],
             vulnerabilities=[_vuln("CVE-2020-25159", 9.8, "modbus")],
             value=10),

        Node("plc_valve",    "Valve PLC",        NodeType.SERVER,
             services=[_svc("modbus", 502)],
             vulnerabilities=[_vuln("CVE-2020-25159", 9.8, "modbus")],
             value=10),

        Node("dmz_firewall", "IT/OT Firewall",   NodeType.FIREWALL,
             services=[],
             vulnerabilities=[_vuln("CVE-2022-0778", 6.5, "tls")],
             value=5, state=NodeState(patch_level=2)),
    ]

    edges = [
        Edge("corp_laptop",  "it_server",    bandwidth=100),
        Edge("it_server",    "historian",    bandwidth=100),
        Edge("it_server",    "dmz_firewall", bandwidth=100),
        Edge("dmz_firewall", "hmi",          bandwidth=10, monitored=True),
        Edge("hmi",          "plc_pump",     bandwidth=10),
        Edge("hmi",          "plc_valve",    bandwidth=10),
        Edge("historian",    "dmz_firewall", bandwidth=100),
    ]

    for n in nodes:
        net.add_node(n)
    for e in edges:
        net.add_edge(e)

    return net, "corp_laptop"


# ---------------------------------------------------------------------------
# Scenario 3: Cloud Tenant Attack
# ---------------------------------------------------------------------------



def cloud_network() -> tuple[Network, str]:
    """
    Attacker compromises a public-facing lambda/container,
    tries to reach S3 buckets and RDS.
    """
    net = Network(name="Cloud Tenant")

    nodes = [
        Node("public_api",  "Public API Gateway", NodeType.DMZ,
             services=[_svc("https", 443)],
             vulnerabilities=[
                 _vuln("CVE-2022-1388", 9.8, "api"),
                 _vuln("CVE-2021-44228", 10.0, "http"),
             ],
             value=2,
             state=NodeState(owner=Team.RED, compromised=True)),

        Node("lambda_fn",   "Lambda Function",    NodeType.SERVER,
             services=[_svc("https", 443)],
             vulnerabilities=[_vuln("CVE-2021-3156", 7.8, "runtime")],
             value=3),

        Node("ec2_app",     "EC2 App Server",     NodeType.SERVER,
             services=[_svc("ssh", 22), _svc("http", 8080)],
             vulnerabilities=[
                 _vuln("CVE-2022-0847", 7.8, "linux"),   # Dirty Pipe
             ],
             value=4),

        Node("rds_db",      "RDS Database",       NodeType.DATABASE,
             services=[_svc("postgres", 5432)],
             vulnerabilities=[_vuln("CVE-2022-21699", 7.5, "db")],
             value=9),

        Node("s3_bucket",   "S3 Data Bucket",     NodeType.DATABASE,
             services=[_svc("https", 443)],
             vulnerabilities=[],
             value=8),

        Node("iam_role",    "IAM / Secrets Mgr",  NodeType.SERVER,
             services=[_svc("https", 443)],
             vulnerabilities=[_vuln("CVE-2022-25897", 8.8, "iam")],
             value=10),

        Node("vpc_endpoint","VPC Private Endpoint",NodeType.ROUTER,
             services=[],
             vulnerabilities=[],
             value=2, state=NodeState(patch_level=3)),
    ]

    edges = [
        Edge("public_api",  "lambda_fn",   bandwidth=1000),
        Edge("public_api",  "ec2_app",     bandwidth=1000),
        Edge("lambda_fn",   "rds_db",      bandwidth=100, monitored=True),
        Edge("lambda_fn",   "vpc_endpoint",bandwidth=100),
        Edge("ec2_app",     "rds_db",      bandwidth=100),
        Edge("ec2_app",     "iam_role",    bandwidth=100),
        Edge("vpc_endpoint","s3_bucket",   bandwidth=1000),
        Edge("vpc_endpoint","iam_role",    bandwidth=100, monitored=True),
        Edge("iam_role",    "s3_bucket",   bandwidth=1000),
    ]

    for n in nodes:
        net.add_node(n)
    for e in edges:
        net.add_edge(e)

    return net, "public_api"


# ---------------------------------------------------------------------------
# Scenario 4: Government / Defense SCIF Network
# ---------------------------------------------------------------------------

def govdef_network() -> tuple[Network, str]:
    """
    Classified enclave attack scenario modelled on US DoD network architecture.

    Red starts at a compromised unclassified contractor workstation (spearphish
    entry via Follina / Office RCE) and must cross the Cross-Domain Solution
    (CDS) boundary from NIPRNET into SIPRNET, then pivot deeper toward
    mission-critical and SCIF-level crown jewels.

    Topology:
        unclass_ws → nipr_server → cross_domain → sipr_gateway
        sipr_gateway → intel_db
        sipr_gateway → mission_sys → scif_terminal
        sipr_gateway → comms_node

    Win conditions (for Red):
        - Exfiltrate from intel_db (value=8) for large score
        - Compromise mission_sys (value=10) or scif_terminal (value=10)
    """
    net = Network(name="Government/Defense SCIF Network")

    nodes = [
        # ── Unclassified side (NIPRNET-equivalent) ────────────────────────
        Node("unclass_ws",   "Contractor Workstation", NodeType.WORKSTATION,
             services=[_svc("rdp", 3389), _svc("smb", 445)],
             vulnerabilities=[
                 _vuln("CVE-2022-30190", 7.8, "msdt"),   # Follina / Office RCE
             ],
             value=1,
             state=NodeState(owner=Team.RED, compromised=True)),  # spearphish entry

        Node("nipr_server",  "NIPRNET App Server",     NodeType.SERVER,
             services=[_svc("http", 80), _svc("https", 443), _svc("ssh", 22)],
             vulnerabilities=[
                 _vuln("CVE-2021-44228", 10.0, "http"),   # Log4Shell
                 _vuln("CVE-2022-41082",  8.8, "https"),  # ProxyNotShell (Exchange)
             ],
             value=3),

        # ── Cross-Domain Solution / Guard (the hardened boundary) ─────────
        Node("cross_domain", "Cross-Domain Solution",  NodeType.FIREWALL,
             services=[_svc("https", 8443)],
             vulnerabilities=[
                 _vuln("CVE-2023-4966", 9.4, "https"),    # Citrix Bleed (NetScaler)
                 _vuln("CVE-2023-20198", 10.0, "https"),  # Cisco IOS XE auth bypass
             ],
             value=6,
             state=NodeState(patch_level=2)),  # hardened boundary device

        # ── Classified side (SIPRNET-equivalent) ─────────────────────────
        Node("sipr_gateway", "SIPRNET Gateway",        NodeType.ROUTER,
             services=[_svc("https", 443)],
             vulnerabilities=[
                 _vuln("CVE-2023-35078", 10.0, "api"),    # Ivanti MDM unauthenticated RCE
             ],
             value=5),

        Node("intel_db",     "Intelligence Database",  NodeType.DATABASE,
             services=[_svc("postgres", 5432), _svc("ssh", 22)],
             vulnerabilities=[
                 _vuln("CVE-2021-21985", 9.8, "vmware"),  # VMware vCenter RCE
             ],
             value=8),

        # ── Mission-critical systems ───────────────────────────────────────
        Node("mission_sys",  "Mission Planning System", NodeType.SERVER,
             services=[_svc("https", 443), _svc("ssh", 22)],
             vulnerabilities=[
                 _vuln("CVE-2022-26134", 9.8, "confluence"),  # Confluence OGNL RCE
             ],
             value=10,
             state=NodeState(patch_level=1)),

        Node("scif_terminal","SCIF Workstation",        NodeType.WORKSTATION,
             services=[_svc("rdp", 3389)],
             vulnerabilities=[
                 _vuln("CVE-2021-3156", 7.8, "sudo"),     # Sudo Baron Samedit
             ],
             value=10,
             state=NodeState(patch_level=2)),              # hardened end-point

        # ── Encrypted comms node (lateral pivot route) ────────────────────
        Node("comms_node",   "Encrypted Comms Router",  NodeType.SERVER,
             services=[_svc("ssh", 22), _svc("https", 8443)],
             vulnerabilities=[
                 _vuln("CVE-2022-0778", 7.5, "openssl"),  # OpenSSL infinite loop
             ],
             value=4),
    ]

    edges = [
        # Unclassified network
        Edge("unclass_ws",   "nipr_server",   bandwidth=100),
        # NIPR → CDS boundary (monitored — Blue watches traffic crossing)
        Edge("nipr_server",  "cross_domain",  bandwidth=100, monitored=True),
        # CDS → SIPR (heavily monitored — any crossing raises immediate alerts)
        Edge("cross_domain", "sipr_gateway",  bandwidth=10,  monitored=True),
        # SIPR internal (monitored near crown jewels)
        Edge("sipr_gateway", "intel_db",      bandwidth=100, monitored=True),
        Edge("sipr_gateway", "mission_sys",   bandwidth=100, monitored=True),
        Edge("sipr_gateway", "comms_node",    bandwidth=100),
        # Deep classified links
        Edge("mission_sys",  "scif_terminal", bandwidth=10,  monitored=True),
        Edge("comms_node",   "mission_sys",   bandwidth=10),
    ]

    for n in nodes:
        net.add_node(n)
    for e in edges:
        net.add_edge(e)

    return net, "unclass_ws"
