import os
import json

def build_annotations():
    docs_dir = os.path.join(os.path.dirname(__file__), "..", "data", "evaluation", "documents")
    docs = {}
    for f in os.listdir(docs_dir):
        if f.endswith(".json"):
            with open(os.path.join(docs_dir, f), "r", encoding="utf-8") as fp:
                d = json.load(fp)
                docs[d["source_id"]] = d

    entities_data = [
        # cisa_aa21_356a
        {"id": "eval_prod_apache_log4j", "label": "Product", "name": "Apache Log4j", "aliases": ["Log4j"], "source_id": "cisa_aa21_356a", "mention_text": "Apache Log4j"},
        {"id": "eval_vuln_cve_2021_44228", "label": "Vulnerability", "name": "CVE-2021-44228", "aliases": ["Log4Shell"], "source_id": "cisa_aa21_356a", "mention_text": "CVE-2021-44228"},
        {"id": "eval_malware_cobaltstrike", "label": "Malware", "name": "Cobalt Strike", "aliases": ["Cobalt Strike Beacon"], "source_id": "cisa_aa21_356a", "mention_text": "Cobalt Strike"},
        {"id": "eval_tech_powershell", "label": "Technique", "name": "PowerShell", "aliases": ["PowerShell scripts"], "source_id": "cisa_aa21_356a", "mention_text": "PowerShell"},
        {"id": "eval_os_windows", "label": "OperatingSystem", "name": "Windows", "aliases": ["Windows systems"], "source_id": "cisa_aa21_356a", "mention_text": "Windows"},

        # cisa_aa24_038a
        {"id": "eval_actor_volt_typhoon", "label": "ThreatActor", "name": "Volt Typhoon", "aliases": ["PRC state-sponsored cyber group Volt Typhoon"], "source_id": "cisa_aa24_038a", "mention_text": "Volt Typhoon"},
        {"id": "eval_org_critical_infrastructure", "label": "Organization", "name": "Critical Infrastructure Organizations", "aliases": ["critical infrastructure organizations"], "source_id": "cisa_aa24_038a", "mention_text": "critical infrastructure organizations"},
        {"id": "eval_prod_fortinet_fortios", "label": "Product", "name": "Fortinet FortiOS", "aliases": ["Fortinet FortiOS appliances"], "source_id": "cisa_aa24_038a", "mention_text": "Fortinet FortiOS"},
        {"id": "eval_prod_ivanti_connect_secure", "label": "Product", "name": "Ivanti Connect Secure", "aliases": ["Ivanti Connect Secure gateways"], "source_id": "cisa_aa24_038a", "mention_text": "Ivanti Connect Secure"},
        {"id": "eval_tech_valid_accounts", "label": "Technique", "name": "Valid Accounts", "aliases": ["T1078"], "source_id": "cisa_aa24_038a", "mention_text": "Valid Accounts"},

        # cisa_aa21_116a
        {"id": "eval_actor_apt29", "label": "ThreatActor", "name": "APT29", "aliases": ["Cozy Bear", "SVR"], "source_id": "cisa_aa21_116a", "mention_text": "APT29"},
        {"id": "eval_org_government", "label": "Organization", "name": "Government Organizations", "aliases": ["government, diplomatic, think-tank, and healthcare organizations"], "source_id": "cisa_aa21_116a", "mention_text": "government, diplomatic, think-tank, and healthcare organizations"},
        {"id": "eval_malware_wellmess", "label": "Malware", "name": "WellMess", "aliases": [], "source_id": "cisa_aa21_116a", "mention_text": "WellMess"},
        {"id": "eval_malware_wellmail", "label": "Malware", "name": "WellMail", "aliases": [], "source_id": "cisa_aa21_116a", "mention_text": "WellMail"},
        {"id": "eval_vuln_cve_2019_19781", "label": "Vulnerability", "name": "CVE-2019-19781", "aliases": [], "source_id": "cisa_aa21_116a", "mention_text": "CVE-2019-19781"},
        {"id": "eval_prod_citrix_adc", "label": "Product", "name": "Citrix ADC", "aliases": ["Citrix Application Delivery Controller"], "source_id": "cisa_aa21_116a", "mention_text": "Citrix Application Delivery Controller"},
        {"id": "eval_vuln_cve_2020_0688", "label": "Vulnerability", "name": "CVE-2020-0688", "aliases": [], "source_id": "cisa_aa21_116a", "mention_text": "CVE-2020-0688"},
        {"id": "eval_prod_ms_exchange", "label": "Product", "name": "Microsoft Exchange Server", "aliases": ["Microsoft Exchange"], "source_id": "cisa_aa21_116a", "mention_text": "Microsoft Exchange Server"},

        # cisa_aa22_110a (replaces cisa_aa20_258a)
        {"id": "eval_actor_sandworm", "label": "ThreatActor", "name": "Sandworm Team", "aliases": ["Unit 74455", "GRU Unit 74455"], "source_id": "cisa_aa22_110a", "mention_text": "Sandworm Team"},
        {"id": "eval_malware_blackenergy", "label": "Malware", "name": "BlackEnergy", "aliases": [], "source_id": "cisa_aa22_110a", "mention_text": "BlackEnergy"},
        {"id": "eval_malware_industroyer", "label": "Malware", "name": "Industroyer", "aliases": [], "source_id": "cisa_aa22_110a", "mention_text": "Industroyer"},
        {"id": "eval_malware_notpetya", "label": "Malware", "name": "NotPetya", "aliases": [], "source_id": "cisa_aa22_110a", "mention_text": "NotPetya"},
        {"id": "eval_org_energy_sector", "label": "Organization", "name": "Energy Sector", "aliases": ["Ukrainian power grid"], "source_id": "cisa_aa22_110a", "mention_text": "Ukrainian power grid"},

        # cisa_aa24_060b (replaces cisa_aa24_010a)
        {"id": "eval_vuln_cve_2023_46805", "label": "Vulnerability", "name": "CVE-2023-46805", "aliases": [], "source_id": "cisa_aa24_060b", "mention_text": "CVE-2023-46805"},
        {"id": "eval_vuln_cve_2024_21887", "label": "Vulnerability", "name": "CVE-2024-21887", "aliases": [], "source_id": "cisa_aa24_060b", "mention_text": "CVE-2024-21887"},

        # mitre_g0016_apt29
        {"id": "eval_tech_archive_collected_data", "label": "Technique", "name": "Archive Collected Data", "aliases": ["T1560"], "source_id": "mitre_g0016_apt29", "mention_text": "Archive Collected Data"},

        # mitre_g0034_sandworm
        {"id": "eval_malware_olympic_destroyer", "label": "Malware", "name": "Olympic Destroyer", "aliases": ["S0365"], "source_id": "mitre_g0034_sandworm", "mention_text": "Olympic Destroyer"},
        {"id": "eval_tech_data_destruction", "label": "Technique", "name": "Data Destruction", "aliases": ["T1485"], "source_id": "mitre_g0034_sandworm", "mention_text": "Data Destruction"},
        {"id": "eval_tech_cmd_interpreter", "label": "Technique", "name": "Command and Scripting Interpreter", "aliases": ["T1059"], "source_id": "mitre_g0034_sandworm", "mention_text": "Command and Scripting Interpreter"},
        {"id": "eval_tech_network_dos", "label": "Technique", "name": "Network Denial of Service", "aliases": ["T1498"], "source_id": "mitre_g0034_sandworm", "mention_text": "Network Denial of Service"}
    ]

    for e in entities_data:
        raw = docs[e["source_id"]]["raw_text"]
        idx = raw.find(e["mention_text"])
        if idx == -1:
            raise ValueError(f"Entity mention '{e['mention_text']}' not found in {e['source_id']}")
        e["start_char"] = idx
        e["end_char"] = idx + len(e["mention_text"])
        e["is_synthetic"] = False

    relationships_data = [
        # cisa_aa21_356a
        {
            "id": "eval_rel_01",
            "source_id": "eval_vuln_cve_2021_44228",
            "source_name": "CVE-2021-44228",
            "source_label": "Vulnerability",
            "rel_type": "AFFECTS",
            "target_id": "eval_prod_apache_log4j",
            "target_name": "Apache Log4j",
            "target_label": "Product",
            "document_source_id": "cisa_aa21_356a",
            "verbatim_evidence_quote": "The primary vulnerability, designated as CVE-2021-44228, affects the Apache Log4j Java logging framework.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        # cisa_aa24_038a
        {
            "id": "eval_rel_02",
            "source_id": "eval_actor_volt_typhoon",
            "source_name": "Volt Typhoon",
            "source_label": "ThreatActor",
            "rel_type": "TARGETS",
            "target_id": "eval_org_critical_infrastructure",
            "target_name": "Critical Infrastructure Organizations",
            "target_label": "Organization",
            "document_source_id": "cisa_aa24_038a",
            "verbatim_evidence_quote": "Volt Typhoon targets organizations across the energy, water, telecommunications, and transportation sectors.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_03",
            "source_id": "eval_actor_volt_typhoon",
            "source_name": "Volt Typhoon",
            "source_label": "ThreatActor",
            "rel_type": "TARGETS",
            "target_id": "eval_prod_fortinet_fortios",
            "target_name": "Fortinet FortiOS",
            "target_label": "Product",
            "document_source_id": "cisa_aa24_038a",
            "verbatim_evidence_quote": "To gain initial access, Volt Typhoon exploits known security vulnerabilities in internet-facing network appliances, including Fortinet FortiOS appliances and Ivanti Connect Secure gateways.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_04",
            "source_id": "eval_actor_volt_typhoon",
            "source_name": "Volt Typhoon",
            "source_label": "ThreatActor",
            "rel_type": "TARGETS",
            "target_id": "eval_prod_ivanti_connect_secure",
            "target_name": "Ivanti Connect Secure",
            "target_label": "Product",
            "document_source_id": "cisa_aa24_038a",
            "verbatim_evidence_quote": "To gain initial access, Volt Typhoon exploits known security vulnerabilities in internet-facing network appliances, including Fortinet FortiOS appliances and Ivanti Connect Secure gateways.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_05",
            "source_id": "eval_actor_volt_typhoon",
            "source_name": "Volt Typhoon",
            "source_label": "ThreatActor",
            "rel_type": "USES_TECHNIQUE",
            "target_id": "eval_tech_valid_accounts",
            "target_name": "Valid Accounts",
            "target_label": "Technique",
            "document_source_id": "cisa_aa24_038a",
            "verbatim_evidence_quote": "The actor leverages Valid Accounts to maintain long-term persistent access and evade traditional endpoint security detection.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        # cisa_aa21_116a
        {
            "id": "eval_rel_06",
            "source_id": "eval_actor_apt29",
            "source_name": "APT29",
            "source_label": "ThreatActor",
            "rel_type": "TARGETS",
            "target_id": "eval_org_government",
            "target_name": "Government Organizations",
            "target_label": "Organization",
            "document_source_id": "cisa_aa21_116a",
            "verbatim_evidence_quote": "APT29 targets government, diplomatic, think-tank, and healthcare organizations globally.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_07",
            "source_id": "eval_actor_apt29",
            "source_name": "APT29",
            "source_label": "ThreatActor",
            "rel_type": "USES",
            "target_id": "eval_malware_wellmess",
            "target_name": "WellMess",
            "target_label": "Malware",
            "document_source_id": "cisa_aa21_116a",
            "verbatim_evidence_quote": "In their campaigns, APT29 deployed custom backdoor malware families known as WellMess and WellMail to exfiltrate intelligence and command compromised systems.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_08",
            "source_id": "eval_actor_apt29",
            "source_name": "APT29",
            "source_label": "ThreatActor",
            "rel_type": "USES",
            "target_id": "eval_malware_wellmail",
            "target_name": "WellMail",
            "target_label": "Malware",
            "document_source_id": "cisa_aa21_116a",
            "verbatim_evidence_quote": "In their campaigns, APT29 deployed custom backdoor malware families known as WellMess and WellMail to exfiltrate intelligence and command compromised systems.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_09",
            "source_id": "eval_actor_apt29",
            "source_name": "APT29",
            "source_label": "ThreatActor",
            "rel_type": "EXPLOITS",
            "target_id": "eval_vuln_cve_2019_19781",
            "target_name": "CVE-2019-19781",
            "target_label": "Vulnerability",
            "document_source_id": "cisa_aa21_116a",
            "verbatim_evidence_quote": "The actors gained entry by exploiting external network vulnerabilities, notably CVE-2019-19781 in Citrix Application Delivery Controller and Gateway appliances, as well as CVE-2020-0688 in Microsoft Exchange Server.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_10",
            "source_id": "eval_vuln_cve_2019_19781",
            "source_name": "CVE-2019-19781",
            "source_label": "Vulnerability",
            "rel_type": "AFFECTS",
            "target_id": "eval_prod_citrix_adc",
            "target_name": "Citrix ADC",
            "target_label": "Product",
            "document_source_id": "cisa_aa21_116a",
            "verbatim_evidence_quote": "The actors gained entry by exploiting external network vulnerabilities, notably CVE-2019-19781 in Citrix Application Delivery Controller and Gateway appliances, as well as CVE-2020-0688 in Microsoft Exchange Server.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_11",
            "source_id": "eval_actor_apt29",
            "source_name": "APT29",
            "source_label": "ThreatActor",
            "rel_type": "EXPLOITS",
            "target_id": "eval_vuln_cve_2020_0688",
            "target_name": "CVE-2020-0688",
            "target_label": "Vulnerability",
            "document_source_id": "cisa_aa21_116a",
            "verbatim_evidence_quote": "The actors gained entry by exploiting external network vulnerabilities, notably CVE-2019-19781 in Citrix Application Delivery Controller and Gateway appliances, as well as CVE-2020-0688 in Microsoft Exchange Server.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_12",
            "source_id": "eval_vuln_cve_2020_0688",
            "source_name": "CVE-2020-0688",
            "source_label": "Vulnerability",
            "rel_type": "AFFECTS",
            "target_id": "eval_prod_ms_exchange",
            "target_name": "Microsoft Exchange Server",
            "target_label": "Product",
            "document_source_id": "cisa_aa21_116a",
            "verbatim_evidence_quote": "as well as CVE-2020-0688 in Microsoft Exchange Server.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_13",
            "source_id": "eval_actor_apt29",
            "source_name": "APT29",
            "source_label": "ThreatActor",
            "rel_type": "USES_TECHNIQUE",
            "target_id": "eval_tech_powershell",
            "target_name": "PowerShell",
            "target_label": "Technique",
            "document_source_id": "cisa_aa21_116a",
            "verbatim_evidence_quote": "Following successful exploitation, APT29 uses PowerShell scripts to harvest local credentials and stage encrypted archives for remote exfiltration.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        # cisa_aa22_110a (replaces cisa_aa20_258a)
        {
            "id": "eval_rel_14",
            "source_id": "eval_actor_sandworm",
            "source_name": "Sandworm Team",
            "source_label": "ThreatActor",
            "rel_type": "USES",
            "target_id": "eval_malware_blackenergy",
            "target_name": "BlackEnergy",
            "target_label": "Malware",
            "document_source_id": "cisa_aa22_110a",
            "verbatim_evidence_quote": "In destructive intrusions against the Ukrainian power grid, Sandworm Team used BlackEnergy malware and Industroyer to manipulate electrical substation systems and force power outages.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_15",
            "source_id": "eval_actor_sandworm",
            "source_name": "Sandworm Team",
            "source_label": "ThreatActor",
            "rel_type": "USES",
            "target_id": "eval_malware_industroyer",
            "target_name": "Industroyer",
            "target_label": "Malware",
            "document_source_id": "cisa_aa22_110a",
            "verbatim_evidence_quote": "In destructive intrusions against the Ukrainian power grid, Sandworm Team used BlackEnergy malware and Industroyer to manipulate electrical substation systems and force power outages.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_16",
            "source_id": "eval_actor_sandworm",
            "source_name": "Sandworm Team",
            "source_label": "ThreatActor",
            "rel_type": "USES",
            "target_id": "eval_malware_olympic_destroyer",
            "target_name": "Olympic Destroyer",
            "target_label": "Malware",
            "document_source_id": "mitre_g0034_sandworm",
            "verbatim_evidence_quote": "Sandworm Team deployed the destructive wiper malware Olympic Destroyer to disrupt the 2018 Winter Olympic Games.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_17",
            "source_id": "eval_actor_sandworm",
            "source_name": "Sandworm Team",
            "source_label": "ThreatActor",
            "rel_type": "USES",
            "target_id": "eval_malware_notpetya",
            "target_name": "NotPetya",
            "target_label": "Malware",
            "document_source_id": "cisa_aa22_110a",
            "verbatim_evidence_quote": "Sandworm Team also developed and distributed the NotPetya ransomware to cause global operational paralysis across multinational shipping and logistics enterprises.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_18",
            "source_id": "eval_actor_sandworm",
            "source_name": "Sandworm Team",
            "source_label": "ThreatActor",
            "rel_type": "TARGETS",
            "target_id": "eval_org_energy_sector",
            "target_name": "Energy Sector",
            "target_label": "Organization",
            "document_source_id": "cisa_aa22_110a",
            "verbatim_evidence_quote": "In destructive intrusions against the Ukrainian power grid, Sandworm Team used BlackEnergy malware and Industroyer to manipulate electrical substation systems and force power outages.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        # cisa_aa24_060b (replaces cisa_aa24_010a)
        {
            "id": "eval_rel_19",
            "source_id": "eval_vuln_cve_2023_46805",
            "source_name": "CVE-2023-46805",
            "source_label": "Vulnerability",
            "rel_type": "AFFECTS",
            "target_id": "eval_prod_ivanti_connect_secure",
            "target_name": "Ivanti Connect Secure",
            "target_label": "Product",
            "document_source_id": "cisa_aa24_060b",
            "verbatim_evidence_quote": "The first flaw, CVE-2023-46805, is an authentication bypass vulnerability affecting web components of Ivanti Connect Secure.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_20",
            "source_id": "eval_vuln_cve_2024_21887",
            "source_name": "CVE-2024-21887",
            "source_label": "Vulnerability",
            "rel_type": "AFFECTS",
            "target_id": "eval_prod_ivanti_connect_secure",
            "target_name": "Ivanti Connect Secure",
            "target_label": "Product",
            "document_source_id": "cisa_aa24_060b",
            "verbatim_evidence_quote": "The second flaw, CVE-2024-21887, is a command injection vulnerability in the management interface of Ivanti Connect Secure that allows authenticated administrators to send crafted requests and execute arbitrary commands.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        # mitre_g0016_apt29
        {
            "id": "eval_rel_21",
            "source_id": "eval_actor_apt29",
            "source_name": "APT29",
            "source_label": "ThreatActor",
            "rel_type": "USES_TECHNIQUE",
            "target_id": "eval_tech_archive_collected_data",
            "target_name": "Archive Collected Data",
            "target_label": "Technique",
            "document_source_id": "mitre_g0016_apt29",
            "verbatim_evidence_quote": "Before exfiltrating stolen intelligence, APT29 uses Archive Collected Data by compressing sensitive documents into password-protected ZIP and RAR archives to conceal data transfers from network inspection controls.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_22",
            "source_id": "eval_actor_apt29",
            "source_name": "APT29",
            "source_label": "ThreatActor",
            "rel_type": "USES_TECHNIQUE",
            "target_id": "eval_tech_valid_accounts",
            "target_name": "Valid Accounts",
            "target_label": "Technique",
            "document_source_id": "mitre_g0016_apt29",
            "verbatim_evidence_quote": "To establish and maintain access to enterprise victim environments, APT29 uses Valid Accounts, obtaining legitimate user and administrative credentials to log into cloud and on-premises infrastructure undetected.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        # mitre_g0034_sandworm
        {
            "id": "eval_rel_23",
            "source_id": "eval_actor_sandworm",
            "source_name": "Sandworm Team",
            "source_label": "ThreatActor",
            "rel_type": "USES_TECHNIQUE",
            "target_id": "eval_tech_data_destruction",
            "target_name": "Data Destruction",
            "target_label": "Technique",
            "document_source_id": "mitre_g0034_sandworm",
            "verbatim_evidence_quote": "In observed disruptive campaigns, Sandworm Team conducts Data Destruction by deploying custom wipers designed to overwrite master boot records, wipe disk partitions, and render operational computer systems permanently unrecoverable.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_24",
            "source_id": "eval_actor_sandworm",
            "source_name": "Sandworm Team",
            "source_label": "ThreatActor",
            "rel_type": "USES_TECHNIQUE",
            "target_id": "eval_tech_cmd_interpreter",
            "target_name": "Command and Scripting Interpreter",
            "target_label": "Technique",
            "document_source_id": "mitre_g0034_sandworm",
            "verbatim_evidence_quote": "Sandworm Team uses Command and Scripting Interpreter components, including Unix shells and Windows script hosts, to stage malware execution and coordinate rapid malware propagation.",
            "confidence": 1.0,
            "is_synthetic": False
        },
        {
            "id": "eval_rel_25",
            "source_id": "eval_actor_sandworm",
            "source_name": "Sandworm Team",
            "source_label": "ThreatActor",
            "rel_type": "USES_TECHNIQUE",
            "target_id": "eval_tech_network_dos",
            "target_name": "Network Denial of Service",
            "target_label": "Technique",
            "document_source_id": "mitre_g0034_sandworm",
            "verbatim_evidence_quote": "The group also performs Network Denial of Service attacks against target telecommunication providers and government portals to disrupt communication channels during kinetic operations.",
            "confidence": 1.0,
            "is_synthetic": False
        }
    ]

    for r in relationships_data:
        raw = docs[r["document_source_id"]]["raw_text"]
        idx = raw.find(r["verbatim_evidence_quote"])
        if idx == -1:
            raise ValueError(f"Relationship quote '{r['verbatim_evidence_quote']}' not found in {r['document_source_id']}")
        r["char_start"] = idx
        r["char_end"] = idx + len(r["verbatim_evidence_quote"])

    ann_dir = os.path.join(os.path.dirname(__file__), "..", "data", "evaluation", "annotations")
    os.makedirs(ann_dir, exist_ok=True)

    with open(os.path.join(ann_dir, "entities.json"), "w", encoding="utf-8") as fp:
        json.dump({"total_entities": len(entities_data), "entities": entities_data}, fp, indent=2)

    with open(os.path.join(ann_dir, "relationships.json"), "w", encoding="utf-8") as fp:
        json.dump({"total_relationships": len(relationships_data), "relationships": relationships_data}, fp, indent=2)

    print(f"SUCCESS: Built annotations: {len(entities_data)} entities, {len(relationships_data)} relationships.")

if __name__ == "__main__":
    build_annotations()
