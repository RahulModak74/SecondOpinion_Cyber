create chain_of_attacks
Rohit-Cyber-16gb :) show create table chain_of_attacks;

SHOW CREATE TABLE chain_of_attacks

Query id: 7e5885d0-7072-4f3f-ae09-33991e50ec28

   ┌─statement───────────────────────────────┐
1. │ CREATE TABLE default.chain_of_attacks  ↴│
   │↳(                                      ↴│
   │↳    `chain_id` UInt64,                 ↴│
   │↳    `attack_name` String,              ↴│
   │↳    `attack_description` String,       ↴│
   │↳    `mitre_tactics` Array(String),     ↴│
   │↳    `mitre_techniques` Array(String),  ↴│
   │↳    `severity` String,                 ↴│
   │↳    `first_seen` DateTime,             ↴│
   │↳    `last_seen` DateTime,              ↴│
   │↳    `duration_hours` Float32,          ↴│
   │↳    `affected_hosts` Array(String),    ↴│
   │↳    `affected_users` Array(String),    ↴│
   │↳    `events_summary` String,           ↴│
   │↳    `detection_rules` Array(String),   ↴│
   │↳    `chain_stages` Array(String),      ↴│
   │↳    `stage_descriptions` Array(String),↴│
   │↳    `ioc_hashes` Array(String),        ↴│
   │↳    `ioc_ips` Array(String),           ↴│
   │↳    `ioc_domains` Array(String),       ↴│
   │↳    `ioc_files` Array(String),         ↴│
   │↳    `temp_severity` String DEFAULT ''  ↴│
   │↳)                                      ↴│
   │↳ENGINE = MergeTree                     ↴│
   │↳ORDER BY (chain_id, first_seen)        ↴│
   │↳SETTINGS index_granularity = 8192       │
   └─────────────────────────────────────────┘

1 row in set. Elapsed: 0.002 sec. 

-- Insert into chain_of_attacks using revised severity logic




INSERT INTO chain_of_attacks
SELECT
    cityHash64(concat(toString(OrgId), toString(arrayStringConcat(categories, ',')), toString(arrayStringConcat(techniques, ',')))) AS chain_id,
   
    -- Attack name with revised severity logic
    concat(
        'Potential ',
        -- Apply our new severity logic directly in the name
        if(length(arrayDistinct(mapped_tactics)) >= 3
           OR arrayExists(x -> x IN ('Command and Control', 'Exfiltration', 'Impact'), arrayDistinct(mapped_tactics))
           OR dateDiff('hour', first_seen, last_seen) > 24, 'High Severity ',
           if(length(arrayDistinct(mapped_tactics)) = 2
              OR arrayExists(x -> x IN ('Lateral Movement', 'Privilege Escalation', 'Defense Evasion'), arrayDistinct(mapped_tactics))
              OR dateDiff('hour', first_seen, last_seen) > 1, 'Medium Severity ',
              'Low Severity ')),
        -- Category-based naming remains the same
        if(arrayExists(x -> x LIKE '%Malware%', categories), 'Malware ',
           if(arrayExists(x -> x LIKE '%Phishing%', categories), 'Phishing ',
              if(arrayExists(x -> x LIKE '%Ransomware%', categories), 'Ransomware ', 'Threat '))),
        'Activity'
    ) AS attack_name,
   
    -- Attack description with revised severity indicators
    concat(
        'Multi-stage ',
        if(arrayExists(x -> x LIKE '%Malware%', categories), 'malware ',
           if(arrayExists(x -> x LIKE '%Phishing%', categories), 'phishing ',
              if(arrayExists(x -> x LIKE '%Ransomware%', categories), 'ransomware ', 'security '))),
        'incident involving ',
        toString(event_count),
        ' events across ',
        arrayStringConcat(arrayDistinct(categories), ', '),
        ' categories with ',
        -- Apply same severity logic to description
        if(length(arrayDistinct(mapped_tactics)) >= 3
           OR arrayExists(x -> x IN ('Command and Control', 'Exfiltration', 'Impact'), arrayDistinct(mapped_tactics))
           OR dateDiff('hour', first_seen, last_seen) > 24, 'high severity indicators.',
           if(length(arrayDistinct(mapped_tactics)) = 2
              OR arrayExists(x -> x IN ('Lateral Movement', 'Privilege Escalation', 'Defense Evasion'), arrayDistinct(mapped_tactics))
              OR dateDiff('hour', first_seen, last_seen) > 1, 'medium severity indicators.',
              'low severity indicators.'))
    ) AS attack_description,
   
    -- MITRE tactics and techniques
    arrayDistinct(mapped_tactics) AS mitre_tactics,
    arrayDistinct(techniques) AS mitre_techniques,
   
    -- Severity using our revised logic
    if(length(arrayDistinct(mapped_tactics)) >= 3
       OR arrayExists(x -> x IN ('Command and Control', 'Exfiltration', 'Impact'), arrayDistinct(mapped_tactics))
       OR dateDiff('hour', first_seen, last_seen) > 24, 'High',
       if(length(arrayDistinct(mapped_tactics)) = 2
          OR arrayExists(x -> x IN ('Lateral Movement', 'Privilege Escalation', 'Defense Evasion'), arrayDistinct(mapped_tactics))
          OR dateDiff('hour', first_seen, last_seen) > 1, 'Medium',
          'Low')) AS severity,
   
    -- Timestamps
    first_seen,
    last_seen,
   
    -- Duration in hours
    dateDiff('hour', first_seen, last_seen) AS duration_hours,
   
    -- Affected hosts and users - using placeholder arrays
    ['Unknown Host'] AS affected_hosts,
    ['Unknown User'] AS affected_users,
   
    -- Events summary
    concat(
        'A series of ',
        toString(event_count),
        ' related security events were detected starting with ',
        arrayStringConcat(arrayDistinct(categories), ', '),
        '. Actions observed include ',
        arrayStringConcat(arrayDistinct(actions), ', '),
        '.'
    ) AS events_summary,
   
    -- Detection rules
    arrayMap(x -> concat('Rule_', replaceRegexpAll(x, '[^a-zA-Z0-9]', '_')), arrayDistinct(categories)) AS detection_rules,
   
    -- Chain stages
    arrayDistinct(mapped_tactics) AS chain_stages,
   
    -- Stage descriptions
    arrayMap(tactic ->
        multiIf(
            tactic = 'Initial Access', 'Adversary established initial foothold in the environment',
            tactic = 'Execution', 'Malicious code executed on compromised systems',
            tactic = 'Persistence', 'Adversary established persistence mechanisms',
            tactic = 'Privilege Escalation', 'Adversary gained higher privileges in the system',
            tactic = 'Defense Evasion', 'Attempts to evade detection and security controls',
            tactic = 'Credential Access', 'Attempted theft of credentials or account information',
            tactic = 'Discovery', 'Adversary performed reconnaissance activities',
            tactic = 'Lateral Movement', 'Adversary moved through the environment',
            tactic = 'Collection', 'Data collection prior to exfiltration',
            tactic = 'Exfiltration', 'Data exfiltration detected',
            tactic = 'Impact', 'Systems or data negatively impacted',
            tactic = 'Command and Control', 'Command and control communication detected',
            'Other suspicious activities detected'
        )
    , arrayDistinct(mapped_tactics)) AS stage_descriptions,
   
    -- IOCs - using placeholder arrays
    ['Unknown'] AS ioc_hashes,
    ['0.0.0.0'] AS ioc_ips,
    ['unknown.com'] AS ioc_domains,
    ['unknown.exe'] AS ioc_files,
   
    -- Add temp_severity field matching the main severity
    if(length(arrayDistinct(mapped_tactics)) >= 3
       OR arrayExists(x -> x IN ('Command and Control', 'Exfiltration', 'Impact'), arrayDistinct(mapped_tactics))
       OR dateDiff('hour', first_seen, last_seen) > 24, 'High',
       if(length(arrayDistinct(mapped_tactics)) = 2
          OR arrayExists(x -> x IN ('Lateral Movement', 'Privilege Escalation', 'Defense Evasion'), arrayDistinct(mapped_tactics))
          OR dateDiff('hour', first_seen, last_seen) > 1, 'Medium',
          'Low')) AS temp_severity
FROM enriched_incidents
GROUP BY
    OrgId,
    categories,
    techniques,
    grades,
    actions,
    mapped_tactics,
    first_seen,
    last_seen,
    event_count
HAVING event_count >= 3
ORDER BY event_count DESC, first_seen DESC;



STEP 1- CREATE INTERMEDIATORY TABLES

-- Create incident_groups table
CREATE TABLE IF NOT EXISTS incident_groups (
    IncidentId UInt32,
    OrgId UInt32,
    event_ids Array(UInt64),
    categories Array(String),
    techniques Array(String),
    grades Array(String),
    actions Array(String),
    entity_types Array(String),
    threat_families Array(String),
    resource_types Array(String),
    roles Array(String),
    suspicion_levels Array(String),
    verdicts Array(String),
    first_seen_str String,
    last_seen_str String,
    event_count UInt32
) ENGINE = MergeTree ORDER BY (IncidentId, OrgId);

-- Create time_converted table
CREATE TABLE IF NOT EXISTS time_converted (
    IncidentId UInt32,
    OrgId UInt32,
    event_ids Array(UInt64),
    categories Array(String),
    techniques Array(String),
    grades Array(String),
    actions Array(String),
    entity_types Array(String),
    threat_families Array(String),
    resource_types Array(String),
    roles Array(String),
    suspicion_levels Array(String),
    verdicts Array(String),
    first_seen_str String,
    last_seen_str String,
    first_seen DateTime,
    last_seen DateTime,
    event_count UInt32
) ENGINE = MergeTree ORDER BY (IncidentId, OrgId);

-- Create tactics_mapping table
CREATE TABLE IF NOT EXISTS tactics_mapping (
    IncidentId UInt32,
    OrgId UInt32,
    mapped_tactics Array(String),
    techniques Array(String)
) ENGINE = MergeTree ORDER BY (IncidentId, OrgId);

-- Create enriched_incidents table
CREATE TABLE IF NOT EXISTS enriched_incidents (
    IncidentId UInt32,
    OrgId UInt32,
    event_ids Array(UInt64),
    categories Array(String),
    techniques Array(String),
    grades Array(String),
    actions Array(String),
    entity_types Array(String),
    threat_families Array(String),
    resource_types Array(String),
    roles Array(String),
    suspicion_levels Array(String),
    verdicts Array(String),
    first_seen_str String,
    last_seen_str String,
    first_seen DateTime,
    last_seen DateTime,
    event_count UInt32,
    mapped_tactics Array(String)
) ENGINE = MergeTree ORDER BY (IncidentId, OrgId);




FILL INTERMEDITORY TABLES


-- Fill incident_groups
INSERT INTO incident_groups
SELECT
    IncidentId,
    OrgId,
    groupArray(Id) AS event_ids,
    groupArray(Category) AS categories,
    groupArray(MitreTechniques) AS techniques,
    groupArray(IncidentGrade) AS grades,
    groupArray(ActionGrouped) AS actions,
    groupArray(EntityType) AS entity_types,
    groupArray(ThreatFamily) AS threat_families,
    groupArray(ResourceType) AS resource_types,
    groupArray(Roles) AS roles,
    groupArray(SuspicionLevel) AS suspicion_levels,
    groupArray(LastVerdict) AS verdicts,
    min(Timestamp) AS first_seen_str,
    max(Timestamp) AS last_seen_str,
    count() AS event_count
FROM guide_train
GROUP BY IncidentId, OrgId
HAVING event_count >= 3;

-- Fill time_converted
INSERT INTO time_converted
SELECT
    *,
    toDateTime(first_seen_str) AS first_seen,
    toDateTime(last_seen_str) AS last_seen
FROM incident_groups;

-- Fill tactics_mapping
INSERT INTO tactics_mapping
SELECT
    IncidentId,
    OrgId,
    arrayMap(x ->
        multiIf(
            x LIKE '%T1078%' OR x LIKE '%T1586%', 'Initial Access',
            x LIKE '%T1059%' OR x LIKE '%T1204%', 'Execution',
            x LIKE '%T1053%' OR x LIKE '%T1547%', 'Persistence',
            x LIKE '%T1134%' OR x LIKE '%T1068%', 'Privilege Escalation',
            x LIKE '%T1027%' OR x LIKE '%T1070%', 'Defense Evasion',
            x LIKE '%T1078%' OR x LIKE '%T1550%', 'Credential Access',
            x LIKE '%T1018%' OR x LIKE '%T1082%', 'Discovery',
            x LIKE '%T1021%' OR x LIKE '%T1091%', 'Lateral Movement',
            x LIKE '%T1005%' OR x LIKE '%T1039%', 'Collection',
            x LIKE '%T1567%' OR x LIKE '%T1048%', 'Exfiltration',
            x LIKE '%T1529%' OR x LIKE '%T1486%', 'Impact',
            x LIKE '%T1071%' OR x LIKE '%T1090%', 'Command and Control',
            'Other'
        )
    , techniques) AS mapped_tactics,
    techniques
FROM time_converted;

-- Fill enriched_incidents
INSERT INTO enriched_incidents
SELECT
    tc.*,
    tm.mapped_tactics
FROM time_converted tc
JOIN tactics_mapping tm ON tc.IncidentId = tm.IncidentId AND tc.OrgId = tm.OrgId;
