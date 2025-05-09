Rohit-Cyber-16gb :) show create table guide_train;

SHOW CREATE TABLE guide_train

Query id: 1ec4a92c-4b7b-410c-a80e-51b41f9f31c2

   ┌─statement───────────────────────────────┐
1. │ CREATE TABLE default.guide_train       ↴│
   │↳(                                      ↴│
   │↳    `Id` UInt64,                       ↴│
   │↳    `OrgId` UInt32,                    ↴│
   │↳    `IncidentId` UInt32,               ↴│
   │↳    `AlertId` UInt32,                  ↴│
   │↳    `Timestamp` String,                ↴│
   │↳    `DetectorId` UInt32,               ↴│
   │↳    `AlertTitle` UInt32,               ↴│
   │↳    `Category` String,                 ↴│
   │↳    `MitreTechniques` String,          ↴│
   │↳    `IncidentGrade` String,            ↴│
   │↳    `ActionGrouped` String,            ↴│
   │↳    `ActionGranular` String,           ↴│
   │↳    `EntityType` String,               ↴│
   │↳    `EvidenceRole` String,             ↴│
   │↳    `DeviceId` UInt32,                 ↴│
   │↳    `Sha256` UInt32,                   ↴│
   │↳    `IpAddress` UInt32,                ↴│
   │↳    `Url` UInt32,                      ↴│
   │↳    `AccountSid` UInt32,               ↴│
   │↳    `AccountUpn` UInt32,               ↴│
   │↳    `AccountObjectId` UInt32,          ↴│
   │↳    `AccountName` UInt32,              ↴│
   │↳    `DeviceName` UInt32,               ↴│
   │↳    `NetworkMessageId` UInt32,         ↴│
   │↳    `EmailClusterId` Nullable(Float64),↴│
   │↳    `RegistryKey` UInt32,              ↴│
   │↳    `RegistryValueName` UInt32,        ↴│
   │↳    `RegistryValueData` UInt32,        ↴│
   │↳    `ApplicationId` UInt32,            ↴│
   │↳    `ApplicationName` UInt32,          ↴│
   │↳    `OAuthApplicationId` UInt32,       ↴│
   │↳    `ThreatFamily` String,             ↴│
   │↳    `FileName` UInt32,                 ↴│
   │↳    `FolderPath` UInt32,               ↴│
   │↳    `ResourceIdName` UInt32,           ↴│
   │↳    `ResourceType` String,             ↴│
   │↳    `Roles` String,                    ↴│
   │↳    `OSFamily` UInt32,                 ↴│
   │↳    `OSVersion` UInt32,                ↴│
   │↳    `AntispamDirection` String,        ↴│
   │↳    `SuspicionLevel` String,           ↴│
   │↳    `LastVerdict` String,              ↴│
   │↳    `CountryCode` UInt32,              ↴│
   │↳    `State` UInt32,                    ↴│
   │↳    `City` UInt32                      ↴│
   │↳)                                      ↴│
   │↳ENGINE = MergeTree                     ↴│
   │↳ORDER BY (Id, Category)                ↴│
   │↳SETTINGS index_granularity = 8192       │
   └─────────────────────────────────────────┘
