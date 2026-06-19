## NetWatcher site policy — JSON logs for the analysis pipeline

redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1day;

@load tuning/defaults
@load protocols/conn/known-hosts

## MITRE ATT&CK detections via BZAR (SMB/DCE-RPC analytics)
@load site/bzar
