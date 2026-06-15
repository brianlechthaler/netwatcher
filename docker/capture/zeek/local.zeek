# NetWatcher site policy - JSON logging for all default logs
@load policy/tuning/defaults
@load policy/protocols/conn/known-hosts

redef LogAscii::use_json = T;
redef Log::default_rotation_interval = 1day;

# Enable additional protocol analyzers useful for threat hunting
@load protocols/dns
@load protocols/http
@load protocols/ssl
@load protocols/ftp
@load protocols/smtp
@load protocols/ssh
@load protocols/rdp

# Notice framework for anomaly detection
@load frameworks/notice

module NetWatcher;

export {
    redef Notice::policy_hooks += {
        ["NetWatcher::tag"] = function(n: notice::Info): string
            {
            return fmt("netwatcher");
            }
    };
}
