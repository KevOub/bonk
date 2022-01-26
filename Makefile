
build:
	go build bonk.go && echo "" > /var/log/audit/audit.log && systemctl start auditd && ./bonk