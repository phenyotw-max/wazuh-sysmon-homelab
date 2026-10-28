<group name="windows,windows_security,account_changed,adduser">

  <rule id="100200" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4722$</field>
    <field name="win.eventdata.targetUserName">^Guest$</field>

    <description>MYDFIR-Steven Windows Guest account was enabled.</description>

    <mitre>
      <id>T1078</id>
    </mitre>

    <group>
      windows,
      windows_account_management,
      account_enabled,
      guest_account,
    </group>
  </rule>

</group>

<group name="local,syslog,sshd,authentication_failed,">
  <rule id="100101" level="10" frequency="3" timeframe="120">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />
    <description>Multiple SSH login failures observed from the same source IP</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,ssh_bruteforce,credential_access,</group>
  </rule>
</group>

<group name="local,custom_detections,">

  <!-- Rule 1: Detect PowerShell execution on Windows (Sysmon Event ID 1) -->
  <rule id="100001" level="7">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe</field>
    <description>Custom Rule: PowerShell Process Spawned on $(win.system.computer)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <!-- Rule 2: High Alert for Repeated SSH Failures on Linux -->
  <rule id="100002" level="10" frequency="4" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>Custom Rule: Possible SSH Brute Force Attack Detected from $(srcip)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

</group>