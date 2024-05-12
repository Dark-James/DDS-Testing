if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999999");
  script_version("2023-10-24T05:06:28+0000");
  script_tag(name:"last_modification", value:"2023-10-24 05:06:28 +0000 (Tue, 24 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-06-17 16:27:41 +0200 (Mon, 17 Jun 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DDS Test");

  script_category(ACT_GATHER_INFO);

  script_copyright("Andrew");
  script_family("Tester");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("RTPS", 7400);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"DDS Test");

  script_xref(name:"URL", value:"https://www.xxx.com/");

  exit(0);
}

include("/var/lib/openvas/plugins/misc_func.inc");
include("/var/lib/openvas/plugins/global_settings.inc");

# Define the Python script command
command = "/usr/bin/env python3";
argv = make_list("/home/kali/Documents/Uni-DDS/py-read-pkt-test.py");

# Execute the Python script and capture the output
result = pread(cmd: command, argv: argv);

# Debugging output
display("Output from Python script: ", result);

if (strstr(result, "Response from DDS") != NULL) {
    security_message(port: 7400, data: "DDS Vulnerability detected");
}