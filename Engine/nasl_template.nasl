#
#CWE <CWE_id> Script
#

if(description)
{
  script_id(<CWE_id>);
  script_version("");

  script_name(english:"<CWE_name>");

  script_set_attribute(attribute:"synopsis", value:"");
  script_set_attribute(attribute:"description",value:"");
  script_set_attribute(attribute:"solution", value:"");
  script_set_attribute(attribute:"risk_factor", value:"");


  script_set_attribute(attribute:"plugin_publication_date", value: "");
  script_set_attribute(attribute:"plugin_type", value: "");
  script_set_attribute(attribute:"plugin_ref", value: "");
  script_set_attribute(attribute:"cwss", value: "");
  script_set_attribute(attribute:"location", value: "");

  script_end_attributes();

  script_summary(english: "");
  script_category(ACT_ATTACK);

  script_copyright(english: "Copyright(c) 2023");
  script_family(english: "CGI abuses");

  script_timeout();

  exit(0);
}

# Attack code



# End of attack code