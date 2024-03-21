# RULE-MITRE output SNORT 3 loggers

This repository contains 3 additional Snort 3 output modules for rule-MITRE mapping. Each module reads CSV rule-mitre mapping file and integrate these mappings to Snort detection output.

## 

The Snort 3 installation is needed for running the plugins. For installation, you need to download and copy these files to snort3_extra folder and run:

    ./configure_cmake.sh
    cd build
    make
    make install

And modify 'snort.lua' configuration file. Examples:

    alert_mitre_json = { 
      file = true,
      mapping = "<your_path>/rules_parsed.csv",
      fields = "timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action classtype direction TActic Technique Tname TA_inb T_inb TA_lat T_lat TA_out T_out msg reference"
    }
    
    alert_mitre_csv = { 
      file = true,
      mapping = "<your_path>/rules_parsed.csv",
      fields = "timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action classtype direction TActic Technique Tname TA_inb T_inb TA_lat T_lat TA_out T_out msg reference"
    }

    alert_mitre_full = { 
      file = true,
      mapping = "<your_path>/rules_parsed.csv"
    }
