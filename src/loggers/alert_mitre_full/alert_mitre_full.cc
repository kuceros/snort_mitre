//--------------------------------------------------------------------------
// Copyright (C) 2014-2024 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
// Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
// Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

/* alert_mitre_full
 *
 * Purpose:  output plugin for full MITRE alerting
 *
 * Arguments:  alert file (eventually)
 *
 * Effect:
 *
 * Alerts are written to a file in the snort full alert format
 *
 * Comments:   Allows use of full alerts with other output plugin types
 *
 */

// modified alert_full.cc by Rostislav Kucera <kucera.rosta@gmail.com>, 2024

#include <iostream>
#include <fstream>

#include "detection/ips_context.h"
#include "detection/signature.h"
#include "events/event.h"
#include "framework/logger.h"
#include "framework/module.h"
#include "log/log_text.h"
#include "log/text_log.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "packet_io/sfdaq.h"
#include "protocols/packet.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL TextLog* full_log = nullptr;

#define LOG_BUFFER (4*K_BYTES)

#define S_NAME "alert_mitre_full"
#define F_NAME S_NAME ".txt"

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

struct Mitre{
    string classtype;
    string direction;
    string TActic;
    string Technique;
    string Tname;
    string TA_inb;
    string T_inb;
    string TA_lat;
    string T_lat;
    string TA_out;
    string T_out;
    string msg;
    string reference;
};

static const Parameter s_params[] =
{
    { "mapping", Parameter::PT_STRING, nullptr, "false",
      "csv file of rule-mitre mapping" },

    { "file", Parameter::PT_BOOL, nullptr, "false",
      "output to " F_NAME " instead of stdout" },

    { "limit", Parameter::PT_INT, "0:maxSZ", "0",
      "set maximum size in MB before rollover (0 is unlimited)" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event with full mitre packet dump"

class MitreFullModule : public Module
{
public:
    MitreFullModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;

    Usage get_usage() const override
    { return CONTEXT; }

public:
    bool file = false;
    string mapping = "";
    map<int, Mitre> rules_map;
    size_t limit = 0;
};

bool MitreFullModule::set(const char*, Value& v, SnortConfig*)
{
    if(v.is("mapping"))
        mapping = v.get_string();

    else if ( v.is("file") )
        file = v.get_bool();

    else if ( v.is("limit") )
        limit = v.get_size() * 1024 * 1024;

    return true;
}

bool MitreFullModule::begin(const char*, int, SnortConfig*)
{
    mapping = "";
    file = false;
    limit = 0;
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class MitreFullLogger : public Logger
{
public:
    MitreFullLogger(MitreFullModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;

private:
    string mapping;
    string file;
    unsigned long limit;
    map<int, Mitre> rules_map;
};

MitreFullLogger::MitreFullLogger(MitreFullModule* m) : file(m->file ? F_NAME : "stdout"), limit(m->limit)
{ 
    string file_in = m->mapping; 
    ifstream map_file(file_in);


    // Check if the file is opened successfully
    if (!map_file.is_open()) {
        ErrorMessage("Error opening mapping file");
        return ;
    }

    // Read the file line by line
    string line;
    getline(map_file, line);
    while (getline(map_file, line)) {
        // Create a stringstream from the line
        istringstream ss(line);

        // Define a map to store data for this line

        // Read each column of the line
        string sid;
        string proto, source, src_port, destination, dst_port, classtype, direction, TActic, Technique, Tname, TA_inb, T_inb, TA_lat, T_lat, TA_out, T_out, msg, reference, arrow;
        char comma;

        
        if (getline(ss, sid, ',') && getline(ss, proto, ',') && getline(ss, source, ',') &&  
            getline(ss, src_port, ',') && getline(ss, arrow, ',') && getline(ss, destination, ',') &&
            getline(ss, dst_port, ',') && getline(ss, classtype, ',') && getline(ss, direction, ',') &&
            getline(ss, TActic, ',') && getline(ss, Technique, ',') && getline(ss, Tname, ',') &&
            getline(ss, TA_inb, ',') && getline(ss, T_inb, ',') && getline(ss, TA_lat, ',') &&
            getline(ss, T_lat, ',') && getline(ss, TA_out, ',') && getline(ss, T_out, ',') &&
            getline(ss, msg, ',') && getline(ss, reference)){
            // Store the parsed data into the map
            Mitre mitre_data;
            mitre_data.classtype = classtype;
            mitre_data.direction = direction;
            mitre_data.TActic = TActic;
            mitre_data.Technique = Technique;
            mitre_data.Tname = Tname;
            mitre_data.TA_inb = TA_inb;
            mitre_data.T_inb = T_inb;
            mitre_data.TA_lat = TA_lat;
            mitre_data.T_lat = T_lat;
            mitre_data.TA_out = TA_out;
            mitre_data.T_out = T_out;
            mitre_data.msg = msg;
            mitre_data.reference = reference;
            rules_map[stoi(sid)] = mitre_data;
        }
    }  
    // Close the file
    map_file.close();
}

void MitreFullLogger::open()
{
    full_log = TextLog_Init(file.c_str(), LOG_BUFFER, limit);
}

void MitreFullLogger::close()
{
    if ( full_log )
        TextLog_Term(full_log);
}

void MitreFullLogger::alert(Packet* p, const char* msg, const Event& event)
{

    TextLog_Puts(full_log, "[**] ");

    TextLog_Print(full_log, "[%u:%u:%u] ",
        event.sig_info->gid, event.sig_info->sid, event.sig_info->rev);

    if (p->context->conf->alert_interface())
    {
        const char* iface = SFDAQ::get_input_spec();
        TextLog_Print(full_log, " <%s> ", iface);
    }

    if (msg != nullptr)
    {
        TextLog_Puts(full_log, msg);
        TextLog_Puts(full_log, " [**]\n");
    }
    else
    {
        TextLog_Puts(full_log, "[**]\n");
    }

    if (p->has_ip())
    {
        LogPriorityData(full_log, event);
        TextLog_NewLine(full_log);
        if ( LogAppID(full_log, p) )
            TextLog_NewLine(full_log);
    }

    LogTimeStamp(full_log, p);
    TextLog_Putc(full_log, ' ');

    if (p->has_ip())
    {
        /* print the packet header to the alert file */

        if (p->context->conf->output_datalink())
        {
            Log2ndHeader(full_log, p);
        }

        LogIPHeader(full_log, p);

        /* if this isn't a fragment, print the other header info */
        if (!(p->is_fragment()))
        {
            switch (p->type())
            {
            case PktType::TCP:
                LogTCPHeader(full_log, p);
                break;

            case PktType::UDP:
                LogUDPHeader(full_log, p);
                break;

            case PktType::ICMP:
                LogICMPHeader(full_log, p);
                break;

            default:
                break;
            }
        }
        LogXrefs(full_log, event);
    }
    else
    {
        TextLog_Puts(full_log, "\n");
    }
    
    auto it = rules_map.find(event.sig_info->sid);
    if(it != rules_map.end())
    {
        TextLog_Puts(full_log, "*** MITRE\n");
        if(rules_map[event.sig_info->sid].classtype != "")
            TextLog_Puts(full_log, ("Classtype: " + it->second.classtype + "\n").c_str());
        if(rules_map[event.sig_info->sid].direction != "")
            TextLog_Puts(full_log, ("Direction: " + it->second.direction + "\n").c_str());
        if(rules_map[event.sig_info->sid].TActic != "")
            TextLog_Puts(full_log, ("TActic: " + it->second.TActic + "\n").c_str());
        if(rules_map[event.sig_info->sid].Technique != "")
            TextLog_Puts(full_log, ("Technique: " + it->second.Technique + "\n").c_str());
        if(rules_map[event.sig_info->sid].Tname != "")
            TextLog_Puts(full_log, ("Tname: " + it->second.Tname + "\n").c_str());
        if(rules_map[event.sig_info->sid].TA_inb != "")
            TextLog_Puts(full_log, ("TA_inb: " + it->second.TA_inb + "\n").c_str());
        if(rules_map[event.sig_info->sid].T_inb != "")
            TextLog_Puts(full_log, ("T_inb: " + it->second.T_inb + "\n").c_str());
        if(rules_map[event.sig_info->sid].TA_lat != "")
            TextLog_Puts(full_log, ("TA_lat: " + it->second.TA_lat + "\n").c_str());
        if(rules_map[event.sig_info->sid].T_lat != "")
            TextLog_Puts(full_log, ("T_lat: " + it->second.T_lat + "\n").c_str());
        if(rules_map[event.sig_info->sid].TA_out != "")
            TextLog_Puts(full_log, ("TA_out: " + it->second.TA_out + "\n").c_str());
        if(rules_map[event.sig_info->sid].T_out != "")
            TextLog_Puts(full_log, ("T_out: " + it->second.T_out + "\n").c_str());
        if(rules_map[event.sig_info->sid].reference != "")
            TextLog_Puts(full_log, ("Ref: " + it->second.reference + "\n").c_str());
        
        TextLog_Puts(full_log, "*** END OF MITRE\n");
    }
    TextLog_Puts(full_log, "\n");
    TextLog_Flush(full_log);
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new MitreFullModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* mitre_full_ctor(Module* mod)
{ return new MitreFullLogger((MitreFullModule*)mod); }

static void mitre_full_dtor(Logger* p)
{ delete p; }

static const LogApi mitre_full_api = 
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    mitre_full_ctor,
    mitre_full_dtor
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &mitre_full_api.base,
    nullptr
};

