﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PDFILE
{
    internal class Report
    {
        public string Title { get; set; }
        public string? Synopsis { get; set; }
        public string? Description { get; set; }
        public string? See_Also { get; set; }
        public string? Solution { get; set; }
        public string? Risk_Factor { get; set; }
        public string? CVSS_Base_Score { get; set; }
        public string? CVSS_V30_Base_Score { get; set; }
        public string? CVSS_Temporal_Score { get; set; }
        public string? CVSS_V30_Temporal_Score { get; set; }
        public string? Plugin_Information { get; set; }
        public string? Plugin_Output { get; set; }
        public string? References { get; set; }
        public string? STIG_Severity { get; set; }
    }
}