Return-Path: <kasan-dev+bncBDN7L7O25EIBBM42SKNQMGQEW7FCG3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EEDF1618F4D
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 04:55:31 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id l42-20020a05600c1d2a00b003cf8e70c1ecsf90052wms.4
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 20:55:31 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DJ1A+hRhaHrRM1KdbAcSrKXb8ruj6vVJE+qJv8sz3OI=;
        b=KPyynzrUMmFbVl62UpfvyjJ43op/Zojf5ssbIGCcwB+hac5EPPURIv1BpuFTE+vvNk
         AGLZjLHo/YT0H/DejMafS/X3t+RIhYYdxCpB9QfeQYI6lJiNtgN94tnh0LPai0A9xM35
         tcGmvqRGbmfKXX+kSSk26BmwL24sn49dBwQ9CjVnJHVnLG7eTNsJ26hv5KPZ2kr2o5Hm
         dlMy9SxKtfA5lzFUFH/IOG7W7qf1hkpxtM501xxMGt0P5VpCyw8mSnijY6U+wn7scc5k
         T5kcRK9eKHOOi05D5tUoMNqpYIRxt9jJnLy/DAX+RlchJSNHQL4VPyK9qZR/eAKhVA1B
         VMvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DJ1A+hRhaHrRM1KdbAcSrKXb8ruj6vVJE+qJv8sz3OI=;
        b=NPwxOCkW92bHpxzji0GVuGGvRU1FxyJSvAchmGGAVMzJRnZuhdUB80PvKkkGYK712d
         RPFTSjNsGSJDpDNeD2h5ybrENq4wabxFGFh3LTDVVMI+VBWMNToaT4uoGn2CxWu8sYyF
         OwsLGfVdhyZRFzb0eP0joW6buu63XtvBzz6xmulbdCfKl4e1mgItbveUHOIoS3kF1c/T
         VuysRhkF3CxFAgqS0vzCsTx2V+0UTxHAZkx2kkDagLvBqf/ZgvK9N+bO5MuFuHQR9s8O
         H1sESfUVh8JNsovwUzljx7GRHHv0cMZ4DvRXTjOxdNpvIe1ikPH6Ay7OVgOYCZk9DMsr
         dUcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf36gVsgg2qwK1gmmidJH4lK2CtnWNJaqZUDXDg88HV4QiTqOgQk
	4Bzg53mGBB/D01tEsqZA41U=
X-Google-Smtp-Source: AMsMyM4oMJDDmjPrTN2JPFXQaxuphAnzVrx75SFtGubLJF3TwkvR13gXNbHJ66nULkDciMnrjzZc1Q==
X-Received: by 2002:a5d:4acc:0:b0:236:6665:b471 with SMTP id y12-20020a5d4acc000000b002366665b471mr21452447wrs.633.1667534131477;
        Thu, 03 Nov 2022 20:55:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b0f:b0:3cf:84e9:e6f7 with SMTP id
 m15-20020a05600c3b0f00b003cf84e9e6f7ls3489450wms.3.-pod-canary-gmail; Thu, 03
 Nov 2022 20:55:30 -0700 (PDT)
X-Received: by 2002:a05:600c:4e45:b0:3cd:f141:b7d8 with SMTP id e5-20020a05600c4e4500b003cdf141b7d8mr21879486wmq.196.1667534130478;
        Thu, 03 Nov 2022 20:55:30 -0700 (PDT)
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id b1-20020a05600003c100b00239778ccf84si92777wrg.2.2022.11.03.20.55.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Nov 2022 20:55:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6500,9779,10520"; a="290261758"
X-IronPort-AV: E=Sophos;i="5.96,136,1665471600"; 
   d="scan'208";a="290261758"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Nov 2022 20:55:28 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10520"; a="634944443"
X-IronPort-AV: E=Sophos;i="5.96,136,1665471600"; 
   d="scan'208";a="634944443"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by orsmga002.jf.intel.com with ESMTP; 03 Nov 2022 20:55:27 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 3 Nov 2022 20:55:27 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 3 Nov 2022 20:55:26 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 3 Nov 2022 20:55:26 -0700
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (104.47.59.170)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 3 Nov 2022 20:55:26 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=GJHNitSgnE5KfumooNKjar3u2pPqprguBTben/E1IMm2akz6n/weqkvMIvGfYyF0RdWR3BBdtIF41UdYuwECGHgQ3XQCb9r5x+HHF4DBtFreP570loMOIV8WmONQefxV3QlUge3pc/LRu/ftsqFJ3MgxgepuGHwZu5iVLYqV4TE1wdFSy+9iLhYBeBAr5GCbz9PM0r6c/ZWXueW2JOqyZK0b768SBb9wzJzvAMpuPsIz2NU5vxZDZDmXIi5esTX6m/VKWCKB2wxfWCJQimfBg9S/HXd8i/5V7kapJMCjkpt2Y8EC160lRai5WQbzmBqPZ4Re6khI1TnorPTlE/XT1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qOzArVKmtG0k0wtEglA8dpUrvyYXoJJkokqON8EPjE0=;
 b=nmK2M6dbhIhM72x+/7ejHx4+gjyNJAzWtyx7l0zuP9PP6VvKCIK3HyIYKZXasxduoZNOXHwWLRFVqvUWZEsi2VVwCceE501xoE2ouWCW+mQqJLkgfqwU7HwvgnFDyrnRDPLHa5Zr2Dr3rlMxm3SvDTK2SWTo32Wepmc+Di+mCZzReylU51VyBVfTv+n2/HvyO4t51Hzv5eUjQrhjyrBXsaXJgd3rYsPoc6MgNOpnxRLHdm/WD/ZqQIwky5FNy46FAtAHfBPKZ4jNHOlzI0IS5OnDa8/bcH25RxqYntDLBwr2PHzTR86zALI5QdB1qPpw+1Je2W7tGpshouhZ996cEg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by DM4PR11MB5536.namprd11.prod.outlook.com (2603:10b6:5:39b::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5791.22; Fri, 4 Nov
 2022 03:55:21 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b%3]) with mapi id 15.20.5769.021; Fri, 4 Nov 2022
 03:55:20 +0000
Date: Fri, 4 Nov 2022 11:52:07 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Hyeonggon Yoo <42.hyeyoo@gmail.com>, John Thomson
	<lists@johnthomson.fastmail.com.au>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, "Dmitry
 Vyukov" <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Robin Murphy <robin.murphy@arm.com>, John Garry
	<john.garry@huawei.com>, Kefeng Wang <wangkefeng.wang@huawei.com>, "Thomas
 Bogendoerfer" <tsbogend@alpha.franken.de>, "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>, Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2SMZ0//dReS/NMV@feng-clx>
References: <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz>
 <Y2NXiiAF6V2DnBrB@feng-clx>
 <f88a5d34-de05-25d7-832d-36b3a3eddd72@suse.cz>
 <Y2PNLENnxxpqZ74g@feng-clx>
 <Y2PR45BW2mgLLMwC@hyeyoo>
 <8f2cc14c-d8b3-728d-7d12-13f2c1b0d8a0@suse.cz>
 <55ace2db-80b6-04db-e8b5-03bd3b5061cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <55ace2db-80b6-04db-e8b5-03bd3b5061cf@suse.cz>
X-ClientProxiedBy: SI2PR02CA0027.apcprd02.prod.outlook.com
 (2603:1096:4:195::14) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|DM4PR11MB5536:EE_
X-MS-Office365-Filtering-Correlation-Id: cf39d40a-b05a-466b-e087-08dabe1864d2
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: J9dr9gHIIfsBe3L41RuDdCmHw+Vo1cOsRyMEFDumJd5+O5MerjH+dB19UHCiFzKb5sWmjMvcatzt3Y6GynqWO/Q3qTaPYNovFWlYH1VNcWFrFoIfZxI6tLeGvGZGsiBCePAU7T3BdYAI+j75ayVmRcQnv5g5w6T7d9F5q1YHlDAxbCtaPT6TK7xoCmwWyxPKJhPKKYF90T3ghtFfSS+3l0th/lALrwmPUfk04IrS52ncDdxAWeu7rGtlbQWqUuMzBiP/ndONSasr6OFQD8CH7EcZ/UEGEtI4M8jF1j6Ll7eKF4PO0wumXuqM+6Cr50G+0O4venpMivuiQ4P/Yytz1GB4aH7R/MifpYJCRaQxxVVrmK56X3FzFAcinHeGxPYphygfxbQwbf6YeGPcGxPYkee7qwhvn3QYcjyd6mHQWQLZrYJP8khYWgsXARwTjEKwGTasjyzfL+pcNZrkQpsfiYAWNBOCcbxfIIOTYn4MgtB/HXZkTFqWCJNzs4wujL61hV5Hho8Sfi8LMFhdt3JTa3KVws8Ry8syWfaLgxBvjBEOCKCoSVhwm3y33kF1T4zh/ztFDSWZV73RA7nvnd84PMC6DPRmVxRIqgaAm8kYx8bSFWUvFmjajdiBQZiUC1vHy50GgeDkRmcucP9I8w4KbYhThG2cukcuwlTQBqmIXjN33ijC4b4AbZ2OndizpoRP6qrkbMgNUX1Aiif9QkX5EiwcS5IeUUVOQfunL1VouJTactTE69QjuXGwcT4PfcqH
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(346002)(366004)(136003)(376002)(39860400002)(396003)(451199015)(6666004)(66476007)(4326008)(44832011)(6486002)(966005)(66556008)(478600001)(66946007)(186003)(7416002)(8676002)(5660300002)(6916009)(33716001)(316002)(38100700002)(2906002)(41300700001)(83380400001)(54906003)(82960400001)(53546011)(6506007)(8936002)(86362001)(9686003)(26005)(6512007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?V1Gq5p1ZA7tiH0dSTCKei9R7oQCLW6aHqGOc1YSUzqJCWaaEdKWKvmJslhXe?=
 =?us-ascii?Q?+mF3XSblpJlDFpU+2IYO7L5xnUIn4QSbz7593ImeBuiz0vhvEKLxi8x+eGMo?=
 =?us-ascii?Q?HA2/pTJWpqEgNFUmkbSRSqh6tKXaAj9piBdV9o9s+GJA2qcDevoe2jZSTbSw?=
 =?us-ascii?Q?rCuS1cPw1R+1axFZMaI+/krwW9gT57vFnetne61MFlVYvko7gH4azdf2qsyB?=
 =?us-ascii?Q?rNEgv1TgDXpih3fnvD9+Ad8SjxgDHcJ7oACdsgKwqffnYWM9NH2IKS0oGxYz?=
 =?us-ascii?Q?XqGjoBtE6UttU/XdPE3LoIxxv79tZKvSEKCoFnVHs8ByyjpvvaR1WU7lq+h+?=
 =?us-ascii?Q?l0jI0PWHa2i+6G0VQFKYUzIcSQ9SFFPDn4K7omJMP9KllamM0gjI9+K+id/D?=
 =?us-ascii?Q?1/tydRmkOhFHVmBINuVkdylniq50aHCNPrMnd/QCoELFASeOOSU6+OxDxiS3?=
 =?us-ascii?Q?IGljVTuTcmx0h7WR2XtAJztWMDOHgewBliJrQrDq1In/B64ZW0sMgTNnQvlL?=
 =?us-ascii?Q?j5R7zITWwjp7OYxyjM/XX53djTn87fj6SeHPXZ5JyUL7iAnp+RzLIP/I/fli?=
 =?us-ascii?Q?4Qnu8lHensuGjqa8ae16EFI3U6k5VMpyLWFzcB0YLL9KLqkr9thFx+T3fuUI?=
 =?us-ascii?Q?LqXXVY5uVAMfFyIH+KVJk7jVSSzp3/Vl19VpLjQOGZ6ze76cRPozd1KQKamX?=
 =?us-ascii?Q?gpoXequK26oXHUbsQUPnBl8jq+cFP9wD/dMM3LuumN5Ur0j9TN168ha4cM+N?=
 =?us-ascii?Q?C4hgIt6PMF5umkUqCyin2170zYUgMgpUZzWTh1WEHyV9fpGkde0O9Ycw58n3?=
 =?us-ascii?Q?joGUbtLZhiMxhZ9lBJUHxmtTdnG0dGo2Mi2RTWjlWad9HkCOlo3b6RpVGMPj?=
 =?us-ascii?Q?Iphs4jeslTq9xCw0oqGNIFw/osLxaz9Ey1kyfKtcBkIH4ydp4lzhtFRfAP91?=
 =?us-ascii?Q?UYuPcgj8N958kzvyzcyj+to/oSUJvYMJ0YgpheFqV5EO3jZn3NwUT3AcZ65/?=
 =?us-ascii?Q?Xh0g02fV7tdZdBAKT1bPIP607R8+gFi0xJeuD6omLXkS86d4pc6pCFmQ0n25?=
 =?us-ascii?Q?hLJeLr04Tiv4b0p6oLpx/Vb3YIK1rLWiSwKkgJzOIWy5KRhxx+29Jr2Haybc?=
 =?us-ascii?Q?oGvDu+NUFY7SiVplyw+2zIl3NrExBQAs/ZVoUGTJQ66WpaPhDr4I1sru7vx1?=
 =?us-ascii?Q?SX+v+M1Mb4IckpQO+m9l7Pdp7vyUDHz4/hzdhIJ7TiOZbDqiZdLHbQ4fX7ay?=
 =?us-ascii?Q?yYtyU3bKqFnhW96Xj32QtZ4bkSc6CqbRc/qEBc7NC9WAdKYU9cH8/S5+Da8x?=
 =?us-ascii?Q?7sr4b14BpChbzy/kZW6/8DMAzpPj4UpUIEP/59zAoTHcjkuyy7HsdBlqFICC?=
 =?us-ascii?Q?YvNvwB6++tFe1Oqlhx7DcN7u5huMG0fXUu0a5azdDrBXdJdxmqtnBhweh3yp?=
 =?us-ascii?Q?RB8bDHR4qERBVE7V3bjEl3Ppo4D7UnCQBYmC3hS+75eyvCFX/hTCwlWoK9Pa?=
 =?us-ascii?Q?Yj/sFU6Q7oPUzzGb+I/CPVCOE+S+U1ZB/tSG4uG5GUM48dV2Bn+eWyq2+q5G?=
 =?us-ascii?Q?ghtqvD/9Jw6AMgX+oPCw2Sh+eQneS+Y3gX7PzX2V?=
X-MS-Exchange-CrossTenant-Network-Message-Id: cf39d40a-b05a-466b-e087-08dabe1864d2
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 04 Nov 2022 03:55:20.8893
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 810jYzCHR3aa/YHl0WUWiLZjioeig6ltQ33g6rxcxDdpDwPmtRhQV7NQ9VkXYlB61v8rmN8ENg8l3v7r4FNV6w==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR11MB5536
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jkO2S0tv;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.151 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Thu, Nov 03, 2022 at 06:35:53PM +0100, Vlastimil Babka wrote:

[...]

> >> But FYI I'm suggesting to drop CONFIG_TRACING=n variant:
> >> 
> >> https://lore.kernel.org/linux-mm/20221101222520.never.109-kees@kernel.org/T/#m20ecf14390e406247bde0ea9cce368f469c539ed
> >> 
> >> Any thoughts?
> > 
> > I'll get to it, also I think we were pondering that within your series too,
> > but I wanted to postpone in case somebody objects to the extra function call
> > it creates.
> > But that would be for 6.2 anyway while I'll collect the fix here for 6.1.
> 
> On second thought, the fix is making the inlined kmalloc_trace() expand to a
> call that had 2 parameters and now it has 5, which seems to me like a worse
> thing (code bloat) than the function call. With the other reasons to ditch
> the CONFIG_TRACING=n variant I'm inclined to just do it right now.

That's great! It will save much trouble, and reduce code complexity.

Btw, the patch below also has some compiling issue for some kconfig
(thanks to 0Day's kbuild bot).

Thanks,
Feng

> >>> 
> >>> How about the following fix?
> >>> 
> >>> Thanks,
> >>> Feng
> >>> 
> >>> ---
> >>> From 9f9fa9da8946fd44625f873c0f51167357075be1 Mon Sep 17 00:00:00 2001
> >>> From: Feng Tang <feng.tang@intel.com>
> >>> Date: Thu, 3 Nov 2022 21:32:10 +0800
> >>> Subject: [PATCH] mm/slub: Add missing orig_size parameter for wastage debug
> >>> 
> >>> commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
> >>> kmalloc") was introduced for debugging kmalloc memory wastage,
> >>> and it missed to pass the original request size for kmalloc_trace()
> >>> and kmalloc_node_trace() in CONFIG_TRACING=n path.
> >>> 
> >>> Fix it by using __kmem_cache_alloc_node() with correct original
> >>> request size.
> >>> 
> >>> Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc")
> >>> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> >>> Signed-off-by: Feng Tang <feng.tang@intel.com>
> >>> ---
> >>>  include/linux/slab.h | 9 +++++++--
> >>>  1 file changed, 7 insertions(+), 2 deletions(-)
> >>> 
> >>> diff --git a/include/linux/slab.h b/include/linux/slab.h
> >>> index 90877fcde70b..9691afa569e1 100644
> >>> --- a/include/linux/slab.h
> >>> +++ b/include/linux/slab.h
> >>> @@ -469,6 +469,9 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node) __assume_kmalloc_alignm
> >>>  							 __alloc_size(1);
> >>>  void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node) __assume_slab_alignment
> >>>  									 __malloc;
> >>> +void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node,
> >>> +				size_t orig_size, unsigned long caller) __assume_slab_alignment
> >>> +									 __malloc;
> >>>  
> >>>  #ifdef CONFIG_TRACING
> >>>  void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
> >>> @@ -482,7 +485,8 @@ void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
> >>>  static __always_inline __alloc_size(3)
> >>>  void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
> >>>  {
> >>> -	void *ret = kmem_cache_alloc(s, flags);
> >>> +	void *ret = __kmem_cache_alloc_node(s, flags, NUMA_NO_NODE,
> >>> +					    size, _RET_IP_);
> >>>  
> >>>  	ret = kasan_kmalloc(s, ret, size, flags);
> >>>  	return ret;
> >>> @@ -492,7 +496,8 @@ static __always_inline __alloc_size(4)
> >>>  void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
> >>>  			 int node, size_t size)
> >>>  {
> >>> -	void *ret = kmem_cache_alloc_node(s, gfpflags, node);
> >>> +	void *ret = __kmem_cache_alloc_node(s, gfpflags, node,
> >>> +					    size, _RET_IP_);
> >>>  
> >>>  	ret = kasan_kmalloc(s, ret, size, gfpflags);
> >>>  	return ret;
> >>> -- 
> >>> 2.34.1
> >>> 
> >>> 
> >>> 
> >> 
> > 
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2SMZ0//dReS/NMV%40feng-clx.
