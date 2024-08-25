Return-Path: <kasan-dev+bncBD2KV7O4UQOBBLH2VO3AMGQE3X446HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DB5595E2E4
	for <lists+kasan-dev@lfdr.de>; Sun, 25 Aug 2024 11:45:18 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-5d5c7bfd8aasf4399545eaf.2
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Aug 2024 02:45:17 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724579116; x=1725183916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eJUImmW2MneicHCsvWzniBB4icQL8DZbPUepR0fMtc4=;
        b=NY6cPb3M7n+bBgjiYZ8aakqW3v4vGGZ0NJRHbSRd2XeNL17l59bsSYPoyo5yIyU6/x
         VLl8liIG4m5iE9gshY9TjppmASqyhj7oXaAkHiA4Ykk3pizpitMmdcIcvR1f6mCzAlA/
         ch1IzQlAZc0n3NUqvnQ6mbXMPY/mj9T/sKBaN6cL05rI793/jWZh3Lrzhi+JYKmbaRsj
         JTe8DNQ4PIe9fBib9X7DcLRETT/0I70DC1NDxX9CNJgZPpw2T8wg/bUW5uZYXHTPBBxs
         kEUl6VtWm4rNe8FvCxSWgPqvjYvMUYlTR6wEXfQBEPyxr8LM/XXxfAfa/jc3CAc/6oKW
         4kXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724579116; x=1725183916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eJUImmW2MneicHCsvWzniBB4icQL8DZbPUepR0fMtc4=;
        b=mjHMcVmxnByAhpB7r9K8eLpElw0YKJ5LfeQV9s6tf9qLXNxIYOa1V7yXCzZZdmAa1Z
         gzZrRA6vSIuZ6GYbCSMc4MuCbEgHQdb7TVcDoM5Rqk65wO/jkSqE6M5AtsOnUr+PPUBy
         0Jm7EQMyD0bYgOIVM1lpJlVdDfsDVBtLRTmgg9B1mx0iqLhAMO40k6V74UZgIXiD+qDT
         fovUB1ZnHCiADAza+BPlNsIYzlyQfCHDToEbJ9f/7SvIkhecSiV6eBcDwgxPpaGDzBg4
         o3XdTcFqkDlzjrZCgF1WJsHI1o/mHbCHeB4NrGwpWZplvQQCUmvnUa75TDJFT6WGke6t
         yOHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzK/J4lOHPVIY+Sks/sQxw0LIcqUS9yxYCjwao+RPIMAVnhDCviP/2+JIdVLjz+GLN21WPag==@lfdr.de
X-Gm-Message-State: AOJu0YzXapKGr3LFeGh70aem1/NqO9vlWuJWv/XAc+WiSu1RchykO4uG
	ZZ2Z0yJz/ez+4ufFXd5EwV/o+NbAXBRY1PSV7He8+fCe1Ll/XtYT
X-Google-Smtp-Source: AGHT+IFyXxNGsAxupK2Rf8AIdYhrIb8s7fZf6TPbTFGzbduBEg5Iw/VggUyWz1RAylZMgEl0TinWeg==
X-Received: by 2002:a05:6820:206:b0:5d8:e6a:236 with SMTP id 006d021491bc7-5dcc6210b78mr7644866eaf.3.1724579116577;
        Sun, 25 Aug 2024 02:45:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ba9a:0:b0:5d5:b99a:b26e with SMTP id 006d021491bc7-5dcb1ba1f43ls3463159eaf.0.-pod-prod-02-us;
 Sun, 25 Aug 2024 02:45:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxErovNjEEg/EBpCwtuMd3LKyGLRUCw46mD9RNwWSoTuYryJ48IfqaSrrC7qH+dTnyP/XmdnJUQhA=@googlegroups.com
X-Received: by 2002:a05:6808:1a27:b0:3da:a16e:1759 with SMTP id 5614622812f47-3de2a910976mr8232889b6e.48.1724579115579;
        Sun, 25 Aug 2024 02:45:15 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3de22461a0fsi349488b6e.0.2024.08.25.02.45.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 25 Aug 2024 02:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: SJj0ILOFREeTybfvKrJVqQ==
X-CSE-MsgGUID: VDSL4VuYSFq6l0QP0qbIHg==
X-IronPort-AV: E=McAfee;i="6700,10204,11173"; a="22817580"
X-IronPort-AV: E=Sophos;i="6.10,175,1719903600"; 
   d="scan'208";a="22817580"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2024 02:45:13 -0700
X-CSE-ConnectionGUID: OWOzRlPXS2Gztf6IXVs2vw==
X-CSE-MsgGUID: ajM0izvWSVKmnW6phYzvQA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,175,1719903600"; 
   d="scan'208";a="66552365"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by fmviesa005.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 25 Aug 2024 02:45:13 -0700
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Sun, 25 Aug 2024 02:45:12 -0700
Received: from fmsmsx603.amr.corp.intel.com (10.18.126.83) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Sun, 25 Aug 2024 02:45:12 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Sun, 25 Aug 2024 02:45:12 -0700
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (104.47.66.40) by
 edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Sun, 25 Aug 2024 02:45:12 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IW+iyc1iMaNXun9r7UKOTM5OusL/up4RA7D393lfqbfJKGfMLY2PcQ2O19vFuOyvSZerF+HjB0wltPj214WhOOkBofs0RA0ixU/IZbAEDYUMJBExm3rAatMn2SN2Bqy+mbzhTJ2ub8/pD3uZJm3QXovv4H7bC5lpCkMS/Dd3YMkYSMX1Ip2VPuFjbctRQB7YJaFQ5Cq5wmBvW9ZEdRB7CmSlguSWdN0FMayggSAKB1ZaPLEghxkWukpfOEKVrIWmjl8gW2/o+yw2wp+ut6wPaaHXe9l/CZWIDrAiLEqH5QgGdWi094uYXGNk7WV3rtTlmqBtOCCy29PDyOeD1MmSZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=iji2xY/KUUjRiIXzQJVHWpqe2B8ZzMZufptWsgeQEzI=;
 b=scc4l0n8YtJVMEQzxXoFP7DIIvH52G6TwCNS0VNUH9KdpZ6TKPJpiJusD53kB17/QAghbmswUsupzhshSeVIplI9zsJymMl3BGXIVpq5fnBgacTIZyVEppGk0EBIVoFoFW2NiAeWxqT7fSOBpZStFv//CgDmk6RiQiT+zXnFLkkMxsdFLphxtPe4zjR+Do1fMV2sjmG/RmzxmBLU3wjxCeOL/Hu+5MoipTsvVniCnT2EN/IFScs/IxMGFdAc9eiIuf8cug3HJYSBzK6YC8SGy84hBU1iih2i7nmdHBtVN4fPGO5VNGj5dnPK083wwHxfH0gIx9fLLXk27ppPPwnjMg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by MN2PR11MB4584.namprd11.prod.outlook.com (2603:10b6:208:264::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7875.19; Sun, 25 Aug
 2024 09:45:10 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.7897.021; Sun, 25 Aug 2024
 09:45:10 +0000
Date: Sun, 25 Aug 2024 17:45:00 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Jann Horn <jannh@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, Linux Memory Management List
	<linux-mm@kvack.org>, Vlastimil Babka <vbabka@suse.cz>, Andrey Konovalov
	<andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
	<kasan-dev@googlegroups.com>, <oliver.sang@intel.com>
Subject: [linux-next:master] [slub]  3a34e8ea62:
 BUG:KASAN:slab-use-after-free_in_kmem_cache_rcu_uaf
Message-ID: <202408251741.4ce3b34e-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SG2PR03CA0125.apcprd03.prod.outlook.com
 (2603:1096:4:91::29) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|MN2PR11MB4584:EE_
X-MS-Office365-Filtering-Correlation-Id: 66542325-5e10-4d01-361d-08dcc4ea9c04
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?nVCzJQTM4O7KsiQO/hxityRWJwDQ0n7bWLOauuDlrHPnQNl+A9uMEMjROWHQ?=
 =?us-ascii?Q?bWZaBmD0nso2bB3H+VmEROAmaeOkdBdyn4uIelnWI68+5M2zVXHVbwab4/KB?=
 =?us-ascii?Q?iLDy/pmzfvIQ8Bd1A9L7J0/IoDtdJPHHILO5KNo3n8VFHhcXNtzcEIKzM/AN?=
 =?us-ascii?Q?mjA6Y+kBv5MksWIYwYJX1A8LXG2oZvXIgIHYmVyQwNKuzHfMj4UlXoUYLGMF?=
 =?us-ascii?Q?OC6uIuB9EsKYkYVu3UfpMmaVVShfdOwfmJyA7GeiYpNqI2OiBcSobaMNw2nA?=
 =?us-ascii?Q?NdkhsD5u9nu8+86jFD4wgrg1uIIS8Rp7MK1kl03yifaWvsmpLQEU5aY6Oxpw?=
 =?us-ascii?Q?mQNmvGGhoc0+mf6xv9EJnmDP3lp3ziH0UZ1s6N/k1mQqwfcVASgKisHUG4PZ?=
 =?us-ascii?Q?Kb/yjyy4wuZOd7s/Kg1IuYNKsFoQF6Xn2hDOzhZznGS8gksz8iKhJNLThmpE?=
 =?us-ascii?Q?tLpkXpQ7pqwKXP5bVzX3uNmiR+aU56VVZ/FyPeUja8bfvSHk/hcmIe097x2s?=
 =?us-ascii?Q?I6Jpf4JOKl0NuefjRadYpPdnksTf98YX4H75EZ9cRqgk98Hk/Ue99swTVa0H?=
 =?us-ascii?Q?Qa6IRfIAXljflPRsJRd2mp1QGdNjz1mmAssY/hrr+sB0d54x+v+Vnj5m9RWx?=
 =?us-ascii?Q?TwBYsgv1Dc3cnAAAej3RgIQRR72QOT92ZM7NWOnC+b2M94dL3NZBh+HKScLS?=
 =?us-ascii?Q?dPebs0yFdAdjoc0CFZRiUc0Km3zKWqLvMa42HBiT6a6G73N9vb8h4kWU5jvc?=
 =?us-ascii?Q?tOCTyILTji5g2Rtif518rfd0Z0j17R8WHB168XADzTs6Shzhp9TTsb/y5pmv?=
 =?us-ascii?Q?+xBIO5qeZDdAJxpqJPktykQWRzcdi287DlTG4CrqepAYHE0JoHKhzisNEGSW?=
 =?us-ascii?Q?P1AD1rr8kV3HrqL+VQ2GoWGAmv6us6NiIvqVJ0jz63oBUGk05QmZNPp8KLQA?=
 =?us-ascii?Q?vWN4KEXyxh4C+iRURc+eblHVBMP+9BZVJKypvYYFvWRcR69TjL6jA1gz0sWs?=
 =?us-ascii?Q?0lOlACFOLLGuQI58UdneHSIBFY9ulUDt27S5jlP9yPBJSRkDAIuV7rLEhvwy?=
 =?us-ascii?Q?vmNymXOMKp5u2aDDCqwSL+XjCG9iY0ipLAx5XaJKEXj0ua9jn3W35XzqqUDj?=
 =?us-ascii?Q?FaKYZge98PUp/Ts9NWJSezHVigSGvjgTiq46YpVj0g/EdvRHq5DZdI67y4Yh?=
 =?us-ascii?Q?2C29jx4d0QWzP80XCrFWq+6L74uBQhvujdXYdTTV3HMWccpQJ0XwsQBCy6OU?=
 =?us-ascii?Q?avLwbrmgKB8xPVoZBAwCpSBesi+xS0O3ClQFxB4MXRFErigBLQjjYh6pOx7P?=
 =?us-ascii?Q?l95vhn6xzbQm7jjvZDgVLi40?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?HLMUqhj6VsfXU1Wp31RonDRVKXjXkN7QPqibN8BdTxpiNBTDw+X+6MZCHu0p?=
 =?us-ascii?Q?826ZAxasNjT4TZFiw8nD7/ppwBmNE4koKvhyLYQkJitgw5Dc2WyZzfCY3Nrg?=
 =?us-ascii?Q?I45RwVZaF0473UkchO9PaDl8Sk+cKXF7JT4T1cAvYPILLxDZFJAOY+EuTfC/?=
 =?us-ascii?Q?STOS1wa6Gg/gdsS9Qa3++Ar/9ocsZPgALHWp7ltbG6+0gHxXvk74sbuMV3mC?=
 =?us-ascii?Q?YWgm8bQ4U0zml9JrrZzfwCUiw1r5Bn6pPVsMhTaTDW3D7rBTHSmVuwZY7MDi?=
 =?us-ascii?Q?Cp0VeCK2+n1BLVfX5AKPSNljOUqSBDijUU2wR0hf8DFuw4k2HTp/iUhoWZOj?=
 =?us-ascii?Q?T3ijaUQ+uAHdGv7NrTr9u6GLvjPYotK2kQfWwpgvF/jM+AFh3GtAC+YTWIOK?=
 =?us-ascii?Q?HEksIvxJhV1n0EkuztlPdiUDqE5MFmbQbah2XDLEfO9Zn+brY8n0JxcI/TV1?=
 =?us-ascii?Q?keTrOGQWS//QoGzqB5hg6hsDyTBx4wOqSn4V1yK5PalFcVZli0bSLL7xD70+?=
 =?us-ascii?Q?iqbhjPYZKSitIHd9qaGmtPBcIcehqheCTSa1q82MPNJwz4kGEyqbz0QbXXPJ?=
 =?us-ascii?Q?ujVzKqZT+ELovSPIR2jPoBjH9IfQbQ90215UJdi5mgXzs6WZA//NgRAMz4Oe?=
 =?us-ascii?Q?uYQq1bIyaoFLuin+EN3p2C74sw9DVgO2a1jbS+U85L0k/EfCbEWukYgY8Zdw?=
 =?us-ascii?Q?P1ObRnkNqfb2IZrYWhSrL0uJOLldC2T+YJg2y8GHVAQv8lkEFT/b6FlNRrwF?=
 =?us-ascii?Q?mJQNhxv5v0Jx63baO/7SY3ezgzdZoztU0p1BlDbi1pMAc+9Ztj/dw7t6YB+0?=
 =?us-ascii?Q?X/883nt8a4WGolvGEW62VQou1IELwBGoXPl1B7GmF+864VVdZ7IGooD98ZHB?=
 =?us-ascii?Q?9EzNdcdFsaj8xukOXzZTV4fMfIFdmAHi6oseqYZblS1jhXZAr0DREkuct01L?=
 =?us-ascii?Q?QcGT6g78/SRHXVTEuRZEiQr4YlCrzg1mK1HfjP5L9+7IrQmZGvIcGw/7ouOP?=
 =?us-ascii?Q?ehHDzgNtEvy7Iu8cP5Zf7bTEiHG2ABA/1Y8gkIoOvww88zp+2bXMKMDEmH7K?=
 =?us-ascii?Q?DgZhOS+Z2Ltd6ZHvu5deC0djdI85AMia1D83ZAs82bqxDQsPee89qgBAM5TL?=
 =?us-ascii?Q?vyn/7BvQyJH9nt+Mg1KlCuYWC0Q0k4GqWt10PAVzZhyGcflqRKBL1azsZ0yf?=
 =?us-ascii?Q?/ZzLk7argwl3T6LD+sEsGPfYtBfjhujR8vcL4JwmgwaN/uMZWfstODJkdOQG?=
 =?us-ascii?Q?HrqGq71aiW3Jb60ox1fEgv+I+pRdAaxc9DswffAmgGb2vzLw1jzB/iqTRm/5?=
 =?us-ascii?Q?FDi9JMqGupKQajJ58HsndjeQxogE72QhqMwWD5Wn+fIRYycOGSamXgMHOy+t?=
 =?us-ascii?Q?+4ob19i/CsuEyOY6MTMPQviNPmX0DU/aUCOvrR7HzkGItxL+rhA4mmVm1S/T?=
 =?us-ascii?Q?HgXvnkcGKzImWyTC6wOVf8fsIv8EktpOb6NXh0dzoU7lrbuzmWyx1O0I+nNM?=
 =?us-ascii?Q?Q2O1XePgmcJYYb7nma1DmBIlLaD4VZnX8NLFUAR5kYXjIgjfoPrAkO6rFYM0?=
 =?us-ascii?Q?4V4jyhjes6AguGmf49RnIAF56PDbUhsW7U3xEZI7SNmUbmJ6bv3aJb54coM0?=
 =?us-ascii?Q?jA=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 66542325-5e10-4d01-361d-08dcc4ea9c04
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Aug 2024 09:45:10.0099
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: oAxS6OZqmP8N+8QWVrWLoo2c7GaRQBAotGTqXqGIRXoXcIyc6ZpJr100oFsSQ0coP3hAypUVRA6Q4ykZVXBK8g==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR11MB4584
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=VelZT9Bp;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 198.175.65.20 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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



Hello,

kernel test robot noticed "BUG:KASAN:slab-use-after-free_in_kmem_cache_rcu_uaf" on:

commit: 3a34e8ea62cdeba64a66fa4489059c59ba4ec285 ("slub: Introduce CONFIG_SLUB_RCU_DEBUG")
https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master

[test failed on linux-next/master c79c85875f1af04040fe4492ed94ce37ad729c4d]

in testcase: kunit
version: 
with following parameters:

	group: group-00



compiler: gcc-12
test machine: 36 threads 1 sockets Intel(R) Core(TM) i9-10980XE CPU @ 3.00GHz (Cascade Lake) with 128G memory

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202408251741.4ce3b34e-oliver.sang@intel.com


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20240825/202408251741.4ce3b34e-oliver.sang@intel.com


kern  :err   : [  359.476745] ==================================================================
kern  :err   : [  359.479027] BUG: KASAN: slab-use-after-free in kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
kern  :err   : [  359.480349] Read of size 1 at addr ffff888361948840 by task kunit_try_catch/4608

kern  :err   : [  359.482361] CPU: 29 UID: 0 PID: 4608 Comm: kunit_try_catch Tainted: G    B            N 6.11.0-rc2-00010-g3a34e8ea62cd #1
kern  :err   : [  359.484487] Tainted: [B]=BAD_PAGE, [N]=TEST
kern  :err   : [  359.485478] Hardware name: Gigabyte Technology Co., Ltd. X299 UD4 Pro/X299 UD4 Pro-CF, BIOS F8a 04/27/2021
kern  :err   : [  359.486969] Call Trace:
kern  :err   : [  359.487837]  <TASK>
kern  :err   : [  359.488673]  dump_stack_lvl+0x53/0x70
kern  :err   : [  359.489634]  print_address_description+0x2c/0x3a0
kern  :err   : [  359.490788]  ? kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
kern  :err   : [  359.491900]  print_report+0xb9/0x2b0
kern  :err   : [  359.492830]  ? kasan_addr_to_slab+0xd/0xb0
kern  :err   : [  359.493806]  ? kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
kern  :err   : [  359.494882]  kasan_report+0xe8/0x120
kern  :err   : [  359.495797]  ? kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
kern  :err   : [  359.496862]  kmem_cache_rcu_uaf+0x377/0x490 [kasan_test]
kern  :err   : [  359.497927]  ? __pfx_kmem_cache_rcu_uaf+0x10/0x10 [kasan_test]
kern  :err   : [  359.499020]  ? __schedule+0x7ec/0x1950
kern  :err   : [  359.499929]  ? ktime_get_ts64+0x7f/0x230
kern  :err   : [  359.500843]  kunit_try_run_case+0x1b0/0x490
kern  :err   : [  359.501772]  ? __pfx_kunit_try_run_case+0x10/0x10
kern  :err   : [  359.502735]  ? set_cpus_allowed_ptr+0x85/0xc0
kern  :err   : [  359.503662]  ? __pfx_set_cpus_allowed_ptr+0x10/0x10
kern  :err   : [  359.504629]  ? __pfx_kunit_try_run_case+0x10/0x10
kern  :err   : [  359.505579]  ? __pfx_kunit_generic_run_threadfn_adapter+0x10/0x10
kern  :err   : [  359.506640]  kunit_generic_run_threadfn_adapter+0x7d/0xe0
kern  :err   : [  359.507642]  kthread+0x2d8/0x3c0
kern  :err   : [  359.508468]  ? __pfx_kthread+0x10/0x10
kern  :err   : [  359.509337]  ret_from_fork+0x31/0x70
kern  :err   : [  359.510185]  ? __pfx_kthread+0x10/0x10
kern  :err   : [  359.511042]  ret_from_fork_asm+0x1a/0x30
kern  :err   : [  359.511912]  </TASK>

kern  :err   : [  359.513276] Allocated by task 4608:
kern  :warn  : [  359.514082]  kasan_save_stack+0x33/0x60
kern  :warn  : [  359.514917]  kasan_save_track+0x14/0x30
kern  :warn  : [  359.515748]  __kasan_slab_alloc+0x89/0x90
kern  :warn  : [  359.516595]  kmem_cache_alloc_noprof+0x10e/0x380
kern  :warn  : [  359.517499]  kmem_cache_rcu_uaf+0x10d/0x490 [kasan_test]
kern  :warn  : [  359.518464]  kunit_try_run_case+0x1b0/0x490
kern  :warn  : [  359.519323]  kunit_generic_run_threadfn_adapter+0x7d/0xe0
kern  :warn  : [  359.520274]  kthread+0x2d8/0x3c0
kern  :warn  : [  359.521040]  ret_from_fork+0x31/0x70
kern  :warn  : [  359.521825]  ret_from_fork_asm+0x1a/0x30

kern  :err   : [  359.523201] Freed by task 0:
kern  :warn  : [  359.523891]  kasan_save_stack+0x33/0x60
kern  :warn  : [  359.524646]  kasan_save_track+0x14/0x30
kern  :warn  : [  359.525384]  kasan_save_free_info+0x3b/0x60
kern  :warn  : [  359.526154]  __kasan_slab_free+0x51/0x70
kern  :warn  : [  359.526901]  slab_free_after_rcu_debug+0xf8/0x2a0
kern  :warn  : [  359.527711]  rcu_do_batch+0x388/0xde0
kern  :warn  : [  359.528433]  rcu_core+0x419/0xea0
kern  :warn  : [  359.529120]  handle_softirqs+0x1d3/0x630
kern  :warn  : [  359.529858]  __irq_exit_rcu+0x125/0x170
kern  :warn  : [  359.530584]  sysvec_apic_timer_interrupt+0x6f/0x90
kern  :warn  : [  359.531389]  asm_sysvec_apic_timer_interrupt+0x1a/0x20

kern  :err   : [  359.532754] Last potentially related work creation:
kern  :warn  : [  359.533562]  kasan_save_stack+0x33/0x60
kern  :warn  : [  359.534283]  __kasan_record_aux_stack+0xad/0xc0
kern  :warn  : [  359.535063]  kmem_cache_free+0x337/0x4c0
kern  :warn  : [  359.535794]  kmem_cache_rcu_uaf+0x14b/0x490 [kasan_test]
kern  :warn  : [  359.536644]  kunit_try_run_case+0x1b0/0x490
kern  :warn  : [  359.537394]  kunit_generic_run_threadfn_adapter+0x7d/0xe0
kern  :warn  : [  359.538244]  kthread+0x2d8/0x3c0
kern  :warn  : [  359.538917]  ret_from_fork+0x31/0x70
kern  :warn  : [  359.539616]  ret_from_fork_asm+0x1a/0x30

kern  :err   : [  359.540850] The buggy address belongs to the object at ffff888361948840
                               which belongs to the cache test_cache of size 200
kern  :err   : [  359.542668] The buggy address is located 0 bytes inside of
                               freed 200-byte region [ffff888361948840, ffff888361948908)

kern  :err   : [  359.545021] The buggy address belongs to the physical page:
kern  :warn  : [  359.545911] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x361948
kern  :warn  : [  359.547012] head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
kern  :warn  : [  359.548094] flags: 0x17ffffc0000040(head|node=0|zone=2|lastcpupid=0x1fffff)
kern  :warn  : [  359.549131] page_type: 0xfdffffff(slab)
kern  :warn  : [  359.549918] raw: 0017ffffc0000040 ffff88821419ca00 dead000000000122 0000000000000000
kern  :warn  : [  359.551034] raw: 0000000000000000 00000000801f001f 00000001fdffffff 0000000000000000
kern  :warn  : [  359.552151] head: 0017ffffc0000040 ffff88821419ca00 dead000000000122 0000000000000000
kern  :warn  : [  359.553278] head: 0000000000000000 00000000801f001f 00000001fdffffff 0000000000000000
kern  :warn  : [  359.554406] head: 0017ffffc0000001 ffffea000d865201 ffffffffffffffff 0000000000000000
kern  :warn  : [  359.555532] head: 0000000000000002 0000000000000000 00000000ffffffff 0000000000000000
kern  :warn  : [  359.556660] page dumped because: kasan: bad access detected

kern  :err   : [  359.558233] Memory state around the buggy address:
kern  :err   : [  359.559130]  ffff888361948700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
kern  :err   : [  359.560238]  ffff888361948780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
kern  :err   : [  359.561344] >ffff888361948800: fc fc fc fc fc fc fc fc fa fb fb fb fb fb fb fb
kern  :err   : [  359.562451]                                            ^
kern  :err   : [  359.563410]  ffff888361948880: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
kern  :err   : [  359.564535]  ffff888361948900: fb fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
kern  :err   : [  359.565661] ==================================================================
kern  :info  : [  359.982162]     ok 38 kmem_cache_rcu_uaf



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202408251741.4ce3b34e-oliver.sang%40intel.com.
