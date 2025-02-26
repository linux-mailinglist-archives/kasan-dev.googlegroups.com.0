Return-Path: <kasan-dev+bncBCMMDDFSWYCBBBMT7W6QMGQEY3Q2BYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DC58A46754
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 18:04:09 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4399d2a1331sf410215e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 09:04:09 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740589448; x=1741194248; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F1j5vyt+7ke/na2nujAVjObHze/FZP7fOPGOOUjB5Z4=;
        b=pheuyLtzICEoEzMcPKgptBrrLtRNNJg75QiAXXSxakjuzyMBtnD2fcH+WDlXUkNYUb
         YseJbhNxeSXDLVwPlM972LGcP9uybcyMuuBt6l+pmGsr1fT9o7U2dK4jqd/3vrltsqQL
         LOmnA2ALJVGX2TFH+bhKfAMAxyjlCZrwxZ++QbP3kAhWf+9L+i0hR/GJ3Shd4ZQyfD1+
         aAXX6A3hjLENFufEI1FnBAZfs8DTF798UCmtattOaOyuH8Ld3DgfCQ68VW327f5/0p2U
         bcjQU9VSriFnfABeFPOoNIuH5mTwDWEpjKbH5Pj0vuOKUgaotZpyLW/912pokrHiEcog
         X3ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740589448; x=1741194248;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F1j5vyt+7ke/na2nujAVjObHze/FZP7fOPGOOUjB5Z4=;
        b=ADrAtEmp1JIjvZ14SSNJD/GrjNB+O3TKQZyKc3q0libpcPiIVWhj8FE64zGigDrt7+
         Q1KWTzoUq7oeJYN56H60ff0j5ZfKG07bYhDrqoRtSjSkdg7etG0snvvOY7uO5gtAA+nt
         ypvsso1yLPYKvxqP0PsCYmZ/AyFW3UF5yGGR7JjUxeLzQniXPp1Gkxp5cqaa6C7RC3MW
         IdM5J8eiMBcsp6top2swvQG7tbEsEa+HNWdP+WX75XrDez2sulX00NVRgnZukI8Dwjcv
         dT8Mjoj0STcN4tPPZRsIlOBIUa/kAhoqBJrFfSnBEd8aM2l1OQ28oh8I+FfcgUFKgLhL
         85CQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCwdoqB/t3A7/nGAl7JmkXKu04Dg7F11q0aMDy7MNc3FrBs/QHRDZ2+2E/6IeNhgtIQ7u1Ug==@lfdr.de
X-Gm-Message-State: AOJu0YxB6JqE4wBmnt87X88fsnwKj4RGIVcntqCoApWWpSoYiKh08ILf
	kZe3Y718zsTBqGN3INfAKyD/BxDN9hPgWlBBbhQQvyPnSpMuca+X
X-Google-Smtp-Source: AGHT+IHqFFXUA6TFgWASmVjaFab+yJzDxqTWzywlrtg1AA3lO/zLjq23WHxtqoC0NmAoLq+rThr5Lw==
X-Received: by 2002:a05:600c:1c0b:b0:439:86c4:a8d7 with SMTP id 5b1f17b1804b1-43afddb659dmr1142425e9.5.1740589446171;
        Wed, 26 Feb 2025 09:04:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE3QMBNWR6JYbm2zuTZWwu/qNoeuzhfyIQsDUiKJzUjCA==
Received: by 2002:a05:600c:1592:b0:439:8aa2:645c with SMTP id
 5b1f17b1804b1-43af7935073ls92175e9.2.-pod-prod-00-eu; Wed, 26 Feb 2025
 09:04:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUrW7hjXaKKZPhVQRzCzqD0KTGvVlvYzdjd4boESlgRYVtniHmFqeTE8CZFpyRqeoreElsCC6DRcZU=@googlegroups.com
X-Received: by 2002:a05:600c:1f88:b0:439:8634:9909 with SMTP id 5b1f17b1804b1-43afe1c653bmr1163435e9.14.1740589441927;
        Wed, 26 Feb 2025 09:04:01 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.15])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab2c50559si2897565e9.0.2025.02.26.09.04.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 26 Feb 2025 09:04:01 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.15 as permitted sender) client-ip=192.198.163.15;
X-CSE-ConnectionGUID: f7psszyDSNGYvUviySMULQ==
X-CSE-MsgGUID: lg+bbbcEQoqLFLmCUEUXXw==
X-IronPort-AV: E=McAfee;i="6700,10204,11357"; a="41578280"
X-IronPort-AV: E=Sophos;i="6.13,317,1732608000"; 
   d="scan'208";a="41578280"
Received: from orviesa004.jf.intel.com ([10.64.159.144])
  by fmvoesa109.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Feb 2025 09:03:54 -0800
X-CSE-ConnectionGUID: R6865C4kTbKdOavgqf37Bw==
X-CSE-MsgGUID: 8vW5Rq2LTBWWnr5gdbFGMA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,317,1732608000"; 
   d="scan'208";a="121754660"
Received: from orsmsx902.amr.corp.intel.com ([10.22.229.24])
  by orviesa004.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Feb 2025 09:03:54 -0800
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX902.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.1544.14; Wed, 26 Feb 2025 09:03:53 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Wed, 26 Feb 2025 09:03:53 -0800
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.176)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Wed, 26 Feb 2025 09:03:51 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=V4eE8SnRWe8q7738SrmNp+Qsw6tCsSUi2P8V5MIpXTENxgGcbeESMapRclPthk1aL9/5Cw+tFVydnBpyhE2cIlwm+Fhez+PUNjaDngPpGX96xyGcT789O2k70kkbrQfg6Ew5MLirGIWJBznZOCR/2BCJIfT3Uo0ixXz+In7BLD2+KwjFkuQ955wKs1f7svkcwvAM3TOv03aOCjNb1jgpAIbYYPD0hL+zEarfiVsvUNOf7Jip7c+MHbrdWrgTTaEDQPAq6yLiptONRUP6VE5/zYl8jsOUcdJgqYs+i/ZrRp8gpnJaa63+E1Uu5fmsRz91/KgYJAKfQYIIk6aN/glyXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=sgEWTsO4voBv6EkabzeQB852Ch5LbS1/FdNtaXf/YIg=;
 b=jM4f7sVaOxbf2Nst5RQ87skN2R171h8PSu4SKFD6bLn2zkEymoP2EcieUSIwhryBEzlSTCoteh+npW/NkCq8KpETaJeduN51rREo9uzf7tP4l47/OYGvWpGMjAGwDs0aVT4d19lnSXsaYJ5IrhAu/kQKUm310+B+1caY63TOd2jPJto9xiILiETwl+MqPbb9JNXfWhxs5cFjOj2xZphw1Tutkz7tMqh+YQY9Km066dHMhjR72gudlDL+gC0l/QNm2Q0RyU0B+ZobRbOyymqAhE0Blt4x008FF3vHOsxysdcvhiZpZSRfde61UZPJKTMkHrYib8J1V8LCfhVyT8o0Fw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by DS0PR11MB7382.namprd11.prod.outlook.com (2603:10b6:8:131::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.21; Wed, 26 Feb
 2025 17:03:45 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8489.018; Wed, 26 Feb 2025
 17:03:45 +0000
Date: Wed, 26 Feb 2025 18:03:07 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Florian Mayer <fmayer@google.com>, Vitaly Buka <vitalybuka@google.com>,
	<kees@kernel.org>, <julian.stecklina@cyberus-technology.de>,
	<kevinloughlin@google.com>, <peterz@infradead.org>, <tglx@linutronix.de>,
	<justinstitt@google.com>, <catalin.marinas@arm.com>,
	<wangkefeng.wang@huawei.com>, <bhe@redhat.com>, <ryabinin.a.a@gmail.com>,
	<kirill.shutemov@linux.intel.com>, <will@kernel.org>, <ardb@kernel.org>,
	<jason.andryuk@amd.com>, <dave.hansen@linux.intel.com>,
	<pasha.tatashin@soleen.com>, <ndesaulniers@google.com>,
	<guoweikang.kernel@gmail.com>, <dwmw@amazon.co.uk>, <mark.rutland@arm.com>,
	<broonie@kernel.org>, <apopple@nvidia.com>, <bp@alien8.de>,
	<rppt@kernel.org>, <kaleshsingh@google.com>, <richard.weiyang@gmail.com>,
	<luto@kernel.org>, <glider@google.com>, <pankaj.gupta@amd.com>,
	<pawan.kumar.gupta@linux.intel.com>, <kuan-ying.lee@canonical.com>,
	<tony.luck@intel.com>, <tj@kernel.org>, <jgross@suse.com>,
	<dvyukov@google.com>, <baohua@kernel.org>, <samuel.holland@sifive.com>,
	<dennis@kernel.org>, <akpm@linux-foundation.org>,
	<thomas.weissschuh@linutronix.de>, <surenb@google.com>,
	<kbingham@kernel.org>, <ankita@nvidia.com>, <nathan@kernel.org>,
	<ziy@nvidia.com>, <xin@zytor.com>, <rafael.j.wysocki@intel.com>,
	<andriy.shevchenko@linux.intel.com>, <cl@linux.com>, <jhubbard@nvidia.com>,
	<hpa@zytor.com>, <scott@os.amperecomputing.com>, <david@redhat.com>,
	<jan.kiszka@siemens.com>, <vincenzo.frascino@arm.com>, <corbet@lwn.net>,
	<maz@kernel.org>, <mingo@redhat.com>, <arnd@arndb.de>, <ytcoode@gmail.com>,
	<xur@google.com>, <morbo@google.com>, <thiago.bauermann@linaro.org>,
	<linux-doc@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <llvm@lists.linux.dev>, <linux-mm@kvack.org>,
	<linux-arm-kernel@lists.infradead.org>, <x86@kernel.org>
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
Message-ID: <2bhtxd4vrkyx26wczp25adpg6wqr6pq4j63ez42zjoxbl7inn6@4mnmpat7uve5>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
 <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
 <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
 <CA+fCnZcsg13eoaDJpueZ=erWjosgLDeTrjXVaifA305qAFEYDQ@mail.gmail.com>
 <ffr673gcremzfvcmjnt5qigfjfkrgchipgungjgnzqnf6kc7y6@n4kdu7nxoaw4>
 <CA+fCnZejp4YKT0-9Ak_8kauXDg5MsTLy0CVNQzzvtP29rqQ6Bw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZejp4YKT0-9Ak_8kauXDg5MsTLy0CVNQzzvtP29rqQ6Bw@mail.gmail.com>
X-ClientProxiedBy: DUZP191CA0063.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:10:4fa::7) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|DS0PR11MB7382:EE_
X-MS-Office365-Filtering-Correlation-Id: 01feab03-d904-4436-b8c7-08dd5687877a
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?SlhQVGZnTDNIcWNLcmlaK2V4WUFRdU9LZVpNbGsxKzZRMkh0SzAxY0VWSTc3?=
 =?utf-8?B?MzFHRkJzNU1mSm9NNnNGbTUxdGlWa3lQSS9KU1pxRVBlUDZLYWlCclBMa2xZ?=
 =?utf-8?B?b2NjenhtbDJZSWdIdzJRZXFESHo2VWJBdXdpVkJVNUU3ZXZnYmRaa3d4c0s1?=
 =?utf-8?B?a0s4UVBEaEc0a21OSThyLzZDSitaMVl5UjBiemMzK0dFVW81c2lpdm1OcXo0?=
 =?utf-8?B?NTlDREFoeHJZb0R6MzExbFFPNzJRdk54ZDN1Ykg4cFRXRWphZllMQW9Ud1hx?=
 =?utf-8?B?bmYrdEJuZXBpbVpqazZXNkpKeXMrank2YVVxYUxjbVpWaWJWb2dsM2REdy9T?=
 =?utf-8?B?SHg1ZU9HSkZONWp5R1lzaFdQT0MvY3FBZnZKSTBvU0IzUThqQUxuUkx6dHZD?=
 =?utf-8?B?eVhPZ2xHYnc0OGZUYUFQRUY3d0R3QzRNd1lCN2dDMmJxNk1ncWVmZGpZTHpC?=
 =?utf-8?B?a0t0dDJkUWNaWjd4bStub1k4aGZ0ZFRNdFlwRFMvcm54RDlKK1h5SHZwZDdi?=
 =?utf-8?B?Q2U2eFZqcVVYbWxXYTlLMGRQNDBJa1NPQTdDNEh0dlFad01QQ1MrbllwRHFK?=
 =?utf-8?B?eG1Qc2JScCs5ZlA4WjUxMzRRN3lROWVEN0s4bjNZWHIrQXlUZjd0VnlGNlFY?=
 =?utf-8?B?VmQ4dVAzQjhlRlBYWHU4Q2FKMll6VXMzZnRqaUZMbVA0QkpzYnlpL0dqamUw?=
 =?utf-8?B?NStwOFMvWUFza0xOc2FON3gzTEw3bEFOTm5KUG1BSXY4b2JMdkw5R3ppRDB6?=
 =?utf-8?B?UjNGOVhxcDZ4ZnB1SXZwL3FiV2hjc1BiS2pBWlNTQzE3ZG0wMkNwVTdNeFZs?=
 =?utf-8?B?ZU1zd0JZZHZZZk5LVmZIYUF6b3ZRQ01iZWI5a3E0Q3N2OEJMOEFEWGtkMWxr?=
 =?utf-8?B?SjRZSU5iTWZNbDczeGdDRCtlUkVpVjZlSnNaWkxHK051M1NmMU9GZWkvUHdK?=
 =?utf-8?B?S2FtbFprNlhLV0NDcmNlcE5FWTROSm8rM1NHdnZqUmNCTXkraXZVQ2piTW85?=
 =?utf-8?B?aGRZa1JONjBoTTYwdlc5RjFsVHV4Y1M0SG85UnF5NWxZUldMWlBTazNTZ1Bj?=
 =?utf-8?B?SjVCQ3Jtei96eEdSL0Rmb3duV0xZLzBNZVlZd1ZDLzhVZ0Q5T3hERjNLc2d2?=
 =?utf-8?B?RFY2TEg0Ujg2ODBTMzBrSkJVMm9pTWlwSU0xNWJ6L3NNZHAzQVNSNGZJa0NU?=
 =?utf-8?B?M0MvUTh1SXBPK3J4eHk0bVhJOWwxSDhybHhscmpiU0hMdWtzYUphOU1nNGNR?=
 =?utf-8?B?U2l3M1lnMkpvNUxDZ3UyMVZBQ2JvVzRPUmlQckR4RkNPZFVtb3ZpM29hazRF?=
 =?utf-8?B?Vi9hdkhUQlpsNWE3cVd3YnFsdlIwKzZRMkwzM1ZVSERBdFdQVmN5aWljNlU0?=
 =?utf-8?B?YndNTTZzWjRZd0tEK3pzYjA3TjdMdWZyVlF3NWtNWjBuV0xINzRQL0pMMHpR?=
 =?utf-8?B?VTlDOWZOdEVjQlBLRUlVZHVCVEQ1QjE3akM0KzFrckYzVVZpRHZxcmtDNkQz?=
 =?utf-8?B?TUIwV2szdjcyVVpWU1FJNC9NdkdUSW9nZUd4Z0R1MUNaZGJBY3dMNXB6VitR?=
 =?utf-8?B?a3dJNlhQYks5TUR6RTVWQWxya1VwOVVqYkRtbWY2Q094WFc2a0RFeUlIaU5K?=
 =?utf-8?B?VmF1SEFlRnh0ZjNnNnNPQTV0T3pMcGRMNlZIUmNHRHQ1N0FVSXpMWlgyWkYv?=
 =?utf-8?B?V1ZXR2s2ZmVrT0tJL3NuVmpQRGNjenBacjNHa2p6Smp3T3VacVgxZENsM3RL?=
 =?utf-8?B?anpYY2N5TXMrVktiQnpIZ1k3QVNYZkNURVlxUEtnZitBQ3BZTTFzY2N5SHFM?=
 =?utf-8?B?djZBTE5wMksxMkpvQXRYc2UrU2RmcksxNDhnbUpiWDFsYkVsK2UrOE1pSmlV?=
 =?utf-8?Q?anO/KKKN/Q9oY?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?eU5xUGlzTFBtbkJaaGMzYldEU1EvRHI3K09yWDM0RXoyUXlOZ2FtQlMxYWtG?=
 =?utf-8?B?MGZ3ekR1RUFOY2RjbjdpdVdmQ2o2QWpmUWVrWi83ZW9keE1XNXBtSGhuRktR?=
 =?utf-8?B?VEY3UUo5eUxLcE4zNCtjQWRwV1ZQalhSb2REUHdteE5mMU5jcHVkOU53NTZq?=
 =?utf-8?B?eXhhTk80dGJRZEhOSTFYdll6ZkdiN2l5WE9Qb3V0RjB4ZVkxeCtBeU1HbEgx?=
 =?utf-8?B?b2FJeGJnajNWOEhpYVQ4VS9seXVPWEpZbWd5RTRLNjdIdGdNeGhpTk5rOXU5?=
 =?utf-8?B?T3NVam85TllwOWg1aFNHNGQxQkJFMk1RT3ordndOcFY1QnlpRVRIczNTTnFx?=
 =?utf-8?B?VUpZWXRPR3VDQVBYcU5nQnhDbHFwbTFkZjY2cHJWVnE2RWlwczFRb1BmVHdV?=
 =?utf-8?B?UHp4SndOazIzU1ZZZGYveG1rVVlZU1lVakVaaFQ5MGd1bUcwVFJHYzFTVTVs?=
 =?utf-8?B?OWc4c1ErM2xIempSNEwxbjQwZjl1VlEyRkNHVHE3ZW5GNWlGZDhEMkcyQ2Zy?=
 =?utf-8?B?clhuZlNSY2FMZnZ2TWZEVTljM1ZpTmlScW01TUY4dWE2c1JxS2dUdkZvb0Jw?=
 =?utf-8?B?SUVGbndOZGdRRlpIWjJlNVQrSEUyejJ5YnVtUnBsZ0lCeFk4MWxScDNscloz?=
 =?utf-8?B?ZG1vWEM3OFJMeitjZmRpWmtzT3k0bHBvak9xT3phVVZ0dm8yelhBY0VkaTJx?=
 =?utf-8?B?NnFjMmtObXVIblZ2angwUzl4TFVVbFZTamowN0xaNTN2RzJTZGhKK3FKMmN2?=
 =?utf-8?B?SWovZEJRdFpXa0JwaGJ4VG52bDVVYmZDT3ZmdmJ6Rm1nL1l4ZHg1L1pSeldS?=
 =?utf-8?B?Rk9STEsrQzdhbGRpWWgwWmpnNWlSZEpWenNwZnQ0cmRuN2lRN2xTU1piYTNG?=
 =?utf-8?B?bFR2Y0RQY2tMS1NUdVNqN1dRWHJhWm9BRVhTQzVLaENYVkZwRWhyclV3SThE?=
 =?utf-8?B?dXA2encvRGJOTHltZlNKL1RJaUdCRDdPSzNqS0lBY0lzcHdTVzRaRFgyallv?=
 =?utf-8?B?MWNFeFd5L2NJNngwYzZ2S3k1Z3k5OXRCSmpUSk91TUhESHZuOU1ybXdrYy9K?=
 =?utf-8?B?bzNLaTZLdW53QUZnVk02VlhHZ0s0U1MyYjltaUNBaXgreXp5YVNyYUJsdGk4?=
 =?utf-8?B?aUh4bG04eFBveEtUZG1pKzBnN0podmZnTTlnUGxDc3h6ZHE4VE1XdnQ5ZU9W?=
 =?utf-8?B?VHFKdzZxUDg3NXplT0ZmS1BCc1pUMjJpbnU5NXZ2NG54ZVJ1dCtJUE9ta1J3?=
 =?utf-8?B?eUhCbEpBbTBXYm1LeHdhMFEyMXZNQ1RJMjByWDZWQ3kvMDl1ejcvY1k5NFh5?=
 =?utf-8?B?NlBDUEMwT1UwZU1IUkhiVkY3VTVyOG4xcFRlL25qaTYwek5leGI0OEJtcTUr?=
 =?utf-8?B?elVHdnUrbXZRTmRlQVZNS2pXQThIVVZvYi9LYUVTWGwxWXZMcnJqMkN4UHdy?=
 =?utf-8?B?N3NzZ2g1YW9peSsxWE5jZE5XZ0h6dkJFbElCM21nZG9YMEkxenJHUWgzZGtG?=
 =?utf-8?B?U2pyWTF6SFQydjhnNVd2VXJmM3B6em00NnNlQ1I4dVlweFk0ZFh4TlJnZFBz?=
 =?utf-8?B?QUZ3Unpic3FLMWFqU1kxOWpzbHFKelJqRWNnbTc1bFJkY1pJbCtvdFE5RENP?=
 =?utf-8?B?QlpHTVdXQXd0UnpIVUZYMWhzMHpiNTY0NVdqNVFIUkYxdm9oaU5LVXJJZy9m?=
 =?utf-8?B?akhNYkhkcFpXeVFuaXFCSE5CQm41Y2c2RDkzdmFPWWV2OGNHM1Y5L3MzbDgv?=
 =?utf-8?B?Yk1jdDhjNnJsU1dab1lxTVFQNmtKd29KbTVONE16RjhmK1Vtck5RRDJDV3Fa?=
 =?utf-8?B?NW0zS0RuUkdiZm8wZU95ZDd5V0dXUk0yTjc4MDNDL0NaaXFEcW5QcDQ5Y00r?=
 =?utf-8?B?TUZrbkxJYXpWcHJvWnFqNFZoaTVscDd1UnppcXd2Sm5sa25yZ1lLS0xNMDdn?=
 =?utf-8?B?SndiQXUwR1k5SHZVUDhxMnBaUFlJTTBER3IwZ3hoaGdmSmpuUVFsblhFZFU1?=
 =?utf-8?B?enMzajVxZUVieTVBQ0Rua1FDRXZxYi83MnNwM0pwZFdETXN2MlB4Nm0vYUtX?=
 =?utf-8?B?RlhSdkRQRlFVWXREdUtJbnV0K1hCMGFacnk3N3R3dlZKUkZaY1Rlak5ob0gr?=
 =?utf-8?B?Wno3M0hjL0owOVI1YVV1czhPTy9NMExtem9wcXpVVTVtdElwWlFrSXJSZ1Nk?=
 =?utf-8?Q?9GdW3/EpgJC+8wOWO0MpOM0=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 01feab03-d904-4436-b8c7-08dd5687877a
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Feb 2025 17:03:45.3363
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 0N6EAlhrSQO5Q7n7PNZjx41FJbgy2QlelOuFe4pyXJ5rOAY1sUaY0UIJ2IQOSHVVibgARWqENCm2jXTMcth4QX0EnH443MZaJi5mJm58HWU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR11MB7382
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=L1UUlQ4A;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-26 at 16:24:28 +0100, Andrey Konovalov wrote:
>On Wed, Feb 26, 2025 at 12:53=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> After adding
>>         kasan_params +=3D hwasan-instrument-with-calls=3D0
>> to Makefile.kasan just under
>>         kasan_params +=3D hwasan-mapping-offset=3D$(KASAN_SHADOW_OFFSET)
>> inline works properly in x86. I looked into assembly and before there we=
re just
>> calls to __hwasan_load/store. After adding the the
>> hwasan-instrument-with-calls=3D0 I can see no calls and the KASAN offset=
 is now
>> inlined, plus all functions that were previously instrumented now have t=
he
>> kasan_check_range inlined in them.
>>
>> My LLVM investigation lead me to
>>         bool shouldInstrumentWithCalls(const Triple &TargetTriple) {
>>           return optOr(ClInstrumentWithCalls, TargetTriple.getArch() =3D=
=3D Triple::x86_64);
>>         }
>> which I assume defaults to "1" on x86? So even with inline mode it doesn=
't care
>> and still does an outline version.
>
>Ah, indeed. Weird discrepancy between x86 and arm.
>
>Florian, Vitaly, do you recall why this was implemented like this?
>
>To account for this, let's then set hwasan-instrument-with-calls=3D0
>when CONFIG_KASAN_INLINE is enabled. And also please add a comment
>explaining why this is done.

Sure, will do :)

>
>[...]
>
>> >What do you mean by "The alignment doesn't fit the shadow memory size"?
>>
>> Maybe that's the wrong way to put it. I meant that KASAN_SHADOW_END and
>> KASAN_SHADOW_END aren't aligned to the size of shadow memory.
>
>I see. And the negative side-effect of this would be that we'll need
>extra page table entries to describe the shadow region?

I think so, yes. But I guess it's not a big issue, and anyway right now I'm=
 not
sure how to change it so other necessary parts don't break :b

>
>[...]
>
>> I think this was a false alarm, sorry. I asked Kirill about turning
>> pgtable_l5_enabled() into a runtime_const value but it turns out it's al=
ready
>> patched by alternative code during boot. I just saw a bunch more stuff t=
here
>> because I was looking at the assembly output and the code isn't patched =
there
>> yet.
>
>Great!

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
bhtxd4vrkyx26wczp25adpg6wqr6pq4j63ez42zjoxbl7inn6%404mnmpat7uve5.
