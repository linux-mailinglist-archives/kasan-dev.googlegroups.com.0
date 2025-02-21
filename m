Return-Path: <kasan-dev+bncBCMMDDFSWYCBBHNP4K6QMGQEFVJY26I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C6BAA3F81A
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 16:11:27 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2fc1c3b3dc7sf4390132a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 07:11:27 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740150686; x=1740755486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TEhVS6phH8LGabSF1AKNsjuxKchJiEwb/sTB02Dng14=;
        b=Wyv415W9BDW5TkX9jYASxX34fFSNhKG9ZUpefa53PvlgRC1oufw6Iw/keJjp/WNHcK
         8FX4IyQNi1L/uo575m3aC/DPyTPZg5bfNjCNtE9w9CxcOS+J6c6kY6QiON9FVkbytWBQ
         ovYQ1yHZ65bYIuvn5rtSxVMIlCOtx+SgEVEIeCD01jE49FSJjjMRrEULivxLFVrIn2q1
         UqFDwIzruMcJicpzAv0jzXlWD/UvpvFyyB72SpyCNajLgU3+FbtskRAJYDDTeaiypQZY
         aQ44/Pq3b1SHzHK2Av/+5QridtSapLyuipWS/Fh8Ei7tFCuADWEyjGeaZgggm0EjI6lb
         GvUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740150686; x=1740755486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TEhVS6phH8LGabSF1AKNsjuxKchJiEwb/sTB02Dng14=;
        b=r3e13qt4sP/xGi2H5x4uja8fe4qDcIMlzJr2Lt9+9JB3LA+XT2TTSI2m+hRhdyRQje
         IsdRh9dQhCKlB54kxG9wWxY1Fp4YWvsRNxmzHN31HQ8QOJBX0Af/DG6KJ5AfU1++YRW0
         0VS4HaUxmcmqzKuINESewPiDsNUoQ74/WZzzWRmWMqrGsJ9Vzud190bm1QQ60GJHQamL
         T8bnrzXK9ErxgSPDYskRjHcYemAgN1fwbLwbxFNnc9qwdTeD3l+KceJkQPviPeCji3K9
         aA/P2V9RkvQ4FVcReoEKRU5XikuaCzxPGsWt13e+Gln4es/dOQKpMcDj4hni+sBjzfDG
         NAJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW7tjIYeeWPK9l31BqBle10X+TrUjmy+T/MTSXvMFHmF1CRM6+JmdlxWgQDYfKb2EM3F10INQ==@lfdr.de
X-Gm-Message-State: AOJu0YyDow/zBSaqTR+32gNLFJNz2OATwaR+lJxIcSN0+sfLbkI32A6A
	AevaxiVZOScwcbwSt4+aj7ZXfIMaaDGe3iene5r7PIWliVuTXEAI
X-Google-Smtp-Source: AGHT+IEgmT/XoA79fy1vQEafQ66H6bN8s4xbXYOvLktNp4CZZqpAS3abO6czxlEiEctLCQ7OWTUQog==
X-Received: by 2002:a17:90b:1344:b0:2fc:a3b7:10a2 with SMTP id 98e67ed59e1d1-2fce78cb879mr6865784a91.17.1740150685411;
        Fri, 21 Feb 2025 07:11:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF7ifq8+bBnaDvZhOyz6k1ViJ9x1DNTFH2iQN/ewA+LYw==
Received: by 2002:a17:90a:d484:b0:2f7:21c:a7d1 with SMTP id
 98e67ed59e1d1-2fccbecec1als2244972a91.0.-pod-prod-07-us; Fri, 21 Feb 2025
 07:11:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXLVww1N+t0lb3aa0Wn5M2wwTFlmCcwfi4qRxuY/HTOsKJhRmHDH3ni4QFcKo1va4rviyQTckyHX4Q=@googlegroups.com
X-Received: by 2002:a17:90b:388b:b0:2fa:f8d:65de with SMTP id 98e67ed59e1d1-2fce7b11354mr4841958a91.22.1740150683903;
        Fri, 21 Feb 2025 07:11:23 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2fcbab56cf0si621834a91.1.2025.02.21.07.11.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Feb 2025 07:11:23 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.18 as permitted sender) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: K30qPHRrQLKyMvQ1TA/aMg==
X-CSE-MsgGUID: zzfBYNG1QcK4erWGAPWdFg==
X-IronPort-AV: E=McAfee;i="6700,10204,11314"; a="41175762"
X-IronPort-AV: E=Sophos;i="6.12,310,1728975600"; 
   d="scan'208";a="41175762"
Received: from orviesa004.jf.intel.com ([10.64.159.144])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Feb 2025 07:11:22 -0800
X-CSE-ConnectionGUID: nnu17HrDTymJEDfzMMjVbQ==
X-CSE-MsgGUID: 9N36K1q/QNKPo2RLpqz8QQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,305,1732608000"; 
   d="scan'208";a="120375167"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by orviesa004.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Feb 2025 07:11:20 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Fri, 21 Feb 2025 07:11:18 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Fri, 21 Feb 2025 07:11:18 -0800
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (104.47.59.170)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Fri, 21 Feb 2025 07:11:16 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ac1wYruhWL5F7Xw93BpoA0giuSGPLpjJXl2rohcOysnAcw8AmN4RckTrIwGER4ijwG7+jJ/bfVmKJbUgOj7BO6xF9CDJgxfbUJkDO4UiU3lbUb+KmYm/QoJrwaK99Raz1XYTSy1nSzo6KnFxFB8XFuwnmo3hW8/lzNndJo2g5oUReSWES5aZihl6mBVWPSqaArUkcXQyPMtd/icz6r67vOr8nt77zDdyYuc0WgWLIIRE+JBteRmj2SUdhfGYAInYNpayQD3RmkktEd2GDzIVvA9X9v5fzQRtpJkPpXa+0B3OypLHNzn2BWgpG/qY31CUzimMtwFezO1aXhUVnFDn+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=br7WMH+i5lpWuD59nMIsHjIWzgKipYvc2sChV/WbIfw=;
 b=jB3SH+oVhbG7YVGZLT+7nvy43uYNEozjYaYuneUES/YFFQEFw42R3NVw2Q8X+GWNjJ7q6yoDXzbZJYUE0QRaAnK8bgqMEkQMhmeG+iOnuzmt1YXg6HMyJz8bPmamK4IJCx0oH4Go3epr3JXSzTliRHZN+X5CAt95lutTLrplLcV+JiaC9IbE79GXzGw0e98h181fzRqNyWFx/yzE9eSLBxJ+PJQN8fMEk8Kq1rc2EC5Z+o0NoHCiff1u0wmx67cKmaBd2YXF1rFN0QCmb7mb650ORXJAsdrDbPSXQOFWGqIvzdZU3MgLZjFCVjLUvicH1Q82S8wUk2+yXG6Bpiv/XA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by MW6PR11MB8338.namprd11.prod.outlook.com (2603:10b6:303:247::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.15; Fri, 21 Feb
 2025 15:11:08 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8466.015; Fri, 21 Feb 2025
 15:11:07 +0000
Date: Fri, 21 Feb 2025 16:10:54 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <kees@kernel.org>, <julian.stecklina@cyberus-technology.de>,
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
Message-ID: <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
X-ClientProxiedBy: DU2P251CA0007.EURP251.PROD.OUTLOOK.COM
 (2603:10a6:10:230::9) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|MW6PR11MB8338:EE_
X-MS-Office365-Filtering-Correlation-Id: ce383990-bc09-4ba6-5fc7-08dd5289f786
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?QURjU3Y3L1RwVWowK1lDcUpHYktFMWdESHJrMmhWNW9GckRwTHlFZUJCRXVC?=
 =?utf-8?B?eDJxNVNkQVVQTktBT1A3cGE5Zm9rS1Noa2Q4bWFXUkNsZDh5eDJ1bTBXcW5G?=
 =?utf-8?B?Zit4Q3hzSUs5ZjBTVXFrdGZvbU8vTTdsN0JhVWlFeTVhZGx5MW9mZ2owRXQx?=
 =?utf-8?B?K1YwWGRKSWNNQ2xKSFpaTzh2TEZaWGpvei9WeW5RYjhiQ3ZVTnhzUmUvc1du?=
 =?utf-8?B?Ujc3bEp1bUJFUjZTaldQQnNrdGFzdEtxdVA3VnVkWGU5SVVPOU1aNmxKUS9S?=
 =?utf-8?B?RjFnSGIweVFpMVBpT21DaSs2ZnI0Wnhvb3UvdzJadEcwcFYraFBFZUh5c1Nt?=
 =?utf-8?B?UUlOQS9sQ0pJaXRPTDJWdmFOd3M3UlNoV0FueVJCY21wNVhIVkhHem9waHVv?=
 =?utf-8?B?ZFZrekhIdUFqUmEycjlRN1R6UGdXWlloU3RGcmtuLzMwTU5mZU9Qc3psWXdY?=
 =?utf-8?B?UGhJTWw0TmdKTHA1VnBEZFF1OG9GWkF6cFBkOWRRRTZldlBjWjIyUVFZejlB?=
 =?utf-8?B?SS9qSkJZdlhtUjNoQnlFTTEwMEM5U2ZCczJHN1BQdjFzemIvV3o1dVp1azc5?=
 =?utf-8?B?WTlUdEtKOXhOcTlJbnVveWVyR05jaUhhT3drMXpTNENnSnhBaDd0TFFkbUYv?=
 =?utf-8?B?dlhLT1ZLZ3g1cnlKN2I5bEZJQllFUjVlL1ZHLytnQWY1NFFxL3pqSHc4T25U?=
 =?utf-8?B?eGlnZ1k4Z0VlMDh6elpBZ3ZuWEJoUTN6NkI4bnllMjFBZms2WEU2VTR2RlVM?=
 =?utf-8?B?ZW5IZDgvQzBOcjU5Z3hBOENBV2FuSjRxeVFGa2o2SzYrcDJTeHo5UXpDOW42?=
 =?utf-8?B?WkFWSXd2UE5JbDdKSFpqZWN3aUNPdlVLUXBWK3M5NWgxdjg2UEFuSHNTNTJp?=
 =?utf-8?B?WVoxZFhkeEJiRHUxVHpSNUtZdUNTaG9ZTFBSRXUwZERwU2xScDltYXhHTTRK?=
 =?utf-8?B?ajJmblRkUlpyUW15TzZpcUxIODVhT1hQd3E4R1R3ZVpDUWpZdVdUaDk2M1NM?=
 =?utf-8?B?a1N4d3FtMkxLMHdHc3FyT3FzdElsV2FkQXVYeVh2RlZPdi9hS2RxQVVwQngw?=
 =?utf-8?B?S3B0TEE3YUVCKy9jNVg3K1FBdmVCUURCVWl2Y0JoM0l4eDlJYzl0YUhLbWZL?=
 =?utf-8?B?c0tpNnY4M0tCQWl6VmEzNXZoUTNVcjdFT1pscjd6TUJOVk14RlJsREFqWkxi?=
 =?utf-8?B?RVZKcnJHbGdkeVNkQW5aYlM1UVgvamVjWHZCcW11NUNRYWJCbkovZ3RwSTg3?=
 =?utf-8?B?bmcwRkJQTnhYcmtlL094cWhFVzU2MlZFUDkrZFFXbk05d0FmRWlXbXk4RTFo?=
 =?utf-8?B?NnhhZlBhdENySlJGdjBYenJrYVljMjI1UGw1RnRkMUJLSGV2N0J2d2tzUi95?=
 =?utf-8?B?aTdsUDJmYndnVm9Fb25QUGJWVUVyM1grcTdsL2dWMVNVd2RkNGhlUkdKSitI?=
 =?utf-8?B?bHhweXZOamF2WnUwNE1FbUx6MjkxTnh0VHNMQmt1K3BVWExURVFXNlpCalhm?=
 =?utf-8?B?VXdESGJGa2U0Z2ZjWFpRZlk5WUJGbFU0VlRNK0FTYjUwVUszWERaWlRRRUZw?=
 =?utf-8?B?RWxvMmRCQ2UwVnVsQmM4R09nK2s2bStXRU1sTFRMM3ZjSGZOcnpYZzBwYkY1?=
 =?utf-8?B?Uis2dTFFeWJLelY0K04vb1RZT0Zteko0OW9nQnN3aXd5b1JIYTFDVEd2RWIw?=
 =?utf-8?B?NDlHMjk4dG93Vmdzbit4RVZISS9DNmJQVjN1K3Jib0cvVTRmMXRVelhTY2J6?=
 =?utf-8?B?T2dWODFRY3o2bHUzbWdySkFrU3I2VEtuZ3hRQmM2a1ArMTJUWmYrNXFsUng5?=
 =?utf-8?B?YUt3RlFTU0UvRmwzdFpIeWl5NGNtbGlYOURRWlhvdE45RkZLaDVsQnQ0dTJv?=
 =?utf-8?Q?C0ZzH7r/YcR3x?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?VWZvRE9FNmVSYzdIVURSVkxsZ0ZFaGZqOXdYTkxVenNjSnlGM0dvcXBQNTZa?=
 =?utf-8?B?MkNZSEUzZUF1M2Z2RzlPdTVBV0dMdDZrR2hsWm5LSmh2RElLbHUwTW1XcFlt?=
 =?utf-8?B?MXROR2ZCdHdYUnJBZytobG5pQVVjNDN0aitJeWhGZ2Z3R0dnbHk2ZllNUHNF?=
 =?utf-8?B?WGpCZ3VQNGxFNTVyajJtdno1WFpzL1pOZm1uSEZOUXNOdzlIbmlnMWUxeThj?=
 =?utf-8?B?bkpITDQxQkltT09TVXlHV0VJajZBSktkSzRobnljcTBCbjJ4Q0gwR1d6VTFq?=
 =?utf-8?B?UkFPNEpJY3RvWE9OWUl3ZnBjRGYxSGFYcGVhRUNDSFF6TVlQeDd5Ulo3WUZK?=
 =?utf-8?B?bnUxVlRRWCtQdHRqMFc3MHVaMWl0WENnWU9yaGhjV3VHQkdTdUpvV1UvVmRC?=
 =?utf-8?B?dEY1amtYaUZ3TlNpckJCdG5maDAyQnc1Ukt3UE1vT2RMcVNzM21CSGk5R0R2?=
 =?utf-8?B?bW51blVRTjVkQ0orY3h2V2xBOWthcGtSaFprL1JPZTdlWldEYkYyNWt5bGpR?=
 =?utf-8?B?TTZPc3ZSb1ViOTQyTG1pWHpEb2hiUi9HWlptZTZ4U2F6RXhqbldpMXJlZkc0?=
 =?utf-8?B?TTgxZWhtVTEvT3piU2FpMnJ0MUZEUlZKSXdicEx5d0t6ekp3R0ZvYmthclFo?=
 =?utf-8?B?UGlFQlRndmgwNk1TeTIybVdjZmlJaEZPKzZLNXFWSDQxQUpoVzVpeTRaRXdJ?=
 =?utf-8?B?cHRqRDI3blpBU01hUlIvY2dYOFVzanZNMWljVHFGNjNzejVZSFZFMS9lQkRH?=
 =?utf-8?B?SXBkdGxsckJTeWVSczlxd1Y1eVhpT0VrRzZqOU5FbWJzeXN3TC9mekZITGNU?=
 =?utf-8?B?ZnVnblNlWWdpQUJSajAxSzZxcEsrM0xEb2tBc3hiSnhBc0c0aGJraTd3UVBm?=
 =?utf-8?B?ZHdEL1pkZmZQbjRPWkNtYUd0bkFTNGtEVHZmRWpKbzJMS3p5cFY3ODNjVFlm?=
 =?utf-8?B?WEJuRHFhb0xnSkxlWkR6dnlDWnhjdWtFN2YrT1gvUGszKzJ1enMxeHVqQU1H?=
 =?utf-8?B?M01ndDhVNEQ2VzFWMmp5aVJWZXRaV3RHSXRIT3NpRldSZUtrbEpjcHpETHFI?=
 =?utf-8?B?NWRSbERrTlJHVkhCdWdOMGNITXNHZzdUUTN3VWNRRDROSVlnZitnYWZZMFFH?=
 =?utf-8?B?dW9zQzZsZXpQaDlTUFVFVFRtYnRJSFRBVENBbzZIcjJ1Z1ppS3lCdmtIVDM3?=
 =?utf-8?B?Z08vRFQ1VmloVEpobW8xaCtVQjVZeTl4OUhGcEsyVXdnTmdxSG1XcGFhb0FR?=
 =?utf-8?B?eGxmUDdqWmZaUnpoeDRhSE5LTzJpclo0OUNQWDkrekxtZXZOS1VjMFB4THJ4?=
 =?utf-8?B?WlZ1SDdqWXp2ZXAvTndraUhQbDlhWExJcGxhTDV1RlQ5bW1rZ050eHZ3ZS93?=
 =?utf-8?B?UUhtaS9BT3BQK0FtdmowTmNYOUgxYSswbHE3em9DaUQyUm9tb1hjeUcvSjZx?=
 =?utf-8?B?ZTZaSnNVN3VxWGxlbjRYd3VlZjRYNENEU0RvNmhXQVkrcXhJd1lkMUVOa28x?=
 =?utf-8?B?bzFUWXVFcGlTZHVjVmxOWDZyWDNpSG9Pak1obUpFSlp6M3pMWmxCVnhxMWlx?=
 =?utf-8?B?TVpPbFFiTnI1aXN2S1J2alFQbWdRMDZRcXhUYjZsRXlnYVRkSmIvZVZEZ0ZS?=
 =?utf-8?B?eVdnVjlQMUtkL2p2STJ4TXZLVVdOcXh5dlhhV2NsQ0JCY3J6UDk2U0UwZzd3?=
 =?utf-8?B?SU5nWG9DbVFjV3pqYklrNWF6WXNCTTFjZnpqRG9jSndtb0FGTWtiY1RQMWlX?=
 =?utf-8?B?NGZLZ0RSbG5FanNxTHh4ZWFkem5JMHljcUs2cVNRNEU4aWRhWVp5WndFM01N?=
 =?utf-8?B?OHhnRVA1Rjl1ZzRVVitqNmdKSGxTczVnTit5YnRVNXppQUYrd2FmQWFBWGla?=
 =?utf-8?B?TGprTEFaOWt0NlRFdTRudGZuZ2xUSGJsakg1N3pVd0llYUhsMU5udU82anlk?=
 =?utf-8?B?UjYvRXo0MHdBT1IzbVUzSGN4aTNJUVUzRm1YUzhKcGh2N3l6WnFWTUk3VjBU?=
 =?utf-8?B?WEJjU2h6UUwvLy9HS2Vtc3FJUm01NjhybGpab3pLb0NFdUs0ZWhwb0RUVTgw?=
 =?utf-8?B?T1NEYnZrNkphWU5QVFhDVGFhYU1qVTBKVm56M1doODcwS2plaTBTMzU0ZEpU?=
 =?utf-8?B?aDlicWFpWjBpSnpCbzRjMGE4dU1FSVkwc0xsdWxCUnJGOXFnVjFJaWtkZEY0?=
 =?utf-8?Q?v/6gpebIwANEAEE07eaokUM=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: ce383990-bc09-4ba6-5fc7-08dd5289f786
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Feb 2025 15:11:07.6263
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: d9d+7QOOfzO4ZnZ/W8dOlKTThaGlArmoMULwK/itOaC3+5wW5+MZ+mS2/AXopISi+daqnlxQelAJUDylDnCmP/VqeM/8yujahfXGj58GbT4=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW6PR11MB8338
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jcf06MDP;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.18 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-20 at 00:31:08 +0100, Andrey Konovalov wrote:
>On Tue, Feb 18, 2025 at 9:20=E2=80=AFAM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> On x86, generic KASAN is setup in a way that needs a single
>> KASAN_SHADOW_OFFSET value for both 4 and 5 level paging. It's required
>> to facilitate boot time switching and it's a compiler ABI so it can't be
>> changed during runtime.
>>
>> Software tag-based mode doesn't tie shadow start and end to any linear
>> addresses as part of the compiler ABI so it can be changed during
>> runtime.
>
>KASAN_SHADOW_OFFSET is passed to the compiler via
>hwasan-mapping-offset, see scripts/Makefile.kasan (for the INLINE
>mode). So while we can change its value, it has to be known at compile
>time. So I don't think using a runtime constant would work.

I don't know about arm64, but this doesn't seem to work right now on x86. I
think I recall that hwasan-mapping-offset isn't implemented on the x86 LLVM=
 or
something like that? I'm sure I saw some note about it a while ago on the
internet but I couldn't find it today.

Anyway if KASAN_SHADOW_OFFSET is not set at compile time it defaults to not=
hing
and just doesn't get passed into kasan-params a few lines below. I assume t=
hat
result seems a little too makeshift for runtime const to make sense here?

>
>Which means that KASAN_SHADOW_OFFSET has to have such a value that
>works for both 4 and 5 level page tables. This possibly means we might
>need something different than the first patch in this series.

I'll think again about doing one offset for both paging levels so that it's=
 as
optimal as possible.

>
>But in case I'm wrong, I left comments for the current code below.
>
>> This notion, for KASAN purposes, allows to optimize out macros
>> such us pgtable_l5_enabled() which would otherwise be used in every
>> single KASAN related function.
>>
>> Use runtime_const infrastructure with pgtable_l5_enabled() to initialize
>> the end address of KASAN's shadow address space. It's a good choice
>> since in software tag based mode KASAN_SHADOW_OFFSET and
>> KASAN_SHADOW_END refer to the same value and the offset in
>> kasan_mem_to_shadow() is a signed negative value.
>>
>> Setup KASAN_SHADOW_END values so that they're aligned to 4TB in 4-level
>> paging mode and to 2PB in 5-level paging mode. Also update x86 memory
>> map documentation.
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> Changelog v2:
>> - Change documentation kasan start address to non-dense values.
>>
>>  Documentation/arch/x86/x86_64/mm.rst |  6 ++++--
>>  arch/x86/Kconfig                     |  3 +--
>>  arch/x86/include/asm/kasan.h         | 14 +++++++++++++-
>>  arch/x86/kernel/vmlinux.lds.S        |  1 +
>>  arch/x86/mm/kasan_init_64.c          |  5 ++++-
>>  5 files changed, 23 insertions(+), 6 deletions(-)
>>
>> diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x=
86/x86_64/mm.rst
>> index f2db178b353f..5014ec322e19 100644
>> --- a/Documentation/arch/x86/x86_64/mm.rst
>> +++ b/Documentation/arch/x86/x86_64/mm.rst
>> @@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
>>     ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unu=
sed hole
>>     ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual=
 memory map (vmemmap_base)
>>     ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unu=
sed hole
>> -   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory
>> +   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN s=
hadow memory (generic mode)
>> +   fffff40000000000 |   -8    TB | fffffc0000000000 |    8 TB | KASAN s=
hadow memory (software tag-based mode)
>>    __________________|____________|__________________|_________|________=
____________________________________________________
>>                                                                |
>>                                                                | Identic=
al layout to the 56-bit one from here on:
>> @@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
>>     ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unu=
sed hole
>>     ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual=
 memory map (vmemmap_base)
>>     ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unu=
sed hole
>> -   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN s=
hadow memory
>> +   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN s=
hadow memory (generic mode)
>> +   ffe0000000000000 |   -6    PB | fff0000000000000 |    4 PB | KASAN s=
hadow memory (software tag-based mode)
>>    __________________|____________|__________________|_________|________=
____________________________________________________
>>                                                                |
>>                                                                | Identic=
al layout to the 47-bit one from here on:
>> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
>> index 6df7779ed6da..f4ef64bf824a 100644
>> --- a/arch/x86/Kconfig
>> +++ b/arch/x86/Kconfig
>> @@ -400,8 +400,7 @@ config AUDIT_ARCH
>>
>>  config KASAN_SHADOW_OFFSET
>>         hex
>> -       depends on KASAN
>> -       default 0xdffffc0000000000
>> +       default 0xdffffc0000000000 if KASAN_GENERIC
>
>Let's put a comment here explaining what happens if !KASAN_GENERIC.
>
>Also, as I mentioned in the first patch, we need to figure out what to
>do with scripts/gdb/linux/kasan.py.

I'll look through the scripts. Maybe it's possible to figure out if 5-level
paging is enabled from there and setup the kasan offset based on that.

>
>>
>>  config HAVE_INTEL_TXT
>>         def_bool y
>> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
>> index a75f0748a4b6..4bfd3641af84 100644
>> --- a/arch/x86/include/asm/kasan.h
>> +++ b/arch/x86/include/asm/kasan.h
>> @@ -5,7 +5,7 @@
>>  #include <linux/const.h>
>>  #include <linux/kasan-tags.h>
>>  #include <linux/types.h>
>> -#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>> +
>>  #define KASAN_SHADOW_SCALE_SHIFT 3
>>
>>  /*
>> @@ -14,6 +14,8 @@
>>   * for kernel really starts from compiler's shadow offset +
>>   * 'kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT
>>   */
>> +#ifdef CONFIG_KASAN_GENERIC
>> +#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>>  #define KASAN_SHADOW_START      (KASAN_SHADOW_OFFSET + \
>>                                         ((-1UL << __VIRTUAL_MASK_SHIFT) =
>> \
>>                                                 KASAN_SHADOW_SCALE_SHIFT=
))
>> @@ -24,12 +26,22 @@
>>  #define KASAN_SHADOW_END        (KASAN_SHADOW_START + \
>>                                         (1ULL << (__VIRTUAL_MASK_SHIFT -=
 \
>>                                                   KASAN_SHADOW_SCALE_SHI=
FT)))
>> +#endif
>> +
>>
>>  #ifndef __ASSEMBLY__
>> +#include <asm/runtime-const.h>
>>  #include <linux/bitops.h>
>>  #include <linux/bitfield.h>
>>  #include <linux/bits.h>
>>
>> +#ifdef CONFIG_KASAN_SW_TAGS
>> +extern unsigned long KASAN_SHADOW_END_RC;
>> +#define KASAN_SHADOW_END       runtime_const_ptr(KASAN_SHADOW_END_RC)
>> +#define KASAN_SHADOW_OFFSET    KASAN_SHADOW_END
>> +#define KASAN_SHADOW_START     (KASAN_SHADOW_END - ((UL(1)) << (__VIRTU=
AL_MASK_SHIFT - KASAN_SHADOW_SCALE_SHIFT)))
>
>Any reason these are under __ASSEMBLY__? They seem to belong better
>together with the CONFIG_KASAN_GENERIC definitions above.

I remember getting a wall of odd looking compile errors when this wasn't un=
der
assembly. But I'll recheck.

>
>> +#endif
>> +
>>  #define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
>>  #define arch_kasan_reset_tag(addr)     __tag_reset(addr)
>>  #define arch_kasan_get_tag(addr)       __tag_get(addr)
>> diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds=
.S
>> index 0deb4887d6e9..df6c85f8f48f 100644
>> --- a/arch/x86/kernel/vmlinux.lds.S
>> +++ b/arch/x86/kernel/vmlinux.lds.S
>> @@ -353,6 +353,7 @@ SECTIONS
>>
>>         RUNTIME_CONST_VARIABLES
>>         RUNTIME_CONST(ptr, USER_PTR_MAX)
>> +       RUNTIME_CONST(ptr, KASAN_SHADOW_END_RC)
>>
>>         . =3D ALIGN(PAGE_SIZE);
>>
>> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
>> index 299a2144dac4..5ca5862a5cd6 100644
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -358,6 +358,9 @@ void __init kasan_init(void)
>>         int i;
>>
>>         memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
>> +       unsigned long KASAN_SHADOW_END_RC =3D pgtable_l5_enabled() ? 0xf=
ff0000000000000 : 0xfffffc0000000000;
>
>I think defining these constants in arch/x86/include/asm/kasan.h is
>cleaner than hardcoding them here.
>

Okay, I'll change that.

>
>
>
>
>
>
>> +
>> +       runtime_const_init(ptr, KASAN_SHADOW_END_RC);
>>
>>         /*
>>          * We use the same shadow offset for 4- and 5-level paging to
>> @@ -372,7 +375,7 @@ void __init kasan_init(void)
>>          * bunch of things like kernel code, modules, EFI mapping, etc.
>>          * We need to take extra steps to not overwrite them.
>>          */
>> -       if (pgtable_l5_enabled()) {
>> +       if (pgtable_l5_enabled() && !IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
>>                 void *ptr;
>>
>>                 ptr =3D (void *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADO=
W_END));
>> --
>> 2.47.1
>>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/l=
cbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr%40nyssicid3kwb.
