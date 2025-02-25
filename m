Return-Path: <kasan-dev+bncBCMMDDFSWYCBB7XX666QMGQEN7TNDRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id AA0DCA447CF
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 18:21:04 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id a640c23a62f3a-aa6b904a886sf545514566b.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 09:21:04 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740504064; x=1741108864; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hLaDhZKCiNJEiif8sEAxUbxduC6OORLKdHYYvxB6hLk=;
        b=ddxEVUA1x96QwCO9VP+t8omrAQdlLcqibgNkL3Zo+2qGsIW+T+PBdsRhB9Ocs5VJfE
         jvX11Uvhk4Go+pwFDYOuSXBNDpqHquwQpstyiLvyfy7DBEr/lVuli+k+Wz1+7fPUkkig
         7EcE025VV+3CY3Kssc4eyBCIY/1t8g79xS7ndQNLTo4/L2MQR+MkHl6zRUtDJvkpBwWA
         bEJldpPHWDSmG0ArVJT5rAdYvmRvzwNbLEwakaVanZhEQ03cqQ/1GpudbohEw8JkzQHV
         IpDdUx/WigEswWjNUXR6yE6kz7SUcW5kSOUx7t/xAUnUBVSvosnOcVqFlosH5CwN+AB3
         6dnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740504064; x=1741108864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hLaDhZKCiNJEiif8sEAxUbxduC6OORLKdHYYvxB6hLk=;
        b=Rmv00IMfTP1GTpzPl6KicD/rjwK3F1AtY8lIJ+YkIF6dxTXc7Lj7VXpHEhyGY42i8V
         v4Mvg20HJi0BKoTnuc0uQ5R3ThspSSBsAm0unZPHdgpQh7nUYw55LM+b3AZnYX/rtUz7
         hPSL9rH+INJbxNN6Z31MqPd4A8vO0HJpkJv2f5eW02bk247hV2H7Qcx17wibhN40uZpo
         IANEAtt88nLX77GQR6DnMXRoe7YmqoquMqmPLl/QMN6onRPc3ppx8StEkROCcvOKk2Uu
         7gDanEOBsdbFPw/s7aI4qM8WZmYJOIHsbKL9+epQoZJkaakucCIRBNyLK6rRAUV9uKuf
         Hmrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbYmqE+TYsfsNS2hfQ5NGcB9PQuqdHZqorirqba4iEEpYw3p2BAnsIpS6iBTDagchl+siHOQ==@lfdr.de
X-Gm-Message-State: AOJu0YxgDWh0LvJfnM9sXV5t1Bf9W0IkBFI1sHSYg0YJW8PwQAb7SLaq
	vb0XGKb6PsxJmHqdmIQGlqaKfdp+96HE0NoxcIUJgXwQAAHuh36F
X-Google-Smtp-Source: AGHT+IERXLotRne0usvbKS1n7AHGDGuk/MR8sB6Vpu555/+fPCn50j+/mrzOWwjpGU8KvLUN7cU82w==
X-Received: by 2002:a05:6402:4409:b0:5e0:8c55:504 with SMTP id 4fb4d7f45d1cf-5e0b70bf3a7mr17287481a12.7.1740504063020;
        Tue, 25 Feb 2025 09:21:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFAFnP9ncttvv9tOaqbTx9vjknSgd9Y+sUVPKxZZ14Wcg==
Received: by 2002:a05:6402:1caf:b0:5da:aad:6265 with SMTP id
 4fb4d7f45d1cf-5e491dcacbfls230527a12.2.-pod-prod-02-eu; Tue, 25 Feb 2025
 09:21:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXK+rZERYxUSkZWLkf4Pnwi1XJtsdfPXfjzGdfio5YP/J9yo6AgDehBIbAj2he6LRt9YJDd3kTtKTg=@googlegroups.com
X-Received: by 2002:a17:906:e95:b0:abe:cac5:bd4e with SMTP id a640c23a62f3a-abecac5d64emr486028066b.43.1740504060379;
        Tue, 25 Feb 2025 09:21:00 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5e459c40412si97685a12.1.2025.02.25.09.20.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 25 Feb 2025 09:21:00 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: sBiehEU1R46xnyrrTzTXKA==
X-CSE-MsgGUID: DG7F8tqjQku1cwc9dbNBFg==
X-IronPort-AV: E=McAfee;i="6700,10204,11356"; a="58743441"
X-IronPort-AV: E=Sophos;i="6.13,314,1732608000"; 
   d="scan'208";a="58743441"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Feb 2025 09:20:44 -0800
X-CSE-ConnectionGUID: CiLY/ECrSCWQcxz1khAMoQ==
X-CSE-MsgGUID: XeqWG7b2TMOsghRHpWtf4Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="120561981"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by fmviesa003.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 25 Feb 2025 09:20:38 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Tue, 25 Feb 2025 09:20:32 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Tue, 25 Feb 2025 09:20:32 -0800
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.171)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Tue, 25 Feb 2025 09:20:29 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=i87VsXYvDW5jbNbxOIC8xS4SlE0mdXcXaFBiYQcPMMgb4rlGxHxegnVlwhfDTBkrNF86mipOuds3el78k1sXfOXhjbF5RF1uFu9kpMYZKnTYlr7krbjf7Q1z1O6jlOvhmiK9scZ10HdkmalITd83ge0K7WWfzCkZBa0+UjizyFFhiQWcv5M0D7Kkj8iO1lGn6+G1lg9ReIFkUrkHlGbOVe0uOAa0awrGumsKAXfRb6Y0YwjaGad1xnBZSUP7I2oX3YQb1toajrqvILQnAYaWnPb1/8+un7f0Ul0IuKXtvTsB7f2Z/6oID7AaEBEqmm092Cf5cPKgxI0PDXURRrqaiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1/cpoIsYVvxpIH7OKvm3BOMOiT0hT9QBOTbltxVXxI4=;
 b=DEgxyAl4+qTdfOJanLuQOkYrobCEILRvDz76Vs/9J/1HxVgMRloTCQj3DF4q/lX4y3Q48Q3+aO3yseQfLxc68FZ9Y2IxFtKqrKrIkHKU7ruBqnqMeDG0lEV8M36nUf333mEKpIQGkwKZzM0YjIzk2X1O7Q2qkoOECE8B0uZahsQIP+vGFDYuMgeKi5LVJggCJZpMhIn5s+JfTW4F1q/GhJH7ZItfIs7vdFbHFHelVy12VbobPh9kdHGSpFzQKcdYzbONG8gDPnM0qij2noTzDJhcmuViXa2YGnaRLVP3IDfIoMBnn8p7qi3vvjHcKBJs5uh2+PrDYpQVCOicqNW65w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by IA1PR11MB8864.namprd11.prod.outlook.com (2603:10b6:208:597::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.20; Tue, 25 Feb
 2025 17:20:21 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8466.016; Tue, 25 Feb 2025
 17:20:21 +0000
Date: Tue, 25 Feb 2025 18:20:08 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <kees@kernel.org>, <julian.stecklina@cyberus-technology.de>,
	<kevinloughlin@google.com>, <peterz@infradead.org>, <tglx@linutronix.de>,
	<justinstitt@google.com>, <catalin.marinas@arm.com>,
	<wangkefeng.wang@huawei.com>, <bhe@redhat.com>, <ryabinin.a.a@gmail.com>,
	<kirill.shutemov@linux.intel.com>, <will@kernel.org>, <ardb@kernel.org>,
	<jason.andryuk@amd.com>, <dave.hansen@linux.intel.com>,
	<pasha.tatashin@soleen.com>, <guoweikang.kernel@gmail.com>,
	<dwmw@amazon.co.uk>, <mark.rutland@arm.com>, <broonie@kernel.org>,
	<apopple@nvidia.com>, <bp@alien8.de>, <rppt@kernel.org>,
	<kaleshsingh@google.com>, <richard.weiyang@gmail.com>, <luto@kernel.org>,
	<glider@google.com>, <pankaj.gupta@amd.com>,
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
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow
 computation
Message-ID: <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
X-ClientProxiedBy: DUZPR01CA0027.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:46b::14) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|IA1PR11MB8864:EE_
X-MS-Office365-Filtering-Correlation-Id: 5c6b65d1-d4f3-40dd-c950-08dd55c0ae8c
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?Y016VWZOclU1MkNxcG9waGVRM1Z5VVY5eFZRc2lCZjFwZDEzbXRTdFF1U0NG?=
 =?utf-8?B?YlpieklHVk1RKzY2ZlNvK2JmMkNGTDhraGZSZitZdEhQQVRRNDExdEN4Wnho?=
 =?utf-8?B?ZGNHTmRzc01CaEo2ZHd5Q2RhVmFmWUhZYlVsME1MbnhvOVlrYVk5YkcrK0VO?=
 =?utf-8?B?OG9FZkM4M01KNDZiekY1UkNjVDVUZ0h3aDJzSnpVT0pJUnRNNkRJYjZGNXZi?=
 =?utf-8?B?eTJjZ0VyUklxcHRvb3hvS1dFdXBpdkRvWlcrRGFLMU1zQ1NoYkJGUWUwclQ5?=
 =?utf-8?B?OG5FVUZwaXpYMDErKzlMVEhubXBTRHQ3TFFETlhrRmRHL0ZGU1VxemY0c2pl?=
 =?utf-8?B?S3BuaTRVSmllMEtnMFhNODh6WFRVcG9WMFk5Nlcrc1M4a2hQQ1p6VlRqcmNN?=
 =?utf-8?B?Yzk3d0ZYY3AwaEFaNDBvUzNHMWFPc3RUS3A4SVBuUTNtNkR5K2VHUWw3UFA2?=
 =?utf-8?B?eUtOMlVBZTNiRWw2YkNlcEQ5Yy9XcVNGNWZHaHdueWw0QkxubE9odm1Ybm1L?=
 =?utf-8?B?MXZmd1ZqTmkwMkExeWhnWmJWNVR6NzhkMUlGU0NENHFOQ3g4dGhtd1I1eHJN?=
 =?utf-8?B?QjFha0JZR3lqSVdVSThZY0IzM0N6amVhcTg3TlBYSDdtWUdsazFpM1ZJSXA2?=
 =?utf-8?B?K0M3d2VKYVk4YTlLS2pqakhyMWE3OWFqR29tV240c2NKd2ZiYXFCT3FwTTlZ?=
 =?utf-8?B?Qk1GeUJxeDZjTTRXVWozR2hobGloS1pnVUdFMlRnbVh0WTd1Sm9BL0wxbHB5?=
 =?utf-8?B?eWtxZnprZHpDRkhRTi9naG9mZjRTaXg4NnZtY0lqSmZ4b203RlExYmpRWXJh?=
 =?utf-8?B?azIzOWRlSFliSE9UUUJIOFAzS2xQanFwL2c4N3V5QjY4YkhiZGNSS1B5QmY0?=
 =?utf-8?B?bmFZWjdLeEpFa2dMV2R2QmJjNzdjUWZEa1M1N0Vaa2tGYnpBRnZSZnRzeHQw?=
 =?utf-8?B?cmFZY1d2cWx0S2dYcmcvdWZrOHJHUTZKWGp6RmQ1SmNuOFk3UEkvRHJyWmwr?=
 =?utf-8?B?RkpGT2pNd28wZ0pCZmkyQkRYNy8xRDdJZG9HL1RQZnRucjBGNEVpUWxVckNY?=
 =?utf-8?B?UWlmcWh5Z0tDMmkyVTNEbWF4cVA3R1dGNGIyaWZxQlVxdGVkS1lFMC9tRVla?=
 =?utf-8?B?L0s3Vy9CdzBZR21wZHlUYkp0V3liYUdDdGdDOHRCMjR6bjMyWFBHVWh4VG9B?=
 =?utf-8?B?UXRVRGhlY240UmsvMzFrVFZNRG1aZzkvRnZZUDIvMlhLNVlhcUFhMnp5YVZJ?=
 =?utf-8?B?empMcTdpN1d3cHJGeGxKcWJCVFp3L2F3b2NETFdJc0E5WHppSE5pR3d4MzYv?=
 =?utf-8?B?QmdaZ1VhMzV6TWlCdTRsUWMzemp5MUV4cDVxT0tBbHpHWnBQdWFZU09JWTFZ?=
 =?utf-8?B?SXRWVVA2blJxTERrdlhHWmxqdTVhazdndStrZGtXWU5FanNFVVh2YkJqMDBs?=
 =?utf-8?B?bkZFVFl3Rk5KU0w0LzZ6VzhNZ1MzTmY1TUVuQ202cXQ3S25wTEVwbkw2TWtV?=
 =?utf-8?B?UnpjZGdzV1BTR2dDVHB1RXdqdDlnaTk4NmpXbEprc0dEV0tYbGExV0Q5WWxC?=
 =?utf-8?B?aDJTT1hQV29sdjlaZUF3ZGFseFh4NUZhSWZ0aGtGOXNUTmloeFVMakNTT3JW?=
 =?utf-8?B?alkxYkdVU3ZNQXFvUzFoRWhnWUNTVlZkaTN1ZTQzSWxCa1hXdGdTWjU0QXd0?=
 =?utf-8?B?Q1psbG5YRXlGUGRiS1NVVSs0N1RYdmZPbFRYeVZISFpCUEVQUHJnei9kZjVl?=
 =?utf-8?B?UFQzeUlkNUQ0Q3lGS2wyNEFyN1M3dVlKeVM0NDV5MUlFbVVqU21ldFBvWnhN?=
 =?utf-8?B?b21CVWNUNzdXcWZGZ1hxQT09?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?TTNENHROVlArSmh5WVR6Sm9pa2hWRmRpVjhHN1UvcVNaRG5LRWEvdnNKdlRu?=
 =?utf-8?B?WFlsZEJCdEJTNzBpNnRJWDNhQStvZDVaNnFJVE0zbnBMWnBmb1h1ZzFYanlE?=
 =?utf-8?B?TjE4YlEzM1RCcG9SY0s1OGdKSGxKZmJ6YWpvb01aSzVZa0xmcG1MTnFVTisx?=
 =?utf-8?B?ekV0LzBKc2RZd2gvLzZ0UjU4enNOM1FQaS9sZW5nZDIvUm9ITTczWXAyelp0?=
 =?utf-8?B?OFMzL2NLOHBIejJ1VHo4cFJPazM1bE55MTAwMmtQVkFYNHNIbVFmRWluQVZv?=
 =?utf-8?B?VTVETnlWQVlDRndjZnZKZHJwb2J2dFB2VmlRMXZRY21mQWdMcklkNGpBMFJB?=
 =?utf-8?B?N2w1ZE5reVZvZ2MvMG1iWVNrMzV0WjVoNlB4WWZrTzZsZlpVdXNGMVZLdDFX?=
 =?utf-8?B?QktvZEdEQXhwUWVpM1k2d01hL2hyL21ZVFhmZU9mWHZpU3N3UlVjdzBoRkE2?=
 =?utf-8?B?UU1EVUVseFJOOURtWENtclN4dEhzTk1wdHVIOXJlSTFQc3dVSFVhY3RHc1Bm?=
 =?utf-8?B?OVFodjRhcjNrZ3UwYSt6aE05YXZ3MXNqaWd1Y29tbENIQlpMQ0lxZ1dHemxp?=
 =?utf-8?B?Q0c3RFByTXVmUmdRSzhPdmxzbXhaaHJtcXVrUzZid0xrd1ZPcy9nRkozSFFP?=
 =?utf-8?B?K1Z4Q21ETnZJOThvT0w2SUZpS3Q1QUhiQk95U2E5S2tqa3FXbUhJbXBQSWlO?=
 =?utf-8?B?amlDUDJocW4ydUhmWWwwMGlITHI2M3BRS3FEczBKZituSFRRcTZkYmFYN1VF?=
 =?utf-8?B?cm9EV29Va1FzUWpSVitHa0pZTlRjeDFvNGZXTWYyWEcxRzZvZ3JMOXhweDdm?=
 =?utf-8?B?Rm5QMFNlbU5SMjNaYk56OUZiYnFHaHJldjF0OGRaZUxFVDY5VjZWRThkakd1?=
 =?utf-8?B?N0FTMFJXUllZRlltVUVXNUFiYTJLYTVQaXhYLy9OUVFXekppL3hvRGxYV0Rx?=
 =?utf-8?B?ZXF5OHBBRC9wNjhrSjRLWUM2bnpxUW4yeFJ3dEZ1Q3E0RHZabS9xUmh2QnJV?=
 =?utf-8?B?OUhVS3JObU9sMjVsSHBybElXMng3ajUwZm9tZ3gxZlJLNHNyU05WRFVXenE5?=
 =?utf-8?B?RWwrbUVscDZyY2VraXYrZmtRajJIZlIrVGE3OUZST3krb1FhbVVDczgwblhn?=
 =?utf-8?B?U2pHT2s5RGw5M1c1ZUwwMWY5THUzZHBJUWwvL0pVcWtCVmhwdDdDVHJ4RG9p?=
 =?utf-8?B?WHdMSFYvc2tpeW1BQXNBS1JKTXo0WFlrSEgxbFhDTUdnNUtxek5jNUpRZnVK?=
 =?utf-8?B?eklYdGdPSFNaK2U5RlNRVHpuZzFpNTRBZHp0SVZHblFpbzhyNXhpd2FtWFlW?=
 =?utf-8?B?c1VKRnlhNnhQWHU5dUdpN0hjUnRXU0Uvb2ZZd2dOMkRxS2lOZ2szekJseEFp?=
 =?utf-8?B?TU9EMnQvSklGbForVElQTUVHMXhMZGZWc3dLdDNOdFF3WldMczBaOEVBMkRo?=
 =?utf-8?B?UXhYN253eXBSV0RyRXNmWDFhcVYvS0NXYUhzb24ranRHOGt1dTRuUlNXMTNj?=
 =?utf-8?B?ZGhaSzhuc3paeTdQYWtzcnMxNU1uZFlQS1pXUjB6ZW1LZk43bGdLKzdyNWh3?=
 =?utf-8?B?MVVhbVIyRmllL1IxSVFsOE9iN2lWOXZ3cUhWK2NzYy83NjltNGUzaVM4enN5?=
 =?utf-8?B?NGNkUWNsOHBRaEcwTDE1YnZhdEcvZGx0ZVhqZi9pN1diaGRYVTUyZ1BmS21F?=
 =?utf-8?B?SE90NGxhUmVLV0FOKzJtTDJ3a3ZkLytjcDRDMnUzR3pJeWR0cDJsUEw5bmZT?=
 =?utf-8?B?MW1LWS9Wem1OMStUQ1k4Z1hNM0hrUnI1QjE2TGZXMWlMU2NRV0NhcnhiU2l2?=
 =?utf-8?B?Q1h2Nk5JZUxGaE0wbnh5N2plYTg2U1FONWJFY0t5dXM4Q29DT2ZpSDhBa2pq?=
 =?utf-8?B?YVFXZ0NOenpBMzZaYTJPN1VnVE1UTUJheDViV0hKT3VDRENGdWpRd3c4cmgr?=
 =?utf-8?B?VysxOGNBQk5FRmF2QTRDTTg3cFRQVHd2ZlZKSm9LbW55OGo1WlBMR2NEVXB2?=
 =?utf-8?B?bzBQS2p2aXdUQXRIM0xDRVoydDU0VlpXbFBBWFpMbXRFZEhLNHUxbzhrQ1g4?=
 =?utf-8?B?SXUrODBhUlhWSkxocjFXRjB6VkhlUklSZ2JEMXgzVEpzVnhaMXl1dHhJc29s?=
 =?utf-8?B?VnFjTXM2Mlg0OEtVaTRlTHhNdHFnU2tic1luTEloOGg0SC9oTFRZaU9VcEtK?=
 =?utf-8?Q?RM4ZnlJ/A33qrKZUiFveDoY=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 5c6b65d1-d4f3-40dd-c950-08dd55c0ae8c
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Feb 2025 17:20:20.9133
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8ToOK6jPuWPolHuBPb4Np2/2g6XGwJFJuKdCT+kd8argyyRW7ES65O9vuke2cD0eAWzhzTf0YAvKTYL4rQC/nXQGUEVaV8QV2+pqnVWl5m0=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB8864
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=cpiHZ8WN;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.10 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-22 at 16:06:02 +0100, Andrey Konovalov wrote:
>On Fri, Feb 21, 2025 at 2:12=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> >Is there any reason we need this change for x86 SW_TAGS besides the
>> >optimization benefits?
>>
>> I wanted to have the shadow memory boundries aligned properly, to not wa=
ste page
>> table entries, so the memory map is more straight forward. This patch he=
lps with
>> that, I don't think it would have worked without it.
>
>Ok, I see - let's add this info into the commit message then.

Sure, but if you like the 0xffeffc0000000000 offset I'll just drop this par=
t.

>
>> >However, I just realized that this check is not entirely precise. When
>> >doing the memory-to-shadow mapping, the memory address always has its
>> >top byte set to 0xff: both the inlined compiler code and the outline
>> >KASAN code do this
>>
>> Do you mean that non-canonical addresses passed to kasan_mem_to_shadow()=
 will
>> map to the same space that the canonical version would map to?
>
>No, but non-canonical address are never passed to
>kasan_mem_to_shadow(): KASAN always resets the tag before calling this
>function.
>
>> What does that? Does the compiler do something more than is in
>> kasan_mem_to_shadow() when instrumenting functions?
>
>Same for the compiler, it always untags the pointer first [1].
>
>[1] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tra=
nsforms/Instrumentation/HWAddressSanitizer.cpp#L922
>
>> >                   Thus, the possible values a shadow address can
>> >take are the result of the memory-to-shadow mapping applied to
>> >[0xff00000000000000, 0xffffffffffffffff], not to the whole address
>> >space. So we can make this check more precise.
>>
>> In case my question above didn't lead to this: what happens to the rest =
of the
>> values if they get plugged into kasan_mem_to_shadow()?
>
>We will get some invalid addresses. But this should never happen in
>the first place.

Thanks for letting me know about the tag resets, that should make changing =
the
check in kasan_non_canonical_hook() easier.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/u=
up72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32%40t6fgaxcaw2oi.
