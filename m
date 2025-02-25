Return-Path: <kasan-dev+bncBCMMDDFSWYCBBZPV666QMGQEK2NI5FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F589A447A4
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 18:16:24 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-38f44be93a8sf2992565f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 09:16:24 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740503783; x=1741108583; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H4cZlYHVyNQAxf9NlW0Z8OXNzFf5Z0NhZodVHPNhpv8=;
        b=KegJcHXCpnn3L8kzuSwwABBbROhGKOI55TRlK4AKI5E8bdAfseD6JCGlKmB08+iRcL
         yuDERrGQn76gcd8GS+zsXMq1RMQycMMBwSgiGkmXxEwQvU6K3Jtx1B35+iiX0UU4eHg9
         tmc85EpBWd1sSRHXffY9tKhcHpxgD/9R5ET7bPirrgSKv6JFCn+8gxw1R5k+2MZfKJ3C
         9RJaG8u8uuabWQMteF3EcSH2MewH5sPSu4D8UQ4hULrOFuzUfMccaFjBTbU79Amull8P
         uLU3qeJClB9ouULIn1zWHmQuW28plXk2sQ0ITzfpLwInLYDy83ipZJolkC+YJouZHcsE
         2a3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740503783; x=1741108583;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H4cZlYHVyNQAxf9NlW0Z8OXNzFf5Z0NhZodVHPNhpv8=;
        b=rXvp5IhAg1R5/XE2D/AmxHCYGFLkkfwd3fvjxUg/p+FzGNOqQeOtGLBChYqzgOxtxO
         siK9tg0rqz+Pc5KaxE659GEB+5D0eWuf/olQx5KajeXY2HDczekxmY+ZjdSIEbEpKUQc
         rmeA0Ay/ixVfI4iT3FlTeO1UFKMBaQYF4kD0/gG0zkeYW5/u5dT1k13sFukAkKtZ89yI
         +KUufEH9zg0pYr34IfvUUxDDI2KXBy7ri7KtSa+1zj0x3cmwnswszajoNp/NGBtCVXza
         CSPhQ6cRvKTCw6K6l8nVbBbZHUfQfgIFmT3VZppc9rOfXRlEJlE5/xB6BX+9v/f/aRP1
         jAvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWCkTskAS4GcMHhDpZRRTqDtDp6r5QtQu5uJ6qLIzFeiOmHvlcswMsq2t62yAr/SfqV0uLW8w==@lfdr.de
X-Gm-Message-State: AOJu0YxulvuirwrXCjrrOr4/MYA6Q6N41RZIBkqyTPb530aWP1Jo17xr
	Ah7bXhSLcbmvGAD9PNb2v7sPW5QWAYzcBSQM9vJzbq4PRi4vxVLU
X-Google-Smtp-Source: AGHT+IEyZYyqtOYmaOPzDeiwGmk+CGq7QP9EhecXxbiOleNg2F12JF/99JRca704FZ1PTPp2/9pSRw==
X-Received: by 2002:a05:6000:1843:b0:38d:e078:43a0 with SMTP id ffacd0b85a97d-390d4f84922mr59759f8f.38.1740503782003;
        Tue, 25 Feb 2025 09:16:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFqJN8PHRUBXh4STTF3VKDNfWBwHsNpB5Jaj2PNZpXbKg==
Received: by 2002:a05:600c:304c:b0:439:ad97:3e41 with SMTP id
 5b1f17b1804b1-43ab93fa5cels87055e9.0.-pod-prod-08-eu; Tue, 25 Feb 2025
 09:16:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7R7EYFiAx+Hdiez3a58BM4ki2L9h1z3hYbQWTp9Ea5R7F4J6i2gXOX5bEjCn7F4bU7pvdiRi1wDU=@googlegroups.com
X-Received: by 2002:a05:600c:3b93:b0:439:7b5e:820a with SMTP id 5b1f17b1804b1-43ab8fdcac1mr3873755e9.11.1740503779549;
        Tue, 25 Feb 2025 09:16:19 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.13])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390cd8d7368si103437f8f.3.2025.02.25.09.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 25 Feb 2025 09:16:19 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.13 as permitted sender) client-ip=198.175.65.13;
X-CSE-ConnectionGUID: a/SzrmRgSuas3oR/m3Y6FA==
X-CSE-MsgGUID: caFl8IypRmCBf8vX7H8xrQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11356"; a="52320067"
X-IronPort-AV: E=Sophos;i="6.13,314,1732608000"; 
   d="scan'208";a="52320067"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by orvoesa105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Feb 2025 09:16:16 -0800
X-CSE-ConnectionGUID: tTIGqqffRcePwPwKqO4qaA==
X-CSE-MsgGUID: oB9N0/5HR6uBNw0a3Cja6A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,314,1732608000"; 
   d="scan'208";a="121061741"
Received: from orsmsx902.amr.corp.intel.com ([10.22.229.24])
  by fmviesa005.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Feb 2025 09:16:13 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX902.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Tue, 25 Feb 2025 09:16:12 -0800
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Tue, 25 Feb 2025 09:16:12 -0800
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (104.47.66.43) by
 edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Tue, 25 Feb 2025 09:16:12 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=gsxUZsvyRe2IrfKP78ZnESso2J3sxNmsM537jQlaoW5/H6E35gp1kih6JSA9VwT5n9k1qMBz7A4Z6+x/3oJs2+a4gzygvNX0+k/S/do4wGsOkxFCAeBUyv6GbWmjyWdYgzzJEuKjP1IxS4vE4ymAB4FAzKqkbXk4PxmrqbB0hVkW1SuBmtUgDGLRy1DacPc3RZvicmzGOH4w0/6hRdHV5JfmjttyPlLoLbH440wVeMjMZi7fPW+8nBBIU2zlldZMtyLkS1yNWBnCf8uZv+Jlq+9F3zHIH3txrrx0488njvltazd6NrRT1VSf4AfZzmGIj+dbG9oCvxUZeJSMhgZzwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=CYdQUc4W3E0jEX9rH4QwVN0saR32zGHdq6c2NCUWUVQ=;
 b=ZxT3ssY5/Zt7fnhyNqlAhXihH9srASt0x9yXtYrxuxK816yV1IkdImuEtdtLKcFwfQCI3bEIoZQPimyuxQq2qhQCujI2rx7OMpVQoloBLuBb73vWtO2ffThrwT42OIgJOGoQFpB31wzb4nihSYksKsCrIM8RMBiNYbEpQGyLZWJ++yUREZiTf065I7qkpKLnYen0iAfRSjfVi/9gAZJ2nh+IgKt+EpfMOe5L+zSoH3LGxLohgkzkO07eaBXSTI/vPdxNVmUut02AiRF65ncwcwPzMOCrL0ntPGWfAr9vTOyGrjB/MiEPyH+JpG95CLogYMAOYOb8gmzXV7uXkn3pYQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by BL4PR11MB8872.namprd11.prod.outlook.com (2603:10b6:208:5a8::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.20; Tue, 25 Feb
 2025 17:16:08 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8466.016; Tue, 25 Feb 2025
 17:16:08 +0000
Date: Tue, 25 Feb 2025 18:15:27 +0100
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
Message-ID: <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
 <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
X-ClientProxiedBy: DU7P250CA0017.EURP250.PROD.OUTLOOK.COM
 (2603:10a6:10:54f::20) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|BL4PR11MB8872:EE_
X-MS-Office365-Filtering-Correlation-Id: c9c4d76a-5c14-4c0f-7574-08dd55c01832
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?bEVPL08vYUU2ZHQzTHY4WDVJMlV0NEZMcHkyV1NsNWNJSXhNdzZ0aEFOTldN?=
 =?utf-8?B?YjVrVjdyUjl5QnZMVXdDOTNpTVFFQ0orSjBZSzExZkVIT2ZCa2VJdnFweWtL?=
 =?utf-8?B?VTJRb3VyK2FjR2JncXhHRFEzS1pKaFNSMFd6ckxzRDA3bmw1eFYwZDVnQUc5?=
 =?utf-8?B?VVFtQmhpakNndzZXcEFIdzRlaWsrODU5YTdvVWM4TWpGTU1mQVRXZUt0ZmlK?=
 =?utf-8?B?YnNNVkV5TVJHN1creDIxMnRDZnZTM0NiQ1Z5Y09IMnZPQ05EZzB3TWRCbHVl?=
 =?utf-8?B?dTBlRlZGR3RMWDNVdUVRMDEzOUY1a1YrQ0NIK0RxQzRTQ05ReE5vNFpvQ05z?=
 =?utf-8?B?NzhWT1VxZkE4bE1qZVlOMDl5cEtQcTBXejhWK1FFS1VBTU14S3hpT04zUW1r?=
 =?utf-8?B?TDZDcEZRVEpSMDVndDFHMTR3YkNOUmFHaGpvMjVBdXV2VVFRZ2g2eWw1bEFo?=
 =?utf-8?B?R0NWaGlKay9XTEV6ek9MeHZPOFpKcThnVmlTR25PSmJYZFQ5ZlRHTDAvZHlk?=
 =?utf-8?B?bFYxMjBWVWNhbk1uNkJaNDhDR2IrQnFwK2IwZ0NKVENiZDJFQW4yQWFTS3ZU?=
 =?utf-8?B?RzZNZ2xldlJMQmFUMXd3SlF6Q0ZiOGZ4c1NmMEJJeGVTZEV0S1RNU1J5aFll?=
 =?utf-8?B?bkREUy9lUGFlWTdmVzJqYlUxU3k4UFdwQy8wUUR0OWxObjRpN2tUc0dUclll?=
 =?utf-8?B?QVhoWS9UYzJvZ1ViQ0Y0T0dYYlpEaWJreTRmS1pUbnhGbWt0eHVDb1NtNlkr?=
 =?utf-8?B?YWg4ejZQb0NJWGJLSUJmTi8vV1hRVGpTNjgwS3BybnkzbHNabldHL3AyZjNH?=
 =?utf-8?B?UUFUeVVyYUFkdkVmVmQwWXR0WTl0QWlmSXdCR1FVWGNNaTlQNVdSZkhmR2c2?=
 =?utf-8?B?Ry9ZWGFLOFVyTkZlRUlneFY0ZlpaMGtFVGpWQ0ViYVZyUkVtMlljeWZ6K29h?=
 =?utf-8?B?Z1ZCejd5d2JvbkhWTkdKaXlJUWdDQlNnWnFDam81RHBRQzdqSUdocHRGVDNB?=
 =?utf-8?B?MjlrSURBaFJXWXRwSGxWWG9UT2RrU1Z3K09yTWNTVlNOQ3ZSenJuOVFTUkdl?=
 =?utf-8?B?UC9mT2wzdG96WUdnMXZicVFaOTVabEM5SEJzMU1uYURsNlB5QWJmTVBzNDBw?=
 =?utf-8?B?ajB1eU1nMGtSSGYySkl0V05QTmpRemVZL202aFhhNUpMMTZGY3VkZFJMVXpo?=
 =?utf-8?B?QlBub3dreStzL1UzNG9qemMvaWpqakdEZUFqNDJkQ0UwN1FtOHRnMmdUNTUv?=
 =?utf-8?B?T2txMy90R2VOVWY5eHNaRHNDRm1DQ0R2S3Z5TFlDL0Zsbk4ySDVQN2ErdXkz?=
 =?utf-8?B?bkhmUVZYSStuMklNbTN0cDhFanpNOC9ENTk4OExjeldiTjA5YlZZaFBVbHJN?=
 =?utf-8?B?T1JNM0tWQlZ3Mk9kRXFLTkdlQmxyMVBhbDVqV1VnL05VM1N6ckRUZ0w2OTdK?=
 =?utf-8?B?WndCNGoyNTVpb0g2czMrRlNWcStCYktMWE5lc1JGWFppRE1TS25mRUM3ZTRU?=
 =?utf-8?B?VGdEUjJBdWxBM0twNmdqQmJvdGxRbmdEVktKYmFmWWZZZWtGYkVKc1o1YlBD?=
 =?utf-8?B?YXNPMjhlNkYvVnVEQS9EYlErOW9FVVFNY1FjcDBmd0RQcTNOVkZHQzJ3b3Zi?=
 =?utf-8?B?N3UrSGpYZ3FSS3RKeG5HaVhjTkw1amRiN1lvNzlRaDgzdzNNL3B3cWxvYTRY?=
 =?utf-8?B?S2FYWHVUWVRJaUlqSktVcERNRWRhUi9talVRdTNSa0x1R2pHNnExOC9oNHJj?=
 =?utf-8?B?SW8zQ1hZb3J4a2xiSmJTYW5DQXYvcWdaOUZoQTdMdlU3N3hUQ2JHcEhFSnZK?=
 =?utf-8?B?VlhBMHkrcTVhN2tNNldTdz09?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?UGpkdTRaS1FoT0RrWHpjZFNsanJxbU9IOHprZm5vR3RGcXd4R1RtRXBVQmlp?=
 =?utf-8?B?VFMzYUZJcXIrK3owN3lWN3pGbkRiVU5jRWdibmY5dDMydWF4Q1NEdXFPQWpF?=
 =?utf-8?B?d2ZlYVYxWVFxOUZkMVZrdGYrUHNCNU9Damlad0JLT0hKYjJuVXNONUxsaWw0?=
 =?utf-8?B?amU0SGkvZzc5eGpxNnJheUo3RjdjLytNK2JPVVM3OFROZk4zZ1NjRFNMUU82?=
 =?utf-8?B?bmREYVMvOWlHOEZyNnZTaG9hV1phUUtNRWk5dnJLSUc2N2wvUFN2N2xqUWtL?=
 =?utf-8?B?dlhlb3UyTnZaRHZzK21hUExta2N5RFp6WTl6MzNveGVmSlE2RHNnTzArVGxh?=
 =?utf-8?B?N3RHazdWeHRRRVVRQkY1azYrMzNuTDlSNVFyY1FxRjZzVWhlNkJsRmxJK1RP?=
 =?utf-8?B?SVkwOVdNMzRBTW41KzBPSm96QVNPUUE3eFRMUHExeTZlYUhBWVJxSmtqNS9G?=
 =?utf-8?B?UVh2Vkc4eDdsY1hkMUJ0Yno4VTFWWGZaVG5WbmtWUHROSDV6U2lSNHIyMFY0?=
 =?utf-8?B?MHdnZ3VEaGo4b3ZRcjJ0QnBNQ1llbWNINEVhWk9UdytBQXpzditjMEcrcjNp?=
 =?utf-8?B?WXd6OGEzM3EyZXdFZEhLZ1VodjdTNFRsMlpneDJMNUFUY0VLVGxNZ0xiSTJ4?=
 =?utf-8?B?MXB0TVJBaDl2YXJPVXc2VUVFTEpUY055SHVmNjRYNS9FaldDZHF4eHlqRnBj?=
 =?utf-8?B?YTE5dmQxc3BuekxsNWFycFlaOHNlckJ5ZVZWck1wNmU5UDNhaWpWZVF5Vmo1?=
 =?utf-8?B?b2tiV0c4Wk5XcXh4ZHRDajJGTlU0SUZaZGNCamRnaDdidUp1dUVGaytXeWdX?=
 =?utf-8?B?RUk0WnlFdC90cjNIcENzKzkyRjZETEw0dXRvbmxnaXB1QlRUVi95TFE4Qitl?=
 =?utf-8?B?cU5WRi9KVE5rUDVUdzlmVGNpZiszblZpd1JyajVUTFNWbnloekZuR1Z3YWx1?=
 =?utf-8?B?L0cySDBsdUNzSHMxRnNXdkdPRGJLMnRteGpuVXBtcHIyUEhoaUdCYWc3Ynlq?=
 =?utf-8?B?YXZTT2hhVzlFZzdtSjd0QVB3Z3pkK0FocHQ5Q2ZiRUNya01LTzdPOWZvQWhw?=
 =?utf-8?B?b2pzQUtqMXlLZXBiRkl5MndEcWpOTmVaVEMvY1VLRlFVOUlseEpRTXNrNmlZ?=
 =?utf-8?B?RngxK0JjTmlnWGxtTWhMQ3g4cnpvVUxCUThGRHM1UzJWRTgxbkx4djhMU0Nn?=
 =?utf-8?B?aU9nR0NDckkwMEcxeWRlTW1wRG5QeGpoYlZ6SEVaekpLaGV1R203Uk1BYUNs?=
 =?utf-8?B?bHRIVXRoR3pEb2hqdWFoU3dkNzNoMEFKTGNhWVBKQ0l4WTFiL2duWnM1amlm?=
 =?utf-8?B?UnIzRlJtcGk2Zm5XbW0xN29UNTNwSVlZSXdRb2lCODlZVnowYmk4bUxGSm15?=
 =?utf-8?B?TTVZdUd2U0F6L0k4NVNRRmczbExsVmNUMXRoeXNNcEIzd1ZpMDQyV0VhOUFK?=
 =?utf-8?B?M1dHYkNtSllhVlE2ZVA3NWppYkxMWmZvS05FLzZpa09xY001aWkrYnozZnUx?=
 =?utf-8?B?STFHZVZtaG9uaUlqL2xWU29iUXV3WmkvbkxYbXBYUHBNWmRFNkZqZmd6Q1ND?=
 =?utf-8?B?T204UlhVUUNUbTduamJEN3FnZEZPdmZBRW9xUGtOV0RObFQ2T3FndUpVVDZL?=
 =?utf-8?B?QTdCNUpLZ003TWhxandZWlJaQU1ZNWUyTDNzd1VMbDRZbFlTNVVJbHpoWitO?=
 =?utf-8?B?OFZ1dTVZbFp0MW5yZFdQT1lEUlJVc2NzNUNSd3gvZUFwTHRWYldmM2s2NHVv?=
 =?utf-8?B?a2lMdDcrMzVIdHYvd3h4WVltTXVtU1FkMWJqVW5HQzlsZnMzb0pKVTBVTVZi?=
 =?utf-8?B?Rm5jY01XTWtMMDJaOVlZdEFoS20yUk9jTnFBUVFML2NMOXZDS1kxZTJ5MHUr?=
 =?utf-8?B?N1NNaUUvaTVYZ3dOdCtEb256ZHU0eUpKWk9iQkowUWlWWDhwcytTanVoZ00v?=
 =?utf-8?B?VUVMS1J5MEo1bUFMRzdLZW5kRG15NHFlZU9iZytnYzIyTk1pSEhvSzlLVFF4?=
 =?utf-8?B?SGpnRFFtQmtWbVdvQ3N4aUZEVnY1K05odmZ3RDhDYVh2MmhQOVJ4TzlKS0pI?=
 =?utf-8?B?QmsrVUw4Tnk5UHFBdktKa0pMeVBUQXJrT2tYUUg3Q1FNOE9HYWlhekFJUFBZ?=
 =?utf-8?B?Qk9rMitXRFZzbzJuUG5PUmdkTi9KSVp5Ty9OUW1XaEdVNVcyUGhaTmg1eHNH?=
 =?utf-8?Q?DMxSdeGGFi9u5aTi3WZl6rg=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: c9c4d76a-5c14-4c0f-7574-08dd55c01832
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Feb 2025 17:16:08.7572
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: mix8vEUzIPdUGC3yg7NIM8ULeej/GCcj1Gxtd3wEjOLGT6PBVD/i9aH9gHgvSHdjws9Wi0WrGSuvqMjSKmqnEB8rHVVlkkeXjLZMg1wH4ts=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BL4PR11MB8872
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Eoyd8eCJ;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.13 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-22 at 16:07:20 +0100, Andrey Konovalov wrote:
>On Fri, Feb 21, 2025 at 4:11=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> On 2025-02-20 at 00:31:08 +0100, Andrey Konovalov wrote:
>> >On Tue, Feb 18, 2025 at 9:20=E2=80=AFAM Maciej Wieczor-Retman
>> ><maciej.wieczor-retman@intel.com> wrote:
>> >>
>> >> On x86, generic KASAN is setup in a way that needs a single
>> >> KASAN_SHADOW_OFFSET value for both 4 and 5 level paging. It's require=
d
>> >> to facilitate boot time switching and it's a compiler ABI so it can't=
 be
>> >> changed during runtime.
>> >>
>> >> Software tag-based mode doesn't tie shadow start and end to any linea=
r
>> >> addresses as part of the compiler ABI so it can be changed during
>> >> runtime.
>> >
>> >KASAN_SHADOW_OFFSET is passed to the compiler via
>> >hwasan-mapping-offset, see scripts/Makefile.kasan (for the INLINE
>> >mode). So while we can change its value, it has to be known at compile
>> >time. So I don't think using a runtime constant would work.
>>
>> I don't know about arm64, but this doesn't seem to work right now on x86=
.
>
>You mean it _does_ seem to work? Or otherwise if runtime constant
>doesn't work on x86, then we shouldn't use it?

I mean in my tests, with setting offset in runtime, everything works correc=
tly
in inline mode. Even though hwasan-mapping-offset ends up empty and doesn't=
 end
up in CFLAGS_KASAN. I assume this means that the inline mode is pretty much=
 the
same as outline mode with the runtime offset setting?

I also tested if hwasan-mapping-offset does anything if I passed random val=
ues
to it by hardcoding them in the makefile and still everything seemed to wor=
k
just fine. Therefore I assumed that this option doesn't have any effect on =
x86.

>
>> I
>> think I recall that hwasan-mapping-offset isn't implemented on the x86 L=
LVM or
>> something like that? I'm sure I saw some note about it a while ago on th=
e
>> internet but I couldn't find it today.
>
>In LLVM sources, ShadowBase gets calculated [1] based on
>Mapping.Offset [2], which is in turn taken [3] from
>hwasan-mapping-offset [4]. And then ShadowBase is used to calculate
>[5] the shadow memory address.
>
>All of this happens in the common code, so this should affect both x86
>and arm64.
>
>[1] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tra=
nsforms/Instrumentation/HWAddressSanitizer.cpp#L1305
>[2] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tra=
nsforms/Instrumentation/HWAddressSanitizer.cpp#L761
>[3] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tra=
nsforms/Instrumentation/HWAddressSanitizer.cpp#L1863
>[4] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tra=
nsforms/Instrumentation/HWAddressSanitizer.cpp#L171
>[5] https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Tra=
nsforms/Instrumentation/HWAddressSanitizer.cpp#L899

Hmm indeed it does. Then I'm not sure why I didn't crash when I started put=
ting
in random variables. I'll dive into assembly and see what's up in there.

>
>>
>> Anyway if KASAN_SHADOW_OFFSET is not set at compile time it defaults to =
nothing
>> and just doesn't get passed into kasan-params a few lines below. I assum=
e that
>> result seems a little too makeshift for runtime const to make sense here=
?
>
>Sorry, I don't understand this question.
>
>If hwasan-mapping-offset is not set properly, then in the inline
>instrumentation mode, the compiler won't generate the right
>instructions to calculate the shadow memory address.

I meant that if we end up with "hwasan-mapping-offset=3D" because
$(KASAN_SHADOW_OFFSET) didn't return anything, then
$(call check-args, cc-param, $(kasan_params)) drops hwasan-mapping-offset a=
nd
doesn't pass it to CFLAGS_KASAN. So I guess then it isn't an issue for the
compiler and inline mode is essentially outline mode.

But anyway I have an idea how to setup the x86 offset for tag-based mode so=
 it
works for both paging modes. I did some testing and value
	0xffeffc0000000000
seems to work fine and has at least some of the benefits I was hoping for w=
hen
doing the runtime_const thing. It works in both paging modes because in 5 l=
evels
it's just a little bit below the 0xffe0000000000000 that I was thinking abo=
ut
first and in 4 levels, because of LAM, it becomes 0xfffffc0000000000 (becau=
se in
4 level paging bits 62:48 are masked from address translation. So it's the =
same
as the end of generic mode shadow memory space.

The alignment doesn't fit the shadow memory size so it's not optimal but I'=
m not
sure it can be if we want to have the inline mode and python scripts workin=
g at
the same time. At the very least I think the KASAN_SHADOW_END won't collide=
 with
other things in the tab-based mode in 5 level paging mode, so no extra step=
s are
needed (arch/x86/mm/kasan_init_64.c in kasan_init()).

Do you see any problems with this offset for x86 tag-based mode?


Btw I think kasan_check_range() can be optimized on x86 if we use
addr_has_metadata() that doesn't use KASAN_SHADOW_START. Getting rid of it =
from
the implementation will remove pgtable_l5_enabled() which is pretty slow so
kasan_check_range() which is called a lot would probably work much faster.
Do you see any way in which addr_has_metadata() will make sense but won't u=
se
KASAN_SHADOW_START? Every one of my ideas ends up using pgtable_l5_enabled(=
)
because the metadata can have 6 or 15 bits depending on paging level.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/u=
ov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv%40ztvxz235oggw.
