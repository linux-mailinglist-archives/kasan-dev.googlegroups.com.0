Return-Path: <kasan-dev+bncBCMMDDFSWYCBBN5XQG7AMGQES3TNQDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 52340A47DD1
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2025 13:34:01 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6e65a429164sf17591846d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2025 04:34:01 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740659640; x=1741264440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UajRJXNAwzMn6A3R9IWQ/NEh7a0aUQjZ5YsH4ebdgmY=;
        b=BO9OfQraYN/Ap5PaLahL1IYlNUJD/lGtFuKax7Md3oCMyWRs+NVDFA8tc48/EPLOQv
         rH21A9BQjaH9PRQu2djZEbd1nvK76AoA4AEVwK9cfKP9MxPXPTnVOpb7zYAApTYqW9j1
         JSDTLHzWci7C/xG+/SzJ6DvdL6RyhG5GiEyTwb39fYN9K11X0y5eeMGuRAtbaMMqon9l
         K+w127B2ftkhvFZgdFQibOwfC5rs0oi0aDz6kvONdUxXOGZXcAcjFPeb/tdAPfHQdI1V
         BdxYh5vGFWGNQihnBzcTzhjRMXh4vKnZHPd1mVaiL0ML6/Rf9UiyrMQlnN8XjnuqwT3N
         1Bzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740659640; x=1741264440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UajRJXNAwzMn6A3R9IWQ/NEh7a0aUQjZ5YsH4ebdgmY=;
        b=wxdx2gohtITzSN0ma1wk4rFtioizPiheb5ohiHYecmxcFawDs+2H8Ooy1rp8RdfkJt
         y/yyCQBZjvIYcIWZCJRGM3vrLgKq7RlvnkRwPzoLS9MfY+2Vpy2VD2gAx1EdTvo5pGqs
         Cq+8O2e7TwFs7owP/nYuU0T14WYF+R5Vtwx6f/VDPJhK7hKb41a6k4HO4GrpH99EFrlR
         XEZYAy4qciGFqrwfaXPFfrgLyowyPDDji3n5cPT17wls++RrtWHUxsXpqGp+aA+X1D4x
         ECgeYx4bRtTBkZImXeZmRi7RS62QDEYoFGoIVJ0bnEQlPBhIBukZl2AyDWwjOXjdYYqg
         ucHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnr0eUsSYlNeLTmUPYXGTWSyr1mz3Cb89T2/zUDkcpSn672qpKCrHwos4bpmsXAvI6S5ufSw==@lfdr.de
X-Gm-Message-State: AOJu0Yysg3bqxO/siSr3lOMbMcRI4w82ckpecm3WiTAKc95tRXeSdx9/
	U7Dg8LM65YY3V4cs2k3q4yNNTFlgDPyKB0EmePFFs9EQWjTdnZ7S
X-Google-Smtp-Source: AGHT+IFqxmAStxmh6RAZ+j74a3MSczjyoIaHN6m6ChTN5PDdfDNbJHXL2/ESbFi4X6Xp4FoTx7HBlA==
X-Received: by 2002:a05:6214:d0d:b0:6e6:65df:557a with SMTP id 6a1803df08f44-6e6b01a9d9dmr309474476d6.31.1740659639804;
        Thu, 27 Feb 2025 04:33:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHH+4VvDY5LSI5vZMY3RTzLvSm2ne7KN/3jte7XzUG9WQ==
Received: by 2002:a0c:fc0b:0:b0:6d8:89a6:8447 with SMTP id 6a1803df08f44-6e895522737ls12480646d6.0.-pod-prod-02-us;
 Thu, 27 Feb 2025 04:33:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU0WGk1hXfyUqmQMDMv9x7cUp+1DQ1pfLr5n7eTLUeAYioJOTUHwQ+9RFa/Qj54UIo+EXb97fQuaEY=@googlegroups.com
X-Received: by 2002:a05:6214:21e2:b0:6d3:f1ff:f8d6 with SMTP id 6a1803df08f44-6e6b01d8fe2mr335883966d6.40.1740659638921;
        Thu, 27 Feb 2025 04:33:58 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6e8976cdc8esi595286d6.7.2025.02.27.04.33.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 27 Feb 2025 04:33:58 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: nGuEY2uCTGCScXjqZHe43w==
X-CSE-MsgGUID: AzFB9Gq3Suq5MOxyUcuVRg==
X-IronPort-AV: E=McAfee;i="6700,10204,11358"; a="41249271"
X-IronPort-AV: E=Sophos;i="6.13,319,1732608000"; 
   d="scan'208";a="41249271"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Feb 2025 04:33:56 -0800
X-CSE-ConnectionGUID: ueDpfij4TKSQbep4BQdWqA==
X-CSE-MsgGUID: riJ3aPadSbG6k1S0Db1h6w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="116883006"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by orviesa010.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Feb 2025 04:33:57 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Thu, 27 Feb 2025 04:33:56 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Thu, 27 Feb 2025 04:33:56 -0800
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (104.47.59.174)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Thu, 27 Feb 2025 04:33:55 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=P2kT4q7oRtqkxzdYkyi+XeBjARdR6jwI6PiHunEO1xgxGGDeJy6xWNQyYi9TG2fr8ikDeiGEwSU1usVKpAALnJHXCl03CIFk8yaM2DwFM9mvCDpXo/WFSkEJp5xNhiWwV6bW8wN1QwN7jHw/NGaBfL62Mzzg6RObQATvP4RQhXjDJXtVLoAnJl72zGPmPRh3LBvqRX0DL5IzChL2NqYyID5I8NsDGJCwJhundcGZ2EUVizx3BL/3/DgkKfDC/cGuE4FyyNGs+PajwVCTDmVcQTSnYpBe/0lQGsrmMfvHswhJGHR4bz71xAL6v5SKtIhYp1gPERMtNCZoo6pJyTxVdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SL5R9LpZbsSvpMhI2ugK9++veE7grfo0muZEh2HWxLs=;
 b=SSmOrX76V5lSDJCtS4u8GF0S4pQEAOyYg+Fuxv/wL9YB9mqFthh/4joZbr3kYXVvgANmb2VBeWe8cvNWYXyeqfMePbS18/Kykir46LbchNadbFkHmRR3WL6lsdTQXRB1mUqRU8F28/+Uuu1uQwAJTrbNkz28ZBD1IaEwbSoUAIZHIHVVW7DWM9o9yJun8WqWOSnXqFahMBv9NKLHpJr6tXyQALiGmQE9mGCV4LR4dpiooMfwqY4m7hNNmBtbk0ID2b1LGihz2dMxXuXU6y14zoKQkl4TQc+Z5TA3mMqf8DdWph3lXBI7X1eNNSWkF8UMQ3aDSwBSfx2DOB3Yq82igw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by PH7PR11MB5941.namprd11.prod.outlook.com (2603:10b6:510:13d::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.19; Thu, 27 Feb
 2025 12:33:23 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8489.018; Thu, 27 Feb 2025
 12:33:23 +0000
Date: Thu, 27 Feb 2025 13:33:10 +0100
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
Message-ID: <paotjsjnoezcdjj57dsy3ufuneezmlxbc3zk3ebfzuiq722kz2@6vhollkdhul7>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <CA+fCnZfb_cF1gbASZsi6Th_zDwXqu4KMtRUDxbsyfnyCfyUGfQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfb_cF1gbASZsi6Th_zDwXqu4KMtRUDxbsyfnyCfyUGfQ@mail.gmail.com>
X-ClientProxiedBy: DB8PR06CA0037.eurprd06.prod.outlook.com
 (2603:10a6:10:120::11) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|PH7PR11MB5941:EE_
X-MS-Office365-Filtering-Correlation-Id: ec4e0211-ee68-4895-fe5b-08dd572aed16
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?TkpLL3dNVGplcllOSDhvcEltcVVNNXBrbkJBWGJvK2JvOU95eXJ0elpVcDZP?=
 =?utf-8?B?cCtFYWR2TzN4cmx6NWhqd2dJd1d0ekV4dHRNYWFNOWlRZ1NjL0oyZ0pWMjJr?=
 =?utf-8?B?SHpGTWRBVTdOcGI1ejAvQ0ZNQkpHalpHQ0RNemdYQmZmSHh1LzgrTllEN25M?=
 =?utf-8?B?d01yamgrZGx1WGltL0Rqc3lCRUNRMHJ2L3BGZ2YvWXBJaWgzd01XYXRHdG5q?=
 =?utf-8?B?eWh2OU1qS0MwbjBnZGZzTW1BRzVrd3hLcS9saW81N0g2R0pBamZ2cWlxa3lU?=
 =?utf-8?B?SVBzRWRQaUZPaGpZcU1Yb2VtRkRSMnZzOTBxVzYybE1VVERvWW5lQjhpN09r?=
 =?utf-8?B?T1JTWnFoY24wd2lmVzlaZ09iN2ptQ3ZEbTR0RG44TUpObzU4VVFxekNKSU15?=
 =?utf-8?B?a25hT3prSG5GL2tCSkxIUUgwbkFNVTlrRy9yVFJjVG9KYkhGZE1jRzFoUjBm?=
 =?utf-8?B?K2pLbG5tRGR6N3FDZ3BQaGtDcE5ndjNFTm10OHY0cU5DOEwxV203dWRsYVZl?=
 =?utf-8?B?UnJPZXE5M290M1lJTnhrQlN2NVhJT3RvaVlOa3Q2U3RUU09OZ0FaTnU1UDJW?=
 =?utf-8?B?UEZOcGY5VEdvbk5kcFU4aWxqejZTbVh0MUZ3UHpYZmpKUjIrd3BFZUVGNHcx?=
 =?utf-8?B?cjBJRDdNMDRDUlhXQm5DYTNGZjhEWXJTVVpxUjg1Y0lveDNIRG02dG0vS2l0?=
 =?utf-8?B?S2dPNktPdnYrVG5IVWRsWVQ5dS8zMTRxZHVYR1ZKU3M1bm5BZUgvNEUySFd1?=
 =?utf-8?B?MWJ4UEQzNkdueXlHU0htK2dkVVAvRXB5YnlveGhyL3hqL2hNMzBKZm9xZlFG?=
 =?utf-8?B?VFRpd0RYRUxSaEpaZUgrODFCUGlaUmZQYzBiZFFaZUJWRVkxNW1Kc1BhZmlQ?=
 =?utf-8?B?TmJmdWRIL3gwTlpFejZhcklkZm5kbEFKQ3dxbTNuSUNLSC9IK29tWTlJTG5K?=
 =?utf-8?B?czRrRWFidGFWS3BJdy9RK01PajA3QjZjSk42bkVBK3prZWdxVnR0cjNCRGo5?=
 =?utf-8?B?WVdYaGJQeFRPcnZmMDhSZG9Lakg0THA2YnR4ZmF2cjlGaFVIYmZFSmx0SG9B?=
 =?utf-8?B?Y1BsR1hRWXhmaHZJdEYyekg4KzE2bWNzWUEvRll2cjVRZHh1TVdjTm00WGJ4?=
 =?utf-8?B?RlQ3UGxMVytYM1dXTEhHYTZnOWhxSVVrVW1tWmZlRGJlRW1tVlVKbW5VNFNa?=
 =?utf-8?B?TktzejBLSjhKMEFiMlYwY3dWem1JbllMbE9kMEp6bk5lSTl6M0E1WWsrUDZl?=
 =?utf-8?B?YTF6QmpxQXRucnAvcy81bEtXU2dRWFdZNVMzTkVtT3F0dU5UNVdaQmNRajdu?=
 =?utf-8?B?VW1UQVpRNXg1ZTV6ekFBTXdBa3lld2VLUVl0NWxReW5PczNGdkhWeGhub2tk?=
 =?utf-8?B?TDZVUTJlNkNrVHJKNFM5ZmZCZWk5RTZsSWVqMnpVOHFYSkhxdWZkRHlhWDBw?=
 =?utf-8?B?dVdsRnlWQnEzVG5wT1JuM25qS3luK2xwMjZmWWR6dnZiSElxK1hyZDdBbG41?=
 =?utf-8?B?VHNPN21sNE9KL0puUmNLeEdPTUFxeXZ1K0hLVE1UdTk3NG9uNUovamsvdjhn?=
 =?utf-8?B?SE1Ua1FRZk9JcGZCeDNuMERTWUF0eGV0cjYyOUFwcC9rQ0Ixd1drU3BMK1px?=
 =?utf-8?B?emJoMDM3KzZqeDB5cmlHbnRnaGd0dS9MWkE2N0ZsZkluM0FycFkyVG5oczhx?=
 =?utf-8?B?N2wwamlvNzR4VHVoM2NGeWRmaFNhcnpqNjUwRFh4dGt3MXV2RzRPSDRlQlBq?=
 =?utf-8?B?SktMYzdTS0pyb1hBMTlUVTlzTk8wV2l4dnM3MVJuN1haejByYWZya1pFRVNk?=
 =?utf-8?B?OVNJUnFhWGpGdkxVbnBmTXNZejQyTGFXYkRPdEMxTktmb2cwb2UxcGZ2eHh2?=
 =?utf-8?Q?5Qm5aqlujeUwf?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?UTZhZ0ZNMWU3djJMYlhiV0xRVnU3dk0zTUI0WTdFcnp6dGtRQ0crWG56aXIw?=
 =?utf-8?B?aUliczltYktkOVJVNGpYZzlkM2J3OExpQjdVRlRDcmkrR3Z2UGd0NzVUVXAx?=
 =?utf-8?B?WTlSTWp4VTRRRis3VjdkeHF2VFdzUlg4ZjBqdmVoVDdOTUcwbEUwUmFFSlpw?=
 =?utf-8?B?Qi9IbS8ycEtuUVlncDVHTGovQkdPZzc5Y3NmZCtZK1pCSDdEVVh4aXlGTmJi?=
 =?utf-8?B?S0xtOEovUGo4bnNtZTlzMktKVFI3NWZtdEJDL3lBcjN2clBpdjhDbXRpLys5?=
 =?utf-8?B?SUV0bGsvTHJ0bHlCRVVwbHZWR0J2OTRvZ25FRE5KMFBLUUZqS2t1RFZPT3Vo?=
 =?utf-8?B?Y0NvZUEwWVUvek1uWmVEUE5GUzNSUlFpbEwyOHRCeTI1Z2RwS2JXZnhXSEJB?=
 =?utf-8?B?cGtSbVJlR2Z5bVR6QmhUQXgvZmlsNHp2djgraG5WTHo1ajBLcExscXVwekpN?=
 =?utf-8?B?djVHS2t1OXErQUU3d3B5UElMQ1BqdXRyUzIwdmwvazlmSVRKU3RXVzluMTgr?=
 =?utf-8?B?Nzg4YzdYYUl3d044SkRMUkVPNWpqYU9YRnp2eUhoU2JOOGtib0laaTBjRXFu?=
 =?utf-8?B?M3I4SW51RHZ3dWVWWXhWTnY5aFVuYnlEbWNuZVBkZDQ4MFYwUWkxN3pSVFlj?=
 =?utf-8?B?OFJZMG5wckwwamQ2WDJRZjVmeVNuSkM2MnNaVGdkS2l4dzFncC9Falg0WmR5?=
 =?utf-8?B?SUxoblBMWCt1NytmUlRTZWdJcDBTVzA3WDVLajdnMVlBeGhyRUtiTXNZemVR?=
 =?utf-8?B?cWI3QjRVamNkbXBFVFRLY0lmUWlvVkZmQ3VVMFdTS2QrbjFmZ3o3cXV2MWdM?=
 =?utf-8?B?S0hjOTRIazZuN0dmRDFHWkR0eXdwZURMeDB6WVNzb0JOV0l2NjZmd2trd1d5?=
 =?utf-8?B?QWFzMlZhK09BTzdNZjhsL3o0NXQxT0g0WnpqQzg1VS9EMDl3UFRkUDIvZzJS?=
 =?utf-8?B?RERLMllNNklOU2NnYk5VMTd1U0FlQlZvVGJENEh6K1VJQ0c4cnZ6OFJQT0xm?=
 =?utf-8?B?MjJaRk5uSllneGQ5QjYyM3J2b1BUVTg3Tlhhc3A0UjRNOTBSK285TUk2eE1T?=
 =?utf-8?B?ZG1HQWVRekZLRGtZMWN5MlQvT0VySEU5ZytLWm1rRWxXb2JTdVJmTDBSR0Za?=
 =?utf-8?B?MHdPKzdVSWdjQk5jSDIxcjRQelp1TzMxMXZIMnlKdjVnVGtpbWdmbE4xOFZP?=
 =?utf-8?B?ZlFFLzREKzJydU84L1c3QlgzUllIN2ZiL2YwOVYyR0lGWmYvMm53MjBSTkRY?=
 =?utf-8?B?OFJqNWdtT21jZjgyb2QvMEg4SmdMc2o4d1RYTjRzVGx5bENYUFZxUkhtdlh4?=
 =?utf-8?B?NS9IeTFNMEFOcExWVWRHQjVYNXhDSGVoaXpEcUd1SVlUYzBRbFQzL2JYT3NQ?=
 =?utf-8?B?a1VMdmVWcG1ZSHQ0eHpZNmQzMzI3bXN0RDRzd3hSeTkyNnhEWi9UTkorRElB?=
 =?utf-8?B?cGFsaW5zUlBZNGpjdXVYS2FJREhEM0NlMGlWWmdIekZycWxCdEdOOEJqZ2VD?=
 =?utf-8?B?NnFYUTV4Q0trcTVmWUhpamsrSDlXMWJsbjdHU2xkcnFPd1RrYzlWV2xlNGdH?=
 =?utf-8?B?VkxBaFlVa05RYUw2K2Z6cTZQTWJleVFWZTB3cnlJcTM4R0phUlhBeUVLdWNB?=
 =?utf-8?B?QTBVSkFBb2JQRHJDOG5zanB6ZUlWOXJGbXBFNTRjWW1wN2svU3hqa1FWZVcv?=
 =?utf-8?B?dE01RUM3UE9FazdvZHRZTE8wTk9qTVhKRmJyWFlkeXhBa3dQS3V1Nno5M2NK?=
 =?utf-8?B?dDFBbmdNYzlUanAzSFRMWXF2VkVUVmFSWjFsN3lkTkl2dTlYdm1SMEd1emRI?=
 =?utf-8?B?S1ZrblJ3NmlhdlNBR1ZhNWtPNnlHWHlyc2xENWJ4amxnbzkyRE9rMnYyalhB?=
 =?utf-8?B?R0JudjRTTy9MVExIK1Q3V3VBaFI5cDU0MFhHa0xheHo5RS9sY0lsa01oeXo4?=
 =?utf-8?B?SnlyY3BYOEEyZWpvMWI5UEVmVCtpYksyUzVQSzVSUisweE10Wk5BZzlBZjl4?=
 =?utf-8?B?M2dDY2lJY3QzRitHZ0tJcTBCMFdoSkRpYzMweFpIcVdEaGROT3JqS0U5MU1R?=
 =?utf-8?B?N0lPTGd0TkZYeTVLeGJoSzBzaCtWeVU0QWplR0I3NTBFR25wcWpUV3lMSVBh?=
 =?utf-8?B?RWNEMmRtdFgvR25OTDlkdy9tZkhLYUxiWDA0aDBSZWZma21FdSsvdkwzWmkx?=
 =?utf-8?Q?TpTfZ4jCejENDwrBTxvaFIM=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: ec4e0211-ee68-4895-fe5b-08dd572aed16
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Feb 2025 12:33:23.6084
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: toNj4Mj1spaLdFcWcBKlEDLaNbMfF1900y4euwWd4txvZL+ED+Dw49cGNUwEv9Dk6Ac4qXT4NfhGMOQNU9LkVL6RQ1Sc6wzDCoiTN7h/0ds=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB5941
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=RrjBlvuB;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-25 at 22:37:58 +0100, Andrey Konovalov wrote:
>On Tue, Feb 25, 2025 at 6:21=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> >> I wanted to have the shadow memory boundries aligned properly, to not=
 waste page
>> >> table entries, so the memory map is more straight forward. This patch=
 helps with
>> >> that, I don't think it would have worked without it.
>> >
>> >Ok, I see - let's add this info into the commit message then.
>>
>> Sure, but if you like the 0xffeffc0000000000 offset I'll just drop this =
part.
>
>Sure, assuming it works, I like this address :) But to be fair, I like
>any fixed address better than using a runtime const, just to avoid the
>complexity.

Btw just out of curiosity on the topic. If we used a runtime specified kasa=
n
offset, could the gdb script issue (not knowing the offset at compile-time)=
 be
fixed by just exporting the value through sysfs?

I know that in inline mode the compiler would still need to know the offset
value but I was curious if this approach was okay at least in outline mode?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/p=
aotjsjnoezcdjj57dsy3ufuneezmlxbc3zk3ebfzuiq722kz2%406vhollkdhul7.
