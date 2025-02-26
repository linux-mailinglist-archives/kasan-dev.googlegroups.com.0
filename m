Return-Path: <kasan-dev+bncBCMMDDFSWYCBBT4B7S6QMGQEHAGJYJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 207C8A45DCA
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 12:53:53 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id a640c23a62f3a-abb9962ebe5sf620840066b.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 03:53:53 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740570832; x=1741175632; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nqzurlVjf5Tn+hMfFnod2qxYo+1QDoaBpOarqoyM0Io=;
        b=TekEBiWOWncmT2QzRwJAtk2XtoQxKfNCW65tgl1rwOAqZM0ZUZHeYFgyP+ktsSnM30
         Umh5sZTYkEbkWyea0gibpJFNTqYnj/3qXljXu5sbrnj7NLLDpqd3vyKjlXPQ1MZ201q5
         ljo0IuLXvLxho9o3UaLWGwd3MOzP2Rqb3jswPzoIBglBk4N/mygTppRuB6oh3D1f5SE1
         r/XiZ6u+NpiDcSz0RnFBwRWF/xgYcgN7wp/BbVgLq9YWa3BdBhBOJuCz9bo2r/xjSzOW
         g3cxItFpImyHRiZqAoWzIjS7oDTb1fbmUxe7RiKTl/FXMwYcYSrrkH10/D7c02/9gKmQ
         YJBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740570832; x=1741175632;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nqzurlVjf5Tn+hMfFnod2qxYo+1QDoaBpOarqoyM0Io=;
        b=JXDVuiZpguNOeJYpFiA2AF0tcr7KxdbykmbICV28K+ds49gkffQWB7QJYGNDbqUmUc
         cVQN7AbFmYEOId6IvJwLfM0DfJ2FGIlTGRSV5/mOT0Se7txQgv4d7nyWPWnBS1Tmo+2n
         t93tXOHp/XENNh0KGmnEPXc/RsyM1ShdQPpxcwM84Z1RG3catWRTCslHlOcDUwVZVwtm
         6jXkxTRdUNxcB7Mg/fcVK1A6tIrdFJn3Rlcw1j2NPRjTWr06TaIMu1n4GdCWMKlXeU/o
         AReF4vXbJeUsH0hKxHmbYDvpJn7GGIBU/LEeDE9VCc/iqFyu3Say3ZM8RTki9FnLmpjy
         LNtw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0XN/JK3OAtxYCMGCzHY9rF3ueceHkI0AsdLcnsBpdjP+TniTbqtisetEPN+/aoE0tIEGnJg==@lfdr.de
X-Gm-Message-State: AOJu0Yy2+RruMGOJpGlPOIDbXxcm8rErNGcZD0IrT9Hf2IYdwMArq6mD
	KM7U0wPatsENSDcCotRLkrBUys1snVg11bZDJrc9W8qfyv89kaoN
X-Google-Smtp-Source: AGHT+IFi/lWsDfBhPdNDWqAeAqOJC0oF6VKPinMY93+j+m+gfFfFsM5oAATJd2+kEZYyJ2K2Fun01Q==
X-Received: by 2002:a05:6402:2812:b0:5df:25e8:26d2 with SMTP id 4fb4d7f45d1cf-5e444853ee3mr16958228a12.5.1740570831646;
        Wed, 26 Feb 2025 03:53:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH3iyGpwYrd6Wf7trx2NTyyZANbGE13GpBgCXqaynZ61Q==
Received: by 2002:a05:6402:365:b0:5e4:b7e7:93e7 with SMTP id
 4fb4d7f45d1cf-5e4b7e7953dls47941a12.0.-pod-prod-05-eu; Wed, 26 Feb 2025
 03:53:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXX582pGnApVyJXoob2e5Gmm/433xp0+Yr1ZuWq3zeg07+KrIm8Euh7HjMpvhF5b2UAPCv4Lc5c/rQ=@googlegroups.com
X-Received: by 2002:a05:6402:50c7:b0:5e0:7510:5787 with SMTP id 4fb4d7f45d1cf-5e4469ddac9mr17734126a12.19.1740570829137;
        Wed, 26 Feb 2025 03:53:49 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.8])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5e4b638bc47si4524a12.0.2025.02.26.03.53.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 26 Feb 2025 03:53:49 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.8 as permitted sender) client-ip=192.198.163.8;
X-CSE-ConnectionGUID: H4Ee1qTbSmqa5i8k4BUOdg==
X-CSE-MsgGUID: uvnePjq4SN+iU+wyS2Z6XQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11357"; a="58946662"
X-IronPort-AV: E=Sophos;i="6.13,317,1732608000"; 
   d="scan'208";a="58946662"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by fmvoesa102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Feb 2025 03:53:46 -0800
X-CSE-ConnectionGUID: JV0dyDJqTtOtICKOVLhkLQ==
X-CSE-MsgGUID: Sqb2XMdSTGyOWRZ6JswYmw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,317,1732608000"; 
   d="scan'208";a="116492901"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmviesa006.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 26 Feb 2025 03:53:45 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Wed, 26 Feb 2025 03:53:44 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Wed, 26 Feb 2025 03:53:44 -0800
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.45) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Wed, 26 Feb 2025 03:53:43 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=QbDDK+XkH1R9b+SF5db/FH6Zo5zEhQVdRWf05tmTBoeKLbN1acR8b8oCabY8HbMOIOEBYJryxKnR+flboz9TMFCXf1iIAd0aoHFK8C2akBgrXMULK1RuyImzOOXNGoJC/AMLIMF9ZkQlu0unLijcZyL3AvnKktSobKPINM22BL/CyLAOEl++3h+dzJdX+bnHmAugOFMs8DM01rPS0zE8CATZRpJ1cOzIHnDO0YhHxPdoNIJAY6AaqKroiWSxn5OBJ6Yflzcovmcjnu5V0VITlhdKaeJFKJ+/tl7I5ea9DHsMxLa+rAiVHyy70OQokMzskupMcalbb5nqgoSDZNBkJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=c2tMdKQ9QONiiRKOvsiAHyE1lz0jk6878oFS8pM3ByQ=;
 b=O7j+USJlIFjtV7RJ5KcdMKkzkzBkCAWs+QqhHeryX/m+MS6nilyTOb4lEKosSyqIO3/q52JBCsN+5amaK0rFW/X7u9sn8jtl87EKAtxDX4Lu4gO6vHqgmmydVGlPCWmxsWdRYVcEJuo3ynp0yN3n0pbs8yLtr8/9GZKEdEy5O9DCmCYW1W8cePQibUuknZMLQ5tUQ339z00gycjql6GfwsZddmM52umJX31TKZsFSjxrxMIYx/viJ9dB5yxgXi1Mgc7wuV1sR8mgNvvIcXF669ks6ixHzP9LCAWACCBIMhYR4rbv5nCAkjcOjERvzWJDvZNW7+c0O3Y5rmFoOWBbxg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by SJ0PR11MB6741.namprd11.prod.outlook.com (2603:10b6:a03:47a::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.19; Wed, 26 Feb
 2025 11:53:14 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8489.018; Wed, 26 Feb 2025
 11:53:14 +0000
Date: Wed, 26 Feb 2025 12:52:38 +0100
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
Message-ID: <ffr673gcremzfvcmjnt5qigfjfkrgchipgungjgnzqnf6kc7y6@n4kdu7nxoaw4>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
 <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
 <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
 <CA+fCnZcsg13eoaDJpueZ=erWjosgLDeTrjXVaifA305qAFEYDQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcsg13eoaDJpueZ=erWjosgLDeTrjXVaifA305qAFEYDQ@mail.gmail.com>
X-ClientProxiedBy: DU7P189CA0016.EURP189.PROD.OUTLOOK.COM
 (2603:10a6:10:552::28) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|SJ0PR11MB6741:EE_
X-MS-Office365-Filtering-Correlation-Id: 0a6dc528-2ca6-4570-5f73-08dd565c2662
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|366016|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?ZzMwenhObjFDU1NKMGtLS3dFWE9oSVVEWENBOHRWUE5obHNMakxpL2ZGOG95?=
 =?utf-8?B?RU9DSXpUYzRBQXJrUzRaQWpRMXB0ZWJ2ME51RUkrbmFuZURYRnNNUEFsd0hT?=
 =?utf-8?B?dVBTR2lMRFNmTXp5QnBCRDdYeU4vNTJlc1h6NmFaNG5hRHM0aitOS1JjLzc3?=
 =?utf-8?B?NzZYMlRRbmpXVHNnSWllOWt1eHBucDRLRVNiTEErMGVrdmVUQ1VHMU82NThq?=
 =?utf-8?B?TzdpSDhjVFJyOUdIdVpBd1hYNVRjdmhJc3orN3JNdFFrdTByYlExbWJpWXRW?=
 =?utf-8?B?bk00L0RZN0dHVENsTW1vU3hIN2JZc01nZ0cwSnlpT1NpdFRBZWppdnhFMGhm?=
 =?utf-8?B?NndDeEJLYVJVTGhFMmsvTXA4S2JvK2RrcHp4VnJFTHZCMnprU2lsOUZSb0xq?=
 =?utf-8?B?eUp2STA5SUJCZ0tSK2s0WEYraUZ6SUhueXhodzBIeVg4aDJBVG9EbEJaZ3Ji?=
 =?utf-8?B?aGx0ck9mTWZUWGNtM3JHZFlFMmphTHNJY3lUSktVVmEwNTVLMWhzeDFJTysz?=
 =?utf-8?B?V0UrRitQdXJuSzRnQ0RYU2NHZ2lsVHNCTkd5a2ZXTjZkMWxKQjBtN3J1RWlm?=
 =?utf-8?B?bGlPLy9lTUZ6T0tEZDV5d1JNWkFvNUdsMVNUb1l5OGU0UjF5RkpGZW5CbUxn?=
 =?utf-8?B?RkdUZW5qQzcxU3pUaHVEaE5QSXdGMk9DZTVQVDhKbnlMRkx4TWZ4OWdvTnR1?=
 =?utf-8?B?cUs0QlQ3SGVTTDhycERHZ1hsc2lvWXkvSTRJOW1GWWpxSFI4enFRckl2UkFL?=
 =?utf-8?B?bCtmWjd0SE5aaVNpR3ZvUVhra2NXZ1ZYd3F3L3pyUHYzdnBDbnhyVmJWT1NX?=
 =?utf-8?B?M3BkWC9mMFg5TkpUdVJjTnFKNkc0Q1UxSFRkc2Y5b1ZhVFNsN0lDV1BrQzgv?=
 =?utf-8?B?T0tKYitobzBUTk4vUkRPSDFIT29MV2FrTDlYS0dER3hyaE16TWthUzJSdnZj?=
 =?utf-8?B?UUx5eEw4ZjRRdEI2Z0tCT3ZPMytyR1RhaG1BZmhhN3Vobzl2OXZoODVmYlVq?=
 =?utf-8?B?SVV3TDhvdFkrRjd3Wms0eG5QU0NtV1B6a005NEwvNmpQRDNsTDU4WmM2eGdC?=
 =?utf-8?B?UHdMem5NTUMxL3hZRXUyQlRYNEJzVWgzbUNRUVNMN2MyOWc4T0JuTUFsK2tu?=
 =?utf-8?B?b3JSbG1UVTQrWXI4M1IyOWlDUWVUcEFnOGgwcWk4TEFPYWk0VjJhQVFKUitY?=
 =?utf-8?B?WE5QbGcwZVZiT05IOFNySWsxOWFoM3VwTlpZUk4yNTJsSW9KVWdIaFpESDhq?=
 =?utf-8?B?T3ZVc1NkbDhnVjF2bkJqa21uTTBPUytxYUFDS0xBcVRsckVaQXk0OExGeVdi?=
 =?utf-8?B?aEYrMjJjTUlIcWlUOFd0MStZZTh3Vzh3cHcvMzUxUmRXR2NBKzdnRG1FT0Jx?=
 =?utf-8?B?TVpCa0MycFhNMGMvMTIvY1J1UTJNd05PS1BlU094djNlcEFOM1haOVR0c2hS?=
 =?utf-8?B?NmlQUmRWRkdWait3dUc2Nkp4STJONmE2emVWYktKcnFNamdEeVk1ZTlub25G?=
 =?utf-8?B?RHpsN2NjK0w3T3BCeEEzcU5VNmx5YitSMENraGMyRWltaURPNnhwUHNXckV1?=
 =?utf-8?B?VGtUUmlNNE50UmNQMnlOT1JHM1lPNGxMQVA2NWRGZFBhUEdBeHV3TUdkTU9Q?=
 =?utf-8?B?b056QnhqWWVnR2F3QVd3ZDFzaGlobmlZRUxZVFoxSTU3UFBuRkFzY2pyankv?=
 =?utf-8?B?OC8xNGJZTDNQb2hWN2MwazkxRy8wMitUQ3AxZlluSi9wWlVPakpRMC9Lb1Jy?=
 =?utf-8?B?dklDTDBXUWQ3eEtpeTYrbkZZYnFGbndXY1FiODRQdXM4SFBYeXQ5ejk0SUtG?=
 =?utf-8?B?YzJRY2JYQWpHWHM4ajJhYXRaZ05SaHFrY3ozdTRRZDc5bjh6M2psVEhCZkVy?=
 =?utf-8?Q?v0BNMvuw1vC+E?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(366016)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?bXdBVGovbEJKZ1YyQTViR25DRmRpYUlpT1JtU3dWa0VFMUZBNlkvazdrTks0?=
 =?utf-8?B?dzYvTGU1dndnemZ6UmxmRFVGcFFYbE15dTAyTGVhMVRNcjRTNDlhMnYzU3Ru?=
 =?utf-8?B?SElDTkczV21hR2FvVkhhZ1JXUXRlMDVvOFNtVEFYeWVXUDArWSsvNkRFcG1V?=
 =?utf-8?B?WVV3T1l1QlVYYnhRSmxDK3l6NGs0aG1iZXJNdEk1S1p3am91TVdhLzFMVWQ5?=
 =?utf-8?B?L3lSY3RRcG95dW1sd0t1K3JlOGpyQWU1czFaVzNwU0tZU3dEbFdrTkg5aGY2?=
 =?utf-8?B?d0FhSUdUc05MY0tGT2FGMjg0ODJrQjA2WTBLWkFwdmFQcXRrSjBlclg2aGNT?=
 =?utf-8?B?amo0cENyMlNnRVNjUzRZQjdFMHFpRHlEcEd2SE00YlBiZU9Ra3FFYUZZekp1?=
 =?utf-8?B?MkZGdVQ5QkhXRk9tT0xwZTdxZXBuTDNoTUtZc294WkpSR2tOWjNDRlVXOFNX?=
 =?utf-8?B?elAxdWRlNzhYNytlazVxeWpuODFvSzF5ZmN3YWFVMzhuMUlVZkJVblQ4VlVa?=
 =?utf-8?B?MkdETHNIb2ZacUZaZjJ2SUpnc0t4UlR4QzlMM0o2U0tNRExuWEtwa2dkOWZV?=
 =?utf-8?B?RFRPdHZndUV4T1h4ODI3T3JCQXZRK3lobVZUZytrVHdMMm5IUXJ1ekhINjRY?=
 =?utf-8?B?YUF2Q0UvZEt1K1FSTStzbmhCLzlqeFdPaTFaVTlXVURPMlhaQ0JaQWpKM0ZV?=
 =?utf-8?B?Qkl3bi83dkRvNEdEVkNxYWNrRmxnZUVLd0gvelpZOXpSVm9hb1F0RXZvbnQ2?=
 =?utf-8?B?UVRKdndxKzZ5RmVNcEhrQjV3MUJaT2pBVFdkWjRZVXUyd21hZXZkTUJ5Z29O?=
 =?utf-8?B?SnhUS1I3SmZSRU5PdjdLOG9zQkVCejNsWTNBdmlOZzRrYkR1MzBkOHBVMVYw?=
 =?utf-8?B?QTQ4S3RxT1VqUUdMTWd6MUlIbWc2NnVhYlBYUjY4Vy9WTGF6L1ppTEtIc1VL?=
 =?utf-8?B?U1docVQwQ0NQeE01Z0pqYzIwWGcxMDNScE5EU2VxZXFESUNKTTNJVEp0amhK?=
 =?utf-8?B?RTIyTVNzRWVOVS9iSThjODdzZVlGNm1UMjVFWisvdnh3TkE0RitRY3U3dFBD?=
 =?utf-8?B?ZExzcjVpWm5QbU11TzZ0bGJ0ZEd4a3lBWi9DckVKbWxSU01kbUJCKzBiZkR1?=
 =?utf-8?B?SlBFcW9hRFhYUUIxWEhPbG5MTUFsOVg5b3R0ZzJhc0ZudndGZnUvSVFMT0dn?=
 =?utf-8?B?WjNyNlhRejJrZndSbGJTUC90WkVieVZxZFVPQ1lVUWMxKytONGpRZUxJR3ZP?=
 =?utf-8?B?NEFWTkhZb09OVmQ3eFJ2eVZyczNhQjdrUnhraDhIQ1gxQ2t1d0FsdjFIc3Nw?=
 =?utf-8?B?UERtc2tBSnRJU1M4QXlnejhMME8yaWs5ZVN2YW9QSTg0emJ3eDdESHJ6b2lD?=
 =?utf-8?B?TjNBMGY2d0JFZzFOUUNrRjRzSTZVVTh3Y0x5UDRTU0pTNkJieXFtdnU4RkF6?=
 =?utf-8?B?UWNXa1RCWTFZc2JWeVpjNGFlN1hna3lqTC9YQktJa1Uxdm5CQnB2dzBzT21a?=
 =?utf-8?B?ME85TldBVS9Ec3VtdEJ3OEN0U2lya2JFTmUrOVA3M1gvUGptdEJBWTZCSCt5?=
 =?utf-8?B?Q3A1V3dCK2FJOGZxbS9NU1U3YSt6enk1WEVadWZpN1dyblc4QWdGWjkyRGZP?=
 =?utf-8?B?ZktzUHpjVHNpRHJvMG05cEowL2lNUnhtVWdacDJGVDVXY0c2aTV3bHNIem41?=
 =?utf-8?B?bTIzZ0JzWXYwcVdMdVdnaEJOZ2l5SGdDL0ZRSzE2SElPVkp1MTFzemsvZm5Y?=
 =?utf-8?B?T3NzZHQ1UUE3Wmc5ZzZpOEFucjZBRjVpNzFUZzFoWS9jcktHSDNrVXVaVVNV?=
 =?utf-8?B?ODBDRmJBbUQzSjRTZVhBV3BUSTdRa1dNSCtkUEtlQVc3RUJjUDlLd2syWDEv?=
 =?utf-8?B?S2hlR3hHZU5YQVYwR1QraHJnTng5eFFLNlZuQWlNRENjZFhTOVJITi9kbjJR?=
 =?utf-8?B?SFhQU0VjbHpRSDFHSGZGMUROc3NaSENuV0tkcnBBS3lIbEVkNnhsaHk2RzZr?=
 =?utf-8?B?RW1VeWhvd2xNZk9QcEJtWWNTcmpoV29hUnBzODBNUVM5MG54aWJtUHhqODZp?=
 =?utf-8?B?NEdta1B1WEJEeXdZVXZteWZwVkRHUVIvWC80d2V0aHlLN0g2Rmg0aXVzc3RS?=
 =?utf-8?B?czN5YkdLRnNQOURlNVN6VnVnUkhETHg5MHc0ektlc3F5RTliMWtTa0syR090?=
 =?utf-8?Q?UbH/TTlfUfpckBBahXJaF8g=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 0a6dc528-2ca6-4570-5f73-08dd565c2662
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Feb 2025 11:53:13.9923
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: uU/OV7CtoiGcNJBNAIvH2vLAR8zYTMzn0VNuqoKnImVf/UmY3d8Gb+BYhVJPNlICwiBMYbfpGJFeQpZgsOGS4BbtP5u2c+9TSy77U6ZT4JA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR11MB6741
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DKFoic11;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.8 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-25 at 22:37:37 +0100, Andrey Konovalov wrote:
>On Tue, Feb 25, 2025 at 6:16=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> I mean in my tests, with setting offset in runtime, everything works cor=
rectly
>> in inline mode. Even though hwasan-mapping-offset ends up empty and does=
n't end
>> up in CFLAGS_KASAN. I assume this means that the inline mode is pretty m=
uch the
>> same as outline mode with the runtime offset setting?
>>
>> I also tested if hwasan-mapping-offset does anything if I passed random =
values
>> to it by hardcoding them in the makefile and still everything seemed to =
work
>> just fine. Therefore I assumed that this option doesn't have any effect =
on x86.
>
>Hm that's weird. I wonder if inline instrumentation somehow gets auto-disa=
bled.
>
>> Hmm indeed it does. Then I'm not sure why I didn't crash when I started =
putting
>> in random variables. I'll dive into assembly and see what's up in there.
>
>Please do, I'm curious what's going on there.

I think I figured it out.

After adding
	kasan_params +=3D hwasan-instrument-with-calls=3D0
to Makefile.kasan just under
	kasan_params +=3D hwasan-mapping-offset=3D$(KASAN_SHADOW_OFFSET)
inline works properly in x86. I looked into assembly and before there were =
just
calls to __hwasan_load/store. After adding the the
hwasan-instrument-with-calls=3D0 I can see no calls and the KASAN offset is=
 now
inlined, plus all functions that were previously instrumented now have the
kasan_check_range inlined in them.

My LLVM investigation lead me to
	bool shouldInstrumentWithCalls(const Triple &TargetTriple) {
	  return optOr(ClInstrumentWithCalls, TargetTriple.getArch() =3D=3D Triple=
::x86_64);
	}
which I assume defaults to "1" on x86? So even with inline mode it doesn't =
care
and still does an outline version.

I checked how arm64 reacts to adding the hwasan-instrument-with-calls=3D0 b=
y cross
compiling and I don't see any differences in output assembly.

>
>> But anyway I have an idea how to setup the x86 offset for tag-based mode=
 so it
>> works for both paging modes. I did some testing and value
>>         0xffeffc0000000000
>> seems to work fine and has at least some of the benefits I was hoping fo=
r when
>> doing the runtime_const thing. It works in both paging modes because in =
5 levels
>> it's just a little bit below the 0xffe0000000000000 that I was thinking =
about
>> first and in 4 levels, because of LAM, it becomes 0xfffffc0000000000 (be=
cause in
>> 4 level paging bits 62:48 are masked from address translation. So it's t=
he same
>> as the end of generic mode shadow memory space.
>>
>> The alignment doesn't fit the shadow memory size so it's not optimal but=
 I'm not
>> sure it can be if we want to have the inline mode and python scripts wor=
king at
>> the same time. At the very least I think the KASAN_SHADOW_END won't coll=
ide with
>> other things in the tab-based mode in 5 level paging mode, so no extra s=
teps are
>> needed (arch/x86/mm/kasan_init_64.c in kasan_init()).
>
>What do you mean by "The alignment doesn't fit the shadow memory size"?

Maybe that's the wrong way to put it. I meant that KASAN_SHADOW_END and
KASAN_SHADOW_END aren't aligned to the size of shadow memory.

>
>> Do you see any problems with this offset for x86 tag-based mode?
>
>I don't, but I think someone who understands the x86 memory layout
>better needs to look at this.
>
>> Btw I think kasan_check_range() can be optimized on x86 if we use
>> addr_has_metadata() that doesn't use KASAN_SHADOW_START. Getting rid of =
it from
>> the implementation will remove pgtable_l5_enabled() which is pretty slow=
 so
>> kasan_check_range() which is called a lot would probably work much faste=
r.
>> Do you see any way in which addr_has_metadata() will make sense but won'=
t use
>> KASAN_SHADOW_START? Every one of my ideas ends up using pgtable_l5_enabl=
ed()
>> because the metadata can have 6 or 15 bits depending on paging level.
>
>What if we turn pgtable_l5_enabled() into using a read-only static key
>(DEFINE_STATIC_KEY_FALSE_RO) instead of a bool variable? Or if that is
>not acceptable, we could cache its value in a KASAN-specific static
>key.

I think this was a false alarm, sorry. I asked Kirill about turning
pgtable_l5_enabled() into a runtime_const value but it turns out it's alrea=
dy
patched by alternative code during boot. I just saw a bunch more stuff ther=
e
because I was looking at the assembly output and the code isn't patched the=
re
yet.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
fr673gcremzfvcmjnt5qigfjfkrgchipgungjgnzqnf6kc7y6%40n4kdu7nxoaw4.
