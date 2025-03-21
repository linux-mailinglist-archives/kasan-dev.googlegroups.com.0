Return-Path: <kasan-dev+bncBCMMDDFSWYCBBGUE6W7AMGQEAVTXTWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 82245A6B8E6
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 11:40:28 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-22412127fd7sf22229885ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 03:40:28 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742553626; x=1743158426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tFz4uF37eaKhvJFMD+Ymh+T/w1RgFcjB2naFeshMfXI=;
        b=DIFH9HkcaNUkomAJ142TTfoUQ9xY1EwibVvnpHikP9+LFk7Y9RiJ1Pobd+fZ7SAJ2K
         CC+PfH7Ze6pN6DcDzSYkIU7KhKk4Kr0R98833g8XEbRh/aCRH4ofcHBduIsAo79FlDix
         Zto+45jf8kOXPaqp5CA1+dQ4V/CjbTpCEAy83kIK8YxPTJqsYnxMm5fDiqyDtAD4P3Vd
         NsSENvmGxU80MmyV6Jx+czH5ER+wOj+QakYSWmRghcTl2Xnp8Yee+LARKIzpfvWSPtx6
         vFpFOSMIdJghlYQdfVDoaqkuv7Wr+bTkgmWDm1m9OhaK/nXbJnM+pUm6yNBIcJV+bYXY
         rwEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742553626; x=1743158426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tFz4uF37eaKhvJFMD+Ymh+T/w1RgFcjB2naFeshMfXI=;
        b=Z6Ssu9N/13K6PYUhYHKhsY0zi60mVru/WC9I4fM2zjGivOq4ybYUjQx8sEmVYy7/R6
         YHVwztlh+96stF8yMFAVz7xKqs+XFNVnKUFmvsg4TRLD0Vn9btKiPGCfOPNN3G/2IVj3
         ceqaH1nTHLu3jL+T6BOl9je8XsylI3Q4vegEWVMImsNEYQx/T8vyfJTfCiJM97Adea2a
         yf67pNHNBNGKzFN0/gV77GdR3+QXCuG9oQHuiSCVL2g/VBlQIEomuHMB9jEiSdUIY6Cj
         4uIHuuej1mZRYNTxdyayrKh9Xz1yOuE6SVT3zL3N9GZcR4RCV0DgUDWh0x7pxdYRm5IE
         A6Ew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWs5xL8uaIhAAeQfcEY3gVqg40lvhna7z5/yeaZNGwsILCHw+r5onUnm+LBBl6y9E8Jh3mGCw==@lfdr.de
X-Gm-Message-State: AOJu0Yz0/9NH/X6intp2r/nDx0wTM5/VFhSR/HoOhjJs1L66LyXbZlH6
	XyGgBT87N+nFW5TxE5flaKD8NQmWEymEFquZ3K8kB0WPUDu0ijz4
X-Google-Smtp-Source: AGHT+IF6neXdI+ms2OzwL+kgZyHXNmj/gLJleE/pgvjK3EsQXsff8Fn8EJdzaok569xCtcSivBD3jg==
X-Received: by 2002:a05:6a00:c82:b0:736:32d2:aa82 with SMTP id d2e1a72fcca58-73905a63e19mr4151392b3a.23.1742553626418;
        Fri, 21 Mar 2025 03:40:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALU9kRi+p1DCaZPYcG9Z6LBSEnmBqEindFd68eI2MT3jg==
Received: by 2002:a05:6a00:8219:b0:736:a49f:553a with SMTP id
 d2e1a72fcca58-73902b67832ls820420b3a.0.-pod-prod-07-us; Fri, 21 Mar 2025
 03:40:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZFJpPnoXja9HfrGgO4LgZvQlXwQ8GOeGcsVETHqf8E7EgnqjcmsJ2+MuRox+S/Z/urfoY8w3VQKU=@googlegroups.com
X-Received: by 2002:a05:6a00:1d11:b0:736:51a6:78af with SMTP id d2e1a72fcca58-739059d7660mr4926547b3a.12.1742553624242;
        Fri, 21 Mar 2025 03:40:24 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-739060b76fasi72362b3a.3.2025.03.21.03.40.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Mar 2025 03:40:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.18 as permitted sender) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: e4K9TimjQgqd4KK0nkZWIg==
X-CSE-MsgGUID: wPlZ+ikGQ+WtwwzS7B701w==
X-IronPort-AV: E=McAfee;i="6700,10204,11379"; a="43979714"
X-IronPort-AV: E=Sophos;i="6.14,264,1736841600"; 
   d="scan'208";a="43979714"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Mar 2025 03:40:24 -0700
X-CSE-ConnectionGUID: XOLuRHxzSJakM0GaVbF/eA==
X-CSE-MsgGUID: o0ixPV2VSQmDt3KDAel4iw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.14,264,1736841600"; 
   d="scan'208";a="123541633"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by fmviesa008.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Mar 2025 03:40:21 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Fri, 21 Mar 2025 03:40:21 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Fri, 21 Mar 2025 03:40:21 -0700
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (104.47.66.40) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Fri, 21 Mar 2025 03:40:20 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=grglC8c/YKs539CRKBfV1EsbTV5H5m4aD5AC/JvNZLTHTdx2Y0tthSWr0DafbBVCeJMwrQ0tu0byTir9RN2v9xDPO+tfALpUOBzYeOr4rSyE5Ecna5wN/rMNJfBtm3M1ArPQJMTChngvkW4ElrbXOa+HlHXlIbIB/inQk07E9emAtxWCdjQOPLZjJnxyyv3e4dh64/TMd4f7x3eScH94+o2IPmCpRWC0dpeAcEMyzqZGjHbyEAlWANQdFv9W7PnGKrsGh91pi949aNeI3TfBtDzz900zC3Bl5h5efBD2PRaLQ+EJiMFTS6EZum2tX4CtJs5aurfEUZV4JFwbf9zg4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lJCa0VdNHwZ1RziCymSVITLgcx5Ii66V+Frv47z9Sgo=;
 b=lFSmsZgijZqeCcoW2mgeISsX1dG0WvJP4IHBfUPbpwqO782XVS+bB8mAKpOuJQe3c/hr6RkXaNvZO5lhARXN13mL6l/I8qNiKvXCwJaGVpxPgVkuNicEk4tH8ovzbburPdIJhESbulTFHHJ6mOmaKU616hMfTl/aCFuG2iU6ErsOpuPo/DsW4HJCK6XOt/+5KGW/orIPajl0cbzPgU7BJWzkyQDFmGPqA4W/z6AxlbsZdvq85bXXYYOGTF82aQsr9yeKrfy75qPXHXvedMbX6iAIl3OEj2YR5UvCT2do7Sao62dSuzg0x7mXwMoxGLgG2fi2ZVSCKLLpwk8wmLfzVg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by SA1PR11MB5874.namprd11.prod.outlook.com (2603:10b6:806:229::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8534.33; Fri, 21 Mar
 2025 10:40:18 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%5]) with mapi id 15.20.8534.034; Fri, 21 Mar 2025
 10:40:17 +0000
Date: Fri, 21 Mar 2025 11:40:04 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
CC: <kees@kernel.org>, <julian.stecklina@cyberus-technology.de>,
	<kevinloughlin@google.com>, <peterz@infradead.org>, <tglx@linutronix.de>,
	<justinstitt@google.com>, <catalin.marinas@arm.com>,
	<wangkefeng.wang@huawei.com>, <bhe@redhat.com>,
	<kirill.shutemov@linux.intel.com>, <will@kernel.org>, <ardb@kernel.org>,
	<jason.andryuk@amd.com>, <dave.hansen@linux.intel.com>,
	<pasha.tatashin@soleen.com>, <ndesaulniers@google.com>,
	<guoweikang.kernel@gmail.com>, <dwmw@amazon.co.uk>, <mark.rutland@arm.com>,
	<broonie@kernel.org>, <apopple@nvidia.com>, <bp@alien8.de>,
	<rppt@kernel.org>, <kaleshsingh@google.com>, <richard.weiyang@gmail.com>,
	<luto@kernel.org>, <glider@google.com>, <pankaj.gupta@amd.com>,
	<andreyknvl@gmail.com>, <pawan.kumar.gupta@linux.intel.com>,
	<kuan-ying.lee@canonical.com>, <tony.luck@intel.com>, <tj@kernel.org>,
	<jgross@suse.com>, <dvyukov@google.com>, <baohua@kernel.org>,
	<samuel.holland@sifive.com>, <dennis@kernel.org>,
	<akpm@linux-foundation.org>, <thomas.weissschuh@linutronix.de>,
	<surenb@google.com>, <kbingham@kernel.org>, <ankita@nvidia.com>,
	<nathan@kernel.org>, <ziy@nvidia.com>, <xin@zytor.com>,
	<rafael.j.wysocki@intel.com>, <andriy.shevchenko@linux.intel.com>,
	<cl@linux.com>, <jhubbard@nvidia.com>, <hpa@zytor.com>,
	<scott@os.amperecomputing.com>, <david@redhat.com>, <jan.kiszka@siemens.com>,
	<vincenzo.frascino@arm.com>, <corbet@lwn.net>, <maz@kernel.org>,
	<mingo@redhat.com>, <arnd@arndb.de>, <ytcoode@gmail.com>, <xur@google.com>,
	<morbo@google.com>, <thiago.bauermann@linaro.org>,
	<linux-doc@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <llvm@lists.linux.dev>, <linux-mm@kvack.org>,
	<linux-arm-kernel@lists.infradead.org>, <x86@kernel.org>
Subject: Re: [PATCH v2 09/14] mm: Pcpu chunk address tag reset
Message-ID: <7v47bmgtm5jyvbxzgr2465kkho2bcziiilz7fw736fghto32cd@nmrwxwbtdptl>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <383482f87ad4f68690021e0cc75df8143b6babe2.1739866028.git.maciej.wieczor-retman@intel.com>
 <CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com>
X-ClientProxiedBy: DU6P191CA0072.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:10:53e::25) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|SA1PR11MB5874:EE_
X-MS-Office365-Filtering-Correlation-Id: 6c40e264-a2ab-4b62-2dc0-08dd6864c554
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?eXR0RXZraERMcFF1OU9CK1ozRVUyTHUwSWE2QTVQS0ZRMURYb1p3N3NLaEJ0?=
 =?utf-8?B?cHZTNEdQWkplVG9SWW5YS1NxWUcyU01rK2JFRUNoV2RqZ2ZsNFVtazR2ZEc3?=
 =?utf-8?B?MVA2UWtpcDUrN1hZc2Vtdjk4Zmk4YUlSS0RXcElDUWVMaWhJdnZQSlRBNHlq?=
 =?utf-8?B?QktWbVJhTVNGM1RGQ3NtNnljVnFKNTdGa3BCRE5FRnl4MlBJcDNhUW1LQzIr?=
 =?utf-8?B?TDdQM0lZOGFja2VSei9RSXRJNXQ3L2RPZUhkVFlHWnFRWTYxam9aT0x1OHV3?=
 =?utf-8?B?bThCZkhEMit6Q2tneUg5K29pU0tGcWR4aGoxVHNoK0xPc1FLeVN4aGt5Qllz?=
 =?utf-8?B?SlZQeVBUQm9KSEllREFvL1hVU0xJV3I2TENneHMyNm4zK0hSM2xzdTUzRGJY?=
 =?utf-8?B?ZGp3cXU0aWduK054Mk00SjBBRXdGSk5UaThxVmNic1VmRGdwRTVYdmRZMm82?=
 =?utf-8?B?MGM1Q1lwS2hldUJwdUkwcjZHdmFoaVRPdWpib29hZk54b1pkY21CTEk5aE84?=
 =?utf-8?B?VW1DTU1wbTFTdEpWcGc3SXFWdjB4eWU3c1VnZTJ3QVpYTFhGUkI2YXVNYUh3?=
 =?utf-8?B?bE9wSVNKekptOXJxdDYySHJneDNncmtYeURtSzNyWk5IVXJ2Y0NweDhweHpu?=
 =?utf-8?B?cXFNd1BDNHEzdklURHNsVU90R1I3MXZkbU4yVTQ0Z1BCN2t1YXozQW12ZlRh?=
 =?utf-8?B?Y1F5L3ppU3dTUFBzRXVRZVNjMzV1R3BWcXBpbExlbEtkV29oM1htTjRqcDFw?=
 =?utf-8?B?dVhxQzN0VGVwclJFY0FCM2FMWjNybUNTanhQSjYydGE2ck9EOCtkZHltQzZs?=
 =?utf-8?B?MGJOcCt1Q2xza3RPZnYwbDFQd3E5d3NUTTBLelB2cEllZStEMVN5aUh5K0k0?=
 =?utf-8?B?OTRhdllnMHE4YnRJdUFSWkM2RnZQc2N6SDVHYkxaNWdId3E1d01HYnVtS3Nn?=
 =?utf-8?B?RmJacU5BRjgyWGl3UUF0ZG5iTCtpWldVOVZvMEZrT1JydVNnNmlYWVM2aWMz?=
 =?utf-8?B?MTB4OGNzTkRHZit4aDd3Zm5QWTlxc2IvRkV2R0JzdmNCd0UydFZMRTE1bjRH?=
 =?utf-8?B?SkI3Z090ZmlWU01Wamh3Y2ZaemNQSi9LM1pUYUp2WndsRXZydU1JbGpkTXpT?=
 =?utf-8?B?U2hmdjBSV0dKTFltU1duUEpFaHN4STcxaHFxQmxUTDlxOHZBRzVpM0RnZm1I?=
 =?utf-8?B?Ris3V2hpUUtMejdjNEhDaWUvdldQUnR4NkRwS3BZWnpVckNKODFSTWhRam56?=
 =?utf-8?B?emdLVHVxN2liU1MydmUrTkxQM3h6SG1ISXVIcW9TcVJrN1RpWVRsdUxHNHND?=
 =?utf-8?B?WDFkSko5UGdxRGk4N0RkS2N1aGdGNElhL25WZEZTSnJPOWdvUEpXZ2ErQXNP?=
 =?utf-8?B?SGJocU45ajd4YWk0aTFNRklOSFJIbGFURmVUdklvMm5hZWFuS09qbi8za2g4?=
 =?utf-8?B?WFU0NG9Xcy9pV0ZpOHVWSEZCT0l2OEtxc1dFQ1lkWG9VZEphUFBxV1FERWdE?=
 =?utf-8?B?TGpGamVCYkNORWdWck1lajF5emxVc0RXSU9rMzE2RzJpSGVlYnYzMzZyTU5o?=
 =?utf-8?B?S0YxZ2RGOHVRemVEQVVrSDBOTi9NOWlJNEdtMGdiMGdoYmRYeTc0MmN5bkxL?=
 =?utf-8?B?OVQzeGtlc0VZQ3BwajFWSEVEdzM1SmRBTXBnTmV5T3JCNFRkOTBma2FDVUpD?=
 =?utf-8?B?TDRBTm5sNHJnd29HTlBpMmdJSjJyb1JwdkU4ZkhaUFY4cHc2ek4rb0cwQUJC?=
 =?utf-8?B?ZmFBTXlZd2xDQm9mVW80UnFKT0Y3SFJCU2lHaFdpVk1kLzhaMWp3NDFWTmNn?=
 =?utf-8?B?L1J1UWVnZDRrdWxpRVRENjZVMGgvRU5VZWFnRXpvZDZiZkVQYkwxc3UwRmZ4?=
 =?utf-8?Q?M1DzmXyLJuNAQ?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?VzlObllvSXhYV1lLZnNxekZjUUpGOUwrUVRYUHVtYTJEM2JTczFWTEwzMThJ?=
 =?utf-8?B?U1hjKzBTclh1bEJCTHBEMjFsUlBnNkt0RFlIKzRUd2xkVnAzUkFsS2l1OER2?=
 =?utf-8?B?YmVNV0FoZGpQRlIrWlgzdlZ1THl4UEtBWmRWRFpkRkRJcHlrZUR5Z0RCeEcz?=
 =?utf-8?B?NlVTMlV4Sm9wUEZiUytyb0o4eEx5dUw5Qk4wTWsyM2l2MytZLzdyV2FiTnlt?=
 =?utf-8?B?bCtmaFpFdnpka3N3Zi9OME1FT25wMldjMWtqTXl5ZURpUisrRkxnL2VKdGpk?=
 =?utf-8?B?RDE4N2p0bVBxOGR6OHI2ZnRXekNjMFlwUHVKR0Rid3N5bkFIMFJKRWE3MU8z?=
 =?utf-8?B?N2ZLYWtUU0MwdE56UklYaVZBZlJIYkJxRzBqeFFqUlovbSs3emZRS01UWW1t?=
 =?utf-8?B?cGNoVnpqQk0zZEFJbTF4S01XWmhSakRCQkprRk9kbGFSK3N1ZFdlZTFYZEZY?=
 =?utf-8?B?R1FLbGtrQUFVV01DM0hSNVBuTFVvbUwxa0JQQS9KYzIxdGFxRG9aT3pzZ2w1?=
 =?utf-8?B?MjBzVm9GZ0JLN20vU3JVZ21BeE8wZVc2YXhER21nNnUvNE1TYmNMeHhvQy9B?=
 =?utf-8?B?WUZDWFU2b0RjenhKUWlQeVJveWswWHpzbWpsd3dPQ3RwTHJTNWQxODNkRFJ1?=
 =?utf-8?B?NzllSGJpQmc0dXhIUEV2YUFtRkFyZ3BtSERaNkV5L3FrSkZvQ3hKSlNEY1Q2?=
 =?utf-8?B?elp4cUprYkJKdTh5RUFoTVk2bHJKREtRRm9lK2xVa3FyN3AyQVY3TzlONXJj?=
 =?utf-8?B?b2oyS1VmUFpEQnBqcEh6cDVLSXByeHhDZDVJT0tWaTFHS2VnVkdkRDFRVDVS?=
 =?utf-8?B?QVdJbVJ3SkVVYmpQWHFNVldnL0ZveHlYWEdrd053Rm1ua2x6dFJEMjU0Z1hi?=
 =?utf-8?B?YzBNVDJCODAzV1RrTFhjVS9yL1A1NDROUkJIOE9HV3hmbkp5MW1vYnYzNy8y?=
 =?utf-8?B?UTlJbkxTZ3NIaHdjN1dOQTZJTS9WODJpM0RqOXRmZEExTGtwS1RtaGUrYU42?=
 =?utf-8?B?azR5NjVlVHNocU5XNkZIdlZmS2tUYmNaTWxHdHYzVm1Lb0dhM0ZOano5MFlx?=
 =?utf-8?B?VjY3RDJJNWZYSXRSdHdpeG9VVnFoVFNiTkJOZHA3SkxrUkFvL09PTkxVbVlZ?=
 =?utf-8?B?eWFocXJUT2o3dUVscDdBc0tQTFZ6ZUZzUkp1MUorZmlMV3ZpbHg3U0hybGpD?=
 =?utf-8?B?YXNEeHFQUWlnLzF5cVplS0dCTGp1R1V4dFFQSWFEMExFcjE2Z3NTWEV5d0o5?=
 =?utf-8?B?aVplK1BEQ3hwSTBXYjYrZE9HTERiM2V0QTAwOHI0Qkt1Q21KaTJVSWNNQUhh?=
 =?utf-8?B?cExLRlhEV1RWblErNStvM2xmeEtuV2lQbGVHSHpYU0JOQnNrQ2NncWZMR2hU?=
 =?utf-8?B?Vmw1aW4ySXV3TnlsS2dFRTFxYzBUK0JCc1poOXpOSkRVY0tSbWppNlErNHZq?=
 =?utf-8?B?QTRPSWkvSVozaEVvaXdwWXVZekNmU0t0dkVxYzB2azJuRmFHdE1iQVBXYTRV?=
 =?utf-8?B?clNXNDE4QjZQRkdUaGhZVDIxWmdzNndiTXBwVkp6VTlDelJTekRDM3VNR2t5?=
 =?utf-8?B?NHQ2Mkp4eDhvOHFKTEt0WjlYWHUzeVVYY0xsL1N3OEpjbktKTmU0M3Rtc0pN?=
 =?utf-8?B?OVVzUFFvdFpOcXF0bHZmZi8yc2xBLytOZXBmaWNjNW9WWnAzczNvWlg3cHVT?=
 =?utf-8?B?MXN2QzJNRXRzYXl6TkszQThiM05HMVhWMlNKMlFCc1JHdXgvRy9yMDJvb2lM?=
 =?utf-8?B?UjZXOWZoQWEvUHBFUnk1c21PQ0dCTlJqN0FJZUoyNGNkVDhEMkk3OVNsU2RG?=
 =?utf-8?B?bWdmL0poa1c2emdPOTdpVnFLK0RMcFJKbTBKdEZoa2QrbDVtVFVRTnh0cnQ5?=
 =?utf-8?B?OXZWU1hYRzcxWmEyRVZ1bzUzVC9kckJnZ000WEVrWVIwa1VOdi9SdUJuV3hj?=
 =?utf-8?B?ZGNNVko3L3VaK05jL05TaHllSEVkazlMUzYzbmFLVldGSk5tNitMWVdmQlAr?=
 =?utf-8?B?VkxBU0xIUnhwQmQ4N01EeGdVWFhLNDhnRUdtZDN3ZmhCL2w5THU0RmUveGU0?=
 =?utf-8?B?NWFiN21nNmk1ZFlrbjJjSVdReWtMbnFWeDR2SWV6TnJsbWV3bjlUaVFtT0dj?=
 =?utf-8?B?S2l2TE9RUjd4SUEwSXBpbmk2M3llbFZTbHVFOG1tVXBQVEE5amlTTkVLdldm?=
 =?utf-8?Q?Eh+ElHTM3mkYlC1QfobYKN4=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 6c40e264-a2ab-4b62-2dc0-08dd6864c554
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Mar 2025 10:40:17.4940
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 76SeblngGH4Wlv6Op8ID1T8vgHXe70ZAG3/eBgc+EaJXPYDWiIKhaN3XIomsPZ5mtIXBsuUdMXmrny7v2qHjV7JVAIlEf20fTtCIPxNSWAc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR11MB5874
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Rkq1Iy0F;       arc=fail
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

On 2025-03-20 at 18:39:35 +0100, Andrey Ryabinin wrote:
>On Tue, Feb 18, 2025 at 9:19=E2=80=AFAM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> The problem presented here is related to NUMA systems and tag-based
>> KASAN mode. Getting to it can be explained in the following points:
>>
>>         1. A new chunk is created with pcpu_create_chunk() and
>>            vm_structs are allocated. On systems with one NUMA node only
>>            one is allocated, but with more NUMA nodes at least a second
>>            one will be allocated too.
>>
>>         2. chunk->base_addr is assigned the modified value of
>>            vms[0]->addr and thus inherits the tag of this allocated
>>            structure.
>>
>>         3. In pcpu_alloc() for each possible cpu pcpu_chunk_addr() is
>>            executed which calculates per cpu pointers that correspond to
>>            the vms structure addresses. The calculations are based on
>>            adding an offset from a table to chunk->base_addr.
>>
>> Here the problem presents itself since for addresses based on vms[1] and
>> up, the tag will be different than the ones based on vms[0] (base_addr).
>> The tag mismatch happens and an error is reported.
>>
>> Reset the base_addr tag, since it will disable tag checks for pointers
>> derived arithmetically from base_addr that would inherit its tag.
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>>  mm/percpu-vm.c | 2 +-
>>  1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/mm/percpu-vm.c b/mm/percpu-vm.c
>> index cd69caf6aa8d..e13750d804f7 100644
>> --- a/mm/percpu-vm.c
>> +++ b/mm/percpu-vm.c
>> @@ -347,7 +347,7 @@ static struct pcpu_chunk *pcpu_create_chunk(gfp_t gf=
p)
>>         }
>>
>>         chunk->data =3D vms;
>> -       chunk->base_addr =3D vms[0]->addr - pcpu_group_offsets[0];
>> +       chunk->base_addr =3D kasan_reset_tag(vms[0]->addr) - pcpu_group_=
offsets[0];
>
>This looks like a generic tags mode bug. I mean that arm64 is also
>affected by this.
>I assume it just wasn't noticed before because arm64 with multiple
>NUMAs are much less common.

That was my assumption as well

>
>With this change tag-mode KASAN won't be able to catch bugus accesses
>to pcpu areas.
>I'm thinking it would be better to fix this on the pcpu_get_vm_areas()
>area side by replacing
>this
>    for (area =3D 0; area < nr_vms; area++)
>        vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->addr,
>                                             vms[area]->size,
>KASAN_VMALLOC_PROT_NORMAL);
>
>with something like
>    kasan_unpoison_vmap_areas(vms, nr_vms);
>which will unpoison all areas using the same tag.
>
>Thoughts?

I was looking for a solution that would preserve the individual tags for ea=
ch
area. But so far I didn't come up with anything that would work. I first as=
sumed
that some per-cpu pointers would always be derived from from vms[0]->addr, =
and
some from vms[1]->addr. For example first half of the cpus would be tied to
vms[0]->addr, second half to vms[1]->addr (since areas are allocated based =
on
the NUMA layout as far as I know from the docs). But that didn't work and
pointers popped up that were from the second half of the cores but had tags=
 from
the vms[0]->addr.

I think unpoisoning all the areas with the same tag would work, but could i=
t
create issues for out-of-bounds accesses? From my testing the areas are now=
here
near each other but I don't know if that's a given or just by accident?

TLDR: can the areas be adjecent and therefor break OOB checking?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7=
v47bmgtm5jyvbxzgr2465kkho2bcziiilz7fw736fghto32cd%40nmrwxwbtdptl.
