Return-Path: <kasan-dev+bncBCMMDDFSWYCBB2FW4K6QMGQE4JMAASI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 820D0A3F89F
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 16:27:38 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3d2b6d933a5sf16935495ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 07:27:38 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740151657; x=1740756457; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FT76woKBqZBzW15+E9agMy2eUjuu68oBYQpcc2Q927Q=;
        b=mhTZEIsm6vttL9VSfXwdNicu4AGdOzMrTlC4oGlZqiwb4nRJPp+f7kRPcW2v92kYH+
         dmx9OtyERS1mMFRGowj1KmeqKnDbPrP9jkosI2GkzfyyDeenkzWXttsAu8ffBUhj2/t8
         mpZIZIYiaMumxDWmuG6Z2FYCLhKfJ+f+4jNafV40Sixg+BC788ut2HPyGQxGn8MagRX4
         uPZzr32Dj9JlTb+Q+Ujc2C4mhs9ZDyktApRDWoV6c4PVl3sTHdQ93Q0OczPLQPzQKhvQ
         DZzZNobZhnxwjwuv/w69VANagly+k1xwgRBvu+vTFQguf8Im8cMEmKitL858WnmZbckz
         b/mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740151657; x=1740756457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FT76woKBqZBzW15+E9agMy2eUjuu68oBYQpcc2Q927Q=;
        b=cNixTDjlG9ZMppe/66V+Ys85FjGLGj4fG+5tL40N5VccEZWrLJ2jMO9kTbRB3JBMb/
         4lSpdvduIN2fawaFlO0dMgOcbanQpmTVLHgJeG1ybbbtYGwOkj6mCilArE00p3Hgoeob
         1yOzVDrl4vB8SSYkEzFei/d1ciM9oRnA5MFJB1pNY7WH6RTenEYcn5ynUCPlixvA5MKL
         y3cYPWLcALxvOfuwFf/uzFiyZKNsxdTL8xVRnpxSQQYkbVCBfA21C8DlRK6jEy7304K+
         FsZ7qHmZt5bTOVz+fX5eXmuO3OKvCl1QoctpyDJZfcqe0KlcB9cx0jpYCGvk3/xGbDMP
         FoCA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcK6hK/87E5bq7fhVstwyGPNkpBQNbafAj6r9RG/op9z/aDvNBDt2Afl2Z/hk1YVapLRsOxw==@lfdr.de
X-Gm-Message-State: AOJu0YxPxyWXwZ2NIsPGK2nRYtw+6kEOys9RXWNcstibamZXrmpihWQ7
	M5qn9W6PU3Phslnq9pXcfAEQtnpk3Gn+8N15grOCf+x7WMBZF/Nb
X-Google-Smtp-Source: AGHT+IEW+93VUmbVhHph211nWWLscYtDBuVtvgvmPMZRtjiF+2tX0f+XaQRPPR5J7zsxDisDYDkVyg==
X-Received: by 2002:a05:6e02:1448:b0:3d0:10a6:99b9 with SMTP id e9e14a558f8ab-3d2cae474a7mr32599095ab.3.1740151656964;
        Fri, 21 Feb 2025 07:27:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE5vX6e50sPKfTPieiZaEeuvF+ObnlcPrSMwiG0VY/EZA==
Received: by 2002:a05:6e02:3083:b0:3d1:9c39:8f7e with SMTP id
 e9e14a558f8ab-3d2bfd04215ls9754585ab.2.-pod-prod-07-us; Fri, 21 Feb 2025
 07:27:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXiK8GqR+uzIRDD4TrrJgGShaahfnSetEO1ySOvw7C1A6eWkRII94mA0J11AsM4n5hDBVy3wmGlvdM=@googlegroups.com
X-Received: by 2002:a05:6602:1584:b0:832:480d:6fe1 with SMTP id ca18e2360f4ac-855da7ca012mr395830939f.0.1740151656044;
        Fri, 21 Feb 2025 07:27:36 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.7])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ee96201706si546569173.5.2025.02.21.07.27.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Feb 2025 07:27:36 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.7 as permitted sender) client-ip=192.198.163.7;
X-CSE-ConnectionGUID: Rp2Nyt4zR1CxKc1mFWIG3g==
X-CSE-MsgGUID: jVjRXP3uRniz+ZWL+Ocu2w==
X-IronPort-AV: E=McAfee;i="6700,10204,11352"; a="66338027"
X-IronPort-AV: E=Sophos;i="6.13,305,1732608000"; 
   d="scan'208";a="66338027"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by fmvoesa101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Feb 2025 07:27:34 -0800
X-CSE-ConnectionGUID: TAHRenutSAKBMNRqK+TS6A==
X-CSE-MsgGUID: cPXwmQaeS62YlfHRoHaWIg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,305,1732608000"; 
   d="scan'208";a="116035730"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by fmviesa009.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 21 Feb 2025 07:27:32 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Fri, 21 Feb 2025 07:27:31 -0800
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Fri, 21 Feb 2025 07:27:31 -0800
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (104.47.66.44) by
 edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Fri, 21 Feb 2025 07:27:31 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=gmfBjtVn/ebIfZ+QzBTgj5VLjmRQBsDCShaW5ibuz+wriTInBzSklOBkChV5tqM94a1bQw4eOsG1XzZNx7G/D2eiNV/wrjscWwB/SlT3OWhvp40MDptix4TJq/j+IfmWvdLWUWFQMKkGQBPtj4+H7ym/3rJNBYwNxCE0F34/0f6ygX5R4xx17qmp5ou3oWb9HQaCyExd8a5XPC+AB0dO5fVcu4/CV5dPmXN2dAhyX6PAPOkI1mx/zyAuPTFcSn3nBeqOzeW5BuraKYi9qEk6PDcHgVRII6iuF9g7HdF0hy7dMx5ad11P8pdTQJPdLxB7pP+b0mU9kf/IZCOFr9aAtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=LSwNs/iu+liqBsqZ3/cv1oISaypSLBQUUN97eAU5YfE=;
 b=FSONPkbG5nzTkY2zsCjtMMbiIkP2YwdJwF+I90EPIjow5emiGDwVPPX1wMoSyy6ZAQc86l8g0GwRfWb/GSW/wX+TX9PohdhmkVeoXKwXdB00uQsuUGpDsA2OQ+bA4QsY4pNs4gtWfqQloo4NWv2dq8JqWr/SxM43gLrh3A8yRaGTj7//JHFgzoutUYGvxOU83teve/j+X73nWrnEu2Qj0MnVS20VyuwjnmGrRJzdCnspxgl1xYnA7EHW1OBqtDyyr8zJk+3Ts/HTwpJSi30PBLm1qJfCtSVueHBGSZITWC/RbZhA9Tg4zpuCntYQZAL0N1TttE7ghpjp/xChlUxGQw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by IA1PR11MB6468.namprd11.prod.outlook.com (2603:10b6:208:3a4::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.17; Fri, 21 Feb
 2025 15:27:29 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8466.015; Fri, 21 Feb 2025
 15:27:29 +0000
Date: Fri, 21 Feb 2025 16:27:16 +0100
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
Message-ID: <ffbyaler57cdwgs5axtdpnwg52jtwx7tx2rykjro755c45mihl@czmbriuhg3to>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
X-ClientProxiedBy: DB3PR08CA0016.eurprd08.prod.outlook.com (2603:10a6:8::29)
 To MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|IA1PR11MB6468:EE_
X-MS-Office365-Filtering-Correlation-Id: 94a21c3a-bde6-484d-e6eb-08dd528c40a2
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?RnNxcExmajVob0VZcThIQ09FajlScEVDTDQ4d1YrdGY5V254ek9xa2VJT1Zz?=
 =?utf-8?B?NExlblNUSHRkVzd4d2pTbERyV3pjOFNnOEFsVzhGTlR6ZkhGRlVxcUN4dkYz?=
 =?utf-8?B?OG5HWVZsSTc0WnRsRnBGdXZMME9keFlpOWJhdUcvMVZkQjBkT2Q4ajFuOUhm?=
 =?utf-8?B?cXdXUnJhb2poS2tDaEp5T1VrYkF0ZCt2elNCbnk0dEo2MzcreEdSbG9KY0NH?=
 =?utf-8?B?Q2hKZSt4dHlFWWhJa0ltaHZRWUs3aDdOTi9FNlJtMUZIZlFzYkNkWmt2MG01?=
 =?utf-8?B?MmFYUDFkdEY1NTZQRmtidHdkSXNCQzY2cGtJL0M3NkdPZ1ZadXNnNUJ2VCtD?=
 =?utf-8?B?K3hXWkRRV2xhb0ZXc3Rtam5HUGhWSmtNZzA0Rzc2TSt4ZzlCeW5BQ0hSY0RT?=
 =?utf-8?B?QnNFb2g4U0ZxdW1GZnQrNTFad0tTVmlUS3ozZndqeFp4a2xNdjVkN2VObHY5?=
 =?utf-8?B?Qkh3WnY4QWRTbGU4Z0NNU3FxVTY4TStWRURCbzRkc0ZacTVLYkxrbStoTUFU?=
 =?utf-8?B?ZXZhY0RFeDc3ME8wU1lzSlZpdlhCN1BtM2h3bmdCanl4ZEpCdjRaanIrT2FC?=
 =?utf-8?B?RmtDT1lRZGxwWVVMbjhhUmJscnpoeVl1NTB2aFZwbzRhcnVkckE0MFd5K3hy?=
 =?utf-8?B?d1BhdUFSb3lwTzBVN1F5cENoZWs2TmgzU3Z3SnZtTDE1UFlqazFwaDdBZVVB?=
 =?utf-8?B?RFFoRVJTYTBWc0o1N3FzeWpVcEFiMmI2N3Ftckd2RXcwWkNzQlQ5bzVLSFd2?=
 =?utf-8?B?bVl3T1NvSTZ1UTBzRE45Vno2SHdndnllSi9VdVFEeGRLa2FGd2d2K3hCT3Ny?=
 =?utf-8?B?b1VVVkcwb0t2RG1yazRKR2labG91Nkd2ZFp5Sno3M0lrSVVjM2l3SXNYeXNY?=
 =?utf-8?B?WnRlZWxlT2lHM3pkcmF2V2lacmtSR3BVYkxOMC9uR3pua1lPeG9ZcFJYVVBL?=
 =?utf-8?B?OUFwT1l0L1gvUVM3WCtkRU5Da0dSUWZmblJWVHRUUzVUTUZnVHZqSncrN20z?=
 =?utf-8?B?REhEV1A0VDRpYnMwNFZZRWxEUjdYSWp4WC9uWmQyM2hCc2p6Z0dLNUs4Z0ZF?=
 =?utf-8?B?a0VNdjAvSlAzMll6eitjd2JQcU13a3I5NmhiMUdndzF1ay9oNkEvcmtWbE03?=
 =?utf-8?B?QjFIQ2hSN2s5YmxTWHArMHRmN29NSmtqVXdZZkI3VGtrVFVyMTRpQ0ZuL1JF?=
 =?utf-8?B?ODIvSG1JVnRKRmJZZGlMdDhIVU1HMExqbXhlNFg0ZkMwZHM4eHJpRmtEcmRq?=
 =?utf-8?B?VEZPTEY4ZTB5azIvTTI3REpYVkFySUxlMy95WjZ1c2o0SzNvRzd6K3BxWmpm?=
 =?utf-8?B?ZXlMR094N3lBWmtKek0rVHQvZHFDSnI2M21yK0tyNTl6ZkFnUFJNTnBySUY0?=
 =?utf-8?B?anIyOTY2cGk1WWpWTzk5V0xvTS80Vnp5VW0rRndMVjZiOGFXUzRITHZmam84?=
 =?utf-8?B?ZkJ3YXFTd21XeFREYWdHTmlPOEMza3IrekQxbVJFVVlmR2Q0ZkpXaHlRYWd1?=
 =?utf-8?B?TnJvZTJUTUY1ekRTajA3YnJqdjBHQ0ZmaUl1SDFNTUZOZStlTkt4cjNXbWEw?=
 =?utf-8?B?VlptRCtlQjl4cjlFVENCanhybjZGczZ5dHo5b0NabHhFbnFCTUVIVUVWQmVH?=
 =?utf-8?B?clJibG9YTWR2UkFwMURmMlR3WUtMVDV4enZHMUFMUWlnby9kY3dJYmg4LzNS?=
 =?utf-8?B?TFVxaVprT2g1TkUzYTBlTkhQWTNGZm95dGc2Z2lHcElCbG5nYkxFb1hBVFBk?=
 =?utf-8?B?OVpMWGpqcDJRTHdFLzIwN2l3SGZSVnJHVGpKTXZocDJheC9aQkFWYnBpZ1kv?=
 =?utf-8?B?RWZZUG04SC9hUW8vemppVUhhN1czSnJSczVQZWVjTS9zUGp4Y042T0N3ckM0?=
 =?utf-8?Q?Es9QgCjXLYjQP?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?enkvT3JYVGFEQW5HTWh5NFRBZW9FL0ZrZUhKclhSelFyRGZJSnZKM05ZUlBZ?=
 =?utf-8?B?SS9YS2xNWGhkTFhxS2p5ZVRhRGpGelRRUU1PN0czcDVyelRJaFhFUGtXaVhx?=
 =?utf-8?B?ZVgyMlh0cTNVNElJcmJSWUxybHBRSXdsRGZrMDVZaXhGQWlIOXVNbDlaWk1L?=
 =?utf-8?B?UW13SWVEYlJ1b05lZ2tvRkc1V1hNMlBubTBQRWdKQklHSFhnRzZrZmZHQmdq?=
 =?utf-8?B?Q1pQUTJ0cStnWjVUTWRMNTMzOWNTMnFBTHlINlRLV29xU00vVU00ZFlwSmpC?=
 =?utf-8?B?djJXeUFnTU1qdkpURkxnTEYrRTQ3aTV5NjJGaE9vK0s3MnRqZTczcVlxZG5J?=
 =?utf-8?B?VWM4K081MnBsTmtRMlZ5R0tQbk1NT2pveDVxNlkydlBYM2o2UkRUMmhuMnl6?=
 =?utf-8?B?UmlBZzE5RldpRHpOM3NMeGQ4bVdMRElWTHJPUlpMSmg1bG14akVMUzMyK2FN?=
 =?utf-8?B?R01FU2VySmNFdEJmaUFVZE1MSUZRY3hWWkVnR0VBbkpqZXVmNHhlNk04WFVV?=
 =?utf-8?B?SlNzQnovbHVwOXc5bHI4aHA4YWJ2d2hQTGVqN3VzbWtIS1hlMHBKRWtDamVU?=
 =?utf-8?B?S003NFhrVktVZ1VmeHNDb3pwaEE0S2xTRTR1elRwNmJtT01ERERuMFhxVis1?=
 =?utf-8?B?U3dZc2xSWVZPSkJwNTY3cWdYbVFZREJQdXJmQmtmeGZWb2dBLy9WV2Zaczl0?=
 =?utf-8?B?NXdVTDZleFVOWE05QjM4YUxBTlFhNU1BWFZpRUtVVFVzc2RBNzVzdXpUSWJr?=
 =?utf-8?B?bkVXM054eVByUzVLaG5ySmNZdXlrNDcwMUhsR2lveGUxRzFMSERtUXBaWkNB?=
 =?utf-8?B?WFBmejhRQTl3djZHYnRyaDU1WVhSWENTZVNyeVVkUjFGcUp6bVJycW1oT1o0?=
 =?utf-8?B?V2tYTUpLeDd2dFNLc1hpUWZJQ0VjQ21tYVpQK3VKRXBITUROekZaL29HYUMr?=
 =?utf-8?B?Y2tyVzBib05FYUlFcXVFNGw1MW1oUitwc3BWS25tOEpjdFVqbmZRSTNrdlZZ?=
 =?utf-8?B?STRuTzdVNzI3cDZhNEFidEJWL2dvM0lMeHNTMUp0SmxBOGd3ZCtucTNSRDlE?=
 =?utf-8?B?dnE3b3lFbTBoK0hpaERWbk4rdm11VU5tTmhpMTdzWlBWeWo4NDhHVVpMWGVr?=
 =?utf-8?B?ZUoxTWl5QzJBd083VDNCTHg0M09kOWFncGRpbUxnSnZFWEQ4WXQ5bksxNGVq?=
 =?utf-8?B?QWRkek15NUZDZWJyV1VMYUpJbFA2eVcxRUMzZU1ENTVKbEpaUmJEamY5Sm5j?=
 =?utf-8?B?REFIa0lUdzJiZHRYV00rU2U3L0EySlNWeWVzQ1NDd3ZJaEJXSFJGRDRnbjcv?=
 =?utf-8?B?empYcjhpMjU0eEVaMjVFa1A1SnFESllEN3dPVm9QUUt0RHBib0JNSWw3bWU2?=
 =?utf-8?B?NVhiTHBNTlVqandLOUc3N3dOZWJ5VFJGdTJKRnAzSzk4djhReEFORHVYc2tE?=
 =?utf-8?B?RHArcmxRbkFKSmkvWHFQYmw4Z1F1MGUrTTNDWENJOExFOUdZMHpjNjdGamsw?=
 =?utf-8?B?K1o3NVgxcFVUcDQ1QldLZXhDd05QRzBITnVTS3B2RjNlYmFjVldXWU1Vc1VL?=
 =?utf-8?B?TU9LWXVmSXFOdi9jSVpUOFhaRGI1aXE1YVZaN25KVUozMGJVVmF6TzloOTdi?=
 =?utf-8?B?M0pGdlFpemlMbUpPMmpPbi9zbU43TkMwMW1nTDlmSmZiZHlYWnUrZkR6ajQ2?=
 =?utf-8?B?QnQ4WjZ4aWIzTjhvZEx5WkQxcmFGVi9DZGZoc2xFN0dGd1RYdG50QVZuYkxW?=
 =?utf-8?B?M0N6aU1QMHV3RjNiNjBqNVJBdHFGdWpLb1FvM3dVcENsL1ZlS08vU1NwbklB?=
 =?utf-8?B?MmNmY1YxVmc5djlJdTlRTXFtVE5EZTFmRWhvNzgrS3VNVFZSUTNJb0xXNmxE?=
 =?utf-8?B?bjVERENybHFRUWd4WTFEMlBFeHR3SGtvQjV6bTFCTzFZT2kwbXQ3aTMyMzZE?=
 =?utf-8?B?bVNvczd1NnRyaDdhNG9VcUJUTlZGd0hYdTJxcWIrbDM4SzFRQThBQnI5RmFu?=
 =?utf-8?B?cVdwb2p4KzFrYkRqK1dTd1NNNmtGUjdUUXVVM1JkeVpGdzRVZWU2cEc4R2E4?=
 =?utf-8?B?NE1DSjd5Sk9GOHdlcFg0OWhnUXZqWDFMY1JzQm9YYjE0dTZWT2VKMSs0Ylc5?=
 =?utf-8?B?MEpSdUJya1VvR2d0ZzFVT2doN3h6blFtTHpPV0h2SlcvaW5tbXpxbUdiNW9u?=
 =?utf-8?Q?dmwkIlJFmJSRruiE+5iMzEc=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 94a21c3a-bde6-484d-e6eb-08dd528c40a2
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Feb 2025 15:27:29.1800
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ZvNW/R8ItOkTNjRwfEMyX6oOvrQbYlaA8yqRn6Ko38UWYVJe+QoKsOVc3QqSn99RyBSkvKxkTEUwaBKNBZi80lZraXQwGZciu+UDOL2GsxA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB6468
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=iHmQnIdm;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.7 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-21 at 16:10:54 +0100, Maciej Wieczor-Retman wrote:
>On 2025-02-20 at 00:31:08 +0100, Andrey Konovalov wrote:
>>On Tue, Feb 18, 2025 at 9:20=E2=80=AFAM Maciej Wieczor-Retman
>><maciej.wieczor-retman@intel.com> wrote:
>>>
>>> On x86, generic KASAN is setup in a way that needs a single
>>> KASAN_SHADOW_OFFSET value for both 4 and 5 level paging. It's required
>>> to facilitate boot time switching and it's a compiler ABI so it can't b=
e
>>> changed during runtime.
>>>
>>> Software tag-based mode doesn't tie shadow start and end to any linear
>>> addresses as part of the compiler ABI so it can be changed during
>>> runtime.
>>
>>KASAN_SHADOW_OFFSET is passed to the compiler via
>>hwasan-mapping-offset, see scripts/Makefile.kasan (for the INLINE
>>mode). So while we can change its value, it has to be known at compile
>>time. So I don't think using a runtime constant would work.
>
>I don't know about arm64, but this doesn't seem to work right now on x86. =
I
>think I recall that hwasan-mapping-offset isn't implemented on the x86 LLV=
M or
>something like that? I'm sure I saw some note about it a while ago on the
>internet but I couldn't find it today.
>
>Anyway if KASAN_SHADOW_OFFSET is not set at compile time it defaults to no=
thing
>and just doesn't get passed into kasan-params a few lines below. I assume =
that
>result seems a little too makeshift for runtime const to make sense here?
>
>>
>>Which means that KASAN_SHADOW_OFFSET has to have such a value that
>>works for both 4 and 5 level page tables. This possibly means we might
>>need something different than the first patch in this series.
>
>I'll think again about doing one offset for both paging levels so that it'=
s as
>optimal as possible.
>

Also I was wondering if you know what "hwasan-mapping-offset-dynamic" optio=
n is?
I noticed it in the llvm docs but can't find a good description what it doe=
s,
even from looking at the code in HWAddressSanitizer.cpp. If
hwasan-mapping-offset is not implemeneted for x86 I doubt this is but maybe=
 it
could help in a cleaner makefile for x86 at least? Especially once these op=
tions
will be working in x86 llvm.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
fbyaler57cdwgs5axtdpnwg52jtwx7tx2rykjro755c45mihl%40czmbriuhg3to.
