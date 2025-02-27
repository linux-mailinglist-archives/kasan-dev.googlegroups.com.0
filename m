Return-Path: <kasan-dev+bncBCMMDDFSWYCBBY5UQG7AMGQEQVFT6WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id B60C0A47DBB
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2025 13:28:20 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5fc2eb2ddf4sf856018eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Feb 2025 04:28:20 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740659299; x=1741264099; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EL8dcNSVGuEUsanUBwVmykOD8kTNjKBHrvJEY3orN2A=;
        b=uyVJVJoQYdOmJdHs43WUaK88JgfQoXdCPeWR1DBHrqOuLqIRQ75qnrj5LLhfM8Eons
         04PfUyaHZiolPr/czIlOz2US7Fm3BLY9TYpHJ7SnsGTUzzBfZchkHNj28X71CAVoxLxG
         dgzW9QYmqGoOXmsH4IdgOdvjlYneTXtCYZA29Yz0TNeGMnHoxjceot94Zlwn7PFg13xS
         sTPEuew0I5xydMOECDRogsKvTM+0222mJoDfpo++M8biEcFeFnbLJwTdf3USQrxRuaRA
         FLt+XR4izWR5n0dN2d0qhZx6CzKiRoqpArjHZGa2B4uwJPOAhMMs96sZBuWjcRsMFxIT
         4/iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740659299; x=1741264099;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=EL8dcNSVGuEUsanUBwVmykOD8kTNjKBHrvJEY3orN2A=;
        b=JumpJXuw4yzIqK1IAZf+EkI+2B+s4olgBp/3IWklu13PbEWiw+/fwJWbV4INWOYgu9
         JX8VprmoRMMMc9lY5fE8Yg6ZaDTYiiQaoS28pE/e+7JHRadQOFcNSuIUcTqdq9Ul7GVN
         tccD9pL/CNmHaJqjRoRZUCQvj08NQv7PEkywixHXyHvRlVXlgR52u84TSPuBVJLBGsw8
         Y2u/gUQgza2auic8KetIttLGKu0ILQ6LupIaGp3p5jZEJqsO9MLYCN8GlZIRJjFtDN+W
         XPdyn4CoyBr6vhB6bDyaZwrOr7CaoNXBFAacz1Lsy1aRXjVulgclSkSfNFocg2+xSJ0F
         2VGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLsZR1+q98lG0JepmnDNr4tLUwSWhNdRQAW4GYTeU+VTL5EpBrinseNgsIFS8M9xKeJ3uvrw==@lfdr.de
X-Gm-Message-State: AOJu0YwFN36HgLYXKpj/jpr3Lod7qbiXbq0yTV+59nC/j7SZ4034Dfm7
	lKd56Ount6z+DqKVouN2f/gKMCetBbjAGD5hreVDnZ1uKSE7ad7a
X-Google-Smtp-Source: AGHT+IFBKSwljHzu/XWJj6bN3x2yZ3vbYwcWheOud8M60rAHK4Q1N69cpMA0jBl7XmhizQTKQB2PnQ==
X-Received: by 2002:a05:6820:1849:b0:5fc:f3b8:78c2 with SMTP id 006d021491bc7-5fe937673e6mr5733924eaf.3.1740659299281;
        Thu, 27 Feb 2025 04:28:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGzTWE43lKFN6LAnMYWft4wTaRQU8euz5lYgYwbBNymwA==
Received: by 2002:a4a:e70d:0:b0:5fc:f0b7:c94d with SMTP id 006d021491bc7-5fea9374788ls589644eaf.2.-pod-prod-05-us;
 Thu, 27 Feb 2025 04:28:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW7GaaEUrsyHRXKHBxbuCDsIzdUyBv5OCM/Db+MjAmAxDFzzQBYmf3suubhk7RCYIR1mnw6GadMiTg=@googlegroups.com
X-Received: by 2002:a05:6808:3846:b0:3f3:fc58:4997 with SMTP id 5614622812f47-3f540fd384emr6318565b6e.32.1740659298592;
        Thu, 27 Feb 2025 04:28:18 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.14])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5feaaba0dcesi71851eaf.2.2025.02.27.04.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 27 Feb 2025 04:28:18 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.14 as permitted sender) client-ip=192.198.163.14;
X-CSE-ConnectionGUID: 1FDDokyeQ7idD8DUFkBX7Q==
X-CSE-MsgGUID: e6kWIDPYQfaajHu4iD0kSA==
X-IronPort-AV: E=McAfee;i="6700,10204,11358"; a="41798978"
X-IronPort-AV: E=Sophos;i="6.13,319,1732608000"; 
   d="scan'208";a="41798978"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by fmvoesa108.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Feb 2025 04:28:17 -0800
X-CSE-ConnectionGUID: J4x86Q82Tbei4qYeUkn+0g==
X-CSE-MsgGUID: geJEHdd2SFiLr6KApCGudQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147930528"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmviesa001.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 27 Feb 2025 04:28:15 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Thu, 27 Feb 2025 04:28:14 -0800
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Thu, 27 Feb 2025 04:28:14 -0800
Received: from NAM02-BN1-obe.outbound.protection.outlook.com (104.47.51.47) by
 edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Thu, 27 Feb 2025 04:28:14 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=n+lQlF7vizZfhtwbkO9mzB84NRCLhEReryCw/GHRD0GYaFXJxJ92PJgFtUEK9Dk8dfhNWxj2ps0V4iusn4EjpZMON9pn444aiYhDjh9Bchbjw+cmoo+gqXHgy4lRWtmXWP4OWJH2/3IcWRiZShkGMEJaxfF1VtcB1qhRn75iaJY/zLdmp4rg1audBv8VkSo4HEUwO18LNLkyRNdnbxsZOzmvC6GcnmGGUPfZ58ptFyrPWgGt+owZWek8Gio/xFkTkGwRPLSVGf4/42A925Wvp7DW2cEimcQZsSKBgTeD8RWe75yjEOGwqArWEElp4tAhqZKH5g2qiZt7zKFg4+fc3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kmOtvO92HoSLW9ObHdGLPiMy2VPSNBV0fjGnVVkX6oA=;
 b=yNVNDuUpiXANjpZNRdFFs/CbOOv5Azn49M+xPfq5jSernrruoiQL4/1fSSGoaCwTAfjqjJt9xw6OfnqncyYwO82mt72mg06WfrfCWabiT07oNk9r98mmrf9YuG8LvQPIGZSQJla0QnWqL7xzsy24Y5ikBoZxhekYzyLsMJCCZ/kJWsq1OaTZHv97BtjZuJf60qkgKMlr89JfSo7OZVTXAWj+5p7wAFSCjjuTy1LK/EnPGYtb3ceURIb6yRvdZYCtwV5aiBM6QrKqNqRzHavCnK5C+9RANqNBYlBEuGTCru9WKLZgJi22n8f93cq355+JfbOdiQqOtk2/9mkd2Wj4YA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by MW5PR11MB5883.namprd11.prod.outlook.com (2603:10b6:303:19f::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.19; Thu, 27 Feb
 2025 12:28:10 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8489.018; Thu, 27 Feb 2025
 12:28:09 +0000
Date: Thu, 27 Feb 2025 13:27:32 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Vitaly Buka <vitalybuka@google.com>, <kees@kernel.org>,
	<julian.stecklina@cyberus-technology.de>, <kevinloughlin@google.com>,
	<peterz@infradead.org>, <tglx@linutronix.de>, <justinstitt@google.com>,
	<catalin.marinas@arm.com>, <wangkefeng.wang@huawei.com>, <bhe@redhat.com>,
	<ryabinin.a.a@gmail.com>, <kirill.shutemov@linux.intel.com>,
	<will@kernel.org>, <ardb@kernel.org>, <jason.andryuk@amd.com>,
	<dave.hansen@linux.intel.com>, <pasha.tatashin@soleen.com>,
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
Subject: Re: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow
 computation
Message-ID: <agqtypvkcpju3gdsq7pnpabikm4mnnpy4kp5efqs2pvsz6ubsl@togxtecvtb74>
References: <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
 <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
 <CA+fCnZeEm+-RzqEXp1FqYJ5Gsm+mUZh5k3nq=92ZuTiqwsaWvA@mail.gmail.com>
 <qnxlqbc4cs7izjilisbjlrup4zyntjyucvfa4s6eegn72wfbkd@czthvwkdvo3v>
 <CA+fCnZdUFO0+G9HHy4oaQfEx8sm3D_ZfxdkH3y2ZojjYqTN74Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdUFO0+G9HHy4oaQfEx8sm3D_ZfxdkH3y2ZojjYqTN74Q@mail.gmail.com>
X-ClientProxiedBy: DBBPR09CA0016.eurprd09.prod.outlook.com
 (2603:10a6:10:c0::28) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|MW5PR11MB5883:EE_
X-MS-Office365-Filtering-Correlation-Id: 6f6c6504-721c-457d-8535-08dd572a31be
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?Qm9EdUFuUHdVcTlvdHh1N3dJU0JxRk9ITTdBYlk3RTF5OFdublo0WmVWM0dm?=
 =?utf-8?B?N05NZU54N1M1aW5sMmZ2bGtSaVloL1o0UEttQTMvN0xtNDZQKzdpc05GM0h2?=
 =?utf-8?B?YjJCcGFzUzBoWlRsRU41YTV0WWovZ3h3eHB2WSs1RFdvRDdWNUZPbnNiL0pK?=
 =?utf-8?B?Sk0yUFlac0xsVDUxeU9TejdseStRMkJ2T2NBb1FDMi91dE1IOGZueEFhUmpI?=
 =?utf-8?B?L2Y2Q2hhVUE5Yi9DUzhWc0xzV0crN3RsOVU4cW9uWkVnd1NPL2VmdXN1dGUv?=
 =?utf-8?B?UmJLRVBsUnZyRngxczR0WWlhaDNoQkdBNHY4Vko3YkdrcjFKU0JNYWFFSjJN?=
 =?utf-8?B?K2wxbWt2bXhCNFVTRC9hZjBCbHdtQ2pVSFc5WTFpcjJwRGwxY0dtNk8xQm5N?=
 =?utf-8?B?dlRhRm41YkpwSDRWV0EwRFBKWWUvRHlYbjZKcG9vU2tyaE5PK1NTdzZWRUU4?=
 =?utf-8?B?S1ZMZmRzaXZNNURXT1dZVjRUU3FDMjZvaVhIaUdHTjNGeDgrM3JTZFFLQ3RW?=
 =?utf-8?B?UWovdmdMakE3KzdWYTYydXJxNGxyVmQzSWw4SnI4WnAzeFBhM3Z5RTduWE9X?=
 =?utf-8?B?ZExTZDU1Q1M0YTVRcVlMZm9YbXhnSnM2RzJhNER2eDhtbndmdXgzNU80TUF1?=
 =?utf-8?B?S2J4U095dW5SYzNHMWhFNEdnWTIzVWpITVcybUVxQWllMUpQa3NEczhqeTNE?=
 =?utf-8?B?K0lTNGIwKzZyb25LcTl0THBUaUdkaXBBZGFyeFM3NzVPWU01cUxLbk5DOE14?=
 =?utf-8?B?VjNDOFFrMUtrVUNNSWU2NHdsQjlpWEs4OHkxbVRoTnhLOWxhOVVIZEdmL3FL?=
 =?utf-8?B?ZUFLRk43eTJ6L3RHRVZzOVZUZ1VsZFdJbW9QV2hxQ1V5NmpScUdHekprY1Y1?=
 =?utf-8?B?RDRVREVrR3FoWWRROFU3VGZGSGVHK2VESGM2a01qRHpQdU9RajFoeE1iaWtG?=
 =?utf-8?B?ZjhiVmkvUDMwZ3pHUlFZRHRKRmV6TTZvYmZhWUhPUjBEMFcwSDJvQ1NCOHRI?=
 =?utf-8?B?dWc5QXhQNlFIRGJDVkhFLzZ0UHZRN1RjYTh0RWdLZkIyWVhEUzNhTm1QT3Zx?=
 =?utf-8?B?Z3hqZU4remJUYlloUUNGWmpUYyt2T3hGem5LVjZWU3c1ckQ5Vm1jOUhIekJq?=
 =?utf-8?B?Q1FMWlBTNndZaEtmSXJJdFNLSGJSVnlRWWZmVlFxbDZKOHhHSXFzQXpMV3Uw?=
 =?utf-8?B?L3JaandLUS9hMHNhWHdWUWxvdVQ5WWFBcFhzU1VTSmZ1UzFKK0RMWjM5bmFy?=
 =?utf-8?B?b1VLVk03clo3WVpkemUyU3hNTHRPUEQyN3NRTnBGaXZ4MDFXbURXb3NCWUZY?=
 =?utf-8?B?TTJBQkRQYm1LSFdTUndmNEhDS2FZVytWeTdQV0xJWEs2UTJuc3kwbHBrZGFt?=
 =?utf-8?B?NDBGQ1hFVUxtcU52SW5KMmJRL1MybTZxenVFcjVpYXg2ZGg2dGlPdGtHRC9E?=
 =?utf-8?B?TnBrS0dFNHpLT0NIZVRmUFNWSlZyaUd0L2ZvSEg1RnRsZU5oWW51ZDFMa2ZV?=
 =?utf-8?B?dGYwdk13cjNweHhKNVNZS3RjWGx1blZsak96am1DQkdEK3JOS0VyTXhDdW5N?=
 =?utf-8?B?clpISWJ6NmxIMThwbnRJbFFGbzZVODRINmVDK3hNT29zSGxiS01tQVZyRkl2?=
 =?utf-8?B?VDJwRmVJMGxqWnNRRzhETm1NQmN0YmhDNGVoMGY2c0VGMVd6dnFPVFE2K0wz?=
 =?utf-8?B?ZjJVdm5rOVYzUERDZ3lYcnhKT1hhM2RMeHBSZW5NMStGLzZiN0JQcE1wQzVj?=
 =?utf-8?B?Ry94R1hQVlE4cHF1U3MwNGFZOHhVV1d5S3ZuUzB2dEdYbUcvUi9oeWM2WWpm?=
 =?utf-8?B?THVCVHZuYjI5aGhmSWNjYUJyYWFBdTAvRWJpUjcybGg1QWZMTXkwVVdjazFj?=
 =?utf-8?Q?Q8jSDSWlfL0wt?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?SlRKNnpZMlZNM1pucHZCc3hhODBoSldzVHJTcEpsaExmOVViUGkrc0pGNDVZ?=
 =?utf-8?B?Um1hWnhsV0QyVnBoRXBDaU5VQWs5aVROVEdudk1kS1IxQ05oeDZ3bkM3ZERO?=
 =?utf-8?B?aCtLNUVxNUQrb0Voc3lCUFN1amdlSm5NcFRqUjI2TUFxNWRrR3hRc2loS0lx?=
 =?utf-8?B?djdyL1B4MnBOV0ZYdkU4d1RBMHRyM2RWU0tmTU9PUTFaZFpBMTJjYzh1a3lT?=
 =?utf-8?B?elZENXdsL0xWS2dnekJCRnhZelNacGZDZThZTWFnTzUwNjhpZEY4SktxeFN1?=
 =?utf-8?B?WDVJT3BmeWRlcUdIOWN3WUlrVkV2T0U2QzVNYzZpMkRoU1pEYUFscEpGVmtt?=
 =?utf-8?B?Ly9pUFF2a2t2WTJKeERSK3B4aG1qNnY2V0lOZ0RiR0RodFdySjkvVFByZG9p?=
 =?utf-8?B?MlhjejdmTXU0RFREcDRETHRvais3WTFPU3hxZ0UwWmRKUWljQzZ4Kyt3Y2Uy?=
 =?utf-8?B?b3RuNFlQNnM2Q1VPYkFkWWEzRjE4MExPUTdnTGk1WGlzbEJwbkF2Ti9YRWo0?=
 =?utf-8?B?RTlFWmRFeFloMitycG5yUHlqZm9MYkhac3cxZis3MmpPbG8rUFgzWk80YnZu?=
 =?utf-8?B?M1N2VGNsL1hJL1pTVVdsTDJ6eVY2WVdEMU9tQjJXcWYxSmxTU1R2bmdGbDZK?=
 =?utf-8?B?QlNGL2IzbzA1MUxFdDVaZk5yckNPdmtNWkRUemRuTnI2Q0pJVDlMdHY4em5a?=
 =?utf-8?B?dStHSnU5S3F2blZqR0N6RFJWQkZ6b3d2MUgxRy9wV3JPQkFXNFF0QUxXLzBZ?=
 =?utf-8?B?eW11ZGd3STZhRnMwcjZ1eE1pSks5UW5pMGVoYzk5Zk42NWdXdzcyZ0RBbWpK?=
 =?utf-8?B?ZDJiQXBvY2RCVFpPY0NuTSs1NzlHd0cwRGlsRjg3cXN1ZjJVNW01WDI5SWVE?=
 =?utf-8?B?dTJlQXFQcEY2YXFUZ0lWYXNrMWwyZ24rb1NPV3MyUm5vUHRFdFVBbW1xT21X?=
 =?utf-8?B?YzJ6WUlydS90OTJFcEhMcFVDZTg3U2M2bGxuUlVjdDlXTFkxN3JSd3ZuQlM0?=
 =?utf-8?B?WEdaOE4xa2FUeUR3U1I1WElVUmRwSGM2QkpQTDdUSDd3L00wZmNEeTJ5QWpB?=
 =?utf-8?B?NjVRYW83aHVjZ1owK2FjR2UwV1ArWUR0d1N4MzZrV21yTitkM3NIWkZ3NFZp?=
 =?utf-8?B?MkliVzczaExnaXZ6ZFdUL1dvdU1QOHdULy9MTDBNL3BFSTlZODJ4S3k4UDF1?=
 =?utf-8?B?TFQ0blA5bnJTZWh2QnBVM1NscUNjQ2MxNUlHNjRpT29YcGNEL3NLRWJXVGtF?=
 =?utf-8?B?dUIwZDdscC9zU1FqcjRpaE53aEhPYWZtMnVkSlh2a0FZeWpna0hwaXZWR2hK?=
 =?utf-8?B?ZzE5bWhhOUh2TWF2L3g5M0RsZzd2aXh1eTNDQVNON2JOd2JHQ3lreU9nQ091?=
 =?utf-8?B?cCsrNmJTSFRjaHBvcUpKaExBdFZGZitqbmpkVys5VHdVTWdyUXlYL1Frdkky?=
 =?utf-8?B?N3VYTXVaQjkzazZlSGt6Q1lEYk01L1ROWGNqNmFWR09RUkJEd29sM3RTamVv?=
 =?utf-8?B?UW53enNtZXlONWlVSHpsVnpkQmdGc0xUMFUxcjBKSGphT2VyN0V6eGlYSDZU?=
 =?utf-8?B?aVQ0ZG1WVFl4YWVuYURFYmk1MDJZdmU5clBpWmRaVjhkWjFkV3NXRkdmTitM?=
 =?utf-8?B?YVFQMHN1Q3IvZjdpOWhGd1FIQXZSK08zYWticzM3aWZCSTMreXhmaTJMbW9u?=
 =?utf-8?B?QUltTE1Lb0Z3UU95UzZNYnlFNS9ZTGE1SVF0ZUlhekt0ZVBMSURQWWtkZy9X?=
 =?utf-8?B?bUhNc0VoeUEzelZLS0s0ajczUWMzbmdjSmhOSU9RMElJenhSQmtWNndzSlBh?=
 =?utf-8?B?VUpBak9wQmZibFZuYWpnVkxrcnVDY2phNUMySGI5VzFIVmYwS2tDUmtTK0ZM?=
 =?utf-8?B?NWRvekpFei82aVNLcnZQQURnNnRkSDVyYkM0Tk94V0hlbW5SU3VMU1JwRTZl?=
 =?utf-8?B?QnJJK09lNG5xWUU3NHlTRVowR3VhZXowdUZFTS9rSXRhWFhBM2k0V2dwSWhz?=
 =?utf-8?B?RjV5NEQ5Si9aRW5XbWNaMUYzdU5SQk9ib3BVL2EzSTU4OFF0TmRsOTV0ZVpY?=
 =?utf-8?B?Wmxrdm82V3Jib2sxOUhPUHZzblE1RG4wZzZNQ3VuSjNWYkhjREVIdmJiRGFO?=
 =?utf-8?B?WlpJUFVIczNQelBwVkg4VDFUTU1sejZ1OFF3Qnc2RElDcU5NcW9IOHd0V0lQ?=
 =?utf-8?Q?+NCr+39R9CAL+Zw2mMI1alI=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 6f6c6504-721c-457d-8535-08dd572a31be
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Feb 2025 12:28:09.4185
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: V4ZXI0Ec0xKODwFQGjroFzjrUAyJ1L/wReirYosMs4CcBtBlIK+dkUHluC43sgixU/qejtiZdVQSY+QgCRfJ3FOaHAZNHGgkwo/YGztQJAw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW5PR11MB5883
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dRWANeIG;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.14 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-26 at 20:44:35 +0100, Andrey Konovalov wrote:
>On Wed, Feb 26, 2025 at 5:43=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> >What value can bit 63 and take for _valid kernel_ pointers (on which
>> >KASAN is intended to operate)? If it is always 1, we could arguably
>> >change the compiler to do | 0xFE for CompileKernel. Which would leave
>> >us with only one region to check: [0xfe00000000000000,
>> >0xffffffffffffffff]. But I don't know whether changing the compiler
>> >makes sense: it technically does as instructed by the LAM spec.
>> >(Vitaly, any thoughts? For context: we are discussing how to check
>> >whether a pointer can be a result of a memory-to-shadow mapping
>> >applied to a potentially invalid pointer in kernel HWASAN.)
>>
>> With LAM, valid pointers need to have bits 63 and 56 equal for 5 level p=
aging
>> and bits 63 and 47 equal for 4 level paging. Both set for kernel address=
es and
>> both clear for user addresses.
>
>Ah, OK. Then I guess we could even change to compiler to do | 0xFF,
>same as arm. But I don't know if this makes sense.

I guess it wouldn't be resetting the tag anymore, just some agreed upon set=
 of
bits. If this argument is just for the non_canonical_hook() purposes I supp=
ose
we can leave it as is and check the two ranges in the kernel.

>
>> >With the way the compiler works right now, for the perfectly precise
>> >check, I think we need to check 2 ranges: [0xfe00000000000000,
>> >0xffffffffffffffff] for when bit 63 is set (of a potentially-invalid
>> >pointer to which memory-to-shadow mapping is to be applied) and
>> >[0x7e00000000000000, 0x7fffffffffffffff] for when bit 63 is reset. Bit
>> >56 ranges through [0, 1] in both cases.
>> >
>> >However, in these patches, you use only bits [60:57]. The compiler is
>> >not aware of this, so it still sets bits [62:57], and we end up with
>> >the same two ranges. But in the KASAN code, you only set bits [60:57],
>> >and thus we can end up with 8 potential ranges (2 possible values for
>> >each of the top 3 bits), which gets complicated. So checking only one
>> >range that covers all of them seems to be reasonable for simplicity
>> >even though not entirely precise. And yes, [0x1e00000000000000,
>> >0xffffffffffffffff] looks like the what we need.
>>
>> Aren't the 2 ranges you mentioned in the previous paragraph still valid,=
 no
>> matter what bits the __tag_set() function uses? I mean bits 62:57 are st=
ill
>> reset by the compiler so bits 62:61 still won't matter. For example addr=
esses
>> 0x1e00000000000000 and 0x3e00000000000000 will resolve to the same thing=
 after
>> the compiler is done with them right?
>
>Ah, yes, you're right, it's the same 2 ranges.
>
>I was thinking about the outline instrumentation mode, where the
>shadow address would be calculated based on resetting only bits
>[60:57]. But then there we have a addr_has_metadata() check in
>kasan_check_range(), so KASAN should not try to deference a bad shadow
>address and thus should not reach kasan_non_canonical_hook() anyway.

Okay, so I guess we should do the same check for both arm64 and x86 right? =
(and
risc-v in the future). Just use the wider range - in this case the 2 ranges=
 that
x86 needs. Then it could look something like:

			// 0xffffffffffffffff maps just below the shadow offset
	if (addr > KASAN_SHADOW_OFFSET ||
			// and check below the most negative address
		(addr < kasan_mem_to_shadow(0xFE << 56) &&
			// biggest positive address that overflows so check both above it
		addr > kasan_mem_to_shadow(~0UL >> 1)) ||
			// smallest positive address but will overflow so check addresses below =
it
		addr < kasan_mem_to_shadow(0x7E << 56))
		return

so first two lines deal with the first range, and the next two lines deal w=
ith
the second one.

Or do you want me to make this part of non_canonical_hook() arch specific f=
or
maximum accuracy?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
gqtypvkcpju3gdsq7pnpabikm4mnnpy4kp5efqs2pvsz6ubsl%40togxtecvtb74.
