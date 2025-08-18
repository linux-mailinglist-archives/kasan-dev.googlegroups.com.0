Return-Path: <kasan-dev+bncBCMMDDFSWYCBB3GWRLCQMGQEFBZGPQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D420B2981F
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 06:26:22 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-24457f54bb2sf89894085ad.0
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Aug 2025 21:26:22 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755491180; x=1756095980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hcOL72Uxqv0qveY+8MvJCwPC8WRT/v8KABCLFzIUTIw=;
        b=RnLiwslLSEW/J5rH+eFgdVs+aiyZZWKD3KUgf3WmtsrAiHZ51ipE3TOJNYnhFmgvAk
         Jy4JWHC9ROyvZCYp+4ethpU2/Y/OL/Nd2ZsgcjakXAsO6xAC8AONrScXOf7FyeJdYLnW
         xfX30oOanr2/s1Tp1Gv9e0Q5xG8f4TLpXCDzJ1bKAe1KG1Wgs3pywW/E1RhQtqKZ9S0c
         4hJ8V2CbHXuwoAQ/lYD9EIj7AFm5hFhO1u3qHI7cplMt/PK7agmR5s2DSpCGDOCtuggc
         BNEGN8JvAg3+tQqH+IWxnfxmnwMUnqHdF+z3iDA/ksYrbbss34tGh2sHMwbnarNKlP/E
         URyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755491180; x=1756095980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hcOL72Uxqv0qveY+8MvJCwPC8WRT/v8KABCLFzIUTIw=;
        b=oEuVP8qZ/ANJDGb1odvCUNYORepIIgUQYzs/VfWLJaBmkQLk26J+V83bR+EuaHf1gB
         gFEAg9hTf6uiNfkQnkFsJqobJUsn9AK0/hJ7RU+PWpxeq5lqoqkCXm8dseaitTi1judI
         /9UDMDOsDirNn+EElCtJFFgU+jDXNFgTMlCg/Uy64tPlo6NCXBUCKelHhKG9ZIoHX2l5
         lY6CfGOTCw+szUxROMU/rWp6aVdp9EaA9GwRRztssGwLL3d2VDZohRzZYGDvkq6qznbn
         bKHcrBTRbjNlKcC2Pq3BS088nY81V55k8SqoFt1zw7kfbim1q0EKn6wnd4duZJm0wNZU
         5KVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWFla1VN4BpEgaNbZu0gGAojV6Cl0ngeQrgNHFzdqv2JgcrAeIilWVxAkwNyWaWK6Aqi1RBiw==@lfdr.de
X-Gm-Message-State: AOJu0Yw2l3v6c5kfbVtWCKPh3qpbW64IxhfzqqLDfSMjxH3E5RcOI60m
	JjZwXtlnqojgNbhr+93fkKy1vJQY2X4RnfAdt2gs3fN2itpImpDov9x7
X-Google-Smtp-Source: AGHT+IE50/Zx0wWSbdAxzeEWyhJq4J1r8v0X9DtgnEVrxM0ChEdjYIGhLFSScXnt69wN+T2EitxJGw==
X-Received: by 2002:a17:902:e842:b0:235:ed01:18cd with SMTP id d9443c01a7336-2446d99e6acmr157744435ad.44.1755491180334;
        Sun, 17 Aug 2025 21:26:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc5Prww7EqR4XSXBBK5nY5x4w9Dsc9dwsd97vwV3IFdpw==
Received: by 2002:a17:903:2301:b0:234:d1d3:ca2 with SMTP id
 d9443c01a7336-244575a7ff7ls42281165ad.1.-pod-prod-03-us; Sun, 17 Aug 2025
 21:26:19 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWc2ce9nW1uJasZIFqYymKj/dA/LZBNgU5WQkkI7aLtUCuoRemSuW90GPcUW9IRR+OXK3iafSzjFmc=@googlegroups.com
X-Received: by 2002:a17:902:da92:b0:237:f76f:ce34 with SMTP id d9443c01a7336-2446d759137mr163603845ad.15.1755491179013;
        Sun, 17 Aug 2025 21:26:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755491179; cv=fail;
        d=google.com; s=arc-20240605;
        b=lHshEGRYCLIOOQmfY22g1mQZzZ9aTwh2QAnS+2db0BAAf2TYgNaxKoMhq5oR5rfjAP
         N5koqMy8dZyvcXptGtc4spICHgnmPS0lv0je+abyd6BdisruDAC+UdyvUfZzivTET8Fq
         y83KZI0PhEuEOKOW8Z5GTw35pHtN4HOwOLPRmj5TOkfu9D9Q8TBOK7SWlU9eVgsNHozR
         ynm78nF+gw09LU1SSzFYNLaX9LZKvO+EuWjTXvlGMwvbjuXE4l7pLS2YH5M8gdoHYB6V
         xknSyEfc89RtXT6AQATl5K1OrH727dlIonccrCYTIEuD+K/aItUfJxbLS307xE30U9e7
         gGWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=BADIDDv5Fi6fSSJsaH68dY9FTVCPr/Eyq1rOQxbbSJo=;
        fh=YfqbzSvxCVez2ZmyEqIWPhXY5CaBVAP7tZRZgm6t27s=;
        b=RTUA/xsugj8IJ7B7e1pyOhpI/2tzbnII8vDw7zJ29qwLV+6ABgHyZ0rX3hAC28dCSO
         9i/msDeTEcLwV6YHhRxY6CszJAAWsOBXYTD4RCvcKWBuiyJyQIwVl3aP+I2wRMJukWzS
         J1yAf74cMIPdUpxxcvZk07WAC1/Yre9gK8DBCDjMIVxbohXhtBnB0Taumsh3s/mnBIUA
         XACGlMqmRxF29T8+gjGwFuwdU4/BBv6AxOveQxAKXLo/zBjGLiw8IfY5Wkp1wyeAtYUn
         XfGUaF2JAGRV5LSNVP6q2tiIkYR5fvCYS1wOlFQDnM8/z2zjwFlaA6jsAr/6xdW8bO4g
         a31w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=OHU++Srz;
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.13 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.13])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2446d525defsi3567315ad.6.2025.08.17.21.26.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 17 Aug 2025 21:26:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.13 as permitted sender) client-ip=198.175.65.13;
X-CSE-ConnectionGUID: eaTJ6IxdSou8SEqGTZBBPA==
X-CSE-MsgGUID: /54dfB8jTsqyV9yWcT3+QQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11524"; a="68797693"
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="68797693"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 21:26:17 -0700
X-CSE-ConnectionGUID: 6b4qvhTjSkqaCKeGR4bDeA==
X-CSE-MsgGUID: KTT+J61jTGSl2wqWdcBC7g==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,293,1747724400"; 
   d="scan'208";a="167449412"
Received: from fmsmsx903.amr.corp.intel.com ([10.18.126.92])
  by orviesa007.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Aug 2025 21:26:16 -0700
Received: from FMSMSX903.amr.corp.intel.com (10.18.126.92) by
 fmsmsx903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Sun, 17 Aug 2025 21:26:14 -0700
Received: from fmsedg903.ED.cps.intel.com (10.1.192.145) by
 FMSMSX903.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Sun, 17 Aug 2025 21:26:14 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (40.107.94.45) by
 edgegateway.intel.com (192.55.55.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Sun, 17 Aug 2025 21:26:14 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Jxb3JQSu1ODQbcXqtqf0JhAtZ+ZmI+8D8CSCb+V8ph9LPXjfrwCHyplJJJzUZt99gCHKJhQAFpOdUdfEJ+4Vx35NqzHCv8kOZ/noc1Y9Pz0xaUgD7XdsoEEDAshChd1CZlYi3mAfjyKZ2BVR7BiIY4PWtTdOcgnBnW/IategP14CsdyY4EBtRjpYfKJ/v8dP3gzZGY1U0aCqVGLqmdk9Ti9NLXsukSjNVk9yUXCkY0RJUWKLLh1Rr9g9FFxYGHJUP93O2+8zV9pw2z8Ot+Tn+v6Tm5GTwjWJQC2x53xb1+cvhHPtQLTNsolDux4lim1XfxSJhYDpfPKWCSLvuc2sRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=56kmjPSgiKy2l/WQHdzZAjlNCu2Uae2yrfhn6+CGtoM=;
 b=Pc+BfvpmjXFgme75YF5k4wa6HjOloPqR+6jPKCJ35nhTXmAqmi6aXWqZImFz2oZ7vx1gKg5p9wYdgaFIXfCk5/o/2xwp7xf+6R8yCGIFX5dP4Z9XjqIFNK79CkDG3yz7pOVmruejp0/agUx8mS7PxCbO3MwKAVTSjs7zMPfiaEB8aFcpXZI1zHg+AC8s0fPnIjZEqr3thvEQqc0Cvs6fc8GXkOQyvBW3UVWR3Uo7MAJSmtEgwcJfCzwxdF4ATEXELk++5rGg3xleWRtmRqg+uMpLu0U9HjIVguRsAE+a9fBEU9BILRZr4hgmhOda7fJv0Q0tR9HQZFoyetxZHJdJeg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by IA1PR11MB6419.namprd11.prod.outlook.com (2603:10b6:208:3a9::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.19; Mon, 18 Aug
 2025 04:26:06 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%6]) with mapi id 15.20.9031.023; Mon, 18 Aug 2025
 04:26:06 +0000
Date: Mon, 18 Aug 2025 06:24:44 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Ada Couprie Diaz <ada.coupriediaz@arm.com>
CC: <nathan@kernel.org>, <arnd@arndb.de>, <broonie@kernel.org>,
	<Liam.Howlett@oracle.com>, <urezki@gmail.com>, <will@kernel.org>,
	<kaleshsingh@google.com>, <rppt@kernel.org>, <leitao@debian.org>,
	<coxu@redhat.com>, <surenb@google.com>, <akpm@linux-foundation.org>,
	<luto@kernel.org>, <jpoimboe@kernel.org>, <changyuanl@google.com>,
	<hpa@zytor.com>, <dvyukov@google.com>, <kas@kernel.org>, <corbet@lwn.net>,
	<vincenzo.frascino@arm.com>, <smostafa@google.com>,
	<nick.desaulniers+lkml@gmail.com>, <morbo@google.com>,
	<andreyknvl@gmail.com>, <alexander.shishkin@linux.intel.com>,
	<thiago.bauermann@linaro.org>, <catalin.marinas@arm.com>,
	<ryabinin.a.a@gmail.com>, <jan.kiszka@siemens.com>, <jbohac@suse.cz>,
	<dan.j.williams@intel.com>, <joel.granados@kernel.org>, <baohua@kernel.org>,
	<kevin.brodsky@arm.com>, <nicolas.schier@linux.dev>, <pcc@google.com>,
	<andriy.shevchenko@linux.intel.com>, <wei.liu@kernel.org>, <bp@alien8.de>,
	<xin@zytor.com>, <pankaj.gupta@amd.com>, <vbabka@suse.cz>,
	<glider@google.com>, <jgross@suse.com>, <kees@kernel.org>,
	<jhubbard@nvidia.com>, <joey.gouly@arm.com>, <ardb@kernel.org>,
	<thuth@redhat.com>, <pasha.tatashin@soleen.com>,
	<kristina.martsenko@arm.com>, <bigeasy@linutronix.de>,
	<lorenzo.stoakes@oracle.com>, <jason.andryuk@amd.com>, <david@redhat.com>,
	<graf@amazon.com>, <wangkefeng.wang@huawei.com>, <ziy@nvidia.com>,
	<mark.rutland@arm.com>, <dave.hansen@linux.intel.com>,
	<samuel.holland@sifive.com>, <kbingham@kernel.org>,
	<trintaeoitogc@gmail.com>, <scott@os.amperecomputing.com>,
	<justinstitt@google.com>, <kuan-ying.lee@canonical.com>, <maz@kernel.org>,
	<tglx@linutronix.de>, <samitolvanen@google.com>, <mhocko@suse.com>,
	<nunodasneves@linux.microsoft.com>, <brgerst@gmail.com>,
	<willy@infradead.org>, <ubizjak@gmail.com>, <peterz@infradead.org>,
	<mingo@redhat.com>, <sohil.mehta@intel.com>, <linux-mm@kvack.org>,
	<linux-kbuild@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<x86@kernel.org>, <llvm@lists.linux.dev>, <kasan-dev@googlegroups.com>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 02/18] kasan: sw_tags: Support tag widths less than 8
 bits
Message-ID: <g4fm3avej2ss3am377ebv5og4kl5crano4n7gwl3hwxff4gx7s@uq2hb3egscno>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <780347f3897ea97e90968de028c9dd02f466204e.1755004923.git.maciej.wieczor-retman@intel.com>
 <cae90aa0-9fa6-4066-bbc0-ba391f908fb2@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <cae90aa0-9fa6-4066-bbc0-ba391f908fb2@arm.com>
X-ClientProxiedBy: DUZP191CA0018.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:10:4f9::8) To BN6PR11MB3923.namprd11.prod.outlook.com
 (2603:10b6:405:78::34)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|IA1PR11MB6419:EE_
X-MS-Office365-Filtering-Correlation-Id: aad6271b-dd35-4c10-3c82-08ddde0f5925
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?GwXtDYWN0/6A2zzfTqVA5WvFstj1NyikNtG3DXi9uXbL5s5oDPS/zZagJK?=
 =?iso-8859-1?Q?134yH/V+W2L3yHItDh7R/uRu616KzKTk3h3T1oOwokD0RqVcbuX7rOsS9u?=
 =?iso-8859-1?Q?LsFcvqgLgjH6szVRttMk6lEb/x9Oo1jaDYyfsbHsOr/c5qWaEnoRZ1SPtG?=
 =?iso-8859-1?Q?teqrWWMJiVnNcNTsh0c4dpQRcLfENDaORMjg/g1z9nR08iZe9KVXdJq84j?=
 =?iso-8859-1?Q?1o/8QDOSD5F4sp2VP7Guu9m2sKX+gTB/llqiuX90+xQWDPcMNWIszpnW6b?=
 =?iso-8859-1?Q?IB4IyT2niFdvnr5mNifFTpLYeC0R7t5nqUS55dIdtoczcrSMd6diafRHpo?=
 =?iso-8859-1?Q?qCHDt2YsnK5A0rFBAJ15PZnOglw2gYCt2lbGK6kWztBQ3/VxqVSYzF0Yuk?=
 =?iso-8859-1?Q?lA0AjzBa9HMnkpTAjYui3XyvsKWzKy6ewgd8pHOdntDTa8Oge3alHV7WsY?=
 =?iso-8859-1?Q?dsixhmRHDeQlapTkJQ0jfcduYHetQc7tyj6yVL9TzsW8eIRM/QKF88lW1b?=
 =?iso-8859-1?Q?/Zcz+RwbELimtfLoPfkNjcAnfuTeHW7YUA1uTYaFWbb8sK5kmQAI3A9fyp?=
 =?iso-8859-1?Q?2nOGkzs5FZkhj/XhPNjQauHZ1Q11pNr+bHjZGVO6sH2UfdBWJ96SaG7jkY?=
 =?iso-8859-1?Q?WJUhigPq/kyok8O0qP9mjKX2H/ZR9473ygCdeMk7GfU24JtcDLlB/PYG8A?=
 =?iso-8859-1?Q?pZi/Xq/37NSJ1bXQxVar6iszPJFp2cj+poW0OlIAoKSB2v++FdTwkGK3E1?=
 =?iso-8859-1?Q?dgrLdzj3cJtfJWr6+T8HGx6IJWB96BmLlv1Ab71XIVaJmHVvjAISIliVdV?=
 =?iso-8859-1?Q?bK7Wx+MFiazNgCBNcQOoWLCCRDgWJTQtbwfzamdqQVSba6obU9fVhj9s80?=
 =?iso-8859-1?Q?ieihFa3nKJqP2vXV6tF80exXTUQRH3tyJFaEfBYXmFx+8ePYNaPagj2IsY?=
 =?iso-8859-1?Q?ySB83PvJ2f4aLT+YkyVbBO0uvmYTUoP1P9GpTmL+KChqqNziY0S05eW3Yh?=
 =?iso-8859-1?Q?efe+Z1HIEbFC70unGMrnrVgrWgignKG8gp3h+TEzdo34bE1wfJYHAPlQlH?=
 =?iso-8859-1?Q?OoWIU1E7VSL5kccpq7lXhFwD/+pkgfpusirzVGFZ+WjYAE3iE0OqmFWOau?=
 =?iso-8859-1?Q?jTk+SagSVk/3FP9NfLpgQAAPFQqYJBNOoFmj7AxAQF2pKFo7DnathFU/pb?=
 =?iso-8859-1?Q?zzGTBTETesy6K4w4ty7RwKn2gjwakFxcrlc3KQNlqwre6EChiDk4eMNTYm?=
 =?iso-8859-1?Q?TwXs0Kz5ri5O1C8VKTF2yooyxZTfwBiACXna6DVHWUOtd40CiuBb+/7XEh?=
 =?iso-8859-1?Q?dZbDqn7iIZOOQHCjrxjn+it2i6zVnx+Cu/WoGXh0v88RHwCliMPwjhZzSA?=
 =?iso-8859-1?Q?iSUbELtWCPVdryFFe9VeaUQRDbBV4fi9L0nOITcEFaNFJt9Alm/1q80Mz0?=
 =?iso-8859-1?Q?ND9Y0uUC/mAtX4k1mzoTfTES9qYPBvUeHDvEOOo1dpME3SMrjLY0oLK9bT?=
 =?iso-8859-1?Q?M=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?rpdnBcSo+bh/nWFcoNHSMawTtYqAFDAbrnBKzFRAscpGhiIWSql8xQehWh?=
 =?iso-8859-1?Q?3TtComW9vhC7+ItLwWjPq2IOFl7Mp5TqDAFeFHywB4JCWFIh2foSYiBmJN?=
 =?iso-8859-1?Q?eRkr+kZLwyzqneRtNE5TIJ7u6Lio/Fx6H4g0kXo3aAAZZk4Q8LilyWoREW?=
 =?iso-8859-1?Q?UYblEVa3K1S7dZ+ivA3hlJCuUM+3LI6ED4Eb3TfgYdr2ThMApCl/fB5eSj?=
 =?iso-8859-1?Q?hGGVS1ZLBUN/rYG8fxYtcqVUtcxAUoyd/qnjyPwispoZW6APDcTiZ3LXrV?=
 =?iso-8859-1?Q?CFR7S+Wa5SNMwq18wCRbexfbHLpQxRw7Iev6hY+T4CDIvHTdItTlSJo/Yq?=
 =?iso-8859-1?Q?gzWD16Jqvbig52YEWQocSRtErb1QegImYqyvPzzb9OKFe5vPanYrgbesPE?=
 =?iso-8859-1?Q?2KnMpaD2ih4aKxMF36bVvFgPRwH6O+Wcx/unF938s7Y5dVv42jj/R2r2sX?=
 =?iso-8859-1?Q?VrsUIxCTzY0RcvwJoMSX8SXXPJfY6U8CColv/8AUSYvl9klTBaKy72XSj3?=
 =?iso-8859-1?Q?NkLOqWmjOsI4dhVQDIyHZyLxKIGwSxUHtsJCd/rQdxYukWCf5M8hRGKUmN?=
 =?iso-8859-1?Q?PudwmYB004OW1DC6KJAs6jR0T/DwFYhlMHX/kli61YJ4XXhCDqL8qZwKmT?=
 =?iso-8859-1?Q?J1Bbq/KzurJhr9TlPaLK+fMzNE0LSzErIcZ/EHwM4YWjzHs7LTkciHoDdU?=
 =?iso-8859-1?Q?nLQT/bvN9qmVksDLVFQYhH+ThvtxZ+MUPlHrgNhk29N4EhMMSn2aRgOKYw?=
 =?iso-8859-1?Q?reKE0NjP3EbVl5qloVOfGvwt3cULlH2Vlx2k9fqc++PYxydEEDMmUJbpWL?=
 =?iso-8859-1?Q?R3RmPyQo5K37L0JZD95d73zbFsQ8AnEQ+ir5xQmnB2yBhS7Cu+NOG2NZx5?=
 =?iso-8859-1?Q?1MOc27pRc0+xQNIGTrPgLCnei5mp4cxu7brAq23cstnVNhUBOuOlIFj+pd?=
 =?iso-8859-1?Q?N84RuNmBiz/mkA1TKdCwgPWxPD/1T9ADqi0lweO1nXEOqVQZoN3bmEnUux?=
 =?iso-8859-1?Q?eOgWjzR6IYrIsDhW0XCf0Art47Dq8pxbIHTurv1WDNjJuZmZNwj+IOTQAB?=
 =?iso-8859-1?Q?fKiFnlBsDD1PngwF5mn4G+dEM7CWHeUi41GXGBSLLSNVQrvxPghn/4Aunb?=
 =?iso-8859-1?Q?ssLJdp6uD1AbguYWErQi1yUC5SUiYDQ9pjtK6NOCavq9/bNgbFIvxaPwz9?=
 =?iso-8859-1?Q?UalNwGn3LdX7iyIQdvUXxfWxETh8l8ji3oYqAOgCGFSV/d+j89TdsWWMVC?=
 =?iso-8859-1?Q?xJAx0CFhobo2yk8UQNbIc5A8uIU4lTYzWKt/5oFRrm2aexTUsoq5qus6ef?=
 =?iso-8859-1?Q?7PaL6eyOPfQDF3C5GewZfz2S1GzeAt9ECJspxGEtuggTYMg1lh09m2S0kz?=
 =?iso-8859-1?Q?GaS/JFksUTiWDKlK3iL5lA5SachdS0EJsiL6gWy/r0LLfzCIPBOCyhtTEP?=
 =?iso-8859-1?Q?8D+VBoxarKtw5uJd6vs93bnZWUd6NA0HBkzh/SutGr366dyzbYK9qkbnH4?=
 =?iso-8859-1?Q?lVXpospx9oGA2hSWlc832P9NeEWPVzGwjcOvUWNFkzHVuZ7ZVAtmvuMA8z?=
 =?iso-8859-1?Q?wkLjuvrcm92CHLPooB0Acg2WxT6XIJkqu9taD6OCpNPmvuY7OXBm8Ob2zM?=
 =?iso-8859-1?Q?kFyiqGXjgR/EPuXDr541XSQMnNtjv/Y9j4GW2GDpJ4MMJDN8xzL1tykDyV?=
 =?iso-8859-1?Q?2COyqA6PUr/7+f3UTJ8=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: aad6271b-dd35-4c10-3c82-08ddde0f5925
X-MS-Exchange-CrossTenant-AuthSource: BN6PR11MB3923.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Aug 2025 04:26:06.2247
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: b2G59WhXEHdomVpYxHPAKIMI+x35k0cfpH4LIEk3m5r82zBtfwNmQtv8q6ddhlKgimoyomRyC1nK5rNhHyBrfQ/VAIUTCvUu9/yGac+LnuQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB6419
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=OHU++Srz;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
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

Hi, thanks for pointing it out :).

I'll cross compile for arm64 it with different KASAN settings and fix any s=
uch
errors. I did this a while ago and it went okay then, but there were so man=
y
rebases in the meantime I must have missed something.

Kind regards
Maciej Wiecz=C3=B3r-Retman

On 2025-08-13 at 15:48:32 +0100, Ada Couprie Diaz wrote:
>Hi,
>
>On 12/08/2025 14:23, Maciej Wieczor-Retman wrote:
>> From: Samuel Holland <samuel.holland@sifive.com>
>>=20
>> Allow architectures to override KASAN_TAG_KERNEL in asm/kasan.h. This
>> is needed on RISC-V, which supports 57-bit virtual addresses and 7-bit
>> pointer tags. For consistency, move the arm64 MTE definition of
>> KASAN_TAG_MIN to asm/kasan.h, since it is also architecture-dependent;
>> RISC-V's equivalent extension is expected to support 7-bit hardware
>> memory tags.
>>=20
>> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>>   arch/arm64/include/asm/kasan.h   |  6 ++++--
>>   arch/arm64/include/asm/uaccess.h |  1 +
>>   include/linux/kasan-tags.h       | 13 ++++++++-----
>>   3 files changed, 13 insertions(+), 7 deletions(-)
>>=20
>> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kas=
an.h
>> index e1b57c13f8a4..4ab419df8b93 100644
>> --- a/arch/arm64/include/asm/kasan.h
>> +++ b/arch/arm64/include/asm/kasan.h
>> @@ -6,8 +6,10 @@
>>   #include <linux/linkage.h>
>>   #include <asm/memory.h>
>> -#include <asm/mte-kasan.h>
>> -#include <asm/pgtable-types.h>
>> +
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +#define KASAN_TAG_MIN			0xF0 /* minimum value for random tags */
>> +#endif
>Building CONFIG_KASAN_HW_TAGS with -Werror on arm64 fails here
>due to a warning about KASAN_TAG_MIN being redefined.
>
>On my side the error got triggered when compiling
>arch/arm64/kernel/asm-offsets.c due to the ordering of some includes :
>from <asm/processor.h>, <linux/kasan-tags.h> ends up being included
>(by <asm/cpufeatures.h> including <asm/sysreg.h>) before <asm/kasan.h>.
>(Build trace at the end for reference)
>
>Adding `#undef KASAN_TAG_MIN` before redefining the arch version
>allows building CONFIG_KASAN_HW_TAGS on arm64 without
>further issues, but I don't know if this is most appropriate fix.Thanks, A=
da
>---
>
>  CC      arch/arm64/kernel/asm-offsets.s
>In file included from ./arch/arm64/include/asm/processor.h:42,
>                 from ./include/asm-generic/qrwlock.h:18,
>                 from ./arch/arm64/include/generated/asm/qrwlock.h:1,
>                 from ./arch/arm64/include/asm/spinlock.h:9,
>                 from ./include/linux/spinlock.h:95,
>                 from ./include/linux/mmzone.h:8,
>                 from ./include/linux/gfp.h:7,
>                 from ./include/linux/slab.h:16,
>                 from ./include/linux/resource_ext.h:11,
>                 from ./include/linux/acpi.h:13,
>                 from ./include/acpi/apei.h:9,
>                 from ./include/acpi/ghes.h:5,
>                 from ./include/linux/arm_sdei.h:8,
>                 from ./arch/arm64/kernel/asm-offsets.c:10:
>./arch/arm64/include/asm/kasan.h:11: error: "KASAN_TAG_MIN" redefined [-We=
rror]
>   11 | #define KASAN_TAG_MIN                   0xF0 /* minimum value for =
random tags */
>      |
>In file included from ./arch/arm64/include/asm/sysreg.h:14,
>                 from ./arch/arm64/include/asm/cputype.h:250,
>                 from ./arch/arm64/include/asm/cache.h:43,
>                 from ./include/vdso/cache.h:5,
>                 from ./include/linux/cache.h:6,
>                 from ./include/linux/slab.h:15:
>./include/linux/kasan-tags.h:23: note: this is the location of the previou=
s definition
>   23 | #define KASAN_TAG_MIN           0x00 /* minimum value for random t=
ags */
>      |
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/g=
4fm3avej2ss3am377ebv5og4kl5crano4n7gwl3hwxff4gx7s%40uq2hb3egscno.
