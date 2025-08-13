Return-Path: <kasan-dev+bncBCMMDDFSWYCBBOWX6HCAMGQEWKWDNIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 51314B2478F
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 12:40:59 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b06a73b55asf157498951cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 03:40:59 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755081658; x=1755686458; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WSO7YN8nGY8lDkGM+5oPmPNT48RLwVGC11JgcLWXZnc=;
        b=H/pm5SqAGE+JAtHjQKDVeHt+xRuwwm5CqeFCJ11vDlyt6lVQl0X+kBe320iVVIEzpE
         fx9qnoed6e6/gU+RsyWvxOsJ1F8+9hpB8suG3JEesKWHXI1H49Ieu7orYbkrOz9jE7sl
         mr4Z1U5u/vCvtixC7fdQFavt2jfWqf9wByMu8h8ZaRDhyX/jY4zWl0p7R4dr/GSxFO2h
         +vvNkgeqMuFq9wqjR9/wBLNiyaSXooio2ZWcakXLbblEeQ+qgUbiqgNugBzlNtIhU6bi
         ++21OK1GK2tw5XBidrHzhNzZm5MYoF7m2ZwF13KOTF2MAh/pfzVAvVIU1rhLhlByokqi
         2xdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755081658; x=1755686458;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WSO7YN8nGY8lDkGM+5oPmPNT48RLwVGC11JgcLWXZnc=;
        b=BmHTbuZuT+J44BFZXVBHOyH2UwHSA4HZs8X0rLB85gZ/JWkWiJiPj+SI5j4Lr9HjTc
         jRXdeNnmZ77kl7WbRBLYTq4WKiHdtx5hpZ/s2Ml6kYO723Md2uLAtQrkMBRbwAG0Bu8q
         4PnyiBLRlXbkh5RsR0SGeKYSoKjcBiH/WNZsgnTIf4Nv6to/u5/mnoY/qweSHpFV9iXK
         IwXEw6XHPT4ijPz1TYLjm+6eTkMBsZ4bjm/0jJRuTuHbOFxyOCSXhsX0CCxWJ47hhzd3
         glJWL955WM2kv7Q3yTr2G4MhnKBdcvMPnz7ZIbvpk06umNHU3cvFpXiA239ioNi3B3UD
         abNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCW3X+Sjy4ZCIxmdyq5vI1g5x8n9COhXDkOHIcraPd5jXmdyQqQ4JlqwzTSspSMJMwkaXqsnNA==@lfdr.de
X-Gm-Message-State: AOJu0YxELMFpNWTOS3vhyS8DxRBvWZIkKa+mt4szvXKt7ZAPzqLFQxwP
	ojBclbFYuW/s0v1JEORBX7oORTKLjVz1LTuug/LCq75GBtbHEPGXi19r
X-Google-Smtp-Source: AGHT+IGG2fWthtTBOBOpes5jPVaXzZbNSZRHWVFli7l2a96KL1Xfdk36F4jj0EbnQUhNBHjI64KHJw==
X-Received: by 2002:a05:622a:4818:b0:4ab:37bd:5aa9 with SMTP id d75a77b69052e-4b0fc6e36d5mr33530481cf.17.1755081658169;
        Wed, 13 Aug 2025 03:40:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdDZDYwiUIUxCIOFhOXLuxvnY/YlNfXlXI9Gjq3EQDoyg==
Received: by 2002:ac8:5808:0:b0:4b0:7b0a:5903 with SMTP id d75a77b69052e-4b0a06dda52ls110627531cf.2.-pod-prod-07-us;
 Wed, 13 Aug 2025 03:40:57 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX25z9/+vWdSiecigf6OJEAmzR/8ZqVwz0SV0QW97/fx3Bu+qAou7HWWMISjsrkF0sI1BiAt9V83OM=@googlegroups.com
X-Received: by 2002:a05:620a:a80b:b0:7e6:5ef6:b703 with SMTP id af79cd13be357-7e8653259e3mr355831785a.64.1755081657283;
        Wed, 13 Aug 2025 03:40:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755081657; cv=fail;
        d=google.com; s=arc-20240605;
        b=hCZD/pdZqmSV2L3HvOTdfLaH6PeQk9/DPQDGWjCNe8RbNTgFu6x958KHqgv3SgCTZx
         JvQ1Bn2sEPLMKok1StG1Wdzy4xxcvxVIGOn3zGmym+RAJyT1wnLktIH7vm4+NX4rwQuD
         OoMgDHNii9MjqGbQ2EnZ3wAqlhIkiHPkz/CKwmjslmzEFjWXdCWi0f4BkjPoJDCmqt3/
         X7lM3Tm+gePtAR2AcePKOT9eiEVWGuNshXm5frPZ0VfATtcGK7CyNqtMUZtMMwDOYIUI
         2LrDuKDk5pvq72rv2pe7DhYvQf5c0XFhZhomkyh8gsBg7EOcRCO47W50rT5cCwRrfJ1O
         TxMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=o/V4ysxzRX1oH14Uo2lbLLkafYycPJMyOAwCeRcAo+M=;
        fh=3pkXzgXcVKe35LPgKv0EEigG8SKpEntzVeCeUS1Dfv0=;
        b=DFlfQPsvL/gJycifK91HK9BbPQecz6wmlQZaz7oH5k9+F8vClDvM+4WNtERMsJeHwg
         a9V5G/y/DVcSIeLnYMIU9m87XvcDjaxBLdaf0TNMXLhmwB7BRxj2aVM2eAUnap3vlM4B
         UA8pFTQuYnoQRmzwdRiVaama/FZYUGTecG+5JIxl0oodTqk9aC5Y/p+u8462AvM4xvf5
         bA4DUDZxIvnr85uL5tN6Z/hz3YAKRsAQas7Wp8VpAGCZJ9JLI7dmxCIe0sDYogvKhEOR
         OvgHoaYIqEweXArHdIjaV+jHu1qAXy/fQKzwVBgZdOuAcvF0esYkwG4zwHpnoBIBqbxQ
         EF3A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="CS/WKT58";
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e7fe360ea4si103326685a.1.2025.08.13.03.40.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 13 Aug 2025 03:40:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: KTgLcmPiSveXAOnPPk3sGA==
X-CSE-MsgGUID: AmaGMUyhRSmqePkdv7ZPcg==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="74817704"
X-IronPort-AV: E=Sophos;i="6.17,285,1747724400"; 
   d="scan'208";a="74817704"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Aug 2025 03:40:56 -0700
X-CSE-ConnectionGUID: 8rQVP2eOSUq42A5Q2xoAQA==
X-CSE-MsgGUID: IyB5qBL0S928kK0Y0bWeCQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,285,1747724400"; 
   d="scan'208";a="171764862"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by orviesa005.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Aug 2025 03:40:54 -0700
Received: from ORSMSX902.amr.corp.intel.com (10.22.229.24) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Wed, 13 Aug 2025 03:40:49 -0700
Received: from ORSEDG903.ED.cps.intel.com (10.7.248.13) by
 ORSMSX902.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Wed, 13 Aug 2025 03:40:49 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (40.107.92.84) by
 edgegateway.intel.com (134.134.137.113) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1748.26; Wed, 13 Aug 2025 03:40:49 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=xWsVBLwWbN5fEKHUmd3idmXtSXEvykLmsHfV5PkQX9QFtYD8O54yn5mvEuCesHvsjc5/m8eq/KE8MIQQSEN2/5YR+kqo2ruY51dontnzoDN/p9vZ2AwKJCvaSfZSayuORLiSlmjvHyK2J4HHzyhkDNE0RLob4LflSgPxpMDStOGDb1XROaNel2laQJx7y0GNzVXGH9QHZYfsY3I3wz/RmknAvDpdQv5lb4FVUurSpK72K21SxSuFbN2Ic8XDMTBk1wR1wUPbOQBHGLID64yYOWjc/8OOn8czXRON+L5Tzw5EvlZQZ2ZBj63aM1azyUrP1yr1hJjDqdT53tRxPdrO8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6rKKY8rznZ41XMPA9SgN9+U2171s46U3wvgnEgor5fI=;
 b=XbQci2+feRX7yt7ZYd0zpiRUBgIPvXYDpPmKc973vwGGgWNBxXLZtKztuOi1ReLZmQBEOTJgjXx3oJsVJzhWaBDXuNHGCQGCWAZv2g/bo8ry1x71uBte1wP1N/vuBZocgQFGrLKnIekt6U0WYfWt/MvqqzJaeBC7yevGTzs4xZBuWZwlrIJ+m1c27zu91tl7P+3vYpDoK73T1igxw8c6f0L9LldBX20eBhu6+E0BCqdnfQe5YSSsPnhDJXjvhbijnlQatE3Chr6aBfoXzmlEeU8xq0JWtSYVLA2voZR11U756DeG7fp1fIFeuNhpYLQQiNfl1Ujc0OuWY2rorARWQw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by SJ5PPF1EED2E381.namprd11.prod.outlook.com (2603:10b6:a0f:fc02::817) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.20; Wed, 13 Aug
 2025 10:40:45 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%6]) with mapi id 15.20.9031.012; Wed, 13 Aug 2025
 10:40:45 +0000
Date: Wed, 13 Aug 2025 12:39:35 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Kiryl Shutsemau <kas@kernel.org>
CC: <nathan@kernel.org>, <arnd@arndb.de>, <broonie@kernel.org>,
	<Liam.Howlett@oracle.com>, <urezki@gmail.com>, <will@kernel.org>,
	<kaleshsingh@google.com>, <rppt@kernel.org>, <leitao@debian.org>,
	<coxu@redhat.com>, <surenb@google.com>, <akpm@linux-foundation.org>,
	<luto@kernel.org>, <jpoimboe@kernel.org>, <changyuanl@google.com>,
	<hpa@zytor.com>, <dvyukov@google.com>, <corbet@lwn.net>,
	<vincenzo.frascino@arm.com>, <smostafa@google.com>,
	<nick.desaulniers+lkml@gmail.com>, <morbo@google.com>,
	<andreyknvl@gmail.com>, <alexander.shishkin@linux.intel.com>,
	<thiago.bauermann@linaro.org>, <catalin.marinas@arm.com>,
	<ryabinin.a.a@gmail.com>, <jan.kiszka@siemens.com>, <jbohac@suse.cz>,
	<dan.j.williams@intel.com>, <joel.granados@kernel.org>, <baohua@kernel.org>,
	<kevin.brodsky@arm.com>, <nicolas.schier@linux.dev>, <pcc@google.com>,
	<andriy.shevchenko@linux.intel.com>, <wei.liu@kernel.org>, <bp@alien8.de>,
	<ada.coupriediaz@arm.com>, <xin@zytor.com>, <pankaj.gupta@amd.com>,
	<vbabka@suse.cz>, <glider@google.com>, <jgross@suse.com>, <kees@kernel.org>,
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
Subject: Re: [PATCH v4 00/18] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <rzlimi2nh4balb2zdf7cb75adoh2fb33vfpsirdtrteauhcdjm@jtzfh4zjuwgl>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
 <mt3agowg6ghwhvcjqfgqgua3m3al566ewmvwvqkkenxfkbslhq@eun5r3quvcqq>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <mt3agowg6ghwhvcjqfgqgua3m3al566ewmvwvqkkenxfkbslhq@eun5r3quvcqq>
X-ClientProxiedBy: DB8PR09CA0025.eurprd09.prod.outlook.com
 (2603:10a6:10:a0::38) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|SJ5PPF1EED2E381:EE_
X-MS-Office365-Filtering-Correlation-Id: 74f7127c-56fb-415b-aa13-08ddda55dbdc
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?zh2OKw1mNTYyc7MpM7Gp3Ntsu+ttLa+1Kurrk2+Tntx294FdCv0sB3mUsX?=
 =?iso-8859-1?Q?k6EZutKfpNPlFOtPcJyifPdwTQeFpzzcQXL0BHiRZdBxEV4+0WXK5qNBAu?=
 =?iso-8859-1?Q?SG+1F6uYKGPpmeI66vjq/0xjuFv4FIF8YlbnNhehGZI6trCMeqwcR/sQX4?=
 =?iso-8859-1?Q?31E20VrXo7SLTxuUJ3owLM2Mjgo1tVgMHl7nCwgphJ40tnMzveBvPZ9LOL?=
 =?iso-8859-1?Q?ROAbeKuAT079MxOPUsa2rTJ7tl30mcrbIZoTtBlOZrXJToa/ENbgwSUeFz?=
 =?iso-8859-1?Q?KqzRdwIrhXOlc0dHcEa7xMmwjpTR/3cBXjRbDRSpnsE5pIb4hYwfbUWx9V?=
 =?iso-8859-1?Q?f4Y+U2AVe1XMVG2kHJ32oip+0Eintr3kLXsgJUOvxD9IvUZhbNbhSxkJG+?=
 =?iso-8859-1?Q?5PDI3QPslFQDUsscdsiiITO30+T3htRWJ/zYzfESZx9ckBC+Hnt0Plu44Z?=
 =?iso-8859-1?Q?y2z67aRVwU+KT6/qH2vhEGkiFlQl4TqXiGbnFxHDxOwgLF3ANXpymz05yS?=
 =?iso-8859-1?Q?1cGqo2NAtacyFkTVeZlyURlMHgEc86gCdC/Ooz+JvfDGVf1Hzguj0quGVe?=
 =?iso-8859-1?Q?dXjft/NyZ+NDu0fqxhqbbshdUCSpXL2tV7TneMjuxS9NQm/31/LxY5tb8I?=
 =?iso-8859-1?Q?rRxAGpyQcPFqXH3uz+p9TGheL5GXCG7Tz8t4t5nxtZ9zz6Y6hMYe47eFrR?=
 =?iso-8859-1?Q?ef7+dCMptuWx81oCI5UchOFPhLlE6ThkfMmkB5DbD8brdiZ1Fv2dxHft/o?=
 =?iso-8859-1?Q?zwLlXT7+gP593OhnktHntVFH5pzgzf90mom8p3JDtnsv6G5rc9P8ydTk6H?=
 =?iso-8859-1?Q?QQMUyFqD/fmC4k3tICN/KfT8ujhsVHL6VFPsoN3TW2DBx6nQVSI22aW8sp?=
 =?iso-8859-1?Q?YhGiDOembMYJlEQFRJzTWU6ORLRaYzB/1t/1iSoVH8f2rMSUp6FiDcah7J?=
 =?iso-8859-1?Q?MnV5dVowmgJr04pHueXajQnyn+hvhiiDmKT2+zkSXFMtQsQZ8kZ+JXppuo?=
 =?iso-8859-1?Q?mSXqkXgoZEdfFhXoiB/s16yLN46lyDpZudG5f/jwC6eDUZKbYFVvZL3au2?=
 =?iso-8859-1?Q?DDCVx3tM/mvXcyDn8qwMrp8FKmUWBKk5lpJ4wYXph/iwC77/Wc/9ty39Zz?=
 =?iso-8859-1?Q?Rnh9sUggPiKykTdfyml2RpoUmLwbL1tb5X4iEZPJj4vRIhCt7+7D45izoD?=
 =?iso-8859-1?Q?KqXh8OA+0N/FEUP5EKiSHa4kUko8F8aUCVqwWEwsnO5LQz25t5M4vZzpEY?=
 =?iso-8859-1?Q?/icEE+pK4NdyLMsHwZjMo9P6qT72nfeB09Ok6c1bhJBGwhEWle2FgvksSD?=
 =?iso-8859-1?Q?Z6QND9/8B9h0yRMigqNAUbw2XdNmC2u5zyb46IgpEOKIAFiEPEG0aZO7dl?=
 =?iso-8859-1?Q?PPQAU/GByudllVLHl1SWtjAB5+kdtQ/PrSx334apG28q8GGtfdr5Tj5klX?=
 =?iso-8859-1?Q?C2GQByXCob6cxfM7V6WZXOyE1yeb3vpJWQj2axFGbJ2Mqp3eH1wk+pgJJs?=
 =?iso-8859-1?Q?c=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?omvumtEPIXVSB7pAd+6zqooALYnvYne1GFMQSFPdxc/d7Zdbibttr9LXzV?=
 =?iso-8859-1?Q?vPYNFayQWTeJF4foLzFioaXwHiuGAEmLTnwa+lRp6KgMbH8aoUmCxZ7QtW?=
 =?iso-8859-1?Q?AarwtANXq4Vjc2dVCvYQVX/A5fe3fP1wxQQ+1/8kND6SlHjT9tapCg8syX?=
 =?iso-8859-1?Q?g+9l/Xq/GgZ3Q7i/XlyueOY+/U16WgqpFdAuBArkkaMmfrE1/Pvuw3gbTi?=
 =?iso-8859-1?Q?6IYuyKVEyWRvDSaskxIozgeEJpsT4BQPtHjiZzstDctUpyJfX99WWfHc5W?=
 =?iso-8859-1?Q?606PhEU5+2ZFLgqWPq37tAoKsHKR/wzC7sD4YAF1Ntkx3tboyqKpzUPUm0?=
 =?iso-8859-1?Q?D8MwmsECsLaEQoT9Ivb1K6dimsuXu8qWZrCcwuK87oprrUR0Y+/q2XJJ1Q?=
 =?iso-8859-1?Q?UhfqZJs0XVnQJ+rkD7QSFyQ3802gNN5gCXguldfQ5Gt9tPxSeb1Bm3GiyY?=
 =?iso-8859-1?Q?iZ7GAYeweELvkUjqiqreJuoz/GsfZ7xKAe7oYkEeNjVBca620r6T06yCO0?=
 =?iso-8859-1?Q?tvhpfTnjM9xNDHIqYUO4JAdJTcsQidka7RO8eiR2mxlZbFsiJ7+puyETE/?=
 =?iso-8859-1?Q?BnrnGDOfEi6HWxYdrXSRBvsu3oGyu1+HhnvN2crN1asIZbcTBqaV3OBVtY?=
 =?iso-8859-1?Q?4A1Vva6E090imZz8WAj/INCftXloSLdaa2OT+PYy/rHOvdWNLgYy5GODYG?=
 =?iso-8859-1?Q?juZroSN+g0fmm/OUv3BEZ+Nk+yckNmwhuVGIKpnNrKFAE+1E7XoMvotV7/?=
 =?iso-8859-1?Q?wJIHGWkQ2c1LOovjPdm8QKl+C+6mgDLAkP47xX4UPsD4Y/0ZxKvie5O3Kp?=
 =?iso-8859-1?Q?oVkjllqYs2Mhm2v+QD87V1QyGBCX3WiEbWQ98y3QhDEbMqEEtoLgs9U4Ec?=
 =?iso-8859-1?Q?V8cndjvC9IAjRVo8XtS9Ns+DLEdA8yzwilg9uqPGtU4S5Gl13chqAJ6SUU?=
 =?iso-8859-1?Q?zJ4sdltdu1TCmg/jQ+RGDl5200LCIIBpw3rP4SJgM5tq72+mLGRDVkvTJJ?=
 =?iso-8859-1?Q?0OYC04UWzR12XaCXNp9n5ZPaXWWjiNTUwZdpHeRZFMsLK3euY/JOsE6bVT?=
 =?iso-8859-1?Q?iPulZqXLXI9GWepN2B/d6GFfEV6SEl38qFHpr2VlMujUd7lPcSsxDGNBR0?=
 =?iso-8859-1?Q?aDZAOIu3JxjJw64/oWUh3Bi0ZOK0MR4UR4ofVeh9E15MUsxVbr9e0xXhfn?=
 =?iso-8859-1?Q?aYmEujNYGusfyw4fHC6aCnV+sOareCwoAe990t+VcPuXImM7y3Bbbj16eL?=
 =?iso-8859-1?Q?Q+IknWieQsM7SallgGF4bEXBbVIXYKDDuUZwOZFOZzRpSjeL4EXHyV+BDf?=
 =?iso-8859-1?Q?QEOHJo6oOI3pn9IFWHZzJdMhovacE2Oahfc1lW9cH8BuZCzDeM6achSBcy?=
 =?iso-8859-1?Q?xQkhBS3MCHGQNJG69SjL7wvu46hBIgW+7JuAzv6D6BctglvYXVighIru0n?=
 =?iso-8859-1?Q?NKww3tcXZ7s5mLWvEoTHhjVHipTCv0QG8gPCrDvNJxA0kum/y4Eb/+qUqf?=
 =?iso-8859-1?Q?OMzvipj37aCdd9LZ0RgBcrc2rAA9qHOnjePCvz/GymYG1etvHc2zyHRwZg?=
 =?iso-8859-1?Q?XZU2btE9c20kE3snhwj00r8M6v/K1ApIHc9Z9m3OO9Bo9kBEmsoKvVXBYa?=
 =?iso-8859-1?Q?d8ScPLgP6XtPNoM2W8lfm2SmfrITgyofx7MULYVv6DcX/d61B32GXiVrtg?=
 =?iso-8859-1?Q?k7gGVF7yReA1JeFYaSY=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 74f7127c-56fb-415b-aa13-08ddda55dbdc
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Aug 2025 10:40:45.4279
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 92nhxj/q7p2coUNxRgPTLosXiLtwNOFn1Z9oRuJtqFwKB2xMMLwEuPs65YzpzE3mTtiq9CJSBNUZlE0qs/kgIxPeATfVJ6IotW0bERjOfUA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ5PPF1EED2E381
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="CS/WKT58";       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
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

On 2025-08-13 at 09:16:29 +0100, Kiryl Shutsemau wrote:
>On Tue, Aug 12, 2025 at 03:23:36PM +0200, Maciej Wieczor-Retman wrote:
>> Compilation time comparison (10 cores):
>> * 7:27 for clean kernel
>> * 8:21/7:44 for generic KASAN (inline/outline)
>> * 8:20/7:41 for tag-based KASAN (inline/outline)
>
>It is not clear if it is compilation time of a kernel with different
>config options or compilation time of the same kernel running on machine
>with different kernels (KASAN-off/KASAN-generic/KASAN-tagged).

It's the first one, I'll reword this accordingly.

When you said a while ago this would be a good thing to measure, did you me=
an
the first or the second thing? I thought you meant the first one but now I =
have
doubts.

>
>--=20
>  Kiryl Shutsemau / Kirill A. Shutemov

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/r=
zlimi2nh4balb2zdf7cb75adoh2fb33vfpsirdtrteauhcdjm%40jtzfh4zjuwgl.
