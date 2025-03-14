Return-Path: <kasan-dev+bncBCMMDDFSWYCBBI5E2G7AMGQEF2EDPMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id CCDA2A61586
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Mar 2025 16:58:28 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-3913aea90b4sf1022434f8f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Mar 2025 08:58:28 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741967908; x=1742572708; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BjB3wOYpM6ubLMGkfnlDYczRGKdXhHaQ65oCktU7gWw=;
        b=jnM6HvAmSG2IOpHLMJnUqSSkY6RLBWGe7mYYBowV1hbAv0uUQwbaPod53ffc64zrZE
         p+U0G7+lZsxJPF25zvFeHWn9oFvAjIRVtlkSWGONXWdT6oaHtxyv4eAe0/JZcY9jbL4s
         4dTS26thzOLw+5b2R+LP24A5n0Zd+3uSzYCmwMXRsdSPb0Y7aaVhIW/qLOiBHQOEVdJB
         jMAAamLpA+mL2ZPfddYXzx8calqjeILLF4B2yfj+9St8A8BZjFXXGAa00D3Ki18Pn/68
         xCh840ri7Zm/BwhDn0SM1G6mLPZixrEwy534BIRM/u8eQP2/fFZ/mj1G00vcvM7bs6jv
         DCOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741967908; x=1742572708;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BjB3wOYpM6ubLMGkfnlDYczRGKdXhHaQ65oCktU7gWw=;
        b=Q+qUt5MmrXlgYJBm6eNXb5aT3JkOHs23I82l2xsGeibqKzw5H87m79/S0G/JzQxfqO
         BnKyF5DDox35c4LwrPizNEal7LVr0R45j2Ms0VeJp2oohwyfCd2rX4x+uEvyQDXOCCPd
         2/htz2dK31xPsjgUb7JtXD6HPew7L4+yUKbbfpkjdpbqKOt9FcTlY8++aXZHy/YwxWI7
         ube0uvmmRGqtqhnIRgCTg+olKTNRP7UaCowlbxgia2KRNDUMzQUIzMttZcCBKw2jKewi
         glNcXmGM/IuQ+l6cNWcPt95k4YDprerCp+CvUriLg18nuKCiVAQ+lgdIzjalb+QE/wSL
         GyDg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQ/L4SL0bnF85x3rl8XUwKhvpEEXTEnGvArfkKryjrY9Z5lCVuzPpm9U7krhg26U+68LLMRA==@lfdr.de
X-Gm-Message-State: AOJu0YwnMg+QPFVtc0+gsbq/U0rq0x2QTf/St6AmRJNxUxdbty94Dl4G
	6aZh9ng8ToPuwByZxHEez9cv0e6M+NO+UBrASbsvL6Sb/KWswfOs
X-Google-Smtp-Source: AGHT+IGHJl8EQQW/ETb5BVQqGfI66wpg/cvhICO8imG/LuX7pmxPvNCJbLqr5wSQw/QMGeOVIvUNhw==
X-Received: by 2002:a05:6000:4012:b0:391:4389:f36a with SMTP id ffacd0b85a97d-3971ffb3cefmr4799748f8f.48.1741967907450;
        Fri, 14 Mar 2025 08:58:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKBFsm7VHWSrAP1PFw+w/Y+jHSykpw6qYH0hS726wIpgw==
Received: by 2002:a5d:658a:0:b0:38f:2065:b9ad with SMTP id ffacd0b85a97d-39564438bedls1000014f8f.0.-pod-prod-03-eu;
 Fri, 14 Mar 2025 08:58:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVl2I42N76sHyUPtHVv9vAzf3HcnvfSGXFigWRo+PjbGRagAAQyk4XDrPxJoh3oedXGWFLDDtDsaOI=@googlegroups.com
X-Received: by 2002:a05:6000:1fa6:b0:391:4743:6dc2 with SMTP id ffacd0b85a97d-3971ddd93f0mr4852227f8f.25.1741967905119;
        Fri, 14 Mar 2025 08:58:25 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.14])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-395ca77c3e6si46796f8f.5.2025.03.14.08.58.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 14 Mar 2025 08:58:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.14 as permitted sender) client-ip=192.198.163.14;
X-CSE-ConnectionGUID: Yxl5wU2NTcO+N+sHNeuGnQ==
X-CSE-MsgGUID: cN6FOUPKTlGK1VVIzDoE5Q==
X-IronPort-AV: E=McAfee;i="6700,10204,11373"; a="43331018"
X-IronPort-AV: E=Sophos;i="6.14,246,1736841600"; 
   d="scan'208";a="43331018"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by fmvoesa108.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Mar 2025 08:58:23 -0700
X-CSE-ConnectionGUID: 3RJJi3+xRVmEM5xuXFtAwQ==
X-CSE-MsgGUID: HULiM8elQ3e5L/fY585S4Q==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.14,246,1736841600"; 
   d="scan'208";a="152263268"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by fmviesa001.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Mar 2025 08:58:21 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Fri, 14 Mar 2025 08:58:20 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Fri, 14 Mar 2025 08:58:20 -0700
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (104.47.55.172)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Fri, 14 Mar 2025 08:58:19 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wq4K9iJF5h8kE+EspeOVRVw5lA0HwmWJqo3lku+3AzOKVPHr0p/Q0wvj/QmvSSrG5j/TTXkG1HjH31NT/3nuZ178Wa7pu8BDP0v3EVysxKflHH0qFe8wZVieq52noLOVXc4HhSUhq61vPksygP/5gDTdgMRpKy62sTC4j/r209lVaVeRrIK55baImhwYCx7C+tQCJtD3ceAh2IXQ6goblnnO/9GAuRxZ5BHu/zVCSBDyY40fkNP66IyBup1JThYGZMGRAKU2e5BfJ7vsLQQoKBIiaPh6gR8SzEqXX4vkt0E6N5lyOyHJC5JccnkR4kNhUQH7w2NAjAGDg9pOq4eUyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hTpFKDwXo4CXWi5z65EZs5JJvwuwfNXVXZ+mrDkS9xc=;
 b=xS8r3eUIikiYFTuXebaJu5y06WIVjkUcr9YHGvHCr+XV9GEQ+CVEBsSvvhcCL7ZEC2Q3WhFr3EQlORaHThgJSGNmqPpCXOCZz8DHO2EpaaZFzqQn6cfwSD0+utHxnwLECh9jZRwQ6VsmBvR9CWNKsSw/Fl6Se5X1ppZHLmcdbmbZrmBKlxkqPWQddZWp6bcDvq1SClBBhGH4PblEPxlHEqRnN/OGP61r/KTZXpcN5h8a/Kh6dvhEKMpRq1io5L5YNLbefGkdz7yeK6uqh4mstMgGf6vGx41O60CpqKNK8hiF36WmZp0klaAfYTGW4KNLszTB1YQMp27D2k6y+zhFeA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by LV2PR11MB6069.namprd11.prod.outlook.com (2603:10b6:408:17a::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8534.28; Fri, 14 Mar
 2025 15:58:00 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8511.026; Fri, 14 Mar 2025
 15:58:00 +0000
Date: Fri, 14 Mar 2025 16:57:48 +0100
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
Message-ID: <b2bioloa3qsueqiyjadi5zsvi63v6zh3vwzji4ed4dmsxkaudb@hrxzs4vh7wjf>
References: <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <CA+fCnZfb_cF1gbASZsi6Th_zDwXqu4KMtRUDxbsyfnyCfyUGfQ@mail.gmail.com>
 <paotjsjnoezcdjj57dsy3ufuneezmlxbc3zk3ebfzuiq722kz2@6vhollkdhul7>
 <CA+fCnZcCCXPmeEQw0cyQt7MLchMiMvzfZj=g-95UOURT4xK9KQ@mail.gmail.com>
 <aanh34t7p34xwjc757rzzwraewni54a6xx45q26tljs4crnzbb@s2shobk74gtj>
 <CA+fCnZdj3_+XPtuq15wbdgLxRqXX+ja6vnPCOx3nfR=Z6Q3ChA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdj3_+XPtuq15wbdgLxRqXX+ja6vnPCOx3nfR=Z6Q3ChA@mail.gmail.com>
X-ClientProxiedBy: DUZPR01CA0198.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:4b6::29) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|LV2PR11MB6069:EE_
X-MS-Office365-Filtering-Correlation-Id: 612e4c3d-3abd-40b5-b7c5-08dd6310fed4
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|366016|7416014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?NVZCTzQ1UlNucFdrRXloeTUxWWwyaVBSOFlZUmZLSGszeGxHWk9qNWdGeWw4?=
 =?utf-8?B?VFFPYUtjSHJVc1AxZlEyaGdKajBvaG1JMDV3MlpSdzhGd21USGdOLzllbmJB?=
 =?utf-8?B?NCt6cWVpVFBIbURGVitjcnBLM2txUXRyc1ZoNnhiMzc4MGh4aldwcWFpWXdn?=
 =?utf-8?B?VkhOOXpHMUlBWTdrOXdVd0FZcDZqYjVXRU5YZW43bzlzck15ZkNIcUQvdEZQ?=
 =?utf-8?B?Y1BXVmJnZDJVWHlpRFJxdE5VRlhjdlRUc2tWRmdWOHBWd0dDRW1CRkdzTG9O?=
 =?utf-8?B?ZHRTWTk4NkJYRDFKK08rV0xWYzVTS0lxSDUvNmJId2FZWnJ2R3VWVWhpcm1N?=
 =?utf-8?B?MlJXaEhMd3BBMHg5dEpPbGFYVTdteCt4dVJueGNwZmY0emU2VjBqbFEraDhU?=
 =?utf-8?B?VlQyK3NmcXErL1RGMnFGOHZQSVZDMTZZbDViaE5SVWExa3cwbEhMREREQzBV?=
 =?utf-8?B?aDVpTmlUVUJlRmp0ZG41eVNFdit3bXRsaXErM1NOZXlSb0s5d1VFS0Y2dVB2?=
 =?utf-8?B?WHZZZ0t2ZWlSOHFMTFkyQTAzd0l2OXlLS2ZxN2NtekVVeGxzMDNGY3FsZ2p0?=
 =?utf-8?B?RG4wV0hlSnBsZ0FGaUxUem5RNHhiK3ExeDdnQmJqUm8rWTU0SE0yN0dTWGMz?=
 =?utf-8?B?UVN3VGo3TnRTbitMOUlpMVduaXc1VUVyUGppNHZSVlBwTk5RMWE0eDcwaXZ0?=
 =?utf-8?B?Z2xDUkFWUzFrdmhCODlCaEdOdGN4R284Q0V5NXBKQXZsMS94WmNIY0w5R29L?=
 =?utf-8?B?Vnpwa210aHhaRzV5Uk5UV2JUeGEveGh3NWszUE1BZFZKd2Jkd2VIMUJ0Vndh?=
 =?utf-8?B?ZnNXWkFOY2h5Q0ZXNkVCd1NTMkNKa0Ftb3ZDUFBhekxWN0R6NzJLOXN2WklT?=
 =?utf-8?B?NUx5TDhtT0RBRmlKSmpjUGd2Z3d5d2FvODROcU1qRG9GQ00wei9odWRJa09N?=
 =?utf-8?B?Sld1ckFSM0ZPNU9EcTFhYjlLenRzWFY4MXNsUzBQb01zRWpOL0dVVFovSVlm?=
 =?utf-8?B?MytnWk8rTkJ5eS9tejhGWGJxRnRsWS9FdFphTm9vcFVOWkkvVGJQOVRTT0Zo?=
 =?utf-8?B?U3NINVMwT3d4eFIzK1k2Q0VqMlJzRXluWkpPS0tUaHA1WS8yQXZhdVVOZnRh?=
 =?utf-8?B?RFJtOWtSTmQ1WnV5R0hPN3B3aXE1K3NIWXV4aVpsdkNuN2FCT0hXQjRTZ2tt?=
 =?utf-8?B?clkreFlpckRQR3pkclpKMWh2Ui9hOW1ad2NGRzdzQXJzRGUySWZBK2UzRmU5?=
 =?utf-8?B?YmJhNjlJN0xpYVRqcy9yazNNUm80NEptYnNuemg5ckJTS3NKeGorK2RCZjAy?=
 =?utf-8?B?ZEJkTnZ0b2pCcFRoY3RrZmtaNDEzaEpkTUxSRkhncVM5YjY3NlZFb1p5cE1W?=
 =?utf-8?B?WEgwaW9ZWlo1aFQrdFQyYmZrQjVXOU1VRkcyVlpvWXBLWXVVb2U4SjRORTB2?=
 =?utf-8?B?OTFqTS96cEwrUktHWmpuQVRQTmY2MS9aVGtVM3VONkNJRFlGZkZXK2pPMi9R?=
 =?utf-8?B?YmhPMWlGcnppdDE3ZHRJVU0yQ09xK0NxSnNBUTN2Z1pKSkwzbUh5Q2xpZ3Ay?=
 =?utf-8?B?bURBOURoZmM1bVRxZ25qQVVKVFZyOFAvWi85bU84SFhZdWdjdGxQZWxSLzFY?=
 =?utf-8?B?YzdScURUZ3JrTXZVZVFJMUpTSWU0TkYyU1V5blp1cnpXbVdLQXNlLzd6ay9N?=
 =?utf-8?B?bVI0ejU5anhldEVIWmdhRzA0MFE5MmFYVVIycEM3eTlybkJmNWNRNzR6cEJP?=
 =?utf-8?B?bXg2UW5TYi9jTWQ5d0UzYXhoODFRak9oU2tidS9EUHZ1bXpITGhKekxXRENB?=
 =?utf-8?B?d25Xd0VSdDlRK2dEenY1QW9yQVFvVnNJZy9EVCtkb1NzWGg3dkp1WEpIc2pz?=
 =?utf-8?Q?E3AYInI2IB+a+?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(366016)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?SEJBY2xscnJsVjNrRWJpSmlsTng1bXJFWDgxOHkrYzN1QUpNK1VJZTUwamox?=
 =?utf-8?B?eklzMWJMYWFpUWNpdVZldVlzQzdKREhkazBGdVNUTFhGdi91U2pVUVo3L3Uy?=
 =?utf-8?B?V21wWHk5Z3lUdVhrWHd6anV3ckxON1hyMlZ0Vld4ayt5R3FhUDhLNEgxWXhT?=
 =?utf-8?B?V1B0elZDMkVvcHRYL05oYWxHZ0Jsc2Q1a1NKZ0d2NkxPbGpaSnlpWjBaUTdB?=
 =?utf-8?B?bVdhYlBON3hYcWlmWFJVcXlYa1RiTWFIQnlqdjdwYlM2RTQwN3RjeC9COEh3?=
 =?utf-8?B?U3lVNUZXTlFJb3lNVDhLeUZ3dEVuVlh4TFVHUEpYTGtUS0pWZjZHL25WdmFk?=
 =?utf-8?B?TXhld3JsNWptcVc4UXFaN01DZEU5bFduUkp6S0psKzJwZ3FYRVA1aUExT3pI?=
 =?utf-8?B?MXBvSDFUYWJabytwZ2J4cFVVQUdiTUsvdTVvT0tsZG9aRGdvRVdOOVNZb1Vq?=
 =?utf-8?B?c2dpSE9QOXZJYXpIVEY5eWFZc3NSU08vZ3lyL25tSDhLMnBWR0REWGpDNDF0?=
 =?utf-8?B?MVNtVW9lZEFya0hNb25PQTRtby94M0JyVVNmVDhPbkRRUHBjV0U3cGtpWGEx?=
 =?utf-8?B?SHJobzFhZVhXM1NkMGNhZU52dW95UisvcWRDLzhRSHlqQnBwMXUrVWw5b25q?=
 =?utf-8?B?MjBFeE9XZlRNcnEvelpERjlDRmF1WHNQUG1jMlJRM0xwRG1nbTdzV2dKMWRV?=
 =?utf-8?B?RDFVV3NQTG9uZDY2Y2JGbGlVVjNBTTFpUGN0dkJRRXp3WDMyS0p6aDlnUXQ4?=
 =?utf-8?B?QVAvSi9oZkZCQzhEZDlkRU10T2I0cWRGcG5KVUpvQXUzNUhoQjhyNytUMEtm?=
 =?utf-8?B?YlNpRFgyNnZpeVA4VkZLdmJtdDJROWMyc0ZMdGVBeENvclRWbVV0Y0FJbndX?=
 =?utf-8?B?SDVzT0FzVHNGanQyT2J0RzN3enFCVjA2NmpZRDZwZHR0OTZzcUswS2VlbWhz?=
 =?utf-8?B?N29CSVJpN2FpL2lKb1krbVA0MzdXOVFxOE1tR084QUNjK01YRWtCT3VqMDdV?=
 =?utf-8?B?WGpjQTNQbHBKbS8vbXFLRS9WUXVnQ2NXTWtSVFBRS095MGR6WFdVQWhYdFFS?=
 =?utf-8?B?VW5IMW5wdEVCU21OOVJEdDRZdHhRMmI0YVBtcWNYelloaTQ1eU1BWEZIVXhh?=
 =?utf-8?B?My8zckhKNnRxRE00Y3FkUnJWZlVrdXVLSlpueW56NEZrYjJVUmxQbWhYMk0y?=
 =?utf-8?B?a3U2RHJoT1phdVhFL09Md0ZLcnV4SmZYR3U3WUg0YTR3bTI0UitPUkt5Tjhv?=
 =?utf-8?B?K1ZGYW5qVHlVSzljdFhmamlpaHZMNlM1VXdlV1MvT1hFNWNKeHJkOElJaGRK?=
 =?utf-8?B?TDQxQ2VqS3BMWHM4d29UbFg5U0RpSEtQanpKYk9QcDlGZmpUWjBzM0xGSzRx?=
 =?utf-8?B?dTNRc0cvWWJTcVYrbEZWUjB1VFJleDY1RDNsTWV0QmxjZnNwZUkvOUZMOEh3?=
 =?utf-8?B?eTgxd0tJMHFlUUw3a2Frc1BoTENZUmVxU3Y1QW5FN2JobjdJUDJxRFhheXE2?=
 =?utf-8?B?MjFGcUdlb0NGVytpcHZWaUZUWEhOTmFTcG11R1BrQzlUZG5uN2V1UE1ZbDVT?=
 =?utf-8?B?N29TcXFGOFBrbjF2TWNhbitrbVpaNnVENkt4V2JJNjRqSmI5QXVHeXhET09L?=
 =?utf-8?B?ZVBNbGtoQllucGs1Y3hWQnVwRlFjckdwSHBhVmUzYVUyU2g1Z09LR3AwZVRa?=
 =?utf-8?B?ZXFiOS9vUDVYVlRzVWU2cG9DemYybWwwWFAySUdyeG9oMUVmT2lwcVpKTVNF?=
 =?utf-8?B?cTVQZm8raGJWeERsVytTTkpxWVV2OXd6L2phTEhJL1BPNmV3YmhlT3BlVVdn?=
 =?utf-8?B?Uyt1MmF0QTYrQ2ExUDZQcFUxMUsrakVnRU1uT1dQRVEyYUtpWkZiU3ZBT2FD?=
 =?utf-8?B?dHNoTjU5OG8zYm5LYVZNVUNGMjJVMEd5NStmL0UzYWZ5ZUhwUVMzbmNBb3J5?=
 =?utf-8?B?K0ZsMW4xTkx4VHVRU3ArWVdhYmFMMUtBWkdCTUhhVEMyUHRmc3l4THBiUTQ3?=
 =?utf-8?B?SHFNdmNGVnB6anBIMXpDRDdPdlRhZ205K1AyUGRGLzNpd1JvVUVyaXhNSUhX?=
 =?utf-8?B?bW9lSENoQjBiZG9nd0dhTVAvSnZxSjc0cTZyUXVkY0orR1FJRWxSR29jZUdy?=
 =?utf-8?B?TVA1ckEvMGtTZ0Rqc0hVaDQ4bWZTQVVrVjBUaEZqSkQ3K3Y5cnJNTHNLRzF6?=
 =?utf-8?Q?ZhQFQ5PnySzuEFrMXYExoXQ=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 612e4c3d-3abd-40b5-b7c5-08dd6310fed4
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Mar 2025 15:58:00.4056
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8NUUu8UVVzaM+nxj+dvDMNFt4yJgaO/CtLGFYr//Ka++jGksOkEvJlHTrfuGSIsakYThprJRjCqdkB89+9cwggz6aNvc9YcvDelfEa5ECyo=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV2PR11MB6069
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=h3L+9CCW;       arc=fail
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

On 2025-03-07 at 02:10:12 +0100, Andrey Konovalov wrote:
>On Tue, Mar 4, 2025 at 1:31=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> One other question that came to me about how KASAN works, is there some
>> mechanism to prevent data races between two threads? In the compiler per=
haps?
>>
>> For example memory is de-allocated and shadow memory is poisoned but som=
e other
>> thread was just about to do a shadow memory check and was interrupted?
>>
>> I've read the kasan/vmalloc.c comments and from them I'd extrapolate tha=
t the
>> caller needs to make sure there are not data races / memory barriers are=
 in
>> place.
>
>KASAN does nothing to deliberately prevent or detect races. Even if
>the race leads to an OOB or UAF, KASAN might not be able to detect it.
>But sometimes it does: if poisoned shadow memory values become visible
>to the other thread/CPU before it makes a shadow memory value check.

Thanks :)

I've came up with a theoretical issue for the following dense series that m=
ight
happen if there is some racing but I'll have to experiment if it actually
happens.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
2bioloa3qsueqiyjadi5zsvi63v6zh3vwzji4ed4dmsxkaudb%40hrxzs4vh7wjf.
