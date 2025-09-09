Return-Path: <kasan-dev+bncBCMMDDFSWYCBBDGR77CQMGQERJQWIZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7302EB4A5AD
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 10:42:54 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-336e18c37e2sf26510401fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 01:42:54 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757407374; x=1758012174; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YVIRsBwriXSQa3dUSCLrMJuhBbkUMOScTBFHEZu0yns=;
        b=SLD69Wndw5sJqDWwkFK1OuxPuOi7Ek/pOOO74rQCJOkfVjqjXgcdY3HZmyYVttXM9s
         146hepjvnBB1YTb9WZtzt2bW4qPI1qkBORvPdzCwAnEckWqnRwxwk7MJDKxB+z9qMz4u
         CJAAaInd9ZtRnpQxE6OKmyGgYv6WiQymoiKySvolixvUmO8kqulmw3QQcgn0Qaye2CW6
         jUAMPlpHaKUrvQkOxXXKhIhe81Quwk++Hqgl9vtZr6nW7UTpprHB9OS7BdBUXhy0oKJw
         7cSohveiip+yd6YNJMONT0aQCDA5p9R+upxAFlWqhJynyJLl0eS0YlCuTBGLMOgcISOy
         /BHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757407374; x=1758012174;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YVIRsBwriXSQa3dUSCLrMJuhBbkUMOScTBFHEZu0yns=;
        b=l1OJ7keggM6RRww1wRHjFVhRyf9lGosyti8ZFJEqyDQaC5pm9MHmp0JhtzD7lufz4x
         zZiOuihDFtGEknzEgEAN/owpoWa2ZOBAb8s5wowKVQz+PVtPryrTlo/M2DlJNaU/X55Q
         XapdXfGjqDh9NQ15CCy9NOe8K74SvRXZ1zPOm0/J7FO4edZDFC6e4ngFeqdQkIgjvf/s
         TGPRe48RHVTKnJyXUJCUKZKTvhyj7fJ2bRmDglTUkO6jbV7GpRESPoOl5cyzCYFMeA84
         GjBjX1rQ86gFgotACsjGWduIkD5F5CFgQ8ZSz5hi5NYzCeM7LEy4Iof2/XvNGFIHXwn9
         OaLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUdC8D/4oxarcj+4WZ6CS1SbkK+MRu3LAVtrloU3it0Uk+kNzjggcF5hs2daoYZocpmckGk4A==@lfdr.de
X-Gm-Message-State: AOJu0YzzrmgTQxqLlrqQv694BXg3C1hBQAS0aMuCVANd6UY2Lic/bA6d
	gOg+WQnCixlWWIvj4By+Gb75jDVDeIduN49Zr0rg0K0NEd94YmaJFs86
X-Google-Smtp-Source: AGHT+IFcqPBrGe2ZwMuZKA5FedqjKYFfom7B0zbi0BuK24Hq3cc41JMluRKfxAFkCGDLkL/+Fyu4sQ==
X-Received: by 2002:a2e:be9b:0:b0:336:e4fe:914b with SMTP id 38308e7fff4ca-33b5786268dmr30000511fa.11.1757407373313;
        Tue, 09 Sep 2025 01:42:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdSbWeXiBtiSEG523Vqm7Rqd2tpTcWIQNZ1FBrGOd0JyQ==
Received: by 2002:a05:651c:2353:10b0:337:faae:181a with SMTP id
 38308e7fff4ca-338d4158a04ls6108031fa.2.-pod-prod-05-eu; Tue, 09 Sep 2025
 01:42:50 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUQbNcN7m71SCZYxzEwxfiPP+VwYWsv6gEWFvFtq03Y52JEgjj0oPMoXcfTXO2hz+092tzlFCKlh1E=@googlegroups.com
X-Received: by 2002:a05:651c:40c6:b0:336:8fa8:e03c with SMTP id 38308e7fff4ca-33b5e8f60b0mr17617251fa.31.1757407370555;
        Tue, 09 Sep 2025 01:42:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757407370; cv=fail;
        d=google.com; s=arc-20240605;
        b=ZUIW0irOprhlF7jBki89b+9lGyuttk8QvQfdpZJoIDs89Rj5zo2Y6rP35TozlJfgrs
         VolpPi8cvK0YPZuJRnrCXRHDxDS4S3CsBOCN0l38RB8PvoISE/NG8KODX7VpQWBbhYtg
         afU88+O7sScXmPy0ysQDkbE1Iv+CsRmWeibCpTajFWyPPmdTXbL/qqetorAkEHni4spn
         GA24frGsl8hYoK8vM/zIe9X6unFUGEn+kIpgtoNrCquaFeI88W+rVU5TY0Lo0zjPD6tA
         y1hBZuWepfvdBA/wM3H9mjp2t1yzAJfgTIMjKZgaLlEUyQewrCV75+obfu7A2VpT6Z6b
         1Rhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=tnPoNxvVVMoZss2ZtINLqzMSiQcFUY5y+pO/zilJ374=;
        fh=Wufhi7rrwD20YmLOonxnFQWKE9Ef0FLnk1Jd8nrbCPI=;
        b=YOPly5+3W+9gX6XfuP86G20nynUh4oCRGBNZH3PIS9xJeb9pejbsENIGXMUXiFG+vE
         ZVXBEfyglXA3n8t1gKrDuULDITgRlYArEy6PkzS598vErPRXEqQktXwZQFF1KihF7L/D
         E+O/cDYVAytg1wZXySsmcUeiuHv8zBVtnV7YUtxv985BCIvPWL4lYVN0MILYenpfWX8R
         345/EhyPWO05/iCvsqS8jjjHCXbqLxz5TAKGEkDsaTvZ+kFNZtGyS1MncGppOQB1IwMc
         QyvCy/bXiMEvXez2B2Vmsj1VCFM0tEvLEREKAP35F3gtyVvGJT9ROnS4noeFJ5e7Dw43
         pQYg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=aBpyXf7T;
       arc=fail (signature failed);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4faaadbsi3122221fa.5.2025.09.09.01.42.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 09 Sep 2025 01:42:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: MMk894T6RDSEuh7x8I8Qsg==
X-CSE-MsgGUID: oehOGYglTCauBNR3jWDLvA==
X-IronPort-AV: E=McAfee;i="6800,10657,11547"; a="58722669"
X-IronPort-AV: E=Sophos;i="6.18,250,1751266800"; 
   d="scan'208";a="58722669"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Sep 2025 01:42:48 -0700
X-CSE-ConnectionGUID: GBMFTz0aQnymnPpfhYkaaA==
X-CSE-MsgGUID: s51Gm3NiT3qPiarzZGdVJA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,250,1751266800"; 
   d="scan'208";a="172293151"
Received: from fmsmsx901.amr.corp.intel.com ([10.18.126.90])
  by orviesa010.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Sep 2025 01:42:44 -0700
Received: from FMSMSX902.amr.corp.intel.com (10.18.126.91) by
 fmsmsx901.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Tue, 9 Sep 2025 01:42:42 -0700
Received: from fmsedg903.ED.cps.intel.com (10.1.192.145) by
 FMSMSX902.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Tue, 9 Sep 2025 01:42:42 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (40.107.92.61) by
 edgegateway.intel.com (192.55.55.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Tue, 9 Sep 2025 01:42:42 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=sesReRbqq5ZVagjThWZTzlQ12vUHi9Z5bVziRLhOCcP2+ojSnWYfE/LxUEwHW8H6VRBIg01qpa/A6z2bY8dF3KJHbts5/pBgtAWCS6DnjwBa1Ajj7puHqWaQ1TtZZmbfv+r9Dv/T2iQmt9fTSmxfevH7kSNclmIMWnLY01R5Ki0OcdzYPqxJS7X8eKgZAYhYpAvAKJvcZsF0sRjsLQ9ypDzVTEj4n1+0W0R00jCfGQ8MmGLM/zUM2/bvzWJel2EH8+BEk1xRD9dO9rGF1MrPlAukZ/6Ciot3aIDB7xeKJ0IDgF6zYXUPJnp3lWMsoDORSkzd+mW3bOHHtUgxpdPnnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=tnPoNxvVVMoZss2ZtINLqzMSiQcFUY5y+pO/zilJ374=;
 b=AYtCbaZh9nA83owzQH4Tqpo98zogV7TvJciOTinPQwlRdk/76N4qwuL9CZ7paADh4kQQyAhcBh0YqYZ6gmiJwZLhJTaflfDwWh+vervTCJ+96wJejWHt78E7MR8RdMZpf2ZNt4yk+HR+nz6+yjy6QvsS2UoD9UeCnVanHE1nY4JKzTGV71Kj9fxwWW93KjGShkuKrUbXU5Ydxo+YfT0soAF0FmM8zgEIzJf/Je8zNlDNAE+0XPeh+PTTdXPnhnIh9GCCknefAOSJwEP5nzt7mZyZ0m/1hk1nflJ2OqDAmV1CR105pCX1KrRt3/8iyscykPUfQLsFzbXq9lvt36lGIg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by DS7PR11MB6013.namprd11.prod.outlook.com (2603:10b6:8:70::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 9 Sep
 2025 08:42:37 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%3]) with mapi id 15.20.9094.021; Tue, 9 Sep 2025
 08:42:37 +0000
Date: Tue, 9 Sep 2025 10:42:23 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <sohil.mehta@intel.com>, <baohua@kernel.org>, <david@redhat.com>,
	<kbingham@kernel.org>, <weixugc@google.com>, <Liam.Howlett@oracle.com>,
	<alexandre.chartre@oracle.com>, <kas@kernel.org>, <mark.rutland@arm.com>,
	<trintaeoitogc@gmail.com>, <axelrasmussen@google.com>, <yuanchu@google.com>,
	<joey.gouly@arm.com>, <samitolvanen@google.com>, <joel.granados@kernel.org>,
	<graf@amazon.com>, <vincenzo.frascino@arm.com>, <kees@kernel.org>,
	<ardb@kernel.org>, <thiago.bauermann@linaro.org>, <glider@google.com>,
	<thuth@redhat.com>, <kuan-ying.lee@canonical.com>,
	<pasha.tatashin@soleen.com>, <nick.desaulniers+lkml@gmail.com>,
	<vbabka@suse.cz>, <kaleshsingh@google.com>, <justinstitt@google.com>,
	<catalin.marinas@arm.com>, <alexander.shishkin@linux.intel.com>,
	<samuel.holland@sifive.com>, <dave.hansen@linux.intel.com>, <corbet@lwn.net>,
	<xin@zytor.com>, <dvyukov@google.com>, <tglx@linutronix.de>,
	<scott@os.amperecomputing.com>, <jason.andryuk@amd.com>, <morbo@google.com>,
	<nathan@kernel.org>, <lorenzo.stoakes@oracle.com>, <mingo@redhat.com>,
	<brgerst@gmail.com>, <kristina.martsenko@arm.com>, <bigeasy@linutronix.de>,
	<luto@kernel.org>, <jgross@suse.com>, <jpoimboe@kernel.org>,
	<urezki@gmail.com>, <mhocko@suse.com>, <ada.coupriediaz@arm.com>,
	<hpa@zytor.com>, <leitao@debian.org>, <peterz@infradead.org>,
	<wangkefeng.wang@huawei.com>, <surenb@google.com>, <ziy@nvidia.com>,
	<smostafa@google.com>, <ryabinin.a.a@gmail.com>, <ubizjak@gmail.com>,
	<jbohac@suse.cz>, <broonie@kernel.org>, <akpm@linux-foundation.org>,
	<guoweikang.kernel@gmail.com>, <rppt@kernel.org>, <pcc@google.com>,
	<jan.kiszka@siemens.com>, <nicolas.schier@linux.dev>, <will@kernel.org>,
	<jhubbard@nvidia.com>, <bp@alien8.de>, <x86@kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-mm@kvack.org>, <llvm@lists.linux.dev>,
	<linux-kbuild@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v5 15/19] kasan: x86: Apply multishot to the inline
 report handler
Message-ID: <m7sliogcv2ggy2m7inkzy5p6fkpinic7hqtjoo22ewycancs64@dnfcl2khgfur>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <2f8115faaca5f79062542f930320cbfc6981863d.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZf1YeWzf38XjkXPjTH3dqSCeZ2_XaK0AGUeG05UuXPAbw@mail.gmail.com>
 <cfz7zprwfird7gf5fl36zdpmv3lmht2ibcfwkeulqocw3kokpl@u6snlpuqcc5k>
 <CA+fCnZe52tKCuGUP0LzbAsxqiukOXyLFT4Zc6_c0K1mFCXJ=dQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZe52tKCuGUP0LzbAsxqiukOXyLFT4Zc6_c0K1mFCXJ=dQ@mail.gmail.com>
X-ClientProxiedBy: DU7P191CA0011.EURP191.PROD.OUTLOOK.COM
 (2603:10a6:10:54e::18) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|DS7PR11MB6013:EE_
X-MS-Office365-Filtering-Correlation-Id: 37da5baa-a4c4-4b1b-0efc-08ddef7cd43e
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?QkpHKzhCd2FvaWhjY3pCMm5TWEUwdHRhenFZQTA0anpsOUlLcStxMktYT20x?=
 =?utf-8?B?YTBKeXJvZ2JuekI2RGowSkRJNlZuNVpTWWRwbTgwcFc2RlBLZ3VzRnJneFlB?=
 =?utf-8?B?TEtmQ3phSU1RWnJ3ZExPRUdBTVNYMDg4SG9uR2ZoemhOd0tBZmZXVzU3Q2dY?=
 =?utf-8?B?eVlydFZnYjgrTW93akQwbzVDYXJYbVFtSUdSM2ZKY0NSM1hUaUt1b2k4Y3cw?=
 =?utf-8?B?RU9Xd0NXSWpnV0FFS1JueUJZU0YwaWNrWHZKWDZ5V2dJdUpaUFdncUJLdTIx?=
 =?utf-8?B?MGpLQjJVZ040YzdMeTlNeEw5UmlRejNtcEpXRGF4OEpxbExlcDhEWWV0cDlZ?=
 =?utf-8?B?R1FHakQwOUY2MmNHTmswbjFlM1Y4TnMxNXVYTUNhOHM1dDJZbWRaWTFaUUht?=
 =?utf-8?B?YmNSdk0xaGloajk4M2NYMnY5REVCMGlmT3VHa3RxNW5WY3k0UXJPaTNnR2lY?=
 =?utf-8?B?cGVIcWtIZWhiV29jcmJCemhGaHl2Q3BnMGNNWFFyYnNKYTB3b0R5ZEp2MVV1?=
 =?utf-8?B?RUNveTZXV0tMWDZmQzVZN1ZseC9VT0M4YnNBM3lhSkRKT0graXNvcGhhSk01?=
 =?utf-8?B?WDh2cEtYMHo5MVkwNG5wMW1pc2ppVVJVNWloa1hsZ0EzZEtud2tTd1ZEalJx?=
 =?utf-8?B?bkR2MWlNdWlKN29maHRLRzFseXRqVk5rcno2NThWbFUvVnBqSGkzTm1LVHh0?=
 =?utf-8?B?My9LMWxzYTBYRVU1Nlg4UkVESU5KdDFPNGYxOEhzVnl6UjFYOTEwaTdrb05x?=
 =?utf-8?B?RWV5d2k1TTRmeldXZHFnbDU1SU41WUhOTWRXUXQ1QVZKREVubTdPMlpOWWFZ?=
 =?utf-8?B?c24wbm5ONUFlcTdPamdNdDZ3bzAxMDc3U0xxa3FUc0QwcGc0WEtLbnJzWlhB?=
 =?utf-8?B?TkY0OHVjMmJVZzYvWGtqZnlOVlFQVXI5NUlJMXRoQ2xRMktYQkJrQWZ4TmFK?=
 =?utf-8?B?MHFCOXk5VVBVSVUxTlpyckVlQzVhVkpxZzAwT3JVMDFReVorenBTY0hGNDRM?=
 =?utf-8?B?alNkd2l5ODQxVy9NMnRjMjkwU2VjSXZCNjVGSEYvRnZ4U0Y4UWoyNUU2cTMw?=
 =?utf-8?B?bzFQVVkvY0RvY044U1BBK2l6MHlXYkNuaHlxN3c0b01lMDJwSDJHY1V4eVB4?=
 =?utf-8?B?UGh4a1d5Nm12cFFhMjl6dXJUbUluTVJ5YzE1VlFQTFpkUHZiUFZMaTNWZGc1?=
 =?utf-8?B?V284YkNSa1cwb1JGTmlzQnd5T1NDRXI3VmVYUUJJVEMvUGdzRUVkQWxOcU9k?=
 =?utf-8?B?Skg4dlR1RXlzN1FTRkh6VXVHb3k4cjRQUThIaHMrWVNJSDFycG9BNk1kQkFn?=
 =?utf-8?B?aklCNjlwSnN3NWFTTXlXMmtTRzhvM1pNVlFTeUhjWjVpd3RZRSs4c09aVEdi?=
 =?utf-8?B?NGRuNktLV2o4SzNVeWE5MmFnd2dTSUZwalJGSUJva2lMOEp2ZVNwdUFaUDhl?=
 =?utf-8?B?aGc4RlpHMW45SWFwK3c3VnY4QlhTZXNrSkExblBjNmZTVHBKdW9RLzVmd0hB?=
 =?utf-8?B?aE82QW9XSG9zOEF0STVOZUhYeGo0VXFrVERJdE5CRmhqMllyN282UDNIdm55?=
 =?utf-8?B?eE1CWVlQL3lNNzNmZE5XT3RTc0tZTDRNc3A4UzdMRmcyOFVZMVNKRXVHME1X?=
 =?utf-8?B?THRmVWtiTjFSYjhFaFZzVVFmZXltWWN2aTVOT1F3VEJCeGdIaUc4c2FQeUwv?=
 =?utf-8?B?eUg4THl4M2dxenEwR0krOVpHRjQ1TlJGY3RSOXpTOUJLUU8wRTFKN3hyQURw?=
 =?utf-8?B?VWhKWWRROVliOVlVbktaNVU1SWNPS3Z2VTVmM1YyVlRrUUVFREhUeXNDVGVB?=
 =?utf-8?B?RG9adjBEcVhGeTZIV2ZacGhlVWlBaDhvTUZOTTB3U2ltd0Zzd2xTQnJGOWdv?=
 =?utf-8?B?VDhtbUQ5ajBNYUxiWTBPbndVQ1BiV1dzYVVoajZYVGNUbkVWRDFzMUFtM2tH?=
 =?utf-8?Q?jk56gSrNdz8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?bTdXSHJRaHh0YmdnVG0yLzVxcXdMRlUrQlUvaDFjZU1HS2JHS2o1VGc0QmdZ?=
 =?utf-8?B?T1JZU3VwTDl2cW5PTDZ0V1Y2TU94VVRjbHR2Q0c4alB0N0RYU3d4K1lHRmpm?=
 =?utf-8?B?VGdJU1FGdzJ2QjhwaGJOWm1lMmJ1bFBCTjh0aEl4NXorbW9lMm9jRW9MQnBD?=
 =?utf-8?B?YnZtZ2VlSVBnKzU0eTkzaTBzYmNBb1AxbEs4SzRxSW0vR0dXVlNLcjdOZDd5?=
 =?utf-8?B?SnlZSGkrdUk4bTFsdThXWTgrTXZyUHByN1V6ZkhUeW0xTWU2RDFNVVFuZHJF?=
 =?utf-8?B?Q1M1cGpjMXpkOGZxMjNnaERJNUk1MVpxMnAyb3ZKenp5c3B2NkZjcTRpNlN1?=
 =?utf-8?B?aC84STdYU01QQURwQ0RaUXg2Wk1vODJVcElKS3NBTUZ4Mm5OTlhwTkJjQWJK?=
 =?utf-8?B?bFpvRitCZ0RKTnhEMDBmVXR5MjN2M1d4M2l2SE91SlZqdmJtbFQrSURRdWd3?=
 =?utf-8?B?Nzc3RnF5VTdHU2MwWWFMOURZMTF3Vy9YamN4OEJhRjlzdWZFWkVWWEozRTNM?=
 =?utf-8?B?YmhUK1oyOUs0Y0lXT1I1OGFIRVVvVml6QmZnT1ptZEdTeXMyU2RBbjFQanVJ?=
 =?utf-8?B?NUEyZmFsQjNIK2tBVmtYeEVQWkJ4bGlZN2hRYkdGZWV6WE5HMm56Q2lNM3ls?=
 =?utf-8?B?cHdGMlVxSzBIY0JXMWNOWnYwWjM4dUQydmtsY1pnTWszRkQ0ME9vQWxxazl1?=
 =?utf-8?B?WVk0YkRrM015cEN1OERuMTVLSm8wdTA3c3hUZVpoZ0xxQzZ2L2F5QjBLZVJt?=
 =?utf-8?B?bnZLK1owRURyRjArTjl4Nm1LcmUxK1JvTDFmbkRPNjFvdDNhc3c2dWFEbkMz?=
 =?utf-8?B?eWRKOUIxazJtMTFWWUtmY2FYWmNHZVkzdjd0NTlIeGg5NWFISmNMaXJHakdX?=
 =?utf-8?B?a2pHRm9oZE9YUmM2Z21LUXVKRW5aR1J6NkVTeUU2eGRBaFZKRGsvZzlNdHdV?=
 =?utf-8?B?RmsrSWhNWWpXL215M2RTUUhvM2l2a0QxNU5zMlI4Q2NmRU1QQjNPV3k5bzRL?=
 =?utf-8?B?M3NXZnNhOGtEaFIxU1E4WFl6QlFQVEMzZENJdnZicXB1UDJUWW9hbkE0Qmpj?=
 =?utf-8?B?VzZMWjRjVjZSQ1A1bmVhODJoNUJ3TUt1WHR4cGFmSkxxOUhhY1VyeGRsbVFa?=
 =?utf-8?B?RDlPNmpEd2c1bzljV2hVUENoQVRVaElzOUtLVGorazI2eUw0a2NqWkpUYmpE?=
 =?utf-8?B?SEtPNkJ3ZllKaW1venRWVUJ2SEF0dXF3MUNORjhkM1ZPTlV4Z3NwRlA5cFFB?=
 =?utf-8?B?R1FEZHZPRlh4djM0QW1CUU1sVGorRlMvZCtkUVEzamljMm5uVndmc3VNR3dk?=
 =?utf-8?B?MGJ5NEpZSkFLcVgxR2N0b1lDRk1vcHl1dVllVXI0NTNZQkVkbFVyR0NqMHdj?=
 =?utf-8?B?K0hlakJOMnhQSCtaZFlVQlZQbUlhNVp6Q200dm03cmErZFFlR1ZJeHFjSmZF?=
 =?utf-8?B?NS8zQnNVbWJMamp5UXNTU3l0dVgvUC9DUUhabHh1UkkvSVhad0tBdjlUb2Yx?=
 =?utf-8?B?ODhSOXc1SU9zUnFVWDN1RVV5Mll1c0dzdFBXT3BKOEtxUzRKbHNkbWZwOFVW?=
 =?utf-8?B?Q3lLb2Qwd1pkdXVjRlcySGt1WjF2L05HS0l5L1Z2eTJ4OElNajZkazRZaEFq?=
 =?utf-8?B?UVN3SmhOZ2tXY0RnQjVIZzFnUkpXYXF0SnhiQkNaNnJJNFVlV0ZGZEg5OXpy?=
 =?utf-8?B?NmEyTEZwajFUNlZQTlZMajRLckNXTUFNM040d0FNbVpOSHJJQ0NKcmpOWEJQ?=
 =?utf-8?B?RTA3anYyN1FYS0x5VkdIVm9LOCtmYVN1NGlwVW5aby9hZUF3cjZUbmxPM3VL?=
 =?utf-8?B?TktvY09YKzFHQzRpVUhvd1NYTlVmTlhLZHh1dHpTNURrOENueUR2U2Nxcmln?=
 =?utf-8?B?Nmg2SkJWdGVlOGt0dHZxUFo2b1F2SXNRRGt2QTNCMGZWN1d3SkFsQTl5a05G?=
 =?utf-8?B?NTBYQmtZTE5Ua2gxTzcrdzhTaDRDNWNlVzM4YlhVOWFPSnpOcjRpSnZJMmxT?=
 =?utf-8?B?UE5kZ0ZFMnExYzdhS01PQTFYSG04MnV6Vi9HcVd3NDdiRGV2b1BkczdwaE9Q?=
 =?utf-8?B?NXNFandsOU1xeUdoSk1FNlRKeXY0bVJueVdGa1NrTmtMMnhRc280ZnJseURi?=
 =?utf-8?B?QmUyRi9GeEU1K2FXTmxSdGpCc0Q5NUpzWFZsQ0hNbkp3WnNNUUVseUFCcHk5?=
 =?utf-8?Q?RI6o9yKTJSy8QS5rgNPduas=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 37da5baa-a4c4-4b1b-0efc-08ddef7cd43e
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Sep 2025 08:42:37.3649
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: LeKj+LrAFXRnbrm1cd5v7+wMy6AqvdA4ssxa875Oc1cSqS5PdaQdeU/p4RGEmG/LOXvdfEhL5LWOZSlQ+z/z1n04+iBu0jUvLdeYjduR4h0=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR11MB6013
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=aBpyXf7T;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.19 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-09-08 at 22:19:11 +0200, Andrey Konovalov wrote:
>On Mon, Sep 8, 2025 at 3:04=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> >> +       if (kasan_multi_shot_enabled())
>> >> +               return true;
>> >
>> >It's odd this this is required on x86 but not on arm64, see my comment
>> >on the patch that adds kasan_inline_handler().
>> >
>>
>> I think this is needed if we want to keep the kasan_inline_recover below=
.
>> Because without this patch, kasan_report() will report a mismatch, an th=
en die()
>> will be called. So the multishot gets ignored.
>
>But die() should be called only when recovery is disabled. And
>recovery should always be enabled.

Hmm I thought when I was testing inline mode last time, that recovery was a=
lways
disabled. I'll recheck later.

But just looking at llvm code, hwasan-recover has init(false). And the kern=
el
doesn't do anything to this value in Makefile.kasan. Perhaps it just needs =
to be
corrected in the Makefile.kasan?

>But maybe this is the problem with when kasan_inline_handler(), see my
>comment on the the patch #13.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/m=
7sliogcv2ggy2m7inkzy5p6fkpinic7hqtjoo22ewycancs64%40dnfcl2khgfur.
