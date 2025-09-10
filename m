Return-Path: <kasan-dev+bncBCMMDDFSWYCBBHXLQTDAMGQED6HF3QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 33642B51118
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 10:24:01 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2445805d386sf82846665ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 01:24:01 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757492639; x=1758097439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1Gg7wfQv+eJWqexon677xkSLNlD2Ije1ujWmUss3DQo=;
        b=qoFFpLkIZYKM2SWXKlIBv6VNkxBtBk70Ei1M4dtAEpFs4D44IC30CI9S8V9haHm0Sx
         6rh7R4LxP8emTz1UNapAQbOr89X17MQgBI2vewQFokeCkATYt9WhF0cGrONKh1DrCq93
         ocEGgYy5x13iFkHhz0DenPo/RvdcXl/Wuo+YRkOfYo0VAYGEM0i/u8tGPuyVob2Kj3O7
         DCoT5Vb8SSad8346fp6lGFGmb39FiFHxXtAzvDW4gVRh+OKvElr6FVGnTDV1xh09ZwAw
         yCGee2EZrlK/lLhSTV1rrKsB7If99Q5kOv9pMl5XCdK042jlz8d/OuXNoLC7GW6gvF1h
         q6AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757492639; x=1758097439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1Gg7wfQv+eJWqexon677xkSLNlD2Ije1ujWmUss3DQo=;
        b=KOyFPcXD/i/wRzw3ESsbkcfsnfnwJ5E6Zk6u88oNKoDo3RpBO8TWHxQMZh6G1F3O91
         vwp73aZw0UsTIxefSP0HIfQCXqaB44R3dT2xGWLUdb79iKnIKiIEIi+smn9T6Wwp5/0A
         DwtoTjbo5NciwqdPHdvI0qRuqwtki5OUUX6B31ggUcdUvcrMFLCoaGGWPKfZ0wZu7T5N
         Bunvvq1dUysy9SQIkkUH2ZKFkgA32jAzhe07oh5SLiC4WwuZuwR0DYqVKQHNt/fW/aEt
         tMSjtWNU0TDQDvi4jBlpQz7wGM+mVZeaxr3ab4Q3PDGqsjPfpgBC1kbWKe4T1Z4gUPtP
         63YA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWC+79mCRIK4CAGoj9+bfa9Sn9K0pEQenQol8kzFyrj8M6kuxUApSHA51GhjmhwOx1Mx6x/Kg==@lfdr.de
X-Gm-Message-State: AOJu0YywcTsimHztBjwVJV8RJqMr0zWZcTsk8NqpK56jYkEnjbvnnIht
	wCUi/ZQGRg60hdYDM7XMR+MIqiu1ULKBwYOEU9dBTd4Ej34WYsZ2CbTX
X-Google-Smtp-Source: AGHT+IHvfJGzcuJTLObpjaZaw3mwfHT3USFFTqKq+ZTIhN+cPzDvi0CavgayRX+dhggbQRFGGlPGAw==
X-Received: by 2002:a17:902:ef4f:b0:24c:7f03:61cb with SMTP id d9443c01a7336-25170394a4emr215517945ad.26.1757492639423;
        Wed, 10 Sep 2025 01:23:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6T68Qg01eoxodyu3x7yl2jFxuCwlvEvmqNVc2qo2elug==
Received: by 2002:a17:902:d1ca:b0:24c:c1b8:a9b5 with SMTP id
 d9443c01a7336-24d4c94a24els37078405ad.0.-pod-prod-07-us; Wed, 10 Sep 2025
 01:23:58 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWxxzCpuVO24BmwDjpFadRTdq+VZF3SYZwbexJjHAWbvjRsUuH3NXrQi6YbZwC6FSaJJV9GxD2DDBs=@googlegroups.com
X-Received: by 2002:a17:902:ea0a:b0:246:80ef:87fc with SMTP id d9443c01a7336-25174c1a958mr211167825ad.45.1757492637975;
        Wed, 10 Sep 2025 01:23:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757492637; cv=fail;
        d=google.com; s=arc-20240605;
        b=FW5/fRs6e7+Riz7xeydZ5tr3ZP8YxzO091kGPp5qZUljyXbn+pMx0BGN0LPnSSICoA
         ft7G+4ylOv94MHqc6CoOfTL1cGuNlhdhjLxUl4PxsAM1OhlDFoplr2RfB5TmZpKR1Uua
         loeaqdLnPCDiqbu7Fdv0JJxQ4KEr6sgqpb+8IVZ9S2yW5UnQIaErtC00UR526ldefx1h
         QMbwFEdxlZjYZx0/vYstEcigwBlw73cULRApA7gsTolVU/19Is5MQxdqQe2RcGjEvYXE
         UQ5d7JjMX0UxRuyShUvenHyeoRNKPORCQG46UN14WKXUxHMOBGREF+ISqMN7K8t1MR8k
         OSfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=8U+Pt1K//jwGdtFwdNoyT+KdjwJhZrb6GsuR2FFSf90=;
        fh=G7KcuBc5R/3AOhE+Hp0JaFCX8pztIxRarfvuOPlZzL8=;
        b=DybfoMZ/vPSZaBKTeYeWxnRFby3/Q8rkrcrsmeO4pmgw0rQcylnJtIOZD8el+5q6+v
         0YOezdAg2vC+IauoXpFHqQ/Ptn0goKJZ/zBsRuS+Ql+PEw8sEJ3zSjPJeD7/8DQE/+UF
         K8R3+o/EDAvTJTV8cENrT6dMXJ4xgfywXapzat+4gFSsYdcnXBhF28eqIdrioUL4LHM6
         irpm9ECIyG5bmveiv4oPK78kqv0S7PKANlpyf5g5IpsZlMqfG6qp3KemZBLcu/rM+zJI
         Aj/OfXeJjDXsFOkG8GNr953rRTE+wwKJf9BwbLg7QYM0bP9ecHPxoiNOzmP8PrLsLOJJ
         lWvw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=R98fgxbo;
       arc=fail (body hash mismatch);
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dbb00a944si51953a91.0.2025.09.10.01.23.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 10 Sep 2025 01:23:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: UCXCKa3VTA+zM2Aul6bekg==
X-CSE-MsgGUID: uxJMJcA0RWqRMYdjAj3ZRA==
X-IronPort-AV: E=McAfee;i="6800,10657,11548"; a="70414728"
X-IronPort-AV: E=Sophos;i="6.18,253,1751266800"; 
   d="scan'208";a="70414728"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2025 01:23:55 -0700
X-CSE-ConnectionGUID: vZKvSrNVT0i/+SwV9gVb4g==
X-CSE-MsgGUID: JEagR3QMQEa8FrBcKPaoeA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,253,1751266800"; 
   d="scan'208";a="172894434"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by orviesa009.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2025 01:23:55 -0700
Received: from ORSMSX903.amr.corp.intel.com (10.22.229.25) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Wed, 10 Sep 2025 01:23:54 -0700
Received: from ORSEDG902.ED.cps.intel.com (10.7.248.12) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17 via Frontend Transport; Wed, 10 Sep 2025 01:23:54 -0700
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (40.107.244.81)
 by edgegateway.intel.com (134.134.137.112) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.17; Wed, 10 Sep 2025 01:23:54 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=OTmeLwTPPmcosKjgbXg7DYO2xCMJ7iyYHsUYH+5fVqfxDFuE8Ji5R4LiTr2XMrWXUb8uCnSwDlgJbMK7FRxJGLZ4Uoa5Yz4+fVnsJFPUaum8XdB3ezj5GdTiDGj5SZXv+SbrjNvb0VYpNOhXNS46N/XIXnWqmqYKYC2lQh8ljggoS1PSIi3kN1VBkZIR3NtORaOJHJDxjsro5UTsWLU9fSyxbiAxIOEng0IU5uGu9unadO9mxxJsh4HiMj47mHgRomFV1bivyiGjOkImDkiEkkar2pE31NAodHud9ZCpXEzrhJMHHRRoYLxVXn5mbRiZN8f1VSE6cgSYD3FeqQnFoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=WAaXSaIVoADjoz6HPGtQzawTt9gV+5J32gfTC4nKTbs=;
 b=ijgKlGmSoN2KW/ZFNMkFbNxf5KSGWSBYZ8GY2ft9IOoj30RF3DVl2JvhROUakaBbUNE9xaXCY3unV17/lN9pBRgixJqbUZg7aRllzlTCkTBvsx8bUaYYhKpqwpwg/UfLC0hdP9J87aNv9vO5748L+q9Hl7CYwVDCmKDZexG1eo/pkpnReEhlq0vzVodH6khhp55BOf41Wvo66rEiNUj+mKT73FUvGMUpNz4pCyEhtn7L6UdiV5XjyNRmScjtMJg+14a6weY9v2p68oDNYqijz8Fz/txg/ckJJMwipVZ2Ix+fS6j41byS96ybEf0xojzNUkGoBrn/GwmTR819rcMy+A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN2PR11MB3934.namprd11.prod.outlook.com (2603:10b6:208:152::20)
 by SJ2PR11MB7519.namprd11.prod.outlook.com (2603:10b6:a03:4c0::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Wed, 10 Sep
 2025 08:23:51 +0000
Received: from MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2]) by MN2PR11MB3934.namprd11.prod.outlook.com
 ([fe80::45fd:d835:38c1:f5c2%3]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 08:23:51 +0000
Date: Wed, 10 Sep 2025 10:23:37 +0200
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Peter Zijlstra <peterz@infradead.org>
CC: Andrey Konovalov <andreyknvl@gmail.com>, <sohil.mehta@intel.com>,
	<baohua@kernel.org>, <david@redhat.com>, <kbingham@kernel.org>,
	<weixugc@google.com>, <Liam.Howlett@oracle.com>,
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
	<hpa@zytor.com>, <leitao@debian.org>, <wangkefeng.wang@huawei.com>,
	<surenb@google.com>, <ziy@nvidia.com>, <smostafa@google.com>,
	<ryabinin.a.a@gmail.com>, <ubizjak@gmail.com>, <jbohac@suse.cz>,
	<broonie@kernel.org>, <akpm@linux-foundation.org>,
	<guoweikang.kernel@gmail.com>, <rppt@kernel.org>, <pcc@google.com>,
	<jan.kiszka@siemens.com>, <nicolas.schier@linux.dev>, <will@kernel.org>,
	<jhubbard@nvidia.com>, <bp@alien8.de>, <x86@kernel.org>,
	<linux-doc@vger.kernel.org>, <linux-mm@kvack.org>, <llvm@lists.linux.dev>,
	<linux-kbuild@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v5 13/19] kasan: x86: Handle int3 for inline KASAN reports
Message-ID: <63ocq6aadqn74e7g57a6p3cqkr3sf4hmejfp6hxmuju2b42iny@2du24bomvk4n>
References: <CA+fCnZcMV0BOJyvx2nciCK2jvht-Hx0HnFtRzcc=zu+pQSOdVw@mail.gmail.com>
 <couuy2aawztipvnlmaloadkbceewcekur5qbtzktr7ovneduvf@l47rxycy65aa>
 <hw7xa2ooqeyjo5ypc5jluuyjlgyzimxtylj5sh6igyffsxtyaf@qajqp37h6v2n>
 <epbqhjyfdt3daudp2wx54jsw6d7jf6ifbr3yknlfuqptz7b4uq@73n5k6b2jrrl>
 <CA+fCnZdJckDC4AKYxLS1MLBXir4wWqNddrD0o+mY4MXt0CYhcQ@mail.gmail.com>
 <ra5s3u5ha6mveijzwkoe2437ged5k5kacs5nqvkf4o7c2lcfzd@fishogqlatjb>
 <20250909083425.GH4067720@noisy.programming.kicks-ass.net>
 <20250909084029.GI4067720@noisy.programming.kicks-ass.net>
 <xeedvhlav5rwra4pirinqcgqynth2zrixv7aknlsh2rz7lkppq@kubknviwhpfp>
 <20250909090357.GJ4067720@noisy.programming.kicks-ass.net>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250909090357.GJ4067720@noisy.programming.kicks-ass.net>
X-ClientProxiedBy: DB9PR06CA0016.eurprd06.prod.outlook.com
 (2603:10a6:10:1db::21) To MN2PR11MB3934.namprd11.prod.outlook.com
 (2603:10b6:208:152::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN2PR11MB3934:EE_|SJ2PR11MB7519:EE_
X-MS-Office365-Filtering-Correlation-Id: 0d615ce0-7877-4c1f-6a3f-08ddf0435f8b
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?O1j00+Ekys610nz9REzx+VXDlQGjEkDQkGiIRP5HYqYOTbTsyDS5q7jIez?=
 =?iso-8859-1?Q?jRfl7ulWLJgldc9EczPIQTxKQAJYM9bZNPTHT/STZJ85BPvfCoYHqXNi3j?=
 =?iso-8859-1?Q?cKTt0E6iLfJkR11xj0LeTohE2EfWyPkqMZZXQxDuTzR60Y+xJfVYVGs9Da?=
 =?iso-8859-1?Q?Ewx4jWs8scC7TpOkCz4QYh4YR238G9/MLqv7DS2zsnaU102ccnMcjIH841?=
 =?iso-8859-1?Q?vE8dfRZ6rgUvu7/auypVTkymorbBJIsbdq80GmFIUxu/ALRmqVmC4cPcVG?=
 =?iso-8859-1?Q?hty8+CiDaniDUDbFqLeLNjDVv3I7lR1F2otPp2UhoosEgCK4v6W4n57PSp?=
 =?iso-8859-1?Q?8OEdBFJTlqGUvolVD/AfUcEFdGQbvJTqDaQLGrivb/ELik8h5jVXXoiKp2?=
 =?iso-8859-1?Q?U+dchHEahE1HORDx1t7WnaFpq/zfAEy1jrKuJeZJd0GUr3Y1BvKyP3tIfY?=
 =?iso-8859-1?Q?PGdphGOYUoIVR957d3RMYFU8fn8gQxTRWI/GYZbfFc8lgYJP/lOwCVVIz8?=
 =?iso-8859-1?Q?uW3+MJIaABb6m2dWRf1ZIqNKoVdfgtQsXnmnu3kiLPlC66btKvyVLGCiNl?=
 =?iso-8859-1?Q?5vRQB/J+lOhvoww0ZDUfRBm90YERc9ZYVpenK72WGPXQJlwWXrZBmk316i?=
 =?iso-8859-1?Q?Lm2bVo2oytiG0YJ3XZU6sCgNCKBw++b8JWF3WoiC+1fxVZdpxLpk5omik4?=
 =?iso-8859-1?Q?aaEyy4wXUYa2QAYaNX9XJqiiTeQwmh6rbz1FeY7S/6edI0JC6BnQMS+ue+?=
 =?iso-8859-1?Q?jQdWkll+vEdA2r9lVglKDoF/6bHASuF4l7akCc81h9h2RnPk0I3KCukAbW?=
 =?iso-8859-1?Q?fChbpgaMSOQS5aKLE285IU4U183jRj4MGKokDXuSX3b+vlpDf+f+wFdkMv?=
 =?iso-8859-1?Q?AEZRvKIGZxAoWRUbE+ihYm8hg9DVP63r5Gf9CGP3lsnKyUD2R8209aT+x2?=
 =?iso-8859-1?Q?ucROp0pQEJxcG01dQBhtjhl+DiJAvpFmYGVAbR4P6dbrupu5yPYQ1LIMbh?=
 =?iso-8859-1?Q?l7jH+fvBFz8CJ8kb9Ws2RA9HlMU7msKU/GomCYvNwGTh35kZHt25kHCBWd?=
 =?iso-8859-1?Q?6avYhAZtJQpjv7+eqOQgdzr+ZiLLyBvvn1Gixh8deR3jnWqZNY6RXiyKYu?=
 =?iso-8859-1?Q?Frg+rbwapGNACM4WwOOH082XB8LwvuNSqNySxmmoAaEjV3lyTQCN9P8meC?=
 =?iso-8859-1?Q?uMIXGLvy3ZMEMuhzccDNm4xdYogWt7nIpd0x9yUwqmecPwWnw1tW8KHNg1?=
 =?iso-8859-1?Q?XcOpXX1w8sgS8AvqJmxHERQTFJToYieoSlyl2LfjiI2Wbm7qF40BHwBkE7?=
 =?iso-8859-1?Q?H/jQjwmrhdRr2/gCdhRvkvWKF4zJDVrs7v+8sPHKuHpTzR52ho4wxTA8ab?=
 =?iso-8859-1?Q?TXHlsZoarITgH2rn51VF+lP8D7zPbj4YAEFVHCEHGtfJhIXprPwX1fbQE1?=
 =?iso-8859-1?Q?LToKZCIhzA/26DcHVoffptrCAipesoEnzyVR8s3noA6JRbQ9/AUc9i5rOD?=
 =?iso-8859-1?Q?M=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN2PR11MB3934.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?iso-8859-1?Q?e++uzuqBO2cjbBlUfDsfx5XzXUmH+faLilMr+EIYnrqrfbPmZiOZOPJ+7W?=
 =?iso-8859-1?Q?kQ3/D/H/aHK43WDEFBb3DUhhb545HToI1jyZG3Fm1GjkaU8XnYBpCKyjwU?=
 =?iso-8859-1?Q?kkD/oeO9uNTEWDi7n2IKKaxeYOFcGiKhOrapItCrNtisJ1dkRPsviKECK5?=
 =?iso-8859-1?Q?8AAvKQhJOcgvMhUhnQR6F8KudLDQCLNliWs90/GiPTQ2ytiJk0/blj9RoB?=
 =?iso-8859-1?Q?AZYBBNQbX5z7E7J07s66P52/M5yXlYBdqEonHCCwvly2vPb9X8sNpNrbL/?=
 =?iso-8859-1?Q?u1fYcNEt1qEWUk9shV2CAimTIDHMgRqGzapo1IuFjq57I3Ep68q52Ma3+D?=
 =?iso-8859-1?Q?xkLyoB3EuFATsAASYTdfrSZPydcAPP83mdhcHFYoPzf+7jsHv83XBhhdjg?=
 =?iso-8859-1?Q?14kbL2eCfkSaGS4w4OTUVui37heeZsIZjCgk+Gsh6B0Fv3g5GfM/IQ8fuN?=
 =?iso-8859-1?Q?NSjiEM8bFH4q6WaBuucnm0oN24+oQTt94RuAG0dVm8A3YXFP+zGfH8/RFg?=
 =?iso-8859-1?Q?jrrp4W9DJSs6YsqAYFT2e5ZOIktvDOpSgJLFI6E+1QBsWfE7bmgS9gwS/d?=
 =?iso-8859-1?Q?C+doNSddKOiCNvdfuWPuPzz+hy4qWkBW4bsuA3Mprh+HE9WCIOAyHFyBRs?=
 =?iso-8859-1?Q?18Ava7Gw/hvflMYbK4LGD+y8CQqsuomOmm9ljLHgVRPLxEfOs1KOf0m4mr?=
 =?iso-8859-1?Q?uyChuLsDu8HE5enztKCmgN8JNTXqVZeB7txpSGiSHka1MurFywrPULnRdV?=
 =?iso-8859-1?Q?ZUGZo4mGPzINld3oruplBL5uodz/OFEVzvnbWvGIwDKT6vtuWlxlIC8cN5?=
 =?iso-8859-1?Q?k+HuiOCQ+uR8qu7/scYURmMXtxf9osMOG3QSQKRaJvmHTgRu4Nn+lRyRBE?=
 =?iso-8859-1?Q?S/oj+sk6oaVEtRZljX/4AVoxyA9hMR32Yl+mkmsiLYi5/2gGIMIe03wyK/?=
 =?iso-8859-1?Q?OY0tRJjbzBMoLFL695/02akQYk1TXPD/KyPQvo7ITtpowTX64JNjJ42VAD?=
 =?iso-8859-1?Q?Dmc9+405fmYXTORjJBNQZwWIulJXBfEaMhkg/PTmCrDWVxOK8I9xnOmPyk?=
 =?iso-8859-1?Q?BgCtXHSPlWpm9ixvFdZ5z3cDb0JPjZ3RzcKkaCqwvkPWZmOnbVx0dnyUBx?=
 =?iso-8859-1?Q?CRAQ0Zzr6e3lDxgCMDVOLem4tbWOatn23oFu3/+SU7Yr0rcr542+ylQS8l?=
 =?iso-8859-1?Q?oXwe2G/dclXYaO0hZAJAkA2g/FRdUuUQJ0zQXxifG7p5umfD5/NBFCCqWQ?=
 =?iso-8859-1?Q?3st1iX++AHaz9TuwpAAqoRG/jwHnMyUUfe3xwFPSIMvuPUNX2I21TuVjMF?=
 =?iso-8859-1?Q?bg0j9zJma25eJykcCplO2xMfBYjmVHSdPHfL077VRxsCDRwWdvC5K0S8MK?=
 =?iso-8859-1?Q?9Q5k2i0yAQsua40EENs7SQz5SlpDIbCEaLOgicjKruKLlLAdEfRpTKvWV8?=
 =?iso-8859-1?Q?0zbKRcuQDauxo4LnfajhBqcf5Vqfc8YxN8TXzLKrhvhalOsbDZBFjHRrl7?=
 =?iso-8859-1?Q?08gvXqtwNEMOyJu9qGK1I7H7xoEAMV1Sf7CfLu+rayWI6PRA4x/VDGuQmR?=
 =?iso-8859-1?Q?fwuX034WzVVS4I5pQ/ICKpydxzLj3Lk7S1lUdvyk+DDwNtqkUdoagdlQBn?=
 =?iso-8859-1?Q?+v5ROGw3Yx+f7/Rab3MmJbUBKcZAEFUgXkn0ltrbVXxBWk1vDzXq+0Rs31?=
 =?iso-8859-1?Q?wbWAtWFi0zzIyG16Fwk=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 0d615ce0-7877-4c1f-6a3f-08ddf0435f8b
X-MS-Exchange-CrossTenant-AuthSource: MN2PR11MB3934.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 08:23:51.5114
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: SWUa+B/zhAfZlX9LY1imQIDvmNagix3F3GeEUAbXvvB7+dXBkkEMWlLRhLfgK6BuEAlxVeB+lxhbflBZCW7IbwIAC1Z3mfGjQE/3W1hRNp0=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR11MB7519
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=R98fgxbo;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-09-09 at 11:03:57 +0200, Peter Zijlstra wrote:
>On Tue, Sep 09, 2025 at 10:49:53AM +0200, Maciej Wieczor-Retman wrote:
>
>> >Specifically, look at arch/x86/kernel/traps.h:decode_bug(), UBSan uses
>> >UD1 /0, I would suggest KASAN to use UD1 /1.
>>=20
>> Okay, that sounds great, I'll change it in this patchset and write the L=
LVM
>> patch later.
>
>Thanks! Also note how UBSAN encodes an immediate in the UD1 instruction.
>You can use that same to pass through your meta-data thing.
>
>MOD=3D1 gives you a single byte immediate, and MOD=3D2 gives you 4 bytes,
>eg:
>
>  0f b9 49 xx -- ud1 xx(%rcx), %rcx
>
>When poking at LLVM, try and convince the thing to not emit that
>'operand address size prefix' byte like UBSAN does, that's just a waste
>of bytes.

Thanks, that's good tip :)

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
3ocq6aadqn74e7g57a6p3cqkr3sf4hmejfp6hxmuju2b42iny%402du24bomvk4n.
