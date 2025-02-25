Return-Path: <kasan-dev+bncBCMMDDFSWYCBBYOI7C6QMGQEKJWPHEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 683C4A44C21
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 21:13:23 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43998ec3733sf30690535e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 12:13:23 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740514403; x=1741119203; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gJNrtoQVVA4ca+BoX7DZhT1qVIaLvWpOx9vzqkTmjpc=;
        b=QwDLNukCe2SLmI09YwzWGHm4uagCuUo96IyIPX4j31sGjHsVEfZqdrWbtjnEGBvm/V
         OmOac4eTB4/TOyfQnp7+8Ia4ybytCsWzef0cfNZiE6cIld4WimB5/oygiOLALC025YFk
         dc2st8NdROdHb+gBQw4hkBk/4THuzSws/okBOz6I1AwM4rk/B8niMK/hZEhiQ+xYS6GN
         5GcM26d/mHSOzUcepZs5zMHkqg2OEUWN7/hCUZGwEYKnfDQaDQFceXn6qXsGEWz88zRK
         9c0TqXMBvzIgMpLOML8SCeR6hZqXLkiur+QBuyvAuqZeSAKFvSWx0sDlf1EdVk4a9jTO
         0IRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740514403; x=1741119203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gJNrtoQVVA4ca+BoX7DZhT1qVIaLvWpOx9vzqkTmjpc=;
        b=XDVwcnjM+LGdyi8h22vpLN7IL1sSMGcTQ0rIP6fzfvFdCwtO6xw3t61n5nsPvUx62z
         HUKurNM+1+KdPx/U8eNc39MfHNd7NjcaHJjxEYiV4DiMzoBgrRTMAs91cZONQgE625LJ
         xtHc4b8rWxYrxmvvIpEVnlNW2pXy0Imsi2Uthy+7OlZOCy1ttTfATuyPqVAKTrT4vvNK
         dPPgj5vFQxORYf8JY2FaWZhmKLNHy7xdiXbCZkI5PGW6xzeu6tOqMpehm79597Koq4Z/
         Yg8M+66qh/ilubqIO6ZXBeB5yHAVErdELxuZ6uOBJKCkjpLPxSgPEgjT5cuAP2xrR71o
         rbjQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUtLFwRIMo5QGjKBucosmqsm8wJ8XR7JvuvX1IfpNdaUibNExPK3z7P/0CRo1HIyT8ihKxbuQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyrvzrte1ipo78W04oMZRmDACgXBrmA0nI+J33J/3oRBl/jrYbc
	JikPUADpY6V+K3aY2i3ZcofNLQDcrNV8GZcivsrjS2uIrEfSs6NL
X-Google-Smtp-Source: AGHT+IEc1V9YeDAB9XrJeql/7Oe9wj1st+bOeDRRTv6IzaiUWjf7EbCSEAZCOsNKhqulEkZKY6gmRQ==
X-Received: by 2002:a05:600c:a01:b0:439:84d3:f7ee with SMTP id 5b1f17b1804b1-43ab0f65f98mr32776765e9.24.1740514402124;
        Tue, 25 Feb 2025 12:13:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFQfdHZ1wK3d5p0fj3XWJg4IpvgM+CFYNsWHCzZy3GzBA==
Received: by 2002:a05:600c:20d:b0:439:ad97:3dae with SMTP id
 5b1f17b1804b1-43ab12dbc74ls6628315e9.2.-pod-prod-04-eu; Tue, 25 Feb 2025
 12:13:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX/28Hy8OjsnHfgQ7eGQgcupriDi63QS/av/A3CA8WtvnC27x21zoSuhzPosB2iL0bC9/ZVGQ0q6tk=@googlegroups.com
X-Received: by 2002:a05:600c:46c7:b0:439:955d:c4e2 with SMTP id 5b1f17b1804b1-43ab0f3c192mr38511245e9.13.1740514399741;
        Tue, 25 Feb 2025 12:13:19 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab154c87fsi1008175e9.2.2025.02.25.12.13.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 25 Feb 2025 12:13:19 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.12 as permitted sender) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: DCIzgJ3wT8W25KnCPXgYhQ==
X-CSE-MsgGUID: QJySRokCSYSCHxFIksP6dA==
X-IronPort-AV: E=McAfee;i="6700,10204,11356"; a="45254907"
X-IronPort-AV: E=Sophos;i="6.13,314,1732608000"; 
   d="scan'208";a="45254907"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Feb 2025 12:13:17 -0800
X-CSE-ConnectionGUID: uNxAQiCITX+E+vBU/uNi3Q==
X-CSE-MsgGUID: PnN6e/KUSGKJF27r8F1kQg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,314,1732608000"; 
   d="scan'208";a="116687891"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by fmviesa008.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Feb 2025 12:13:14 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Tue, 25 Feb 2025 12:13:13 -0800
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Tue, 25 Feb 2025 12:13:13 -0800
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.169)
 by edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Tue, 25 Feb 2025 12:13:13 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=XyW2tPBSmHCu9rwbjggO5j7Wbqe02lRkew+l23OBYglwisky43hWsqS687JJVPoAdtbrQBxWGkt31HhKK62jctjgi8ljO/KUwSyHKjddXqAzKNCnZVIeFZ8jZKFHR2M9nJUDRDLASSFJEUH+mTCY9TDPiA5chREgMVahBtGuPyZe6H3Wi7+DJeh6DS2lAeFQjo9jsYeWYlRM3FsE5n/3GnXv9O8xJjSt4MNDMerg/RlsiEFY9D97yQZJn2GbdajKAZppEnZTI+YKfr0yjRDKyYSdzgwKxjXffhhIKU7lUU5aeSpL8lF9d/TXHcAflShPZ0rJfC0bpurl1wX6LhNnsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=rZ+Vqt0SmfpAya6lJpdolVaaTxyKt689D6R8z4gg+dM=;
 b=Xm4anYc6qDoDcNq9cMc1id6nTrUc0T/dvGBfIDDlMjW2Uz+ly3Wa/63pistGMjXToW5m6Tuw9DTobyZebuIOtRGNZAmiV9yt0iNok+4dKsGUCqB+UtWcc34ZHlnpkb9XruxAuzGsTYcLbSc9XybGBbUCJLoJWJBZaLi7HyLVEmToQyQVWOdoi4+PIrQQSw1CCrx3g/5Nhe3B2KF5BYKFvgu74MZkFh4HeDJQq47nML8pshwGhS2vNvtRO1AGPAyKu0BVIYEZqaK5uZ42qhxl3NaMxNPgm+LAqGi9xqkN0G6fFK/nFnzX/ZD21Xj/C94Ps5hmIlIj0C5tirD6PD1mnw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by DS0PR11MB8071.namprd11.prod.outlook.com (2603:10b6:8:12e::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8466.20; Tue, 25 Feb
 2025 20:13:10 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8466.016; Tue, 25 Feb 2025
 20:13:10 +0000
Date: Tue, 25 Feb 2025 21:12:57 +0100
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
Message-ID: <6wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne@uv5wzotu4ri4>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZcVSwUAC9_xtVAHvO6+RWDzt6wOzWN623m=dT-3G=NnTQ@mail.gmail.com>
 <cik7z3nwspdabtw5n2sfoyrq5nqfhuqcsnm42iet5azibsf4rs@jx3qkqwhf6z2>
 <CA+fCnZd6O0_fc1U-D_i2shcF4Td-6389F3Q=fDkdYYXQupX1NA@mail.gmail.com>
 <uup72ceniis544hgfaojy5omctzf7gs4qlydyv2szkr5hqia32@t6fgaxcaw2oi>
 <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <gisttijkccu6pynsdhvv3lpyxx7bxpvqbni43ybsa5axujr7qj@7feqy5fy2kgt>
X-ClientProxiedBy: DUZPR01CA0039.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:468::17) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|DS0PR11MB8071:EE_
X-MS-Office365-Filtering-Correlation-Id: 569f7643-d808-44c9-034b-08dd55d8d35a
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?MitIYmNjdUV4Sm13NFpqbjhrYSt1MFcwclgvNThFbEJxK1VuUS93N0liWlpF?=
 =?utf-8?B?bXNjTWdFZGNnUHQ4MmtDd0lkdXFiSFQybTJ4MDIxMHlDQ29SZ25zMlo4OGdx?=
 =?utf-8?B?ZXRlOVhyNWZRdVRBa3lJUEw2K3pyNzVUMEk0d3M3cnpFdWQ3V3BDTS9OcVJw?=
 =?utf-8?B?WnVPUS95V2lKTldyWmhCVjI2SmlaRUg4bGhMWm1BTDYyenZmeU1RRTU4N2JL?=
 =?utf-8?B?RFZ1blVVSXVJQ0hHWUJCaWc3QSs3aTFiY0pCcmRzT0NDYmxtNmZTaWxjTDdk?=
 =?utf-8?B?QzVKWjg3Qm9MY1MwcVY4d1UzTDJ5SmJTOGt6clU1ckdoTXRRcWpRZHRQREZE?=
 =?utf-8?B?K0xSWW94WThGYkJhK2VsbCtNVTYreHU4ZHg3WVJFb1pZeUxMcEF2cjNGYm1I?=
 =?utf-8?B?cFFBdlhDcVFXajJ6RmQxaXBrWnZMSmFQUTdXQVZsWlA1T0tlR042dWZzcFJq?=
 =?utf-8?B?bmtVbmQvR0t6QWk5ZVc5YlBZNzZlOVRVd2lTbHlhV1ZzMVMzR3lSaEV5YkxE?=
 =?utf-8?B?cWdmcVlCWlJ6NkJNSDFYT1dMc2ZIcHBVQzFxYzFCZW5HSWRSTFA3TGk4Z3JH?=
 =?utf-8?B?eHlsRnFZclZZZEpmNXNSRC9SeEp0NnljVTlvUno1TzJ3N2Nma0owRTVYcTZR?=
 =?utf-8?B?MVlkS1UrSy9pUVlZaFJ3NDlQWUQwUG5Dd1NNOFAyQkpzS3BkZnh4eFFFUVpI?=
 =?utf-8?B?blBKcTRweHYrOUQ2MzVVN1hGSlRkME0rR3dUb2o0VTRwQkRucXE2WE44dmhw?=
 =?utf-8?B?b3VWY1EycHVIK2p5WDhEY2FHQVc2S1NmWkRzZ0xyU2V1elhINTdEbGlYaUNp?=
 =?utf-8?B?ckVaR0YzQzZFaXgrN1liK01mdkRUcTJ6TW1La0JQbytpQURENnN6WHJta3NG?=
 =?utf-8?B?NG9MKzVnTzRsZkFSdyt4MW5DNFYwTTBMVFhJVzh2VnFFU24xMmM3WXkrZTI0?=
 =?utf-8?B?SjVuMkpyKzkvNXJFUVJLK0lJcGREa2pKbmNFTU1IbkN3dHB4ampJUDFWM2hR?=
 =?utf-8?B?Z1lGdGYxYmhUSEt0aTlnUklGamtmdWxYM0hLblBPdnNkeG8vc3dFWG5uOExC?=
 =?utf-8?B?d2tOL2RKc2prMlBHRytyVFJGVEdJa28vRUpiVTlIR2tYaVNGTFdMeEFSVkV6?=
 =?utf-8?B?VGkycUFXcjhzc0tBSStaaHlkb3VnWHp4ZXZIbE4rQ3JDekpkV0krcUN2ODJn?=
 =?utf-8?B?WUxPeVoyQmVIYVZEckk0ZzZaTjJSdEpDZnhXNVNNUHZmLzIvekN2cFQ1YmM1?=
 =?utf-8?B?V0Q0d00xNm1qanZvYStOQWJJYnJ3Y3JTdGdObVBRWElIQWJqTlQ5QVU4dTI5?=
 =?utf-8?B?dUVIWDBESm9LUXZxTlY1dzZtcnBIMGJuVm01VmhCcDlZdG5hR0I1bjREMFNz?=
 =?utf-8?B?TXlVWkpjWU5jUGlXR1JLMnBrNi9QV2ZjN0h1aWlSeFZwYlAwVDNjZXd0bkJK?=
 =?utf-8?B?dDhJN1FKb2I4eWkvV3hZTzYzVWNneGc2RnFBS1QrQXU5NVh4S0sraFhYN1dT?=
 =?utf-8?B?SVBQTmRoUlBJbnNhdTF4RDk5em1yN1VFSS9obkI2QUdKNTEzOG9DMjNzN0NM?=
 =?utf-8?B?RGloQnJFbTk2K1Fub1ZpamRTM2M0d1YzdFI3eEcwTzMwU090SDBBOU4xT0Q5?=
 =?utf-8?B?NGlIN3RsMmtNaDdiVW51bzNCaythYWh1TkJ1R2lLaGcwckwvbWhudi95MnlX?=
 =?utf-8?B?N25jY1dxTHdBcDRVRFUyK3poeXR0VjNuQWxTVWZUelY3bVEveCs0YUVEYUln?=
 =?utf-8?B?cS9mRnhkVmlxU3Z0SFZsdXdTd0dQUzZENTdvQyswSUZOeW9VTUlnOUpQZU9J?=
 =?utf-8?B?OTBiQlIrWHJGTE5kcC8xUWdvWENPU0VWN2Jta1hwYmc1TzZRUFMwUGlDMUdO?=
 =?utf-8?Q?b/kHggWgXyh+X?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?c0RraWtFWGlXVTZFYWE0dVlaR3YybjNoVlpvMFczbUpUSWxJS2swUjlldGdM?=
 =?utf-8?B?V0FxMys5Z3JRQkc2Z0pCajVwdUUyQUlraTd3bXFQVk5TTG40MWc0dVpaKytX?=
 =?utf-8?B?TU1qQ1Y0R3czV3JNNzI5dGdqc3U5L3BiM2dZQnFBaThmcWIzcUNnZGx3elcz?=
 =?utf-8?B?T2Qzc1p0Y25lUkkxSUxyZk5OZVZoa3RUQ1V3blUxUUViKytuS1B0Q0hHbkh3?=
 =?utf-8?B?MGxSYStUVjBMRW5YbDdVSXYyM2hpcWRQR21CaDR5R29iT05qOTNTNVg0R3Yv?=
 =?utf-8?B?VXZ1MFUyWkFuSXYwbFhwMzAxRUducy9IeURFRE0ybExOYlQ5TEc3b2Urc3p4?=
 =?utf-8?B?bjNJeDExSnNNVE5iZWxsR3JSV1FPdUZvNndKb1BvcFdHZUtsY0NVR090MXhr?=
 =?utf-8?B?Zlc4UVhMdDAvMzQrTTYrclExbS9qTUNDK0l4ejBHWmdlaGdwcEQ1bmJjSW9W?=
 =?utf-8?B?cnNiNUFWUGRobG9ORUI1T2RaeXFoS0lwOHBoVkMxWkZJSUwvRWNTMHRKb3A2?=
 =?utf-8?B?Y2EzeTA4YnllVVJ5ZjdET1U0V1ZOWGJHUXdjUVZMbDZlV2Nxb1F2bEJDc3Fs?=
 =?utf-8?B?Z1BRQlZjVm1rcHpJUUVBMjBpZWZhRldNWjlkQ3RxV0lvNWhZYmNNQU81LzJa?=
 =?utf-8?B?ZVJFUmRQUEw5T21sRDd0TDZ0a2ZMY0RMOFMrYW5oWTF1ekloZHVCSmNDT3Rm?=
 =?utf-8?B?NS94bXpVekowOU5kQ29PTEtWeG40L29QZHRhcHEyNlBwR1VmWUpiTzFjVnlh?=
 =?utf-8?B?MytGUlRnNlVwRm5seWFnNlVkNklpT1drUHZpeVI5RWR5Q0xZVE0xU3dacWJp?=
 =?utf-8?B?ZG1tSUpGdDRVcXNpMnhHc2x1b2ZONXdhL3JEWjB6b1RoUjNRQjN3dWJVelJu?=
 =?utf-8?B?N2xsOTBmdHR1UDg2ajFTN1J3clVqV2I1RkVnVk9DdXNEbDZucnBuT2VpOGRt?=
 =?utf-8?B?Rm00TlNJRHo3SkpNTEZKZEtWYWU0ejFraFpHRS92VEY5UmZQOXFMWGh5YWxI?=
 =?utf-8?B?SjV5QTZ5QWtneDd3NS82YUhCMThRSlFhR2dQcDdEczNtdGZQL0tOaHpmdlJt?=
 =?utf-8?B?TXJyNFlzRXFTZjVHOFhNeHdTS3RFUXdEUjN1S3ZDNVZsL25kSVNuZ0Q5YlRN?=
 =?utf-8?B?Mnp6QXQ1L0l3N2RZWm1maXN6NnZKSjgxR21hNGx2Z0Mxd3JRYVQ3V2g3RlB5?=
 =?utf-8?B?UXE5d2RrWWx4ZXc2bll5VlkzTkNhdzUzRkVqajRXKzdhb3hBWE1iRlBzYnFX?=
 =?utf-8?B?TXFqZU9JSWV6WUE3RWN2Z1dEK3lGbWZvVzQ3TituT1RVOE5rTjdjZjQ0MnZy?=
 =?utf-8?B?WmRyeVV0dzRaRmpXSGpnQnAxbDBuaERhbTB1RGlHOXhyKzI1ZVVVK1d4Mito?=
 =?utf-8?B?dFBDc2xyUkxWTnRVOUZvbU0wWU5WWjhzdlpzMUZLRURnV2F5QThTSjVSdFRu?=
 =?utf-8?B?eVkwWk5QWDBhc3Z0RDdDeU1rVHhKN1ROeHBlaEk4Qzlra1BJcGl5cXUxV2J0?=
 =?utf-8?B?R0VCd3NVVWl3aUpzNFl4WVdOZzlrcUN3MDRzVDJuZ3VxZFVoZmpBemtHeEZZ?=
 =?utf-8?B?OU9tUWtEeW1WWkZSMFhCYlBtK2tybnpGQVpBRVl5UGtZOUVGRDQ2M1ZKS0xk?=
 =?utf-8?B?cFVRK3pzVCtUNDVMM3BsNG0zM2lRNkpucHU2b3gyNXVLZldqM1VMcnJ5b29n?=
 =?utf-8?B?M0xTWnJEN1l1NStGZUd2ZWUvNm00TW1RQzkyd0ZjVXRxamJ1SWJhTXBuZVNN?=
 =?utf-8?B?Um1hVG9HNmhnaXJxZ3AweG1mSWNRME9xZjZkNTVhOXVzNUJOZGhnbmhISS9z?=
 =?utf-8?B?UXJ6d1J2MHdYUTFRMDFyNGxMU2VDSDR1SEZQdUxQaUFJcDNGd0VMd29aNExU?=
 =?utf-8?B?NU96alJSRGRmMVNjOUZPam42M1R5c0RUOTk1RDkwaEw2UlVtaXd6SWRZQzlw?=
 =?utf-8?B?cjFkNkI2Nmt3SGorcnBkMkEvZmUxOGVIdGlmR3NFNXhXWWxxbUIxeW0vRVcy?=
 =?utf-8?B?WFp5bTZrNDEzZ0RaMll3eWYxb1MwSkVGYUQvYWhTVC9pbERmOTdqdkQ4UElT?=
 =?utf-8?B?SjU1QmNpbVhkN1VuaGNPR0N6VnFJY0hzQmwrZDFIN2JWTXBGdzh3QkF5OFVu?=
 =?utf-8?B?K3hnb1d4T0d6bi9oRlRNMndyb05aQ05qY1g1VTQwZDBMV25VRytxYXprQzBn?=
 =?utf-8?Q?ZnleW8xktxON/UKyCavoMeg=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 569f7643-d808-44c9-034b-08dd55d8d35a
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Feb 2025 20:13:10.5528
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: VWUVci0fibAsZmEC5XyQ/PY/TfJSIlZw4H2oEhhMmWnDEIx+DJEkXQ/johDDuQNyslvYhvDboWj3wjj0m2JXAnX7cG9pgB+AkUp8uvh6bFc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR11MB8071
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="G3d/mJls";       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.12 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-25 at 20:12:40 +0100, Maciej Wieczor-Retman wrote:
>On 2025-02-25 at 18:20:08 +0100, Maciej Wieczor-Retman wrote:
>>On 2025-02-22 at 16:06:02 +0100, Andrey Konovalov wrote:
>>>On Fri, Feb 21, 2025 at 2:12=E2=80=AFPM Maciej Wieczor-Retman
>>><maciej.wieczor-retman@intel.com> wrote:
>>>> >                   Thus, the possible values a shadow address can
>>>> >take are the result of the memory-to-shadow mapping applied to
>>>> >[0xff00000000000000, 0xffffffffffffffff], not to the whole address
>>>> >space. So we can make this check more precise.
>>>>
>>>> In case my question above didn't lead to this: what happens to the res=
t of the
>>>> values if they get plugged into kasan_mem_to_shadow()?
>>>
>>>We will get some invalid addresses. But this should never happen in
>>>the first place.
>>
>>Thanks for letting me know about the tag resets, that should make changin=
g the
>>check in kasan_non_canonical_hook() easier.
>
>Ah, but the [0xff00000000000000, 0xffffffffffffffff] won't be true for x86
>right? Here the tag reset function only resets bits 60:57. So I presume
>[0x3e00000000000000, 0xffffffffffffffff] would be the range?

Sorry, brain freeze, I meant [0x1e00000000000000, 0xffffffffffffffff]

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
wdzi5lszeaycdfjjowrbsnniks35zhatavknktskslwop5fne%40uv5wzotu4ri4.
