Return-Path: <kasan-dev+bncBD2KV7O4UQOBBGGB2C2QMGQEDPG4SCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BB2F894B4AB
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2024 03:34:18 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id ca18e2360f4ac-8224c9a44dfsf8987039f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 18:34:18 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723080857; x=1723685657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pDK+l/iyB+gyh5K54H62xYupI9dOwSfs6dcQi8ud3ZE=;
        b=lPGI/jcf06ubgczTS0hLJTJ6goqtoNrDm1azTHiwCDmHUN4mF55oIYiV6aYhu6hl5K
         Ii8KF5mEGRnqY5lsBQhvFRVVNHa9C1usR1D1lj5eDaOjji5QeiMNkifxTZYDT1dsSfAZ
         zzHu/0hwo62dmOu8ba+3Kgx4WwFwNnvVM+D+qes88Qzh5iUrCHVx1LSTYtgaI7x7wMcO
         YgRi/3daAqi/WmPYKb209yVz+tF3qcp4Kj3l/6d2+Q+HsYm+oo2NlV7HnaZjd5THr4L8
         U7RK+vZHTVhlkxjkkDcG3RAtf8pN05pYyjN6khypYJnksO/+AOWR0sMy84u3v1Pn2RVQ
         IZlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723080857; x=1723685657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pDK+l/iyB+gyh5K54H62xYupI9dOwSfs6dcQi8ud3ZE=;
        b=rV/e1e732unniIyaJMDlU0IX5L3yh8FGMjCbJsvNjyFHCbVIztMsyoxqoO8jjs+4YP
         VgGb9NsOVAl1+YY/NL6kuDkAMdHQG2SucMTi0XoZKgRDC2DlyQJWRG0EnCbpsSE16axB
         UqoN8Hgcq6ocFd5V9Zb6VHj0CIPU4qK9eNs7w65BaFF5H12VDLT4ZhPhhE+3+eZUoOP8
         R4Blt0rUguNy6qUGO/ct3l9TXAoUJAOsnreqgAUo4DBcvI09Ql/pUBcoIwEW7Zcjb814
         f5Qnv46EXZeat+w1dgzs3/LIUbFC9d4svMCxY7DvZmXwcGC5a9uQvkWQvRLP68PejZBt
         8FSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWW5E84a6OOWKGMjlJGgxW6kmKaJKFOmbeluI1wkgJwI5oVBTz9f4Kdcm/a/IWXyZS6pESuiA==@lfdr.de
X-Gm-Message-State: AOJu0YwUVZgrb7nNk9y6LakxSpW/FwPcc1pLI/LrdP4NAiFKSM0hPIfF
	sxX2olnpzc5fThXHLO8FyJpARJ1pL3VkG/qeL/sqNR6IZZHJKisX
X-Google-Smtp-Source: AGHT+IFiqDm9ypTrZ0YBqJma/+N67Z8+gVlpjzVAm42gK+0T6nC+Ji1cp19buC3LfXo/8QO31DQcUg==
X-Received: by 2002:a05:6e02:18cd:b0:39a:f2f4:7ead with SMTP id e9e14a558f8ab-39b5ec6df27mr2713055ab.1.1723080857010;
        Wed, 07 Aug 2024 18:34:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f91:b0:39a:f263:546d with SMTP id
 e9e14a558f8ab-39b5c99376fls3243975ab.2.-pod-prod-01-us; Wed, 07 Aug 2024
 18:34:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXXnhum8+YpWPBrHxvFXd5GWpuZ5pRWeRfSZB+hsda/hbNG9lpgqqXh9wN56kVTpqJpthtld0rLzkQ=@googlegroups.com
X-Received: by 2002:a05:6602:6d05:b0:803:1d26:d359 with SMTP id ca18e2360f4ac-82253831dddmr65530339f.12.1723080855983;
        Wed, 07 Aug 2024 18:34:15 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-81fd4d50295si60357139f.2.2024.08.07.18.34.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 07 Aug 2024 18:34:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.12 as permitted sender) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: Jt6YntARSsyBaUsBr6ySsA==
X-CSE-MsgGUID: nuPAV2gYQSWNdOLWVnPMng==
X-IronPort-AV: E=McAfee;i="6700,10204,11157"; a="25057621"
X-IronPort-AV: E=Sophos;i="6.09,271,1716274800"; 
   d="scan'208";a="25057621"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Aug 2024 18:34:14 -0700
X-CSE-ConnectionGUID: 1I+IhKOwRGqhW1CcaumgGg==
X-CSE-MsgGUID: lFRQtPVoSxO9aZDRva2MRA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.09,271,1716274800"; 
   d="scan'208";a="94613321"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by orviesa001.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 07 Aug 2024 18:34:13 -0700
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Wed, 7 Aug 2024 18:34:13 -0700
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Wed, 7 Aug 2024 18:34:13 -0700
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.170)
 by edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Wed, 7 Aug 2024 18:34:13 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=p/d98OGVCW9t7KwKpW/ukFXh4beruEma8xkuo2ig9iJqQwQubHgRKUuVQxLMpE3JsymfI2ihLTG/xbhTJgWftb4eHF+2envJNFzOqeddM2b0S/YKy1f1i9X/pc4cSqragxt+xcub6tpjHMpXO746oD6veX03nHaUjGXdt1+jhB71be7wSQtzc9fUo/tdY5tSYnXnD1rYiyXSa2HjciM9PSH4dcngIZR+W/36mcYNZM3HBtLAfSmzOtVIxYttFu9hZ/jIRKZZkmeaClvpzbqkKgMGQow91Yki0o07QRwuxo7lBqkyLvEpeN7o25OTTgoWSZSvE1EQywpYTDjBMQbi3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cTbGTc30PAJxkaqduvqdtsvKRBThQs+tff/zjegJcSY=;
 b=tmFg/0dMwN3lghlKigrbxUyK7VaeJk6mYzJb1mNUF+DnbWtHKaMSfeU2x86WNn50rLu3PS6J6QiOPPFcVEACUAMcgjMrmJgzrB6/odwA7/Q4Craz6s1j5jQJ/qEOrYbZOUQoMCRQ4o6BbnknrllNt714HrGMkmD1OYbyJPxbM53tR/hqsr3k/BY050TJfMW5g1dC7J51VRFJ3EgOQlGRgSGewqzK84pCfR5SyfbfoQSPZK707KG7mF5z1XE79vwAH6dDEjacE3EHc9YmMw8WjSzPWp0RZM3R79/IQYM33627JZPDO+Hw62bjDFgGjNSO4+NzbUx/T09507qE+lYmew==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by CH3PR11MB8518.namprd11.prod.outlook.com (2603:10b6:610:1b8::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7828.23; Thu, 8 Aug
 2024 01:34:10 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.7828.023; Thu, 8 Aug 2024
 01:34:10 +0000
Date: Thu, 8 Aug 2024 09:33:57 +0800
From: Oliver Sang <oliver.sang@intel.com>
To: Jann Horn <jannh@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, Linux Memory Management List
	<linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, "Alexander
 Potapenko" <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Marco Elver <elver@google.com>, Pekka Enberg <penberg@kernel.org>, "Roman
 Gushchin" <roman.gushchin@linux.dev>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>,
	<oliver.sang@intel.com>
Subject: Re: [linux-next:master] [slub] b82c7add4c:
 WARNING:at_mm/slub.c:#slab_free_after_rcu_debug
Message-ID: <ZrQghVSk39s0gb/k@xsang-OptiPlex-9020>
References: <202408071606.258f19a0-oliver.sang@intel.com>
 <CAG48ez1if0dEpL9kdby=5=PcFfnwSP+xn_kKO2aibGpqNNqm6Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG48ez1if0dEpL9kdby=5=PcFfnwSP+xn_kKO2aibGpqNNqm6Q@mail.gmail.com>
X-ClientProxiedBy: SG2P153CA0054.APCP153.PROD.OUTLOOK.COM (2603:1096:4:c6::23)
 To LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|CH3PR11MB8518:EE_
X-MS-Office365-Filtering-Correlation-Id: fa0fd6a4-3525-4971-846f-08dcb74a33ca
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|1800799024|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?UHZSTmdSeCtYZDdxTy92TEphc2dYcWNsK0ZGZDhxMkZLSFBPd01MOGZVeFZZ?=
 =?utf-8?B?OW9DQm1pdUU3M0NuOUxZNHhUYWVDTlQ2bjRoa2c0QzRPakVYUHZxUUFCOTRC?=
 =?utf-8?B?YlErMHVrVXN0S21sL0tab1d2UkI1dFM4MFROUlk4eWpmYlE3N3hIT2NhTStm?=
 =?utf-8?B?N3VjdC9lWkRvY3VRVWs2bmt4akVyVUxBQjFhdURkbDRta3cxZlpENDJyS2xV?=
 =?utf-8?B?aWlYRGVGNE9CWUFIeWV6cUV5WHErdkduTjFaY0tEbWN0cWI2UnVGVk9LVERT?=
 =?utf-8?B?RzFIazA2N1dLNWN5cmtVaW1xK09vbzJPQUtHRVpMdUtBTWh0NWtJbzk3S0Nt?=
 =?utf-8?B?THBKb2RaMzRWd2RJSW03d05TcmNKbHlhMEZRNVNmR2RHWnlOdDJLSEFjV212?=
 =?utf-8?B?bTl2eThwU3BQdlN4UFd4NkFEMU14NHRjSVN5UEM2a1lkN0JTV1pKREFST29E?=
 =?utf-8?B?ZmZ4aW9NaVlSMHYvZ0c4cjEwaGQ1Z1g3WXlUMHM3Vm5WbWhHUHEzTEpvdFBy?=
 =?utf-8?B?d2NGK1RZNmRJVmZBbmd6aE9pQlFOK0FUUG5HeWdaM1h6S1JOYVhEVTdzdkNL?=
 =?utf-8?B?SlYvcmdXUS83NVgrQzFHTTFMczVtQ05xTUJ1N29oZXFFUXU4K2ZSaHQwWGF3?=
 =?utf-8?B?WlZZcDVhM0pnK2pRRXdHSVhaNnE1eDBuczUvU0I3L3dVdFRmUkFJZ2RmMnoy?=
 =?utf-8?B?bEtlZFB2U1A0RGxvTndmVVA1dGhJVWM5aE9MQ05qNU5GRjBERWI1TGZIa2Jn?=
 =?utf-8?B?QU1vZUxnUmh1S3FBY2QrdmhrVlpYWFJ1Yk1hNi9hRlBXMGFnakhka1dzMlhY?=
 =?utf-8?B?NEhvbENtM3M4MUJuZzI3Q0o2T3VKckF1RjlTS1d3TFM3eFNFU3ptRm9XLzVh?=
 =?utf-8?B?b0RzbWRxYVlSOHVDOXl1T3RkOGV0aUEyUWd6YWE0Qm5xQk0wa2xYaWM5cXVH?=
 =?utf-8?B?LzlLdVh5MWpLZ2wwS3I2REhyVjNRZ2NOMzNxenFkeWZJaG5KYXlQcXpoMkVC?=
 =?utf-8?B?YW94VkxqREtPQlBwOWFXcmlUOEZraVcyMlJiTllUWTdCaDIrMDV1eDZkb016?=
 =?utf-8?B?NzVqRitGN0tibGRCZyswdk8reXd5SmNVREd5THBBUmk0SjdEOU14UHNzcFVB?=
 =?utf-8?B?TkVZQ1o4OHJSTitZaWV3NjFEajlRdklWL0xiVjh0YU9ZcnpmcTI2cG0yazF6?=
 =?utf-8?B?QUh5ak9oVXB6L1ltOTZqRTBHSWtjVG1jRFN5eTNQd2NucnBLYVh0N09EMW4v?=
 =?utf-8?B?a3RuM25ONklvaWs2TlBWcUxOSU1zWnZla05FMUtmNTRqMVA2NWVwSXM0RTlF?=
 =?utf-8?B?K3MwcFhHWWVUOXB4dUVFendLVXdaTURvU1VxS3lia0R6QWdseFl0MjVKd3ZZ?=
 =?utf-8?B?dHNISlpQVU5CNXJHQWdkcDM0QmhpTWQ2Ylg1aTAwM2lMQUJaSGF3RG0zVHMr?=
 =?utf-8?B?RGhCdEpwTno1eE81VmY5YWxzOHZ0QVVJQnhHbjFLemtRVWpqNGNXdEphVHhp?=
 =?utf-8?B?ZjgzZHpxSnkyaUFCdkhLVW41TkRyS0tuQzFtdmo2aGlSY2x6SXQ0elpHaVJO?=
 =?utf-8?B?YWZiTTJYSk9IVmYxa3RsTTR1bmJGSFpRNmYwb2JUQktrS1ZBNlJZRFk1dW5n?=
 =?utf-8?B?VS9Gd29jaklGSC9qcEw3M0RYQVUyR0RoVXZKeDM4YjJ3cGsvOU1TZ3VGb2tj?=
 =?utf-8?B?LzVrcU5yZEdVYVpDVVBaeWV6b2Q3VkFXUGNZajBOTksyVkN6S1czdkIycXI4?=
 =?utf-8?Q?4x680isgdsW4bgs7Uk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(1800799024)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?TFJBOHJCTlVGalVlZmt4dlJndkhwS2hZeEh6cllDNk0zbDJ0L3N4MmhDbTRO?=
 =?utf-8?B?UkdWbnI2NE5KT3FUVlVLY3RhaVNuK2p6c0tyeHA4cDJ5bkRwRURnM3ZOdDg5?=
 =?utf-8?B?ZkwvdFBOb2piV0dTdDNRUC9TL2Y2WTJnOXBaMC9IYzFnelorc1VWazFJS3NH?=
 =?utf-8?B?TlVISWYrSzhDcGJlY0tKcXdqTkJGYk1uSlRnVERBZWNTVmdlbkU5cUQ4MHRa?=
 =?utf-8?B?VHVWbC90ckIrVmdKNERSaDRhZ3RXc25Zb2EwWU16dG9xeTJ3RG14aDIwcUtO?=
 =?utf-8?B?VWRpbUZoL09JVXZBME9ieFRIcStQM24zci9yNy9ZMHhpVjdNajVZVDdiYlBM?=
 =?utf-8?B?Ni8yU3VMZzlwdWNqclE0VWZrdHZGWXNZMHU4L3JVcnFFQjY3MmNEWnl0OEx3?=
 =?utf-8?B?Si9YK3pMMG85b3VZWmp1ekp5RzVsby9PdnM1VHJxUU1hT0dtakxRZG1TZTlY?=
 =?utf-8?B?OTgyODhnTTVtYUducUVjT0o0UW1PZEpiL1pCLzd5Z25jWHdscHJBaVNBcEUz?=
 =?utf-8?B?bnUyU2R2a0gveVdCRTVaNnhXZTRWL2FVRlM4R2h6UmdkNkdSUFZQQU13ZDFq?=
 =?utf-8?B?QVg0ZWhNZmRHWkp2SXEwRWhJUjdZY3pEV1pBZU1KNWtZQWltOFNVZ1NMU1NI?=
 =?utf-8?B?RWhLK04zcHAxYWNqZlU3R1F6U0orVmlBVHhXc25DckVMR1M2aXA2cUdIZGl0?=
 =?utf-8?B?NTRxRGQ1MENEWnNDU3dFb0swMERMb0lqNE1lcVliQzdtOFdUTVJoYXE0ZVBs?=
 =?utf-8?B?UXd1bTlpNzZCL3NRaU8zTjFlVU5JUEJ0ZmNQYmMvYTV3K0JBdzBkQTNPYzBs?=
 =?utf-8?B?bFJ2cWNUbWtrd0dmUWc2emxKc1k0d0Q3cjNDRDhuYmYxRUx6eGpaRGlxWHFJ?=
 =?utf-8?B?aU1Bd25xa3pVWktPQ2k1RXpzenc0OGtGWGMvWmNnQ3EwNzJncFlLUCtGYWdl?=
 =?utf-8?B?dXdrYjdhcXJOZWZNalpvK2tDVVloR2dCb0c5bE9YeTBpdTZjenBMdXg3RWtE?=
 =?utf-8?B?aVVvQk1OcDhWOVg3dDFKVzNscUVnRloya3VqTzhiVUU2cG9wWTl6Yis2RWUw?=
 =?utf-8?B?bzQ3VCsrL0JNV2ttZ25MK0dHdmVSNDdTZHVHUTZTblE2OUk2SU15SGlVVGlL?=
 =?utf-8?B?UjBvQWV2dWhOM3BIYm5VbDdLN1dVY29GQkNtQXBIcVJEakhGWFEvWkpYbHd1?=
 =?utf-8?B?b21DaWNYVU9KR2hTQnBodHpGb3BYSkRqSzI3azh4YVlST3FpS01BU1JKY05h?=
 =?utf-8?B?aVJUckRFVnJFdWlYcENBRzd6VlZzWE9QYzVLT3R2NVNoYUQwZ3BUTmFJVS9t?=
 =?utf-8?B?V1ZHYWNFcm5jT05NamVYZyt3SFZlcW1LNFhyUFRCN1kzdWZ4NXl3Um9lU2hz?=
 =?utf-8?B?MzRHSXVVazZWVForOTVFTFVrWEwrVnkwWnlaMnNTSjBqR0Z2NkVlNlJTTldQ?=
 =?utf-8?B?VFZEVnFYbElZS2xwU0ZiN2w5ZHE1NDc5SG5ZR0lOcFZwN1VpRDlPSUtURk95?=
 =?utf-8?B?R3l6azMwVDl6Zy9Vd0toRnFpME14MFN2K2pLZnJRVWpML3RacGsrejRpcHI1?=
 =?utf-8?B?RUlZZXlUaEM2ZXVaQzJRajBZQVRaNTA1Q09ucng1TUd4VU9IOVJrRlZpN3RZ?=
 =?utf-8?B?eVkyNk9jcitlS0Z4ZTV4SU1rMlRJR1VlWktzT01ORC9RRVFDRGZVUkV1ZmpQ?=
 =?utf-8?B?eWtTZGJ1VzAzWjFWQVJLbnJXbHU5ZXJvLzFmcjdoQzhSR1lrR1Qzdk0rc1lO?=
 =?utf-8?B?L2RKdHZiSkV0M2ZTczlZTFlrRmhuQ1NTdmwwbU9rRkNoaFZzaFhZdzJkVCtu?=
 =?utf-8?B?UWk3V0YvcDBtaWc1M1ZkeGR0STYxbXpVNmlac0lSSlVRb3paZk9HRm8xS0xh?=
 =?utf-8?B?bHNnTzdUVjloc243Y0tYNnVGbkFRNVZQZEplaVhYVWQxV204bkVINk15S1Zx?=
 =?utf-8?B?YjNHaHpKYS9RTFFVeEtJTUtzNnlhS0NrS3ZoZFJ4WnhXdlNITmpodXNESUNJ?=
 =?utf-8?B?UzRhQ1pIUm1lbUNCZkRPQUthTFBGUDlMdmt1aVA2SkcydFdQTmhBMnlDVmVF?=
 =?utf-8?B?akdNaUxpZjYvN05mTVVJVTY4NEorb1pmNzhvb3NxTmsyMnhKN3prZmZ3N0tK?=
 =?utf-8?B?Z1JheDVoS3NTakR3SlRLU0luWGQ4RHpTeTZBVTJ2SUFjWVlrUzBKMVhtSWtk?=
 =?utf-8?B?VUE9PQ==?=
X-MS-Exchange-CrossTenant-Network-Message-Id: fa0fd6a4-3525-4971-846f-08dcb74a33ca
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Aug 2024 01:34:10.5218
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: tR0bNO/W/tw/272jd553dkkJ9Uc2YCQJemK+oN1Ooich1m4ENBlFCOw6c9bSGxK8uR2OKiX3Wbppi7E0SoteHg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR11MB8518
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="NRWGq3F/";       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 192.198.163.12 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

On Wed, Aug 07, 2024 at 02:54:52PM +0200, Jann Horn wrote:
> Hi!
>=20
> On Wed, Aug 7, 2024 at 10:42=E2=80=AFAM kernel test robot <oliver.sang@in=
tel.com> wrote:
> > hi, Jann Horn,
> >
> > as you educated me last time, I know this b82c7add4c is v5:)
> > the CONFIG_SLUB_RCU_DEBUG is really enabled, and we saw lots of WARNING=
 in dmesg
> > https://download.01.org/0day-ci/archive/20240807/202408071606.258f19a0-=
oliver.sang@intel.com/dmesg.xz
> >
> > not sure if it's expected? below report (parsed one of WARNING) just FY=
I.
>=20
> Thanks a lot, and sorry that my series is creating so much work for you..=
.

not at all! our team's work is testing linux kernel and helping developers
regarding with increasing kernel code quality.

>=20
> Okay, all these warnings at mm/slub.c:4550 are for the "if
> (WARN_ON(is_kfence_address(rcu_head)))" check, which was wrong up to
> v5 and fixed in v6. syzbot had also encountered that bug...

thanks a lot for information!

>=20
> Thanks for letting me know, and have a nice day!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZrQghVSk39s0gb/k%40xsang-OptiPlex-9020.
