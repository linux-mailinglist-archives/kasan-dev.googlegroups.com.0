Return-Path: <kasan-dev+bncBD2KV7O4UQOBB3EK77EAMGQETQBIXHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 89C0BC76E48
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Nov 2025 02:50:38 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-bd74e95f05asf1042025a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 17:50:38 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763689836; x=1764294636; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NtehyOgEKe3Fxfdpy1DR3dC3a2Qzf3wVWom6tQL11Ok=;
        b=IGkHm2x/D0tuFQY2ivdNR1xK2IsZUgP0DCCxEWh5pY85QwkkEU0yHfNdOqO5RUv2l1
         fjo5R5uo0VYcsM7fcPDK4Rd6mypYj0WC1kKwLoj8qIcLp2e5PyYrKSLB1vqJO9YYjl0k
         oZFV+yZghqbMkxgtoBxjZRbi3HmcF1vpRY9ko0OwoxMe2TY0QQEjB9R2HzoEcVOfn0Kf
         z9iMjJweeKPDvC9G4iYe2Ng1ojgThex1p543DflYzvPo0+Uxa8idWlBPG0S+74zkXHAw
         qD61QryXfFnxFwkynlYaln2+2Skh7fRkGji2i4E6tR4YlcGbyBbCp1saYyActSdIF5wG
         Naig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763689836; x=1764294636;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=NtehyOgEKe3Fxfdpy1DR3dC3a2Qzf3wVWom6tQL11Ok=;
        b=nS25srmFzb1yT3Y7E5kjLilxBIzRopwq+CE2PnLIFR0gMcrCms/ruFtf0HAWvOzrYC
         ILODRnraf1RrgwwP/3UONz8fv+Vb46E7i6S9QtQei+Ydy6rNzKiX7Z9TembYYJyeKbvu
         UAxNPvHXZdVERt85tmqaXLqNGbmqtJTKL/gKX/PzE/PSE9H0PmBwmoqy5jn6/jt+Elrz
         zR18ARIpfNCVEqIl6lp9HGVYtHVxwujWcw1ErLhl3t+aGVAqgcvxBKjIW/s69bgP5whd
         dBUsa/ME/uaCJmZSv9XUFkFGjXUzbxhQdaQBxxNqM13VbYtVJPOuMANY9nnMiT7TJBNG
         vH0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCXSiG7tVro2Wum+IwoKtGE6NSD/4SBxHz/ufXBkXZ4xFsdBeSNjDT45Qnp6dLuxXCBJXh6VAg==@lfdr.de
X-Gm-Message-State: AOJu0Yy6UYbzx+Hq59ge9R4HY9KVZRdwAJ25hhxxLnLOt3WHfzHYpu8I
	uI5o37FG+lwmnfjMuNsbZftY08yYWKVpaAFI+gVzkhTNPBKfkahyur6O
X-Google-Smtp-Source: AGHT+IGTgX7X3gRoBi5lm8qUApZw4nl8K78vjJBZ/TVfb4m8+Xb0B+WVBs8e3CwJ8SQ256/RJGrgcQ==
X-Received: by 2002:a17:90b:5286:b0:343:3898:e7c7 with SMTP id 98e67ed59e1d1-34733258d8cmr721349a91.12.1763689836535;
        Thu, 20 Nov 2025 17:50:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZlavM5GQWoH9wjGuoxXZrciDV8GMUIaHVL3YMHljZR1w=="
Received: by 2002:a17:90a:e581:b0:341:6618:be9d with SMTP id
 98e67ed59e1d1-34727d8103als554003a91.1.-pod-prod-00-us; Thu, 20 Nov 2025
 17:50:35 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVvfYYIC6few2rvqoFryzGKSDZfjBjqVJl65gN78RSOTG2qnN0vYwYYuZkOefKcGXrt26OckFp1w20=@googlegroups.com
X-Received: by 2002:a17:90b:3806:b0:340:f009:ca99 with SMTP id 98e67ed59e1d1-34732fff7ecmr930413a91.0.1763689835029;
        Thu, 20 Nov 2025 17:50:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763689834; cv=fail;
        d=google.com; s=arc-20240605;
        b=LToTnreoOfyOgeLB1kvTxzPcZR/4+uPg7qQUkqUMys5pnOBLk6MRgR5bdS4tWpbkXm
         9z4ZP4k2ZbjgRGITGCDLmR0Nkg2CchGcSNgOWJ+yzvuFbTpussY8dtfuFGW5OtepdvyL
         37T8RHY/3aOTDT06bLpYAXVt+zngGYwFucIjyNaqlxe5ZPvkCtFQbbrw17y30AS38J16
         BNiXxR9KER9pmETCOxgkn8qifwXAnzoKJQIXC+QqCeZMKDtO7Wusn3NZ97KSv+yF93fp
         CV0JFYkDQPNVgZZf8zyguQYVOo0uoPrej87LhmY4QQaO69rIHZwZCofH+gXUpjbzQL90
         bISg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2XEMmC1PmNFZvRL63J8SqXugtp0MXj4rzcpjgF+Tc24=;
        fh=wHZ7HDC7ghSLpp4HSV5mBifVICTHmf/Q0JS9njRNTUM=;
        b=SUn8FgkNiSFfvLjXGJwUJ8IEisLu7mQ4T0tc4OwwMJuG/g0otNIArZByYL9iKZKWNb
         rt970SM1NHNP/WrJZkh6u23rF2YWOIcYAOfYbJBYT4lsW4jGyhrHwazhwV+RHNldzG0d
         l0oE0zjon5KinHM9ul60Ho5hDyjUq9qyklyzWDVzs/vjLIdRG4exZkeBaGuBElW+sN5D
         5dE2y1lXQQyqwRsxTWjrw0XRIHrWn2AiQSrxvqWekHq8l6n7I2qLu1zQcDNci9cCT4KV
         14U/KJ/LZmjBGgSm5nEtRHJyooSuOtNN5B8W61IqH2+ywfcw0JSRQ2AXUVsF87R/Jy5l
         W00Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=M+hS09yx;
       arc=fail (signature failed);
       spf=pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-345af1ff3e2si90165a91.1.2025.11.20.17.50.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 20 Nov 2025 17:50:34 -0800 (PST)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: DQTA9nooQciWdCG4bTdWUg==
X-CSE-MsgGUID: psaBQ74WTPyEmmOixj9ZEQ==
X-IronPort-AV: E=McAfee;i="6800,10657,11619"; a="77246225"
X-IronPort-AV: E=Sophos;i="6.20,214,1758610800"; 
   d="scan'208";a="77246225"
Received: from orviesa010.jf.intel.com ([10.64.159.150])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Nov 2025 17:50:33 -0800
X-CSE-ConnectionGUID: extCmX48RS2Ykw2vLahVwg==
X-CSE-MsgGUID: RmI7IUhtSl6ButG5j2YVDQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.20,214,1758610800"; 
   d="scan'208";a="190834867"
Received: from orsmsx902.amr.corp.intel.com ([10.22.229.24])
  by orviesa010.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Nov 2025 17:50:33 -0800
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX902.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27; Thu, 20 Nov 2025 17:50:32 -0800
Received: from ORSEDG903.ED.cps.intel.com (10.7.248.13) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27 via Frontend Transport; Thu, 20 Nov 2025 17:50:32 -0800
Received: from CY3PR05CU001.outbound.protection.outlook.com (40.93.201.46) by
 edgegateway.intel.com (134.134.137.113) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27; Thu, 20 Nov 2025 17:50:32 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=C8Pu9e4ED464BK2C0y3sPqRVEm1nJOnjsChKlvigcummJegfUwfWS1gYSEuGYQmPSiYVSmAW/DuRhSZuQljOn2pf/2Tg/O7HQLucconCmqkySFf1+KcvtSsRvKORkp8S2ue6srZb5ujgy3iqLVhQ1kD6Q0M+raTNsDHSb0LUCsrmSWgFKRPyKAAfe8HI7A0SsHxhDkOnQSPY4J381Ld9vM+9u4mSTaVwlDn0ukkHyIOdbHvze/S/9E7dyAk46mXnp9xEeNi1uwwRtxY+aNQCQb6uGu4cZnMBMgfjiZIxkzqJmuU2jRkx8xiSARBLiyasPnMP3chaOQzr31+TbORZhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2XEMmC1PmNFZvRL63J8SqXugtp0MXj4rzcpjgF+Tc24=;
 b=pVogoSpTLl4zwk2jGkOcLVAcP4yrL9yubOfmoLWuYOIjNsIwqdRG0sQ3xLjm8Vo5uK3j1nokUvmfvLxP7FFq8yVdv0G4FNNKwctUalzYLxmOJfG/VUtknWCzfzDAuZAnwzL9ZYPP7q7Uu1OBxCB2PRoi39VXjt6evCDgazdvYpwhPKDqVRJ1EwBWTfGe5ZNzDnO5amx8of3fGDTzSx1QiwxSys971IBA1BNKr3Hr3enX8woUKt36Txr4zaln430goarrEMyLJlKd8//D6UhMHiQRl4a1L/01QoLD+vtkT0kg3PWh21Xuq2M6Qtpu1fwg83hxt4oJ17JpmmAmsXc9Aw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by CH3PR11MB7371.namprd11.prod.outlook.com (2603:10b6:610:151::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9343.10; Fri, 21 Nov
 2025 01:50:30 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.9343.011; Fri, 21 Nov 2025
 01:50:29 +0000
Date: Fri, 21 Nov 2025 09:50:08 +0800
From: Oliver Sang <oliver.sang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Christoph Hellwig <hch@lst.de>,
	<oe-lkp@lists.linux.dev>, <lkp@intel.com>, <linux-mm@kvack.org>, "Alexander
 Potapenko" <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>,
	<oliver.sang@intel.com>
Subject: Re: [linux-next:master] [mempool] 022e94e2c3:
 BUG:KASAN:double-free_in_mempool_free
Message-ID: <aR/FUAPSZHuKr6Zn@xsang-OptiPlex-9020>
References: <202511201309.55538605-lkp@intel.com>
 <20251120072726.GA31171@lst.de>
 <9e066a2f-28fd-4da7-bca8-c10f7b58f811@gmail.com>
 <7ffb1908-464a-4158-8712-7735100ae630@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7ffb1908-464a-4158-8712-7735100ae630@suse.cz>
X-ClientProxiedBy: TPYP295CA0035.TWNP295.PROD.OUTLOOK.COM (2603:1096:7d0:7::7)
 To LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|CH3PR11MB7371:EE_
X-MS-Office365-Filtering-Correlation-Id: 1765a387-798e-4f1d-151a-08de28a052ef
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?QafFDs0gBgKdpX751LzEanX492xVLPu+zS/CHTKcYEWmtV9j+FPSnnwmVHpn?=
 =?us-ascii?Q?UltcKKnO4aBhq7AZD+hj/op7bLCxkdbfhHn8vTG2P0/6ZLXHkA4TShM9DhuQ?=
 =?us-ascii?Q?7F73bp2tIival9pjea++L/qyN4SMG/qZYnvtNBClF9VT073Bb9dg19nEKVvo?=
 =?us-ascii?Q?tKS4bk4Umrmmif2bNrbJEDVFKhYYoJ3KXixpyP/BiASFcmnUd/NANLZkHOCu?=
 =?us-ascii?Q?ufj49k9B3utDfwIBtsCnZSrp7QfeBomfbWY0PaQdtNv9W9XNO+cPRXfI/24H?=
 =?us-ascii?Q?SAcpccF3YBl3Z4WbToaMBrNxUu+LG+WR4gh2elG8sRmYDuKy8akTorA8bQ9U?=
 =?us-ascii?Q?SjUQdWU+DqnFk4b3h38sYh+pntCirbbn5QwRMnk/x4HEkUw+fnlnBZ9m9tkV?=
 =?us-ascii?Q?4hC74l1C3Vu06oiaoqPvGXDF3k5a9FLpQxBL48YwOOQjtLe9zddLFKKdrI/2?=
 =?us-ascii?Q?KQE+olWmlbNe8lsfRzA2O4wll++tlfXbzIcKLNOVfdmGKAVCiaGRUOGBosQB?=
 =?us-ascii?Q?PWShCErzRk5QJxOABR7DdNy+IPUzHquyc1JOIsKxlAi8LTroLzSbj7QVTGaT?=
 =?us-ascii?Q?TzRKtKQevLjPov5dYMCkITJJQGSm+Oxae8j2py3ngTj0Bu7JRTSalH5ttgsO?=
 =?us-ascii?Q?lXwrJX1Kr1+0TOCo2Iy7hJainu7YSfMqFhDEVImptfUQxL+/S8sC6sKE7cO2?=
 =?us-ascii?Q?4SW96lWcyZR5DsDC67+15Fq8H5YqQ1fRfBefcKDX3UXuBjLTtc/tFCVrZUvn?=
 =?us-ascii?Q?93SW29TdPBUuYe+ZIgKADn1Y8YI9Ie5wwqI0BIRk4DRdPQhqwHEj2/MXTCdj?=
 =?us-ascii?Q?Etrg8tNVRMdPy4WvW17vLM2MvNINXsnkps8w+cuMso8sCdSaSPrhr+q8MTf0?=
 =?us-ascii?Q?TPen+43lpOMGHnn1e89djt6wlyT+bL2AaMLhhJ7ICNMdulq189TXK/Vsv8TU?=
 =?us-ascii?Q?aiN+HlfxCycBQ8rEvFTvkuEWqCB4O+AxTUORFtqZXdxQEsM2TOW0glDjUph1?=
 =?us-ascii?Q?4qfJITR0wkUxfIENvUbElLVmyeDVnyB69sPz7PYYGD7P75jM3e52EmumlJkz?=
 =?us-ascii?Q?GiRo8ic+r5W7lPwz3yxHuVkvODKMBviDiAk0v6QNFCGZ7cHnvnS7gi1tzH+w?=
 =?us-ascii?Q?pZeCybV6owVzV7u1T4Ft9vp9mhKqdcYtw/ZRs0KlgUp0CCTqnKYSo7FsfBN2?=
 =?us-ascii?Q?72arjATp/xys307/6vK35RS6YusduUXPrFOyHBa6kKAgzXpYam0+smxEuISL?=
 =?us-ascii?Q?fFhOdGmItruGiuLjmIHm4S9A9aK8uxzQtpwr/lkjmoI3DodOVB5U3bSxI5cb?=
 =?us-ascii?Q?pqiaOQGpw3CHrKscy0U5URmBNE071u+vR5p8SLnXHWk56OyesBZzP7TdoCTG?=
 =?us-ascii?Q?kIs1Y38n5OEK4+Bsp4NFDIJLatl/YHwY/2WtkRq12JTHe+Lrz5oEVmZJfNmC?=
 =?us-ascii?Q?gHGj5hK4SdUh7QNpz19TFD8HYKbppgEb?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?rwXeZC8TwEQk20KOZZk1jieA+EcZ2qyEBy9eKEeJ7k5XAkDl7qP2oJ3Va8iI?=
 =?us-ascii?Q?pADFG4IQtpwr1M4u800I9YJ4PotWmBB0bFus/jiUgvGDveMPSWZmnQZFSw2K?=
 =?us-ascii?Q?GhX9VywySAS4uAzJnwEsdTGhOPA0+pPlvcY7E8B4sVsy+CiB1J2/hhE7Hmx1?=
 =?us-ascii?Q?KC/mSPfLzXTcFw38X7FHU1E0eWvcmkfPYgtdNadH6Ykt1I5tQQXE8net1mgB?=
 =?us-ascii?Q?rtLnQZ3v4C439st7Z1B69dZVmEjI+OrsTBgvRuf9TRWVWzp41xgrQ2cMefBx?=
 =?us-ascii?Q?470N0mFY8y9BpMYT7vb/2zW7YmQaMLoEFyFYOysk7btNDCTz6YPZW3afGGfB?=
 =?us-ascii?Q?3/DmBITuPWaBoWSQT7PMJJ/c4QYn++Vx5rWOqBg0TtvUdZdZhlRvNt6nh45Q?=
 =?us-ascii?Q?fmb6a6lI2p19fU56qFIaBGOYoNEmwE3ayO2/57JU7k3MTT4Q1tP7jGz9eeBD?=
 =?us-ascii?Q?+Aj2eQO/k4sFHz6hnMMIgEw/24faHSVVKmcIyEzgUyblZ8nQvUPV4jxF6N/1?=
 =?us-ascii?Q?1gPJsGBVM+pa/UJN31xhbpb3sTpKpzOLWW7BFjOZIewCMw39LjkOgtfgeYWA?=
 =?us-ascii?Q?l76dMesbmqnCCYTTbUfI+nG/lD1CIewFCV1Hy4fIZ1oJnBu2A+/44kAkenHX?=
 =?us-ascii?Q?Tad/QkQxtJKGIJuku3fYSe7ArIaR8fsYpTrBxWnoMDADmG2zrt7u8qXXEFsQ?=
 =?us-ascii?Q?Z1KUd5pYC02KsUjalClUBgccSceMAkL7qepxtox3OnqfVeZULM0xDkDaj5vN?=
 =?us-ascii?Q?vMtlYNgNmmt1Stdq8wvqigKbt4krIO+CyJkr/hM7hz/h0CXjAM4a+/B/oQxx?=
 =?us-ascii?Q?Qv1/kJrqKlRwV3JMb5gqgFqXH9qeQXi8qrqiQLp8qMz31B48xcxRXChkUGIv?=
 =?us-ascii?Q?dw9AXFTvFDcEV8eqA2R0XKPIkdB3/bJrGYD4bbGLfz1iQyO1YYwUd9Lzp6nQ?=
 =?us-ascii?Q?bbFWMjAwo5dwcr3NpCcOKuNelsAk/StZHkWQjV5DpQgVMydoDHnEwYu/qF++?=
 =?us-ascii?Q?l4CP3Uet2rcXcKsK1PRyrqcZfgnqLJxyyvU9bjgpE3g1g8DDNHV4K8wyIpf4?=
 =?us-ascii?Q?LoB9qb1vNj8+0rhUswQnP84XN4tWr6wO/x3FS637lQFV1WZSeVi+tbbYNmO4?=
 =?us-ascii?Q?306aKbrb5xNlLO8Lmkvpo4VgxPgbgy1iRKD7EuH07exklBl0ak4fxTRTHkCh?=
 =?us-ascii?Q?jQsu8OSGt8F9A1zbht2vyPnM/mZVBD1ZLhDjuMoY2PSml056O9maOdKLUY6Q?=
 =?us-ascii?Q?NCP60oDfS1qybE+i/t/CeJI9mx6vGCMIZPLudjM1uudqbIyvN/uVPlkzlipU?=
 =?us-ascii?Q?6qLArncM3Gg3GnTw/5YPV1549AHOdfBcoQWck7CGP3+Ff4YeMO8EY0zMyFdE?=
 =?us-ascii?Q?uvi1Ie43vzJF28SWMRPqHErbaChSYI0KSq0KJp32cSwv+MnGZWXoUYKa7YGF?=
 =?us-ascii?Q?oMdP1fk60ShAZOpdsFRlOEC0SmCxv1/tWH5NBny1pxS3pF+Hh6TJWhRzjNT+?=
 =?us-ascii?Q?/otnMNtrfhQXNAC9By+JwJrJxEt81uPIr5mr4DAJR4qS8+jbZjLFSwPtkkJ7?=
 =?us-ascii?Q?IB6JIm2aru5VxtOhgX3eAqOe/8cEGjcHilmJOkGNC1Jz99y4S0smCDPZvnAW?=
 =?us-ascii?Q?Vw=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 1765a387-798e-4f1d-151a-08de28a052ef
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Nov 2025 01:50:28.0260
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: VOdGCbQaN5p+DPMVrqf9q/KPylh2PcrqitieXhop8RtafbzIPXhUcepM4TselEuAnAkQxIYwqhNw2BU/uPfUIw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR11MB7371
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=M+hS09yx;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 198.175.65.12 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

hi, all,

On Thu, Nov 20, 2025 at 01:58:02PM +0100, Vlastimil Babka wrote:
> On 11/20/25 12:17, Andrey Ryabinin wrote:
> > 
> > 
> > On 11/20/25 8:27 AM, Christoph Hellwig wrote:
> >> Maybe I'm misunderstanding the trace, but AFAICS this comes from
> >> the KASAN kunit test that injects a double free, and the trace
> >> shows that KASAN indeed detected the double free and everything is
> >> fine.  Or did I misunderstand the report?
> >> 
> > 
> > Right, the report comes from the test, so it's expected behavior.
> 
> I assume the bot was filtering those, but the changed stacktrace (now
> including the new mempool_free_bulk()) now looks new and the filter needs
> updating?

thanks a lot for information! and sorry for false positive.

we will check the kunit test final results in the future.
kernel test robot doesn't have filter so far. we will consider how to improve
this. thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aR/FUAPSZHuKr6Zn%40xsang-OptiPlex-9020.
