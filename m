Return-Path: <kasan-dev+bncBCMMDDFSWYCBBTVCVS6QMGQEFBCEKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A676A30688
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 09:58:56 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-471aa567902sf1291111cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 00:58:56 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739264335; x=1739869135; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2YblAIjU7OFhltwYsFP6nXQWg13q5JoAzzxQumZQK4Q=;
        b=LM4mqoi+GVyZZzCSYdYMKrsTB10hQCzdNhk4WaSkGz4PII8KImQxBJL4Hg2mp64qzq
         FIDb4z5ybZKTtE5daEoRYJ29+VSk54eirPXUb73BX/1bzn6Z3wjQ7A6LwmARJXm6aTNV
         Lh2h9LwX8uvMkWAXXXMv4/R2iTkrrRywionF1dAzcNQJxxr8FXMXVFV2vXE3uzYA0K9p
         /MnUFqka2JV+Ay98EGoPFPFfDi6XG+L4+43xAFqb/MgXvbhWbw1e4OXtyi8vlX5/4WMP
         v/1cf68xxoFynKBoA2o0MhE0yKvhmQUYSwpfK7kYQ3O9PcltDRmIslZANek/87I35qJq
         JZsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739264335; x=1739869135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2YblAIjU7OFhltwYsFP6nXQWg13q5JoAzzxQumZQK4Q=;
        b=NLfMVxMbiI0LvOKYupIYz1L2M+NlMi9RbybVIjL0swtbHGlpVaa+zDvdsD/3GRuyqQ
         AZkVnFPAj+f1AHXJr4ixVEq/bZvyKlDtnByCjHeB5++VUHMxTTWqVtJ1DKqv9LW5wZcK
         mdDIMjvNvdzcH122rhhAqS54unsVFH5XvWPUNq9aWYNEnDDcUDYKla375CuCKPWo9yVx
         01uH3RnT7+/3930pq39yVsCNlT9W49Wicyg6uF6UpvitVTB5o8h7cpqk+2tqrLHMWoTx
         QGcA1C/RkyIhHaecu3wk4tYidMzlf+x6YkUIDMojaHHKfw1bMpsuSsaXR2wDcHgqWAGn
         IR2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURqZ3rCuqtNfz0A23eu/pi8fwpKN6NOLJR8XxJRZEvMpIKwl9WoXxy11vmQfo4dZ/gpQPueA==@lfdr.de
X-Gm-Message-State: AOJu0YyQZtj/qegfUvnjYX74+neni6vlxzGmUrQLUMQdSxZlbBGrxJnM
	ycZVIN0oSfWrrFMR8Zv59FYSHoBkWqpPDT8A49hOofXE1e/qi3rk
X-Google-Smtp-Source: AGHT+IHJS8rkUqRWnKnVSzpqm7UdMQMCKNJILWZxs4rU2rprv7sxb/gZL6gIFaVz+k/0cTdZLvNuWA==
X-Received: by 2002:a05:622a:1a99:b0:471:a836:8e90 with SMTP id d75a77b69052e-471a8369119mr6215481cf.29.1739264334836;
        Tue, 11 Feb 2025 00:58:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4085:0:b0:46d:dee4:45d6 with SMTP id d75a77b69052e-47167d34f73ls37713131cf.2.-pod-prod-03-us;
 Tue, 11 Feb 2025 00:58:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWVMzJGBfuPjoWtIuUuiAS9yaTphT2sLzdsGVNW4kZLrCagmMf1sSYkSEkZEVXa/K8jeK6wMS9RWMs=@googlegroups.com
X-Received: by 2002:a05:622a:4118:b0:467:6c95:19e5 with SMTP id d75a77b69052e-471679a8e2amr219362871cf.8.1739264333932;
        Tue, 11 Feb 2025 00:58:53 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.14])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47153b2ce99si5296071cf.4.2025.02.11.00.58.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 11 Feb 2025 00:58:53 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.14 as permitted sender) client-ip=192.198.163.14;
X-CSE-ConnectionGUID: OSl1PIQSRXO6lqb/KSjzQw==
X-CSE-MsgGUID: wlucugxjS8GFr7jhaDtwbA==
X-IronPort-AV: E=McAfee;i="6700,10204,11341"; a="40141424"
X-IronPort-AV: E=Sophos;i="6.13,277,1732608000"; 
   d="scan'208";a="40141424"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by fmvoesa108.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2025 00:58:52 -0800
X-CSE-ConnectionGUID: LLa/JqOiQSCgt6re7goI3g==
X-CSE-MsgGUID: xvwJ7ZchTM+SgdHi7xASzQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="112913685"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orviesa007.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 11 Feb 2025 00:58:52 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Tue, 11 Feb 2025 00:58:51 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Tue, 11 Feb 2025 00:58:51 -0800
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.174)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Tue, 11 Feb 2025 00:58:51 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=I5g98T9ipxmgYKDW/OWKIt6Z2e4g04IuhHonKY4rwrBQKOv8GvATvo3qJHDli0etmuWpTgaYetwHfyz10QcUwoGWQ+i+XO27Myniza0fbo3XRCsQQW6ICouEXGRQ9Kmtn1m41QJK7e3WtMCjKmU1IHnusFY6CZJzxyJuPuZNxpc84cvBEJ97lA3y8cyxsEnZsmsh9ldgMGfPNTTNh0MRxKgYNumfT0UwiJKx/0JojrCFevTqFhs8xhfZhpsEDsJnw4mnsJecDU0Z6DleSDqTTSenySehM+97wz6x5HdM02i1i2EAWXQr+wylLsP4vmHU0LLBVzlKuIP7PWR2KXK75w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=W7QgXS8TS+VSf9wXC59Mcq0LhkK8u2Z6sU+hdjDQ2gM=;
 b=IYMzHIlGeRIRU527vpi21PBEvVdFIFFpPh36tkTZM9P/ZjOKk8DDQccjM5aEyt+PVY42V8QbnrgWE0R2tciqKO7ZUkfKSO0Hi928Oe87CKewPJHwPUV7QRwumFcKHmA+/FG9hWG5Ur5FFFShCIvAYzx2PeFVlPtKRRj620KRmChkPy3oYSkXaHzSdK3utYLYU2+YhFfZDAwFqYTstlSMFr5x+1PcVWDDWtCNomaWx2p0q48THgpFXqWJn45jhqFc+K8bBraBQysJ3d48NaIqfcjsNfpasK8Uj1E5RMy7JZxmXRogpdXJhleTizylmyL5PTTwBut37kQ+bbt/+JWXpQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by CY8PR11MB7242.namprd11.prod.outlook.com (2603:10b6:930:95::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8422.16; Tue, 11 Feb
 2025 08:58:49 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8422.015; Tue, 11 Feb 2025
 08:58:49 +0000
Date: Tue, 11 Feb 2025 09:58:22 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Samuel Holland <samuel.holland@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, <linux-riscv@lists.infradead.org>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	<kasan-dev@googlegroups.com>, <llvm@lists.linux.dev>, Catalin Marinas
	<catalin.marinas@arm.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon
	<will@kernel.org>, Evgenii Stepanov <eugenis@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v2 1/9] kasan: sw_tags: Use arithmetic shift for shadow
 computation
Message-ID: <lrlnvcxofcnsm5rou3iwbawyfwtz6mx4gn6eflpm4srhjj37kb@pwsozjgdyxfu>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-2-samuel.holland@sifive.com>
 <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
 <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl>
 <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
 <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com>
X-ClientProxiedBy: DUZPR01CA0070.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:3c2::9) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|CY8PR11MB7242:EE_
X-MS-Office365-Filtering-Correlation-Id: 4342a5f0-910f-48de-5419-08dd4a7a4cb4
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|27256017;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?bUFQZ3ROY2RiTm0xck1GbmkxZ3Nsc0x6bC91c2lON2JzVFpiek5heHFVeTZ2?=
 =?utf-8?B?anNGQUxlU29icXEvUTBCU3ZWc3Z3T2lOc2dDUjF4YzJ2OGtaZSttbXcxYVYy?=
 =?utf-8?B?OGd3azNVVUFUWjYvdXM1RGluS0p1ckZuM0ljSjhmV0hFcmRDalZjWVp4K2Zh?=
 =?utf-8?B?OUd3RTlOS2VySGhRZkpwRFpzMFdCNGxxSmE2YWZFdkdMK2xtK0xFNGg3Zm5Q?=
 =?utf-8?B?NVpmZHVvV1RSSkYyaTVGdENsYngyYjF4VHpEQlNMeFJzcURueW5WS0k3WGtw?=
 =?utf-8?B?K2RERFdOSHNKYUlsZFRjWWErZnlSN2FlRWIrSURzRmM3QmxQVXNTcDRnZk9x?=
 =?utf-8?B?amFlNmEwN3U4czhERkxsVEdya2c1a0ZXWklRUHdYT0I1bDVZOTJ5dHVKWWpi?=
 =?utf-8?B?RkxKcjlmQzZZOVZNelV5S0o3UlR5ZldUT3NqaXU5Skx3YkRsa215OHRJM3RO?=
 =?utf-8?B?K2htd3ZOTUN2Sk85cjJSMkJPRzVtSWJ6T1hLTEEvMTYxdW1OM2gvcHB3Ni9T?=
 =?utf-8?B?R2pnM0E3SXpwVFBxN2hJT0FrVDlmcERtWEp0UmlnZHpmVExFOXZDNTFITFd2?=
 =?utf-8?B?N29vMWJ3bjBEbUhZYUpEUlBVTHJzQ1BBS1ArVFhuS01zdVhOSGhhcDEyaHBa?=
 =?utf-8?B?MDU5L0VFVE4vbGpqTStKakNZTEQvMld6eEMyT0VQWG1JbWxFUGpmOHA5U1Bs?=
 =?utf-8?B?YkpFMXlsWFgya3dIR1ZTWEZ3VmNudFpzd2w2cHZUQld5ZmRrRkZFeW84YWZ5?=
 =?utf-8?B?US9URkNqOUZJM01MbmFQOG9UVlV0NGp2Ui9CNWpGcTh6Zk9jVzVrdkpkdkdK?=
 =?utf-8?B?L2dHdVdRM0JoZVFlNENTVkJJRThaT1Eyb200d0xEMS9mWFNiM2Z3Rm1GQ0g3?=
 =?utf-8?B?cGU3WE5peHNteEJYTyt0elVneHJZeTZhVTRXaElqK1hqZllKUWtrM2ZzNEJ1?=
 =?utf-8?B?ZElHREU5SmRMR1RlRkNvY21XYXRkVVhZaU1GTitONWl5SHh1Szg0Y0lJNFJU?=
 =?utf-8?B?LzRwTjNlT0hXTEdTajR0K2NkV2dqTUxINmpEbm5XNmpQc3VPVXN5T1JFUU84?=
 =?utf-8?B?RWx5UTJ3alRhdkhod0hXMVIxa2J6bkNxNlRnNXM2NmQyV1ZnYjc2S21FbnRw?=
 =?utf-8?B?K21tMzhZZ2h1dzBqQUJJOWVocjk2WEdkWTRQdmhjOTVaODJJV3pQZmFzWk0z?=
 =?utf-8?B?czh4eko0UXZPaU1zTU92NHZEWkJneG1FdjZ6T3pFVnZ6czdrNnBtMy9CeDls?=
 =?utf-8?B?cG5tQTdJK29UM09XOTk0VjNzTUYxLzFaMm82M21ydXl1SVlPYjc4ZFFxWGxX?=
 =?utf-8?B?eWFkUGIzWnR6cFJmbnRnQnZ1U01BSnUvMFB6NG5UMVZMVExTYjQ1UXZ1ZXc4?=
 =?utf-8?B?OS9kbmFuZ1g0RHJUeFBqNEJobTM1QnViZFBkZ2lvbytlVUxUVnlzWXBSMU5v?=
 =?utf-8?B?bzgzZWVuRHQydXk4ejF5N3lEcjVKdHpFWTVmTTNQN1I2NjhFLzdZcklNaXo4?=
 =?utf-8?B?QjBOeWxyR3lXTU9rY0xjaERpeHZWV2ZtNEJRSjBMZFVNUlV1NTV2MG9RaDJz?=
 =?utf-8?B?RWdieDNDZnlBaDFiRmNDZTNiMGZ4Y2dSY3IzMGE4RGNiaUNqOHdQZVlBZCts?=
 =?utf-8?B?eGFZdU1aeVM2YzMvRGQ5a0FaV2JBMFlDUWNsRUdzbjhrY0NHNUN4dXVTMC9i?=
 =?utf-8?B?TTEzUkFzeVV0UXQvVkczS2RhNHZBZDB2aVdiajZkMll6dGF6RUpLYmk0L0Yx?=
 =?utf-8?B?clVEVU9DWUpVbzI2OUszZ201WDhxZ0R5VGtaQnpJTXBHVTJrRUVYSTVPMTkz?=
 =?utf-8?B?WkphNDdJM1ZCTGs5WTJzUi91aG5HZFhPamdrNU5YTkNDdlRTSlAxaWJ4VHdq?=
 =?utf-8?B?RmJNSFR2a2RvUzZWQUJ6aXhSeDhpVzJCaUVSWDQ1b1JxWHRCMTZaSEFESVBI?=
 =?utf-8?Q?hMOKTsnYyMTHxCPYjNq1IEoiT46u+2pq?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(27256017);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?eHNKcmtHWWJnRUtIa2pOY1RNWG1EUERVVWlqN0pqa05Oelg5U0RhTzB5UTFo?=
 =?utf-8?B?bWkvVzNVOHJkU2NvTnZqK0ZId3FaSnFIWFk0NlZOVldnbnoyRXJaMkVERjdr?=
 =?utf-8?B?bHkwSm11MUtIaHNaeHVNMFkvU3F2SkFmemVEekhjcS9kdmQ2SXBOdnhTbFZ3?=
 =?utf-8?B?SVFac2V3K1RWY3RrRXpWK3BaZW56RFV2eUwvZERsTUZOQklrb3EraFp1K0xs?=
 =?utf-8?B?SHZGSkhyYWZ0Umtya3JrRWg5TzdjcWRnOUpza000OEl2RG9GZ1BOVWZJYVZP?=
 =?utf-8?B?T3g5V29mRFc3RzB1WXJjZVVQUThFaFZnaVJDalRUbVZWb09KRmFjN0Jzd0l5?=
 =?utf-8?B?QzBFazJvZG41cWlBbHBGQlBnYmlzUk9ZRlozVzRhbUdQV3Jhd00zK3ZtNXIz?=
 =?utf-8?B?NUE4WVZSeTB0Z0xtaG5uV21EWW5sOUcrM3R1UjQxS0U4ZDFzR0xabENuVWVs?=
 =?utf-8?B?L1ZQNXZjMmI4UGdCUVdPc1ZKY2dMYzYxaFdpNUU4d3Q3eFV6VndLT0p0RFNo?=
 =?utf-8?B?Z01NUWV6dHd5eFhzRHBPb3FWVWhkMEV1WkpKUkdlWnd4SmVJak5GdkV4RGNp?=
 =?utf-8?B?Uk5ZRWg1Y085RVM1VnhxcnB5Vjc4TTJBVFdzNnRKQVpBK1NURW1HRnJteW5t?=
 =?utf-8?B?OWV1Y1hZenFMT2Z0WHNGb0s3cngvblpjVGVzdkVYM0puOG1XdkJGcTR6L0JO?=
 =?utf-8?B?ZUd6S1AvRlRVYStTNDFidFZrK3k5L0ZPM093NUkxNlVOZzAwQTh5ZDZlRUU1?=
 =?utf-8?B?ZGJJK1dCaVo2bDRPU0JFb3lqdjhSV2xOZmNoNDJUa3hva3kxUDRGSmhrTjZj?=
 =?utf-8?B?RGpiMWxrOW1JYjZSQ01mSnhzNVFuN0NVVjNNR1lRdkd1NC93L0thbktOK3ZB?=
 =?utf-8?B?ZEpWdjZwR1dtWGE2Y05SSVZGb2dEMmpQMkhHa0dsZXV4ejRXTGhlSVVlNGZL?=
 =?utf-8?B?WFZ3RFZnZktxdDRCb2FkckYvVzlINitVcUcwcnVmck5jakgvQlkyY0wyRmRP?=
 =?utf-8?B?dUpHbFZCS1Z0ZHVNL3JzN0R4ZTlFUnVLb3A4VSs1N0kwWm13M2tPR1BxSVBi?=
 =?utf-8?B?TnBLUk9kZHFXTEtKazhtMU5TcjdFdUlSMmJtaWdLMnFHT1BUL09KT3RQUDZN?=
 =?utf-8?B?TWZBWjhFM2FMWHlaR201QVY0WkdES21aZUN6Sy9pNWtRNThKUXNHcmtPa2U4?=
 =?utf-8?B?T0d2UU1LYi84cTV3Njd5ZFdCRUxzSEFPZWVuemtTblE0VHpNVTB1Y2tLZ2VL?=
 =?utf-8?B?emZuK3k0aGlld3hWUXB1ZGErNnhvWmFIcGxjS1FzZ0NiTUpEbmZ2QzRIRzN4?=
 =?utf-8?B?R0p1cWFSWGhqN2lEQzAyZlQ1cVFzZVF1Z3U0NkwvbTJBTU5QbWppTnFhUnF2?=
 =?utf-8?B?Rk1pejlKejBJWlhSZU5GZkpGWUhoV2dReDVtejN5TWJmWkprTTJMZEJ3aVJJ?=
 =?utf-8?B?aVpsSmQrT1d5NE51V0lKMjcyV1JOZlh0TTFtWi9VWldPankvc2dxdlJ3bysy?=
 =?utf-8?B?OUVlT1dHOGd1RE1wQ2J5YmZtalhNQnRKV0MyTlU2aUpCMTYrNXorMEtYTDJn?=
 =?utf-8?B?K3JuR2xNeFBmU2duZ0wwQjZUR0RHWENOTnBoT0lrYTcxMCs0MEpnWlprQXB1?=
 =?utf-8?B?SWNJdkpsd3Y3ODIxS08yeTNmQ3JlUnlIT1UxSTAxUHluQVh4dDVjYTFscGhQ?=
 =?utf-8?B?c3ZpL05qa21pY29KeXVKTm9OSnpxalFKRzJIaUFrUEdLd1ovemZEdWxGUzlm?=
 =?utf-8?B?MW51QkpOc1dvaGhMb3NYREY0N25scUJWNThvWTI4NERwNnYwV2ZnQmFZQ0xE?=
 =?utf-8?B?WXZvTG11d2Y1UWMxTW5oTllRQnNEcGRTNlVrUjcrWFNrbFpTRm5nVnVFVzdQ?=
 =?utf-8?B?cmFpOEpPU2QzNTJyY1pzNjltaTR0L1JFallHTGNQV3huYlRjL1BBcExsZDJF?=
 =?utf-8?B?TnZIRUtoTklXS2FrR2NsSER1T0hDYXl1UHhCS3VHK0NuUDRtVHZKY2J3dTVj?=
 =?utf-8?B?bnZva0loTVA4R2xGallsY0Y1dUlVSEZOZ1BDdlNKbXpBYVBLY2FrcWt0Ukcr?=
 =?utf-8?B?dE56WCtaMUdkMGFCb2h6VmtVWlVTRnpLcjNwQW1NUHdVMjdVZTRtemhVRUlM?=
 =?utf-8?B?QkFYU1RzT0diOUFuMVpzVW9ick1peFNSSWg0aWRQRC9rTGtnaW9ZYkFuQUJy?=
 =?utf-8?Q?D92ejm+64D6CtJiwWEkfaOs=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 4342a5f0-910f-48de-5419-08dd4a7a4cb4
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Feb 2025 08:58:49.1919
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: zhz6T7K2We6BJSFwCxGX43rVBHeOpRhuSLMXzPHV20YzjEJMv+V5v4OKH7mcsIkj4Qtew3OUjzIbUAMEikAzSt9PXT5YdhBBiRm/HgL6YpU=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR11MB7242
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=hrYQ+0+P;       arc=fail
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

On 2025-02-10 at 23:57:10 +0100, Andrey Konovalov wrote:
>On Mon, Feb 10, 2025 at 4:53=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> On 2025-02-10 at 16:22:41 +0100, Maciej Wieczor-Retman wrote:
>> >On 2024-10-23 at 20:41:57 +0200, Andrey Konovalov wrote:
>> >>On Tue, Oct 22, 2024 at 3:59=E2=80=AFAM Samuel Holland
>> >><samuel.holland@sifive.com> wrote:
>> >...
>> >>> +        * Software Tag-Based KASAN, the displacement is signed, so
>> >>> +        * KASAN_SHADOW_OFFSET is the center of the range.
>> >>>          */
>> >>> -       if (addr < KASAN_SHADOW_OFFSET)
>> >>> -               return;
>> >>> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>> >>> +               if (addr < KASAN_SHADOW_OFFSET ||
>> >>> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size)
>> >>> +                       return;
>> >>> +       } else {
>> >>> +               if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2=
 ||
>> >>> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size =
/ 2)
>> >>> +                       return;
>> >>
>> >>Hm, I might be wrong, but I think this check does not work.
>> >>
>> >>Let's say we have non-canonical address 0x4242424242424242 and number
>> >>of VA bits is 48.
>> >>
>> >>Then:
>> >>
>> >>KASAN_SHADOW_OFFSET =3D=3D 0xffff800000000000
>> >>kasan_mem_to_shadow(0x4242424242424242) =3D=3D 0x0423a42424242424
>> >>max_shadow_size =3D=3D 0x1000000000000000
>> >>KASAN_SHADOW_OFFSET - max_shadow_size / 2 =3D=3D 0xf7ff800000000000
>> >>KASAN_SHADOW_OFFSET + max_shadow_size / 2 =3D=3D 0x07ff800000000000 (o=
verflows)
>> >>
>> >>0x0423a42424242424 is < than 0xf7ff800000000000, so the function will
>> >>wrongly return.
>> >
>> >As I understand this check aims to figure out if the address landed in =
shadow
>> >space and if it didn't we can return.
>> >
>> >Can't this above snippet be a simple:
>> >
>> >       if (!addr_in_shadow(addr))
>> >               return;
>> >
>> >?
>>
>> Sorry, I think this wouldn't work. The tag also needs to be reset. Does =
this
>> perhaps work for this problem?
>>
>>         if (!addr_in_shadow(kasan_reset_tag((void *)addr)))
>>                 return;
>
>This wouldn't work as well.
>
>addr_in_shadow() checks whether an address belongs to the proper
>shadow memory area. That area is the result of the memory-to-shadow
>mapping applied to the range of proper kernel addresses.
>
>However, what we want to check in this function is whether the given
>address can be the result of the memory-to-shadow mapping for some
>memory address, including userspace addresses, non-canonical
>addresses, etc. So essentially we need to check whether the given
>address belongs to the area that is the result of the memory-to-shadow
>mapping applied to the whole address space, not only to proper kernel
>addresses.k

Ah, okay, I get it. Would the old version

       if (addr < KASAN_SHADOW_OFFSET)
               return;

work if the *addr* had kasan_reset_tag() around it? That would sort of re-u=
nsign
the address only for the purpose of the if().

Also I was thinking about it because x86 even with address masking enabled =
keeps
bit 63 set, so all kernel addresses will be negative in the signed
kasan_mem_to_shadow(). That's great for simplifying the KASAN_SHADOW_OFFSET=
 but
it differs from the TBI and risc-v ideas where half of addresses are negati=
ve,
hald positive. So the temporary re-unsigning could maybe make it simpler fo=
r x86
and avoid adding separate cases or alternative kasan_non_canonical_hook()
implementation.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/l=
rlnvcxofcnsm5rou3iwbawyfwtz6mx4gn6eflpm4srhjj37kb%40pwsozjgdyxfu.
