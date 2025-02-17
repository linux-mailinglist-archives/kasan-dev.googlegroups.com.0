Return-Path: <kasan-dev+bncBCMMDDFSWYCBBGEEZ26QMGQEZWLAKMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id E49EFA38B5A
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 19:38:17 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-220c1f88eb4sf73348085ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 10:38:17 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739817496; x=1740422296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=91E64YqoXzk5hs5KS1NbVRt3fyavEohEyXYJO5em+9E=;
        b=fVtwAj2TefLi+UMk7nRhtnJyCDIHBzpciR+fa1NiGHZn5rtKvQMqjuNfs9MK+CHFp+
         U2pR8NNUb5GbXcNp7gDQL0ZdPTjqhTUuj3+LEAQtEAjSG4cmE6oQGm/uIVgQB33eW2sZ
         P7bRzOFF+DpGbCBWkUT1VuK69kadQonTwGdPl/lAcCLM2Yjzv/vq6YoWs4zuMUkAOCJ4
         dA+i69vr8pvtILY9dWdwslqFGmFpFS4/KMihEIq8ekiSz/zZxNjK+q7oZrHgw4EkyJ/S
         iPgrdLH5eONW+D+PlfWVoMELFe3qO0gBPXHh3A081A25V/wS3Utmt5OlQGsK+fuudHSq
         UE3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739817496; x=1740422296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=91E64YqoXzk5hs5KS1NbVRt3fyavEohEyXYJO5em+9E=;
        b=d2BeCjogs/4mSd+CmD+BL3p9mLvP9gxwiNGDGAjsOwERRjqlTOF9iblEJKBxg9kQTH
         7sTejWeSrugEeUvQB0cqPSr+rkP5tKDYWOdwmFKjfBuCIMOFy8sy2bZzP5qhgMeA2UHq
         rNGqNbdRwiq2byzKsl38qZshPL3hyL7SrrLTZyzUnov5PArgSzJT6bY+lEh/p/PzC8I3
         dYPfbyiUkv10hgBDT5HnBZFcGM7dXpX7IxyCjkhTWopekb2h1PX/myEW2Bd1pKqGCBX7
         lZmDlVErw+Cep9rGahY2qkLwiJdP3IvqxJZHSCeSNXuzVyiDJJIzu8LsjLmdf/RAqEzz
         V9Lg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUJ020/Mn+bXZR2QogrrO/iPbHWAZW/ERnLSaLjUXItYWklt6MlqI5N+znFYEhA+43aqIKLzg==@lfdr.de
X-Gm-Message-State: AOJu0YwmA4PWSQ1raDGEFvrGoj3Ev/ELOXQ/txYUXnhtOHpyAvWeaXXM
	mY0iWwb8kPL44WabnRWD4U9Y35Xbbk/jz5PN3Vt5ThYeMzL9QJvN
X-Google-Smtp-Source: AGHT+IG52tHlfV4xWIhBhH0mDkpSuiFU3D3xwBXA+CslzfcGBryIgWoACBOaCdIDLbavVHpVFBgkvQ==
X-Received: by 2002:a05:6a21:e8d:b0:1ee:7ddf:f40c with SMTP id adf61e73a8af0-1ee8cb499ccmr16272464637.11.1739817496243;
        Mon, 17 Feb 2025 10:38:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFG8WyShTsUOvF+FxY+776WrmxAfVwTa22YocntoTP1gA==
Received: by 2002:a05:6a00:4d95:b0:728:f8a6:8599 with SMTP id
 d2e1a72fcca58-7323bdde883ls2319831b3a.0.-pod-prod-09-us; Mon, 17 Feb 2025
 10:38:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbNVGjLV6k+HwYLstGSQZ8VJLTiGJCl8ZMop13vXHEkfn0ckczwaMgcEsPJW8BBhEdSOyDhMuTAsQ=@googlegroups.com
X-Received: by 2002:a05:6a00:218c:b0:728:9d19:d2ea with SMTP id d2e1a72fcca58-732617c3c8fmr14576531b3a.13.1739817494979;
        Mon, 17 Feb 2025 10:38:14 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-adb59c7ac8bsi365535a12.4.2025.02.17.10.38.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 17 Feb 2025 10:38:14 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: 6rhjJ9LQSp6iJHoxtAwecw==
X-CSE-MsgGUID: TxAMpmKvS8yTSOcV2GhUkg==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="40214115"
X-IronPort-AV: E=Sophos;i="6.13,293,1732608000"; 
   d="scan'208";a="40214115"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Feb 2025 10:38:13 -0800
X-CSE-ConnectionGUID: 6rBB0pooTYyJwpVire+I9g==
X-CSE-MsgGUID: isLAIaGlRWix1d3Hz0A3wA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,293,1732608000"; 
   d="scan'208";a="114386506"
Received: from orsmsx903.amr.corp.intel.com ([10.22.229.25])
  by fmviesa008.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Feb 2025 10:38:13 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX903.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.2.1544.14; Mon, 17 Feb 2025 10:38:12 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Mon, 17 Feb 2025 10:38:12 -0800
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (104.47.56.45) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Mon, 17 Feb 2025 10:38:12 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=SSJRo5CDU1O9HFg6TyIQTfxgFbsKNUvRiLSz2xx8hyjsLN3CTVh+hBZyvx/6TtDe9huXWqeDhFsyisjYzwlZT2e9CZq/F/ujOKxvoHbW1boKPRH5mMfdQ62sl7K512N119Mb4/niAuf3kfRPXlk2hXrvme4mCgmfJy2I9B9kyb211FrT/JNX9LHwmKVv0llsqrSTAy/NCWwqhQqKCO16uuN4yBds0S7uhGxMxXkHYBVnLHZYcY0Fy20Xhl1KOhnlp4poTq4+aEIfNr+7pxR6oPrsCMkclf1tKqMXd7rS+ljxOeqc7J1NSoQ6yy1UXbUIVRHA9fN9xOmM0eqShzkwRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=FJOr/W5XvA4Jct+SudYeYcMy2N3Q46HCp6mZjRtE/Vg=;
 b=g6gNxNCkKzGDI35i+whcD+OU5Loq5gJCH351R8a/vZhvN3npd2PG1pHnoLy86DZSZDjkI4/ZrLaNDLTdRF19XICQ8r0nT/T3OfcUP5T3jpBThbEwNl7Hz4GwgG/h9WLGc0S1Ai2bCpeo/mL7iY1XPbMGY9O/NyYfi+vksii9PUz49EbraTzxlLKX/Wjh13uRO8jjnfntmmHDcYwdSEv5KtFD5YJKK53xADISZPHVMjDtgYQNSnGTy7NHrKaav5N0THsBrDZlzc7fNjiO3O//EX3tZQ3Sg+0U8NTL4M5nIBT0mrFOrHcWXbc9RDSia+JRrtvSS/n7ssgnmymB4hmAXQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by DS7PR11MB7860.namprd11.prod.outlook.com (2603:10b6:8:e9::7) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.8445.13; Mon, 17 Feb 2025 18:37:42 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8445.015; Mon, 17 Feb 2025
 18:37:41 +0000
Date: Mon, 17 Feb 2025 19:37:12 +0100
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
Message-ID: <kmibbbrtlwds6td64hloau7pf3smqth4wff33soebvujohsvli@kni5dtvpwsxf>
References: <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
 <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl>
 <zjuvfdbl7q76ahdxk3lrgaznk7vjj43f5ftzfgrnca6dqtcd5x@5qj24womzgyq>
 <CA+fCnZfySpeRy0FCFidLdUUeqp97eBdjAqQyYPpz1WxYwcsW9A@mail.gmail.com>
 <aqhm7lc57srsfuff3bceb3dcmsdyxksb7t6bgwbqi54ppevpoh@apolj3nteaz6>
 <CA+fCnZdjTkreTcoo+J8wMhwDuAFM4g33U5BFy0OPtE0UCvyJbQ@mail.gmail.com>
 <CA+fCnZcoVdfXVN8VBFLx835cV0eGAT6Ewror2whLW761JnHjNQ@mail.gmail.com>
 <sjownmnyf4ygi5rtbedan6oauzvyk2d7xcummo5rykiryrpcrt@kasomz5imkkm>
 <tuwambkzk6ca5mpni7ev5hvr47dkbk6ru3vikplx67hyvqj2sw@rugqv7vhikxb>
 <CA+fCnZcHnWr0++8omB5ju8E3uSK+s+JOFZ3=UqgtVEcBzrm2Lg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcHnWr0++8omB5ju8E3uSK+s+JOFZ3=UqgtVEcBzrm2Lg@mail.gmail.com>
X-ClientProxiedBy: DUZPR01CA0075.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:3c2::7) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|DS7PR11MB7860:EE_
X-MS-Office365-Filtering-Correlation-Id: c1cec8ee-d1c9-40ca-7e93-08dd4f822979
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?eGdXbG1CV014dmlZd1Y3bXVlQUV5MWpuOEFSUHZiVXZ5N2k0aGJNbXI3VlNR?=
 =?utf-8?B?L3J2Z0JuQ0VHSG04Snh3dk5SUWpaTXB3UkNtZUpnZGpqZnNaM3hkZ0VSWXZy?=
 =?utf-8?B?cFh6WmcyblpOZEF3SzF2cUV0NmVCV0poM2dzRmJBOWluck1iSldnVFRSQ2ta?=
 =?utf-8?B?RDVCejA3Uyt3aHFIRWhpSk5xeWhicThYODJNVHhEc3hjRW1JVi9SNk11VDVG?=
 =?utf-8?B?SzYxblJZYStRd3V2MFlqQVJoL01ReG14VUpDY1pmbWlkWFphMTFsZXdYQ1Nx?=
 =?utf-8?B?ZHhRMDc5VWhySVpHNjdPeSsrSFRYbjlqM3FzZFd3RkFEcnBWZGREeHFFVmZ5?=
 =?utf-8?B?MnVGWGloK2pIVmQwOEwrcitBY3hIL0k0cU45YzVNQ2xEOGE3cnhFRXAyUFMy?=
 =?utf-8?B?N2JVOHFzQThwb2JIRnhaYVk5d3ZYcnlKWDNDM2ZPLy96aXk4K1FiOGN3bUY2?=
 =?utf-8?B?OEU2czNDUVNua0htby9nVTJJSWc4aExJaDZYZU5jNUplR3RzUEpmMStLWGN2?=
 =?utf-8?B?STROMGtXaGZaWm1ab3lPcGdLQlNjdTJHR0gxOGl2TGpmR2N3QytPM29GSkNK?=
 =?utf-8?B?VEozTU5TT0MvNVdQOVhvVEpEd0ZLMXBYdEIyeDdUMlRkNWNTd3BDa2hjWnUx?=
 =?utf-8?B?UEJ3VnhRNGx4UVlSQjNkdjVmSU9YcERlUkFXK1dMS2xVbm1aTllBazFjdTFP?=
 =?utf-8?B?Nk5nTWZTeFhYdDVqOUVEb3ZJV2RXTGdCU0dRRm4wYTlxbmVrVnJZOUpDRXpW?=
 =?utf-8?B?d2RsYTJCSWJOQWZvVXZvRCtuL1QxRHhFRjNlNmFqNGxnWlFjajQ1L1FDNzRq?=
 =?utf-8?B?Qml2R0Y0eHg1MlppMkUxUWNCVzA5WlBCYXAvRk11aGQ0bElYNXJFYUVXSUpX?=
 =?utf-8?B?Y2tkRHhQc0VNKzVDTFNSSUh6MFJ0UU1OTmJadjVuZzE5RWxkZHErM21sam9O?=
 =?utf-8?B?bGtzdTRMYUF2L25VWGV4UzlTc29ReGxPYXU1K29ydHJ6UzI2MmpoaGoxWFk5?=
 =?utf-8?B?TWkyWnZOSnlCOTdUYnE0Ty84U3EybEZYeEJsY1NRMG1HNTdIL0dNLzZxVVZ6?=
 =?utf-8?B?eVoya0x6bnd2bDRUTlJWYTdNaGJXMjRRUytSTkpmbTh4bWFJekM3R1NvZjZ2?=
 =?utf-8?B?emVmVWlienRZNEFxN09qNmxLMTFaa0FTeWJ0N3Npa2wwREpqUG1waXlSVjZ5?=
 =?utf-8?B?bjlCWXBFckVoTGIxeWQwUnlQR09UbG5NcHpKRkNlN0FPbXVKZzV3SEZzaXhX?=
 =?utf-8?B?QmFRd2RmWXNGNU1rM2wxVDdPRythMlBjZUUyL3FQSzV6bHZhYlQrVjFhTHhx?=
 =?utf-8?B?aDdVaG1RUmg5djNzSkFwcDNQRURBazBaNDIzazJnWU83MVZQMjFDVFhFL1VU?=
 =?utf-8?B?MjdYdkczelpyRDY1a3VVZTh5OGV6YmRhVDhoTEEvUHlqOXJIMlZMSlFkYWQ2?=
 =?utf-8?B?ZnRKQnRtanV6Vi9sTWQ2OW1iTHBJYmNCY1l3ME5rTTFKV3pDMkRvMWN3YnhZ?=
 =?utf-8?B?RGlNUDNPb2p6WTVhQnRmSXFYOW9GbVY4OFdyYWhBenRlUmNkTE5WV1JlcW1L?=
 =?utf-8?B?aHlLSXhSbjlLMjZaOGp0U2g2c3FvWmZvN2hUVThJTlY2c3EzSFdTRm9YVllD?=
 =?utf-8?B?aFRTbU13SVdHT1hXcXl5VkJYU3VWVko4anFEMk5UQU1DZ3hRdmxzU1V6ek0r?=
 =?utf-8?B?RXVWczJqeWNmaDlvRkZOWHZyZHRsSENGSzA0K1NBZXMyU0xyRitzYUxENFUy?=
 =?utf-8?B?ODhkSkZoTVVZZTZ0L0RhWWk0cEtQMWdUZG00YmxLMHA1MGNnUnRHTG1uaVd2?=
 =?utf-8?B?dHFTNVZrdW5sZ1llaVlWS0h4bXZ3NW1wdlc2Rm5FcjROYjVnK1NZWGlXcWd0?=
 =?utf-8?Q?KXXem+9otIMea?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?N2hUTk1pcVZ4OXZ2eitrN0J2aTZtOU5qdWlvTmdyL3pzVWJkSTZTSVRLVjNj?=
 =?utf-8?B?bjQwd3dKQ1hqNGR4dDJtQVVWbU1KYTdaSDRJY3hhaHF1VHVkVCszMFhkSVdn?=
 =?utf-8?B?YzM0NTU1M1ErZ3dTYVRyL0JJdFY0YVVzWDV6eDJhWW5XRHdTdjcvRUxPS09u?=
 =?utf-8?B?clRmNndMVS9pdHNLb2N1VkpaVVJpeE1wOCtoVURoY1p0c2N6bzdrWFhyUVNY?=
 =?utf-8?B?TmZmRnQ1ODN0djVTRS9iYXdOdjczcHdJb3pnZkhKT2FBdFAxQUZZRm55MGdY?=
 =?utf-8?B?bW9uZVFsMzFaM2pzVjF2ZUFubFozS1VybHVId2o5d2lHOStTODNReG5QdlRW?=
 =?utf-8?B?S3M4UHdhd1FQVEhqdUFCVFl6RVNXdHozVkFxb0hSNVJIdlBvaDcxdmhxVE5o?=
 =?utf-8?B?eUV5aFdFa05ZZ2pCSDhRSHRtd0ZJeWcrM0duRjBNenp3THZTSFNiY0tydjFq?=
 =?utf-8?B?NjlzZitOR25WalBKVWh0UTUwSkJDYUdUdytSNW40bi9KTUQ5a1hhOXVkWTM2?=
 =?utf-8?B?WXBpdU84RDhrU1l6WWJ0c1pQUkxxbThLUlg3M0xPSXQ4N1dGcG8xZGs1Z0Rx?=
 =?utf-8?B?L0tvc2kzWVpncnhkSnhoT0hoSm5BS2RkajJMbTdGQWRJdmg1NTRmZDhTTU1n?=
 =?utf-8?B?dkQwWXdvek5pMzRhOGlCVG9IR0tjNFZBNGtMWUhEVmNsZzRhZDN2ejhqc0FE?=
 =?utf-8?B?ZWwycTRhampvUzExMEl6d2xJMDJDZ0J4Szc3TkszTXVOcnJBOFVBeGJ2a1hj?=
 =?utf-8?B?d3FUeW1DV2ZtZFFzbUtuWEVhM1RWN0ovaHRTQk9HNFprSlNYQjYxdWUwUDNX?=
 =?utf-8?B?elZyNXMyTU9xVmRKSkZ5WFZmY01MeHpkb2NQN24xeUMrMjRqbWs3SGNVbE9z?=
 =?utf-8?B?alpCZjE4SkgzVms4MkdGa2luZG9uUGVmemtQVFRTdjRxWXhHcEhWYTd4Wkty?=
 =?utf-8?B?RjAwa0RUWWN6Rko4QnFUTlg2T0dIRVh4MkpVT25FTXI3SHg1Si9lU0ZpRkdk?=
 =?utf-8?B?ejJaeDhIWXdaVng1Z0hFcG1XSm5uRnBsWWhHNjNUK3ZzaFNiOUYzLzJSbkp2?=
 =?utf-8?B?V1QvK0RhMHNKcGRJemt6R1V2Q2Nab2Fkc0pCWmd1UUMzRUcwNzBJUWw3eXlZ?=
 =?utf-8?B?VURkM1c4Wmh2VTJKSllNYmVmK1ZYL09lbFhhdk5KUVJmL00wTlluNndvQzRB?=
 =?utf-8?B?bFoyQzVKVFRrZnBFTENOdStxcFRzeFkrWlpUdnU3WGpGZ2hHa0FUWm0rblky?=
 =?utf-8?B?WFAvVksxTGFsbTRUU1M4elp3aUJKTFI3L1dyRnZ0REdBblI4ZittdG16L3Vj?=
 =?utf-8?B?K1ZRV2pBUTVzbGQ1UzVmUHd0YTl5OS9RZHBvMm1BQ3cvc0RGZVZLRDdBUlFt?=
 =?utf-8?B?UXREU3A0UEg2K2lnR1ZPTm1xZVpUT042VFB3cmlyTWxzaERtTzZMLzMxWHNh?=
 =?utf-8?B?RVgzbXRhRHlCbW5qakRJeXZyTlUyUGNPZWhmcURjNWNhdkNLbVoyMTlYNDBE?=
 =?utf-8?B?UVBZN0ZrdG1GNk5vTFZVQ2RSMG1haHp6WUROMTlFZTFyNkxaL3A5NTZ0cFRu?=
 =?utf-8?B?YmREbW5DbmtyOGlIVFV3TFdxSWFRY1R0UlhIZUh4d1prRzY5S3JEeVBIc0R5?=
 =?utf-8?B?eUtiem84RmpnTmdhZjFCVHZYRC9TTlVkZjJxbzRTcFI5Y3NsYWlmTURpcm1i?=
 =?utf-8?B?YXZpT0dQWE5MbUlxdTVYUjFQTEFMZjRRUW9CVzdsdjZJbE1kNHl3T3lFQTZR?=
 =?utf-8?B?QXRRZldvOHNsSWlEU1ZWME5BTUdJQlk4VDVWMW5qS3d5NDlJSE9qWGdpVDJX?=
 =?utf-8?B?clYxZytNTDMwN1dnODhIOXFLSmloa1BHdEhCbmZzdkFEcjVtbnNxb3pvR3ZE?=
 =?utf-8?B?VW5QTnU5YTRDZXlGZFJlVXUvM3Y5UG9oQm9Vak5FR2Y2WVNGSWNuM29MazRu?=
 =?utf-8?B?ZGxPSnBCd2h3c2l6WUtmaGtjT0dMWTFPaGNSK2FDVUhRcGlWZFZRNHlmSUJL?=
 =?utf-8?B?VUxqTjVyRm9GWEx4QUttZlBUMEFtMTNjaEhZQ1JQaHVtUkluMEdrZTBpMHlX?=
 =?utf-8?B?Z0RlbTNrcVVXMnNYWlNQUU9leklqOEpOajduWTdleTQvdWNDcGE0eVcxeGdR?=
 =?utf-8?B?OWtzbmpZTWZGcnp1Z01taC9Mc3c2Z1dlRlBMRExiZk9veSt4a3BlNDc5TTc2?=
 =?utf-8?Q?tXRZJgVTLDWquoa2f7MFFGA=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: c1cec8ee-d1c9-40ca-7e93-08dd4f822979
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Feb 2025 18:37:41.8862
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: gnde02ZQefCeJ+Vw4RcdDaUi3QdNfeuWsahKFtY7vOH5FAnhL0rMt16LRV+DdRwkLaDbTxAwwsLo9YwZtOgNwMRPaIeglJfI86jin5AV+1E=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR11MB7860
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QYZwrQM7;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-17 at 17:13:23 +0100, Andrey Konovalov wrote:
>On Fri, Feb 14, 2025 at 9:21=E2=80=AFAM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> On 2025-02-13 at 17:20:22 +0100, Maciej Wieczor-Retman wrote:
>> >On 2025-02-13 at 02:28:08 +0100, Andrey Konovalov wrote:
>> >>On Thu, Feb 13, 2025 at 2:21=E2=80=AFAM Andrey Konovalov <andreyknvl@g=
mail.com> wrote:
>> >>>
>> >>> On Tue, Feb 11, 2025 at 7:07=E2=80=AFPM Maciej Wieczor-Retman
>> >>> <maciej.wieczor-retman@intel.com> wrote:
>> >>> >
>> >>> > I did some experiments with multiple addresses passed through
>> >>> > kasan_mem_to_shadow(). And it seems like we can get almost any add=
ress out when
>> >>> > we consider any random bogus pointers.
>> >>> >
>> >>> > I used the KASAN_SHADOW_OFFSET from your example above. Userspace =
addresses seem
>> >>> > to map to the range [KASAN_SHADOW_OFFSET - 0xffff8fffffffffff]. Th=
en going
>> >>> > through non-canonical addresses until 0x0007ffffffffffff we reach =
the end of
>> >>> > kernel LA and we loop around. Then the addresses seem to go from 0=
 until we
>> >>> > again start reaching the kernel space and then it maps into the pr=
oper shadow
>> >>> > memory.
>> >>> >
>> >>> > It gave me the same results when using the previous version of
>> >>> > kasan_mem_to_shadow() so I'm wondering whether I'm doing this expe=
riment
>> >>> > incorrectly or if there aren't any addresses we can rule out here?
>> >>>
>> >>> By the definition of the shadow mapping, if we apply that mapping to
>> >>> the whole 64-bit address space, the result will only contain 1/8th
>> >>> (1/16th for SW/HW_TAGS) of that space.
>> >>>
>> >>> For example, with the current upstream value of KASAN_SHADOW_OFFSET =
on
>> >>> x86 and arm64, the value of the top 3 bits (4 for SW/HW_TAGS) of any
>> >>> shadow address are always the same: KASAN_SHADOW_OFFSET's value is
>> >>> such that the shadow address calculation never overflows. Addresses
>> >>> that have a different value for those top 3 bits are the once we can
>> >>> rule out.
>> >>
>> >>Eh, scratch that, the 3rd bit from the top changes, as
>> >>KASAN_SHADOW_OFFSET is not a that-well-aligned value, the overall size
>> >>of the mapping holds.
>> >>
>> >>> The KASAN_SHADOW_OFFSET value from my example does rely on the
>> >>> overflow (arguably, this makes things more confusing [1]). But still=
,
>> >>> the possible values of shadow addresses should only cover 1/16th of
>> >>> the address space.
>> >>>
>> >>> So whether the address belongs to that 1/8th (1/16th) of the address
>> >>> space is what we want to check in kasan_non_canonical_hook().
>> >>>
>> >
>> >Right, I somehow forgot that obviously the whole LA has to map to 1/16t=
h of the
>> >address space and it shold stay contiguous.
>> >
>> >After rethinking how the mapping worked before and will work after maki=
ng stuff
>> >signed I thought this patch could make use of the overflow?
>> >
>> >From what I noticed, all the Kconfig values for KASAN_SHADOW_OFFSET sho=
uld make
>> >it so there will be overflow when inputing more and more positive addre=
sses.
>> >
>> >So maybe we should first find what the most negative and most positive =
(signed)
>> >addresses map to in shadow memory address space. And then when looking =
for
>> >invalid values that aren't the product of kasan_mem_to_shadow() we shou=
ld check
>> >
>> >       if (addr > kasan_mem_to_shadow(biggest_positive_address) &&
>> >           addr < kasan_mem_to_shadow(smallest_negative_address))
>> >               return;
>> >
>> >Is this correct?
>>
>> I suppose the original code in the patch does the same thing when you ch=
ange the
>> || into &&:
>>
>>         if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2 &&
>>             addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size / 2)
>>                 return;
>>
>> kasan_mem_to_shadow(0x7FFFFFFFFFFFFFFF) -> 0x07ff7fffffffffff
>> kasan_mem_to_shadow(0x8000000000000000) -> 0xf7ff800000000000
>
>I'm a bit lost with these calculations at this point. Please send the
>full patch, including the new values for KASAN_SHADOW_OFFSET (do I
>understand correctly that you want to change them?). It'll be easier
>to look at the code.

Sorry, this thread became a little bit confusing. No, I think the
KASAN_SHADOW_OFFSET values are fine. I just wanted to embrace the idea of
overflow for the purpose of the check in kasan_non_canonical_hook().

But I'll put down my train of thought about the overflow + calculations in =
the
patch message.

>
>Feel free to send this patch separately from the rest of the series,
>so that we can finalize it first.

I have the x86 tag-based series basically ready (just need to re-read it) s=
o I
think I can send it as whole with this patch and 3 others from this series.

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/k=
mibbbrtlwds6td64hloau7pf3smqth4wff33soebvujohsvli%40kni5dtvpwsxf.
