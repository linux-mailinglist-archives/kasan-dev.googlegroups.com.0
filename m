Return-Path: <kasan-dev+bncBCMMDDFSWYCBB6VTVC6QMGQEAL2SQZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 25B1BA2F16A
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 16:23:56 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2fa3e1f08a0sf7623262a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2025 07:23:56 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739201019; x=1739805819; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=07vWcAIgjUadXaDD4ZANfyHlnBbHW8ujTGMyKGT9CUI=;
        b=KcNsyNgbgSsrEDRBTNP60dJp0+cE/9lfp3XAn8xM87gTNuzZx2GZcYgxTTFxOgpXgo
         aLbZQoDTz9MsZHPMK/mSoUZ/NZg98gGl2oRmIeOhV4LofT2fqna4WogJKST35TRIOpCR
         OPldaIL6IFnOCdec8CbDwV7u4l6S6ow8mX1RsRlGXOOlouDfAeIbvEuTCaArL4OMQ4hs
         9bCPeJRuMSS4mzFKP3vI3be0yqaTxmHjWieooT4SV78mTR/mxbDMRfsEzzyH0niuYdez
         J87mVGqQeZ9GosWmi/EvLlagA1UmVSFBF71ITsopmf85KKt09ZxwbGBmedtkzn62ppqI
         jwNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739201019; x=1739805819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=07vWcAIgjUadXaDD4ZANfyHlnBbHW8ujTGMyKGT9CUI=;
        b=m3zxGgZvS+i8N1VQUUu7DsUDnnWtNNScmyWJrvx2frw54OK5AM2kkrxQxTm5HfWXRQ
         0Tm3tOffACyWQm64nviVtPW3C74N0xgKwrn/j7osl1CGgdZdmHqz8n6NtAYBVtH52j/L
         9RJEM+ne2nDk1zTsn0EKTOxYFAKfK7cy5DSkUDUs53y+payZoivQy29Ub84sjzWfhacc
         Wz/SxB2T89pNM62XOGJjAWSEnrAdob4ERKgLY1wJxMbFgWH+IocWBmqi+myMDooDzgrN
         oYtm3FWkl4byOadb34b2pxMRf7ypPpMDv+Jf+0Q3nWaeNJtKMlxWTixTFjo77vme2zOY
         7POQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVwr7dqeT/muXyWOTMqxTnzPrDtVdsUAotGVddHpq0t2kENqJxjhmjHWNZotpHFmhEGxnsjCQ==@lfdr.de
X-Gm-Message-State: AOJu0YwemCr4/F5k1Ko0122AeEWUNcclHcfUce4hwrZz7PwCVYNt2VmX
	v9hk3/D0JRbuiXzfwFFMyiQnaMRgf9M43N8ggoOY43FOfZKcL+Ja
X-Google-Smtp-Source: AGHT+IFuWGYHd2Jl06GRRC13hHhIWW4nS9itX6cxUtc/jD+KMg1oPYJ1fLI01Jggf+kCjqynITlZew==
X-Received: by 2002:a05:6a00:888:b0:72d:9cbc:730d with SMTP id d2e1a72fcca58-7305d475f0bmr22541730b3a.11.1739201018829;
        Mon, 10 Feb 2025 07:23:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b45:b0:730:8472:3054 with SMTP id
 d2e1a72fcca58-730847230f4ls1782327b3a.1.-pod-prod-03-us; Mon, 10 Feb 2025
 07:23:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVj0K+zdXQxaDYEg8f2ngz7QK2tPcZXlr9wDIAr90BF3BwSpcF48QlLKE8IrN6wAExIMhudkBp73Gc=@googlegroups.com
X-Received: by 2002:a05:6a00:c81:b0:72d:8fa2:9998 with SMTP id d2e1a72fcca58-7305d4be8dcmr21794471b3a.14.1739201017453;
        Mon, 10 Feb 2025 07:23:37 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.21])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73092373763si81650b3a.4.2025.02.10.07.23.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 10 Feb 2025 07:23:36 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.21 as permitted sender) client-ip=198.175.65.21;
X-CSE-ConnectionGUID: Fq07n0JkSvi+a66EGQrYUQ==
X-CSE-MsgGUID: 0waLpIL9QfCIS4gE8FPJvw==
X-IronPort-AV: E=McAfee;i="6700,10204,11341"; a="39700053"
X-IronPort-AV: E=Sophos;i="6.13,274,1732608000"; 
   d="scan'208";a="39700053"
Received: from fmviesa007.fm.intel.com ([10.60.135.147])
  by orvoesa113.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Feb 2025 07:23:34 -0800
X-CSE-ConnectionGUID: SL112yZNRDW9ZCRDKUIS+w==
X-CSE-MsgGUID: SUzTqhCZRt+0T6jzQwaZVQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,274,1732608000"; 
   d="scan'208";a="112169206"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmviesa007.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 10 Feb 2025 07:23:32 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Mon, 10 Feb 2025 07:23:31 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Mon, 10 Feb 2025 07:23:31 -0800
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (104.47.66.42) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Mon, 10 Feb 2025 07:23:29 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=uZfNz/tpp0PDt3D8H1qqYJ/mc2C1iH9Ag31ByTDQc3LmityqR4HFm16ohuibLy3j0QGW/7ggEuXNFda5Q790r+HkcDbiGcMZYZ5xFYllgsxKi63cCXvtO4iLhIEtD7O6vhA0SvJCm9xSmucJE67swBnsjsm4ODJBqgeR8iAdK3fN97vwjVrUXFsRslZi80asqaY9PetYyCdiZ40mNbiNk62OGJUZBdE989dmnD0jmJjBKOqhAlKgNUpJYisv3vDePdIZ+/PSIYByz1lexk30QNTuLTmY7f8DwooebA7dwLRpxg8rnZG2Q1+ML4d7Vuja/shNWyI7wx9GwVE6KDm2mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=pHyHuZ+A8N1s48feZVsRvxC0J9JrnOpJ1SDsyjoWO08=;
 b=BC06CayGkIvJKeEuB6jZ+H9YiHYCg5ij/xl+VaofNQ6D/KMgG3IozkhC4gDEPLmeLTYohkYL6BZVGhPnWsuvCJeBVjf3E9f5DytLNJgUeRHBvu5oQM6M+Bco4xVPMR9banToq+8R/quaBdMYecpqEEq7M0ntuwBOr06OIaYjUYe1gddNZssyncWopSCU8+6F46tqXVhy5cN1VP7wRvpsy4dnB+MtqLNXqBj9LlV2J43NNEhoFNGQS33qPyi2xYj2G4w+y2mYXzV2Zki0rzfB3103f3dg0NHwL0FgeA+QM42NGrDqHLwwcPzycI+DfxiQSFIaPP2p8UsCnb5X9QF7oQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by CY5PR11MB6257.namprd11.prod.outlook.com (2603:10b6:930:26::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8422.18; Mon, 10 Feb
 2025 15:23:12 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8422.015; Mon, 10 Feb 2025
 15:23:12 +0000
Date: Mon, 10 Feb 2025 16:22:41 +0100
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
Message-ID: <e7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t@oomoynf3b2jl>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
 <20241022015913.3524425-2-samuel.holland@sifive.com>
 <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZeBEe3VWm=VfYvG-f4eh2jAFP-p4Xn4SLEeFCGTudVuEw@mail.gmail.com>
X-ClientProxiedBy: DB9PR05CA0027.eurprd05.prod.outlook.com
 (2603:10a6:10:1da::32) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|CY5PR11MB6257:EE_
X-MS-Office365-Filtering-Correlation-Id: c1d7d9c2-63aa-4455-1d31-08dd49e6d502
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?djZvMXFsZmdETjlMTVFCK2JkUHdWemxrNndLRXh2ckNoVE50NWhYWGhycFB1?=
 =?utf-8?B?Q090cjNzSHFkWVFCSWwzalZYSkE4aTh3aXR6RUkwaWM1UzNBY2hvN2huWGJz?=
 =?utf-8?B?RmNFZE9reTl6MC9MQ0VtbG0vQlQzdGRyQkJVMG4vazNtbVB0V0Q5eTBzNWda?=
 =?utf-8?B?eWlBZ2hDTTg3a1IzelRhS2R3VDBtTEhPU1dlUU4waGJvdjJUb3dkNW5EdWZE?=
 =?utf-8?B?NWE5VXpuSzZyODRQQStzbWd6cnRWdnFQQmRKL3pkYVdjU3ZYU1o1MG9FeXJR?=
 =?utf-8?B?d09XVnVBYVdGeHZQQ0FiVGlaeXBpcFpEeG04ZDZOdi9BQjFoUE9KRVNXUGd6?=
 =?utf-8?B?TlNUb3BydzllK2lJRlo3NHVpa2NidkNiOW0rODJiazF4R3ZaMkF4MS9oYWFs?=
 =?utf-8?B?VXpyeHRyUVhjQVVVbTNFK0dvMmxXNXA1RVZSNy9QUDhFQ3djdGZJeDVhT2JK?=
 =?utf-8?B?NDgwM2hDaUZmeEd4ZkJhdjRIdFNTM2JkcDFoMEFyeGYzTkcrZmxOVGdjV282?=
 =?utf-8?B?bWpYYWJMT001SGhBMzRQT0JscHZ1SGJJb0EyZzJLditaU2pLZEVabjREMjY2?=
 =?utf-8?B?VmFDSzU3bzJ4U0pnVFVWak9zQ2lsQmgyQlY1R25xc3k5UW9GanVuenM5RVNS?=
 =?utf-8?B?dlhPVmVtRnZ1UWhqOHZzNTFlbUlDbzNtb0M5S0YzbzVQQ1Q0Q3lVUFRnNThz?=
 =?utf-8?B?dlFmUGtSWkNvY2M3UldNWC9XejlaVE05VnBUbVIzTlkzd3Z2cXpuZFRVUGt0?=
 =?utf-8?B?SjNEVXRRNk9QSDRYS1Z2dW96RXdRSDUxQnVrT2Rlb0s3ZzdHSW5rZ3F6bVFu?=
 =?utf-8?B?OTJsbThJdHlxNnRSZDFrRi9tSDVMVUI4S1RQZEpMRWYra3dibllqNWpCeWJR?=
 =?utf-8?B?eExpTy9DbE03RFN2b2owODFocUN6YSsyVWZhcmVqNEl5TzhPR3Y0bWdYN0F2?=
 =?utf-8?B?cHJDS1VmSVJFdkRyZUNhT1NQbW1WQU10SHVEck9vSng1UnZlb0huSU5XUDlZ?=
 =?utf-8?B?SityV2ZNY05hOHRlUDhDRWFJc2hWK3N0N0VtbkpHMTFCbW94c3VBNnNsK0Na?=
 =?utf-8?B?bTArVzRSZzRzS0tnTTNOVFppNnczWlR1QWdrVXJnNUJzalJ0R3pIc2xNQXFv?=
 =?utf-8?B?bWltK3lLVVVWQnVnZWh1d0hGVC9sa1k5WkRYWDV2REFKYTlZeHc1UzIxbHdx?=
 =?utf-8?B?NmxiV0lVazM3Y3kxdHRWU2dhSmNlSGNzaFpBR3pXTGZxK2s0SzhtUFBnUVNC?=
 =?utf-8?B?VWM5K1JWMjlYVEVCb0wyUk9ES3oyZ29ScldrMFNSZDlTaXFXS0lpWWhlSnNq?=
 =?utf-8?B?TnBQNXNuSmJLc2QydTZYNGlJejNGSzVKbnhXTEJZM3RPZDVxNXd6QzRxWTI0?=
 =?utf-8?B?Y3FiNi90YWNja3pJMFkxK0tQWXMxN1Ixa3Rtblc1VE1YVkpqSG5PODg5dXow?=
 =?utf-8?B?V3BuTUp2SGJmVmx2SzA3SGxWRm05K0ZFYlpudG9yYXRGb3ZLYXhZM0MyZGFY?=
 =?utf-8?B?UTBqZk50cm1XYmRDajhCZXQ4NjUrSFN5cVRyUUxzTDNuV3NXK3MyUmRYTy9W?=
 =?utf-8?B?a2pRdHg5UEt3aE94c280S2F2eE1TbU0yRFBqb0dYdlZaMUwxUUpwbmdwVFRu?=
 =?utf-8?B?RzdrVjdrQzAyWjNuLzNMT1o1VEVWNTVydzhRTFFyWjZyUlBtQXYxb2RYamRY?=
 =?utf-8?B?YnVTLzZLN2tySXg4L1JTbUwvTm1FMU0vcUtyT3ZLQ3MybHBGbzN5S0RsS2l4?=
 =?utf-8?B?eUJSZUlLQVBGS1B6UVkwdzhGdFR3VjJWTkRPYm9VaHBIY2ZDWTBOYm1tWlJ1?=
 =?utf-8?B?RERSbFZGTk5jTTFXcWkwVGg1VUdLY2U3dFVZQ2l4SUE4ZTRadmt3T1FXZ3Jj?=
 =?utf-8?Q?NNR1Bj5wwn/kU?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?MDh1cDd0THJ4VUFFbmFEeWdPcDZiajhocnBYaTJvQUV4aWFmdW5ocUtBUzVj?=
 =?utf-8?B?am9uWXFxeDdVNy85QzJ0SVRTYjBNc3ROZWhqTTdZOStOOW1BNExmcWNyMEcw?=
 =?utf-8?B?Y24xMkw4RFFNU3A0ZjhIVFFYb0VuT1NkcVdpNkNLd2Q0Q0xuSnZDdDFOU0Vs?=
 =?utf-8?B?U3BMZWJCZnhaS25vWlliRnVDbktWNkRUU3IvMXc3N0REaFhwNElBMzFFaFY3?=
 =?utf-8?B?aFVDeGlnc25yLzNMb0lyNGVPUWljcHhSVnE2QVJxWUw0S0lPVnVlQzVHd0tH?=
 =?utf-8?B?RzlZcGt4NjFnZnJ6MUNRMzZjSkY2SkgvdnZGa3Q4YXprS2tXakIzb3pZcTYv?=
 =?utf-8?B?QWQ3cG9jWWhTNjM2RGxrSGtmRWF5QjFKUGZtcmlBZm1VY2plRkhVMUVjTlBt?=
 =?utf-8?B?L002Mld0dUZVSkx0UUpPN2lwbzRicnpaYjRIWXRRS2g5MWcxMUQ4Vk1QQVcy?=
 =?utf-8?B?RnBXSXh2UVBrODdkZEx6ejgyMTJ3aU5aK3phZ0x1bHFCWnVwNGZvallBbjNV?=
 =?utf-8?B?K0orQ29BVUVMc3JuZTFxTTRWbHllTy92WEF0amZVdjNjV1ExNGlkN1Ayb2tW?=
 =?utf-8?B?S2oyTC9UOVRvWVJvbjVNbmE5MUc5aldPRy9VV05NYXBjZjgxUEhVTjl4OTVJ?=
 =?utf-8?B?SzdUemZCQ2hhTUZKTlRTQ21lSFZMbEo1ak5YRzNoTWlMQzFFUmh0dEtTbDJa?=
 =?utf-8?B?R3piRUNETzlyWWRFUU95NTRHRFRmTTdRUG5zZVZYOStIU0E3SjI4NjIzTTNV?=
 =?utf-8?B?T2ZOTnUrRWlLZTRWdHk3OXJjaDBEaktTTzlpWkk5T1NHdEtHRjVRNTNCV1or?=
 =?utf-8?B?d3UxNDRnZUk3SE9sNSs3azNOSjRQOHlOOUMySWhud0w2K0VQaVliQVJkV01S?=
 =?utf-8?B?L24vWnN6UEI0cDE5bk9KaDI4RmhreDh3K3NFbm1ENVNIRDFsM256Zm1mMGsx?=
 =?utf-8?B?aUJZb1lJSG9VSHZUOE9FSzBZRk1hTDRXZ1hkSDZ6YnB1QkwxcFYvWDRxNTZD?=
 =?utf-8?B?T2NEdzBGSnJteHBVQ0Z6YVZCTFNucC9UTnNmSmRpVy9SSnlMcTJUc0tmUUZK?=
 =?utf-8?B?MHgwVEU3dldZM2J5NUdxaExUV1RjWEc0c1I0Y3FvME5zUGRtNWo2TG45VFZm?=
 =?utf-8?B?K1h4Q2JlandwZURBRytPMVdnZGV3cVFXZ3BLNlgwUE9IMWRNQVVwYzNRWk14?=
 =?utf-8?B?TlNJM1VyNjdCeFkxK1d6WlR0bHEybmkyRU5YckF1amJKM0xsQytkZ1kyVGQ2?=
 =?utf-8?B?YXlOTVdqZEdPUTRjN3ZTWjRiTWRjNllCb1RDVTFsOHdpMVU5V2N0RE5sWUZL?=
 =?utf-8?B?MFd2QndWb0szWHJkSitTNE1adGZvYjJlblRJS2xxTEV1bnk2ZWtxNHNTdkVu?=
 =?utf-8?B?TUtWQmg2SFhsT2lGY1BIMDFVaFJiSnNKSC9XV0g5bHJKYXhIYTRQV1B1SmxH?=
 =?utf-8?B?cVdIZ3lPQXEra2dZM2ZBaXZPVXd4c3RQR3NPcTh6cWVhN1FJMGdmQzhvQXFC?=
 =?utf-8?B?R244aVh4Z0hwMjJvclRaTVRqTWJLMFFoaGVSNnRWTnNMcFF5Lzl0dDU0d3dL?=
 =?utf-8?B?MXFmT093ZG5YbVE0RElhMG40TXZrR0J2ajlNSVA3TlpldjhjVnpnSTd2RC9n?=
 =?utf-8?B?TFNWUFFLVnQ3SDRUU2hlaS8weGhEczMvZERYaDBjcHNBcVJxSE4vVUt6dUpS?=
 =?utf-8?B?UHEvaWMwOWkwYWNiUW9EZUNyN09yNUJEeFU0OXA3YVlKZjJXdlBjUnJCcW9x?=
 =?utf-8?B?K2pPd0ZoKy82SDVtV1k4T1R6TjkwV0hHNStqRkNhei8wSHlQdnpEc1VyaTlt?=
 =?utf-8?B?Q3VRbGRiU2ZLYURHbVRoQkI0NkZ4SE8xeWcxdlh5R2UwM285R0VLcEI5K2hi?=
 =?utf-8?B?ZjZseUtiR2tISkwrZWhEKzh5TjdVSkhTY1ZkOVlJajlQVGlTTDhSN1pBeHdD?=
 =?utf-8?B?aExrRHc2YU1vSHRQNUR4ZGFndldKcmlsZHNIalNpWS9DMEV5UThhMmNNOVBC?=
 =?utf-8?B?T1VadDEvTkJGU0w1N1lCRDdlczM2QkJYNlJRQ2pZZXBjZTljaHcvZjRyWjNX?=
 =?utf-8?B?Q05TZmdvWU91SjBZSnRBSXVZa0tpakNWRFg0VVU5YlBpdlVXeW02bHExUnA0?=
 =?utf-8?B?Y1pJaHczMDNieHB3OENVVkh2TE9mVTFhQXA4OEw1S2MvRmsrVkRJQWpQSGJK?=
 =?utf-8?Q?j0hNqp8spRQfF6EFFA6+2vo=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: c1d7d9c2-63aa-4455-1d31-08dd49e6d502
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Feb 2025 15:23:12.4401
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Ll196ZK8u1OAxVtdGC+oyBfK+UZmWP3yOSmWS2BJ5l5Ip4d9txHr+SMKeo3lerMjJw5bVHNtxXaDVdMbSj59sDLybwKz5+cOvAvvSPdDe2k=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR11MB6257
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dJpo0T3W;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 198.175.65.21 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2024-10-23 at 20:41:57 +0200, Andrey Konovalov wrote:
>On Tue, Oct 22, 2024 at 3:59=E2=80=AFAM Samuel Holland
><samuel.holland@sifive.com> wrote:
...
>> +        * Software Tag-Based KASAN, the displacement is signed, so
>> +        * KASAN_SHADOW_OFFSET is the center of the range.
>>          */
>> -       if (addr < KASAN_SHADOW_OFFSET)
>> -               return;
>> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
>> +               if (addr < KASAN_SHADOW_OFFSET ||
>> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size)
>> +                       return;
>> +       } else {
>> +               if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2 ||
>> +                   addr >=3D KASAN_SHADOW_OFFSET + max_shadow_size / 2)
>> +                       return;
>
>Hm, I might be wrong, but I think this check does not work.
>
>Let's say we have non-canonical address 0x4242424242424242 and number
>of VA bits is 48.
>
>Then:
>
>KASAN_SHADOW_OFFSET =3D=3D 0xffff800000000000
>kasan_mem_to_shadow(0x4242424242424242) =3D=3D 0x0423a42424242424
>max_shadow_size =3D=3D 0x1000000000000000
>KASAN_SHADOW_OFFSET - max_shadow_size / 2 =3D=3D 0xf7ff800000000000
>KASAN_SHADOW_OFFSET + max_shadow_size / 2 =3D=3D 0x07ff800000000000 (overf=
lows)
>
>0x0423a42424242424 is < than 0xf7ff800000000000, so the function will
>wrongly return.

As I understand this check aims to figure out if the address landed in shad=
ow
space and if it didn't we can return.

Can't this above snippet be a simple:

	if (!addr_in_shadow(addr))
		return;

?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
7t5yzfw3dq5stp5xjy5yclcx6ikne4vwz7d6w2ukfw2b7gr6t%40oomoynf3b2jl.
