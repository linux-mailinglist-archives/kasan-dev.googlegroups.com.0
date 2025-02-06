Return-Path: <kasan-dev+bncBCMMDDFSWYCBB5XDSK6QMGQEM72CW3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id DAE5FA2A8E3
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 13:58:31 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-5dcdd517613sf970927a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 04:58:31 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738846711; x=1739451511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dhpBYkvwGQEBrw8RuQdbtLZmlPvEJGXbfa9OKy8ULto=;
        b=VW63wHjuE+uzLL1mZ52rNgxNUQd+85gvv/jU44f73njtkRh9c/IZ8E59IeEPZ7nPDo
         gC83HUc8a/PgDYhhnRzU40Vrrma2qcRWCN72gU2OBsaVu+7vvJCAJewpNw68dmv9439d
         GiGv0p338nrODligCCKA+g7LAEO2cSGzWiYEWmopt5bM9pkXhmAKJQNQPURM8/WYUS87
         dB8FnVyba1mmAYjQHc5TGV3YloVqmL6SEJP7aGjEKTmOaNfrs1E6Iiyx+al4OJQ/kHj9
         JD4B4/tHz5uefzU8eOPlWE0l6+vprIjqfl5dg28xuRvjaJ9RYIvolUGiuPNcMxfuFRWs
         KQVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738846711; x=1739451511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dhpBYkvwGQEBrw8RuQdbtLZmlPvEJGXbfa9OKy8ULto=;
        b=RlJGD96GxDGcnxGs2xujxBfakBiATKbqnuzKJ4DwH+iLb82Wa6/8utcg9/jyN4Lrgg
         bR5J7iA3s1uz49oSPYQZJPz8ijJr4IPKGrwizpbmHCgzRbGyi6+t/iv+L1Pb0mBeWuQg
         vaX5LwN93XFEz3hUXsttDPw0nMVAS0TbP+zvn4dU4pK1wr7d/rM1wq6tgslhRLlI+Yap
         AJv68fnhKXf4OoWcwSBBdDS3ApiiQkaErtKXYrZmj9igqf+Vh8n4LbRMZk7VPiuabMqA
         dWWi3/9C8uG0xztVdPiwxFn7IY42Gxb1Lst/YhKyLvRbTH71eo//dkrepfZQf9GBBcsn
         Ydjw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWBdCDSO5V67ibfPPu27oA79UbTi9OuXJqd4QLMj7drUGfRhliTfzuqkQ2tspSGJfEwzL2o6w==@lfdr.de
X-Gm-Message-State: AOJu0YyjTegZzQH2zhivkiZVQomOcdhhJBg732jvxrwomNFH7XYfquco
	xd8TH2jC89rDnWFvXbPcvjRwnnQU9REn90RvmpoP1KL1oBBrT/Hr
X-Google-Smtp-Source: AGHT+IGF5SuKgKqALEEn3DW51eJxRemUeRVq1+e7xaUc3gSeJmdPPP/dN4iamTjyx3xUJJIXGh2vtw==
X-Received: by 2002:a05:6402:34ce:b0:5dc:90d8:f4c1 with SMTP id 4fb4d7f45d1cf-5dcdb733210mr6750264a12.10.1738846710732;
        Thu, 06 Feb 2025 04:58:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cfc9:0:b0:5dc:d34e:9e26 with SMTP id 4fb4d7f45d1cf-5dcecbdcd6fls161509a12.1.-pod-prod-04-eu;
 Thu, 06 Feb 2025 04:58:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUhQcFI02JbFQZMxBcDp3AFysuogq5W8++Urp69X4S+gxHd+ChvEA14YNoF5LZqz8qKpMID1PDYcwM=@googlegroups.com
X-Received: by 2002:a05:6402:35c5:b0:5d0:bcdd:ffa1 with SMTP id 4fb4d7f45d1cf-5dcdb71fa4bmr5949693a12.2.1738846708164;
        Thu, 06 Feb 2025 04:58:28 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcf1b7b164si27796a12.2.2025.02.06.04.58.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 06 Feb 2025 04:58:27 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: Ua5qecCGQ66GzJ1uDIs3nw==
X-CSE-MsgGUID: 8e0/dmJXSwSvvv0aoJgHug==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="42281973"
X-IronPort-AV: E=Sophos;i="6.13,264,1732608000"; 
   d="scan'208";a="42281973"
Received: from fmviesa006.fm.intel.com ([10.60.135.146])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Feb 2025 04:58:25 -0800
X-CSE-ConnectionGUID: ttN44p78Spuc2cv8ztNT0Q==
X-CSE-MsgGUID: 7tLQslnWQRiHeKlxYMZmMA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,264,1732608000"; 
   d="scan'208";a="111030285"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by fmviesa006.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 06 Feb 2025 04:58:23 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Thu, 6 Feb 2025 04:58:22 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Thu, 6 Feb 2025 04:58:22 -0800
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.46) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Thu, 6 Feb 2025 04:58:22 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=DMxckqGEL/bR0I31J2oPbUYgDxOFYKXlY2OzbKiGc2EISsof/A+UnH2/HFcVCWVbn74jc7SUmmnUDlNkP+NsJgz2lG949w4LiBBn19ykwxejoZnj2bAiAfv9f+NodI488R+NOb9jqZ1rXjQsoddBFP5RpBaOd1kwAe0sFvLKzhqssh8JUKEUi05I07bqiX57eTgZFG4xA+aUcH7pUlDKgJ/cXckSG5QiV9YW4DfzD0mXxfKIDoj4EonSKIeuqWZUYqqhOnmlGwtYPo/ERboZB4WX0U72CdyfPNYcwPojEiaNmHXlz4bPFksIs3w8GjsNSc6bXj0ZO4LvSaWm9d0FUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3PQtbDOswEvWlnfSu7y84F88uLmn8i2rk+bytGB5RBQ=;
 b=QdIX6NE1Yb4A7ruMLzRuuwhUf6iq7ailGizUVPLpPN66MyB/QZI8XsvMU82d277Y/7AgDHBy232eGccKZAASuEgG+IIK4Sm+8YyXe5lNdXiLQfgkaJxLYYsk6p7HTsFEamc0HslNhl3LXJgAgHSYz3CMkkCY/rQK2dyBkVVJwOy55zfnFqd4I/gIaZuqbIk2SGftBLjkMuqzTQRZ5A8a5jMO1O8Hb50thz8HBZl4tMoBhb5MwUDv0XFovQUstUB1DTWJ5TGiWFnR6OtseGh0BGWdf+DoxqmIZAAVzFPo6B+ItH1uelo32iovqBQYYHvM4IYdbzRT6Vpmm13FgLICbA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from DM4PR11MB6239.namprd11.prod.outlook.com (2603:10b6:8:a7::20) by
 SN7PR11MB7465.namprd11.prod.outlook.com (2603:10b6:806:34e::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8422.11; Thu, 6 Feb
 2025 12:58:06 +0000
Received: from DM4PR11MB6239.namprd11.prod.outlook.com
 ([fe80::244e:154d:1b0b:5eb5]) by DM4PR11MB6239.namprd11.prod.outlook.com
 ([fe80::244e:154d:1b0b:5eb5%4]) with mapi id 15.20.8398.021; Thu, 6 Feb 2025
 12:58:06 +0000
Date: Thu, 6 Feb 2025 13:57:33 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <luto@kernel.org>, <xin@zytor.com>, <kirill.shutemov@linux.intel.com>,
	<palmer@dabbelt.com>, <tj@kernel.org>, <brgerst@gmail.com>,
	<ardb@kernel.org>, <dave.hansen@linux.intel.com>, <jgross@suse.com>,
	<will@kernel.org>, <akpm@linux-foundation.org>, <arnd@arndb.de>,
	<corbet@lwn.net>, <dvyukov@google.com>, <richard.weiyang@gmail.com>,
	<ytcoode@gmail.com>, <tglx@linutronix.de>, <hpa@zytor.com>,
	<seanjc@google.com>, <paul.walmsley@sifive.com>, <aou@eecs.berkeley.edu>,
	<justinstitt@google.com>, <jason.andryuk@amd.com>, <glider@google.com>,
	<ubizjak@gmail.com>, <jannh@google.com>, <bhe@redhat.com>,
	<vincenzo.frascino@arm.com>, <rafael.j.wysocki@intel.com>,
	<ndesaulniers@google.com>, <mingo@redhat.com>, <catalin.marinas@arm.com>,
	<junichi.nomura@nec.com>, <nathan@kernel.org>, <ryabinin.a.a@gmail.com>,
	<dennis@kernel.org>, <bp@alien8.de>, <kevinloughlin@google.com>,
	<morbo@google.com>, <dan.j.williams@intel.com>,
	<julian.stecklina@cyberus-technology.de>, <peterz@infradead.org>,
	<cl@linux.com>, <kees@kernel.org>, <kasan-dev@googlegroups.com>,
	<x86@kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <llvm@lists.linux.dev>, <linux-doc@vger.kernel.org>
Subject: Re: [PATCH 01/15] kasan: Allocation enhancement for dense tag-based
 mode
Message-ID: <zwug3yr7p7x7276g5tpwsvuxefkxn2pwggozgq7krdaquqktc5@eefn3vi3tynu>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <808cc6516f47d5f5e811d2c237983767952f3743.1738686764.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZd3sP1_x2c5FvztA6LzsBY3Fq3cD5cJ6FQ+FAnmawe06Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZd3sP1_x2c5FvztA6LzsBY3Fq3cD5cJ6FQ+FAnmawe06Q@mail.gmail.com>
X-ClientProxiedBy: DB9PR02CA0022.eurprd02.prod.outlook.com
 (2603:10a6:10:1d9::27) To DM4PR11MB6239.namprd11.prod.outlook.com
 (2603:10b6:8:a7::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR11MB6239:EE_|SN7PR11MB7465:EE_
X-MS-Office365-Filtering-Correlation-Id: 9f61d69c-7158-4439-4902-08dd46ade5fa
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?M3ZzUU5wK2xLa1dPZmpYNFR6OXZMOVZGZ093WXFaMGx0ekxLRCtDL0FvTXZw?=
 =?utf-8?B?ZStIdHovbHY3NXJoSTAyTDA4dkVRb2JZMlIwRUl5SGN0eS93ZC80U0JNRTk5?=
 =?utf-8?B?a2VGM2d6Y1JYcVduU2p3QmlkTGpKNnhwbW5TeVpXYmF1SHoveWlJb3FweUVn?=
 =?utf-8?B?Ri9Pd09TaERxZFIzVGwxVzJXTThsOXJUOGtKNW5IQUZsUUIvMkRWWm1pM2NH?=
 =?utf-8?B?OTlZTVBlMSs1UGpJVll4dEhxSGdrKzlxc3pDWUZUY0RhN29KeEl0MDY5dW9Y?=
 =?utf-8?B?SktDaC96N0dtNEpUYlhUdzUrY1h0UkpPS3FJWDFVTGw4ZTJZMDNvTWhTLzhM?=
 =?utf-8?B?azczaHQwU21OeWIyZHZpTmQvWGlCMFFtRUpCWUFxYjNTVnY4UGc5R3liQkRx?=
 =?utf-8?B?bU16T1cyODFUWHlPa3phQUViWmZGb3ltbngyZmo0RFZ2WUw0b3o0aElqdk5E?=
 =?utf-8?B?WnZ3eXBiWHpyVnZXaU8wWGdZT3RISGRRckk4MEhUMzF3SC81MkgzVk1vNUFE?=
 =?utf-8?B?d3BBRmVvYUQ3SmtDMnl2NWdmQUJMTUlMdkZ5VjJxbGUxa3VSaU5zR1hQTDMw?=
 =?utf-8?B?UDY0YVdUWVFkZjR3NGZSTUw5aWdseUZNSndnQWJwOUVaTmRlM2xqT0RIaEZp?=
 =?utf-8?B?YTVhenIxc3ZZODZ6ckJodHdWbGxlMXZCVldSZnVIcUVFdkdsekJJNGZGWFh1?=
 =?utf-8?B?NWJqc01HU25QL0Zid3ZlZlNCWkhkOFJPWE14UGp6Q2xvck1qQTF6QUtibmRv?=
 =?utf-8?B?UEJmMDd3NFloR3RTdFAzZ28rdktnL0V0RTFmaEZjTnRNTUtveDFqWFFXNjFo?=
 =?utf-8?B?QmpQR001L0JmeUdkY25zSkZGcy9GL1NQUng5dDlPNWQzMlR4WFRBK0ZEMjdD?=
 =?utf-8?B?cDJxcWlIRVBDczAxV1dTeGV2K1lRZ0RFNGE2T3IvMTdkbEZoTkx5YXZQc1FH?=
 =?utf-8?B?cTFpd2dWbnNpOWl3OWZQNWVjNzNsNktUd2hsbU5yaWJWaVc5NzkzWEE0bUxL?=
 =?utf-8?B?cGk1WHVDbFg0dm0wWHIwNUlQOThVQm0rZjNYZGp2c29KSEFneXV1UGErU0RM?=
 =?utf-8?B?eWw4ZGlseTVMQkFyRTEvVFJ2b2lwZVhGdzJjUXFEOU15bENZR2d4MC9ETWUx?=
 =?utf-8?B?TzJVbm5XL1dXY1I0OGk0ZElTRE5qMjNmeldUQkEyY3pIb3lLSnYxMlE4KzF5?=
 =?utf-8?B?MjNiT3FiSEU5SlVOTmR4ZVhMcmVSb096MDh1eU5LWHp1dFhLamhjRTBmUlJ5?=
 =?utf-8?B?azA2L1FnejdlTjdwM1I5c3d0THAzYjhXZVIxQlRuamcrS0hqYU5qbGJvc3R6?=
 =?utf-8?B?cGsxWWdEbWtnYjEvaWx6RUxSM1BRVUtERFAvZ215Q2YzbnpBOVYyeFR5RzRL?=
 =?utf-8?B?Mjh4YzNaNWdhOEVGazJ5QlRSUDJjOThYN1FzbWl6VDlDYVZ0UXA2UU05WXpY?=
 =?utf-8?B?UUY1dUw0NVRkblY3blRoMkNQTFF5TVdybEwvanRpTWg5TU5jQU1na1MySmJa?=
 =?utf-8?B?M280ZEdUaDloWFk3NUVYVERhOTc5Y0ZhZUFWT0Y4dGg3bkZEa3N6bkVvdlAx?=
 =?utf-8?B?c3REdG1wTkl1eWt2QThHRjFLMkVEQVN3UFdzSTRTUjdmNjR0OU43UTJ3bG95?=
 =?utf-8?B?dDlyY3lpQVBNTGQzYVJMdzM1MjA2K0FTRkFqV2xXNDdkYjRZcDVjOXBGQjBv?=
 =?utf-8?B?emVoQUJaYXhOWkNTK2h2MWF5VnR0ZTZWYjJtYTMwNEkyUm5adUxnZHhnSllJ?=
 =?utf-8?B?QWxDYmtUc1o2UE5EZlVCMkx3L1dUMkh2WFFXNllHVVdhL3dkNVYraHVEUFdX?=
 =?utf-8?B?SlpjazBnQUhSZjYxQlVQbEtsayt3cU01Y2RLNk9BazJ2K0RQZVRPN1JIbEFo?=
 =?utf-8?Q?xNS6UoHwZYJl9?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR11MB6239.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?K1I1NGhjMXZjT2JHRkdQdWR4OVdYcm12bjBKSU9VZGszci96c20wcUlFYlJu?=
 =?utf-8?B?dUlZS3gvNzFqdTRPS0FnNmttd2Z5T0JST0ZSU2JUQ054L2VNS3k0TWlZSFJW?=
 =?utf-8?B?bU9Lelk2OXlodE0xZWw5RDJhZGt0bWR5TUhGTExRSUNGeThUMnBPejI5T1ZU?=
 =?utf-8?B?ZWlxN2ZoQm4zelY1NDRhS0x1aWsvQjBIZGQxSDhmb2Z1KzFXdUpKOTBWS0NC?=
 =?utf-8?B?NnRjekxFUWhXV0FMSXBOMlBMUmRtc3g3MFJVZXlrNGdmZjlpdmQvZXU1eEc4?=
 =?utf-8?B?dFdNY2hqU1NWaVNKS2JsYTZ5ei9VRTJJMVhOS1NJNFJxRG9KYVRLWVJWRXJn?=
 =?utf-8?B?VXhjcFNIeFZvZThDQW9iTzQxaUtTZnRyM3hTQllWTHFqeFdqem9nWTkyUlpl?=
 =?utf-8?B?YWJhaGJFVG5ERWFlOHRSeThTRFBsTWpqbTlGR01rL0N6MW1lSzd3Zng0b2NQ?=
 =?utf-8?B?MVRMbGdPViszSUFiSDJmYTBkVWE0czMwaDVJL2U0cGVadjAzTTNHaFE3WGJn?=
 =?utf-8?B?SGNwdlNvUGlCbDJicjZUQVEwZzBmc25tZE9VbWI0QXF5ZStkMURZakVISVpS?=
 =?utf-8?B?anVpT0RZZnZVZ09HMFFhL29TcjNMU0xUQU9nL1hDMkdYait1aFY1UTBsM0x5?=
 =?utf-8?B?MUFnUXh6MjgrVWMzeTk5bHdVU1VGQnR5WFhlNlAvR1FPR3ZRT3cvWHVvVGtP?=
 =?utf-8?B?c3VaRzhleW1xQlhpc3R4NWNRNTRIV3FTZEN6Q20rcUcvaGo1S2pPZFM0NGtZ?=
 =?utf-8?B?UGcxL0dJMEpjU0NTTWVvWEVZZWliQjZ0ZEhOQzVzeklpVmpBUXJweVFtQklx?=
 =?utf-8?B?VFNFSWdOOHdwTVo1ZXlWSnRWRDFRTDdIS3ZVQ3lKUmQ4NWRIN2VNSThlNjB6?=
 =?utf-8?B?aSszanllTFBwY1A2dU84bTROODdUcDZxaktkNk81RGd1bFNhUXVEakFDQldL?=
 =?utf-8?B?YlhaeC9zSkhHNmRSQU5TZTl4NmtTcTU1aHgydncramMrV2Yvcyt5ZzE1OVps?=
 =?utf-8?B?cHhORjRCMUpna1pYNFlicEZSZW9IVFNnME90a3NNZ0xjQTJmNmVnVmcvRHEz?=
 =?utf-8?B?QXJ4MDVtOGNJVGVIb3c1aFhhS0dXcDNJZzRESTV6ZTJsa0NzQ1U2VjNpYTBH?=
 =?utf-8?B?WjloejQwcTNIMVRDbXRJZ1FnUnpvZnZIN3poRkJrZGMveHNkb3R5cnEyeHI1?=
 =?utf-8?B?WjB0a3d5K3YyOHg3UWsrVUFDTXRZK2pBdm0zVmZUeVpSZHZqRXNyNEhaUEg5?=
 =?utf-8?B?M25oTVBtaS9yQ3VSejkxU0N0MFZjN1hweHJ6bEtpYzZnWUlZN1dFY3ovc2xw?=
 =?utf-8?B?eUlRSERnTkVKWXhrNkZIUlhzUlBFNjB3QmdGQzVmZUI3WG10djRMT1ViSUU5?=
 =?utf-8?B?VWxqRDEvMzJMTXYvaE5rZDk1UUVINWs5MW5QK3F5WUcrd0NLOW1jTUVDRWNp?=
 =?utf-8?B?VWVlczFmNmJ1Yng5ZUVRZFFiM2VYMFR5Vzl6YjJkajNMc3ZRcU4vN0g0cWJm?=
 =?utf-8?B?RDk5cEt2dm1naHlzcHRUV1J4T3kzL1l6Y1NtbnRBek9YYWRjNGpPS1NmUVQy?=
 =?utf-8?B?eUs3S2VDMEFNZURKclVNeFZXN2pRTFl0Z2tlcHBZNkY5bHBzeTVlak5zSGV5?=
 =?utf-8?B?VlNoRjdrRHM4LzJ4SWYvSVJWdlduUFVROUdIRC9lVU1zVW1XTU5QTUxITCsw?=
 =?utf-8?B?Y0VwSzlOT2NsZjhyaE04eWhqVE1PSnVBaWtnN0lzMndLZUlYWmJiTE9NOVg0?=
 =?utf-8?B?TTY4VkZrVmlVZ0ErblBQNlg3RjUvRG84SUYycUg3WFUyWUNtYTBYVUFLU3d3?=
 =?utf-8?B?WklZK0pGOWhQdmJMR09Md05CaEswT0pzN2JLT0FBUjZtREh6MDlNWER1Y0Nm?=
 =?utf-8?B?QVcxOTNTNi9NekRTWWpPTWdmeUdkSnovTEFSY0dhQU82RWtLcVRSbzFUSHBy?=
 =?utf-8?B?bXUzaUJnc3Rta1hDUWdheWNIWGFqWi9VQmprMWtPbkRMQUNGOVRpbDZiWTJo?=
 =?utf-8?B?Vk5WWWV3OFdyak9lYVZtUlJqRWE5OEN4dEpJLytwQVExZ2J2bE9XRjdNbzFn?=
 =?utf-8?B?SW1rUmFJNFhlT2JGNEVMb1dCSWYwWlUyNVJ6dUJCcjdUSzBSWFZMY3hGYmFY?=
 =?utf-8?B?ajZsZjdPTFVJM0FGWWJUWitscGc5ZHJuTmV0Z1FpVkJwRlNiVy9NeSt6L01O?=
 =?utf-8?Q?icNptX48dzWiD2B8/y2xlOQ=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 9f61d69c-7158-4439-4902-08dd46ade5fa
X-MS-Exchange-CrossTenant-AuthSource: DM4PR11MB6239.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Feb 2025 12:58:06.0421
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: hCJZ9Ci/6SmfQb0nmcwnv7xPL1zaIV/JoLbMQIXOb4yV+fxU1D1D6F6hAPK0/b692M5+Z8Zhmzut4gnTj2F+e11gfDmmdw/LdBYb1BqtuBk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR11MB7465
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="e0sYR/LU";       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.13 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On 2025-02-06 at 00:43:46 +0100, Andrey Konovalov wrote:
>On Tue, Feb 4, 2025 at 6:34=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> Tag-based KASAN (on arm64) works by generating a random 8-bit tag and
>> putting it in both the top byte of the pointer (that points to the
>> allocated memory) and into all bytes of shadow memory that correspond to
>> the chunk of allocated regular memory. Each byte of shadow memory covers
>> a 16 byte chunk of allocated memory - a value called KASAN granularity.
>> This means that out-of-bounds memory accesses that happen inside the 16
>> bytes can't be caught.
>>
>> The dense mode offers reducing the tag width from 8 to 4 bits and
>> storing two tags in one byte of shadow memory - one in the upper 4 bits
>> of the byte and one in the lower 4. This way one byte of shadow memory
>> can cover 32 bytes of allocated memory while still keeping the "16 bytes
>> per one tag" granularity. The lower 4 bits of each shadow byte map bytes
>> of memory with offsets 0-15 and the upper 4 bits map offsets 16-31.
>>
>> Example:
>> The example below shows how the shadow memory looks like after
>> allocating 48 bytes of memory in both normal tag-based mode and the
>> dense mode. The contents of shadow memory are overlaid onto address
>> offsets that they relate to in the allocated kernel memory. Each cell
>> |    | symbolizes one byte of shadow memory.
>>
>> =3D The regular tag based mode:
>> - Randomly generated 8-bit tag equals 0xAB.
>> - 0xFE is the tag that symbolizes unallocated memory.
>>
>> Shadow memory contents:           |  0xAB  |  0xAB  |  0xAB  |  0xFE  |
>> Shadow memory address offsets:    0        1        2        3        4
>> Allocated memory address offsets: 0        16       32       48       64
>>
>> =3D The dense tag based mode:
>> - Randomly generated 4-bit tag equals 0xC.
>> - 0xE is the tag that symbolizes unallocated memory.
>>
>> Shadow memory contents:           |0xC 0xC |0xC 0xE |0xE 0xE |0xE 0xE |
>> Shadow memory address offsets:    0        1        2        3        4
>> Allocated memory address offsets: 0        32       64       96       12=
8
>>
>> Add a new config option and defines that can override the standard
>> system of one tag per one shadow byte.
>>
>> Add alternative version of the kasan_poison() that deals with tags not
>> being aligned to byte size in shadow memory.
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>>  include/linux/kasan.h | 18 ++++++++++++++++++
>>  lib/Kconfig.kasan     | 21 +++++++++++++++++++++
>>  mm/kasan/kasan.h      |  4 +---
>>  mm/kasan/shadow.c     | 33 ++++++++++++++++++++++++++++++---
>>  4 files changed, 70 insertions(+), 6 deletions(-)
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 03b440658817..ea0f5acd875b 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -35,6 +35,24 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
>>
>>  /* Software KASAN implementations use shadow memory. */
>>
>> +#ifdef CONFIG_KASAN_SW_TAGS_DENSE
>> +#define KASAN_GRANULE_SHIFT    (KASAN_SHADOW_SCALE_SHIFT - 1)
>> +#define KASAN_SHADOW_SCALE_SIZE        (1UL << KASAN_SHADOW_SCALE_SHIFT=
)
>> +static inline u8 kasan_dense_tag(u8 tag)
>> +{
>> +       return (tag << KASAN_TAG_WIDTH | tag);
>> +}
>> +#else
>> +#define KASAN_GRANULE_SHIFT    KASAN_SHADOW_SCALE_SHIFT
>> +#define KASAN_SHADOW_SCALE_SIZE        (1UL << KASAN_GRANULE_SHIFT)
>> +static inline u8 kasan_dense_tag(u8 tag)
>> +{
>> +       return tag;
>> +}
>> +#endif
>> +
>> +#define KASAN_GRANULE_SIZE     (1UL << KASAN_GRANULE_SHIFT)
>> +
>
>Is there a reason these definitions are added to
>include/linux/kasan.h? At least within this patch, they are only used
>within mm/kasan, so let's keep them in mm/kasan/kasan.h.

Parts of x86 arch use these later (minimal slab alignment, kasan shadow sta=
rt
address) so I thought it was convenient to already have it in place here?

Since I'll be reordering patches I can just move these changes together.

>
>>  #ifdef CONFIG_KASAN_SW_TAGS
>>  /* This matches KASAN_TAG_INVALID. */
>>  #define KASAN_SHADOW_INIT 0xFE
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index 98016e137b7f..d08b4e9bf477 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -19,6 +19,13 @@ config ARCH_DISABLE_KASAN_INLINE
>>           Disables both inline and stack instrumentation. Selected by
>>           architectures that do not support these instrumentation types.
>>
>> +config ARCH_HAS_KASAN_SW_TAGS_DENSE
>> +       bool
>> +       help
>> +         Enables option to compile tag-based KASAN with densely packed =
tags -
>> +         two 4-bit tags per one byte of shadow memory. Set on architect=
ures
>> +         that have 4-bit tag macros.
>> +
>>  config CC_HAS_KASAN_GENERIC
>>         def_bool $(cc-option, -fsanitize=3Dkernel-address)
>>
>> @@ -223,4 +230,18 @@ config KASAN_EXTRA_INFO
>>           boot parameter, it will add 8 * stack_ring_size bytes of addit=
ional
>>           memory consumption.
>>
>> +config KASAN_SW_TAGS_DENSE
>> +       bool "Two 4-bit tags in one shadow memory byte"
>> +       depends on KASAN_SW_TAGS
>> +       depends on ARCH_HAS_KASAN_SW_TAGS_DENSE
>
>I think this should also depend on KASAN_OUTLINE: Clang/GCC aren't
>aware of the dense mode.

I wasn't sure I fully understood how inline/outline interacts with clang/gc=
c on
x86 (especially that I think some parts are still missing in x86 clang for
tag-based KASAN). So I understand that compiling with inline doesn't do
anything? If so, is it not doing anything because of missing compiler code =
or
something in the kernel?

>
>> +       help
>> +         Enables packing two tags into one shadow byte to half the memo=
ry usage
>> +         compared to normal tag-based mode.
>
>But adds some performance impact?

I tried to measure the performance impact of dense/non-dense but didn't see=
 much
more than noise in my tests. But I'll mention that there is some small
performance impact due to more bit shifts.

>
>> +
>> +         After setting this option, tag width macro is set to 4 and siz=
e macros
>> +         are adjusted based on used KASAN_SHADOW_SCALE_SHIFT.
>
>I think this paragraph is an implementation detail and we can drop it.

Okay, will do.

>
>> +
>> +         ARCH_HAS_KASAN_SW_TAGS_DENSE is needed for this option since t=
he
>> +         special tag macros need to be properly set for 4-bit wide tags=
.
>> +
>>  endif # KASAN
>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> index 72da5ddcceaa..0e04c5e2c405 100644
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
>> @@ -128,9 +128,7 @@ static inline bool kasan_requires_meta(void)
>>
>>  #endif /* CONFIG_KASAN_GENERIC */
>>
>> -#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>> -#define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
>> -#else
>> +#ifdef CONFIG_KASAN_HW_TAGS
>>  #include <asm/mte-kasan.h>
>>  #define KASAN_GRANULE_SIZE     MTE_GRANULE_SIZE
>>  #endif
>> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
>> index d6210ca48dda..368503f54b87 100644
>> --- a/mm/kasan/shadow.c
>> +++ b/mm/kasan/shadow.c
>> @@ -123,7 +123,8 @@ EXPORT_SYMBOL(__hwasan_memcpy);
>>
>>  void kasan_poison(const void *addr, size_t size, u8 value, bool init)
>>  {
>> -       void *shadow_start, *shadow_end;
>> +       u8 *shadow_start, *shadow_end, *shadow_start_aligned, *shadow_en=
d_aligned, tag;
>> +       u64 addr64, addr_start_aligned, addr_end_aligned;
>>
>>         if (!kasan_arch_is_ready())
>>                 return;
>> @@ -134,16 +135,42 @@ void kasan_poison(const void *addr, size_t size, u=
8 value, bool init)
>>          * addresses to this function.
>>          */
>>         addr =3D kasan_reset_tag(addr);
>> +       addr64 =3D (u64)addr;
>>
>> -       if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
>> +       if (WARN_ON(addr64 & KASAN_GRANULE_MASK))
>>                 return;
>>         if (WARN_ON(size & KASAN_GRANULE_MASK))
>>                 return;
>>
>>         shadow_start =3D kasan_mem_to_shadow(addr);
>>         shadow_end =3D kasan_mem_to_shadow(addr + size);
>> +       addr_start_aligned =3D round_up(addr64, KASAN_SHADOW_SCALE_SIZE)=
;
>> +       addr_end_aligned =3D round_down(addr64 + size, KASAN_SHADOW_SCAL=
E_SIZE);
>> +       shadow_start_aligned =3D kasan_mem_to_shadow((void *)addr_start_=
aligned);
>> +       shadow_end_aligned =3D kasan_mem_to_shadow((void *)addr_end_alig=
ned);
>> +
>> +       /* If size is empty just return. */
>> +       if (!size)
>> +               return;
>>
>> -       __memset(shadow_start, value, shadow_end - shadow_start);
>> +       /* Memset the first unaligned tag in shadow memory. */
>> +       if (addr64 % KASAN_SHADOW_SCALE_SIZE) {
>
>So this is required, because KASAN_SHADOW_SCALE_SIZE is 32 but minimal
>slab alignment is still KASAN_GRANULE_SIZE =3D=3D 16... We should at least
>hide this check is under IS_ENABLED(KASAN_SW_TAGS_DENSE).

...
>
>> +               tag =3D *shadow_start & KASAN_TAG_MASK;
>> +               tag |=3D value << KASAN_TAG_WIDTH;
>> +               *shadow_start =3D tag;
>> +       }
>> +
>> +       /* Memset the middle aligned part in shadow memory. */
>> +       tag =3D kasan_dense_tag(value);
>> +       __memset(shadow_start_aligned, tag, shadow_end_aligned - shadow_=
start_aligned);
>> +
>> +       /* Memset the last unaligned tag in shadow memory. */
>> +       if ((addr64 + size) % KASAN_SHADOW_SCALE_SIZE) {
>
>Would it be possible to move this part to kasan_poison_last_granule()?
>That functions seems to be serving a similar purpose but for the
>Generic mode.
>
>It might also be cleaner to add a kasan_poison_first_granule() that
>contains the if (addr64 % KASAN_SHADOW_SCALE_SIZE) check.
...
sure, I'll try to move these checks to kasan_poison_first/last_granule.

>
>> +               tag =3D KASAN_TAG_MASK << KASAN_TAG_WIDTH;
>> +               tag &=3D *shadow_end;
>> +               tag |=3D value;
>> +               *shadow_end =3D tag;
>> +       }
>>  }
>>  EXPORT_SYMBOL_GPL(kasan_poison);
>>
>> --
>> 2.47.1
>>

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/z=
wug3yr7p7x7276g5tpwsvuxefkxn2pwggozgq7krdaquqktc5%40eefn3vi3tynu.
