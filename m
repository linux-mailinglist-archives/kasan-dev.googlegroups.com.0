Return-Path: <kasan-dev+bncBCMMDDFSWYCBBS7Y627AMGQEFONVWBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 58AF1A6C349
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 20:21:49 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5fea6c35b34sf426669eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 12:21:49 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742584907; x=1743189707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=t1EYoQPUVoJsCMktODx9605tc+uglMIHXMyax23SVak=;
        b=IaQNE1UJNa38bXsFaVcZtjYA8IGHrRIaWEfsxRdtFkBpNrICFnjAd2jvTVLTfeSIyU
         u3SzNdtBnm7D4KL3LZHNbOvhzmZ7NJWB2TIjonWaAyltePKDz5PF37o1AQ1vkEcpr73b
         NFhBbgBHA67kLPiN+SRaZLh1K3dLlqtS488i9sqOR4fEMvEBSj3smYiJKNlcijU7feKX
         d7D/+PggtU/aQUKCFbe7cjKzvkO1bUwdBwy5bmdL7C+p26D6jXv9FPCRv4j7v+6K4mNC
         1pajp4QKZZvNEQJaa+qa8Anh9iYXhKo1a+Mp+c3pF5zHQK49mltAimeWbRVuOf24tmLg
         k5WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742584907; x=1743189707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=t1EYoQPUVoJsCMktODx9605tc+uglMIHXMyax23SVak=;
        b=RWYLu9aNExlmn/VQ5xoZRhn84aPoDXR0Shl+NMjsvMDLEd9es4njQsllPRh1m9F4r1
         pUhYU1mb9qmqDH9XzxWodSAEco5y6Zo0O8bgIiF3Yya0rJuYzZLGk+nlEs37ElDh80c7
         Z8XKIet2c8lLgYe1C9+cLRnZGTbg5snR99Jqc9GP3VWRVVE6KzWoEec+yr/dV8qnlY/B
         9qVc4RlhJx6w8vJASew0wwQvRJ5q4iO9nPk1SFIITDfhsCyCj8gj8fO4j6MwTWc+nIBj
         zvQsRjUW56hVa7ixaD18WCNoPKEJ8BGkLGAvKQJ1kdNJLuRJ8Y4u1kRR7X25PKOX6djZ
         uGFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV6e+LkANDkpYEGVl3UcLGUHrbaks8oSiJQnMVjWGxQMUixcZOE2CCa7U1Wy1K+tr5vLphffg==@lfdr.de
X-Gm-Message-State: AOJu0YwUoXXzf/knFs0x64+2OlMVf+POZM3J+lVjqNv5jprxcQPbbbpX
	xaYlgMaXw0Greiodp1uGkFb2QxgcLYLYFXMBbky8XwCanXVFiUi3
X-Google-Smtp-Source: AGHT+IFgjUm90rI/jtGH1y/PCewff8WEP2zcqjtE4SkNKAZdCGyKKcs7QwgP8XFG2GGaaJippO/RaQ==
X-Received: by 2002:a05:6820:4481:b0:5fe:a12d:46cc with SMTP id 006d021491bc7-602345dc38dmr2282506eaf.4.1742584907481;
        Fri, 21 Mar 2025 12:21:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALcJsyCzbhO3Dxt6+VdxvGmw3M5E6JCqHaej6GtvEHA4Q==
Received: by 2002:a4a:a5c8:0:b0:602:caa:ced0 with SMTP id 006d021491bc7-602295f1d3als647875eaf.2.-pod-prod-04-us;
 Fri, 21 Mar 2025 12:21:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWv4YDlgQKW6TG91Lmk2eRwxGlWoEx84KrYdS+MXyMrVvmq7KzJSWsI8/SEnxuQ1fELJ6wmTAhCxeI=@googlegroups.com
X-Received: by 2002:a05:6830:6019:b0:72b:a61c:cbb2 with SMTP id 46e09a7af769-72c0ae5b5famr3431585a34.10.1742584906517;
        Fri, 21 Mar 2025 12:21:46 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-72c0ac77f94si132749a34.4.2025.03.21.12.21.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Mar 2025 12:21:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: k1hQdwzmQce8C7oNNrKjhQ==
X-CSE-MsgGUID: qTaFSOCJSAGsvWIQzPi+ow==
X-IronPort-AV: E=McAfee;i="6700,10204,11380"; a="43027284"
X-IronPort-AV: E=Sophos;i="6.14,265,1736841600"; 
   d="scan'208";a="43027284"
Received: from orviesa005.jf.intel.com ([10.64.159.145])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Mar 2025 12:21:44 -0700
X-CSE-ConnectionGUID: 0Mv5jk+bSGCFW7MyVJUK4Q==
X-CSE-MsgGUID: k8tzk4bASouzZmRTW2RLRA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.14,265,1736841600"; 
   d="scan'208";a="128707246"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by orviesa005.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Mar 2025 12:21:44 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14; Fri, 21 Mar 2025 12:21:43 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.14 via Frontend Transport; Fri, 21 Mar 2025 12:21:43 -0700
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.172)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Fri, 21 Mar 2025 12:21:43 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ZplJhzmenNRKp3KMxDgHiAe0V03Adt66iTJcG4CsAYlbSD72VUwh2I6QMKEW+rkDBhvAzCSj3jykjCnZMURcQD0XXC17uWk6ynm8hMVaaJayjiAOhhEW6zdhfjvyDkl5By0D6L6mWZ95J1uAJ+MFbFdV5RBgWS6IUH69iBqnlBWrhHZbCLZwS2luswnIJ+lSPFyc6TKRHNM0hvM8+zAUVvvuQnf1lJO8su/FqCnzcuOHaLy75zvTWRcdOnpX00fvAPwN0d2q7uYRcvThP2aLf554ce4q5eYdQmX7dotyOx6d6Ll5/4AP6w4M82JbQrffsBRbrClZBKi1qFCIGWci7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2IdvR9dmFg2NgNNfai0tjWD/N+wQKGeqh7xtFKh8dfo=;
 b=yYYP3Z0itaZkBwB0Pjw9sc3yCLEHIqrVK2BkZFYGrWZz4SaezaoCSpHN0jzD/xMSnrPxsAbzLZG/BulQEEoSw2Z6pRTsnzcZm2xR7U66SMAHtBZxZr5F8py8zNXAKOzaY3/EcOk92KrVxHzIVHZ0hIk8sCS/Pb61ncPKXbMK65Ls9tUfCQJReMihRqjeuZh+/H7Ph7HOWGp7Cd/15VlvA52cSMgigJgxPSCiOVfrlHF8vXTuTqhPc4OrDEgGJoE8deXpsoTYecqAB4UgCT10H5e6svNacVqH/5XLOBWiB3b/4RwIkWNSPTOAFH3zL8S9AA0qPQlE3NOzN4MHopEC7A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from DM4PR11MB6239.namprd11.prod.outlook.com (2603:10b6:8:a7::20) by
 PH0PR11MB5830.namprd11.prod.outlook.com (2603:10b6:510:129::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8534.34; Fri, 21 Mar
 2025 19:21:39 +0000
Received: from DM4PR11MB6239.namprd11.prod.outlook.com
 ([fe80::244e:154d:1b0b:5eb5]) by DM4PR11MB6239.namprd11.prod.outlook.com
 ([fe80::244e:154d:1b0b:5eb5%6]) with mapi id 15.20.8534.034; Fri, 21 Mar 2025
 19:21:39 +0000
Date: Fri, 21 Mar 2025 20:20:51 +0100
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Florian Mayer <fmayer@google.com>, Vitaly Buka <vitalybuka@google.com>,
	<kees@kernel.org>, <julian.stecklina@cyberus-technology.de>,
	<kevinloughlin@google.com>, <peterz@infradead.org>, <tglx@linutronix.de>,
	<justinstitt@google.com>, <catalin.marinas@arm.com>,
	<wangkefeng.wang@huawei.com>, <bhe@redhat.com>, <ryabinin.a.a@gmail.com>,
	<kirill.shutemov@linux.intel.com>, <will@kernel.org>, <ardb@kernel.org>,
	<jason.andryuk@amd.com>, <dave.hansen@linux.intel.com>,
	<pasha.tatashin@soleen.com>, <ndesaulniers@google.com>,
	<guoweikang.kernel@gmail.com>, <dwmw@amazon.co.uk>, <mark.rutland@arm.com>,
	<broonie@kernel.org>, <apopple@nvidia.com>, <bp@alien8.de>,
	<rppt@kernel.org>, <kaleshsingh@google.com>, <richard.weiyang@gmail.com>,
	<luto@kernel.org>, <glider@google.com>, <pankaj.gupta@amd.com>,
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
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
Message-ID: <t5bgb7eiyfc2ufsljsrdcinaqtzsnpyyorh2tqww2x35mg6tbt@sexrvo55uxfi>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
 <2a2f08bc8118b369610d34e4d190a879d44f76b8.1739866028.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
 <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
 <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
 <CA+fCnZcsg13eoaDJpueZ=erWjosgLDeTrjXVaifA305qAFEYDQ@mail.gmail.com>
 <ffr673gcremzfvcmjnt5qigfjfkrgchipgungjgnzqnf6kc7y6@n4kdu7nxoaw4>
 <CA+fCnZejp4YKT0-9Ak_8kauXDg5MsTLy0CVNQzzvtP29rqQ6Bw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZejp4YKT0-9Ak_8kauXDg5MsTLy0CVNQzzvtP29rqQ6Bw@mail.gmail.com>
X-ClientProxiedBy: DB7PR05CA0026.eurprd05.prod.outlook.com
 (2603:10a6:10:36::39) To DM4PR11MB6239.namprd11.prod.outlook.com
 (2603:10b6:8:a7::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR11MB6239:EE_|PH0PR11MB5830:EE_
X-MS-Office365-Filtering-Correlation-Id: ac6ee51b-b671-4386-152f-08dd68ad9a99
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?YkJiVXRQRkJrQWV3MEdPV2VNczRBcENZalE2K1NqSWpORlVrMzIzZzIzaU81?=
 =?utf-8?B?aVpsM25UckdyY3ZqYllIdlhkdm4wRGFPWm1kVGlWZlNySzFnVGRrV3ltbU0x?=
 =?utf-8?B?bVYrdGF4bDdTd2RVV2JNMFBtYlhCQkdDeFhSaG43K1lIWXpmM0FVWjhtYUtI?=
 =?utf-8?B?eWZteDN3KzBzNys1ckR1UGJHR2NDcE5kcUlvUG0yUm1hRzU4RHVET0FvTWxZ?=
 =?utf-8?B?SkJnOUFMQjN4TVNFTzJkTURSbEM5NlJKZTNMdTFVQUV1WUJsV0hNY3hHd2V0?=
 =?utf-8?B?NVhEaGVRa1ZnM05FZmhCTGNlZ3JMVHJNUmgzWEtvUStCTWtKTWhqYkNNTzht?=
 =?utf-8?B?NkN4U08wQ3k3VGUwdFdwdE5JeFord3Z4aDRBQzNqVGxUWlExTGJsTnFab1hz?=
 =?utf-8?B?T0xPUXU2a2Y0R3BSc3ppN3NvU0NjTWNUdllWamMwZXM0dDNwWWFhVmR6R2Ux?=
 =?utf-8?B?ZUs4d0ZkeFQ2NTB6eWpwQmRHSE5QZnFwMUw1T1lLSUxpc3RzU3QxdTNzOWRM?=
 =?utf-8?B?N29URk1CN1VNZzR5SmJnemlGdkwrU3ZKdnRnRTdpaElEMFdWMU9PVWlHTUhH?=
 =?utf-8?B?WlJjMUlpN0N1V3c0dlRkdFlMK291ODdKd293dGdYd3gyVk14KzZTRlAzekZn?=
 =?utf-8?B?aDJjTEhZYzJuNWZkemVKOUZyc2xMQytsUEkyYzF1Y2Y5VkMzQ2krVTNaeFI1?=
 =?utf-8?B?NGFNclRKcCsveFJJaFRFWVdqMGlaN0NoUG0rYXcrUTZTS1QxSkxVOTk5U0JB?=
 =?utf-8?B?ZFJBR29LaGRKRi9TNVQwa2VBamJ3LzZvWkx0VTF0MzJ0Nk9mcVhwSnNlRnVT?=
 =?utf-8?B?UG9SK01XSUErcXgrTzRGNTV6RFJNUFVKZkRyZUNuaTd4UVdacm1yZkdDZS9I?=
 =?utf-8?B?UFJoTFE3TXRRbkpSUW1Ub1gzSTFaZGJvVDFtQlJyWG1FTWpndHZKdUNCdzBh?=
 =?utf-8?B?TG1QMTlHcVFzc29MMjJaem52Qys4MW1rSFlMQVpLQWtNQ0doNkVyL2o1MjE3?=
 =?utf-8?B?ajJ6MktLV1ZNbnBnVTBWM2F6SWJyRWVkT0o1WnJFNm4yb3RQa3RScDdHS2Jm?=
 =?utf-8?B?Q3Nxa3hZQkpTUFYzSHdSNDNsTWZFcTBQZnRTcmVDT2N2MFoySCt6WWoyU2c5?=
 =?utf-8?B?T1d0SlFoWG4wdEROSmRiNGd2RjdWWWRPQ3JYT1ZlOGFzN1V3c3V2UjgwYytE?=
 =?utf-8?B?Z3BuUXR3Zk14Zi9WaE1vRnNTS2o0dTE4WnZsR2g4NGhzejdmN2tNT01XK0N5?=
 =?utf-8?B?L0RmQkxreHlwZWhScnd3Q3prQnpCYWlmbkZPR2RTMDVwYjJGeUJzcU5MNGI0?=
 =?utf-8?B?RHBsZ0txYnVPOElqR25zN3BjQm1PMVp6bVp4SFpNSXJCRWRIZWNRdExrbk9v?=
 =?utf-8?B?dm12RmxJVGZ5cDFGMUk5NDRydVk4emQ0dU5ieXB1VVFSelBIY0crcGNhV2hS?=
 =?utf-8?B?TkNVeDJ1OTBRWjAyeGducG8zbWFqRGZFZ1FpZFhrZ1N0SVc1MDQ3K2l1WkJH?=
 =?utf-8?B?RlgyM1gycnUzNTJyRzlLZUhmcGM3eThFZmhNVVNYc3lUbVFMeVhsV3c5UlBH?=
 =?utf-8?B?SWVLNnJjWGtFTTVNbnYyYUU4Ylc1SFVDU0NzdEk3YzJ6dTR0MXhLZnJ2QUJW?=
 =?utf-8?B?aHR6N0VwUlVXK3h5MDNqZityWDdMTmcwQlVrcjdPaU80QkVBelR4TXZZcDNt?=
 =?utf-8?B?RXFtLzg5ZXJLVVZhNmJQeTMybDFLVFFtVG9pNUZNK1UxUG1mZ1hCRmpVNytl?=
 =?utf-8?B?VFJuYTVFTmRTd3NmYzdvVndaSE0rdXBxYVAxZzIybDNoaGtyTm81MVhXSUVV?=
 =?utf-8?B?bXU3dllVd1kxbHdTd0tMQT09?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR11MB6239.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?MW1OMjR0Y3hKQVo0QTRKcncxdHlSYmdyRTkwWGsxenRUZUR5WG12WkNoRG52?=
 =?utf-8?B?cVY5djJIR0o0cGFTZmRlT1dyZEpnNVBiQXphaFAzL2hDNUtnS21TcnluWXhX?=
 =?utf-8?B?clNrMU1sTDBZN3pWYXJpQ3Q3WXV6STQvZzB1YjlNdlBGb3d4RS9aaGJ4Smg3?=
 =?utf-8?B?VGZURjk2b1hmVUcwcUJqTlBlVG9aZlBpL295TkdUR3Yzb1VTZy9WTVZSVTZE?=
 =?utf-8?B?cXV6YmdnY1FSUnp1Z3pNOXlxSk1PSksxRlcvNVlFaFVqQWQ3d2tRVkNjUWVK?=
 =?utf-8?B?Q2FqNjJMbk95ZGJRVWN6RDZDejl3NUlGWnAySjNXYXNLb21aZk9nTWZEMnV0?=
 =?utf-8?B?THpmVGZORXh6dXVybm1TMmZjaFkybVNiaG5WUTdNTWRaN1JvSUxzTTZRYmd1?=
 =?utf-8?B?RjRDa1VZR29IYXlYUnFRcEMrRktRMHlkeFBPZWlkQXRwV3M1WVlkN09PS1k3?=
 =?utf-8?B?dGJYRmwwcCtJMSs0WjZwbkdONkZNNjdRSVBlc3Y5bjc3WXRJSkkxOWtzZmtM?=
 =?utf-8?B?eTNwU3VOOE1ObmpINXcwQXF5OVBENEZXYko2RDd5R3RjdUJoQmtVcmFVWE0r?=
 =?utf-8?B?T0xvbEdqdlRVT2hvc2FiUG0yU1BXQUpZa0ttc0hPK01FUVg3Wm9oNWE1T08z?=
 =?utf-8?B?UWhpYk5vYnd3NnlhNVVnc2UvMy80a3JSeCtUNUJOYnFHZGFKTytkMmxycjNB?=
 =?utf-8?B?TDVqU3JWYWhsRUcwcG1qQTcyZnEzL2tzbW9hak1QYy9UVUpMa0NvdUxLcWM5?=
 =?utf-8?B?UzhtK2k3T1o5TFh0Z3NHZ1pzcklFbnRWcUVjMkxZcCszdnNWUXJRTldyaXVT?=
 =?utf-8?B?Vmpld2VtbXI3QXZjbHRxd2NQWHBFZ0xTT0lTV2xTcXdZNVJzd0ttOEp1c2pM?=
 =?utf-8?B?R2RjOWJKN3VjN08va3dpamdDVU1VRW1HakVLdWJqV3BBYVJJQUtDM3VYVGJC?=
 =?utf-8?B?cnY1Z0JCVGxmSllZSkdhTWI5WDJwRmRtNFJySmFHUXBxcmxIVEpkcHhHek9n?=
 =?utf-8?B?a2JKZ3BXWWh5YVFQeFpYYVp6a2NleEdYZGpoT2dTcUxjdDNCbzM3RG9lYWNG?=
 =?utf-8?B?MXFZNjk1RGlFL2pvUzZMZVhPUVlodjF6T2JEZ2Mva1MwTWwwTUhERnJINUNw?=
 =?utf-8?B?SmtOejNrck51YkdZTmswTzlrMWpMRkNBZElJV0ZWcForZjJqK1VzNEpTaGRZ?=
 =?utf-8?B?ZzczTUIrNDB1TmJyNk1tUTBNV0F0YlNTMVQrQTRzT3ZzRy9wcktHNStaSUx6?=
 =?utf-8?B?Y1pVd1AyK2lmNzQ0Vm1Va2UybmpvNkliUWdRY1lBbDlwUWdwWFhzMnZsVnJ3?=
 =?utf-8?B?U1NUV0x2OGpNWUZGNndXbEVtY1lIM0lnemtLbkhEWjV4bWNJb2JHTEwvcnR5?=
 =?utf-8?B?dHZ6TUZNVkY3bEI3b0kvUCt6ZnhWV2VFZklXNnVjS0k5THk0SWxVU09oTU9L?=
 =?utf-8?B?akk5RXI0UmlsY1hmV0xWRjNpS0RGWmhmc0Q1OFN2bGVVVFRXblpBbWJwS0Mx?=
 =?utf-8?B?ejlKYWNsS2FPSWdoa2dNZ1o3cXhKeW5sMDdtdnFmSUFxYWxJSGVDeXRBTm1I?=
 =?utf-8?B?andEVU9GMDVVaHhMbmhjT3NZN3dpdXpXYzVZRzJwYWF4R05ZMitKaDI5bXR0?=
 =?utf-8?B?KzBmdVI2RDkyL1pjR1h1MlRWcXZlRVVkRktIOTNLcWs5VTdveFM4YWV4ZnFz?=
 =?utf-8?B?M3g3ME05RWVEMDkwazlJaHpJSDdaMEdOWjdaaU8xUy9kcFpCWVNWMm96VEpN?=
 =?utf-8?B?bWh2dHBYYjZNcC9rekhyWmpBNXE4czN4SWFjRFNFdUF1a2RSd1hWOEdlM3Jy?=
 =?utf-8?B?MnJiREphR1MwZDdhMGY5OTh6REpKbGN5ZkExaFhJY0hydzdSSUZPMS9KOE03?=
 =?utf-8?B?WUkvRU9lcmpyaGp4NlB3a0hXb1BSYzVRSTFlU2RnZ1pSdHNneFc2SGcvWlFq?=
 =?utf-8?B?MzFTVXZzdzE5RWt2bU5Id1NrWEJQVklPM1N1TTFpYm5MY0swOHNaUEhvZ0Nl?=
 =?utf-8?B?ZXRTYks2SWVxUEpIczJiSDI3NUtmcEZFZERnaTRTTGgwd2dxMFBvbEJ1T0RR?=
 =?utf-8?B?S0pLS3BscTB4VGtuWXVIalAwWFhXMGdQY2dXVFRuQ2RrVmp0Qis3V1FyOVJa?=
 =?utf-8?B?TVNNem8wVTZJWm9xeFhzSUV2SXRVMmRPc2trdkxTS0FDaDUxZ0hjVkhiTEVX?=
 =?utf-8?Q?fVq1OB1X5txiIaDwyycE8s0=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: ac6ee51b-b671-4386-152f-08dd68ad9a99
X-MS-Exchange-CrossTenant-AuthSource: DM4PR11MB6239.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Mar 2025 19:21:39.1858
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: OPGaikMLTHlQaEz1OREOq7rqlwe9PQDJ5cBdY0r7XGXzm7T8OfvffucktJA+hMewZsTUZJ5ES+Iig9W4tAqjQY94MfPmOWA9OIVlizAoli8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR11MB5830
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=FrLRhgYw;       arc=fail
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

On 2025-02-26 at 16:24:28 +0100, Andrey Konovalov wrote:
>On Wed, Feb 26, 2025 at 12:53=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> After adding
>>         kasan_params +=3D hwasan-instrument-with-calls=3D0
>> to Makefile.kasan just under
>>         kasan_params +=3D hwasan-mapping-offset=3D$(KASAN_SHADOW_OFFSET)
>> inline works properly in x86. I looked into assembly and before there we=
re just
>> calls to __hwasan_load/store. After adding the the
>> hwasan-instrument-with-calls=3D0 I can see no calls and the KASAN offset=
 is now
>> inlined, plus all functions that were previously instrumented now have t=
he
>> kasan_check_range inlined in them.
>>
>> My LLVM investigation lead me to
>>         bool shouldInstrumentWithCalls(const Triple &TargetTriple) {
>>           return optOr(ClInstrumentWithCalls, TargetTriple.getArch() =3D=
=3D Triple::x86_64);
>>         }
>> which I assume defaults to "1" on x86? So even with inline mode it doesn=
't care
>> and still does an outline version.
>
>Ah, indeed. Weird discrepancy between x86 and arm.
>
>Florian, Vitaly, do you recall why this was implemented like this?
>
>To account for this, let's then set hwasan-instrument-with-calls=3D0
>when CONFIG_KASAN_INLINE is enabled. And also please add a comment
>explaining why this is done.

After adding this option the kernel doesn't want to boot past uncompressing=
 :b

I went into Samuel's clang PR [1] and found there might be one more LShr th=
at
needs changing into AShr [2]? But I'm not very good at clang code. Do you m=
aybe
know if anything else in the clang code could be messing things up?

After changing that LShr to AShr it moves a little further and hangs on som=
e
initmem setup code. Then I thought my KASAN_SHADOW_OFFSET is an issue so I
changed to 4-level paging and the offset to 0xfffffc0000000000 and it moves=
 a
little further and panics on kmem_cache_init. I'll be debugging that furthe=
r but
just thought I'd ask if you know about something missing from the compiler =
side?

[1] https://github.com/llvm/llvm-project/pull/103727
[2] https://github.com/SiFiveHolland/llvm-project/blob/up/hwasan-opt/llvm/l=
ib/Transforms/Instrumentation/HWAddressSanitizer.cpp#L995

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/t=
5bgb7eiyfc2ufsljsrdcinaqtzsnpyyorh2tqww2x35mg6tbt%40sexrvo55uxfi.
