Return-Path: <kasan-dev+bncBCMMDDFSWYCBBU5DV26QMGQERDLNG7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id D0B51A313BB
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 19:07:19 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-471a0703d15sf23774881cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 10:07:19 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739297236; x=1739902036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bp/ckaz0f6kKZEPGIWiST8ZG1LXSVkUWMDRY7eYU9FM=;
        b=iK66wdb+J7BNag7IlRRlGh3TUMXopJlL8pdrLA86N7bGwyhvtnbUVf5eFltcpV0KdR
         reQABSxNKLM+MiQHZJnUy7K0f6IPSE1XDgtOQ9d0wTsYCGLpSG86mDZWylZaNlAvMVzc
         VcLhCVDSI1WkZmCleHrOJZaTMao2j+9nFbepDmAGELJpJfCM/Dt/rY8dE0Fk4hsKmAr8
         wluV1ctuUcPiLuyFJBDiiRf7/fBtdLfTDuTi7g620Dni5jjc4Hp6fsNSRP1CiyOSjWLf
         Vjl8JsDfsn8nvEjPsGKrHn/MwVAP3F8We5MW+q46xWUxpUpVXL3EkzmlTug/GEoGQRLj
         1NAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739297236; x=1739902036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bp/ckaz0f6kKZEPGIWiST8ZG1LXSVkUWMDRY7eYU9FM=;
        b=XevdVLsBkAYeiz1dBa6lAvauoe0iFticz4Y6rLNMSgo3BYKg91nINVPTXZBVZVbDBt
         auEMN3Mtg1PZ1buqSOOAbzaC/SZEVCw8I1faTglfmMP5I85UvzhThifT5g78wx0Fnwjt
         XRR43rNBQn6yitP1oTpy8jYCYUhN19HvbkzaiblSl5SX/5BPFUpCSZk2/Z2P5NbjD60k
         R7Ht0LUbpTYdsLH073Qw7OKaxR+JgJM4Oh/dDlvcgxiPIptsKqsG1tPCIDqMPi5ru47n
         nNF061o1+Zj0A3jBUdanfsgBP5c8fibTGAOCp/Q9z0I5JMof/P54vq24wjHzzBV+9eb3
         vUcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqUMNcR1XQQ3w78rORyprAESnM1NilVaVpC6x0UoAtQ2KBOFvSUJwPYTXY5QWIZkWDdwdp/A==@lfdr.de
X-Gm-Message-State: AOJu0YyZp+dZ9yhtWzUjhig2LpcCVt+3brsGoP4E4j2Va5TQVIV+gpoy
	Db9k6s67YE8hShGgMr8dOU1g0JFZQQD/KR3JaCEK6qO7URcjcbOW
X-Google-Smtp-Source: AGHT+IGMxcVTG5Jp83oSKq5gBjirAiJl7n1wuKOl1ETuIXrQAXJAaR5pI+FPFLrHq73KSSzSpxNwXQ==
X-Received: by 2002:ac8:7dd1:0:b0:46c:8380:4392 with SMTP id d75a77b69052e-471afe38603mr712541cf.20.1739297236104;
        Tue, 11 Feb 2025 10:07:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4785:b0:463:f0e:44c6 with SMTP id
 d75a77b69052e-47046cada9fls28265971cf.0.-pod-prod-01-us; Tue, 11 Feb 2025
 10:07:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWl2ypCqW6iHdhIed1JV7ACBR8P14+6DMcdf4bmoj0rqq+F9BRJnCENhxE18avBb65BTJWU3miIQnI=@googlegroups.com
X-Received: by 2002:a05:620a:24c4:b0:7c0:61be:4972 with SMTP id af79cd13be357-7c06fcd0b32mr29424785a.36.1739297235206;
        Tue, 11 Feb 2025 10:07:15 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.13])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c041e60f6csi69211785a.3.2025.02.11.10.07.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 11 Feb 2025 10:07:15 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.13 as permitted sender) client-ip=192.198.163.13;
X-CSE-ConnectionGUID: cjbq8E9TT8O9HTv4hA9saA==
X-CSE-MsgGUID: TuZXCCXJToWs/+hUStYCXg==
X-IronPort-AV: E=McAfee;i="6700,10204,11342"; a="42774996"
X-IronPort-AV: E=Sophos;i="6.13,278,1732608000"; 
   d="scan'208";a="42774996"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by fmvoesa107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Feb 2025 10:07:14 -0800
X-CSE-ConnectionGUID: Ee+KlhsyRbuGSvNcQ3gEVQ==
X-CSE-MsgGUID: EnsCil4JTCeHhclcpq2ZZw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.13,278,1732608000"; 
   d="scan'208";a="113225615"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by fmviesa009.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 11 Feb 2025 10:07:13 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Tue, 11 Feb 2025 10:07:12 -0800
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Tue, 11 Feb 2025 10:07:12 -0800
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (104.47.55.173)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Tue, 11 Feb 2025 10:07:12 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=aDBtPDllVYjWaUtX7pyODBuGGd/Eg5D/Hj+nkDAWgM1WNYXkQh2E5tvEfnIs4KNfvADcEQFwb+St1qoW+Dh9q48Willft4M/LGtOHb8b/LNT503krQ+/D3gWO81VkCdk8YXGwqFW6bvMCmATJJsSzXmLKOGyg0IkHEhDR1wtRDY5ZyF1aoDL8jx+TRlLpLWVmTgcBLZ790UluFBCWBUvUO7YG+OiOu6fdxONyS1XkxolaOnwTsMy0popfYchNO/R4nDmOGKXuK/0fhlGB5G2cnlP1VkdI2o0XU45mQ53Vr0k8XQ0gQUrsQpO9p78SClZiPyb1XbAlSZxfImozVUa6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=XGGSQwV3a1a0L2knURqhiYZ41iqTJ6DHL5eMBp6RGSk=;
 b=iIiY/Tuimeb/FPednX9UstfxgYwXE00HLMupIAUaTmZFr+KtsIo4lvJxvBOw9Y6ZGMDnpprD1/lCmWu8Q31O3rM7IMoaJvw21QyQArv/0UM4zehsiiv0Yes37/kyqG07nf63HFibpnMpXPkm7Fcfvoz9WNE7/AHTY7pXblgNzkmoOEK5mkfktlZwtyjhiOrGD2Dtdn4Lk0duAPA0U1icRWYobsT+89yoQFzWvkRO5FZEKXIf2GdLnrstyDgPxX/Dwx+KKJ/WAR1s4GgJvGUmjLmPWn2NGCpFwTWJg9emLnqDOPMLA+NavaJIHUM3UeOTihJ7g5jfCerTG0Rin/DqbA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6231.namprd11.prod.outlook.com (2603:10b6:208:3c4::15)
 by SA1PR11MB8395.namprd11.prod.outlook.com (2603:10b6:806:38c::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8422.18; Tue, 11 Feb
 2025 18:07:09 +0000
Received: from MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4]) by MN0PR11MB6231.namprd11.prod.outlook.com
 ([fe80::a137:ffd0:97a3:1db4%4]) with mapi id 15.20.8422.015; Tue, 11 Feb 2025
 18:07:09 +0000
Date: Tue, 11 Feb 2025 19:06:38 +0100
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
Message-ID: <aqhm7lc57srsfuff3bceb3dcmsdyxksb7t6bgwbqi54ppevpoh@apolj3nteaz6>
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
X-ClientProxiedBy: DUZPR01CA0315.eurprd01.prod.exchangelabs.com
 (2603:10a6:10:4ba::6) To MN0PR11MB6231.namprd11.prod.outlook.com
 (2603:10b6:208:3c4::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6231:EE_|SA1PR11MB8395:EE_
X-MS-Office365-Filtering-Correlation-Id: 744c0e24-d67a-469b-60bf-08dd4ac6e6df
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?eGdnT1Y4ZlBLT1BBL2t3bHhUS2V5YVVLOWNwdVRncEdrWTQxblM2Qzc1UXQw?=
 =?utf-8?B?dkg5V2M0UlhzR1U1OHBuOVJ0NEZRWmJPWm0rZEtJNTk2bWtRZ21RaEFoUmN3?=
 =?utf-8?B?OXhQK0xVT1N5b25CcHNmS2d3OFIwbVpYWHM3MUxJOE0va3lBKzN6QlJUaVZr?=
 =?utf-8?B?dGpDSWpteDJtTVlQemlyckRMbzVVUkY5ZFcvbDZkbXgyYVdZdjc4Vyt5T0NM?=
 =?utf-8?B?ZjVzWTVPN08vRkF5UXIvVnIxT1hQYkdKamtFRjBPajFQUUU0QkRnaWFmUnpW?=
 =?utf-8?B?V0dwd3FwYkFLSktEOEYvckxsaXB5cWg1cVlDV1NGclFLNFRUSXVrMkFlYndD?=
 =?utf-8?B?dGJDaGduUlNienVhUlBJOTI1bW5nS0cvM0IrbnFZc3V5SWFpOU9wZFBERHcz?=
 =?utf-8?B?NDlqcmpzeWJFdTM3aFQ4eGF6MTRZdFB3T0tXTndVb0ZZeFhNc09KQWp3Rklu?=
 =?utf-8?B?aXpSUVNzUCtJSmlOVkE4T2I1MGdNamtFMUh0Mjd1OXpVSnZlRG1IOVBmYktD?=
 =?utf-8?B?TzJ6djJVdDVoUGJZdEVTMjUzcy9LclNRc2g0bXJGTWg0dVMxekRTQ3lLa29W?=
 =?utf-8?B?R0ZjYlJMbjdmZzRxZWpraXdxbzRxQnhudzlsQXpRREdOcTFjVUJGMUhRUmpl?=
 =?utf-8?B?SWtWd3Z6cDc4RGJLN0VJWGVmVmtsSTV0MmFkclN5a2RsZ0hTemRvLzFZcSty?=
 =?utf-8?B?RVh5T3ZTMWtpYXRXanVlNTd3cEZsRFpQMlI2NTJCYlpENmRCQWJwQzl6Y0NI?=
 =?utf-8?B?cFNMVCtEV2dBTkkySVFFNmFRWko5YkpEWkZrVkRZaCtOUU90QmpNcDYvUFNo?=
 =?utf-8?B?TWFpV1M3SnF3UGdQOG5vbW1mNHQyUXVJZDhqRythUFd1bERsODdLOWRvYVZW?=
 =?utf-8?B?ZkVMbjdmdSt2M3lJWGNtb1E1UHE1UGd4b1ZmNTVvRnJnaWhkS01uR1JGZXVP?=
 =?utf-8?B?UURXa00yKzlDYWFEaGt1aHNvMUU5OFlRU3AvZXFMeHRCUGhHeXA0ZXh1dDR2?=
 =?utf-8?B?ZGJtZXh2aGcxTnBKcUF5M0w0OHRIc2ErdTArWGpBUWNwWlR6cGc4TVIrTlQr?=
 =?utf-8?B?d01qTnIrUUk0UGVXQVhVaVJhSkptdDlpRWE3YUFkS0dSOEtoMUZ0ZWpRQyt1?=
 =?utf-8?B?NW5UN1JhOXN5aFBnOTllQ1FLaXcxcngxeWxUbEtiNUhHWWhQYWFtUExHYUw1?=
 =?utf-8?B?RjBFOHJBMmJObWFHb243b2ZCWjNVekdRZENjM3VtcmFPN3pjS3F0VFluN2JU?=
 =?utf-8?B?VzVIcER1ZjExeGhWQ2tvQXFKZUFWSWIzUlZraHU2R3MxVVBXN25LTGdpa1JI?=
 =?utf-8?B?MWFCZ2VUWEVHSUpIUzJ4Mjk1Slluc2dxTDkyeEV1VHVRcG5mYklaTjFPWXAv?=
 =?utf-8?B?NVZmVlo0MHByaHA0WGQ4WGdCSy96ZnE0bDE3Z201RkM1cGhYWWdzaCtOZm83?=
 =?utf-8?B?UVVmYVBBcC9zaUJ4V1ZybzlRNUFLMDU2ald3SUNrSnV5WDhuUk9neHViU1ZY?=
 =?utf-8?B?NXVpRXNwMWVQRzBKOVJFZ2JSVVlISFVTVnRwd1U4TEVkUnhOTGo1enI2dnN5?=
 =?utf-8?B?aU13UmZIaHJKUVBISHRCdnQwWU5VQ3lrckZGcDhEcWVUMEpreUNDeWZUSmhP?=
 =?utf-8?B?b3VPdTlmVVRxT29YbHNQQmlzUTBhYm1wS29lTi81OFBoNGhoRHpiSElVcmVr?=
 =?utf-8?B?cmQwMFpYWVJ5WVgvZ0IzVzFzaThUeGQ1Wk0vRGxLVFp4SkY2TDYxVmgvYnRH?=
 =?utf-8?B?aTdwWUZBRmNkZUZzQjdFSVdqeG1OQ3ZQbFZmS1FqZjJlVVJoVjhFU3VpTXNV?=
 =?utf-8?B?QlVxdE82YzlvYkltNFBOeGx5K3djd0J5alFKbWs3SDg0TER1NHZIVTMxTFNP?=
 =?utf-8?Q?r9T0oODdSzcQX?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6231.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?S1RWcXhVTWd4anErZ3JmVTd6cUwxMWh6QVJFa0RweHMrVlllaW1hUzJhRXhk?=
 =?utf-8?B?U0dXNSs0S0RiK0t6WjFhOGVicEptajFrQ3dXSnptZ2JjRkM3bHZRZkVaeWpu?=
 =?utf-8?B?RnM1TkVna0FxdEtDTzE2KzZqS3dlWmI0ZWRjTkttYnVCanVWVWZZZ3JCOUhz?=
 =?utf-8?B?aVNnVk9ZQkZYekl2NnNoNGdhNXMyS0NDK2FGOElFbWhJSmZneExWWFNiWDFx?=
 =?utf-8?B?ODA5UDE4eS80WE53N3dyYjFiZzZhR0tCQTdVWmhIZVhQMmtpaU9RRWYraUpm?=
 =?utf-8?B?bFBVZFRPbnBkVCt3Q04xaXRCbFlURDRmYUFGRStBbDVmcWk1NW8rQlVUd0sx?=
 =?utf-8?B?U1ZKcWpGZjBnay9VN1NnQVIrSDhQa2xnZ1JkYXN0YnFvUGx5QW4wVTl3WDUv?=
 =?utf-8?B?SjJIZGJzYjRxaFRTdklIQnZaMmxyUzI1eVBlelNLVmRjWU5FNEFrcEtjN2VT?=
 =?utf-8?B?Wk1tUlFQNk9DREQrU2lZZUptRHJQVVJVV3NmZGZKT3FaeHVLaUxSQ3kxN3ph?=
 =?utf-8?B?bzE4dUwya1NGSnB0VlNaV3RhenQ1UWRxelV0ck82Z1g0SGtPcFFPSnhZbWx5?=
 =?utf-8?B?NGFGR0ZoOTNpYTNBdnd0cXpYR0doNnhBdFVub1cvb0FGcVVMdmhjT3FNRVRH?=
 =?utf-8?B?UitqMk56ZnhTN1pVdGJNUnZKM2RqZ0JoMWUycE9Jd29OdEYxTkRVeHNna3VW?=
 =?utf-8?B?dGl3NHk2Z2UvbEc5VjkvcjZsZG10cy9lbklWbFVWYkJ4RVg5Yys3ZkdtMGFP?=
 =?utf-8?B?Mm9HOEpYbnhQVngrVGNsWkRHRTNZNkdQZm1ta3kwTEgxUGpyUnJTWVdpb2g3?=
 =?utf-8?B?UmxXTy9ZdmR6dFp2RkM1YmNwcm5BK2owTGh3cXZnZEdMZU5YUnlSUEcvdTRY?=
 =?utf-8?B?YS9TajVUWFVwK3hBS01abDBZQ3pvTlg0MVFVQnE2RVN3NzdaTThhSm42cThy?=
 =?utf-8?B?RGF5dm4xbVlZMkZ3bWUydHBoWTI3emNaYlA4K3pHb3lMaHpuMlNOc1lmdmtx?=
 =?utf-8?B?UnoyVUQ5T0ZLYktxRlBobHlvdWlwVENUS3dmL20xWk1YMWF4MVEySmNnbCtw?=
 =?utf-8?B?NVBEYnZ2ZmZlZ0orVWxUMndCSVZJMmdma0Y4RHFrVzFUbm1lblR0TGdnNFlt?=
 =?utf-8?B?NU0yNzVTS1QxU00vd0twa240RGF6Y3RhdU9obGp4SkxESXJ1Skhia2xOdVA1?=
 =?utf-8?B?MXdpUHNQMlA0YmlZYXlhNS96RXN5UVBYU2dYNXZNSjUvcjBOeWxBaUNZRXNy?=
 =?utf-8?B?YXRPZUdNRE5YeHpDNGwvL0s3ZmMzdFVsSmIwSXA4Z1NqeWdKWjBQbERhMDNj?=
 =?utf-8?B?NDBTNzU5bjNFclpaNkthSFlua3ZYSU5POE43RUJ0QXdFLzdpcE9jdUVSMFk5?=
 =?utf-8?B?UCtqc2VKSXExS0VlNU9TT1l0d2pPb2o2SkMzZ2dURFFzbjZhNko5TFQvSDFM?=
 =?utf-8?B?RXBCVit1R1hsd2Vud1VmMGI2eGloOExDUDRvZjdQWlRtZ1h5R1lDZW1ySS9P?=
 =?utf-8?B?RTNaemtTUW4xUmU1S1gwREIvMjVRWmJqZXEyNWJOb1YweXIwYlJrMGt0c2pw?=
 =?utf-8?B?ZUN3MUxtaG1rUEFldzRwS2RiMnlFZ0Mxdi9kTWFJWGFIVThPcys3dnN2Vmtj?=
 =?utf-8?B?cGlkUjZLUm9MREJrTHlVWUprcFlISlBlRHNKZWw0a3NUK1lBdzkvZ1Q5d09Y?=
 =?utf-8?B?UGYyeFR1MXpxTm0xREE5bGM2bGtnSG1rTWlxM1YyeEdUN2FpTDRoQmF0eFVq?=
 =?utf-8?B?RWNnRHFVZ2VlRFVMNlRjd0N1a3hZT2s5QUZZVFBSZmNuUm9oZlpQQzljM0dY?=
 =?utf-8?B?NnNWU3pQcHNONy9sOWg2OVc5QjB2LzNkZlRZN050Y0x4bUxOdmlGZVUyR2lC?=
 =?utf-8?B?WVhXQ29xR1h4TGdmSW11SWd1b291WlBnUDUzeVM1UmlmTlhPd09CQzJjbERj?=
 =?utf-8?B?YzZseXo1V0d6Mmc5OGxCbnlMSk85bnQwUVhzK3FZVitBVW1YK2VPSkhBb2o0?=
 =?utf-8?B?YnlUai82bEZpK01td1lHZkZyRm5meTRBcmp5eUpQMDBqdXRnM0NCaUo1Smww?=
 =?utf-8?B?UnplUzJwUUU3V2cyVnlYUUV4UkJ5MlcwU0gwckwwUEowejlubUlpRGhUSWxt?=
 =?utf-8?B?ajRNV0k5TmJaR2IveWNycEpSQ3FuM2htVDhTaG5vU0Ywc2dsM2phZ3VRNTY0?=
 =?utf-8?Q?IunXcSC8NWf9Gcj9ORviwic=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 744c0e24-d67a-469b-60bf-08dd4ac6e6df
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6231.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Feb 2025 18:07:09.6205
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: aptKyYxRPfpOIhoGzVGPdv5C4Hgs8MsoygiTU7AtuipkZ3StJS9an7MVsvNz24nC9CZduH5Wv+JgvRNe6AZUqTNnwxDL3u1oEw/X5TmJWp8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR11MB8395
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=T0L+qyU1;       arc=fail
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
>addresses.

I did some experiments with multiple addresses passed through
kasan_mem_to_shadow(). And it seems like we can get almost any address out =
when
we consider any random bogus pointers.

I used the KASAN_SHADOW_OFFSET from your example above. Userspace addresses=
 seem
to map to the range [KASAN_SHADOW_OFFSET - 0xffff8fffffffffff]. Then going
through non-canonical addresses until 0x0007ffffffffffff we reach the end o=
f
kernel LA and we loop around. Then the addresses seem to go from 0 until we
again start reaching the kernel space and then it maps into the proper shad=
ow
memory.

It gave me the same results when using the previous version of
kasan_mem_to_shadow() so I'm wondering whether I'm doing this experiment
incorrectly or if there aren't any addresses we can rule out here?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
qhm7lc57srsfuff3bceb3dcmsdyxksb7t6bgwbqi54ppevpoh%40apolj3nteaz6.
