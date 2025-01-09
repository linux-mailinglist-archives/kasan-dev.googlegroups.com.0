Return-Path: <kasan-dev+bncBD2KV7O4UQOBB4647S5QMGQEIVZXMSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id DBC44A06AA0
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2025 03:03:33 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2162f80040asf5875215ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2025 18:03:33 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736388212; x=1736993012; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=n0GN5b0noGfjsErZbC8rllOWAVTCCrQbYW83cZs6hpg=;
        b=L0YTNaREeUC6cVeNffmatW+vQU4HUlEl5lAoVy1ZtAbLOLtAkkNfh2+WXmcYMToHrf
         uVCOTJi34iHv0UCs/nxMckN5C9DGKBUvkFhgV38pJjX1Btxf6j27Gf+je2DWy36TP1Ua
         o6KOBYtDHRhWFX2HrtZQ9O9wXXxf0ERZuJCv5oMqd1l0NNEjUQdbV0esjCSapMPZ0q+X
         iA2qkm/evbF7FVv8dCXqDh6Hz+ycmlfLumBxKknvmUdht6WTp2HolWlm3N85kep4MmdV
         q0E9s/eARNU7sdhNzv0Gkyo3LROby4GkYPsLpGKRhETjqvPEKrImvdEIcWVXJJR48W/N
         zurA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736388212; x=1736993012;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=n0GN5b0noGfjsErZbC8rllOWAVTCCrQbYW83cZs6hpg=;
        b=Y4uiwnm2bplN/kBaB4BpozZo8QWtfUm8SjL4TyUeJceTi/iwffPHBMLpYJZGJ6o9Gh
         Hi0Ijb1+aoV0OW7goHVhI+GIkSb0kG+HwfNCNjutpTUzfEl4yqnbnIxbKYnO3nbEuX3S
         CmgVG+B8HGjXZLrsf9B5hovuqZtN9lyIn0lbRqtuha9fpyhHmI/n33yq7h1vFN8GrryS
         AjrGut+yoAPlaEU/PDs/v45yTSW6QVQCMBATT1rCt+p8D+d9QjX/xGHvrHEpVvXKXEGM
         T1QapvvL7wLGRLaa2uy3FM9fmqGYY8WeKlX21KbhXdVizmvKNHtVQERuullbqemaxUFO
         53ZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYFwBjvu9A18/jKPaLT4WNEtpHVkyKMIraqvnK6LGYaMcmtfox4Ry1mvurHYyBenZBwLhY2Q==@lfdr.de
X-Gm-Message-State: AOJu0Yz9lLKsRHpoVf3A9VHmleXAqanc1MdtXoKaVIQQ70lj5SpNanQi
	QPAyFdPcF54vrHKJ8JwRgLBCZ5/1Hy7+5O/+5py1y43E8t+Um7mG
X-Google-Smtp-Source: AGHT+IGebJ2K3YS945Mu5fEsRAtIAb6yByYlUWtdh8qjpw46jwjXtde5rco3QBCQijccZK0yNpGF6Q==
X-Received: by 2002:a05:6a21:998d:b0:1db:df34:a1d6 with SMTP id adf61e73a8af0-1e88d2f9153mr7876524637.42.1736388211789;
        Wed, 08 Jan 2025 18:03:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:3929:b0:725:4630:50f1 with SMTP id
 d2e1a72fcca58-72d2fb4cae1ls479460b3a.0.-pod-prod-02-us; Wed, 08 Jan 2025
 18:03:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWDweOhM5okqrafSAaFTct03gt2UMqJUdgun7/TZzm7EeFJxMJgtA59xH8RVhR3ZKQe7MOPObYzWrE=@googlegroups.com
X-Received: by 2002:a05:6a20:db0a:b0:1e1:9f57:eac3 with SMTP id adf61e73a8af0-1e88d105012mr8968801637.18.1736388210300;
        Wed, 08 Jan 2025 18:03:30 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.21])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-a31b946c5f1si10956a12.4.2025.01.08.18.03.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 08 Jan 2025 18:03:30 -0800 (PST)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.21 as permitted sender) client-ip=198.175.65.21;
X-CSE-ConnectionGUID: HHAKheY1S4K5JU8p0a7swg==
X-CSE-MsgGUID: gF7lmBPFSDytckB/1Cq0+g==
X-IronPort-AV: E=McAfee;i="6700,10204,11309"; a="36517855"
X-IronPort-AV: E=Sophos;i="6.12,300,1728975600"; 
   d="scan'208";a="36517855"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by orvoesa113.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Jan 2025 18:03:29 -0800
X-CSE-ConnectionGUID: 9YczL4khQNuXPYjjB2hwFg==
X-CSE-MsgGUID: gGz18UCeT0itJR8CLSseaA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="107870727"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmviesa005.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 08 Jan 2025 18:03:28 -0800
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Wed, 8 Jan 2025 18:03:27 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Wed, 8 Jan 2025 18:03:27 -0800
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (104.47.56.169)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Wed, 8 Jan 2025 18:03:27 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=nCpR4LCvcBPzzLziVM5A2K+ZmR6rUB4gqLaW+qGawVYItzYuc2UY9/jWY3uxk9C40LWObpjeAq20j7pSt7Ra2tOFKk0SImlpNuOOWue4ps22XFGU6YTxKWkHc8OS6QHupcY07kgmQtVgmiI+Zdao/Oa2P2DENnnC2JJ7QRMJ4Naz9dL/5YrR5P3xH4JMHX1DlchjfL+KrpSOg0Ys5kyPiqAzf201EXPTsUz4XzcksIx/obvlVeXmnll62RzcCutoVqsO+ifCfmobDHzjlbqIir0dbW4aBIl2WmARBCjjhVHAMpkGd8vLFFtHlxQYDuBYjZgBAU7Mi6CuyOwwEenoPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=C3jdtxNIkFmXRuWDpcTpdk6mMhhE8mhBRjRTqUZ4tXg=;
 b=p/W65/EY2zHgX2CIOAzUB37azo+LRNNHvSgeszRcPEg4nk+tGSKCQYcMsYAJbVyoydDLF0MyCpiq2I9hxkkWE75cV07VMd8EIMZBc0Rv//2KI5db/qp4xOZjiplfRX3t0cUc890K/IKJ0cZMyk8AIzz+rwAjKqPJ4FRVy8VfqGKFfxECwvl6C+JSoamwz93mtB3VcqSSZUyhbP6Oh9q/VI2LTV9c+hWiRSz4sbmZtSLfbVAwa9jqVnafupGtORavH7Elb+Y/SJ26aAWUE9OvH+KBJz8ZY2Suz3NfJ4zl5sWJ+Qz+mJ6I0nEVcVpBAeQYDuT1ZjtNqVO80TeESlbPSg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by CH2PR11MB8865.namprd11.prod.outlook.com (2603:10b6:610:282::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8335.11; Thu, 9 Jan
 2025 02:02:58 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%3]) with mapi id 15.20.8335.010; Thu, 9 Jan 2025
 02:02:58 +0000
Date: Thu, 9 Jan 2025 10:02:48 +0800
From: Oliver Sang <oliver.sang@intel.com>
To: Alexander Potapenko <glider@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
	Nihar Chaithanya <niharchaithanya@gmail.com>, <oe-lkp@lists.linux.dev>,
	<lkp@intel.com>, <linux-kernel@vger.kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	"Dmitry Vyukov" <dvyukov@google.com>, Shuah Khan <skhan@linuxfoundation.org>,
	<kasan-dev@googlegroups.com>, <oliver.sang@intel.com>
Subject: Re: [linus:master] [kasan] 3738290bfc: kunit.kasan.fail
Message-ID: <Z38uSJ0ut2XikMYj@xsang-OptiPlex-9020>
References: <202501081209.b7d8b735-lkp@intel.com>
 <CA+fCnZfkMuk8dtk+5_7DK_h0Pxv_JNgJDL3D-8pBXOByzVOtzQ@mail.gmail.com>
 <CAG_fn=UKrpQCQu__nJ74C4xqn5VOcYRc+hbXX5wwmLcR3oKdeQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=UKrpQCQu__nJ74C4xqn5VOcYRc+hbXX5wwmLcR3oKdeQ@mail.gmail.com>
X-ClientProxiedBy: SI1PR02CA0013.apcprd02.prod.outlook.com
 (2603:1096:4:1f7::7) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|CH2PR11MB8865:EE_
X-MS-Office365-Filtering-Correlation-Id: 25b6f45a-460e-4405-6171-08dd3051bd2d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|366016|1800799024|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?eElqcDU0UlVLQ3d1QnpoTU1ZdkdTQVNxWTJaWkNOeSsralFIS3NZVXRVUU42?=
 =?utf-8?B?ZEJBbU50TUJidEJzb2RRNzN1VEsweFpkeFE0NE96cTBsVzFVcXUreDB4K3VV?=
 =?utf-8?B?M0o3U2YrZG9hU1VMMEtKYnYyV1R0UGY3dU90Q2RwVEU4cHU5UWFGTjNxNTlF?=
 =?utf-8?B?MUo1dWk4QlBLU0J1Q3BqWTc1ODFJanlDckNRaE1peWMvT1Rib1FJYU5YQU9Y?=
 =?utf-8?B?bEVFdnVybE9sTVZKK1lyME1wYnZqQktCQk1Pd1NEcGhmSkc5eFVMdWRzL1d1?=
 =?utf-8?B?MnV0Rzlwcy91aXZ3QTRaZGRQSnVDeGx3ZGJweHg4Y0xkY3lXWGpka0pXQjF4?=
 =?utf-8?B?VkVReld3bnB1NzhKNVJQQ1RRaHc0eEl5akhTZWNlUjgvaWlqOFVxTXkwdmp5?=
 =?utf-8?B?M0FnVkJIMmdUa0pjVmtXRVhuckNUa1JRcHk4SzBjei9lTmlGVjRsV0pwMjRB?=
 =?utf-8?B?YjNUOWxPdDNIMnRWeitiV28yYzBrMDZ5KzAvd3ZVZTExNFRiOURETC9JZzBB?=
 =?utf-8?B?YVpaTHdMQmszTHl2d3VGQmtxc3FYWTQvdmpzZkJpUC8xb20yc2RmWVFNMlg2?=
 =?utf-8?B?aEFKU1dJUk9vNXQxNUdoelhTZjR6REovazc2VGVNbisxeTA3NithbzgzMUFu?=
 =?utf-8?B?TVR5K1lZUHRNN3BVSW5ZR3B0WU00SmFDQmxhUWJ4U3hHdXhRMzNSWmp1eHBO?=
 =?utf-8?B?TkxwYVVKWEd0Q1JNbzFKREp1R3Y5RGhVUEZyYTBWRVJpMUUyQWZJS0gzWkpN?=
 =?utf-8?B?UTE3Mmt3dmNkOU9RMmR5cjZ3TDh1YkRhVGRqdnpaNFNKQkVDVjdpcFA1MHln?=
 =?utf-8?B?Y2hYMTV0c1dhVG9Qd1VBL3RZMlBpRzlHZExnclJYaUlDTm8wMEQxYmVmV0Zy?=
 =?utf-8?B?ZlJCWUpvV3Z4bk1OSENHWlRZS01KbzB1VloxZVJISnBVWGNJM3NQWTRFK1Nt?=
 =?utf-8?B?Y3VBdWZhTWpMcmRxYmtxZStuRVMxOGtVbXZkSENFeXRTdjJJTnRnek1sOXZz?=
 =?utf-8?B?ZjdCZitGMGJ1TUdZYTlUSXc1SWFxSWRjWDFsMy9TaERXaVpoUlZVcDBtYlI0?=
 =?utf-8?B?SG1nTy9oN2dNRFBhV2NCeWpRaTQ0ZGdaL09USjdMMFdlMHc2ZkRVNEkyb0xw?=
 =?utf-8?B?enZMb2VjWXN5WGQ5bXFVNElhMmd2N29SOWpFMnk4THBFY1VIL05hL1FFdjhE?=
 =?utf-8?B?Y1huSEhERm1Tdm5xUGF5U0dFZVRqN2ZoSElOb0tiejJ0RUVYUkRsVnI2SkZy?=
 =?utf-8?B?UVNrVm5lcmF2SklCNXVrclpvK05UYnNiNDBEMFJuZ0xnazM1R3F2ZUp1akVr?=
 =?utf-8?B?cDkvWVd0RElERTUxWVQ5ckVUOUhCc0dna1ZuUTNhZ2tremtBUlFWeHh4UXph?=
 =?utf-8?B?YWVWSmd5MmI4ZlNYYXREWlh1U2xPZHdzMzZrRkFodWhvdEphTFU2YkRaWHEv?=
 =?utf-8?B?MEhRYncxL204a2ZtOUloZldHYTJtVHRxalNiS2lPUzdVVWxEYmkxbzR4bEFP?=
 =?utf-8?B?UlB5My96b2dINEVFdmNPeG0wK2dtYzlZbnRWSlkzOThpUG1iNDk2Q2grTC81?=
 =?utf-8?B?OVlnTnRQWjIxRFdtaXJKOVlaZnBYS1JQOSs3cWtQZ3djaE9ueWd6ZjVOdkxP?=
 =?utf-8?B?N3RDWnp0SmtYYjQ3d09hNk9mbWtXQnhvazFsYnJ3ekZqN1U3ZSszV2lsUkRk?=
 =?utf-8?B?a0hsQ1dOUTZNdVU5SmF6M054MmRDVlMxOVhkQTNTSmhvakJ2b1lSRzNOZEIv?=
 =?utf-8?B?ak9xclQ4OGpETStETEJZQTN6OThxTDNDMGJPWHB1NDI0MXN2T1FsYjNIVGFD?=
 =?utf-8?B?ZVRkNXFEYkFveUFGYUlNMyszOEExYTEyMkVjUXhORlBRV0pIa1FNWEo0b1Nz?=
 =?utf-8?Q?2fAhNoJrhcZyp?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(366016)(1800799024)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?N0FnY20va1ZRL0JHMFJhZ2hMKzhQMWFBVnQwcFdKNVB3VkplV2MxZllDWFNN?=
 =?utf-8?B?MnBaT0l0bDVaQWtoTDdqYWM5QUw5MDg0Z1BBOU1EZkJiR2tjV0NYd0p3OUlr?=
 =?utf-8?B?MzFyNHUzSm1xdDVxZTI3d3JXV0s0ZDkxYXFHWS8rdWxvOFpCdDNPZHZwMVND?=
 =?utf-8?B?WXFaRUd2V2ZTZ2dvSDlkUVN2UFZtTFRXdVpJRmRveGVOR3pVcENkdG1qN29y?=
 =?utf-8?B?UitoeGlJSTluSm9RQkw0c3B2YzVvSG9ubjl0T2ZzZWd6MldiR1ZYUFhjRWRO?=
 =?utf-8?B?dFZ4d2JCaGdscnpmUm9aMkVSTzV3UW1KZ3pTN3JKZjNoMy9XNlJwcVQ5bHZs?=
 =?utf-8?B?RGNnRm9sS2xGMEJxcEdRYzhINGQrQXIvRmNJcWt0dGl0STl1VE1wSmRFZmxJ?=
 =?utf-8?B?UmhUc001RGRSS1BwbEhWQ3JUbmIzVnRSQXMyRThORjZzQytxZ1pHWDAvQS9Z?=
 =?utf-8?B?QThzeDBEYmphMjg3cUlKTXlVTXUzOVBURmt4ZkFBVUVrRTRPMUFqVkp3WW50?=
 =?utf-8?B?ejJqVW1PZFZXR1BhVmRpWmRNOUZrZ1BEZFlGY09hRlc2aFZZenBuWmhBc1Jx?=
 =?utf-8?B?a0d4d284eDhhc1JTR2xOY1BHUE1GOHRFSzhLM1Fkak93YXNEQ3JBdmg3MCtF?=
 =?utf-8?B?NWl2RnJEODlzNWpUdkZ0MDcwcFlGRUVMMWZkUld6SXIxMkVEek1xU3dwSXNG?=
 =?utf-8?B?cS8veXN6S0I1M2huZ2xGWm91cVRMbXdBZnBtcU1TNjZjaEdiK0g5Rm4wZ2ZM?=
 =?utf-8?B?ODZjcG9uZWRyOG9tTDllbTNSZWRCWHE2b0VOK1RhaS95dmV0eWpPWjd2bUo3?=
 =?utf-8?B?WnE3NVhzRUpSQ0RDVFNxckNoUDBlTkdkNjg2bkRXMGVXbXNjdmo1VWVCV0ZF?=
 =?utf-8?B?SlJRQmZwdURuRVVzRjRDc2J3SUFodk8vMkI3UHNUbzFOQUdBM21JZXNDVE1J?=
 =?utf-8?B?bDZrcDg2WWk1THhtRUpyQ0RLWTQ1RG9DQlRTZjdLNnpuQy9uVk5TbCtXVXgr?=
 =?utf-8?B?b3FrTjNiTmRxbkt2YTZ5bllDSkR5eDF1eGVJMlU2UTNNaWkrdThVQ3k4eXZL?=
 =?utf-8?B?aTJEQjFDSjRmV3Zoem1VR2MvM0o3eW9jZUNHQU1EaEVsMS9uSG9xN2ZrSWRK?=
 =?utf-8?B?cFFGTTkzVFlrZWpwVlVma25IbUNFSVFTTXdhVWlKaUNOY2d6UE5KTXQwNTFB?=
 =?utf-8?B?UUNJR2Q5d0ptU0E3SExHdmtRbnJReG1xNXd5bDgvbXhWd0xOVHUzSVNtbDRF?=
 =?utf-8?B?REFGR0NZTEJZdXd3V3Q3bTJkK3hGWTMxSm9rQWdaMEgzNWxhMXYzcFR2K2NZ?=
 =?utf-8?B?dnVVU1RPVTdxZnFsVzdpMDZHMkZ3RGlrL0lRdlNVWHZrR2c4Uk90bElkeDFi?=
 =?utf-8?B?emJ4R0QxRVNwMEU1NVU4SXVvaVBZTFk0cFpMMjVhY1hZc3lhNWg0QTVQTkJO?=
 =?utf-8?B?UisxakIrQUdaTnhHcXQ2QUI0bCtXQzBrZlBodnB5OVJMb1h2NDRsOC8wOGpS?=
 =?utf-8?B?RkQ3Q0w5N1Nxa2VvRGpDbzd1STNkbG0vSVBiTHduTlgzQmEwdFkvZWpBYU5H?=
 =?utf-8?B?bk9jN0pWUHZoR1IvSjg3VmVRajdScU9nTCtQVW0vY3puREFncG13ZTVmVlNM?=
 =?utf-8?B?Z0x1WkVaRFI0WEhTVVdRQVk2YVhiNHlYUzFrak54Z3pUQU9KcnJIMDZ3bnZY?=
 =?utf-8?B?U3dTUGJHbndCRUVFblN4dmVmOUgyZUl0amhQNEFycHpkSmxLaEl5MThDazVk?=
 =?utf-8?B?VXJ4aFZNR0Q0QUU0UlR5UHowRklMY3N4T0dzVDFYcDlJS0VZYUdzT09YeGJp?=
 =?utf-8?B?VnhSamJXY1pscHJ3STFQRUwrWHlrT1V4K2lzQ3ZnNzU5K1pRZFhEY1lFK1Rh?=
 =?utf-8?B?RzNqdUpZeGlDNEMyT05vMEZWcXc0Ujc3VmwvYThzcUErdVdXWTVIcEd1UWJr?=
 =?utf-8?B?OUtoRGJEdExJbjBOUjJxUkphZ0JoelRBK1ZMbS9NSTJwTjFvOFAyQncyRG9h?=
 =?utf-8?B?bDc0bTNSTHUzRStrYk50SXA3TFZjelRmV080cHRWTlppZzVtRzlsTGg1UEdE?=
 =?utf-8?B?SzFJVm9BVGQvV0Nrb2pqNkE1N2Y5eXdvNTBKY1MvZlh1cW1KT09CV2ZQMWZr?=
 =?utf-8?B?em11SGo2ckhOWXIrMUZJbmZQd1hjalVIV21OS0pnQytIWXE0OHVMeStaazFj?=
 =?utf-8?B?d2c9PQ==?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 25b6f45a-460e-4405-6171-08dd3051bd2d
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 09 Jan 2025 02:02:58.1935
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: dQmobgB4LUnY7TKTSfIAbegypcQDGIfpUvXJb80Bap/cZrMfe2zBxeFhKAmKF4HIn1rEpUNXK/gA3QR50v4XlQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH2PR11MB8865
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=d+lctlAm;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 198.175.65.21 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

hi, Alexander Potapenko, hi, Andrey Konovalov,
On Wed, Jan 08, 2025 at 05:17:55PM +0100, Alexander Potapenko wrote:
> On Wed, Jan 8, 2025 at 5:03=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
> >
>=20
> > > [  118.348258] CPU: 7 UID: 0 PID: 3613 Comm: kunit_try_catch Tainted:=
 G    B   W        N 6.12.0-rc6-00221-g3738290bfc99 #1
> > > [  118.359770] Tainted: [B]=3DBAD_PAGE, [W]=3DWARN, [N]=3DTEST
> > > [  118.365490] Hardware name: Dell Inc. OptiPlex 7050/062KRH, BIOS 1.=
2.0 12/22/2016
> > > [  118.373542] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > [  118.381677]     not ok 4 kmalloc_track_caller_oob_right
> >
> > +Marco and Alexander
> >
> > Looks like KFENCE hijacked the allocation and reported the OOB instead
> > of KASAN. There's a KASAN issue filed for this problem [1], but no
> > solution implemented in the kernel so far.
>=20
> If for some reason we want to keep both KFENCE and KASAN enabled on
> that machine, we can use is_kfence_address() to check if an allocation
> in a KASAN test was made from the KFENCE pool, and repeat it. This
> won't look nice though, because we have several different allocation
> APIs in the C test module alone, not to mention Rust.
>=20
> > Perhaps, it makes sense to disable KFENCE when running the KASAN test
> > suite on kernel test robot for now?
>=20
> Looks like the simplest solution for now.

thanks a lot for information! we will update the bot to do this disable.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
38uSJ0ut2XikMYj%40xsang-OptiPlex-9020.
