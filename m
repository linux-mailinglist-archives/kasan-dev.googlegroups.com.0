Return-Path: <kasan-dev+bncBCMMDDFSWYCBBZ5DSK6QMGQEJKUR7DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D5D5FA2A60E
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 11:41:44 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-3062c49c56csf3824131fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 02:41:44 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738838504; x=1739443304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4n2Y3onKYZQ4A+dv1oK5YOl5R1wjEqVNBhzaME+7k6o=;
        b=RzM4LqMQA5NI4cLpJVOjoPDHcdikw0DpQj60N+Yu+bPaIrTU2YXAk6RvSBeTiUvnFz
         K76QxkrLvUl+YWGUuKtPqIFCTCkvhQ1PvnB6h6OPni9/QFmVGLsbOqJAn/LYCOgibPkE
         yOP4LWLPVqoaA+mzJXW3x1bwqnwb+psDJ0FLzcqBYQUaL437DF5cQrdoueHBtoX4Xoje
         nQ4GR4orJjIXRutOBIouvKGwdgyS7omuJvt+FbRjDoNCtZWXHV3HmnOwJAt3Z1o2ulZY
         VEaURmhDdz3vqHkDlcljY7nrxuJPwwfc7oq6M6z1hING9jVFXDd9BQY0/G7oDEpR9wGI
         8+KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738838504; x=1739443304;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4n2Y3onKYZQ4A+dv1oK5YOl5R1wjEqVNBhzaME+7k6o=;
        b=kJMrSoe8wF4kjlI534K5NnE8H2nJr+Ugba7Xqtln/zESCNJje/YnemlaxRYb7f64G4
         hXpPmbB0tOFeXaWgvlFNQ3rKxyDSdGB6XlAIClW/yQ7nxEsl5t8fH5az+OT+PuAocz2O
         1QDa/gvnFfvOCM8YDzLKeA1+3sgDw72dlDjjRtS/jxpxUNkQ/bO/6AdIaNOYkOnTRMJz
         RgeL7ZthcIQEc51JCavv0h2G3b+jkZ9Q5aWNsqjU5rvCSVupK6nZ2FpxAthc7WzL/CLD
         UPbWpime7GlNbKSxC63ruiOlGUltirQS1WJp1eSS0WtFg2n0S4gznBtabdXXI5EdIIFT
         /2MQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8KiPXgHSF5Ini2FP88m2yzzwCGxWf2xHREBDPsonrgzGYh5fhTtemivHthuj5jHuqfhfKTQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywf7W9uSHAcl0cL/m4cqx9BAPx8kkZCCUNgQq90DWLx+v+hxG9H
	qC0OQRUWFunT1GuWDsNh9JCr9wl21FiNqpdC7uYslHivRe+Z23Tg
X-Google-Smtp-Source: AGHT+IFlhlxGszYp4PRJQeLJ2pMSl2FlY0D1+N131J819o9uRO3orpkZaqAFFoziimZRAToSsacs/g==
X-Received: by 2002:a2e:a909:0:b0:300:15f1:cd5c with SMTP id 38308e7fff4ca-307cf314370mr27515501fa.17.1738838503513;
        Thu, 06 Feb 2025 02:41:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a99b:0:b0:306:37e5:9526 with SMTP id 38308e7fff4ca-307da119989ls1873961fa.0.-pod-prod-03-eu;
 Thu, 06 Feb 2025 02:41:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUOMS7B47w6z5nv9JP1UjGLf0nAgdLdXYlQwF8VZIP/yuVepWdAKS1r/p70KvLJZBGtMjGjzwQDEBs=@googlegroups.com
X-Received: by 2002:a05:6512:3c8d:b0:540:1f7d:8bce with SMTP id 2adb3069b0e04-54405a6c098mr1989547e87.38.1738838501062;
        Thu, 06 Feb 2025 02:41:41 -0800 (PST)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.15])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5441053eae5si14114e87.1.2025.02.06.02.41.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 06 Feb 2025 02:41:40 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.15 as permitted sender) client-ip=192.198.163.15;
X-CSE-ConnectionGUID: HQqK5eltRHu0de+qpwGXbg==
X-CSE-MsgGUID: YxvPCnaGRPiRYgwlt745TQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="39592490"
X-IronPort-AV: E=Sophos;i="6.13,264,1732608000"; 
   d="scan'208";a="39592490"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by fmvoesa109.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Feb 2025 02:41:28 -0800
X-CSE-ConnectionGUID: fl2EJeWFQWSYuKfdsNd9kw==
X-CSE-MsgGUID: tZWoD1dsTryXnEHhZpOxlQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="148383979"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by orviesa001.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 06 Feb 2025 02:41:28 -0800
Received: from orsmsx601.amr.corp.intel.com (10.22.229.14) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44; Thu, 6 Feb 2025 02:41:26 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.44 via Frontend Transport; Thu, 6 Feb 2025 02:41:26 -0800
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.46) by
 edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.44; Thu, 6 Feb 2025 02:41:26 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=bm+KAYS7zMBLS1xfZ2dlIp7Ndf67AqgYRiKOuuLC2egSp80Ywbdh3wGb0sbqgSynsqEdGId+qLygakTWh75mH5Ms5n/wpogMDOXcqWn82rCg880RJQ2GsnrepCsS3a3RG1g/ZC+KWOIQGi9Ud5tEuNtDdrB9urOohQHubdQTWSay+Vzc5bpCYEvxGgOdRCBWmAM8nxDL4kOFLK4WhxcU7XITEHGTteUaB4jjNbv2y7TnYYV9ZvIvcNAxtbAK8/6IRilsYdK7rGdv+F6B7bEVRDTGlmHErdQH/laU3TQJgzrAD84qenWJ+hNMpB6AHIxHfZ4vXMKTPPqeH36maLJw2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+hRg7MwG41ItgdNEk7FYTYq3VOix4p2CsZUnXXS53JQ=;
 b=AKjgsXTx5N+0ddawe4HQKIDZr1iuzdbn2sy6+iqLQHekvFz/dBexE/c8OM8x6jxQPDxXsAF8aG+6jKyYiOSdbv5u96LWDc8q8x7by9T3f9ZjoSwcFXpRwwPBQpLUGtCdP77ND7YBMSkHd30yyiaNTSoOlGHb8Sil5EH4/sq6D5WgTyzgI5xOSeEdzGXwKQSEPx9iSsq35eljO7bH89SRNmdR4MH5jSw5TSM0UjxLMLRfD6Q0V/5pDppc2paTA+kYGLjZNlHEzLOaNtk5SgKZT8BOJc2Pc9avN6H7dVmDpj5q0oBbIG4oK7DOr1+dJhi2NHP88H7VnITJAunfNvUBFA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from DM4PR11MB6239.namprd11.prod.outlook.com (2603:10b6:8:a7::20) by
 MN0PR11MB5961.namprd11.prod.outlook.com (2603:10b6:208:381::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8398.25; Thu, 6 Feb
 2025 10:40:57 +0000
Received: from DM4PR11MB6239.namprd11.prod.outlook.com
 ([fe80::244e:154d:1b0b:5eb5]) by DM4PR11MB6239.namprd11.prod.outlook.com
 ([fe80::244e:154d:1b0b:5eb5%4]) with mapi id 15.20.8398.021; Thu, 6 Feb 2025
 10:40:57 +0000
Date: Thu, 6 Feb 2025 11:40:24 +0100
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
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode
 for x86
Message-ID: <cj2w476ui6g6bjtrnmhozgruhudjx7dbeifxtx4q26c4sqmobt@ill63v5yc3ke>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZd1dpqv+rM2jD1fNGvhU_0+6c8MjzsgEsi2V-RkHVteJg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZd1dpqv+rM2jD1fNGvhU_0+6c8MjzsgEsi2V-RkHVteJg@mail.gmail.com>
X-ClientProxiedBy: DU2PR04CA0260.eurprd04.prod.outlook.com
 (2603:10a6:10:28e::25) To DM4PR11MB6239.namprd11.prod.outlook.com
 (2603:10b6:8:a7::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR11MB6239:EE_|MN0PR11MB5961:EE_
X-MS-Office365-Filtering-Correlation-Id: 7c17654f-9ff1-44d4-4e5c-08dd469abd70
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|1800799024|7416014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?eTZyMXhCZFhZVW8ybWNOL21CVDRpTUtkaW5KYXMrNW5rOXVVSEtUZC9nRFQw?=
 =?utf-8?B?cmdoanhhbnZkYkVicWU4cWVja1hJdWxTdEpscm9ESWwvcmdJeGlVYlFrUlhu?=
 =?utf-8?B?YmZUbVpvaWN0N1ZOL2s1V0p6QlN1OXd3MEtVVHVXdGVFV0VuTVVOVmJRZ1p1?=
 =?utf-8?B?Q2U0SlpYWjhWcVliS2IwdkdPMTFVdEZIb3hpMEUzc1F2VG41YzhoUFZkM0Uv?=
 =?utf-8?B?QnBYZlpNenFvRWdKaml4dGZwM0VCYWFoeWNXd2NMenlmaFZrRFIxWHc0TU5T?=
 =?utf-8?B?RVA5QzEvS1d2T0JTME1xMnlnKytWcWJNUjljSWVmemo1TURmelRtZkhBelBM?=
 =?utf-8?B?QmwrNUE5RnIzL0JBRVJpemdvbWpZRENWZjQySEhrRDBtRVJyUU9KdUphZExr?=
 =?utf-8?B?MGNTTkpLMVRCQkdPSFhRblRGaFZja0NVMG54dE1JN0phNUpVVkVObUVlRzYr?=
 =?utf-8?B?RVA3eVhlMXlsY0hvU0E1TUNFZGoxdktaRHBKd1lHYysxYzBKYnhEU1VDUHRx?=
 =?utf-8?B?dm04UzRmdWVaS0VBcFZ6M2c2ai9KNVNSRVovbG1jek1qblE1VmdmKzk0NFEx?=
 =?utf-8?B?YVBMdXFtTnNNQ25hVU1tN1AwNzIyMUg3b0V6cWRsMC9aRlBSNG40NGRZLzNH?=
 =?utf-8?B?UW04UWp4OHU2dGorVlhpcVpKTTlCZnYvanhJeWpSZWVRZWZ2MTAyYi9aNzI2?=
 =?utf-8?B?c28wSGVHSlJkcVQrd0p6blpoaFJsTURoSk9xV25ja2ZDdGhKVVJkZDh1Z2w3?=
 =?utf-8?B?d2tjY1ZTRStLb0FVNDRRLzFqRzdjanhxRzFERm5MeGFsemxYdEVXOC81dFZJ?=
 =?utf-8?B?N3dKcGhXQjVncmUzZzZKYjJWREV6aXd0aWE1NVIzamRxZmFJK0JVUGFrcEw5?=
 =?utf-8?B?Z2lNdkpWMjJRcU1icmNnRGtOWWIybVRVbW50WDJxSGFPQkhSdWltNWV5bGNt?=
 =?utf-8?B?dGVGL2IyOVgvVW9mdkVsa1ZXcTJIOVhPd002blc1eTMySURyNGR5b2pnOTVU?=
 =?utf-8?B?S2YxejRQZEI3T1lKNUdTSW0wNWFON01DTXREUk15aHNiR1RjTzNZUWQyUnE1?=
 =?utf-8?B?U1Y0SUFBT0ZncHlYeXA5OHR0cFpJZDg3eXljWFFiL3o2RUg3WHZySWFjL3lH?=
 =?utf-8?B?WVd4OG1xczZrUjlyalRHQUR4Q2t1YTM2QzNWRGdvUzRYdUpRSHYvTEkvMC8v?=
 =?utf-8?B?SnhVenlPRXhBYjRSNEdlRkpQMDZDMFhnbDhNT1JzZ0c1R0lJckVia3JZdnZH?=
 =?utf-8?B?QWlwYkx0M0NLSEFEbnd6aXVmVnk2VUxHclZNdTNVcHI0aHdpVk9kWnlmYlNG?=
 =?utf-8?B?Zjg3S2YxcEFXRVBpbmtqU2dZYVRHU056eXJjMTNNYUZHYjgzdkxGZXJYeXBj?=
 =?utf-8?B?R1JKZ3plbkNwWHNjMFNRTVFlMURoUWhJVEpRblFqdlcvMHZjSmlOK3k0bCtw?=
 =?utf-8?B?VXJIMW5Sb2xWaXZiUk91K293RmM1ZTJuMkdmdGc1aGNiaEZhdkI5UnJ1MW0w?=
 =?utf-8?B?ekxOeHhXWGtsQ3AzNWNyTmh5TXFrYUM3ekFIdk9veUE5NVlxaUcxcDFlOWJy?=
 =?utf-8?B?cVNwS09DbHgrTVdlRGNqTUN2cXhHWExpV3ZhTjU5aFRSUkFwMEpkSXM5d0F0?=
 =?utf-8?B?dnBYYUs3REx3VzlwZW1uczhWbkpuaWhpVjlpMTJScUd3bzlaeUJoTUYrL1hY?=
 =?utf-8?B?TzVSVWk1QjdPU1JBUVpKcmoycXA5RXdvblpNNmtoa1N2bjZOazhQays3VEU4?=
 =?utf-8?B?MUE0WEFYQ0lZQ0NvS0Z3N1hOVE5ESlVWS1BmOTVSM0J6d0dWOFcxRnM4MlZj?=
 =?utf-8?B?Yis1U1Bna3JvZjllT3pWeHdqa052djUvZytYMUdaNzZ2VFBmeWZiTW51N093?=
 =?utf-8?Q?MU+fl8fw6t5ly?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR11MB6239.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(1800799024)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?U1RoK2pUdUNQZW9wYzZjcEZOTkc1SVA5VDBvZGpYNGkvWmd5dldXeU1yL0dl?=
 =?utf-8?B?dC80YWdsNUFpZE1Lb05HVzg3SUdlNDNCdnZDVnFLc00zK2JITSt1Rk55MWlR?=
 =?utf-8?B?SjhoN0lhSXo3Q0hOUHp6VVRZUnpIdDRKTTN5M1ltUjQ2OWV0c2pSNDBqTUo3?=
 =?utf-8?B?aGlGM3JwRG0zY1o4Z0NLNWVWWTNEZ1JxY21aSHJoT1o1MStmU1JaMW9qZjl0?=
 =?utf-8?B?aHlaNTE4SHoxei8ydDVYVFZWamUweUFhOVdlSnVuanFxWFp6S0Y5alFCOHhu?=
 =?utf-8?B?ZTZjRGNxeHh4dmhYTUdTd1pJZytKcjRYVmdCcWc5TXV4dFJySDRSeTlEMXF6?=
 =?utf-8?B?bjJRdEMramphUVNONjBLNmQ1YjMrLzZuYXZ6SXV2TWVKNzFZcHRVVTZCb2xn?=
 =?utf-8?B?dVBhUE0rZVBLQitEL2RXVFF2c1QyMysvOWxwdm1nSWRNNEJFaE1oOEh4RFZ4?=
 =?utf-8?B?MlZNYXlLRmFiZWNzMklIVnRWVnAydk9OOXRibFF1MW9pdkUxaU80RnVLbEdB?=
 =?utf-8?B?bmRVRDNzdktsQ2laa3NsTUkvbzQ5dmFSMXM0ZG9WZ0oxWXlJV1R4N3pCUjVx?=
 =?utf-8?B?N0J1ZVhVNFBmU1BGaU5ibTdUcXhtVUV4YnRqdTNXcklLME5NMVJXM1U4Wlhv?=
 =?utf-8?B?N1JHQkxETnVSZ28vdk13VkdvVWNEYW9nMFIrY2ZiQ1Y4bitaV2t2MzREQ3R3?=
 =?utf-8?B?a3FscjEyMnpocWN1M0tuRWN6WWo3SlNxeGZ6UlBGK05PaW80MEtqUVBMYThh?=
 =?utf-8?B?SWJSR08za2twc0JtTm9SMmwxM1laam9GQVZNWjBXaXFrVHZ1dVpmRkpoaWIy?=
 =?utf-8?B?VDFvUTVtUmxJbS9GdDFXU2RIQUlzUVowaWpDZ1VQVFhXaTRmRVVjNVhYMHZO?=
 =?utf-8?B?VlpZeFJhWDhlU3Q3QmdKTDQrc2tVNmVIY01wamJaSGdpenc2WC9EeWJxV1JY?=
 =?utf-8?B?cEVyeG5tSk1KT3EvOWp1ZTVGNmdWa0JmdUdsM3VxL0k2d2MzWGlIY1VDRTFz?=
 =?utf-8?B?ZDlUcXdUVVFrQTdUNDFRYjR1NVY0OGpOV0o2QTg2c2RWZDl5RUlxdytKRTdM?=
 =?utf-8?B?TEtGd1ZjNzAweUZ4amdWRjJKaTFDckp5M1VKVlBWL2NCdFgvcmxIbkNUeXV0?=
 =?utf-8?B?M25wZ3p5M1pCNHhTRllFcU1yM0FyNi9NTFZmMTFGT2t3T1krakVRTEZ4NU45?=
 =?utf-8?B?OUJMM005S1cvOEQwZ3plMi9ZbVZNLzY5L0kvd0l4cHAxT3g5V0VRcVkrR2R4?=
 =?utf-8?B?N1JHNkN4b0ZJbXJzK1dsRUFYaGtqckpnOFNOSFNJdkVYQTdnWmVJdXNPMjRO?=
 =?utf-8?B?MWZzdlFKSHU4RkxHcnlRa0l4NytINmcyRStCRzFUcE05Mi9rSElaeVpZNFBz?=
 =?utf-8?B?ajduN1lZWHVkYkUxNWY5UnN6OHhyVWhmdTVUVkhZTkpqeWdLampPV2Nwd0N2?=
 =?utf-8?B?bndJZWFWZk5JczNXWDlMcHhmbHQ4cmtBMjBzSkpKaUZKRFdoaWE5cWdlM2Ji?=
 =?utf-8?B?bmVnamdFaXNFc0J0dytOZXlNbndGWm9yZS95dGx2cElpekhsdk9hNXBTMlhu?=
 =?utf-8?B?N0FtZGhlelh1M2ZEMzFXWGJwMmtLVXU4SURiOUhHSzdqaHlYOWNXWFJLTGJF?=
 =?utf-8?B?djYxaWN4OHgvaFh1aFlPRERsWUtyRlVIREJQSUVGZWFZeGdYYURFcURBbnM4?=
 =?utf-8?B?WmhmdXlXQktNREorQkgyRENVdGpFV3FYK3lSSVhQMlR1L1poaWVMNWM0UVRv?=
 =?utf-8?B?cHVaTEVjVGY3S09MUnFzZjMvSHBOdTRISHpiOXFPTnpDS3kwbllwUTlkL01U?=
 =?utf-8?B?clJaS3Z3ZmZjRFdBSEVhSExPdTIvQXpHMm44d0NrYVh0bVlFUjFWM09rT2tk?=
 =?utf-8?B?THlDeEZGVW54Mnh2Tyt4NXduT2xMQS90WmNtYnlGS2ZSQ0cwSGVud3RXcGZl?=
 =?utf-8?B?N3E4RU9DWlE5c0lqTXgzRHZWYjhHRGpRc0d0dVlpUXdxT21Sekc1MWV6cno0?=
 =?utf-8?B?VEJEcTkyYThRdVYxYTFZTlAvcmV6a2ErcTBsdHgrQzBFTTNQeXRGNUhrTTRv?=
 =?utf-8?B?OW5LVWUyVlVBNWh0Rk5DNXlLTTVzTmU1UTR0YW5Ec3hHYktKOS9seFREbmM1?=
 =?utf-8?B?bm1Idk5PQTh4RjduVXY3S0JOWXRDTVMrc1RNVFN4V1Z3TFlBZndXcWhIdlgv?=
 =?utf-8?Q?OUbI+pismLB/nodsfuXTRKA=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 7c17654f-9ff1-44d4-4e5c-08dd469abd70
X-MS-Exchange-CrossTenant-AuthSource: DM4PR11MB6239.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Feb 2025 10:40:57.6413
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: bm6ANjBbbvKdxoEHgB6YgQbjvKW3zVbvdEu28Fr5PbE2eQgR4FwvQorVlHGB5PVPBygQyBRfy4Xso2+6OcqvP0dCkJGVUZzLDVYir4grhio=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN0PR11MB5961
X-OriginatorOrg: intel.com
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BKRio1ZD;       arc=fail
 (signature failed);       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com
 designates 192.198.163.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

Hello Andrey!

On 2025-02-06 at 00:40:59 +0100, Andrey Konovalov wrote:
>On Tue, Feb 4, 2025 at 6:34=E2=80=AFPM Maciej Wieczor-Retman
><maciej.wieczor-retman@intel.com> wrote:
>>
>> =3D=3D=3D=3D=3D=3D=3D Introduction
>> The patchset aims to add a KASAN tag-based mode for the x86 architecture
>> with the help of the new CPU feature called Linear Address Masking
>> (LAM). Main improvement introduced by the series is 4x lower memory
>> usage compared to KASAN's generic mode, the only currently available
>> mode on x86.
>>
>> There are two logical parts to this series. The first one attempts to
>> add a new memory saving mechanism called "dense mode" to the generic
>> part of the tag-based KASAN code. The second one focuses on implementing
>> and enabling the tag-based mode for the x86 architecture by using LAM.
>
>Hi Maciej,
>
>Awesome work! Great to see SW_TAGS mode supported on x86!

Glad to hear that, it was a lot of fun to work on :)

>
>I started reviewing the patches, but this is somewhat complicated, as
>the dense mode changes are squashed together with the generic ones for
>x86 support. Could you please split this series into 2? Or at least
>reorder the patches so that everything needed for basic x86 support
>comes first and can be reviewed and tested separately.

I'll try reordering first and see if it looks nice. Since the dense mode wo=
uld
make some parts arch specific I think it's better to have the two parts in =
one
series for easier reference. But if it turns out more convoluted I'll just =
split
it as you suggested.

>
>I will post the comments for things I noted so far, including for the
>dense mode changes, but I'll take a closer look after the split.
>
>Also feel free to drop the dependency on that risc-v series, as it
>doesn't get updated very often. But up to you.

Okay, I was mostly interested in the patch that redefines KASAN_SHADOW_END =
as
KASAN_SHADOW_OFFSET and then gets shadow addresses by using a signed offset=
. But
I suppose I can just take that patch and prepend my series with that? (afte=
r
applying your comments from that series)

>
>And please also update all affected parts of Documentation/dev-tools/kasan=
.rst.

Right, thanks for the reminder :)

>
>Thank you!

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
j2w476ui6g6bjtrnmhozgruhudjx7dbeifxtx4q26c4sqmobt%40ill63v5yc3ke.
