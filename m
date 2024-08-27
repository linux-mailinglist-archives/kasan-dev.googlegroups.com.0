Return-Path: <kasan-dev+bncBD2KV7O4UQOBB2X7WW3AMGQEEULRHJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id E7413960302
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Aug 2024 09:27:40 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2d3c6b19444sf5904946a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Aug 2024 00:27:40 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724743659; x=1725348459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BGISLO96ki+7Ory5rtsk9lLyWdCmKp3IrY1Mrq3cRbw=;
        b=JzKFMqQddQlr/p5BeyoPQd7gVhUFlLYn7y2OETnIVITVC+4VLgOmx6sH8EwlvJDDDT
         MGJS/VyPvbcnFA+LHji17MRufgmvXHT9aI6uNJZKmQPG26+u2RxL5lF5VhZbYPOpj53J
         gMq4WaMcsmXHyhXRyZNuWCmwp38lPJLiBZtelCQlXyF6K8ONSNgzZ9G+CaBWRLN3scnE
         SMUf2Mlp3NIK/H3URjdstCXzc1kBDabZkBxyCfG8T9Uy7+V5KIsEuzAr2LIMKPjEYcLH
         vT49MeC+kePn3PHlmSt9lD+HAdaVu04hoN4cDH17TABcu6m53LiN/mJ/siPCUSoEayxG
         uI7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724743659; x=1725348459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BGISLO96ki+7Ory5rtsk9lLyWdCmKp3IrY1Mrq3cRbw=;
        b=TKCOJHTuBR/TeyvIANHma/GgFASido7rBoxJ3I2QM+yNpoojPNcGl7S5eGmxhsnlnw
         YEQjBVVOyFWRgeToP4iK7Tv24AeoUNSoL4rsO8DNBJhF2B6KuchXVtKY4ip4tFVmFwo9
         0OzZkctx5+n9zr4HNbicYSsSpuYieTRB/GHUB+csG6jNsk2dlCEnbUUX34uDoeQZJ7zM
         vNHaLBzIPciDpOi4LGfQE8s84tYmSKCRNUAc5mHsp6P7/arOd6j/7bHwMASRpcmlY8AK
         yKMYhttLSL2kSdJK2snM+l1r2ntsedUXv0iUFkL+fX8YFX7NHUK5TTxXDvyHviW5FWxn
         eT+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOwqPlPb5MYG5snlzoWB39MTYbY2LtUBSomtweozDkNH46Q2knx6iET0UCxBrBfFn6Wqv1vg==@lfdr.de
X-Gm-Message-State: AOJu0YxlliWhTZj4CSwLYoCAZWlCw8mSb0LgQA1agMLS6oRot3w4gbBt
	beZMwXhBeXrQ2gxAUVbKmcCbrOwZ78uNCS5DIsUFxvW3FPv0RNd0
X-Google-Smtp-Source: AGHT+IGKAB4IwclOgs5YzX/nx+f0jgq6rHJIkCvFRO5MYQ0f/KYYFxPwDObRfkqS1IencdWLzRAJNg==
X-Received: by 2002:a17:902:ecd1:b0:1f7:1655:825c with SMTP id d9443c01a7336-2039e4ca7c3mr126420635ad.36.1724743658851;
        Tue, 27 Aug 2024 00:27:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea0f:b0:1fa:a941:2f23 with SMTP id
 d9443c01a7336-203824a4fadls21630935ad.1.-pod-prod-04-us; Tue, 27 Aug 2024
 00:27:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNaMwJYIRR3742TfqGtfgsazd0hMOBR/h3EWinDuFJKYwFfrLcJ6li6Wi+xgpnZvA8QIb/JDmyo/U=@googlegroups.com
X-Received: by 2002:a17:903:41ca:b0:1fd:672f:2b34 with SMTP id d9443c01a7336-2039e4b77eamr94343885ad.33.1724743657078;
        Tue, 27 Aug 2024 00:27:37 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.21])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2038559115dsi4421845ad.5.2024.08.27.00.27.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 27 Aug 2024 00:27:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.21 as permitted sender) client-ip=198.175.65.21;
X-CSE-ConnectionGUID: Z7SaaQV9SAGPArjal665tg==
X-CSE-MsgGUID: 5qBd4R+zSy6gzcYdgb5zrA==
X-IronPort-AV: E=McAfee;i="6700,10204,11176"; a="23169452"
X-IronPort-AV: E=Sophos;i="6.10,179,1719903600"; 
   d="scan'208";a="23169452"
Received: from orviesa008.jf.intel.com ([10.64.159.148])
  by orvoesa113.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Aug 2024 00:27:34 -0700
X-CSE-ConnectionGUID: FazHEOb1RX6at+15d69Ixw==
X-CSE-MsgGUID: 5J2azOo3SPObs551Ziewfw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,179,1719903600"; 
   d="scan'208";a="63496997"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by orviesa008.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 27 Aug 2024 00:27:36 -0700
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Tue, 27 Aug 2024 00:27:34 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39; Tue, 27 Aug 2024 00:27:33 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.39 via Frontend Transport; Tue, 27 Aug 2024 00:27:33 -0700
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.101)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.39; Tue, 27 Aug 2024 00:27:33 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=S7RbAw5bDeCFbSv60dkMQcYMW4jyfRjvUcR3nnG/19v14nz82VIvk37TfDnkbdxFkQrjXsipk1qh1OqG2UvrRp0ZMxd0ekiezNrKbaDS8+yk0QMUgFYu53AFYOxVyNZ3AJRhW79YnXnvSeHaEuJuxgL1dDaDCaInhw4fNbL0OQAOV5rIx4xWo62RdXVu/BQCmfymYYxE1JX4iWqGTAzDmvl9AUmbG5aRlRXurUr4V0Vc9s/7X5oGq67S4Qp3kQT/uv7iqAvNmkSuFK5UOP6gqJvT+80o5c4XQg0CWvh5Ennhcnk3ALmPGAHIq92YS1N5dqTzHSe5fYow9tfYsQdHLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=r6XIl+rsz8Z6rOchATf7psKZBeEeChfed9HDziLbtfc=;
 b=hYivxhTZAC/H+TbeC/yO3cYi1+KagGAliJIx9HJWWubipQsvfEFjK71WnXH0zYNs3BBS77QmWHontQoXinW6LP3B9ovQv6FLOtnIS6qDPxJZ1Ik7FAsOBGYNkIKTK4KTf9fnHu7E+83IasmmCsyAKZnCbIm7viISU9p5DLeZZxCSKAulwtZYUGE6T8MJMmQzoz81JItGLzMtmNghXXSTYF7xPuD9pu3dmttK1Fl40JxMn6okr9xY/7tXK5KLIAXMFoIB/4MSJbChlQyl1whMYo1wwC/R7P729bCMIKHyk8cstqxezBnCifmWOG3zz8cCkfsXkw43ys/NKSKe7oCg6A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by CY5PR11MB6113.namprd11.prod.outlook.com (2603:10b6:930:2e::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7897.25; Tue, 27 Aug
 2024 07:27:31 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.7897.021; Tue, 27 Aug 2024
 07:27:31 +0000
Date: Tue, 27 Aug 2024 15:27:22 +0800
From: Oliver Sang <oliver.sang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Jann Horn <jannh@google.com>, <oe-lkp@lists.linux.dev>, <lkp@intel.com>,
	Linux Memory Management List <linux-mm@kvack.org>, Andrey Konovalov
	<andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
	<kasan-dev@googlegroups.com>, <oliver.sang@intel.com>
Subject: Re: [linux-next:master] [slub] 3a34e8ea62:
 BUG:KASAN:slab-use-after-free_in_kmem_cache_rcu_uaf
Message-ID: <Zs1/2n2pMQIM389b@xsang-OptiPlex-9020>
References: <202408251741.4ce3b34e-oliver.sang@intel.com>
 <CAG48ez1o2GvYuMxox5HngG57CFcZYVJ02PxF_20ELN7e29epCA@mail.gmail.com>
 <4fbe9507-13b9-4af5-88c3-63379835f386@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <4fbe9507-13b9-4af5-88c3-63379835f386@suse.cz>
X-ClientProxiedBy: SI2PR01CA0016.apcprd01.prod.exchangelabs.com
 (2603:1096:4:191::20) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|CY5PR11MB6113:EE_
X-MS-Office365-Filtering-Correlation-Id: 7159de49-7760-4d9c-96ac-08dcc669b677
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?aVNwSm1uOUk2VWF0cUcwVmkxdmpqTjJ6WkRBbUwwNGhvb3ExNGNlQVgwczN6?=
 =?utf-8?B?Y0ZnUlR1MG5aUExQWW5XODM3VnU2Qmd5aGE1VlBPNDIwem00LzQ2SzR5Yzh6?=
 =?utf-8?B?YktubGNwL3cwRDV5OUVyNVV3VnFlQjRNb3QvMlRNa1VkbGpZSUpXL2hhenBN?=
 =?utf-8?B?ODRvOWVjYjZYYm1rSGRxeUFSZ204b2FrSVlBMm84N0FKVnpDUmJNQVJEQkFh?=
 =?utf-8?B?Sjl2cE95UzliNUJuWUxmSW5CT2lWMkFTWHZlSlprN3Z5OUVVVmtTUFNXazZP?=
 =?utf-8?B?MjN6TzNJRXFxZllRa3c4SmF5MC9Xa3FnOXFGQVVzdmVqMU1NcHAvbnluY2pU?=
 =?utf-8?B?MXpDemVQaWJqeGNqKzdGcUVJWitMcVRKUitGblRLUm5HUElnQWN3NVl5MHM1?=
 =?utf-8?B?UmVpZWw2emhKTUcvMXBHZ3QrMVd0ZFFHenZ2VWNqVSszTW93VjB4bzlXUnZa?=
 =?utf-8?B?cVpVMGQvdVY5TERsa01Vdnk2L01QUHpEd05RUEhEa1pDM2NkL2tHNVlFWDZ4?=
 =?utf-8?B?NURIaFJobW9QYi9WMDRHYVpGdFprWmsrYjlWZUdZT2tPNjdEdExMbmdYdzBG?=
 =?utf-8?B?MSt3Nm5ISng4aXpnbWtmRkM3WTdncnByUitJckpPMGtnVnN5Q0FoS2QxTURy?=
 =?utf-8?B?TGJraHhWZXhObEUvaXdvZ2l4aklzQnN2d3NKVHJTd0VIakdvQ1pUL0hyL0wr?=
 =?utf-8?B?Vy9SZkMrUHZYaDlpTmoySGJQRGM1a2hGdkJESmFUdldDNHJHdHo4Q1Fkb0Mz?=
 =?utf-8?B?RU9oMk5HVW40eWdVRlBDME5WdFd0MTU4cWtjTVQxdTUvci9iUlNheStQckxY?=
 =?utf-8?B?QWFKTUVRZTdaQTJLWjFqRGx5aEoxY2c0S1JBREdxWktNSG1kT0xzeUY1d1Ri?=
 =?utf-8?B?Y1pCQWE0dFdSRWxwQ3N0UllVVHVRcG9VeG9nODlHZUUvY2hSK1NSbThwbktG?=
 =?utf-8?B?aWkvMVpLQ21CNVdtUVpUTmFCTG4xVVlES21FOERTZkJNcGJ2ZjZ0NXAwZ0cr?=
 =?utf-8?B?NWh3QUJQYllGemdjTjl4M0JhSkRReUZMUEg2c1pwaHRhYXI5NE4rR1Rqc1lo?=
 =?utf-8?B?QVZoS3hqTlRDUlZGbnRwVjNoTXd6VVpESWxTZzd3YUcvbHpWcUhJTFk2ZXVX?=
 =?utf-8?B?YUJvRjlHWGRmRmRKRExYNjBKakNxNHRUS28vL3doTzZ2VnlYN2kwNWNnQThN?=
 =?utf-8?B?TnRWc1VFUzVwRHZiY1V3TDJwVWZCUDlET3dZV2ZRMmtOQm1jdlFDak9URVMz?=
 =?utf-8?B?NTkwNWVDY0pLZzViUUFKRlRhZVNZYTJKNzFxMTZTN1ZYRE1tMDRnbWFURUR2?=
 =?utf-8?B?bUIySWhmOTdhbHU5bEtQQVljemxXek9pd3pJQXNEbTBBTEFOTGtua3Z6RDVS?=
 =?utf-8?B?Z2JzSDVtemNTS1BQTEs3ZHhpUjY1L2FCKzlzQ3B2a2dLQ3JnOUk1amhMRDBq?=
 =?utf-8?B?Y3BpTWkvM010NThFS1h2RGZBUXgzcVoxQ2JjYStVeHRWRFYwMkFDK2Jvb1lh?=
 =?utf-8?B?U0MwbjE3QmpDR3V2N0prM1ZrQTlpZmJ0R2pXRklEUXFMd2lPVlZOVkE4OVRF?=
 =?utf-8?B?eGpvZjBaU1F4SW5Cb3ZVVHphbEN1MmlPNnU3VnpmMElPWnI0V1Z6bkhVNEZu?=
 =?utf-8?B?VjQzQ3dpajhJUGlvWTEyZ1dkL2JML0pVcGswcVdOOUxqRVMzUGd5L05ybm11?=
 =?utf-8?B?MEhObkE5RXJSYzMrUm9zNWphd3FCV01oQlltcE9FdDFQcFRiTDdmbHhtcnYy?=
 =?utf-8?Q?UCNvNgdhkTDr6Myh3Tfi6gttJM97ARxtnJxzUX1?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?T3B2YXVzektZU25xLzVFQmplKzFaNGZrdURIQ1ZMZm10a1hCVVdCK3hoUnk3?=
 =?utf-8?B?Y1RMR2dsN3NTNDFiK01aaWVNWnp0TmtjdUNaZVppcy9RL2l3ejVXZEtIRHVE?=
 =?utf-8?B?QTY1R09NT0pCZStkbEVURUxkcWtGVTQrUFNIZVV3alI1ZjBQQ1JHMm1sSjJo?=
 =?utf-8?B?cnZvdEdPTGVDejhVbkVFR1RNWTZFeGJPb2N3Z0F3L2dvaGtqMHRoa0lSbzRP?=
 =?utf-8?B?eW9wZ1NXWDJ4dDFFU0RMaW9NS1dhSk1yaUQzenBGLzhGd0xXY1g1RlU5VDc5?=
 =?utf-8?B?Tnl0WVFNY3B1c1JmaE9RTXUrU3lSMTN3TTBPa2RneklsZVF1K0J0eStkWkRN?=
 =?utf-8?B?RFpEOTVXbktlYjNLVjB6WGRzNlp2a2lBZjRnZXFObHlzcEZ6dlJzNHhCRFl3?=
 =?utf-8?B?d0VEdDYxRlVrUVQrUmJzZVA0K3JvZ3Z4RVhjOVZOSDhiREpQMHB3M3BRamJq?=
 =?utf-8?B?QURqaEtwYWJYZ2g2ZzN1bXdEcTRXOU5xTnhtZ3JucU9sN1QwcWdOWHlwRndJ?=
 =?utf-8?B?VmlSYWhEVDU0SUJUd2ZiaHY3NWZRSmZwb0l5VW96VkxZWDhPS2ZsU293L2dX?=
 =?utf-8?B?Rng0NEpRZEkvVmJaMFJ3Z1o3RXVoSjZBOWdYWEE0dG9ja2M2dW5SaklKTUhz?=
 =?utf-8?B?bGJ6V1crd29TOFpNQ2haaXVnTFlPdTBKOWt2cEtMVEJjbndsQU1HdW5UUjRG?=
 =?utf-8?B?VlNWZlE0TXRoQmlud2d6R1I2dUlHcVhXTDkyb2l1NFIxTlcxNEpPWVcwaTJL?=
 =?utf-8?B?TjFFd3VidjJWK3VOK014RE5TMC9hYVJvN3VlSEJndUNIYVJKRVlxaVFwMnBi?=
 =?utf-8?B?UFJ4YlZjNzI3eWFzS3JJZ3E5WkR2UnVYVXIyam1lT3hlbk1ubGYyQmJRWitZ?=
 =?utf-8?B?MlgxVytNVXVWeUJiY2F1bmx3ZDNBckIxNm11aUFQQnF3M2NoM1VGNFNsQklx?=
 =?utf-8?B?TXAySGdsc2ZNT1RCamZIUWE1K2pZRlBjRGlMRS85R0ZHYW9IbjNHdFBaM1cw?=
 =?utf-8?B?YkNKYk9WNG5qVnJwMW5rTVBzUGhpK0lpZ2pBaXNpT1VpS2ErWkNKUTVMaEE0?=
 =?utf-8?B?VUNWZG8zTHN3TzJXZFZGa0VWd3g2QTdEcEt4clRmcU5VMDVMUUVyZXFpdVJh?=
 =?utf-8?B?Z1p6TnphQVY2S3J1cFV3OUpBM3BOZmE2TVNjaFJoejhTUXk4T1pSMWhkdjFO?=
 =?utf-8?B?U0JEUDlta2tzbkNRMHJOZXVpSXhzSUgxdWdibHM5QzFZSndUTGlSOGJJbmVS?=
 =?utf-8?B?OGVoVDJDVW1EMzVNQUxleWRiQWlNOUFMbnJYRTYzQytWNWN1SGxwV2ZvWjJr?=
 =?utf-8?B?aFNtRXpyQWk5ZnBvWkZrSTBOR1ZHRTZOSEZ0cU5teW5UWVFLemxQT3IxWHZ6?=
 =?utf-8?B?V0hpNzhnNzJIUlU1dk41Y0pnR3dldXF0RnJRb29RRWYxMXhDZTZiODNnYVdY?=
 =?utf-8?B?bE9RSmNIN2gyLzFXVDk4L0ZadVVLdmVHUnVTd1EyYVc4cjJ2M3lwdVhLeXpa?=
 =?utf-8?B?ZktwaTloNmdCU2VmaTZ5TGtWRjFGY0ZieVZOdEdCUDVQSlUyNkJuL3gwd3hP?=
 =?utf-8?B?ZHQzWlJrSERUdk5VQ0xkUms2S01sT0pra3dsd2tzWmFiYlE2YkV3eEZySWI0?=
 =?utf-8?B?dDdKdFN3c0xxdU1KZWJJTWRxaTJrZHcwNEZMUTNKU1psV2NuSlF3SllXcGJ6?=
 =?utf-8?B?akwvZUt0K1ppdWhJWWFHMFhzU2M0ZUlRTEUrNWljbEJSRHd0QnNYS2pRN0lL?=
 =?utf-8?B?VFRrN29TbHR2MmptY25ENUxoQktuZDRub0FiZU13UzdEYWJEZmYzSmJBZGpB?=
 =?utf-8?B?L1BHdmN6NEs0V2lYV0N1dHlhUERuVkZGZ3gvVUZwbnBRbEJOaXB4WWZqSWJV?=
 =?utf-8?B?aUpXbTBzYTFFZ084RDFKNDQxalMvaVA4eVd6Tmc0S0tkQXVIVDQyUHNCYmNu?=
 =?utf-8?B?MlBMVjMwaXprOXhtZENFYU8rK3hPeTcvMGxiblhld0xCOFpaMzZyMFBJQ0N1?=
 =?utf-8?B?WVFKVzdTUXRudGFrKzBDM3NRdzZHNVc4VDc2RXFtcDB1bWNZUzhwTnRIM25x?=
 =?utf-8?B?ZkhRSTRqcmxBdnpxeW1mcnU2YUljTGJDL0pXSEkwVFhpS2FoN0g1OUZUaG1U?=
 =?utf-8?B?NjFzajJTZ0NHNHhUc3VXNVg3MVlnRTdrVkRtWFBEeFpHTEs0L0ZuSjJnVElm?=
 =?utf-8?B?QkE9PQ==?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 7159de49-7760-4d9c-96ac-08dcc669b677
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Aug 2024 07:27:31.5768
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 2t276j3Kjsy1cJ8KyVkYySsvJsCtKuDB5mLHenV6tpfRdXaik1p45XFxChDSNka+n99ir+XsPmTOsRZ9K/VrDQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR11MB6113
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=M0k8T6r3;       arc=fail
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

hi, Vlastimil Babka and Jann Horn,

On Mon, Aug 26, 2024 at 10:27:29PM +0200, Vlastimil Babka wrote:
> On 8/26/24 22:18, Jann Horn wrote:
> > Hi!
> >=20
> > On Sun, Aug 25, 2024 at 11:45=E2=80=AFAM kernel test robot
> > <oliver.sang@intel.com> wrote:
> >> Hello,
> >>
> >> kernel test robot noticed "BUG:KASAN:slab-use-after-free_in_kmem_cache=
_rcu_uaf" on:
> >>
> >> commit: 3a34e8ea62cdeba64a66fa4489059c59ba4ec285 ("slub: Introduce CON=
FIG_SLUB_RCU_DEBUG")
> >> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git maste=
r
> >>
> >> [test failed on linux-next/master c79c85875f1af04040fe4492ed94ce37ad72=
9c4d]
> >>
> >> in testcase: kunit
> >> version:
> >> with following parameters:
> >>
> >>         group: group-00
> >>
> >>
> >>
> >> compiler: gcc-12
> >> test machine: 36 threads 1 sockets Intel(R) Core(TM) i9-10980XE CPU @ =
3.00GHz (Cascade Lake) with 128G memory
> >>
> >> (please refer to attached dmesg/kmsg for entire log/backtrace)
> >>
> >>
> >>
> >> If you fix the issue in a separate patch/commit (i.e. not just a new v=
ersion of
> >> the same patch/commit), kindly add following tags
> >> | Reported-by: kernel test robot <oliver.sang@intel.com>
> >> | Closes: https://lore.kernel.org/oe-lkp/202408251741.4ce3b34e-oliver.=
sang@intel.com
> >>
> >>
> >> The kernel config and materials to reproduce are available at:
> >> https://download.01.org/0day-ci/archive/20240825/202408251741.4ce3b34e=
-oliver.sang@intel.com
> >=20
> > Oh, this is a weird one...
>=20
> As I replied I think lkp simply reacts to the BUG: in dmesg and doesn't
> filter it out as an expected test output.

got it. we will follow to filter out expected test output.

>=20
> > Do you happen to have either the vmlinux ELF file that this issue
> > happened with, or a version of the bug report that's been run through
> > scripts/decode_stacktrace.sh, so that we can tell whether the reported
> > slab-use-after-free is on line 1029 (which would mean that either ASAN
> > is not tracking the state of the object correctly or the object is
>=20
> The reported freed stack suggests the object was already freed by rcu, so=
 we
> should be past the rcu_read_unlock();
>=20
> > freed earlier than it should) or line 1039 (which would mean the
> > KUNIT_EXPECT_KASAN_FAIL() is not working at it should)?
>=20
> There's also "ok 38 kmem_cache_rcu_uaf" in the log so the kunit test macr=
o
> is satisfied.

thanks a lot for information!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zs1/2n2pMQIM389b%40xsang-OptiPlex-9020.
