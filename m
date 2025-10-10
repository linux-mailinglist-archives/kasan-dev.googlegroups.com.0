Return-Path: <kasan-dev+bncBD2KV7O4UQOBBQEMUPDQMGQEW2SYFIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id D5DB9BCC2A6
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 10:39:30 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-42fa528658fsf1888345ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 01:39:30 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760085569; x=1760690369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=oLivnLC6H3HVjAgp5SyKxn5dHECWaptTcb2YCqUlMXo=;
        b=svEInxf8ALqpCPaCjAi3mbWJBycGnL969rbOH3jUlgPJb8cOx/HJeQoNaTwWi/hFof
         zwq+x8FwjmcVk6KsBLNlLR8Gx07YEQXkHkS0E/8BmRjGYpL+RYj2wLZ8fGMoBcyf+cnB
         u6c0CuC3ZR7jPLNHtCTJ+bTPwEkWC6cfGRZOHp2yRBRXn4mduwWIlUs5NrDeqmlET309
         4lfy+ujh4NuYBFkwSwgcq4+cmMpsIv4b9D2J/TIJpoxspkcF+MlRiyuotz12m4jq0iHQ
         gsWH5B+31hCFP6YHpe4kM1OXAG7GA7deM/XcH4JXWIJPKXl5sRX51khjombSY4XbIG8m
         ZSJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760085569; x=1760690369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=oLivnLC6H3HVjAgp5SyKxn5dHECWaptTcb2YCqUlMXo=;
        b=WEGFjjOLDmpd6Ta3VNZ8drvKsOyR0xxpyaSZldXdXcffTw3zBq1WzIlSXrcjgdE7Lp
         FSjx13gMZcxffiXRdIchEI13U1uA62/YLLxJGaVLal4NxfTcFlRV5H0ap1S0lpPCauDi
         r0DvWab+PZKJBQQZ6VmORa4Gy1YyKiF5DigYciptHLu68CUqltFGQ3JpOuc7f+cQTwwX
         paCQ5yANkHeuvs6Ydarz+vi/fnLWZBkRZPro4H6lfPnJW/NUe+h1RnRa1fALoP60+Ylo
         h5a+aYOTjH9miY/VZafptWU/VZMuUdJ/sDAhKai13RdTw3hL7shW8yenPnYxqDzu78/s
         A/Cw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCUe1gv2h18GXq+HamhbzKSu/kdsGXNkXKglSaTfhdoJSoHmrwOilur/m11nr5d9l2UqyfhSzQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy9rx5LyH8JTEUCG6TvekgknIa7vTxH6rvvhF8avAwEhpDI8A5g
	DBTHekO2Z34rRb6mAcfBL3QGrwjcpTrzUF0KbSiy17cwgH2MrPeNcwzK
X-Google-Smtp-Source: AGHT+IERWp8wag5xaF5DE5/PXdfaVFzz+61vUshgTDoONJ64xu7Qnwv896p5KZim0UKyLPF/Jv1L0g==
X-Received: by 2002:a05:6e02:2195:b0:42f:991e:17ea with SMTP id e9e14a558f8ab-42f991e1878mr34644385ab.2.1760085569035;
        Fri, 10 Oct 2025 01:39:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6WL9ZCyewl21boOqboVpWwjoAW3cLhzo7aCGJS+YcFag=="
Received: by 2002:a92:c642:0:b0:42f:8a2e:654 with SMTP id e9e14a558f8ab-42f90ab142els16034785ab.1.-pod-prod-01-us;
 Fri, 10 Oct 2025 01:39:27 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUkKSoI0q2JQXBoW9KVLZ6MM+k4NLIYyRzKHhCxY9Y9uYA+RzIWDcPLq2Xmb4QuE8dNZTQudmP5wDY=@googlegroups.com
X-Received: by 2002:a05:6602:340d:b0:8d3:6ac1:4dd3 with SMTP id ca18e2360f4ac-93bd18b16bdmr1281897139f.6.1760085567330;
        Fri, 10 Oct 2025 01:39:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760085567; cv=fail;
        d=google.com; s=arc-20240605;
        b=bbf2Q93J6aB90BiCeF5RvCjpYixCQmx+CuP494l6kkluo6YB/Tfql/Ho1ls/H35Isd
         nOn7jZLVfi5kk2192TwPhgU0n/HMVvF3Ii4SBewIbdpS3G0749ymZcIGVCMfHFe1zTtD
         kH5qlF3O8vAoPwObgbVNtUAKHzM5pdYaGvltICGmz9odLgBbqsQjG9FoltkVKJHFeoTT
         Z2LfjUarAk6WJ82oj4URs4gqAo87zD3zjduqxpXQeWGF6dtAsUO+c1S+ip8LUdAxlA8/
         cgEraIuj2w/OBOYqsBryevh4vQAbzHdI2zQkFZhc5sjU1Gq7CQXgnRkMkarG1JpbtKwZ
         EKmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-disposition:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=kK8iAwmJ8VRmbSLsetgPNptGBFvzljUrRKGULiUzqTE=;
        fh=mRIWwOjtmAqTWEcQnwnI7G0+xU8AP/13eM5shEJ+vcg=;
        b=TlXV/ISiN53W/Z0j9szWVRpwbgaTVsmwouBdmgH/vpOivzZtFCqw6FQXiYTNXY1lmD
         rLO08doTArV6NcURx/z0PZEnA4rgsiGcNAImb0QySb7tlBOr6ittNCw65MBbYRznEQCz
         FxhtLNeeqTlHzixqhmewHj9BijN2QMaabRQ9kKO6dlmGuCqHSV49fsHBsHgHw6jewXMC
         874UftMKwfZvgz3LxCkoEeYnR5vg67UjiOKRpLURtN+v+Cy6Jd5BoA26YKhfWHOlcgZW
         kfazVhctRrJg2V2pSvJ7jDBsa5NuzbAN8YwT0ryTxbcqBgOKJRpZFvHaNpC5qN1+xJ/a
         ljmA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="LM/HuVmP";
       arc=fail (signature failed);
       spf=pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-58f67446c7fsi85186173.0.2025.10.10.01.39.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 10 Oct 2025 01:39:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: mbo/QIK0TZqjPQB1OCmvsQ==
X-CSE-MsgGUID: Bdkue9UtTL+9Z8KncVqYWw==
X-IronPort-AV: E=McAfee;i="6800,10657,11577"; a="65956449"
X-IronPort-AV: E=Sophos;i="6.19,218,1754982000"; 
   d="scan'208";a="65956449"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2025 01:39:26 -0700
X-CSE-ConnectionGUID: oC20L6ogQOKPywhI/jG3RA==
X-CSE-MsgGUID: bmGvjfYdQo6vk3zwReFSOQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.19,218,1754982000"; 
   d="scan'208";a="180738372"
Received: from orsmsx901.amr.corp.intel.com ([10.22.229.23])
  by orviesa007.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2025 01:39:25 -0700
Received: from ORSMSX901.amr.corp.intel.com (10.22.229.23) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27; Fri, 10 Oct 2025 01:39:25 -0700
Received: from ORSEDG901.ED.cps.intel.com (10.7.248.11) by
 ORSMSX901.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27 via Frontend Transport; Fri, 10 Oct 2025 01:39:25 -0700
Received: from BYAPR05CU005.outbound.protection.outlook.com (52.101.85.10) by
 edgegateway.intel.com (134.134.137.111) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.2562.27; Fri, 10 Oct 2025 01:39:25 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yqpW71MLMtRN2YN7RJYcq8zuuqs3L/Owj5QGXy/bUmGYZYjV21bja3AEWtrHxxuk0Ts24wPw7wfhGB0/7ZD1limd+a4AMLaMUG8efkqMdTu0ex0chmeMTAsWinXbZrSV/mIr5kPAZOOY7GjuAW288CWe15l+EpyOmPwIXRzUZlfHCDKAzmCb1EldnhJOQloES21ctFK1KJ0G06R4R7McIVWo49lGJQUCRYxRCWQIF3SLF4wlBk7aVUZPAs5H9h/COHPbAtT7TwmmSQ6cgB3S6Z4D656vAaubwt98kgyO1uYZlLAKfe7ZM78hAD3U7f/ookzZGUNIYXxQEDxnksR7Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kK8iAwmJ8VRmbSLsetgPNptGBFvzljUrRKGULiUzqTE=;
 b=qZgnXb5NMqFaB0o0POy41HlJn9DAYOTf9mj4h1DcLKCl9qqJxr6J+q2RBVM5cskShtMV29of8KnNH2qW1tqLwnEGqCDz2O405+vRDTC8pYRXsDOqcmVg9OVuqysyluxU5pf9UNGFD4KYiyaVpaO8ZQwCwAM/RoyYrr8FlTWMVgGpestwiCkeCnGgsFZ+rfwFxQj/LDUQLjfigyq+b2jShlYG0Qj361bS1XbeJbaIz1/WqEcxyPGart+gCocKkGO17H50kVS3yHmi33YXCUiouQxgHvDEIX2rf7Lq74YgBbij0CiOamBWRletJyQwdRd8VyOtsh+1I1anHhMtFd/WUQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by MN2PR11MB4727.namprd11.prod.outlook.com (2603:10b6:208:26f::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9203.9; Fri, 10 Oct
 2025 08:39:23 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::4622:29cf:32b:7e5c%5]) with mapi id 15.20.9203.009; Fri, 10 Oct 2025
 08:39:23 +0000
Date: Fri, 10 Oct 2025 16:39:12 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Alexei Starovoitov <ast@kernel.org>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <linux-kernel@vger.kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>,
	<kasan-dev@googlegroups.com>, <cgroups@vger.kernel.org>,
	<linux-mm@kvack.org>, <oliver.sang@intel.com>
Subject: [linus:master] [slab]  af92793e52:
 BUG_kmalloc-#(Not_tainted):Freepointer_corrupt
Message-ID: <202510101652.7921fdc6-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: KU0P306CA0062.MYSP306.PROD.OUTLOOK.COM
 (2603:1096:d10:23::9) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|MN2PR11MB4727:EE_
X-MS-Office365-Filtering-Correlation-Id: 2fbef629-4a90-41a3-dc6e-08de07d8829b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Gvt4ywcXLt1n4dsYvSnRLvxfqcaAcEu7qZloOaF4ftv5b7EQitmzxCOKfQMO?=
 =?us-ascii?Q?t3O/mLQQXZWRN7G/7wVYRtFCuijK/776eG21xsElSVwnzp3nUL1KD4o/ghpz?=
 =?us-ascii?Q?GRO1x3GeQF05fvpLw/MhmnOH9wuk8inDloT8gUn9uEOZw57hyyVShTzJUDab?=
 =?us-ascii?Q?eyx63zcNwYwEP92qGycRHb/HYy+DayI/oSzmeq78qntxRVPBTkPBxbITupZW?=
 =?us-ascii?Q?6VuSkM0sJtKB7WNYpf8eccScvo/Xjg2p70jHQo9sk8ubAOm2ZO7i5EW5n5qa?=
 =?us-ascii?Q?GDWfNSjlGiW/f/HCBJW1wBWGwuvKuNjFMuma5E01evu3yEyYF//oiYXSl+iO?=
 =?us-ascii?Q?aIiYJo0gq3DGhEeA4HYlsxRN5luZODbHUcPOXBElS5TQ72EuPrAWe6Um3N6F?=
 =?us-ascii?Q?p01bTQc6AKyA3PNafe2HME8QQsH3Hl2iy28zWSZfxCBT+yoUyjUs377bbtRZ?=
 =?us-ascii?Q?tKDVcmPB70yFI6Z75aoXd7V7lZEqgAlPFGhLwCKzYIm2mtyKti8+toaLOwBl?=
 =?us-ascii?Q?HW5RAAOWKNrPxoZ1LYgHvLD/PTGiTag4jxa3rDrqRCY0UZ/M/7og6isyvAfm?=
 =?us-ascii?Q?HVLiZ+SdMDaKzU7ReDqNR70uNZz348v/R8cQ7YEdXiec9xq1rOGg9bevT5pR?=
 =?us-ascii?Q?AruBoQSyaAHy7/xDvhhi7PXyr420ac9ydNBngk+E2uvxvS0pB2gJ+V+lDcUl?=
 =?us-ascii?Q?OJtSoTIOrfLv0MsKccNeOXtldsQVh811UKpuPD40Aw9bqHhKVfqGh4g+pvsb?=
 =?us-ascii?Q?iG8EIzMYu1q1jbvd6BYZZgCoVUjUfeQmvrzVigCzHJcmshJdtqXj9ScgObBO?=
 =?us-ascii?Q?jZnAIE5JgjMvSgTBHwND1ZOqV36ova7UY/iQPl8RfIG+y9a6cLH+seO+e3W5?=
 =?us-ascii?Q?s1UFpn5H9aduWlhtCC8G4nHgo2D7XY80Z9MF7CrZg7cg0gCB3/GmS2G4/vek?=
 =?us-ascii?Q?YWrT3nbkRIf8ToKTnefH6e3LBx0/qLGyq8RFvHi8lQQ/QKFtw0tT9FkkZIBW?=
 =?us-ascii?Q?t7i8szdMLHE+wsw9p70Cy5oCaMMu/UJc9oaNAe9FTpFnuRJeun2id/j2Z5Jw?=
 =?us-ascii?Q?6Pjv4snLluMe6lntCXbBj+dJdV7K5So/ZB6l/7xM0gd8qXqa4bdnoJPVBLeD?=
 =?us-ascii?Q?STYd4eEvYR5T6iWknjmbKA8Mu1/P4MgeEuRtqXTIl5yLWeLo2bhJUEhHNoVZ?=
 =?us-ascii?Q?blUOFALS82cmfGRM1xDK3sT6KyvVRRCR7RhtceA3zBdJiBAhZ7TQNdthy/fI?=
 =?us-ascii?Q?BnbcK7Tr5mv9l6MfMLGiBbwwd6sJGflBHb8ORw+7UzRB7Ub+QGvdOl5gmsru?=
 =?us-ascii?Q?8hTYcMwrcNbXQB32Au9XcommMOi05fXx+Mit9k6OG1Tc/SKUcmH5r+WErEJp?=
 =?us-ascii?Q?xmvdEe5HO4K1tbcLz9qgA0A7LZ/gdqIY17RrWfzGfCMe3/VZAhpr9XBTFEpo?=
 =?us-ascii?Q?CEGzJxLnm/w=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?dBxxvt4b1qvCCr7gxHf+cF+OJryyiuQcGdcPtTGqUdNSVhM6Pc3A7m0DD8L0?=
 =?us-ascii?Q?8VBmM8fUm2oc3mV5tXfJD0bQYqtZPe6KktDlMXJsbQgDjiUNHPp52IqcTxkN?=
 =?us-ascii?Q?kPSj7SM9E035CAgFXN4m39WuDq1ax6jG3fHQdLPE4BqLCdsnjiM4nkJnPHuD?=
 =?us-ascii?Q?7E5eyoH2ayQ4UbgNnDYpN5OBjhcaFTlI/O/Wxuh+8m+XbKjLF83N4XBJmFR6?=
 =?us-ascii?Q?otkI9xIwrGI46OktkNl58IIDy055JNGLiDZLtMUtKyIp+kbPO5Xw/bmTJbwR?=
 =?us-ascii?Q?PEadkDTBi1JdcOcOD0Gg6jXg9TlEE3H3FMkNlDu7FN2MR9CA/hQ3QNF+Tm0R?=
 =?us-ascii?Q?N6PdyLIrDJvave3HwYz65ziOdNVgpR19k5IhaLEP/QPTBVxsMAU5H5K2Wzwy?=
 =?us-ascii?Q?qcg+iHRN3R92l+dcWO46Up1F1nTGX9Vbdy6+UY2212s0J3S8MBSBsIul9aFS?=
 =?us-ascii?Q?hmeCSOLiVhcpb0cGs9X74ZJFwAiRwvIJyKrf6iCuDs8m1uI4VH4Dxr2r7aIx?=
 =?us-ascii?Q?cUuE8RGdEO2y6dkHTs9RZNBKw/niWA+NcInM3cSPPMwz1WbMxyjBWsXSQsE8?=
 =?us-ascii?Q?BNiikL4Ah3bybc0V8HThe4d+BYQrJM8vZ6T2ekQ30LSOkamaPUfO1e/8cEOV?=
 =?us-ascii?Q?pdxRDGJDlx3GaMIH/wdAs3M+abVQY5HDbjGhkxBroumAvNTzQozm2Vl5yNte?=
 =?us-ascii?Q?KDqwKZHrm6NhVvQzj/OwYYEo7LXMkaXRLiJp9s1hsGIxkb6lo7W3QVbNCHN+?=
 =?us-ascii?Q?r/Y0qi5oQvwDWc2GJpqvnKdd37a+QJBvvgFb9k87/FeSR8RSLhBfR50nI9s2?=
 =?us-ascii?Q?7m9ipwqwc4Kcvulcqj+iX/MO+Zf/oGDE+1XonB+YnUaoQF8JzsWzJUUFBYPu?=
 =?us-ascii?Q?wOGHFXPHDZA3e81em63elKAJFmGn7VDun0ZSlD1PbFyEDzsONFJldV83zQWT?=
 =?us-ascii?Q?IT5FuuOXBcq5WcQdcVWh+SNalXolQwURh/Fhqt7Akntfirvv/65And0XM1l5?=
 =?us-ascii?Q?e6DODDYwVqpRpS78lVsG3HMEm+p8rYcx7iRE9rjCMhcSP5opG6E4IfE2/rTd?=
 =?us-ascii?Q?HTDqwxVi2BC5XE1MjI92zxlXgQGZlMJu+2fWHnemlG0HUiKF8wjCS7HR462J?=
 =?us-ascii?Q?xO4KWpdcceJ7yLJmn3fMaHDpqG0TT5Yo4S6Tb2Ng/jCp3qFqskLnSWBBuR8Z?=
 =?us-ascii?Q?QSFbLpU6rbBN36mMr4iigpIBHnvL/Er2tJnf7wwIqPVke9mTRVpKokye8im6?=
 =?us-ascii?Q?x70R4UOdYOs5cQ2p3iNwXYnVQOcBOXfjP2JpNP3frMPxwe7tvjyqRWmggtLQ?=
 =?us-ascii?Q?jPg03y4ikwuX3NaItPZ3t2zU/q9n8lo8Kgoc3CVbw4Av77SRcPcZd5BgExFV?=
 =?us-ascii?Q?3Xo5e6u24kJ3ur3Pcv2lJH/LZisC54ok2XwRdNr7cRhf3zmo+OJvX8gc0m0I?=
 =?us-ascii?Q?HD74dA3JxUHrHLN9F1N9IVzk/IBI90exek7811GmTHOBUPootBKbUHxsizZj?=
 =?us-ascii?Q?DoLpcwHbpSBirybl8rJRKTZ37rtP0dli/Fi58vNbwHuyDELKJ5/C+rJd9UJn?=
 =?us-ascii?Q?kyM8zYInrqRIvVzTSQSkkBP6FXDpPOGMFAWJhFGVWo0ljQRHZ8UiuoXEj8oT?=
 =?us-ascii?Q?VQ=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 2fbef629-4a90-41a3-dc6e-08de07d8829b
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Oct 2025 08:39:23.0747
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: qPIYU4Hj94eko9YdN66robuOaMfp6txkjNzS9BWgIhKWZ70DjKQmIX3uz/9WF7wlT+AifJctjqBSaMZnkdDNcw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR11MB4727
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="LM/HuVmP";       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 198.175.65.15 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Content-Transfer-Encoding: quoted-printable
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



Hello,

kernel test robot noticed "BUG_kmalloc-#(Not_tainted):Freepointer_corrupt" =
on:

commit: af92793e52c3a99b828ed4bdd277fd3e11c18d08 ("slab: Introduce kmalloc_=
nolock() and kfree_nolock().")
https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master

[test failed on      linus/master ec714e371f22f716a04e6ecb2a24988c92b26911]
[test failed on linux-next/master 0b2f041c47acb45db82b4e847af6e17eb66cd32d]
[test failed on        fix commit 83d59d81b20c09c256099d1c15d7da21969581bd]

in testcase: trinity
version: trinity-i386-abe9de86-1_20230429
with following parameters:

	runtime: 300s
	group: group-01
	nr_groups: 5



config: i386-randconfig-012-20251004
compiler: gcc-14
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new versio=
n of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202510101652.7921fdc6-lkp@intel.co=
m


[   66.142496][    C0] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   66.146355][    C0] BUG kmalloc-96 (Not tainted): Freepointer corrupt
[   66.147370][    C0] ----------------------------------------------------=
-------------------------
[   66.147370][    C0]
[   66.149155][    C0] Allocated in alloc_slab_obj_exts+0x33c/0x460 age=3D7=
 cpu=3D0 pid=3D3651
[   66.150496][    C0]  kmalloc_nolock_noprof (mm/slub.c:4798 mm/slub.c:565=
8)
[   66.151371][    C0]  alloc_slab_obj_exts (mm/slub.c:2102 (discriminator =
3))
[   66.152250][    C0]  __alloc_tagging_slab_alloc_hook (mm/slub.c:2208 (di=
scriminator 1) mm/slub.c:2224 (discriminator 1))
[   66.153248][    C0]  __kmalloc_cache_noprof (mm/slub.c:5698)
[   66.154093][    C0]  set_mm_walk (include/linux/slab.h:953 include/linux=
/slab.h:1090 mm/vmscan.c:3852)
[   66.154810][    C0]  try_to_inc_max_seq (mm/vmscan.c:4077)
[   66.155627][    C0]  try_to_shrink_lruvec (mm/vmscan.c:4860 mm/vmscan.c:=
4903)
[   66.156512][    C0]  shrink_node (mm/vmscan.c:4952 mm/vmscan.c:5091 mm/v=
mscan.c:6078)
[   66.157363][    C0]  do_try_to_free_pages (mm/vmscan.c:6336 mm/vmscan.c:=
6398)
[   66.158233][    C0]  try_to_free_pages (mm/vmscan.c:6644)
[   66.159023][    C0]  __alloc_pages_slowpath+0x28b/0x6e0
[   66.159977][    C0]  __alloc_frozen_pages_noprof (mm/page_alloc.c:5161)
[   66.160941][    C0]  __folio_alloc_noprof (mm/page_alloc.c:5183 mm/page_=
alloc.c:5192)
[   66.161739][    C0]  shmem_alloc_and_add_folio+0x40/0x200
[   66.162752][    C0]  shmem_get_folio_gfp+0x30b/0x880
[   66.163649][    C0]  shmem_fallocate (mm/shmem.c:3813)
[   66.164498][    C0] Freed in kmem_cache_free_bulk+0x1b/0x50 age=3D89 cpu=
=3D1 pid=3D248
[   66.169568][    C0]  kmem_cache_free_bulk (mm/slub.c:4875 (discriminator=
 3) mm/slub.c:5197 (discriminator 3) mm/slub.c:5228 (discriminator 3))
[   66.170518][    C0]  kmem_cache_free_bulk (mm/slub.c:7226)
[   66.171368][    C0]  kvfree_rcu_bulk (include/linux/slab.h:827 mm/slab_c=
ommon.c:1522)
[   66.172133][    C0]  kfree_rcu_monitor (mm/slab_common.c:1728 (discrimin=
ator 3) mm/slab_common.c:1802 (discriminator 3))
[   66.173002][    C0]  kfree_rcu_shrink_scan (mm/slab_common.c:2155)
[   66.173852][    C0]  do_shrink_slab (mm/shrinker.c:438)
[   66.174640][    C0]  shrink_slab (mm/shrinker.c:665)
[   66.175446][    C0]  shrink_node (mm/vmscan.c:338 (discriminator 1) mm/v=
mscan.c:4960 (discriminator 1) mm/vmscan.c:5091 (discriminator 1) mm/vmscan=
.c:6078 (discriminator 1))
[   66.176205][    C0]  do_try_to_free_pages (mm/vmscan.c:6336 mm/vmscan.c:=
6398)
[   66.177017][    C0]  try_to_free_pages (mm/vmscan.c:6644)
[   66.177808][    C0]  __alloc_pages_slowpath+0x28b/0x6e0
[   66.178851][    C0]  __alloc_frozen_pages_noprof (mm/page_alloc.c:5161)
[   66.179753][    C0]  __folio_alloc_noprof (mm/page_alloc.c:5183 mm/page_=
alloc.c:5192)
[   66.180583][    C0]  folio_prealloc+0x36/0x160
[   66.181430][    C0]  do_anonymous_page (mm/memory.c:4997 mm/memory.c:505=
4)
[   66.182288][    C0]  do_pte_missing (mm/memory.c:4232)
[   66.183062][    C0] Slab 0xe41bfb28 objects=3D21 used=3D17 fp=3D0xedf893=
20 flags=3D0x40000200(workingset|zone=3D1)
[   66.184609][    C0] Object 0xedf89b60 @offset=3D2912 fp=3D0xeac7a8b4
[   66.184609][    C0]
[   66.185960][    C0] Redzone  edf89b40: cc cc cc cc cc cc cc cc cc cc cc =
cc cc cc cc cc  ................
[   66.187388][    C0] Redzone  edf89b50: cc cc cc cc cc cc cc cc cc cc cc =
cc cc cc cc cc  ................
[   66.189695][    C0] Object   edf89b60: 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00 00 00  ................
[   66.191175][    C0] Object   edf89b70: 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00 00 00  ................
[   66.192701][    C0] Object   edf89b80: 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00 00 00  ................
[   66.194259][    C0] Object   edf89b90: 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00 00 00  ................
[   66.195753][    C0] Object   edf89ba0: 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00 00 00  ................
[   66.196836][  T248] sed invoked oom-killer: gfp_mask=3D0x140dca(GFP_HIGH=
USER_MOVABLE|__GFP_ZERO|__GFP_COMP), order=3D0, oom_score_adj=3D-1000
[   66.197239][    C0] Object   edf89bb0: 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00 00 00  ................
[   66.197395][    C0] Redzone  edf89bc0: cc cc cc cc                      =
                ....
[   66.197402][    C0] Padding  edf89bf4: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a =
5a              ZZZZZZZZZZZZ
[   66.197406][    C0] Disabling lock debugging due to kernel taint
[   66.203107][  T248] CPU: 1 UID: 0 PID: 248 Comm: sed Not tainted 6.17.0-=
rc3-00014-gaf92793e52c3 #1 PREEMPTLAZY  2cffa6c1ad8b595a5f5738a3e143d70494d=
8da79
[   66.203119][  T248] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996=
), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
[   66.203122][  T248] Call Trace:
[   66.203125][  T248]  ? show_stack (arch/x86/kernel/dumpstack.c:319)
[   66.203139][  T248]  dump_stack_lvl (lib/dump_stack.c:122)
[   66.203148][  T248]  dump_stack (lib/dump_stack.c:130)
[   66.203153][  T248]  dump_header (mm/oom_kill.c:468 (discriminator 1))
[   66.203165][  T248]  oom_kill_process.cold (mm/oom_kill.c:450 (discrimin=
ator 1) mm/oom_kill.c:1041 (discriminator 1))
[   66.203174][  T248]  out_of_memory (mm/oom_kill.c:1180)
[   66.203184][  T248]  __alloc_pages_may_oom (mm/page_alloc.c:4026)
[   66.203199][  T248]  __alloc_pages_slowpath+0x39d/0x6e0
[   66.203210][  T248]  __alloc_frozen_pages_noprof (mm/page_alloc.c:5161)
[   66.203221][  T248]  __folio_alloc_noprof (mm/page_alloc.c:5183 mm/page_=
alloc.c:5192)
[   66.203227][  T248]  folio_prealloc+0x36/0x160
[   66.203234][  T248]  do_anonymous_page (mm/memory.c:4997 mm/memory.c:505=
4)
[   66.203239][  T248]  ? handle_pte_fault (include/linux/rcupdate.h:341 in=
clude/linux/rcupdate.h:871 include/linux/pgtable.h:136 mm/memory.c:6046)
[   66.203244][  T248]  ? handle_pte_fault (include/linux/spinlock.h:391 mm=
/memory.c:6092)
[   66.203249][  T248]  ? rcu_is_watching (kernel/rcu/tree.c:752 (discrimin=
ator 4))
[   66.203256][  T248]  do_pte_missing (mm/memory.c:4232)
[   66.203260][  T248]  ? handle_pte_fault (arch/x86/include/asm/preempt.h:=
104 (discriminator 1) include/linux/rcupdate.h:100 (discriminator 1) includ=
e/linux/rcupdate.h:873 (discriminator 1) include/linux/pgtable.h:136 (discr=
iminator 1) mm/memory.c:6046 (discriminator 1))
[   66.203267][  T248]  handle_pte_fault (mm/memory.c:6052)
[   66.203275][  T248]  handle_mm_fault (mm/memory.c:6195 mm/memory.c:6364)
[   66.203289][  T248]  do_user_addr_fault (include/linux/sched/signal.h:42=
3 (discriminator 1) arch/x86/mm/fault.c:1389 (discriminator 1))
[   66.203301][  T248]  exc_page_fault (arch/x86/include/asm/irqflags.h:26 =
arch/x86/include/asm/irqflags.h:109 arch/x86/include/asm/irqflags.h:151 arc=
h/x86/mm/fault.c:1484 arch/x86/mm/fault.c:1532)
[   66.203310][  T248]  ? pvclock_clocksource_read_nowd (arch/x86/mm/fault.=
c:1489)
[   66.203316][  T248]  handle_exception (arch/x86/entry/entry_32.S:1055)
[   66.203319][  T248] EIP: 0xb7d730cf
[   66.203325][  T248] Code: 8d 04 33 8d 92 40 07 00 00 89 45 38 39 d5 ba 0=
0 00 00 00 0f 44 fa 83 c9 01 09 f7 89 fa 8d 7b 08 83 ca 01 89 53 04 8b 54 2=
4 04 <89> 48 04 89 f8 e8 a7 cb ff ff e9 93 f7 ff ff 8b 44 24 08 8b 74 24
All code
=3D=3D=3D=3D=3D=3D=3D=3D
   0:	8d 04 33             	lea    (%rbx,%rsi,1),%eax
   3:	8d 92 40 07 00 00    	lea    0x740(%rdx),%edx
   9:	89 45 38             	mov    %eax,0x38(%rbp)
   c:	39 d5                	cmp    %edx,%ebp
   e:	ba 00 00 00 00       	mov    $0x0,%edx
  13:	0f 44 fa             	cmove  %edx,%edi
  16:	83 c9 01             	or     $0x1,%ecx
  19:	09 f7                	or     %esi,%edi
  1b:	89 fa                	mov    %edi,%edx
  1d:	8d 7b 08             	lea    0x8(%rbx),%edi
  20:	83 ca 01             	or     $0x1,%edx
  23:	89 53 04             	mov    %edx,0x4(%rbx)
  26:	8b 54 24 04          	mov    0x4(%rsp),%edx
  2a:*	89 48 04             	mov    %ecx,0x4(%rax)		<-- trapping instructio=
n
  2d:	89 f8                	mov    %edi,%eax
  2f:	e8 a7 cb ff ff       	call   0xffffffffffffcbdb
  34:	e9 93 f7 ff ff       	jmp    0xfffffffffffff7cc
  39:	8b 44 24 08          	mov    0x8(%rsp),%eax
  3d:	8b                   	.byte 0x8b
  3e:	74 24                	je     0x64

Code starting with the faulting instruction
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
   0:	89 48 04             	mov    %ecx,0x4(%rax)
   3:	89 f8                	mov    %edi,%eax
   5:	e8 a7 cb ff ff       	call   0xffffffffffffcbb1
   a:	e9 93 f7 ff ff       	jmp    0xfffffffffffff7a2
   f:	8b 44 24 08          	mov    0x8(%rsp),%eax
  13:	8b                   	.byte 0x8b
  14:	74 24                	je     0x3a


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20251010/202510101652.7921fdc6-lkp@=
intel.com



--=20
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02510101652.7921fdc6-lkp%40intel.com.
