Return-Path: <kasan-dev+bncBD2KV7O4UQOBB6MPUOYAMGQEYJYUIOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F189892E41
	for <lists+kasan-dev@lfdr.de>; Sun, 31 Mar 2024 04:18:35 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-368814a0181sf27369865ab.1
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Mar 2024 19:18:35 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711851514; x=1712456314; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=niSg+4qltLPQtR1c+4T/XecjMRDAcS7uMqoYWCTLKdY=;
        b=rZ+MHxqhGhOv99UEUZFK31vhNwK4xbT9+4E2kiq3p4qm5qQjdJo6Ai+tPL2jq2DUli
         ASd651Xwllu8EpXPFLp+pad5QgSxf9/GZ7VraiM1IHn6uIy4nX4IcG50WB00V/GlX5zJ
         JiVD5iD5jklmLQQJzXKgT5HIQh0xTJ48JRhwqkdNbf8CjG+3P8PbYkN9NeO2cmo8wihZ
         p+fw/hqXTWQpVInQyCdlTZtpd7HNg1bLhDoPjc+QHL9kHiqXMcJI1NwfxMvjOLP5Y5yH
         FUD72fDeDtOnJHlkSzEL3hCQqdr73kCatcIrZkUE1kGA9GomnLI9XMBgvbLbDj179pmF
         L0WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711851514; x=1712456314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=niSg+4qltLPQtR1c+4T/XecjMRDAcS7uMqoYWCTLKdY=;
        b=RNhGhHbUhGRMajBuXMJWtwjkvww+Rt5oW9VNWRWclPLMr0F8x7RDtfpaN86/PgG7Ct
         6OwMpZ9Q9QzLlMD8daYcee7AfZOJEHVnEFmtkR+zsjWqOkLqTHAVxMpeO4ErhuJOom0r
         qFh1KloE5UOl6IsjCStidlzOLxrkwYoF8iX43qoCLLoCXQWxJwekmLd3GVb4i1oLU31R
         4erif+3U5CJa1l7KIOzxTLPH3bgGHxxwY04IW3O78cQd4UTi/rHUOketcMKQD+m2A02S
         AoQWf3mLWLVwV/h5EFEP7ActfDQtfZjvSkAjfD5orWMkmgJo+2WsLBQREstvTSxwLDTp
         uyng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXH6ke6tjKRNlWsxh3w9DvWGYFn7iK24p3sk3dv5qwttnCWSpNwV9HFaIxFjouziQeUiVghJLYahFiVQaJO36g8b0P9bBojaQ==
X-Gm-Message-State: AOJu0Yxs2GQSnCEw+KPPRkBfT5TU0UK0XeqJARVxaiudORnx3M5FZKN1
	S1+AatHB3qfRtCGIYtymKafVy0gTA0J7/sXMesP92Od5e9QG2J05
X-Google-Smtp-Source: AGHT+IGqBSlcL5FhslH+XJldLUHsYz/keeGqrpPnfuH/bffOQb2eTwA9neJbkTxMOzk5vwAc00rqWg==
X-Received: by 2002:a05:6e02:b4e:b0:368:4a19:a840 with SMTP id f14-20020a056e020b4e00b003684a19a840mr6592931ilu.22.1711851513747;
        Sat, 30 Mar 2024 19:18:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d81:b0:366:af4e:9df4 with SMTP id
 h1-20020a056e021d8100b00366af4e9df4ls2108091ila.0.-pod-prod-03-us; Sat, 30
 Mar 2024 19:18:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLbdmrtYEsLUCdgG+GcaBn0MA1ADFtf+LtE5tAWsBSFlcsILAPM33jRLvdJMarhoLmuYkQoK0sMLSbE0zzFNqcwRnG8Plt+CRopw==
X-Received: by 2002:a05:6e02:1d12:b0:368:9913:7ed4 with SMTP id i18-20020a056e021d1200b0036899137ed4mr7277803ila.25.1711851512422;
        Sat, 30 Mar 2024 19:18:32 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.19])
        by gmr-mx.google.com with ESMTPS id r11-20020a92c50b000000b003699900693dsi85964ilg.1.2024.03.30.19.18.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 30 Mar 2024 19:18:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.198.163.19 as permitted sender) client-ip=192.198.163.19;
X-CSE-ConnectionGUID: usYEMnppRfi8dk0LAergJQ==
X-CSE-MsgGUID: 2hbO8zOvT0yR5vqos5nOgg==
X-IronPort-AV: E=McAfee;i="6600,9927,11029"; a="6856778"
X-IronPort-AV: E=Sophos;i="6.07,169,1708416000"; 
   d="scan'208";a="6856778"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by fmvoesa113.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 30 Mar 2024 19:18:30 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.07,169,1708416000"; 
   d="scan'208";a="17755321"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by orviesa007.jf.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 30 Mar 2024 19:18:30 -0700
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Sat, 30 Mar 2024 19:18:29 -0700
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Sat, 30 Mar 2024 19:18:29 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35 via Frontend Transport; Sat, 30 Mar 2024 19:18:29 -0700
Received: from NAM04-MW2-obe.outbound.protection.outlook.com (104.47.73.168)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.35; Sat, 30 Mar 2024 19:18:28 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=XNBf9P945u4sLjKFvX9Judfph79a31axXL7Uai2Wuo4rCk3/JkiotWkx6jDhRUfZkX0xz+jnWC3g/ap6p+vOtYDH4x7dl0dbg3FNLl8zYJ22HnQofOXjv/ONtnZruVHnWqkq8EaeLkd1GoIR+4bBKXvyEbP8E9XajylXfB4jYza7Zz5DVE6+ax0s+jqA2hG99+Y1q0HgC3Hqv+Bezwt+20IKnwQeEwDuyzBToxCgCea0VhoQZTxgUPZvjNeLRMelvcWzkx7xiJVjAsJCkSvpfStn3tDdwqlI+XlvF7zB604tG7VwyEjv2kTvmNh7LS0j7pEcWyQSCO8I9vw3U9G+bA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=wQz7arY6mWYWkoLSSm2EF/02OgOAsaRD3dURPnOPrMw=;
 b=ErOH/bsIeDL+H1pJdJz+U+lYA8RjeGTTywkEeM/wEyGwMkJrD/dYrYMSn4R4Q5XpXZe0Q/8z2WZkxzDtM7rZq+TUfO0xgPrNkMeEo+fc+7GgDAhAqyc2Ytcv0saEDAMAJLUMcAVvAL5iKt+9NtoKZzuqvPjZsDNFrr2FrAxxUhwaG3ZAmr6TxxUEYBCWSRDsjW8KXhny4Hi/BPVjNJBr9ptJe8XcarvwWez0wG59kGea/9KfBhYsImDsurI6GAsXb1QSpjBd49dZk8stcHdv0hEsKvZDnk7K0vyK1tpDsfonHjTAQNBMoX2AwKzJ/iUm/MYSVBXU0V4bVilgWE+pug==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from LV3PR11MB8603.namprd11.prod.outlook.com (2603:10b6:408:1b6::9)
 by IA1PR11MB6193.namprd11.prod.outlook.com (2603:10b6:208:3eb::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7409.33; Sun, 31 Mar
 2024 02:18:27 +0000
Received: from LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::58dd:99ca:74a6:2e3e]) by LV3PR11MB8603.namprd11.prod.outlook.com
 ([fe80::58dd:99ca:74a6:2e3e%3]) with mapi id 15.20.7452.019; Sun, 31 Mar 2024
 02:18:27 +0000
Date: Sun, 31 Mar 2024 10:18:17 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Paul =?iso-8859-1?Q?Heidekr=FCger?= <paul.heidekrueger@tum.de>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <linux-kernel@vger.kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland
	<mark.rutland@arm.com>, Marco Elver <elver@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, "Andrey
 Ryabinin" <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, <kasan-dev@googlegroups.com>,
	<oliver.sang@intel.com>
Subject: [linus:master] [kasan]  4e76c8cc33:
 BUG:KASAN:slab-out-of-bounds_in_kasan_atomics_helper
Message-ID: <202403310849.3bb9f3d2-lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-ClientProxiedBy: SG2PR02CA0123.apcprd02.prod.outlook.com
 (2603:1096:4:188::22) To LV3PR11MB8603.namprd11.prod.outlook.com
 (2603:10b6:408:1b6::9)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV3PR11MB8603:EE_|IA1PR11MB6193:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: r8NY/wrzLotcmjVRbx6aMYWzQ79y6Qh9tYjRf6QGz99qXPRShT+MiLYyV5yh35x2nanpBpPfolygNsRWDV/7zksf2osv5OexcBHX+ldc3gdur9nUvMHet5R7ZLM9vP71BjA92iZC3Pj2jqzpagBalr+eMgFRUStecQApKMNaqgxbDM3tGHdA/Cxohya+1t0k00v5uerGr6eqJ4IdHgC1f0aKf+vHCTMGrB1596M8OgPAJZwVHJ3hDf8kiMkEdNgJ6d88fO2ge1LBz0nUkMIuyg2z5HHwtGJWdcLvd52NlOS1/zAFRyz0nmWVq8w0oB+1/mWSBe3e8ckCGI7334V8onaRFkFDtD0L3kk7nhbhieJ4aHKqBoa6pxvs91B88q++rGqO5BO70EZyVyhpzXOwnbzT9mAhFgXXip62U7FAdFNcgA++U/jFoA8rn6o+dNgToRK4o08dkIwrMIFBIaixG7Fqt6IymCpN6p3TtK5QfjfiCQDMKqiXFyeuaulyorIQjV26TGg3M1LgaZmG/GCz93o/ozCof2B04ShuuPdrrhLQ7q/QqYY692+HPaX8yBOvZB6NiAfiFksOVBmSqOgft/JPdUBYYZkQ56uJInmGOJpniL6e08wYxvWmJD5EStJd
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV3PR11MB8603.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(7416005)(1800799015)(376005)(366007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?x+7O+MA7VnUejDzzPWU5WPU9zYE1m6yg8TeJTCVGKHQv8AuL8QlXk7sD4Ga2?=
 =?us-ascii?Q?7/X81pQqdoDGYTSz4sHtlPQOyBgo8Ejq7HtlyxecsbuJMk+debCZB8jdGBMS?=
 =?us-ascii?Q?wCggl61pmt00e9nXPi2pro9rS4xMFd2Xk2O7+WUUnfEJT1LknE33p3Liy6gZ?=
 =?us-ascii?Q?3GeafpK9PVH01A46Ejnagx3fY306IWPVoAk6Gq8a4GcuB8ODidb7ZejT1zNK?=
 =?us-ascii?Q?C2DlLbvNVzvWvy7uEdWM6TDMaU413NDMfPsyo5yR5Fbeqdu7o9oVK7rhnQcX?=
 =?us-ascii?Q?S1D4ubutYdyX21J7BobKBwiJF7MxenHUxAm/UfO4RoOIT6axsqiaem+sSQGK?=
 =?us-ascii?Q?yYw6fKl7xou1TMk5Ewil6blv/kxm+X4EquRhtuD5EVDWNfSOssiDS4IGUn4G?=
 =?us-ascii?Q?/yaAFWvuXUr74m8AmyHkQ8G3t6Ll7cDCbUfWesF13Er+39MAuvpWv5ZNWtDV?=
 =?us-ascii?Q?eyKRDRznP/OLgyjOXesiG1Z1gRgBVmtlYMxXb0VhuaN+ck6VZBWPfYLDJD4T?=
 =?us-ascii?Q?3hEoWqNo44+kC7d79z2LtrE5oFhlIgdC3tcMCkonYXoN37W4jgDJnzYyBN+4?=
 =?us-ascii?Q?xFc8fD38al8AG21oyHBvcSBnc7f1HZGB1F2v8zHaU8aYxqH8Piehm869r49o?=
 =?us-ascii?Q?DP3aYYHLWU2F94TxKS+yl1a95bbV+4qZk6b3Gc/NDevrzEyqvEPm/XApUd2H?=
 =?us-ascii?Q?D5OOJ1HMKjMjFXScu4QrVDf1Kqan4zEXiA0weOlWbc1FLsgN8dUOQMBWeiRh?=
 =?us-ascii?Q?PuPz0TYN2EkT+PUhFCzSav5Q/ryLfG/whrV/LuJMaQ/gN6pVsKVjTNOUcPK9?=
 =?us-ascii?Q?fZGe7/viJvngDOl+w4c5AgDC2WuKtXDZqGaKB7y1YFDTOWqSZwDlMUWzi9w0?=
 =?us-ascii?Q?bHHeRiAf7AexqWqNIS0GYWQWsB0XtgC6ZGIlVaSB8Mn8P6ExGu2WKHD9SDUf?=
 =?us-ascii?Q?8W2J2g7dubjHEaKRZTvVZegRj85x7JtQhKAZCcaitZT6NMuvnJWGmirRfXt4?=
 =?us-ascii?Q?1TDaAGzCZ5nS0gwqJY833VG1zcovjnYCSB9teJvgnrxIU7jX6K5cS1jMXkUk?=
 =?us-ascii?Q?5UYsqHS6ngIcxJGkURmd/4wAtXcMyFR++msw3xoEdwqxg5O6uBsLBHwyRZJJ?=
 =?us-ascii?Q?Og+TcqGYOyOlyJw6SHjiF8fC7s1V5mrE+EOB6cpiGQUXERLSx6+Q9KefJ0o5?=
 =?us-ascii?Q?BAaQcx29DEoTaqcToWcoTsjYKQwL77aUgkHpgTtYm1T/V+BbQpC8cGkOY0L1?=
 =?us-ascii?Q?3cIuxmtQrzVkGud4Arjszda/P2ETcxObEvNLbz+7mVUfuNaVMtntwgBQFPyr?=
 =?us-ascii?Q?mzhnFrD26lxTt/RH8zEmpmxA2KZH0x9hEplhmOTC2wfW1tEkFyCYIVJQg4jd?=
 =?us-ascii?Q?hgNYrBns7A25BWjqf8xxdsbW/IacB1GgfK+9lnyQzMBxpXWEbZJOUuHuNDdi?=
 =?us-ascii?Q?W9UuzTlD69c4njhaZR5Uv+7ZdB7YuPgwMX3HoTqS9EhHDHvzkcYYIt81CzQs?=
 =?us-ascii?Q?PAzvtLnt64+qXXv2yIIF2u9TKURZ/4DPktEMS+vPQxcHZSi5YDhPDNy6A1U0?=
 =?us-ascii?Q?2v0Zzp6ms1PHpKSyFZRDa1wb3NffwaJ0G94Po92JFW2yH/4yoOQcy/CbOoKJ?=
 =?us-ascii?Q?lg=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 69af4b0d-119e-4b41-4297-08dc5128d984
X-MS-Exchange-CrossTenant-AuthSource: LV3PR11MB8603.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 31 Mar 2024 02:18:27.2577
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: P+plRRvNu9mzJOd+I1Nf8IPtvYuKoPv+4kj3UJS+vK3mvMHpx3QH6s1KbW1pf19EipIkOdY3XEM8pOkKSImh0w==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB6193
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ZoX+Knng;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 192.198.163.19 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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



Hello,

kernel test robot noticed "BUG:KASAN:slab-out-of-bounds_in_kasan_atomics_helper" on:

commit: 4e76c8cc3378a20923965e3345f40f6b8ae0bdba ("kasan: add atomic tests")
https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git master


[test failed on linus/master 8d025e2092e29bfd13e56c78e22af25fac83c8ec]
[test failed on linux-next/master a6bd6c9333397f5a0e2667d4d82fef8c970108f2]

in testcase: kunit
version: 
with following parameters:

	group: group-00



compiler: gcc-12
test machine: 16 threads 1 sockets Intel(R) Xeon(R) CPU D-1541 @ 2.10GHz (Broadwell-DE) with 48G memory

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202403310849.3bb9f3d2-lkp@intel.com


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20240331/202403310849.3bb9f3d2-lkp@intel.com



[  306.028382][ T4480] ==================================================================
[  306.047117][ T4480] BUG: KASAN: slab-out-of-bounds in kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
[  306.057673][ T4480] Read of size 4 at addr ffff888168de7330 by task kunit_try_catch/4480
[  306.067074][ T4480] 
[  306.070605][ T4480] CPU: 2 PID: 4480 Comm: kunit_try_catch Tainted: G S  B            N 6.8.0-rc5-00151-g4e76c8cc3378 #1
[  306.082834][ T4480] Hardware name: Supermicro SYS-5018D-FN4T/X10SDV-8C-TLN4F, BIOS 1.1 03/02/2016
[  306.093195][ T4480] Call Trace:
[  306.097725][ T4480]  <TASK>
[  306.101846][ T4480]  dump_stack_lvl+0x36/0x50
[  306.107696][ T4480]  print_address_description+0x2c/0x3a0
[  306.115489][ T4480]  ? kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
[  306.123367][ T4480]  print_report+0xba/0x2b0
[  306.129115][ T4480]  ? kasan_addr_to_slab+0xd/0x90
[  306.135383][ T4480]  ? kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
[  306.143412][ T4480]  kasan_report+0xe7/0x120
[  306.149087][ T4480]  ? kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
[  306.157076][ T4480]  kasan_atomics_helper+0x25d0/0x26b0 [kasan_test]
[  306.164966][ T4480]  ? kmalloc_oob_right+0x3e0/0x3e0 [kasan_test]
[  306.172608][ T4480]  ? kasan_save_track+0x14/0x30
[  306.178787][ T4480]  kasan_atomics+0xeb/0x190 [kasan_test]
[  306.185724][ T4480]  ? kasan_bitops_generic+0x140/0x140 [kasan_test]
[  306.193520][ T4480]  ? ktime_get_ts64+0x83/0x1b0
[  306.199669][ T4480]  kunit_try_run_case+0x1ab/0x480
[  306.206017][ T4480]  ? kunit_try_run_case_cleanup+0xe0/0xe0
[  306.213174][ T4480]  ? _raw_read_unlock_irqrestore+0x50/0x50
[  306.220337][ T4480]  ? set_cpus_allowed_ptr+0x85/0xb0
[  306.226821][ T4480]  ? migrate_enable+0x2a0/0x2a0
[  306.232966][ T4480]  ? kunit_try_catch_throw+0x80/0x80
[  306.239549][ T4480]  ? kunit_try_run_case_cleanup+0xe0/0xe0
[  306.246540][ T4480]  kunit_generic_run_threadfn_adapter+0x4e/0xa0
[  306.254054][ T4480]  kthread+0x2dd/0x3c0
[  306.259312][ T4480]  ? kthread_complete_and_exit+0x30/0x30
[  306.266147][ T4480]  ret_from_fork+0x31/0x70
[  306.271775][ T4480]  ? kthread_complete_and_exit+0x30/0x30
[  306.278575][ T4480]  ret_from_fork_asm+0x11/0x20
[  306.284413][ T4480]  </TASK>
[  306.288653][ T4480] 
[  306.292149][ T4480] Allocated by task 4480:
[  306.297686][ T4480]  kasan_save_stack+0x33/0x50
[  306.303495][ T4480]  kasan_save_track+0x14/0x30
[  306.309255][ T4480]  __kasan_kmalloc+0xa2/0xb0
[  306.314945][ T4480]  kasan_atomics+0x8c/0x190 [kasan_test]
[  306.321745][ T4480]  kunit_try_run_case+0x1ab/0x480
[  306.327860][ T4480]  kunit_generic_run_threadfn_adapter+0x4e/0xa0
[  306.335239][ T4480]  kthread+0x2dd/0x3c0
[  306.340469][ T4480]  ret_from_fork+0x31/0x70
[  306.346020][ T4480]  ret_from_fork_asm+0x11/0x20
[  306.351815][ T4480] 
[  306.355163][ T4480] The buggy address belongs to the object at ffff888168de7300
[  306.355163][ T4480]  which belongs to the cache kmalloc-64 of size 64
[  306.371174][ T4480] The buggy address is located 0 bytes to the right of
[  306.371174][ T4480]  allocated 48-byte region [ffff888168de7300, ffff888168de7330)
[  306.387688][ T4480] 
[  306.390884][ T4480] The buggy address belongs to the physical page:
[  306.398313][ T4480] page:000000005ccb3a22 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x168de7
[  306.409549][ T4480] flags: 0x17ffffc0000800(slab|node=0|zone=2|lastcpupid=0x1fffff)
[  306.418339][ T4480] page_type: 0xffffffff()
[  306.423762][ T4480] raw: 0017ffffc0000800 ffff888100042640 dead000000000100 dead000000000122
[  306.433384][ T4480] raw: 0000000000000000 0000000080200020 00000001ffffffff 0000000000000000
[  306.443077][ T4480] page dumped because: kasan: bad access detected
[  306.450608][ T4480] 
[  306.454016][ T4480] Memory state around the buggy address:
[  306.460748][ T4480]  ffff888168de7200: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
[  306.469821][ T4480]  ffff888168de7280: 00 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc
[  306.478894][ T4480] >ffff888168de7300: 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc fc
[  306.488019][ T4480]                                      ^
[  306.494672][ T4480]  ffff888168de7380: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
[  306.503812][ T4480]  ffff888168de7400: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
[  306.512946][ T4480] ==================================================================


-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202403310849.3bb9f3d2-lkp%40intel.com.
