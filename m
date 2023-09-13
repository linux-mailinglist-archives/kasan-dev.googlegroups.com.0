Return-Path: <kasan-dev+bncBD2KV7O4UQOBBW7OQWUAMGQEQC736TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 9178779E28C
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:48:28 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-402d63aeea0sf53664725e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 01:48:28 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694594908; x=1695199708; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Gfk9WgizLI8q2xHNrFHzQ2FDliX08RY6xksp/vRgHp0=;
        b=XlwARVxwkbS95IcK3yqws/UACZU/2UpPu7L02qbBZZOCsNoJ3GNsmwtxUHDzeFjVxw
         fTOOupTKO0YUSWYlzTf0A3UmvKiwa2gIqZA6KqSCo4jALHTenr7zBeSzgAKeqZpRAOI8
         c7h1SxBBSiqWfkUKcrCIcJT9NzmEQUQxQzuhEBeeD8WRdbkjSHguNIh5rWcO++51g70v
         fbzdkjw9CtL67iVCzVMLCQrRgEBzdjcU0JHaJ15dRWZgSxasevB+4FTqxzmswKFByCXW
         e7ziw1LNVx24xkoY1EY3sWCMYVytIU8DyT6hpqaYGBEP7a+3GnCd+P39OhQH4bsm11aG
         3hMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694594908; x=1695199708;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Gfk9WgizLI8q2xHNrFHzQ2FDliX08RY6xksp/vRgHp0=;
        b=Uks3uI/ZrjVgHoazlbkCpSxsuUq0Ei01PsbO2d/w2pteiVPgoJtvKl//Oy9ikm+wUy
         3UyxpZl3pTxGleLTNabQQwgbcdiwqoZ76jxIvxIOdyARGOs41+YSAeZnkPDk56IilbSp
         76Z1VfFEIJEG9BJXW3ZFg7jWN3+6/C0c6BDoCnwXhzxVQA3tiiXyGDJnLZ5rmpOSZP87
         xTE5RUHMUlIpb+LebqIoIqxK7tqfXs9tq459fIFZvY1y5r0upMiXsWZ49hMJHkDVtOZ3
         Sqdseo28SUq1ekvmKtMa6yPz4zbQ9gmtI+EwRC+V5U89iKi4B91/LTN9oyOHkPBvzmt6
         xqsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw+sP5KE+iM95COn+sieDWeodMGjAQN6qVXDEzT0RskxskLAy0x
	F8gF2YpGdWumtg2ifWoJx6A=
X-Google-Smtp-Source: AGHT+IHg50DVrY+WnA/GcQdOhDGp/+K+wVSpT+snhMTfHtPZdXAEwKA7nY/jyO2RHG34uxeYs4iP3Q==
X-Received: by 2002:a1c:4c0d:0:b0:3fd:3006:410b with SMTP id z13-20020a1c4c0d000000b003fd3006410bmr1472278wmf.34.1694594907310;
        Wed, 13 Sep 2023 01:48:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:474e:b0:401:b3a5:ebfe with SMTP id
 w14-20020a05600c474e00b00401b3a5ebfels2438wmo.0.-pod-prod-03-eu; Wed, 13 Sep
 2023 01:48:25 -0700 (PDT)
X-Received: by 2002:a7b:c012:0:b0:3fe:dcd0:2e10 with SMTP id c18-20020a7bc012000000b003fedcd02e10mr1299610wmb.17.1694594905346;
        Wed, 13 Sep 2023 01:48:25 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id p25-20020a05600c1d9900b00401bbfb9b35si187882wms.0.2023.09.13.01.48.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Sep 2023 01:48:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6600,9927,10831"; a="378513677"
X-IronPort-AV: E=Sophos;i="6.02,142,1688454000"; 
   d="scan'208";a="378513677"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Sep 2023 01:48:20 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10831"; a="834230025"
X-IronPort-AV: E=Sophos;i="6.02,142,1688454000"; 
   d="scan'208";a="834230025"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by FMSMGA003.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 13 Sep 2023 01:48:20 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.32; Wed, 13 Sep 2023 01:48:20 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.32 via Frontend Transport; Wed, 13 Sep 2023 01:48:20 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.105)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.32; Wed, 13 Sep 2023 01:48:20 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=cOw/1+dQyu9GnCO5AZTY10YrhmQsgKCDKBHz7m9aHUMOWDvqsjlATEXwImKasJWihvHLxmMEjSFcSmbjg3s2sCCIPulNmGPKgspbC3FsJGGR/hvmVXZ56nnNl/03d0UjFY34Q+pAx9U5egtrkJKgvca15PP6wu1X5sCTDW+qxOrlCzC7YB/c2UIPpr2KV/LddURO3g90GWHIouDVpS5A2syUupxdHvv1cf3XpUkGFlR6VOuUScjsZq3oZxHJ8YKyaqXXXmfSamPmsHYucAqJmmRBHaEi3iJ2oWgAWM4ZBmm7kAnfnJs5rnFNNr+CGOyHeGxO4MOOrfmX6yQOyzh8rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qorAOQ27wIywuXKbjvyel1EN70RUWLrExmKxN+vJx9M=;
 b=O11wm+ZMfTEP6+mvzIjHcOLINLw0uQnhWUWUQYz58VbinjSih+B7SUAQXzuVHDzIhmF/LKE0zAuTMuIVYmU2uOb3Z3ihL7kVIhWYCCSuV2vbFgQDo+/HdjZipx0HMhgzZyWz8ziMpmPocZkxkkpcU+zvHaygTe7eyQv14Gt9wVspkcRizv6Q2RWU9Ts5TQ50Zy2PVvUdLy6RI0VWqfR6P/f1PZDLHhJqN+wDtIPhgT2/l5puBvBfIRNg4MGkGeANGB+3NwNq06fmLWYZ46VgcKHAkitWw+7ImTUdckTNOzSdMSuXhTfKHR57Ab9qCi/XpGEZBbs/BzhozdaDSvRY0A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from PH8PR11MB6779.namprd11.prod.outlook.com (2603:10b6:510:1ca::17)
 by PH7PR11MB8273.namprd11.prod.outlook.com (2603:10b6:510:1ac::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6768.31; Wed, 13 Sep
 2023 08:48:18 +0000
Received: from PH8PR11MB6779.namprd11.prod.outlook.com
 ([fe80::73c6:1231:e700:924]) by PH8PR11MB6779.namprd11.prod.outlook.com
 ([fe80::73c6:1231:e700:924%4]) with mapi id 15.20.6768.029; Wed, 13 Sep 2023
 08:48:18 +0000
Date: Wed, 13 Sep 2023 16:48:04 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, "Alexander
 Potapenko" <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>,
	Lorenzo Stoakes <lstoakes@gmail.com>, Kefeng Wang
	<wangkefeng.wang@huawei.com>, <oliver.sang@intel.com>
Subject: Re: [PATCH -rfc 3/3] mm: kasan: shadow: HACK: add
 cond_resched_lock() in kasan_depopulate_vmalloc_pte()
Message-ID: <202309131652.3e9c0f06-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230906124234.134200-4-wangkefeng.wang@huawei.com>
X-ClientProxiedBy: SG2PR02CA0010.apcprd02.prod.outlook.com
 (2603:1096:3:17::22) To PH8PR11MB6779.namprd11.prod.outlook.com
 (2603:10b6:510:1ca::17)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH8PR11MB6779:EE_|PH7PR11MB8273:EE_
X-MS-Office365-Filtering-Correlation-Id: 78bd339e-01c1-4c3e-7a46-08dbb4362be6
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: R4zHLYL1o2AAb125vrLoiLqmjpA6K1ZnTK7D++XFgegm4Pngu3CA7vI5eS52Z/89YBrs1wwj2jrBqoBxlrcqq6WXrYfyZpKLdG+62twhfWCMrgidNHaEge9RHAOC4oD5+TvOp3vd/oIH+GPitV86cQFpsOOg27AnGmajJXzJChc3WFaEzz8SVclIJy3LC9XCGL1Bj5LBmgExve3WPOrlm1hCNTjcQSIhlJCNQG0vuaZ9QaBmUmyxcgZFFVW891lzo3aKjIVdFifat5NBj4al6nBDcy4QBzcfi4VM6j/7Il4EfuTh2yBg/dtgmdEJS69VqvXwubRDxSO94THBsD7dQik4LO6hZkl6d6gsfAKGDJfeRCgpE8XfNl3sP630DeoDGO7/CIdH65ND6bjwCyokLngw9FcFXpTT3LM0o9LWCTCVQXxNjIku5eFtPOP4NbOUeeBAgtRyay790WYmhztjn4Eos+lMqxV7e7gCndqnAvOOxWJYKwRSJ9eeMIRFc+U3y5YJa9dGyhoHLh3PGkZGTHtxzyLlY0Thgs5Ewlg6eac38Uu/HgQDADcL4Z0Fuzkpt5XlMyUWj9uI9xymoM2EjprXYSpNje0rIPKrr1JTTrP8FxPhn5RedzV3vXaNweWmCoxaNRozGicIxixPF7SvbQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH8PR11MB6779.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(346002)(366004)(39860400002)(396003)(136003)(376002)(1800799009)(451199024)(186009)(66556008)(82960400001)(86362001)(5660300002)(38100700002)(7416002)(36756003)(4326008)(8936002)(8676002)(30864003)(54906003)(83380400001)(2906002)(6916009)(316002)(41300700001)(66946007)(6512007)(66476007)(1076003)(2616005)(107886003)(6486002)(6506007)(966005)(6666004)(26005)(478600001)(568244002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?CSvNSsf8TDrwUXrrwMl4li5/1jdYGKU0DPFbj1Qmsui1qolkmgjuvtxPm+0M?=
 =?us-ascii?Q?yT4COSjRNr/dYzxvAXsA/1LdzMNY9BMUDp1FX3YzDZW4HCCS0dvhKpRU7FWi?=
 =?us-ascii?Q?5LW66GxtAmniiNx7c4utBOJJHMLMnYYlVGSFqLYTO9B5F4Vy2/Ym6ctnIUT7?=
 =?us-ascii?Q?m2CXNbYvpN7/xUJEHdbbGEFe0vg0DgEmxHlWRpI3HrvqsnAYK/ms2YumdRYO?=
 =?us-ascii?Q?AuvlpmM2QwIZ6NgwK8wu/agi/7G4u7cj0+7x+7dsoMqVGkOkvKW5ziZibXf/?=
 =?us-ascii?Q?JJAASRHk5XJV9G03jXKKMm9D92guN7DWklhzev6/dE56cd8SLed+bt0xADE0?=
 =?us-ascii?Q?tH4oDOWEL0BqSWMlKw+cAHD54+HM12MAGJw3cN1X58NhoIECH2QTRA1x4FIL?=
 =?us-ascii?Q?+fBd815VsmU13BmD3QcuCgu8/48b2Tcf/F56atIFDBTG2WCR7dEFxjvNNOZ0?=
 =?us-ascii?Q?+/xrIh2ouARsLiaF2DbtPEQEvymTCzpCxh9iKFDAaefKeI9PTt+XVQgnB4gX?=
 =?us-ascii?Q?Uu4wjoW37czI3CsIePW77dcAzXoTP/n/hmL6watnEFMA1XLPB4KxBppz5Z+R?=
 =?us-ascii?Q?5x2L9EWCFR0+t+i/EqnVY1af8v6tPI62y08Af0/GEQz7J/NqExWNZ8UqblPZ?=
 =?us-ascii?Q?8iWIFSEsq4/7OJr5HWiAk5Ca0AVx3w6CIHywjlTUET4fpM45gOSG6BfyQDEN?=
 =?us-ascii?Q?W9CdYXSo/ONwTX1NgNJX59hvY9kgd4mfruBVhNaCe5wB7HnFQD50p0nkXQXb?=
 =?us-ascii?Q?EcaODd7w9L6/d64ktjsWqZMYwvAhE+Rv5aD/JxYcVRldLNplkDJocoxPdiSl?=
 =?us-ascii?Q?QAF/MH7H8VStET5v0zat86bFlj0aDYgiaeyCqMM7RWVa0BCaRBDBXsWKAyrd?=
 =?us-ascii?Q?PGc6UhChk2sZPKbWLFHCj/qNXY+IX8SOxe+wWxyBB/POQtkE9oK37wc0Iq/F?=
 =?us-ascii?Q?U7blaVwuq2pefyYsitmSC2wC7oCS/N5ekYuT+ufm/6/Q8U7t2TsOzDmYtobH?=
 =?us-ascii?Q?5UddqUq6zlydlAgPRLYouca3x1YW4g8ZwSiM+zOJEgjXfMrkfZ7hxKGFo/II?=
 =?us-ascii?Q?PwFqHtsERCCU7nusnHnncBqXgv9vIabNU6GSuDQHmWenacwdGYSVfRrfINM3?=
 =?us-ascii?Q?UM9MreKwcLXPxntSPIsuRYlEykR4T7PNpVj4Z/xWsg9huN5IN+3IEO1Cg1ps?=
 =?us-ascii?Q?sN3EpckX7o4PAq5MgTHu4XNlB1G16I52qTr+gbj5JbxG70HnvgvKchYkGdW1?=
 =?us-ascii?Q?JTi5Enl2bzFHpetxyoQ4IWKuZxKXKPuE9/uq+3d5GaJ74KdGCceRRc9//r18?=
 =?us-ascii?Q?G6c5PjDY1YC08MOrIR86XokNWpEH2ak23vNBq2U6mGWsQe9PDww8quV9FuZH?=
 =?us-ascii?Q?o4Zk1bjjQWyATl60by4QyPU+K+2qKfl+mz3ABmpj6jyEHFWW2uWns/UlzAKN?=
 =?us-ascii?Q?QBtgUGUr4TJ7E05F6qQOqEnMCKjHV0/z2qS4W1krTaJTKVu1yZ2efrZCOf3P?=
 =?us-ascii?Q?3efel1qS5Jo/zgEjCil789BAyijq8eambOW/vfkpzv3QjH4gItC4ohH8f61w?=
 =?us-ascii?Q?qnfXljU7cK/QrmZ2gqAZIYDWq7x97vx/MZ0Teb4l61vjCJ0JGKWB8ViQfxHp?=
 =?us-ascii?Q?vQ=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 78bd339e-01c1-4c3e-7a46-08dbb4362be6
X-MS-Exchange-CrossTenant-AuthSource: PH8PR11MB6779.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Sep 2023 08:48:17.9678
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: oEyDYEUwU2YwT17anJN0lBp9WYPvEG+stWFWFE//VU56jrrkWcaXq/ljasCOyrSJgoOMXEtTdjbDlxJ4hP2REQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR11MB8273
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=L1f5stPP;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 192.55.52.115 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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


hi, Kefeng Wang,

we don't have enough knowledge to connect below random issues with your change,
however, by running up to 300 times, we observed the parent keeps clean.
so make out this report FYI.
if you need more tests, please let us know. Thanks.

cb588b24f0fcf515 eaf065b089545219e27e529e3d6
---------------- ---------------------------
       fail:runs  %reproduction    fail:runs
           |             |             |
           :300          6%          17:300   dmesg.BUG:#DF_stack_guard_page_was_hit_at#(stack_is#..#)
           :300          0%           1:300   dmesg.BUG:#DF_stack_guard_page_was_hit_at(____ptrval____)(stack_is(____ptrval____)..(____ptrval____))
           :300          6%          18:300   dmesg.BUG:KASAN:stack-out-of-bounds_in_vsnprintf
           :300          6%          17:300   dmesg.BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)
           :300          0%           1:300   dmesg.BUG:TASK_stack_guard_page_was_hit_at(____ptrval____)(stack_is(____ptrval____)..(____ptrval____))
           :300          9%          28:300   dmesg.BUG:unable_to_handle_page_fault_for_address
           :300          3%           8:300   dmesg.Kernel_panic-not_syncing:Fatal_exception
           :300          7%          20:300   dmesg.Kernel_panic-not_syncing:Fatal_exception_in_interrupt
           :300          3%          10:300   dmesg.Oops:#[##]
           :300          6%          19:300   dmesg.RIP:__sanitizer_cov_trace_pc
           :300          5%          14:300   dmesg.RIP:exc_page_fault
           :300          6%          18:300   dmesg.WARNING:kernel_stack
           :300          6%          18:300   dmesg.WARNING:stack_recursion
           :300          6%          18:300   dmesg.stack_guard_page:#[##]


Hello,

kernel test robot noticed "BUG:TASK_stack_guard_page_was_hit_at#(stack_is#..#)" on:

commit: eaf065b089545219e27e529e3d6deac4c0bad525 ("[PATCH -rfc 3/3] mm: kasan: shadow: HACK: add cond_resched_lock() in kasan_depopulate_vmalloc_pte()")
url: https://github.com/intel-lab-lkp/linux/commits/Kefeng-Wang/mm-kasan-shadow-add-cond_resched-in-kasan_populate_vmalloc_pte/20230906-205407
base: https://git.kernel.org/cgit/linux/kernel/git/akpm/mm.git mm-everything
patch link: https://lore.kernel.org/all/20230906124234.134200-4-wangkefeng.wang@huawei.com/
patch subject: [PATCH -rfc 3/3] mm: kasan: shadow: HACK: add cond_resched_lock() in kasan_depopulate_vmalloc_pte()

in testcase: rcuscale
version: 
with following parameters:

	runtime: 300s
	scale_type: srcud



compiler: gcc-9
test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new version of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202309131652.3e9c0f06-oliver.sang@intel.com


[  114.366291][    C1] BUG: TASK stack guard page was hit at 00000000d230e938 (stack is 000000004315c7ed..00000000e1c06e40)
[  114.366312][    C1] stack guard page: 0000 [#1] SMP KASAN
[  114.366324][    C1] CPU: 1 PID: 400 Comm: systemd-journal Tainted: G        W        N 6.5.0-11778-geaf065b08954 #1
[  114.366338][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[ 114.366345][ C1] RIP: 0010:exc_page_fault (arch/x86/mm/fault.c:1518) 
[ 114.366365][ C1] Code: 89 ee e8 74 ca 7c fe 0f 1f 44 00 00 90 44 89 f6 4c 89 e7 e8 7d 0b 00 00 41 5c 41 5d 41 5e 5d c3 66 0f 1f 00 55 48 89 e5 41 57 <41> 56 41 55 49 89 f5 41 54 49 89 fc 0f 1f 44 00 00 41 0f 20 d6 65
All code
========
   0:	89 ee                	mov    %ebp,%esi
   2:	e8 74 ca 7c fe       	callq  0xfffffffffe7cca7b
   7:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
   c:	90                   	nop
   d:	44 89 f6             	mov    %r14d,%esi
  10:	4c 89 e7             	mov    %r12,%rdi
  13:	e8 7d 0b 00 00       	callq  0xb95
  18:	41 5c                	pop    %r12
  1a:	41 5d                	pop    %r13
  1c:	41 5e                	pop    %r14
  1e:	5d                   	pop    %rbp
  1f:	c3                   	retq   
  20:	66 0f 1f 00          	nopw   (%rax)
  24:	55                   	push   %rbp
  25:	48 89 e5             	mov    %rsp,%rbp
  28:	41 57                	push   %r15
  2a:*	41 56                	push   %r14		<-- trapping instruction
  2c:	41 55                	push   %r13
  2e:	49 89 f5             	mov    %rsi,%r13
  31:	41 54                	push   %r12
  33:	49 89 fc             	mov    %rdi,%r12
  36:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  3b:	41 0f 20 d6          	mov    %cr2,%r14
  3f:	65                   	gs

Code starting with the faulting instruction
===========================================
   0:	41 56                	push   %r14
   2:	41 55                	push   %r13
   4:	49 89 f5             	mov    %rsi,%r13
   7:	41 54                	push   %r12
   9:	49 89 fc             	mov    %rdi,%r12
   c:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  11:	41 0f 20 d6          	mov    %cr2,%r14
  15:	65                   	gs
[  114.366375][    C1] RSP: 0000:ffffc90001388000 EFLAGS: 00210087
[  114.366386][    C1] RAX: ffffc90001388018 RBX: 0000000000000000 RCX: ffffffff84801717
[  114.366394][    C1] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffc90001388018
[  114.366401][    C1] RBP: ffffc90001388008 R08: 0000000000000000 R09: 0000000000000000
[  114.366409][    C1] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[  114.366416][    C1] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[  114.366423][    C1] FS:  0000000000000000(0000) GS:ffff8883af500000(0063) knlGS:00000000f516bb40
[  114.366433][    C1] CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
[  114.366441][    C1] CR2: ffffc90001387ff8 CR3: 00000001bcfc9000 CR4: 00000000000406a0
[  114.366451][    C1] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[  114.366459][    C1] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[  114.366466][    C1] Call Trace:
[  114.366473][    C1] BUG: unable to handle page fault for address: fffff52000271002
[  114.366479][    C1] #PF: supervisor read access in kernel mode
[  114.366485][    C1] #PF: error_code(0x0000) - not-present page
[  114.366491][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366513][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366518][    C1] #PF: supervisor read access in kernel mode
[  114.366524][    C1] #PF: error_code(0x0000) - not-present page
[  114.366529][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366549][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366554][    C1] #PF: supervisor read access in kernel mode
[  114.366559][    C1] #PF: error_code(0x0000) - not-present page
[  114.366565][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366584][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366589][    C1] #PF: supervisor read access in kernel mode
[  114.366595][    C1] #PF: error_code(0x0000) - not-present page
[  114.366600][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366620][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366625][    C1] #PF: supervisor read access in kernel mode
[  114.366630][    C1] #PF: error_code(0x0000) - not-present page
[  114.366635][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366655][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366660][    C1] #PF: supervisor read access in kernel mode
[  114.366666][    C1] #PF: error_code(0x0000) - not-present page
[  114.366671][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366691][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366695][    C1] #PF: supervisor read access in kernel mode
[  114.366701][    C1] #PF: error_code(0x0000) - not-present page
[  114.366706][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366726][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366731][    C1] #PF: supervisor read access in kernel mode
[  114.366736][    C1] #PF: error_code(0x0000) - not-present page
[  114.366741][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366761][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366766][    C1] #PF: supervisor read access in kernel mode
[  114.366771][    C1] #PF: error_code(0x0000) - not-present page
[  114.366776][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366796][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366801][    C1] #PF: supervisor read access in kernel mode
[  114.366807][    C1] #PF: error_code(0x0000) - not-present page
[  114.366811][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366831][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366836][    C1] #PF: supervisor read access in kernel mode
[  114.366842][    C1] #PF: error_code(0x0000) - not-present page
[  114.366847][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366866][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366871][    C1] #PF: supervisor read access in kernel mode
[  114.366877][    C1] #PF: error_code(0x0000) - not-present page
[  114.366882][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366902][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366907][    C1] #PF: supervisor read access in kernel mode
[  114.366912][    C1] #PF: error_code(0x0000) - not-present page
[  114.366917][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366932][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366937][    C1] #PF: supervisor read access in kernel mode
[  114.366942][    C1] #PF: error_code(0x0000) - not-present page
[  114.366947][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.366966][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.366971][    C1] #PF: supervisor read access in kernel mode
[  114.366976][    C1] #PF: error_code(0x0000) - not-present page
[  114.366981][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.367001][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.367006][    C1] #PF: supervisor read access in kernel mode
[  114.367012][    C1] #PF: error_code(0x0000) - not-present page
[  114.367016][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.367036][    C1] BUG: unable to handle page fault for address: fffff52000271000
[  114.367042][    C1] #PF: supervisor read access in kernel mode
[  114.367047][    C1] #PF: error_code(0x0000) - not-present page
[  114.367052][    C1] PGD 417fdf067 P4D 417fdf067 PUD 1009ad067 PMD 14692d067 PTE 0
[  114.367075][    C1] BUG: #DF stack guard page was hit at 0000000071957a17 (stack is 00000000d15a2314..00000000d7ec09e2)
[  114.367086][    C1] stack guard page: 0000 [#2] SMP KASAN
[  114.367095][    C1] CPU: 1 PID: 400 Comm: systemd-journal Tainted: G        W        N 6.5.0-11778-geaf065b08954 #1
[  114.367107][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[  114.367121][    C1] ==================================================================
[ 114.367125][ C1] BUG: KASAN: stack-out-of-bounds in vsnprintf (lib/vsprintf.c:2851) 
[  114.367141][    C1] Read of size 8 at addr fffffe39ea66b3c0 by task systemd-journal/400
[  114.367150][    C1]
[  114.367153][    C1] CPU: 1 PID: 400 Comm: systemd-journal Tainted: G        W        N 6.5.0-11778-geaf065b08954 #1
[  114.367165][    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
[  114.367172][    C1] Call Trace:
[  114.367176][    C1]  <#DF>
[ 114.367181][ C1] dump_stack_lvl (lib/dump_stack.c:107 (discriminator 4)) 
[ 114.367197][ C1] print_address_description+0x7d/0x2ee 
[ 114.367219][ C1] print_report (mm/kasan/report.c:476) 
[ 114.367234][ C1] ? vsnprintf (lib/vsprintf.c:2851) 
[ 114.367248][ C1] ? kasan_addr_to_slab (mm/kasan/common.c:35) 
[ 114.367265][ C1] ? vsnprintf (lib/vsprintf.c:2851) 
[ 114.367278][ C1] kasan_report (mm/kasan/report.c:590) 
[ 114.367293][ C1] ? format_decode (lib/vsprintf.c:2526) 
[ 114.367308][ C1] ? vsnprintf (lib/vsprintf.c:2851) 
[ 114.367327][ C1] __asan_report_load8_noabort (mm/kasan/report_generic.c:381) 
[ 114.367346][ C1] vsnprintf (lib/vsprintf.c:2851) 
[ 114.367365][ C1] ? pointer (lib/vsprintf.c:2749) 
[ 114.367384][ C1] sprintf (lib/vsprintf.c:3017) 
[ 114.367399][ C1] ? snprintf (lib/vsprintf.c:3017) 
[ 114.367411][ C1] ? kallsyms_sym_address (kernel/kallsyms.c:164) 
[ 114.367426][ C1] ? kallsyms_expand_symbol+0x1f1/0x231 
[ 114.367443][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200) 
[ 114.367460][ C1] ? kallsyms_lookup_buildid (kernel/kallsyms.c:437) 
[ 114.367476][ C1] __sprint_symbol+0x15b/0x1ec 
[ 114.367491][ C1] ? kallsyms_lookup_buildid (kernel/kallsyms.c:482) 
[ 114.367504][ C1] ? page_fault_oops (arch/x86/mm/fault.c:699) 
[ 114.367516][ C1] ? fixup_exception (arch/x86/mm/extable.c:305) 
[ 114.367550][ C1] ? kernelmode_fixup_or_oops (arch/x86/mm/fault.c:761) 
[ 114.367566][ C1] ? __bad_area_nosemaphore (arch/x86/mm/fault.c:819) 
[ 114.367579][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200) 
[ 114.367597][ C1] sprint_symbol (kernel/kallsyms.c:536) 
[ 114.367609][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200) 
[ 114.367625][ C1] symbol_string (lib/vsprintf.c:1001) 
[ 114.367639][ C1] ? ip4_addr_string (lib/vsprintf.c:983) 
[ 114.367656][ C1] ? asm_exc_page_fault (arch/x86/include/asm/idtentry.h:570) 
[ 114.367677][ C1] ? page_fault_oops (include/linux/sched/task_stack.h:31 arch/x86/mm/fault.c:699) 
[ 114.367689][ C1] ? page_fault_oops (arch/x86/mm/fault.c:699) 
[ 114.367706][ C1] ? dump_pagetable (arch/x86/mm/fault.c:635) 
[ 114.367718][ C1] ? search_extable (lib/extable.c:115) 
[ 114.367731][ C1] ? is_prefetch+0x36f/0x3b4 
[ 114.367745][ C1] ? spurious_kernel_fault_check (arch/x86/mm/fault.c:122) 
[ 114.367758][ C1] ? search_module_extables (arch/x86/include/asm/preempt.h:85 kernel/module/main.c:3236) 
[ 114.367775][ C1] ? widen_string (lib/vsprintf.c:618) 
[ 114.367792][ C1] ? widen_string (lib/vsprintf.c:618) 
[ 114.367805][ C1] ? set_precision (lib/vsprintf.c:618) 
[ 114.367824][ C1] ? string_nocheck (lib/vsprintf.c:640) 
[ 114.367838][ C1] ? number (lib/vsprintf.c:573) 
[ 114.367854][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200) 
[ 114.367872][ C1] pointer (lib/vsprintf.c:2416) 
[ 114.367887][ C1] ? va_format+0x1a1/0x1a1 
[ 114.367900][ C1] ? hex_string (lib/vsprintf.c:723) 
[ 114.367919][ C1] vsnprintf (lib/vsprintf.c:2822) 
[ 114.367937][ C1] ? pointer (lib/vsprintf.c:2749) 
[ 114.367952][ C1] ? kvm_sched_clock_read (arch/x86/kernel/kvmclock.c:91) 
[ 114.367966][ C1] ? sched_clock_noinstr (arch/x86/kernel/tsc.c:267) 
[ 114.367982][ C1] vprintk_store (kernel/printk/printk.c:2193) 
[ 114.367996][ C1] ? __kasan_check_write (mm/kasan/shadow.c:38) 
[ 114.368011][ C1] ? printk_sprint (kernel/printk/printk.c:2158) 
[ 114.368028][ C1] ? printk_sprint (kernel/printk/printk.c:2158) 
[ 114.368057][ C1] vprintk_emit (kernel/printk/printk.c:2290) 
[ 114.368074][ C1] vprintk_deferred (kernel/printk/printk.c:3911) 
[ 114.368089][ C1] vprintk (kernel/printk/printk_safe.c:42) 
[ 114.368104][ C1] _printk (kernel/printk/printk.c:2329) 
[ 114.368116][ C1] ? syslog_print (kernel/printk/printk.c:2329) 
[ 114.368127][ C1] ? vprintk (kernel/printk/printk_safe.c:46) 
[ 114.368143][ C1] ? syslog_print (kernel/printk/printk.c:2329) 
[ 114.368157][ C1] ? __sanitizer_cov_trace_pc (kernel/kcov.c:200) 
[ 114.368175][ C1] show_ip (arch/x86/kernel/dumpstack.c:144) 
[ 114.368188][ C1] show_iret_regs (arch/x86/kernel/dumpstack.c:150) 
[ 114.368200][ C1] __show_regs (arch/x86/kernel/process_64.c:77) 
[ 114.368214][ C1] ? dump_stack_print_info (lib/dump_stack.c:71) 
[ 114.368231][ C1] show_regs (arch/x86/kernel/dumpstack.c:477) 
[ 114.368243][ C1] __die_body (arch/x86/kernel/dumpstack.c:421) 
[ 114.368256][ C1] __die (arch/x86/kernel/dumpstack.c:435) 
[ 114.368268][ C1] die (arch/x86/kernel/dumpstack.c:448) 
[ 114.368280][ C1] handle_stack_overflow (arch/x86/kernel/traps.c:327) 
[ 114.368298][ C1] exc_double_fault (arch/x86/kernel/traps.c:464) 
[ 114.368315][ C1] asm_exc_double_fault (arch/x86/include/asm/idtentry.h:611) 
[ 114.368329][ C1] RIP: 0010:__sanitizer_cov_trace_pc (kernel/kcov.c:200) 
[ 114.368347][ C1] Code: 00 00 48 c1 e6 38 48 21 fe 74 12 b8 01 00 00 00 48 c1 e0 38 48 39 c6 b0 00 0f 44 c2 c3 85 ff 0f 44 c1 c3 31 c0 c3 f3 0f 1e fa <55> 65 8b 05 6e 52 f0 7c 89 c1 48 89 e5 81 e1 00 01 00 00 48 8b 75
All code
========
   0:	00 00                	add    %al,(%rax)
   2:	48 c1 e6 38          	shl    $0x38,%rsi
   6:	48 21 fe             	and    %rdi,%rsi
   9:	74 12                	je     0x1d
   b:	b8 01 00 00 00       	mov    $0x1,%eax
  10:	48 c1 e0 38          	shl    $0x38,%rax
  14:	48 39 c6             	cmp    %rax,%rsi
  17:	b0 00                	mov    $0x0,%al
  19:	0f 44 c2             	cmove  %edx,%eax
  1c:	c3                   	retq   
  1d:	85 ff                	test   %edi,%edi
  1f:	0f 44 c1             	cmove  %ecx,%eax
  22:	c3                   	retq   
  23:	31 c0                	xor    %eax,%eax
  25:	c3                   	retq   
  26:	f3 0f 1e fa          	endbr64 
  2a:*	55                   	push   %rbp		<-- trapping instruction
  2b:	65 8b 05 6e 52 f0 7c 	mov    %gs:0x7cf0526e(%rip),%eax        # 0x7cf052a0
  32:	89 c1                	mov    %eax,%ecx
  34:	48 89 e5             	mov    %rsp,%rbp
  37:	81 e1 00 01 00 00    	and    $0x100,%ecx
  3d:	48                   	rex.W
  3e:	8b                   	.byte 0x8b
  3f:	75                   	.byte 0x75

Code starting with the faulting instruction
===========================================
   0:	55                   	push   %rbp
   1:	65 8b 05 6e 52 f0 7c 	mov    %gs:0x7cf0526e(%rip),%eax        # 0x7cf05276
   8:	89 c1                	mov    %eax,%ecx
   a:	48 89 e5             	mov    %rsp,%rbp
   d:	81 e1 00 01 00 00    	and    $0x100,%ecx
  13:	48                   	rex.W
  14:	8b                   	.byte 0x8b
  15:	75                   	.byte 0x75


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20230913/202309131652.3e9c0f06-oliver.sang@intel.com



-- 
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202309131652.3e9c0f06-oliver.sang%40intel.com.
