Return-Path: <kasan-dev+bncBDN7L7O25EIBBHFDQONQMGQEQNTUCRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 06804614556
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Nov 2022 08:58:27 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id v23-20020a1cf717000000b003bff630f31asf3390162wmh.5
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 00:58:27 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vF0uDADz3UwJ4cpQcs9rzJ6pMiZL4IbgI1Bcwsf/Voo=;
        b=G+FrAzyqh8Zswwy5yBtf6LtecjqE9NYzNGgX6HXT6jElPBb0DzYqpAENLcIYec8fTZ
         BnPa7hvNmSghsHPeVS3fgLAVjh7bcW9zkI8Z9dhg//O/vlX2wwt3tJrU0Tc5FX0KX10t
         +QvjUUyS6EE8fjEAKtQqvcH1kPx5u1qZLBexMf9TsjrneY1iYTLWAaoJgjNgRcPtPhdp
         GOc7Zy11dltb80OUv0klzJf6nEBImw98efCSPUAI6LN/eIK1zubtQuxN6tADXWN1yrXD
         hg6ZRqVPT/s1Lj+d5QmSHwaMkJ7V0S/cg3wzRnC+WY1fYA8TiTMFR50Oair+hZo/sMUr
         +35w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vF0uDADz3UwJ4cpQcs9rzJ6pMiZL4IbgI1Bcwsf/Voo=;
        b=1JEhnXvDs+u35/A+/EPIMyuFGCFJpGLOEjmCP9+bQgo3FNWmudHwchW68W+LHiVR1/
         BoEC5vT6kSqFvWNaBGsBUhBJMdVt/xPy/r1xENGYYCkw4D9S484fIHwxkukWFABfWC+3
         cPGkaeIaJ7sDQyTDbzxlSeqO2+gep8Pwi+PFA9rcjIhaaYjMVqC+ZXHMcNSYNtTOLl7/
         72zo8bz9cbPPtN/75Tq7m+wgwjzwlDm9ZmAJe1+tT+qZ65Tij0lPwKtdlAqHTgC5Dftz
         nT1g/ZhtVyXr5az2M0TMwR38n/zoQacMDpyHMmFMXnJpqQaE5+s/r5OVqft6flodDWqc
         cDDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2Pz7JqMOXVP45dZLUiTI6wsWqf8aKZBoLFeE/RRKOmofVahPF/
	WuVe0oMpV7wDZXNZM6ey4NE=
X-Google-Smtp-Source: AMsMyM4AJnocHMlh1MnJSvCkgFo79Q9eSQ1PriXWBdY+N7PdSfGMUculO8PB7/OMIzqLj/u9Ol9tMg==
X-Received: by 2002:adf:e6c3:0:b0:236:acdb:4d9b with SMTP id y3-20020adfe6c3000000b00236acdb4d9bmr10347144wrm.528.1667289501254;
        Tue, 01 Nov 2022 00:58:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:247:b0:22c:d34e:768c with SMTP id
 m7-20020a056000024700b0022cd34e768cls2225870wrz.0.-pod-prod-gmail; Tue, 01
 Nov 2022 00:58:20 -0700 (PDT)
X-Received: by 2002:a5d:62d0:0:b0:236:a46d:4b77 with SMTP id o16-20020a5d62d0000000b00236a46d4b77mr10663862wrv.211.1667289500126;
        Tue, 01 Nov 2022 00:58:20 -0700 (PDT)
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id bv11-20020a0560001f0b00b00236845a6242si242628wrb.2.2022.11.01.00.58.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Nov 2022 00:58:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10517"; a="296515203"
X-IronPort-AV: E=Sophos;i="5.95,230,1661842800"; 
   d="scan'208";a="296515203"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Nov 2022 00:58:18 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10517"; a="776419624"
X-IronPort-AV: E=Sophos;i="5.95,230,1661842800"; 
   d="scan'208";a="776419624"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by fmsmga001.fm.intel.com with ESMTP; 01 Nov 2022 00:58:12 -0700
Received: from fmsmsx601.amr.corp.intel.com (10.18.126.81) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Tue, 1 Nov 2022 00:58:11 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Tue, 1 Nov 2022 00:58:11 -0700
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.109)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Tue, 1 Nov 2022 00:58:11 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=c27hQY59nRUas8d53oMvurXrROmZ0kKAAErrQ6/5W9BsHRjZPrHpALVv6Lguo/5fRG8lOIjooVBtGHzvt8nEIR+/oECFoRDMGWnSQYwyZvmBrPPg9ToOSSDPawPoYjrs6foyN6vk+UUyP/z0BxUBTELAsulDqOWXZBwZ+OSGt1qKOkYNPoMUxgIVDDa48SwUqY+3kmx5E2sZw/dnqB+1lir3doo0cRp6eQbm8J7f8eD6i1tesbCZMfbeVa6XHeHvXU7VcPPcbrBwkxGXl4cMf99pIdEWfYjWvIJvpxcMqz3hpTDQ7lwaSPTmzqDujYdxGFuHVmoZ3o5Zr3uUIVD/qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6zSLQeuGG66zx6XsnqAmAtqAZukaINP80wafUgiPX+Y=;
 b=GDlgg1gOqIxst0rrjnFOGKbb/4CdvgT/YMOYM/GLLuK8xswdAN+UWkWY7X3bx6RCySPKN1RZloo9qfRRuNMdXDWGM3LMgAttkhHU9CA4W0tyvacImm7rEzT9eu1TQPvmWUqzeiy60FCOXNMk47sFod6SDW2crTwRUac48cQTOcJxpcoZLB0eUsiAKUALcW091ljyYghzPODCBmZBSg1Hf/yXjnlaOOlZl52Nv4GrJDT2SEhvtH5Gl+Hz0ArEQ2yFcDg13PS3mDDo+bazrd9BgCaCtwQehNPYBOAbZitMYOosxg7RefAUTtDGSGxe1S737KeKe0qkpFU5PFqIXjDpiA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by CY8PR11MB6913.namprd11.prod.outlook.com (2603:10b6:930:5b::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5769.21; Tue, 1 Nov
 2022 07:58:03 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b%3]) with mapi id 15.20.5769.021; Tue, 1 Nov 2022
 07:58:02 +0000
Date: Tue, 1 Nov 2022 15:57:46 +0800
From: Feng Tang <feng.tang@intel.com>
To: John Thomson <lists@johnthomson.fastmail.com.au>
CC: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>, Andrey Konovalov <andreyknvl@gmail.com>,
	"Hansen, Dave" <dave.hansen@intel.com>, "linux-mm@kvack.org"
	<linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Robin Murphy <robin.murphy@arm.com>, John Garry
	<john.garry@huawei.com>, Kefeng Wang <wangkefeng.wang@huawei.com>, "Thomas
 Bogendoerfer" <tsbogend@alpha.franken.de>, <linux-mips@vger.kernel.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2DReuPHZungAGsU@feng-clx>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
 <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
X-ClientProxiedBy: SI2PR06CA0004.apcprd06.prod.outlook.com
 (2603:1096:4:186::20) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|CY8PR11MB6913:EE_
X-MS-Office365-Filtering-Correlation-Id: bebba90f-a2a1-42ec-d960-08dabbdecc9e
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: /+7bP2I29vYXjIsWpAyQ7XLL+k6QqsJQ8nkNhs+2O4puBx3RzB05AqmQ3rIPuCc2w6mfmG9rQl5NnzykzfQXKov5pCqb9yi6tyWR8iLj/2MVn+C9ibwgho6G5aAkn7ZMMukhGWtPZuLDve3l4u7UjBgkxmf6qjMPP5Tn758qUU1yN0y67gd67g5nn3pcS1hEryfcq55vMLYsuSpRSbPUtXA7V+qGnmt0U1ItdzWnN8JXDmRPa8ZCPIynok8OpNhN6neo10DL7V39zvOjRlGOOssksJHoRwEjhqybSb/cwgPVvBUo1Qcn79FQ3LVjABkeNCJ0UYiwU8Kup0XTLYbyVcRJt5GtYZLzW6d/raUacMhoP3FDGo03pu30OuMJXanXsauPoFKBILkz2GtiPNbNxTq+N8DjGZs6OIDzTcmOmzl1hylYNIcYReFiYlIjf5GwEwhJzduf6bquTjE49KtKXmHvuiJca6uRABTyf+7xIPgPrMVeY2xbIobKxAW6LKRVLjqT2T7p4jb16VR+Vmam52pdAMmLE3+L/a8sOAc2ci5b4+AOh1MlkhofwTzpTx4RQGJYTNdpHhHylMqJjj/wKA8JGNKER9ZDleRieSAGFC7Phw7zj6H0yBYcaYqtcmPAARCMErrqmdzGzE6gGwoCNHcihlj6NBhQe0I1VMaT0XrUyXzCMDRHyx3D8AovRBJQ5JTy+Febyq2ZW58c4oZgEqczPjjA+GQYUH5mjWMJZuM=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(366004)(376002)(136003)(39860400002)(346002)(396003)(451199015)(83380400001)(33716001)(86362001)(82960400001)(38100700002)(6916009)(54906003)(316002)(6666004)(44832011)(7416002)(5660300002)(186003)(6486002)(2906002)(966005)(6512007)(9686003)(41300700001)(26005)(6506007)(8676002)(4326008)(66476007)(66556008)(66946007)(478600001)(8936002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?l+qgPhplE+K9mYy+8IwfgB2GrWBaXneQSj5P1LzWUfSVFPJBzEtg+4/qTeRd?=
 =?us-ascii?Q?Vs9HPB/z/U9LklfGAcocFn5JU0gJ4nWsvbTuBC6JB0WBkP6lWI8QcIuV5sHg?=
 =?us-ascii?Q?i9oiSe16oboG/kHMQpfjB0E3iBbbntcCwZ/eKkeyeYnZ6Y9DD4BVCkhLtB+T?=
 =?us-ascii?Q?WJhi6RV5G97iyfWzf73hjh1itn4p7bFaunt6Z/9MHiEp6+xmm617OZJW3smK?=
 =?us-ascii?Q?dtvFKyOxRflEN+trUJGB7FYNqgz+zkj5v/KOjZOCtoUgqdcba8HwwP4bdRxD?=
 =?us-ascii?Q?CfUFOnHhRPEnRoBRhlOr10I2mq287bnKcZRIfYii1aSNxj0BJcOJAgZ6P4Mh?=
 =?us-ascii?Q?/ycS889EW0cKBcRHRaastvUGU0XH1vYeiHk/xP+hi3vQocfxdObrpLDhux0F?=
 =?us-ascii?Q?4zM/iu5L4T32s2PzohGYN8jSrMQEGn4oMuxpWHigbayhSQR+4d+/Shv+MmHa?=
 =?us-ascii?Q?qri42B6X2e7rIhaYWXljdMp2iPuKZCql/p/k7n9FCEK7uLpi4G64lVAOS5Yg?=
 =?us-ascii?Q?TAeM98pvXphNyLudBnUKWNWzVy5g/1JYLjFQjlykvXcp25LMgpsLsyYu7KyQ?=
 =?us-ascii?Q?OobJuBV5jCwBgFm2F7P6shTcxqaQKQ4eLwOHR6ckRuvlfD/PxOz3ZepnCmKl?=
 =?us-ascii?Q?vE5VcqPBE0tGBeUiJixQLSptRf0HZjnk55GMPJa4dU4nDitrgdA5vwWCcdSx?=
 =?us-ascii?Q?IRl7l0lErJUlUKMwL4cw2heOzBD/48NBHGJ/o6HfvugP4QTjMpvt90DbpwDT?=
 =?us-ascii?Q?gibPd1hmNc6dPUFBF5fTyLdjW6U+nxULJOhrb3Uh29YGVouiwwz7MOt7ba10?=
 =?us-ascii?Q?mNneKyQt1SGx+jh9m33x7hz3ICPogfyKlI5twUjmDzK51Nx4hzH3Gqo3MMFb?=
 =?us-ascii?Q?yIxXOZLZq1vZxvDQDNQpfhBmj+slOrRmCHyTE1A1lzde3ANfNFKSueVqHymb?=
 =?us-ascii?Q?qi/dvje94XxBq3UJe3+0QG8Qm/BEYauUmitoXJnAGjmY8HJPbtK3fmNxo1zV?=
 =?us-ascii?Q?88mine/jAcXpEeijcLFlCgPRdGpj1zwujTaaG1nbjY9Ru/c0K69RU8uSczKZ?=
 =?us-ascii?Q?kDbOsVouEDK6ub2rPBZ0SbsTTyqdaVg0j/IxqpP3JW4i1NCKmkWmvngEmTfP?=
 =?us-ascii?Q?MfR0i8Wl3lCYoFw2JyAQhUhL93fdLz7QFyfjlM3w5fcftGsh6srmF05XCWEJ?=
 =?us-ascii?Q?bqQWNPfpqZpS6FK/uBlxdUt3hpN2oiw0coiICFrb8PU4o39yHwNI7JRfmmQt?=
 =?us-ascii?Q?lRShYe+WUP0KoFt3FKqhKNcVv89stjjR+RPUrgKfUBv+au0WqBpyRwAe1fP4?=
 =?us-ascii?Q?wfk7zmwHkE7y/jWhK3qanAiTl45uiJQCgfZgbv1XDs2EkiRAAItmii9wwCaR?=
 =?us-ascii?Q?1dv4HMYeItOXDqCYzITFWbWqcXzPZ3m65OILn2fNdnaGQcHuvOSyM2ud9cU8?=
 =?us-ascii?Q?UVkxedamRxDqzBuSx2k8HQRy9HytjT7F1IurQS5RIkOuYCB1zAjsuGztQrbx?=
 =?us-ascii?Q?kaqsUIjdMO1Qmr1OqYuUIJuMHZCdTeY5hh2IVU0SaiXEu8iuUXMhqk++c6/e?=
 =?us-ascii?Q?GuOzJjSUdTp66FxWZB8XOFgr6/JOmZNAWF8ozzjB?=
X-MS-Exchange-CrossTenant-Network-Message-Id: bebba90f-a2a1-42ec-d960-08dabbdecc9e
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Nov 2022 07:58:02.2549
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +Spq6KwKs+rl50bZs28kLdQhR+x45aY7uSNJdp8r6YEGxTFv/LDaHiyif1QNCXwYEdxcfKvFZUOwOrbQsSW/cw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR11MB6913
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=fhre0QM2;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

Hi Thomson,

Thanks for testing!

+ mips maintainer and mail list. The original report is here

https://lore.kernel.org/lkml/becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com/

On Tue, Nov 01, 2022 at 12:18:19AM +0000, John Thomson wrote:
> > As I can't reproduce it locally yet, could you help try 3 tests separately:
> > * change the O2/O3 compile option to O1
> > * try the attached 0001 patch (which cut part of commit)
> > * try attached 0001+0002 patch
> 
> None of these changed my outcome.

0001 patch chops off most of the functional changes, and it still
fails. I'm wondering if it is related to the function arguments'
passing, I noticed this is a 32 bits MIPS platform (from your config)   

> I also tried compiling the same linux tree & config with the Bootlin toolchain
> (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0)
> with the same results.
> I will look into finding or building a mips clang toolchain.
 
Yes, Hyeonggon's suggestion makes sense, different compiler may
show some difference.

> No JTAG capability to debug, sorry.
> 
> I get the same outcome with either the ZBOOT vmlinuz, or vmlinux
> 
> Same happening with 6.1-rc3
> 
> 
> After some blind poking around changing (how much of the commit affected) mm/slub.c,
> I may have got lucky. it appears as though this is all I need to boot:
> (against 6.1-rc3), and with the Bootlin toolchain. Will test my other build system as well.
> 
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3276,7 +3276,7 @@ static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>         c = slub_get_cpu_ptr(s->cpu_slab);
>  #endif
>  
> -       p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
> +       p = ___slab_alloc(s, gfpflags, node, addr, c, 0);

___slab_alloc()'s argument number has been changed from 5 to 6, and
some others from 4 to 5.

Thanks,
Feng


>  #ifdef CONFIG_PREEMPT_COUNT
>         slub_put_cpu_ptr(s->cpu_slab);
>  #endif
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2DReuPHZungAGsU%40feng-clx.
