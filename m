Return-Path: <kasan-dev+bncBDN7L7O25EIBB7U4R6NQMGQEIVX3T7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F7CF617F52
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 15:21:51 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id b34-20020a0565120ba200b004a2542bd072sf647096lfv.2
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 07:21:51 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JrkSYszlFnGdDwvgFyj2UdjjmAiEPJhiw36qMvUFrFk=;
        b=FT1jVMp/7G0Snn9Z4VPb7pa99PnwAzT3UzNlbP9PDYIWuugG0NvVqOXL1pkzwtR4lF
         5LuquMqewtn5Vaai0TlYLd8ymr+EwQAKbNkR3Bh3BAAryKJCEcPbOpKSjDMoHqX2pVGB
         +PjmnZ9nZQi8XdQtp++oDSkfNgi//KIE6hRlQwg+i9fWWzPXRuaPOZLW7Uw5+tLCD3FL
         VOKcEw+jA1nxJqwV9gCJPge7wTfBw2X83a7DYzcAcLtFGx1N3c8Fs5l3FE9VSb5WBk5u
         4LyN9wgnjSCSywkFNudkvzjUCpEeYypsxR+cnDp5CLBkPKhoSo/xvUWeY1mc6dfd3a7g
         Xy1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JrkSYszlFnGdDwvgFyj2UdjjmAiEPJhiw36qMvUFrFk=;
        b=AV9HrLuF83y0yMh/cZbcy0h8kukXouruUpMZkFxtQAzCBir2K0pR5R5XvKwwJ8Y0tZ
         d6DqzRBdhb2DrWqsKFYsrbqo1IRGa/vl96X/+4nHbZI6bj8gHxwfrGYjbO2x+9oCKPaB
         w9bKyuqDD3V9785EB2s63wn7JhE5qxbHmrZPllV/PFog0NBoMELy9R3LysoxNuZl0qfW
         pDRbvNqIj6UrBzYjlFINOm1vu3LWFI4VbkDc8rI8x317pQe1uRpDMHLnLZM0R6NQCyrV
         M6gAdAobGTeeSvTtVXnlYN3Hd6NwWsAstJ9mEVf2sKXo31VEg/JClmW+U4JPMJIli5uH
         setA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1XbqI732FyVdbEfs3q5AI1hCrlZjCIUhc7mXfzKwYhGrvOQuQw
	QDqIPLiK9+ImQYz5ptqUEYU=
X-Google-Smtp-Source: AMsMyM5VgUsl5vXTHLB2mvziF3NVQeE69sDqBl8uzMxdj3/U1lDo85TRFUFcPMuhFGrAGxZPSSa9vA==
X-Received: by 2002:ac2:5dd5:0:b0:4a2:2960:a855 with SMTP id x21-20020ac25dd5000000b004a22960a855mr12199547lfq.399.1667485310364;
        Thu, 03 Nov 2022 07:21:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e4c:0:b0:26c:56b2:1383 with SMTP id g12-20020a2e9e4c000000b0026c56b21383ls385782ljk.4.-pod-prod-gmail;
 Thu, 03 Nov 2022 07:21:49 -0700 (PDT)
X-Received: by 2002:a2e:8081:0:b0:277:b:33db with SMTP id i1-20020a2e8081000000b00277000b33dbmr11160778ljg.228.1667485309133;
        Thu, 03 Nov 2022 07:21:49 -0700 (PDT)
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id b12-20020a05651c032c00b00277385b7372si33879ljp.4.2022.11.03.07.21.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Nov 2022 07:21:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6500,9779,10520"; a="290085314"
X-IronPort-AV: E=Sophos;i="5.96,235,1665471600"; 
   d="scan'208";a="290085314"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Nov 2022 07:19:36 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10520"; a="703690367"
X-IronPort-AV: E=Sophos;i="5.96,235,1665471600"; 
   d="scan'208";a="703690367"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by fmsmga004.fm.intel.com with ESMTP; 03 Nov 2022 07:19:35 -0700
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 3 Nov 2022 07:19:35 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 3 Nov 2022 07:19:35 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.109)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 3 Nov 2022 07:19:35 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=W67d4GGI9CVkoWT3+gsyNpKkhBsdMNsBQ+OHMsajgBFRC6fsjq3ulOwkbppfgg625muFTV6PLJbfEPfi7Pu3u/JzDMqxQAwaMQDObAuBokgpszcv0kbxwoURkTFLUWrPT3Y7s9rn/98kRw3z3Nz5OJAeKBCVyhGqJ895opHTmMlODCAijf9cWmzzNbc+lL065F1LbHruYony/h0/WcODhn3baDyB/hCvtLQTo5Y9t3Wdx1AyJ4tG9Uz/LwpDEUSmqYtYrjfh0huWtrJJPlM30Qx82bznBCnpQexM1VFu8YtNkOEodDkYhPHXE5C+ImMzE8B0TsjBC81gP6bxiLWPHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9Hytu0ClCaUeD7K6RlMm0Gx2SWbYu5/I136HN3A8CKg=;
 b=ZwtyyQMMXO0c6XQKSb+EZG0GjvAEta2DMmfGd9RRpYsXYSvvGxWJ0J/l0LyXAEMH4BmF1+9JpWxbys/MdRmpMwipReCLblOnqzfLjCpMIHrJX+qJv/ftqOFSWA0EpQ+0iwczac2MFq89JYurRBswqzzuJUI4J+jdqfbjpDUOKBO4EC7KY3T3ZtvXrZ0Dhkz/3/Dt8pv/djwiyEPJ8q2WSunKvru9HXGEvLyqidYnKmpr1MVRFr53W4+kXc6kkwKDu2Dnr951BfkbekKHF7A7rXedC0SrqUZU7Pzu9Cd3VWkA4ig8R2ZmQOl72vdf9AkdTzmRpOvomMDKO9kxNcVQ8Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by CY5PR11MB6368.namprd11.prod.outlook.com (2603:10b6:930:38::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5769.19; Thu, 3 Nov
 2022 14:19:27 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b%3]) with mapi id 15.20.5769.021; Thu, 3 Nov 2022
 14:19:27 +0000
Date: Thu, 3 Nov 2022 22:16:12 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: John Thomson <lists@johnthomson.fastmail.com.au>, Hyeonggon Yoo
	<42.hyeyoo@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Christoph
 Lameter" <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Dmitry Vyukov <dvyukov@google.com>, "Jonathan
 Corbet" <corbet@lwn.net>, Andrey Konovalov <andreyknvl@gmail.com>, "Hansen,
 Dave" <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Robin Murphy
	<robin.murphy@arm.com>, John Garry <john.garry@huawei.com>, Kefeng Wang
	<wangkefeng.wang@huawei.com>, Thomas Bogendoerfer
	<tsbogend@alpha.franken.de>, "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2PNLENnxxpqZ74g@feng-clx>
References: <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz>
 <Y2NXiiAF6V2DnBrB@feng-clx>
 <f88a5d34-de05-25d7-832d-36b3a3eddd72@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f88a5d34-de05-25d7-832d-36b3a3eddd72@suse.cz>
X-ClientProxiedBy: SI2P153CA0005.APCP153.PROD.OUTLOOK.COM
 (2603:1096:4:140::11) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|CY5PR11MB6368:EE_
X-MS-Office365-Filtering-Correlation-Id: 47db4366-c8e5-4e9d-3b1a-08dabda669f8
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: TxRuRkISGROoUenb1tpqSFbHAKP6Iz5dfekrVbsz0JOotXK6Si24K1RFTaATxQgSzepqHeIAu1H1ktohRGMg703xKqSuHLimn+1Ia77yEWnDnLH86X4ANTX+ewLNAFiNE1NpC5eFkO8L0/bAnQyO0ezgDK7364OQUJfUnobgykwe6ZXVSLhOTuIM/KfDZ+OVEYi+hBAl4XR6JEpnIL4jQzUM6OA43iTQSVz/xtRys4GXyLijOT3ZySJt56UkY/IkKG/YTxYQ3fs45eAeFuhcpgx71V/TkK6zaCvYjzbmVKun+rcm2XyFrT//nY4uhSuA2TE9CVg2cWXbm4gc0WKO+teuKnv3VFFDmjBLR7frDpXaQo8+RttxGC76EoaYaA1cHpCp+0CKu9Ni45kOYW3a+r6SWUGYp74U9vTLWsVjMJx++u/G5aadX1MzdysF6LeXAsFZrlqsIuiaP+Mxa4LkdfRaSR2Da/G9vLGD3K6yKx89wVl/BxVpL3prwjiNnPrY0+v6Uy5G00iJ4avSxDGjX3oMP1KHN2jaCMbo5B74q1ZAcSiaSQwot2THwOHknTPOM9T0f1Ptz855LDrlrq0ksUUKOuBRDJM9VNCKZV82/fHilhDh6RRZ9J9Cccazzkkhyph9LlfphvCftMN7rBUFuqDz70As4FGBJGKo+/UPF79I5hPXWVykTzkKu0dyEEIwHtKlkjbKLEPF64MDb5eULA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(39860400002)(376002)(346002)(366004)(136003)(396003)(451199015)(83380400001)(478600001)(54906003)(38100700002)(33716001)(316002)(82960400001)(53546011)(8676002)(6666004)(66946007)(66476007)(4326008)(6916009)(66556008)(6506007)(6486002)(8936002)(9686003)(26005)(6512007)(41300700001)(5660300002)(7416002)(2906002)(186003)(86362001)(44832011);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?mnIW/4hFAJOAMPxxXE4ITUb7mdVLL6qb6FhCnshD8U50Tht/1LXgyL9hYh6F?=
 =?us-ascii?Q?JDjtdv2cZ/4aZjBD2FqDVrRZ1sca/Ix6x7RNQmDijMzPdOpTsE+SwVICETDg?=
 =?us-ascii?Q?uefhomXiG3XEqmNwvWuPdx0pVqOTWmNPc8TAQvWSDUMdrIuo5XEtP+/mAwja?=
 =?us-ascii?Q?TMyvWWqQsal1Olg3oxh5wg7e238xMI9MVrAnGKbrknr1pgXZk+eOFvHkiPul?=
 =?us-ascii?Q?lyLYqHtoOIwoFI/H0HL1MYBmTE7d7RJm3rsIgT5edJvP6ItkVLGvUcuXMf1f?=
 =?us-ascii?Q?RclUXYd+ppnlBZ7frhxTnNXtRvNhR2pFrltyyZ3wXKIbpxGklCov+kmc8rlU?=
 =?us-ascii?Q?vtJFFMnVGapTLIY9oPjfP9zlGj+aodSfu6sdkiOorqetb5m15kbh/5ZMmrxy?=
 =?us-ascii?Q?rJ41kUIJlMbPx16w5QPHnLYtV8cKulE/JaOLCQHKZCtu/mAaruXhKVAVeij/?=
 =?us-ascii?Q?xwDIvf7wEyYDOsTr3+WQcDEM++GypYNZGdbIzQyRIuVYW9wSJgYMiHC4vbQF?=
 =?us-ascii?Q?45zutgcgIedNy9wg/FTmS0d8B2cJk3ul/eWQtkYGtYLpZMtNNlWL7uaiBOyI?=
 =?us-ascii?Q?72M4T3KT01IEEbdHUc7Evhil4Vlf2cqZnbU3Fs5Yhe/Ih6oG8YHuF0qjNvyB?=
 =?us-ascii?Q?tEHDeVs8reGcqMqyE/N/rcwfPkeOZAH5tawj7H63B2j/W/eJ8A24JcYgDs38?=
 =?us-ascii?Q?w/CValfGTrJQHpx3rSaHGOPqGMMS3R3F1h8F+PDnWQdApNObWa89l9/rmK27?=
 =?us-ascii?Q?do2t8r3+UKRPwU8dzA8aIN3PWqgP+TshHxo9mFI7zN7Mk+Z3VW+U0pNNMV2z?=
 =?us-ascii?Q?4JKYY9IWB2xAkyteQIYl20qngKueY7wbYyg7z8B6izx6K68P8yROO4MeesY1?=
 =?us-ascii?Q?oWMM3lIBrZxo6uF/CcT+y5S05LNrX3PQP6sBwzEZdByDBuq92jTw7rhwSfUm?=
 =?us-ascii?Q?l572hNIayWGbRyLs7usFKKJQajAtEnJZU2LfkPOCZ4ROuMy9u4TL3Lkpi4z2?=
 =?us-ascii?Q?34W9nGGfH2eGdoiCHpPKW52Ei+hyg5NsBeJxr2g47auq8Fx4M6DyoAIMcPwR?=
 =?us-ascii?Q?uoVOUikjvn/u3NkuetGpoBRZJ+auklKlGoc56TeKkm9lj4vGnZDycewd5iCs?=
 =?us-ascii?Q?FJLFxpOKTj9Iykq79ZAJWfK209jNTs5oMFSAq5MTz4QaYYDziu2NjMExXNFo?=
 =?us-ascii?Q?42V+N6HSXeVGdN1bAuLwU01Ggg7x09EWMMZ+w8jrjnJNqLlAxzyDs/hSTv+7?=
 =?us-ascii?Q?zlf745NbEUbpJhlEX1MtWe6VDmShnLoT8Rt9yd9H3wLRYF+fC0uWY77SmlYJ?=
 =?us-ascii?Q?/dgan6l84onMiy6WQZ++uwaRU8GE0HWCJtj0/oMrBBLRQpkU5VKSmrGfElcG?=
 =?us-ascii?Q?vCLC/P+VEAS7WZ9zvibv696WQwBYixO8IVnarEJ5Vr38mlXLPICoUSNTl9XM?=
 =?us-ascii?Q?xwr+ETQfvGYSFfnVAahR2BaS/5lN6ZYILqNADL74GV/8bEBHbyoxCyHYoV6p?=
 =?us-ascii?Q?K5RxcK8zxCn3tS7hW4WO0zkzewIXxYq5A/U5F2yTMfksLiMDAMx1y1ByAMEK?=
 =?us-ascii?Q?6xrf2XoSjXTwsJspLY3SAvgzjUUVR2uCnn+wDDCt?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 47db4366-c8e5-4e9d-3b1a-08dabda669f8
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 03 Nov 2022 14:19:26.9424
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: xmERxHJrd6kRVGeuWw5IoLBNZKDyHvnbPrA1vzNdWAI7Atmsxn5NRDWNhSu/HbZmXzRgwIM7VvkXM2x90wCW6A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR11MB6368
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=diBFqgei;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.151 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Thu, Nov 03, 2022 at 09:33:28AM +0100, Vlastimil Babka wrote:
[...]
> >> AFAICS before this patch, we "survive" "kmem_cache *s" being NULL as
> >> slab_pre_alloc_hook() will happen to return NULL and we bail out from
> >> slab_alloc_node(). But this is a side-effect, not an intended protection.
> >> Also the CONFIG_TRACING variant of kmalloc_trace() would have called
> >> trace_kmalloc dereferencing s->size anyway even before this patch.
> >> 
> >> I don't think we should add WARNS in the slab hot paths just to prevent this
> >> rare error of using slab too early. At most VM_WARN... would be acceptable
> >> but still not necessary as crashing immediately from a NULL pointer is
> >> sufficient.
> >> 
> >> So IMHO mips should fix their soc init, 
> > 
> > Yes, for the mips fix, John has proposed to defer the calling of prom_soc_init(),
> > which looks reasonable.
> > 
> >> and we should look into the
> >> CONFIG_TRACING=n variant of kmalloc_trace(), to pass orig_size properly.
> > 
> > You mean check if the pointer is NULL and bail out early. 
> 
> No I mean here:
> 
> #else /* CONFIG_TRACING */
> /* Save a function call when CONFIG_TRACING=n */
> static __always_inline __alloc_size(3)                                   
> void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
> {       
>         void *ret = kmem_cache_alloc(s, flags);
>                     
>         ret = kasan_kmalloc(s, ret, size, flags);
>         return ret;
> }
> 
> we call kmem_cache_alloc() and discard the size parameter, so it will assume
> s->object_size (and as the side-effect, crash if s is NULL). We shouldn't
> add "s is NULL?" checks, but fix passing the size - probably switch to
> __kmem_cache_alloc_node()? and in the following kmalloc_node_trace() analogically.
 
Got it, thanks! I might have missed it during some rebasing for the
kmalloc wastage debug patch.

How about the following fix?

Thanks,
Feng

---
From 9f9fa9da8946fd44625f873c0f51167357075be1 Mon Sep 17 00:00:00 2001
From: Feng Tang <feng.tang@intel.com>
Date: Thu, 3 Nov 2022 21:32:10 +0800
Subject: [PATCH] mm/slub: Add missing orig_size parameter for wastage debug

commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
kmalloc") was introduced for debugging kmalloc memory wastage,
and it missed to pass the original request size for kmalloc_trace()
and kmalloc_node_trace() in CONFIG_TRACING=n path.

Fix it by using __kmem_cache_alloc_node() with correct original
request size.

Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc")
Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 include/linux/slab.h | 9 +++++++--
 1 file changed, 7 insertions(+), 2 deletions(-)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 90877fcde70b..9691afa569e1 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -469,6 +469,9 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node) __assume_kmalloc_alignm
 							 __alloc_size(1);
 void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node) __assume_slab_alignment
 									 __malloc;
+void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node,
+				size_t orig_size, unsigned long caller) __assume_slab_alignment
+									 __malloc;
 
 #ifdef CONFIG_TRACING
 void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
@@ -482,7 +485,8 @@ void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
 static __always_inline __alloc_size(3)
 void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
 {
-	void *ret = kmem_cache_alloc(s, flags);
+	void *ret = __kmem_cache_alloc_node(s, flags, NUMA_NO_NODE,
+					    size, _RET_IP_);
 
 	ret = kasan_kmalloc(s, ret, size, flags);
 	return ret;
@@ -492,7 +496,8 @@ static __always_inline __alloc_size(4)
 void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
 			 int node, size_t size)
 {
-	void *ret = kmem_cache_alloc_node(s, gfpflags, node);
+	void *ret = __kmem_cache_alloc_node(s, gfpflags, node,
+					    size, _RET_IP_);
 
 	ret = kasan_kmalloc(s, ret, size, gfpflags);
 	return ret;
-- 
2.34.1



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2PNLENnxxpqZ74g%40feng-clx.
