Return-Path: <kasan-dev+bncBDN7L7O25EIBB26KQSNQMGQEHUXX7FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F8AF614C21
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Nov 2022 14:55:56 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id r17-20020ac25a51000000b004b01305202dsf3261769lfn.5
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Nov 2022 06:55:56 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=k7HsvA4lARzAFV4TMYEnxZ7kN7ATRE2UlUtJ5zj57rs=;
        b=PUefCoOuRArsxOan+YehGtxiVcLHMASYogL9lrvnPOBv1zNDT/G1oXqS6CRWs8uf3L
         M4GymrPJB21XJMNSnx6OO/ppvxc0R7JAXsU8MfuELCt23R8w+oAzI9nhiosk+OUyQL98
         k8X26/s2QIQhXWYsR1U54DcYEsSb96TxrI2SiXXpwmt0toB/Ix1awTVGUOgljidhj74M
         9hZCZ28cJHlf2gbYORvXKxtH+RsyL5+in+JWNeC7CakvSPNIN+ClL6YSfQdCXyS2BEjw
         LOG5WsUbXJe+V4/c5QjXv8+qFiWdNiU2VRZkPbDB8PPoLkN2Cf1G/h2j4F17DZvVYnG2
         tpYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k7HsvA4lARzAFV4TMYEnxZ7kN7ATRE2UlUtJ5zj57rs=;
        b=GgGOhLtFRoNdY9c7+Gu2m3hrhMP2Mw75dfgQ7J5gJhaAd0wBQzTpBmz9BaP+Vb+/dj
         RWF1WBGhQHcOt4OYNNXvz1l9zycxqwH7XNZFbW9GwIbCs4ts47Noc9ErSVcMtRcwtn3E
         vb2BYVU0gtlXiiRGua/Gkayc48CjXnmAmu9DKhZ61O64VAao9zzXuTkHtlggJEqC02NY
         2dsIFfEv8cy9yKHHFfvVONn1PximaaD5bckVgk8IocnCfpbiQ5sX6JHNz6waOYOJF8EK
         Trhei0Mq7GlwqysITtesao49ZFO3sY9AuzjtDJUpatQSk29I/rzZ7wmAWP0axi72li3Z
         DX7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf06GdMVwnPm0Vm0lGJf5vuif8a6RNt+IyrAMAEP6OXCa+eJXTtk
	wUIrYlWmetDO1v0klWh5fsk=
X-Google-Smtp-Source: AMsMyM6Mm/GEkJ29cSFHDZDFF0/7aqwzx7Jyqkl31EeWbtvzM62/dTBRH3Ew6+LTDl7nC96a94FA0g==
X-Received: by 2002:a2e:5044:0:b0:277:2463:cfdb with SMTP id v4-20020a2e5044000000b002772463cfdbmr884461ljd.213.1667310955717;
        Tue, 01 Nov 2022 06:55:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6a12:0:b0:26b:db66:8dd4 with SMTP id f18-20020a2e6a12000000b0026bdb668dd4ls2175253ljc.8.-pod-prod-gmail;
 Tue, 01 Nov 2022 06:55:54 -0700 (PDT)
X-Received: by 2002:a2e:b5d2:0:b0:277:11ec:ff2a with SMTP id g18-20020a2eb5d2000000b0027711ecff2amr889070ljn.163.1667310954391;
        Tue, 01 Nov 2022 06:55:54 -0700 (PDT)
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id m4-20020a056512114400b0048b12871da5si297716lfg.4.2022.11.01.06.55.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Nov 2022 06:55:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10517"; a="296565721"
X-IronPort-AV: E=Sophos;i="5.95,231,1661842800"; 
   d="scan'208";a="296565721"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Nov 2022 06:55:51 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10518"; a="739334026"
X-IronPort-AV: E=Sophos;i="5.95,231,1661842800"; 
   d="scan'208";a="739334026"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by fmsmga002.fm.intel.com with ESMTP; 01 Nov 2022 06:55:50 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Tue, 1 Nov 2022 06:55:50 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Tue, 1 Nov 2022 06:55:50 -0700
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (104.47.56.171)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Tue, 1 Nov 2022 06:55:50 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=fFcEKj8NTwXw18J3Sc4f3QohcLCxHGB6KujZAEvbGhp+XrRbjseQrn0rHElivaxjKL3EX0CQEFz0bAcosBUsuKvCzLWNj2TAHPfuGjzCn5CFfRY7iBw67MFmk5stwZsMt0mjZ2W7wCJfZ90JKG9Q0i8mDrEMy0kZbVOMq9T902l0ReoKPHT6hnKPdKN//0U96gFtsSaW+uSLBwJieQgODF1jRIV2BaU0NYvq4UGNOpZGWwpQmCRQJXJmFw/eN1TIdrH10eO4P7DTIdonr0AnDFKcYzzglYXA/nDqJCBiLOYES5B2CEJFBpEVG/TWOhPegxvXkSbvqBVKPPBS9+cTIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=GZh4Qj1FgtWHiIa0FKcL1CY5BaZEL9cWhUaOyeKIolE=;
 b=mUoX/WLv6yw7uQfLtpl0p239QucsxaDCGWZjXZqHhQWY1RBfluJBply9efepbY5/sPj9wSn+/YOUO+riThdE1vIDAMnFTS9k4RKebKsHgYlmBgcDhotPKD14tfqBj03NHyU6L+fVdrL5owlvdW4oKYmZ33Udcktw107WNc5VsTWiwJHc9PV+hzA5M+JrpVU/3hBKOdOVDBuwCg7JrbigPUCHqHHO8TOUcrcDLVqWRjy9AVsDtHUUlKVj61qGgr3HL0R6Z+pfL+TFhFviDKLvTwdzk6OSttgZe+TtC7g6Mz2WhAUfR18L7nl4LGppD5REhz+McRNLi3nxdkue7lb5Jg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by BN9PR11MB5243.namprd11.prod.outlook.com (2603:10b6:408:134::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5769.21; Tue, 1 Nov
 2022 13:55:40 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b%3]) with mapi id 15.20.5769.021; Tue, 1 Nov 2022
 13:55:40 +0000
Date: Tue, 1 Nov 2022 21:55:29 +0800
From: Feng Tang <feng.tang@intel.com>
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
CC: John Thomson <lists@johnthomson.fastmail.com.au>, Vlastimil Babka
	<vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, "Christoph
 Lameter" <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Dmitry Vyukov <dvyukov@google.com>, "Jonathan
 Corbet" <corbet@lwn.net>, Andrey Konovalov <andreyknvl@gmail.com>, "Hansen,
 Dave" <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Robin Murphy
	<robin.murphy@arm.com>, John Garry <john.garry@huawei.com>, Kefeng Wang
	<wangkefeng.wang@huawei.com>, Thomas Bogendoerfer
	<tsbogend@alpha.franken.de>, John Crispin <john@phrozen.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2ElURkvmGD5csMc@feng-clx>
References: <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
 <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <Y2D4D52h5VVa8QpE@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y2D4D52h5VVa8QpE@hyeyoo>
X-ClientProxiedBy: SG3P274CA0001.SGPP274.PROD.OUTLOOK.COM (2603:1096:4:be::13)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|BN9PR11MB5243:EE_
X-MS-Office365-Filtering-Correlation-Id: d6799d13-6bf7-4383-cdb0-08dabc10c2a0
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: Sp5PoI4WGgluTwz5I+k6Qgj7z8mBRdVOEbMs1vMZSOmm5GGxdnXiPmcFhkhyD9MaxljEAA0r9hTVFYzpDggWNMivy6IQA6mCGdegMAfwQKVyaqGKJyPrqZPlZunndjE+wP9PS70QIdnTEd6hZR3qRJTWKzVrskhCQITEVEq39BAY9CRtdBRtmd/vAFOrQJZYQrna/eRbgdbN8NCpDvgxKYnQeaelr1MF+O+5tZLgt3y2tvNjtfM0W8EwT2aXE/nhjqzVyYU+aFGQCulpC1PhZx2jazxZ/puv8teXloQxnQisv1QY1UL6INdv8c1WP4NVuDcW/vY+yhpQxsOD6BJkiqJygXuL1R1eAp7BLDl873PDX6bLtypPA5+pG/V+Hz+zhgFepuEAA8+Cc81ZtPTv9PGR5MLg6HSEDmYQqRmWRSBjfV3LBcd8qsGG0Vjxjp0Q9QFzESiUtpoPvpqaJ0B1zIC5/ombKbredfsuulg0ytyrELtqa3UGLCpZOYUV79hcs8E3kbXeY6s2hOYXQ6bAGu9Z+/+reAZja42gt/JOA6taVohpFuYWc2tBUGzjCCMbqLPJLnMSFnOkz1O3qGkmEEGh/FZjX1zhOy6KpWKqfrOo729Di3b9so6uRafCh8q8+2ub5AF6rqm8TyvYFbEwa/aaBOILAtz9AJLWJY3bMG8t85mv32zKS/rtRnaXuCPatQ0nMRjec4xKuPKbEFpqNRIR1kBbjCA2O/Lv6CaiaeQ=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(396003)(376002)(39860400002)(366004)(346002)(136003)(451199015)(86362001)(82960400001)(38100700002)(478600001)(83380400001)(966005)(2906002)(44832011)(26005)(6666004)(9686003)(6512007)(186003)(6506007)(8676002)(6916009)(6486002)(66476007)(316002)(54906003)(33716001)(8936002)(4326008)(66946007)(41300700001)(5660300002)(66556008)(7416002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?n2JLZMEqxpOYRgB4O+BMpWHBKdB/OuWHte78WumTz/bxXm/OEIBNsxuktJ4e?=
 =?us-ascii?Q?ApRc3x9ydExDYp7CoXcP6JvDsn533H0UHoExy0LpqdpTI0HoKONEU+FydOkB?=
 =?us-ascii?Q?tONfwMtub2KYJtLtE1UJ0avJWdqXRdfJTBOiIBWQgNeqjzregw1as2T9I2O4?=
 =?us-ascii?Q?BVgkgk1HR8UweaLF82yhbi3GELZrmY+l6mhFgtTroH/AoxbGR/s/yWA/KSXe?=
 =?us-ascii?Q?9muj+2qTfYSIhiD6ChoyxvOD+8DYcAZDL/4h8ElXozQBVubHhU+oyS1xGelg?=
 =?us-ascii?Q?zX6uixJJbUh/hCV0ybEfyuzBg7/hjjy1SNkXKsp+mrS4cKCcPV6BMnKXOGZA?=
 =?us-ascii?Q?7QPZi6wnW9wQc0zRLfUCx2RUozEuL9u1k2KhZflN39JaTKgaA0UuaUaBIbRs?=
 =?us-ascii?Q?GO81LrcN5Uy4urK/kRQNt/FJPmU0CEV0UcP0DbkHjHbnXDRWnNd6CaBMXRG5?=
 =?us-ascii?Q?HaEBquAuBcBCEXJyuqtCiTjAKV1aHG256kXz6fgGsiZThpjJTlXGhn4cIxfY?=
 =?us-ascii?Q?X9s2ExA4NorcfkhEGRS4fNY8R1fJClzXds+I+vm5lvePiKolJurmsxcB26aU?=
 =?us-ascii?Q?SRuNJJ9De7AogyfU3h5acF2AeHBKzMR6opKDyM7iNyByg8EP2olXyqIJEhEa?=
 =?us-ascii?Q?MbBscDq1aJAbxmHF3iMINzU3oL4rDTji6XaqsxLsuGtx3wwAzptHqF5usFnL?=
 =?us-ascii?Q?QKgVV00G2LSt9D00PuTS4A1f3vFJGO9WCRha0kkApNobwxfpEfDhT9RMeyKd?=
 =?us-ascii?Q?7n0nPAlEJljwQRPuX9DjoAdA2B9q0OwEhS7qKUBfwNqPt6D6LETJrTAZIetz?=
 =?us-ascii?Q?Xm1bWgzwBJAO83syi6ossNpmUXY4qSTV8iyKSlHBCsf35wMO1r6ksiRB/Gum?=
 =?us-ascii?Q?zESz2/Sl0WTZVmXxkIpvi6Vsiha7DNc0XlntDjvhZrmiPU4AgKGY3wH+WqTI?=
 =?us-ascii?Q?XM2XbmFRf2uBORHpqyanI4WQET4FatJcqhg97/fa7RyEGGA16VQ7sPODWpgh?=
 =?us-ascii?Q?7QFXjN7VKMpn2uTY2e0sYxzFpsjaS9V5Jrl6spHF95G0AM1DPvmeV1zk0jOK?=
 =?us-ascii?Q?i5Hiw3bTuU6pUcJ3+ZWymb9YPiaY0LStmKM24Nne4nUU4mHSqPfk2q+4bEd7?=
 =?us-ascii?Q?tO6RtkKBSGyZ0xdu42C9GukGnYswuIHwvj9fsLWMDzh0isW7mSTZK0RcTNfB?=
 =?us-ascii?Q?XcXYR08Kt0V0xR9JEIN8jTGRT62dmasYPLxg3rqjfx9QOH7385GOkRrobihN?=
 =?us-ascii?Q?Kck0bjDhCLI9kp7+jB7YnImq6A1PX/qxnvTqnRB2Vx63TTKOyLjwGFn/8Jol?=
 =?us-ascii?Q?fL2DEHYFPanz2kVjhWUbrv67AiZTnXJzqrvxSLIJbt4eOidhhJ+/MjApK3yP?=
 =?us-ascii?Q?P0bEUGQH7QP+o2XJxEHg2178lMM6WxESDy1P3Ap2wVRrZWJcViPz89Cs5UX6?=
 =?us-ascii?Q?0GzjJafVj/p6+F+f8vWKPmQoCh4HxdaYE7Gqo2cW8mxu4u3YQW/BsvhrU5dW?=
 =?us-ascii?Q?xTLOI7rXw1RS++wuCSdWJyyDQCxTt6qT/beEXIVQbPOHkPpavlHf/g/kTrf6?=
 =?us-ascii?Q?2RMD5m1D8R9GXWBvGo3QZ1W6FPaOmwgrNqGzoUIR?=
X-MS-Exchange-CrossTenant-Network-Message-Id: d6799d13-6bf7-4383-cdb0-08dabc10c2a0
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Nov 2022 13:55:40.1549
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: EC1WrfK5wkNSRq7+lgjw7H/40AgYk+p6RTJC+5767hi0wRMaUMJbd0ziPGFTNyjcBManTbKFYwIE/9sSKLZOUg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN9PR11MB5243
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=VklUnXh2;       arc=fail
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

On Tue, Nov 01, 2022 at 06:42:23PM +0800, Hyeonggon Yoo wrote:
> On Tue, Nov 01, 2022 at 10:33:32AM +0000, John Thomson wrote:
> > On Tue, 1 Nov 2022, at 09:31, Hyeonggon Yoo wrote:
> > > On Tue, Nov 01, 2022 at 09:20:21AM +0000, John Thomson wrote:
> > >> On Tue, 1 Nov 2022, at 07:57, Feng Tang wrote:
> > >> > Hi Thomson,
> > >> >
> > >> > Thanks for testing!
> > >> >
> > >> > + mips maintainer and mail list. The original report is here
> > >> >
> > >> > https://lore.kernel.org/lkml/becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com/
> > >>
> > >> I am guessing my issue comes from __kmem_cache_alloc_lru accessing s->object_size when (kmem_cache) s is NULL?
> > >> If that is the case, this change is not to blame, it only exposes the issue?
> > >> 
> > >> I get the following dmesg (note very early NULL kmem_cache) with the below change atop v6.1-rc3:
> > >> 
> > >> transfer started ......................................... transfer ok, time=2.02s
> > >> setting up elf image... OK
> > >> jumping to kernel code
> > >> zimage at:     80B842A0 810B4EFC
> > >> 
> > >> Uncompressing Linux at load address 80001000
> > >> 
> > >> Copy device tree to address  80B80EE0
> > >> 
> > >> Now, booting the kernel...
> > >> 
> > >> [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #61 SMP Tue Nov  1 18:04:13 AEST 2022
> > >> [    0.000000] slub: kmem_cache_alloc called with kmem_cache: 0x0
> > >> [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache: 0x0
> > >> [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> > >> [    0.000000] printk: bootconsole [early0] enabled
> > >> [    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
> > >> [    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS
> > >> 
> > >> normal boot
> > >> 
> > >> 
> > >> diff --git a/mm/slub.c b/mm/slub.c
> > >> index 157527d7101b..10fcdf2520d2 100644
> > >> --- a/mm/slub.c
> > >> +++ b/mm/slub.c
> > >> @@ -3410,7 +3410,13 @@ static __always_inline
> > >>  void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
> > >>  			     gfp_t gfpflags)
> > >>  {
> > >> -	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> > >> +	void *ret;
> > >> +	if (IS_ERR_OR_NULL(s)) {
> > >> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n", s);
> > >> +		ret = slab_alloc(s, lru, gfpflags, _RET_IP_, 0);
> > >> +	} else {
> > >> +		ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
> > >> +	}
> > >>  
> > >>  	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
> > >>  
> > >> @@ -3419,6 +3425,8 @@ void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
> > >>  
> > >>  void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
> > >>  {
> > >> +	if (IS_ERR_OR_NULL(s))
> > >> +		pr_warn("slub: kmem_cache_alloc called with kmem_cache: %pSR\n", s);
> > >>  	return __kmem_cache_alloc_lru(s, NULL, gfpflags);
> > >>  }
> > >>  EXPORT_SYMBOL(kmem_cache_alloc);
> > >> @@ -3426,6 +3434,8 @@ EXPORT_SYMBOL(kmem_cache_alloc);
> > >>  void *kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
> > >>  			   gfp_t gfpflags)
> > >>  {
> > >> +	if (IS_ERR_OR_NULL(s))
> > >> +		pr_warn("slub: __kmem_cache_alloc_lru called with kmem_cache: %pSR\n", s);
> > >>  	return __kmem_cache_alloc_lru(s, lru, gfpflags);
> > >>  }
> > >>  EXPORT_SYMBOL(kmem_cache_alloc_lru);
> > >> 
> > >> 
> > >> Any hints on where kmem_cache_alloc would be being called from this early?
> > >> I will start looking from /init/main.c around pr_notice("%s", linux_banner);
> > >
> > > Great. Would you try calling dump_stack(); when we observed s == NULL?
> > > That would give more information about who passed s == NULL to these
> > > functions.
> > >
> > 
> > With the dump_stack() in place:
> > 
> > Now, booting the kernel...
> > 
> > [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #62 SMP Tue Nov  1 19:49:52 AEST 2022
> > [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache ptr: 0x0
> > [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #62
> > [    0.000000] Stack : 810fff78 80084d98 80889d00 00000004 00000000 00000000 80889d5c 80c90000
> > [    0.000000]         80920000 807bd380 8089d368 80923bd3 00000000 00000001 80889d08 00000000
> > [    0.000000]         00000000 00000000 807bd380 8084bd51 00000002 00000002 00000001 6d6f4320
> > [    0.000000]         00000000 80c97ce9 80c97d14 fffffffc 807bd380 00000000 00000003 00000dc0
> > [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000020 80010000 80010000
> > [    0.000000]         ...
> > [    0.000000] Call Trace:
> > [    0.000000] [<80008260>] show_stack+0x28/0xf0
> > [    0.000000] [<8070cdc0>] dump_stack_lvl+0x60/0x80
> > [    0.000000] [<801c1428>] kmem_cache_alloc+0x5c0/0x740
> > [    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
> > [    0.000000] [<80928060>] prom_init+0x44/0xf0
> > [    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
> > [    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
> > [    0.000000] 
> > [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> 
> setup_arch() is too early to use slab allocators.
> I think slab received NULL pointer because kmalloc is not initialized.
> 
> It seems arch/mips/ralink/mt7621.c is using slab too early.

Cool! it is finally root caused :) Thanks!

The following patch should solve it and give it a warning message, though
I'm not sure if there is other holes.  

Thanks,
Feng

---
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 33b1886b06eb..429c21b7ecbc 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1043,7 +1043,14 @@ size_t __ksize(const void *object)
 #ifdef CONFIG_TRACING
 void *kmalloc_trace(struct kmem_cache *s, gfp_t gfpflags, size_t size)
 {
-	void *ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
+	void *ret;
+
+	if (unlikely(ZERO_OR_NULL_PTR(s))) {
+		WARN_ON_ONCE(1);
+		return s;
+	}
+
+	ret = __kmem_cache_alloc_node(s, gfpflags, NUMA_NO_NODE,
 					    size, _RET_IP_);
 
 	trace_kmalloc(_RET_IP_, ret, size, s->size, gfpflags, NUMA_NO_NODE);
diff --git a/mm/slub.c b/mm/slub.c
index 157527d7101b..85d24bb6eda7 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3410,8 +3410,14 @@ static __always_inline
 void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
 			     gfp_t gfpflags)
 {
-	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
+	void *ret;
 
+	if (unlikely(ZERO_OR_NULL_PTR(s))) {
+		WARN_ON_ONCE(1);
+		return s;
+	}
+
+	ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
 	trace_kmem_cache_alloc(_RET_IP_, ret, s, gfpflags, NUMA_NO_NODE);
 
 	return ret;






-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2ElURkvmGD5csMc%40feng-clx.
