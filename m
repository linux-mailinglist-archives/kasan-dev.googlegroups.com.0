Return-Path: <kasan-dev+bncBDN7L7O25EIBBFX3VOMQMGQEDU5OVPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF475BFD78
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Sep 2022 14:03:35 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id c188-20020a1c35c5000000b003b2dee5fb58sf2495906wma.5
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Sep 2022 05:03:35 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=Cc+1tfYHltRogoUH5fYoAwU/YwOwnSZqOKe7Z+2O9/E=;
        b=KaYpvSU9HfhAH/2Ax3tjjjhYp+WfHRFnoYkzePYZhSGu3ccDnTzi84Oaqy1pjNUriF
         nIZpRfP8FMTl5xCH8eV56OYGJP+o7AyUzGZ37lNgiDsrkgmovcPZimR91LpkwpDnio5F
         aTJwjxOJn9LRBuU6wDbl7e+d/zGDDGTRrdBVkuP24pi2u9D6S1XTX9XGKr53tqTqRH1I
         9MRBEuszEzVt67osIAiyjDbPKQzL7acugup120YtkY+B3h2S+FS0gUUaA25XZzlM/FrN
         7dfwYdmgRPugXUmGJFYIaMjq3NBT2vDZ49tcWzyRt/OwgiuKrQw0JBiVq5CnmS4+2zx/
         o43g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Cc+1tfYHltRogoUH5fYoAwU/YwOwnSZqOKe7Z+2O9/E=;
        b=1a6ZR15L1Hj8AYpe5D8zIHXZQxZl9jCdl1BXcq2EYSitROH1PQVEv5HGN2inNav6FS
         2WLo3vGKCM33XLub8EMubJFnERC3y4SxlyliCacbvAuYLfOptLIcB1PJZ+SS+BC/ijP0
         ShmqsVLeInab7vLi55aDmbG4a7G50LmALCd9FHfsmIqbymdzZsZuSc8pSd2fgqWxGfq/
         3iowGjm6gqfUbsQXGVW2yN8mkLzVeR7hXKt8Zv7jHFPq339ZSpDqrmOCA7ZRE4ys1ivr
         Uh4sH75z3ajGREFx6UHX/j6DNksRxxdyuTeYgbmgfD7XXhGJeyXupOpzweOlEA4a4dW+
         u0cQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0K53c3kY36Ur5AoX3TOemwdK1jcaYJm99OioFWPZR6e2LPusTg
	4YkTpDR7DrzcSyuM4ekZ9HU=
X-Google-Smtp-Source: AMsMyM4EOZjjKVm3xLQpK+ZBtzkHNjQD35gX22NtzYID3KTbxfW0tJoPU5+6pyotxpx8H+QLWmVHVQ==
X-Received: by 2002:a7b:c048:0:b0:3b4:fb26:f0f3 with SMTP id u8-20020a7bc048000000b003b4fb26f0f3mr1458601wmc.115.1663761815184;
        Wed, 21 Sep 2022 05:03:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2683:0:b0:3a3:2369:271d with SMTP id m125-20020a1c2683000000b003a32369271dls346902wmm.0.-pod-preprod-gmail;
 Wed, 21 Sep 2022 05:03:34 -0700 (PDT)
X-Received: by 2002:a05:600c:2212:b0:3b4:9ab8:b24e with SMTP id z18-20020a05600c221200b003b49ab8b24emr5616752wml.127.1663761813955;
        Wed, 21 Sep 2022 05:03:33 -0700 (PDT)
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id v12-20020a1cf70c000000b003a83f11cec0si98433wmh.2.2022.09.21.05.03.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Sep 2022 05:03:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6500,9779,10476"; a="386268779"
X-IronPort-AV: E=Sophos;i="5.93,333,1654585200"; 
   d="scan'208";a="386268779"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Sep 2022 05:03:22 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,333,1654585200"; 
   d="scan'208";a="687845758"
Received: from fmsmsx603.amr.corp.intel.com ([10.18.126.83])
  by fmsmga004.fm.intel.com with ESMTP; 21 Sep 2022 05:03:22 -0700
Received: from fmsmsx608.amr.corp.intel.com (10.18.126.88) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 21 Sep 2022 05:03:21 -0700
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx608.amr.corp.intel.com (10.18.126.88) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 21 Sep 2022 05:03:21 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Wed, 21 Sep 2022 05:03:21 -0700
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (104.47.55.175)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Wed, 21 Sep 2022 05:03:21 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=F7wmvR+EW7H5es1IVoY7S4Rc3K7gxU5M2XEii07QCRYKG+851dPRDnZrPeSgW1LNDYdrXclSAgqj8tzPLHqLHNIHALYYLsclfoA9mFcl04mJHwSt/MN4qhh/Ab5y7/r5mUwQJsh4uWBU/3JdNIPyzU/Kd/ueL2YMjsUy+L0dcjZTSmOgF+0IJn3T859xGIS6P3WsBKX+q2K10nFt0PnQhp+GGjpn28+DfnevD8RMObUUfmHejm9oUwrlK2eilq4jRNMG+0kq5hK7JCVWoqP22UtMRScPYPMEy4ezIEO3WMoFomDBGgYWSwQle04mOzbtP5d3kFl/GyTFZccvRYpOiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+hlMTsYQH/ieRjTnnGFqJoekS8RbjYlmMWUEXC9LAzU=;
 b=QsdCnKtqeY1E66VYmegK/ghfNmhBJOUJEbbPFCh12gZyJzh1/b1AMZyNjTlsOnfdHswG3WhYf4bpG7dy4YkhgwJmDiPgyMVhqTl1UbR9Jo/TIJ80b85Dy4QP5KYvTbhgPhUeGTKtgK1dwQ1y540bt62jLbiiJG9j2y/fg+HjOr91Jqk2bgj8wz1Nqlc5gaAagH57uqCb0mWw2s2xDMGy+G0DGasypa1ifMr2CX+Y3Lbhp0xsA/c27nniTaHvLuY16T/EDRGRc5OILYOEF7azT/FFOjlPoj9SSpdwZuWDcaF5keOqOaSM9xtYpU1k1Je4i6ifx1NzyU85Kqc214+tDw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by CY5PR11MB6416.namprd11.prod.outlook.com (2603:10b6:930:34::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5654.16; Wed, 21 Sep
 2022 12:03:17 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::ccec:43dc:464f:4100]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::ccec:43dc:464f:4100%5]) with mapi id 15.20.5654.016; Wed, 21 Sep 2022
 12:03:17 +0000
Date: Wed, 21 Sep 2022 20:02:45 +0800
From: Feng Tang <feng.tang@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>, "Hansen, Dave" <dave.hansen@intel.com>,
	Linux Memory Management List <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	"Sang, Oliver" <oliver.sang@intel.com>
Subject: Re: [PATCH v6 3/4] mm: kasan: Add free_meta size info in struct
 kasan_cache
Message-ID: <Yyr9ZZnVPgr4GHYQ@feng-clx>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-4-feng.tang@intel.com>
 <CA+fCnZdFi471MxQG9RduQcBZWR10GCqxyNkuaDXzX6y4zCaYAQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdFi471MxQG9RduQcBZWR10GCqxyNkuaDXzX6y4zCaYAQ@mail.gmail.com>
X-ClientProxiedBy: SG2PR02CA0005.apcprd02.prod.outlook.com
 (2603:1096:3:17::17) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|CY5PR11MB6416:EE_
X-MS-Office365-Filtering-Correlation-Id: 8d556d52-a915-49f9-187d-08da9bc94490
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: aR/n0+vZmd7jo4f46jJ8WYib7lHzp8+Nor3tgJDvi6YUBpjLFQNuWqqE8XMcED/tUJK3bd01xEkscbub1hoSbiBZ5u80ymFFfulz+0vIXrv5JGfJGsIJn3bPPFaIM7VW3eRBUEVyLGKvvwKUGnhwLNRGPvziYFtF9p6N9AYzIeH96ty9JodaAvVc0MADbHJEQnxOB/ShR0PbhwetGDjTSAgJrFKRHMfxv7mJrObmGJhWHiKCAINtB3ZL3ktHZ8fBqVbx1yLxFxInmR8LxHhCN/3fC0biaUWTQoEFiYh8VM/YE+ILUOudHcab+KPs0AhAfmP5C7ZFCbgM2zFq0L2NUL3QxgvsQrCc7vtiFjEnDUdCqDxVlqJMcGf1QBuYiJL4wLlRjhEf6NS9nCfmgt6n77wbU3qSj676PvFg9hFVnIpwmfBM1kLBNW9KaXs47q/9NsXQ1gVcMOksXqgqVHAp89W3HA5rfLvD6N3pMARuIoJ//+qSGNNdJoFfmM91lfVaWnn0jwNyKak6/MtJfeVrC5J8J4wnJZSBdIcvQddGHY91EBmECsC09QQMwbDY0IutpEM9x+CwX5RKNHjLvdvzYT/tUMT0dhmF197JS0LVksq6tK4uPsdaDocj+UdJmiNlxXbByiGjIx4Ork8vCFdSdtLA13i5yTRF0XxkHAZYQDSe5kbTDOLtO+EhQuA+WgF0DH4BdMhZ1ejfJMTFHp2u+Zj56XwRs7hLiQdu6Uf6ZdTuehSHlSmyTYGKPM4NfaCXG1yyGpDsI68OrpcwyJKLtw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(396003)(136003)(366004)(39860400002)(346002)(376002)(451199015)(38100700002)(82960400001)(86362001)(66556008)(66476007)(33716001)(66946007)(4326008)(8676002)(41300700001)(6916009)(54906003)(2906002)(316002)(5660300002)(8936002)(44832011)(7416002)(186003)(478600001)(6486002)(966005)(53546011)(6512007)(9686003)(26005)(107886003)(6506007)(6666004);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?erhVjrcFkZMDbcqvmCNIJDqrzbL019YW+4N96gi6t5AamPa5i5pGCtIHNDQQ?=
 =?us-ascii?Q?W0+Exav4xItG2CZQt5cZ7Pt8dVXfT5LNve4nVRamPMcPhD8uLeLcKVtX7aH5?=
 =?us-ascii?Q?hBtATSa3FhOrcv9puiAZdvphhv9snVdmLFDYY3bB4AjZfxHrFfwKgK1lavJj?=
 =?us-ascii?Q?t/tffko7vvMvZfJGlamsQqmXiwhHTX16MGQofp8SFnLXex8U6jWUJ9vBc3Dl?=
 =?us-ascii?Q?7UIzLhftcGQTwduwPYNy1P93LIMxLNoYojeRwl9abl1314hSWe8yY+obi13v?=
 =?us-ascii?Q?BKTPVBxbkMCDV0aLklyAS07tZDHQIZ4MbnoAABfSJsaGjGFEP8RZax1NHcvv?=
 =?us-ascii?Q?6q5Js1+RZ/RDa+pU2isqqNWVQMQ4fKD1BxXsUsHjwW5e+qvxfwVgw9xcSy5Y?=
 =?us-ascii?Q?v5D/6mU7RnTNcvYCb7KrWhWeOnQHL8jzZXxjjxrIXw3+MhayfiPEf6xvxYfq?=
 =?us-ascii?Q?Sr5fn2bE3RrD18h29g/fFeP1wUhvo6h1HPEySSo6o2Zi/VUnTD0g1GlNojrN?=
 =?us-ascii?Q?39yWffZsk9CGe++5lfle+bgJQiHXTr8TLHrQqGv6oAWJvcuYfKBJ/s4GEL9i?=
 =?us-ascii?Q?32khk5bkK1qQhHmyJC5Ft4b2fR0HIRaG/bxjNuQljAX8/1wOvLcPDyINqRFd?=
 =?us-ascii?Q?9pUtK8UkrU8EK5Q5cdhPgIgLDQu3nlcyUyz/GQhuZZo1n+6/L58pfita4ZVW?=
 =?us-ascii?Q?w07o0jjO2QwzgUMoe0gNTFeN2PeAp1ltULokrCsgYiLQ1gdOJeadVzBGFhit?=
 =?us-ascii?Q?Ez0kyxMyLim1up+Xz/PWNETYhUNYd9XDnremwiAFHf7JLmHDgvVeCq8mkRfP?=
 =?us-ascii?Q?kb1JrzcNnNH0bFbp/Oa4PhvWuINYppQonvMgM/L6SvsPlgpSjUlDssfV88x7?=
 =?us-ascii?Q?K2qP/3R1OT/tg4RpafWsr4QbDHLc1D2olMcHsEpY52XDWvNJwGALxhqfTXSr?=
 =?us-ascii?Q?spc1zXAKeDUEMpS9WfJS5QWZOezphLKLd/4NXFOeqeC8GQaR3p0mWCG8D2OG?=
 =?us-ascii?Q?agMqVSMoOzb9qq7ohcHBfTpSPHocDtu1asBSCsc4bsXm90AupMcPf1ZKxzBx?=
 =?us-ascii?Q?EHz8QTaxUnH91eBCUW3Z9V4ZeEeXoT2JF2I4l/J8MeXA7fsts3JNBcbcbGw2?=
 =?us-ascii?Q?gDd2pXgNXLDYux69kG/CXvT97QewQbHOfcqz/Lmg05OfBFwtGj92woxsfdOH?=
 =?us-ascii?Q?EsiHHiHslD+7tu13XFwuvNDeVupfJLKokUdBygpBYppGLgu5brUhtoEllNxM?=
 =?us-ascii?Q?Ih0R/cuyQ3J9CCwCwfmP8EhlDRjl98ek2ymkVoQALVyfxliywzWmfNBerck1?=
 =?us-ascii?Q?q1mKwD8YNjRFWlCt4ae9Qr2VSz0H9CoRM5mjZA9T+N52B08GHaiCdP6Fsxgv?=
 =?us-ascii?Q?yeSJbFgjrTAwH1AWqLjxZkCMG62TRsby5Y6W12QyihjX9cH+VjKk+p7/h/co?=
 =?us-ascii?Q?wWn8hEQJ6ybkv651zPiyd1Ym1x7w1XfAMbsdJJSGYEg2/iDIXkz3hW4ce3/Z?=
 =?us-ascii?Q?+5Eh0G51TNuSZgVSiLa8V4/fyx9eA/c11rt/rmt2ct352QuR17JxjqhOxeGf?=
 =?us-ascii?Q?NnGxLnnjEZakUCzbRAaEx+M/1iieC2Pcqush4cJw?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 8d556d52-a915-49f9-187d-08da9bc94490
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Sep 2022 12:03:16.9247
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 3spkvN9C7LuUdPHEA9+cBSlvzD08iwyIxLts5VIplhuJQnDaxzVqBp0iCwltm/d7q5t27/4kGZ2LK8ee3Pm9Tg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR11MB6416
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="f/nJD3eP";       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.43 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

Hi Andrey,

On Wed, Sep 21, 2022 at 03:20:58AM +0800, Andrey Konovalov wrote:
> On Tue, Sep 13, 2022 at 8:54 AM Feng Tang <feng.tang@intel.com> wrote:
> >
> > When kasan is enabled for slab/slub, it may save kasan' free_meta
> > data in the former part of slab object data area in slab object's
> > free path, which works fine.
> >
> > There is ongoing effort to extend slub's debug function which will
> > redzone the latter part of kmalloc object area, and when both of
> > the debug are enabled, there is possible conflict, especially when
> > the kmalloc object has small size, as caught by 0Day bot [1]
> >
> > For better information for slab/slub, add free_meta's data size
> > into 'struct kasan_cache', so that its users can take right action
> > to avoid data conflict.
> >
> > [1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
> > Reported-by: kernel test robot <oliver.sang@intel.com>
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> > ---
> >  include/linux/kasan.h | 2 ++
> >  mm/kasan/common.c     | 2 ++
> >  2 files changed, 4 insertions(+)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index b092277bf48d..49af9513e8ed 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
> >  struct kasan_cache {
> >         int alloc_meta_offset;
> >         int free_meta_offset;
> > +       /* size of free_meta data saved in object's data area */
> > +       int free_meta_size;
> >         bool is_kmalloc;
> >  };
> >
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 69f583855c8b..0cb867e92524 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -201,6 +201,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> >                         cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
> >                         *size = ok_size;
> >                 }
> > +       } else {
> > +               cache->kasan_info.free_meta_size = sizeof(struct kasan_free_meta);
> 
> Hi Feng,
> 
> I just realized that we already have a function that exposes a similar
> functionality: kasan_metadata_size. However, this function returns the
> size of metadata that is stored in the redzone.
> 
> I think, instead of adding free_meta_size, a better approach would be to:
> 
> 1. Rename kasan_metadata_size to kasan_metadata_size_in_redzone (or
> something like that).
> 2. Add kasan_metadata_size_in_object with appropriate implementation
> and use that in your patches.
> 
> This allows avoiding exposing KASAN-internal details such as what kind
> of fields the kasan_cache struct has to the common code.

Agree, it's better not touch the internal fields in slub code.

How about the following patch, it merge the 2 functions with one flag
indicating in meta data or object. (I'm fine with 2 separate functions) 


diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b092277bf48d..0ad05a34e708 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -150,11 +150,12 @@ static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
 		__kasan_cache_create_kmalloc(cache);
 }
 
-size_t __kasan_metadata_size(struct kmem_cache *cache);
-static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
+size_t __kasan_meta_size(struct kmem_cache *cache, bool in_slab_object);
+static __always_inline size_t kasan_meta_size(struct kmem_cache *cache,
+							bool in_slab_object)
 {
 	if (kasan_enabled())
-		return __kasan_metadata_size(cache);
+		return  __kasan_meta_size(cache, in_slab_object);
 	return 0;
 }
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69f583855c8b..2a8710461ebb 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -218,14 +218,21 @@ void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
 	cache->kasan_info.is_kmalloc = true;
 }
 
-size_t __kasan_metadata_size(struct kmem_cache *cache)
+size_t __kasan_meta_size(struct kmem_cache *cache, bool in_slab_object)
 {
 	if (!kasan_stack_collection_enabled())
 		return 0;
-	return (cache->kasan_info.alloc_meta_offset ?
-		sizeof(struct kasan_alloc_meta) : 0) +
-		(cache->kasan_info.free_meta_offset ?
-		sizeof(struct kasan_free_meta) : 0);
+
+	if (in_slab_object)
+		return (cache->kasan_info.alloc_meta_offset == 0 ?
+			sizeof(struct kasan_alloc_meta) : 0) +
+			(cache->kasan_info.free_meta_offset ?
+			sizeof(struct kasan_free_meta) : 0);
+	else
+		return (cache->kasan_info.alloc_meta_offset == 0 ?
+			sizeof(struct kasan_alloc_meta) : 0) +
+			(cache->kasan_info.free_meta_offset ?
+			sizeof(struct kasan_free_meta) : 0);
 }
 
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,

> Sorry for nor realizing this straight away.
> 
> (Note that there's an upcoming patch that fixes a bug in
> kasan_metadata_size' implementation [1].)
 
Thanks for the note, will check this when making the formal patch. 

- Feng

> Thanks!
> 
> [1] https://lore.kernel.org/linux-mm/c7b316d30d90e5947eb8280f4dc78856a49298cf.1662411799.git.andreyknvl@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yyr9ZZnVPgr4GHYQ%40feng-clx.
