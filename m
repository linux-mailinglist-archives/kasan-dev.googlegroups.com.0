Return-Path: <kasan-dev+bncBDN7L7O25EIBBBUVYCMAMGQEZB2GW5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DC715A8A9F
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 03:27:40 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id i7-20020a1c3b07000000b003a534ec2570sf470583wma.7
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 18:27:40 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=Rtpzg4BkE5IkHJiOfkDrGDit0/7gH25REJE3+O/tRRw=;
        b=PHIZdJ+gZjLyngijB6ID/atidtq8ucrRotjENbbCVSRSyDGwunGkP7Ws9hwDXlzK2/
         zfOEY/4zUk2vTMCtsxx8DGJ/YELAQpYg9u7E9m1pydI3wf72IaM2CGhU4H/FmawneEyy
         V+XUZ6Au5H6oWfZeoBj+y86VJR7uoZ4oOnJmISapDjf5CdVJGhTMSp0NDJCjgNzuUPxE
         BIjDhFilTbGujqKajMD+i7E3SGVhdQTjwJXKE4VPp2b6gzVSFrFOjogsRHPzqq5c55dB
         zDPV1aAGPpkh00OxImhasXJy/bO8+nk23/ZH7iukQxdxBG/yp8/lrFbfO8o6N3HrEvWz
         8Osw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc;
        bh=Rtpzg4BkE5IkHJiOfkDrGDit0/7gH25REJE3+O/tRRw=;
        b=zGCFKXSDHcXiJoKA9NoqzV6mshMcr6nrDuQUWGzaUhHZBBZxtKS123g7cz9LXTK3i/
         owRYRco8/PeadXqNgHiFwZ5UknMf+3kZE0mrwW/cpDiPxRb12ZDH3MmNrcIF95UDxaHX
         LpjBkI7IlMg3rLWrTRZg/0/2kBTf12DH+jnYl9hO3ew1lYZFoJMT64GhGHbH46Oi1sNm
         LHd5JxTtR4SIvGzYON6e+fEmLFco1Uq6lYzz09bxnzqprHzHlgmwO4QjR8GH2BaJKggH
         YxCjB43ix0TbNl181LtbCI9plxtftsEclAoNDQsEV1ZeUvPZL61qiHKkoe8BNJFBmAxR
         +fog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3eduMe1RkgMjQjDv0VFhlgkm52M9m5IMImDWLLa1JvyaX/HvtE
	6dM0kSdUkgqpoB1C+PpTkkE=
X-Google-Smtp-Source: AA6agR5ZPeet5c2v/zGhPgEkOUUmlB/bKhB0/D3VGzRHepTzaeYl43KUqe8E+MZuSJeMdjQlCDVYRA==
X-Received: by 2002:a5d:4302:0:b0:225:5303:39e5 with SMTP id h2-20020a5d4302000000b00225530339e5mr13478371wrq.380.1661995654985;
        Wed, 31 Aug 2022 18:27:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22e:0:b0:225:26dd:8b59 with SMTP id k14-20020adfd22e000000b0022526dd8b59ls609273wrh.3.-pod-prod-gmail;
 Wed, 31 Aug 2022 18:27:34 -0700 (PDT)
X-Received: by 2002:a05:6000:156e:b0:226:f190:448b with SMTP id 14-20020a056000156e00b00226f190448bmr1392557wrz.573.1661995653917;
        Wed, 31 Aug 2022 18:27:33 -0700 (PDT)
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id l3-20020a1ced03000000b003a5582cf0f0si264349wmh.0.2022.08.31.18.27.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Aug 2022 18:27:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6500,9779,10456"; a="321733553"
X-IronPort-AV: E=Sophos;i="5.93,279,1654585200"; 
   d="scan'208";a="321733553"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 31 Aug 2022 18:27:31 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,279,1654585200"; 
   d="scan'208";a="563252098"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by orsmga003.jf.intel.com with ESMTP; 31 Aug 2022 18:27:31 -0700
Received: from fmsmsx608.amr.corp.intel.com (10.18.126.88) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 31 Aug 2022 18:27:31 -0700
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx608.amr.corp.intel.com (10.18.126.88) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 31 Aug 2022 18:27:30 -0700
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Wed, 31 Aug 2022 18:27:30 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.106)
 by edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Wed, 31 Aug 2022 18:27:30 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=V7E0y0wtiotLADOi4WUI5N1pdqepqujHgLspf5fVnfomTturMcEB2xz6ztoub+EXlK520a2Q2wBuHmlgm52a4xerJN+/4Ro6gdw8aGbOE3jddL/ANASZkZb2ZqB87+2fvZTOVhcXgvRo4Mqw44RRK7C8QSJncbLVcT4iRvVn6x9iWIpbvLyoAG1Z91/2wI5X7BMhgmi0NiivRPZp7ehfOw/NiA8H7RRfXkdzxW3dbKJIDIlRF37Bug8pg/o/lJWe+/9bGFgZvF+Kxd5vMOnuKhwNppuvyg9K8HijUXFfp115L4JHjJcM6I+b1qZZIpD/Eownv5HUjNHIcZs9OLWx6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TW5LiODEYz3WknU55utscAYy9Jv36BeElHi/AvMOgdk=;
 b=i+6cCw85Pp0PvDRUb3nn+ZGSFfn/FzPbE0N3h3ByTVpq7LPWU/QUk1PqXcK4OR8inqGGMRlgCZ5k3SWXZEyppoKn6t/tkVmx5wP1r47rTY1PCj5KN6fP1IpBPGmoTA7fgxPb8OGINNQpXoxSw1AbgKaq/KnIz2xunIA+nyvakQylX0Oy6mGo2nGiJ8GvyljJfoZvo99BCxh/ijS9oJc8Cl7sd8TBKSCkHQnEB+fEKY+sLojxN/tj7xzd0RqMu2o2zMmoqfMysIjmpUvQY7ozbZH9mv66KqPHmsJlxFMm0osmSCJ02jLdx94LXgq7KAWYL7yAvjAzXsQrRHobGUxOpQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by MW4PR11MB6786.namprd11.prod.outlook.com (2603:10b6:303:20b::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5588.11; Thu, 1 Sep
 2022 01:27:28 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::d446:1cb8:3071:f4e8]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::d446:1cb8:3071:f4e8%5]) with mapi id 15.20.5588.010; Thu, 1 Sep 2022
 01:27:28 +0000
Date: Thu, 1 Sep 2022 09:26:54 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Marco Elver <elver@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip
 list
Message-ID: <YxAKXt+a/pqtUmDz@feng-clx>
References: <20220831073051.3032-1-feng.tang@intel.com>
 <Yw9qeSyrdhnLOA8s@hyeyoo>
 <CANpmjNMFOmtu3B5NCgrbrbkXk=FVfxSKGOEQvBhELSXRSv_1uQ@mail.gmail.com>
 <7edc9d38-da50-21c8-ea79-f003f386c29b@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7edc9d38-da50-21c8-ea79-f003f386c29b@suse.cz>
X-ClientProxiedBy: SG2P153CA0005.APCP153.PROD.OUTLOOK.COM (2603:1096::15) To
 MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 422ac82a-8fbd-4816-342a-08da8bb92224
X-MS-TrafficTypeDiagnostic: MW4PR11MB6786:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: mzm5i49qrtRbXjMeiVkRj0Y6LE87uOenUntMd31jegURj63ncyT2O8mJIxc78cUo/JwNq17NNrXnydONb1tioWDgAZ0WRNsaTu3hsMA5H/6vT/aVYffLEgsiSwCXRpJFbAHqXiETDp5rIPblOXg1VHPij6O1hgu7t1dE13Goh0k/Ilhzk1cxxWWabncgVPphb7fDTnEVrS+9eIscnrxcSQO1NdFcbUrZiEqtF1w2yA118HUm7lgjl5ZLoZRipBKNU1CjrkequhOJ/PUER21abQA/YROfTu8JeQVA28U3CIWM7gM97GhuTzyP1xa8b5TFmwUdGkSQ8+i49IFkMQ2nYASbo0Km7XwZLrQdYGfUDDHQJt1kmUe5zZWFf+5FkeorK808oM/u+xE8a9oowzCRGXByN3zoshNez4D84ITswwy5eIOgM5N9FsCSicXYn5b2nK0tKBwMgU2CUcLZa5Xljtc/nqjSc8uJAjvc4BO7pkDv19r43hzpsy2mn9f8Sv6yA8BLxe+frrTSZZhfjOtoL56EIJ7IUQXopBu0G8weFRBy/f+3G73CuZBgo9v31iupAV7i6pmDEg2DWbu18FnrDrGLZWAJF85KCGS9T3/u9ppqa9dMSrEheZYLwA0s+GP8Q2BdClaEKe/bF4f68+xXlP7wYpLgCkxSwr4zm5nY02yimh62gsTZHWCa0JjP0CmlTN7KqZc1D6EwQDRvjA6wKA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(346002)(136003)(396003)(39860400002)(366004)(376002)(44832011)(33716001)(66476007)(66556008)(66946007)(6916009)(54906003)(316002)(53546011)(41300700001)(6666004)(6506007)(26005)(2906002)(8936002)(5660300002)(6486002)(478600001)(9686003)(6512007)(186003)(83380400001)(82960400001)(86362001)(4326008)(8676002)(38100700002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ZVi+wCytboJCeckyTIl5Um6S72A9AsGImc0ZJDhEI30HQ7qVw5r+K8Xfxnki?=
 =?us-ascii?Q?oU0OYS4RgVOjMAbaRIu7a1BzR2yLGbLJiT4IvLqevxTTt5kLE3FyPMm2S7Dg?=
 =?us-ascii?Q?WCLy7egUwnCXxAwLnV5cQYQnXvptR+IcJKcHjM2OVdVy6trOk+b+bhoNDitO?=
 =?us-ascii?Q?Cr+p+g0T5VEOJihZxfl3ea4qUjU7UYNp7QUZW2twZuIcideE6kNBd6drei1r?=
 =?us-ascii?Q?Kcoc3ia2ZJ577TNVhvrCuoYoHudcrg39YoiSWxMLjrLca4oKdcl78l0kMAJf?=
 =?us-ascii?Q?p5UJ5TeXc3t+9r4yeKCaSq3bnUQIzdVD3KbF8yoZMj65ef//O8LVoqdEUw3s?=
 =?us-ascii?Q?nkAO56eF4MXcH8E1kaoPeAtCXgch8esVX87Z3RFAO9I5ssCfJF3qrtBuAhZU?=
 =?us-ascii?Q?qYQf7vo88hDinxfErNkJqhkYXwbJAYFCfwAzU3Nckxww28YaeQ+9R9Wl0CeP?=
 =?us-ascii?Q?i4NacCNW0LMoAlTQYGDempgp1sUpExmZ/aP8TA5ExbCmyxqcgEwBD+VnIuKb?=
 =?us-ascii?Q?2ZRXap5zTsELwPHaaO863ShDy+cciDnewpCL+dJe1a2Kv89Zw1Y/B9FKdceu?=
 =?us-ascii?Q?kX/wCI4wgQlcwtaU/vKpTGuJmW9rPjyQgJYVeI03Tzv6lwKSTSpHjgPlifOr?=
 =?us-ascii?Q?oJf9HSHG6L2CbWmLVH3XgLaYI1+WviVcsHAUtjDdrLg+m29RkBDZzMvNccxn?=
 =?us-ascii?Q?w/Ai9CeRwLEArS1duAoWqjbsu4vKVROESFuE0x1MXg7P51yEctjpzCvd59F/?=
 =?us-ascii?Q?grhsQ65FovywYjnDU3xPFOuPQSv8jp0E4EmNR1ybKO/Nz+pVbjtG/Nqm8W8F?=
 =?us-ascii?Q?flzqqaF/unESuv+xbLbw2EiqfR/Ewcu10GCo8Gwur41aHPxr7BgT0gHpQwLH?=
 =?us-ascii?Q?WleTTy189Hl4ikQGaVZB8dF7lrulYQDDTPgLMCkM+j0MqZOZ5mU+KhDRyWKb?=
 =?us-ascii?Q?lgZGVa//gmYxBErg7TkJoVtHsnMOSBIC27C/GlCEin0kpuDq5x3tWgqS8KKq?=
 =?us-ascii?Q?BPb8WqN6jdOUDG9BWvoqlNjLvGf+EseCrNiKQaBNq6bw1upag2Nyukx5VW/r?=
 =?us-ascii?Q?p1NozMO1jRRVfdxxi2wrlQ0HKuE1J7Z7vjLbApa0RUneWi3uKtbbTv3vyLJ+?=
 =?us-ascii?Q?kfBW358tOZrOPIPdaMu/sZhMXAZYLDATltH4HL8hPrnmTDFhO66R7tdby9Iz?=
 =?us-ascii?Q?zl/lr4uJJxTIDMjfnwo/ONpVQOWj1kNZitXM6sdoMKfobgl+EnaUZbh3LCl/?=
 =?us-ascii?Q?3OJKcxrcDJgwXoBGftB27Vumn3z2vsU/aEOKwRwtAcnmMpiLVY006AGBu66Y?=
 =?us-ascii?Q?7JWTQZiX9CtRY0bBFIFvcib7BqHHQfoQ2JZKMqei+2ZXkQHLxIpymP0cOqnS?=
 =?us-ascii?Q?h1Bb9uV9ijkMqYGgbx45JH12xXzoPr+tw4WTBuTbBTc8E3BEOlkXnZ2s1JSH?=
 =?us-ascii?Q?WzRisle/fVp2UexC6lnCFWk54q8iBb55tU00ST/nexyLIqneVSjA9CU2NjKm?=
 =?us-ascii?Q?7p93Iij5oiEUfid8a7OcvBt09qwOEQdvjc7kOAcjecg+IY2ICfq2TYtL9flB?=
 =?us-ascii?Q?Xch3yLghyyU6iOjA+p2qtM1MKBhhJzaVDFIOoQKY?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 422ac82a-8fbd-4816-342a-08da8bb92224
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Sep 2022 01:27:28.6086
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: KclWF6jzw5IYkUT79Uv04ib5JN8UQ4ZtM2AmmHO4HLAsqTD16MfvER2CQeihXeugVv1rg8/SgclN6VdA1/jckQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR11MB6786
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=l5Ad38Dx;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.88 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Thu, Sep 01, 2022 at 12:16:17AM +0800, Vlastimil Babka wrote:
> On 8/31/22 16:21, Marco Elver wrote:
> > On Wed, 31 Aug 2022 at 16:04, Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
> > 
> >> Maybe you can include those functions too?
> >>
> >> - __kmem_cache_alloc_node
> >> - kmalloc_[node_]trace, kmalloc_large[_node]
> > 
> > This is only required if they are allocator "root" functions when
> > entering allocator code (or may be tail called by a allocator "root"
> > function). Because get_stack_skipnr() looks for one of the listed
> > function prefixes in the whole stack trace.
> > 
> > The reason __kmem_cache_free() is now required is because it is tail
> > called by kfree() which disappears from the stack trace if the
> > compiler does tail-call-optimization.
> 
> I checked and I have this jmp tail call, yet all test pass here.
> But I assume the right commit to amend is
> 05a1c2e50809 ("mm/sl[au]b: generalize kmalloc subsystem")
> 
> Could you Feng maybe verify that that commit is the first that fails the
> tests, and parent commit of that is OK? Thanks.

Yes, 05a1c2e50809 is the first commit that I saw the 4 kfence failed
kunit cases.

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxAKXt%2Ba/pqtUmDz%40feng-clx.
