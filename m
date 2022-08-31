Return-Path: <kasan-dev+bncBDN7L7O25EIBBAXIXWMAMGQEAUCHOKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 642405A8082
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 16:45:23 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id m1-20020a2eb6c1000000b00261e5aa37fesf4094849ljo.6
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 07:45:23 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=c1CmXxmySOwcp34LcUMCwIfnW6ZeolJcw5OL+YBvfjk=;
        b=WdtY3Zck8q3kB0RQrOMiLy708rgfsb6bj7+ftI6PIp1rBJ6kX42uWkq+4zqag897SN
         6jzHgWEfygp9JdSee3ySyDmVtkk9ez5UBzj9dMtyz/hAgQS/K9myzL5usJJERIY4/tQ6
         YAaZnMSVn5L2rrb2Gq1I1mJrvB/f1Oh9njnvr+Fx/pv1rmxYwcFaV5r2tCCl1M1QY1+u
         zwzEUw2iK+KqIXrleI0pnTVF7CNwMjeJIWKe/1qMawtVxEXxJE6f7DyeJQUaIy3Rdw9z
         kejccxWNNqkHvcKXFVaclNLp+cMK2fGExRYjyRQUTlv2vX4vY1vHYOvU30ts1P3FgA66
         kBIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc;
        bh=c1CmXxmySOwcp34LcUMCwIfnW6ZeolJcw5OL+YBvfjk=;
        b=1+miqDSKa6mRCmB5eNotKKV5H3bdgZGIuEjIv78rNVYXRdx6j/clpVtnLN3DQfRWFP
         2ng4NqnzUhWhAY4mS/UUisndk/V84v4AmLvOKjMIeESf7lXkOQoZm6c78G74D6NIgWfO
         nd64N8K0RVAXRf95MTBcyNJWccxM+EVjvLbgMogBRzAUfhX+EUrAG4utOa2O5ASNfwiU
         Ic+ZKtmHUlIR+fSQptQfvMWopTlDG9sqbSo9NnSNUHoxma2vUfztmXePm/vaBUd46Kf9
         4h32+uY5g4z8bJBfdoKqdCBHBeTKuUE0WIm9TeY+f2vvYDvkSWAt8P/4gp5nTaBGkNWF
         PUrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3bhU3id14zmMRTkQsOCdCkcJWgeEJbmuH2U5M5grXGNU/BYF78
	AOy4+e2aHuYpEYYWX4NDalc=
X-Google-Smtp-Source: AA6agR6FM+Frj2bF4Ml9js7gYi77C4K3XkqzXlp32QUTHx92WvO/zK9p/R3pun6/wzIb+Uy166NPPA==
X-Received: by 2002:a05:6512:1598:b0:494:716d:34e5 with SMTP id bp24-20020a056512159800b00494716d34e5mr3781453lfb.366.1661957122616;
        Wed, 31 Aug 2022 07:45:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3587:b0:494:799f:170 with SMTP id
 m7-20020a056512358700b00494799f0170ls3704954lfr.0.-pod-prod-gmail; Wed, 31
 Aug 2022 07:45:21 -0700 (PDT)
X-Received: by 2002:a05:6512:15aa:b0:494:7a2a:cc1f with SMTP id bp42-20020a05651215aa00b004947a2acc1fmr2752365lfb.36.1661957121031;
        Wed, 31 Aug 2022 07:45:21 -0700 (PDT)
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id w18-20020a05651234d200b00492d8e5069csi13729lfr.9.2022.08.31.07.45.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Aug 2022 07:45:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6500,9779,10456"; a="295465793"
X-IronPort-AV: E=Sophos;i="5.93,278,1654585200"; 
   d="log'?scan'208";a="295465793"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 31 Aug 2022 07:44:59 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,278,1654585200"; 
   d="log'?scan'208";a="589053905"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by orsmga006.jf.intel.com with ESMTP; 31 Aug 2022 07:44:58 -0700
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 31 Aug 2022 07:44:58 -0700
Received: from fmsmsx607.amr.corp.intel.com (10.18.126.87) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 31 Aug 2022 07:44:57 -0700
Received: from fmsedg602.ED.cps.intel.com (10.1.192.136) by
 fmsmsx607.amr.corp.intel.com (10.18.126.87) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Wed, 31 Aug 2022 07:44:57 -0700
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.169)
 by edgegateway.intel.com (192.55.55.71) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Wed, 31 Aug 2022 07:44:56 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Rn6qS6HELK9HUdqTTxtSDN03Gc/IZsmWwcJsTqr8gqKolTSmd12+J4CQ/QHZJ5VL+Z64QaAABo/YSwDfhwGfqOwNujRFrAkmv9EZjSLD/tnDZDWCkYi7PJBp4YcrkkmSGYZNvkL6l7LhZhEhKuGPAlp5Jx+dzR3jWAFwJzqo9mwS12RqNByajte1SaUTeZYT8EiMDZS4doC1zbdImvUrM7ymNfyMjnTKmCZkc2wAxqyHDUCY+qoBC/mI6aWN1VwtU3LA/WfCWwyoRc4o8RRXEQm/GJCuasvDWT8mGnZx9lx1vLfK9giQU9tuw1v6d274aWwBUc5ax4gN02FVgQ26YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=KgI1tg2Dfpsyyys6j6ektXvLdBwV2HgQ0TPHEeHS3g8=;
 b=M8S+OsO+DOV4Eml63mtSejAMjAo/yCSP1b+lLLHnoFKYEcEkKuXUCLWBIUM3f8hJvHhFC/hwlVKM3gjrX3YM8ijNZXx5ODKdKW1U8NKmkMuPfJmhNZ6JulJQSNQdYMi1qIPunSvBgbI4BvpD8P/hqBsSiwtvbtxIzKE75JahDBo+uVlPuxcupH7vpnTO4gUzIHt4WlWaByz5oYcbF116YXg3eDyczLyZGEO54A0unQBNnst4Fu1HDdZMglXNEiPaHuFnif25QVqP3jk5ARZbQHzXEYzwAq9h0/awskFr/F+uv+LwQhO8rjw877ECxtC1v8KQSoLOkp3F8a2oq49EuQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by DM5PR11MB1708.namprd11.prod.outlook.com (2603:10b6:3:d::16) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5588.10; Wed, 31 Aug 2022 14:44:53 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::d446:1cb8:3071:f4e8]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::d446:1cb8:3071:f4e8%5]) with mapi id 15.20.5588.010; Wed, 31 Aug 2022
 14:44:53 +0000
Date: Wed, 31 Aug 2022 22:44:11 +0800
From: Feng Tang <feng.tang@intel.com>
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip
 list
Message-ID: <Yw9zu4RV8Z9QzYiL@feng-clx>
References: <20220831073051.3032-1-feng.tang@intel.com>
 <Yw9qeSyrdhnLOA8s@hyeyoo>
Content-Type: multipart/mixed; boundary="4uR9TydQqPng+7Dv"
Content-Disposition: inline
In-Reply-To: <Yw9qeSyrdhnLOA8s@hyeyoo>
X-ClientProxiedBy: SG2PR03CA0123.apcprd03.prod.outlook.com
 (2603:1096:4:91::27) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 9eaaf7ce-8772-418f-4d87-08da8b5f5cf5
X-MS-TrafficTypeDiagnostic: DM5PR11MB1708:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: fs9qGQXzvS6tnIrsv2HeHm+3AU5WReMxLpF+Ae9/xwamOh3rHcg7yqYi7UJ1Ty9yQnGssd+K/BZB/OOcdnErXCnpTsmbThROZQg5L9WPsQ8JF8jyaQTHRt0rg7TGYH936onb8z2oupF7IfdFgzcWeL+zspMWCCzZ+GSSDbfwg+E5bxKM5774FYrcz3AsguMc6Ic2pqfpg0Z+77xd/tfT2LnsH6ZkJYLop8szTZ0wOaYUmJre+us2aunmv7B6W9qxWe8XjeeQQuz6xow5XeLAxf0BcpZiSuoF7PGjqKqY+kkopjrg7dOCu+i88I+lelsUjttpVjVhkfXGuZ2Tmo4HvCeocJjYeRa3ixl+KsZnJSu2IKSJ4vMomcGck72g+TeC5xxLrh4+UOF3quCvVhuQILiWFmajGpC6f61xPeuLl7mt0367LH+Hwc2NqieQgLXPtL+cbmSsKFwFHjJ8w5lz+gj/mF10DhWNe26CAWVbGtuF7ZlUisIGxSVvxnDbxmV+F3XiC/iEeelbXEQ4JulrFNAj9VTCfmL1kOoJG5TV0gHzs/pl6UzEnXiltsgnem3hZvexgprOGmnrJuiHnmez6PseVSmQ7fWVmWYnXEt8CUkm+K72nN8+7yQDNLujRfx7Vl5bBfQZdsBizc0nNPuVGPajVXxCGUDEaWaAaLXXzJlVtXW851dHqxSa6zyNxbSnPZwtv9tyiBc1bk9SgUdoWLM7vKOTmvmvI2DYP98IDjYmcGV4UjYxHazClMZoorr34taza2R0Ngi80eexQICUYw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(376002)(346002)(39860400002)(366004)(136003)(396003)(6666004)(41300700001)(5660300002)(235185007)(44832011)(33716001)(86362001)(186003)(9686003)(6512007)(8936002)(26005)(6506007)(44144004)(316002)(2906002)(6916009)(54906003)(21480400003)(82960400001)(478600001)(38100700002)(66556008)(66476007)(6486002)(66946007)(8676002)(4326008)(2700100001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?VMnwsKoxtqQz6HlUotLVpSKthmo5JmplNpkIUfUlJy7KYrHbDsDLLl8aJOyT?=
 =?us-ascii?Q?r/PKma9pbgySg7dDgk15rWhyahsKVthuFmCPeZ/x6VKNdOp9Nj78r7v9QB95?=
 =?us-ascii?Q?/h1p0vrWCg+CAk5Xmr3UosV8wJD185ZR2oboB4Hembpxwv2uUwOnWzmmn+w7?=
 =?us-ascii?Q?5PuIUKlKjI7WSrRMPpf7SKx7eT4Nn+BswXd+Z1wS4+Hh8dWy8Yyd0Vh2Y19m?=
 =?us-ascii?Q?mN3Qa/g/tnY+RzUVCawElgU1rrYVjYhBq6sJrBMCPH+vA/X4Gz8cALe8zcxT?=
 =?us-ascii?Q?GQ8BXrPf6L3eaGkVdQZuYvwsXCk+H7XUSo/5SqpJDU7nDhGjuTdbZCWfz8SG?=
 =?us-ascii?Q?8FKWYDTebbdzTinJpLbqaKyW/BHDyp8BcNGVFjULycXSRHI848GYlgvW70Ia?=
 =?us-ascii?Q?gO589+EqdUXqJidW87IKY1pTBnhc7mF/pHlUas9pohFBz2+muKOSvmAw0Pv4?=
 =?us-ascii?Q?VKLseGvdDJAsX6O9ufxlkthEo/mCVSeGk8svdi6ppn8MmRSpA2ykXJR3UPtW?=
 =?us-ascii?Q?O9B46K4PoK31FSeRwxNYk82dbKR7GNEnuItErVgqK+/GX24NtknL3N4s7hx6?=
 =?us-ascii?Q?sHFHyoUQkTL+gNgdun04y60HhqAtakXDwQoeProR26iYC1wC97QAHR6JyyNj?=
 =?us-ascii?Q?CZjdVvLg50rnPw06gLhqCGz/WbiOwpUwBii33t5F+m2fjDjgd3lP+l70SiQG?=
 =?us-ascii?Q?gWoSYF40sXD8+ZrTHKuhObBmiV8EQxaL6jr0rCXnNMV2jnGEltseI40V2gVU?=
 =?us-ascii?Q?fSRso0eLqNZkuUmszdozk+VwFk4EWRJXSW+dha+avLbworACpRmSAAyiqd7y?=
 =?us-ascii?Q?BH1n6Lzl0FUWSmt+9CQ07uuU++IVOUDhAuJA41+2l32E054bQvuRg6rdfeY7?=
 =?us-ascii?Q?TU9l2MSKEFT0/J4Gp5cjqW8BgLZT03s2Uv/i+NGc83GcAnGgGbyvDErnNc+w?=
 =?us-ascii?Q?6SDJbhCbx+eQJgoVxNap++X4+SD6nBdtMyF0tdP1IETqCY7IBxb1tcr7t452?=
 =?us-ascii?Q?MUN7delNvtBmNeEUWRthAhaa9L52Cex8DNJEPiPKOYdXPzF2xgutT9G7a+L3?=
 =?us-ascii?Q?FpfkCdv8adENom2agirErUaBxGfGJKtsvRrFi1oHVNbfe91uPc+4fkQV9ToW?=
 =?us-ascii?Q?pudUXn10ujUvXk5C8OZQcc5fRQVFum4/J3cM8I5fure6460Ht1jMVT30RJtq?=
 =?us-ascii?Q?t2SYslMh5RLYQxjCeEacREUvSOVMvcSmyXmULM36SX40phtu4o1rgYu9xt8p?=
 =?us-ascii?Q?xiViDEGVMkrqXoKREs6YTC0BXah4id9YFdkG4NUGrjZ3FO++Qa+TuHj4teLi?=
 =?us-ascii?Q?LGQGqR2cw55jYHrIJwVgF5UKGOzbKCPQm6AEQKUI2bqhTrWjQOY/ZAIzoUGk?=
 =?us-ascii?Q?SshbpAfO/IGVLBJE7q+nBdIH0CakDsvLHVWX6JE67D62Td9Q5HMGSua+623D?=
 =?us-ascii?Q?u8XqXoCv1Xc/n5Q1q+qSjc+Ey+cZQooqi09WnaL5IsV5x0umYvodKqQzxiaq?=
 =?us-ascii?Q?E7r6UW5/r2APuznP5ogiFBlVhktkf25bbX1YI6SNlMmAR5yNTrtOE5AgD59Q?=
 =?us-ascii?Q?Xq9Nv8Uyih2aK64RF0OKZ7+Q2esaLqh4dIjimRx9?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 9eaaf7ce-8772-418f-4d87-08da8b5f5cf5
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 31 Aug 2022 14:44:53.5677
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Ddz0aDD6Jv9ynoOP33jYn5rRoBA9iYeNLwwJ5CXS6vh2iqDWvFgveyYxPLjFifxuUs22wTb7GNoXhL4MuM9IIA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM5PR11MB1708
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HsqNhekT;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.115 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

--4uR9TydQqPng+7Dv
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hi Hyeonggon,

On Wed, Aug 31, 2022 at 10:04:41PM +0800, Hyeonggon Yoo wrote:
> On Wed, Aug 31, 2022 at 03:30:51PM +0800, Feng Tang wrote:
> > When testing the linux-next kernel, kfence's kunit test reported some
> > errors:
> > 
> >   [   12.812412]     not ok 7 - test_double_free
> >   [   13.011968]     not ok 9 - test_invalid_addr_free
> >   [   13.438947]     not ok 11 - test_corruption
> >   [   18.635647]     not ok 18 - test_kmalloc_aligned_oob_write
> > 
> > Further check shows there is the "common kmalloc" patchset from
> > Hyeonggon Yoo, which cleanup the kmalloc code and make a better
> > sharing of slab/slub. There is some function name change around it,
> > which was not recognized by current kfence function name handling
> > code, and interpreted as error.
> > 
> > Add new function name "__kmem_cache_free" to make it known to kfence.
> > 
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > ---
> >  mm/kfence/report.c | 1 +
> >  1 file changed, 1 insertion(+)
> > 
> > diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> > index f5a6d8ba3e21..7e496856c2eb 100644
> > --- a/mm/kfence/report.c
> > +++ b/mm/kfence/report.c
> > @@ -86,6 +86,7 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
> >  		/* Also the *_bulk() variants by only checking prefixes. */
> >  		if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
> >  		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
> > +		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_free") ||
> >  		    str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
> >  		    str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
> >  			goto found;
> > -- 
> > 2.27.0
> > 
> 
> Thank you for catching this!
> 
> Unfortunately not reproducible on my environment with linux-next (IDK why).

Maybe it's about the kernel config, or gcc version?

The head commit of next tree I tested is at:

7fd22855300e [Stephen Rothwell] Add linux-next specific files for 20220831 Wed Aug 31 15:48:36 2022 +1000

My gcc version is: "gcc (Ubuntu 10.3.0-1ubuntu1~20.10) 10.3.0"

I also attached the kernel config and the dmesg log which has the kfence
unit text info (the kernel is boot in a qemu with debian rootfs).


> Maybe you can include those functions too?
> 
> - __kmem_cache_alloc_node
> - kmalloc_[node_]trace, kmalloc_large[_node]

Though I threw the patch out, I have to admit I know very little about kfence
internals, will leave it to kfence developers :) (I saw Macro Elver already
replied).

Thanks,
Feng


> -- 
> Thanks,
> Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yw9zu4RV8Z9QzYiL%40feng-clx.

--4uR9TydQqPng+7Dv
Content-Type: text/plain; charset="us-ascii"
Content-Disposition: attachment; filename="linux-next-kfence-dmesg.log"

[    0.000000] Linux version 6.0.0-rc3-next-20220831-00002-g6db6c886e5af (feng@shbuild999) (gcc (Ubuntu 10.3.0-1ubuntu1~20.10) 10.3.0, GNU ld (GNU Binutils for Ubuntu) 2.35.1) #245 SMP PREEMPT_DYNAMIC Wed Aug 31 22:24:56 CST 2022
[    0.000000] Command line: root=/dev/sda debug sched_debug apic=debug ignore_loglevel sysrq_always_enabled panic=10 earlyprintk=ttyS0,115200 console=ttyS0,115200 vga=normal nokalsr nokaslr panic_on_warn apic=debug cma=0 psi=no slub_debug=UP movable_nodemask=0xc cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1 rw
[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x004: 'AVX registers'
[    0.000000] x86/fpu: xstate_offset[2]:  576, xstate_sizes[2]:  256
[    0.000000] x86/fpu: Enabled xstate features 0x7, context size is 832 bytes, using 'standard' format.
[    0.000000] signal: max sigframe size: 1776
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x000000000009fc00-0x000000000009ffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000000f0000-0x00000000000fffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000bffdefff] usable
[    0.000000] BIOS-e820: [mem 0x00000000bffdf000-0x00000000bfffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000feffc000-0x00000000feffffff] reserved
[    0.000000] BIOS-e820: [mem 0x00000000fffc0000-0x00000000ffffffff] reserved
[    0.000000] BIOS-e820: [mem 0x0000000100000000-0x000000013fffffff] usable
[    0.000000] printk: debug: ignoring loglevel setting.
[    0.000000] printk: bootconsole [earlyser0] enabled
[    0.000000] NX (Execute Disable) protection: active
[    0.000000] SMBIOS 2.8 present.
[    0.000000] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[    0.000000] Hypervisor detected: KVM
[    0.000000] kvm-clock: Using msrs 4b564d01 and 4b564d00
[    0.000003] kvm-clock: using sched offset of 539331094 cycles
[    0.001038] clocksource: kvm-clock: mask: 0xffffffffffffffff max_cycles: 0x1cd42e4dffb, max_idle_ns: 881590591483 ns
[    0.004267] tsc: Detected 2693.508 MHz processor
[    0.008287] e820: update [mem 0x00000000-0x00000fff] usable ==> reserved
[    0.009657] e820: remove [mem 0x000a0000-0x000fffff] usable
[    0.010753] last_pfn = 0x140000 max_arch_pfn = 0x400000000
[    0.011902] x86/PAT: Configuration [0-7]: WB  WC  UC- UC  WB  WP  UC- WT  
[    0.013255] last_pfn = 0xbffdf max_arch_pfn = 0x400000000
[    0.014327] Scan for SMP in [mem 0x00000000-0x000003ff]
[    0.015404] Scan for SMP in [mem 0x0009fc00-0x0009ffff]
[    0.016496] Scan for SMP in [mem 0x000f0000-0x000fffff]
[    0.031411] found SMP MP-table at [mem 0x000f5a60-0x000f5a6f]
[    0.032535]   mpc: f5a70-f5b84
[    0.033207] Using GB pages for direct mapping
[    0.043436] ACPI: Early table checksum verification disabled
[    0.044612] ACPI: RSDP 0x00000000000F5A20 000014 (v00 BOCHS )
[    0.045818] ACPI: RSDT 0x00000000BFFE1579 000038 (v01 BOCHS  BXPCRSDT 00000001 BXPC 00000001)
[    0.047552] ACPI: FACP 0x00000000BFFE12A1 000074 (v01 BOCHS  BXPCFACP 00000001 BXPC 00000001)
[    0.049233] ACPI: DSDT 0x00000000BFFDFD80 001521 (v01 BOCHS  BXPCDSDT 00000001 BXPC 00000001)
[    0.050935] ACPI: FACS 0x00000000BFFDFD40 000040
[    0.051850] ACPI: APIC 0x00000000BFFE1315 000090 (v01 BOCHS  BXPCAPIC 00000001 BXPC 00000001)
[    0.053518] ACPI: HPET 0x00000000BFFE13A5 000038 (v01 BOCHS  BXPCHPET 00000001 BXPC 00000001)
[    0.055183] ACPI: SRAT 0x00000000BFFE13DD 000160 (v01 BOCHS  BXPCSRAT 00000001 BXPC 00000001)
[    0.056833] ACPI: SLIT 0x00000000BFFE153D 00003C (v01 BOCHS  BXPCSLIT 00000001 BXPC 00000001)
[    0.058528] ACPI: Reserving FACP table memory at [mem 0xbffe12a1-0xbffe1314]
[    0.059892] ACPI: Reserving DSDT table memory at [mem 0xbffdfd80-0xbffe12a0]
[    0.061270] ACPI: Reserving FACS table memory at [mem 0xbffdfd40-0xbffdfd7f]
[    0.062649] ACPI: Reserving APIC table memory at [mem 0xbffe1315-0xbffe13a4]
[    0.064032] ACPI: Reserving HPET table memory at [mem 0xbffe13a5-0xbffe13dc]
[    0.065405] ACPI: Reserving SRAT table memory at [mem 0xbffe13dd-0xbffe153c]
[    0.066793] ACPI: Reserving SLIT table memory at [mem 0xbffe153d-0xbffe1578]
[    0.068346] mapped APIC to ffffffffff5fc000 (        fee00000)
[    0.069798] SRAT: PXM 0 -> APIC 0x00 -> Node 0
[    0.070683] SRAT: PXM 0 -> APIC 0x01 -> Node 0
[    0.071551] SRAT: PXM 1 -> APIC 0x02 -> Node 1
[    0.072408] SRAT: PXM 1 -> APIC 0x03 -> Node 1
[    0.073270] ACPI: SRAT: Node 0 PXM 0 [mem 0x00000000-0x0009ffff]
[    0.074440] ACPI: SRAT: Node 0 PXM 0 [mem 0x00100000-0x3fffffff]
[    0.075611] ACPI: SRAT: Node 1 PXM 1 [mem 0x40000000-0x7fffffff]
[    0.076774] ACPI: SRAT: Node 2 PXM 2 [mem 0x80000000-0xbfffffff]
[    0.077971] ACPI: SRAT: Node 3 PXM 3 [mem 0x100000000-0x13fffffff]
[    0.079238] NUMA: Initialized distance table, cnt=4
[    0.080208] NUMA: Node 0 [mem 0x00000000-0x0009ffff] + [mem 0x00100000-0x3fffffff] -> [mem 0x00000000-0x3fffffff]
[    0.082286] NODE_DATA(0) allocated [mem 0x3ffd5000-0x3fffffff]
[    0.083572] NODE_DATA(1) allocated [mem 0x7ffd5000-0x7fffffff]
[    0.084840] NODE_DATA(2) allocated [mem 0xbffb4000-0xbffdefff]
[    0.086130] NODE_DATA(3) allocated [mem 0x13ffd2000-0x13fffcfff]
[    0.088319] Zone ranges:
[    0.088839]   DMA      [mem 0x0000000000001000-0x0000000000ffffff]
[    0.090072]   DMA32    [mem 0x0000000001000000-0x00000000ffffffff]
[    0.091293]   Normal   [mem 0x0000000100000000-0x000000013fffffff]
[    0.092487]   Device   empty
[    0.093052] Movable zone start for each node
[    0.093927] Early memory node ranges
[    0.094627]   node   0: [mem 0x0000000000001000-0x000000000009efff]
[    0.095844]   node   0: [mem 0x0000000000100000-0x000000003fffffff]
[    0.097065]   node   1: [mem 0x0000000040000000-0x000000007fffffff]
[    0.098329]   node   2: [mem 0x0000000080000000-0x00000000bffdefff]
[    0.099560]   node   3: [mem 0x0000000100000000-0x000000013fffffff]
[    0.100802] Initmem setup node 0 [mem 0x0000000000001000-0x000000003fffffff]
[    0.102248] Initmem setup node 1 [mem 0x0000000040000000-0x000000007fffffff]
[    0.103619] Initmem setup node 2 [mem 0x0000000080000000-0x00000000bffdefff]
[    0.105012] Initmem setup node 3 [mem 0x0000000100000000-0x000000013fffffff]
[    0.106471] On node 0, zone DMA: 1 pages in unavailable ranges
[    0.107077] On node 0, zone DMA: 97 pages in unavailable ranges
[    0.133075] On node 3, zone Normal: 33 pages in unavailable ranges
[    0.703963] kasan: KernelAddressSanitizer initialized
[    0.706935] ACPI: PM-Timer IO Port: 0x608
[    0.707773] ACPI: LAPIC_NMI (acpi_id[0xff] dfl dfl lint[0x1])
[    0.709002] IOAPIC[0]: apic_id 0, version 17, address 0xfec00000, GSI 0-23
[    0.710359] ACPI: INT_SRC_OVR (bus 0 bus_irq 0 global_irq 2 dfl dfl)
[    0.711591] Int: type 0, pol 0, trig 0, bus 00, IRQ 00, APIC ID 0, APIC INT 02
[    0.712993] ACPI: INT_SRC_OVR (bus 0 bus_irq 5 global_irq 5 high level)
[    0.714283] Int: type 0, pol 1, trig 3, bus 00, IRQ 05, APIC ID 0, APIC INT 05
[    0.715679] ACPI: INT_SRC_OVR (bus 0 bus_irq 9 global_irq 9 high level)
[    0.716968] Int: type 0, pol 1, trig 3, bus 00, IRQ 09, APIC ID 0, APIC INT 09
[    0.718440] ACPI: INT_SRC_OVR (bus 0 bus_irq 10 global_irq 10 high level)
[    0.719779] Int: type 0, pol 1, trig 3, bus 00, IRQ 0a, APIC ID 0, APIC INT 0a
[    0.721207] ACPI: INT_SRC_OVR (bus 0 bus_irq 11 global_irq 11 high level)
[    0.722546] Int: type 0, pol 1, trig 3, bus 00, IRQ 0b, APIC ID 0, APIC INT 0b
[    0.723945] Int: type 0, pol 0, trig 0, bus 00, IRQ 01, APIC ID 0, APIC INT 01
[    0.725349] Int: type 0, pol 0, trig 0, bus 00, IRQ 03, APIC ID 0, APIC INT 03
[    0.726767] Int: type 0, pol 0, trig 0, bus 00, IRQ 04, APIC ID 0, APIC INT 04
[    0.728171] Int: type 0, pol 0, trig 0, bus 00, IRQ 06, APIC ID 0, APIC INT 06
[    0.729578] Int: type 0, pol 0, trig 0, bus 00, IRQ 07, APIC ID 0, APIC INT 07
[    0.730990] Int: type 0, pol 0, trig 0, bus 00, IRQ 08, APIC ID 0, APIC INT 08
[    0.732406] Int: type 0, pol 0, trig 0, bus 00, IRQ 0c, APIC ID 0, APIC INT 0c
[    0.733831] Int: type 0, pol 0, trig 0, bus 00, IRQ 0d, APIC ID 0, APIC INT 0d
[    0.735245] Int: type 0, pol 0, trig 0, bus 00, IRQ 0e, APIC ID 0, APIC INT 0e
[    0.736644] Int: type 0, pol 0, trig 0, bus 00, IRQ 0f, APIC ID 0, APIC INT 0f
[    0.738063] ACPI: Using ACPI (MADT) for SMP configuration information
[    0.739329] ACPI: HPET id: 0x8086a201 base: 0xfed00000
[    0.740393] TSC deadline timer available
[    0.741196] smpboot: Allowing 4 CPUs, 0 hotplug CPUs
[    0.742229] mapped IOAPIC to ffffffffff5fb000 (fec00000)
[    0.743341] kvm-guest: KVM setup pv remote TLB flush
[    0.744324] kvm-guest: setup PV sched yield
[    0.745244] PM: hibernation: Registered nosave memory: [mem 0x00000000-0x00000fff]
[    0.746744] PM: hibernation: Registered nosave memory: [mem 0x0009f000-0x0009ffff]
[    0.748214] PM: hibernation: Registered nosave memory: [mem 0x000a0000-0x000effff]
[    0.749704] PM: hibernation: Registered nosave memory: [mem 0x000f0000-0x000fffff]
[    0.751209] PM: hibernation: Registered nosave memory: [mem 0xbffdf000-0xbfffffff]
[    0.752700] PM: hibernation: Registered nosave memory: [mem 0xc0000000-0xfeffbfff]
[    0.754220] PM: hibernation: Registered nosave memory: [mem 0xfeffc000-0xfeffffff]
[    0.755705] PM: hibernation: Registered nosave memory: [mem 0xff000000-0xfffbffff]
[    0.757190] PM: hibernation: Registered nosave memory: [mem 0xfffc0000-0xffffffff]
[    0.758748] [mem 0xc0000000-0xfeffbfff] available for PCI devices
[    0.759945] Booting paravirtualized kernel on KVM
[    0.760955] clocksource: refined-jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 1910969940391419 ns
[    0.781672] setup_percpu: NR_CPUS:8192 nr_cpumask_bits:4 nr_cpu_ids:4 nr_node_ids:4
[    0.786343] percpu: Embedded 76 pages/cpu s274432 r8192 d28672 u1048576
[    0.787686] pcpu-alloc: s274432 r8192 d28672 u1048576 alloc=1*2097152
[    0.788953] pcpu-alloc: [0] 0 1 [1] 2 3 
[    0.789892] kvm-guest: PV spinlocks enabled
[    0.790773] PV qspinlock hash table entries: 256 (order: 0, 4096 bytes, linear)
[    0.792322] Fallback order for Node 0: 0 2 1 3 
[    0.793280] Fallback order for Node 1: 1 3 0 2 
[    0.794250] Fallback order for Node 2: 2 0 3 1 
[    0.795191] Fallback order for Node 3: 3 1 0 2 
[    0.796136] Built 4 zonelists, mobility grouping on.  Total pages: 1031903
[    0.797533] Policy zone: Normal
[    0.798185] Kernel command line: root=/dev/sda debug sched_debug apic=debug ignore_loglevel sysrq_always_enabled panic=10 earlyprintk=ttyS0,115200 console=ttyS0,115200 vga=normal nokalsr nokaslr panic_on_warn apic=debug cma=0 psi=no slub_debug=UP movable_nodemask=0xc cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1 rw
[    0.804437] sysrq: sysrq always enabled.
[    0.805390] Booting kernel: `' invalid for parameter `panic_on_warn'
[    0.806938] Unknown kernel command line parameters "sched_debug nokalsr nokaslr vga=normal psi=no movable_nodemask=0xc", will be passed to user space.
[    0.811442] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.818680] stackdepot hash table entries: 1048576 (order: 11, 8388608 bytes, linear)
[    0.820322] software IO TLB: area num 4.
[    0.980984] Memory: 584380K/4193780K available (26635K kernel code, 11211K rwdata, 9112K rodata, 3244K init, 8224K bss, 1038280K reserved, 0K cma-reserved)
[    0.983825] **********************************************************
[    0.985139] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
[    0.986470] **                                                      **
[    0.987781] ** This system shows unhashed kernel memory addresses   **
[    0.989093] ** via the console, logs, and other interfaces. This    **
[    0.990409] ** might reduce the security of your system.            **
[    0.991713] **                                                      **
[    0.993030] ** If you see this message and you are not debugging    **
[    0.994348] ** the kernel, report this immediately to your system   **
[    0.995664] ** administrator!                                       **
[    0.996995] **                                                      **
[    0.998351] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
[    0.999668] **********************************************************
[    1.006007] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=4, Nodes=4
[    1.007483] Kernel/User page tables isolation: enabled
[    1.008641] ftrace: allocating 54576 entries in 214 pages
[    1.037372] ftrace: allocated 214 pages with 5 groups
[    1.040441] Dynamic Preempt: full
[    1.042079] rcu: Preemptible hierarchical RCU implementation.
[    1.043251] rcu: 	RCU restricting CPUs from NR_CPUS=8192 to nr_cpu_ids=4.
[    1.044644] 	Trampoline variant of Tasks RCU enabled.
[    1.045676] 	Rude variant of Tasks RCU enabled.
[    1.046588] 	Tracing variant of Tasks RCU enabled.
[    1.047585] rcu: RCU calculated value of scheduler-enlistment delay is 100 jiffies.
[    1.049141] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=4
[    1.137210] NR_IRQS: 524544, nr_irqs: 456, preallocated irqs: 16
[    1.139588] rcu: srcu_init: Setting srcu_struct sizes based on contention.
[    1.141346] kfence: initialized - using 2097152 bytes for 255 objects at 0xffff888136c00000-0xffff888136e00000
[    1.150829] Console: colour VGA+ 80x25
[    1.151652] printk: console [ttyS0] enabled
[    1.153388] printk: bootconsole [earlyser0] disabled
[    1.155749] mempolicy: Enabling automatic NUMA balancing. Configure with numa_balancing= or the kernel.numa_balancing sysctl
[    1.158085] ACPI: Core revision 20220331
[    1.160377] clocksource: hpet: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 19112604467 ns
[    1.162468] APIC: Switch to symmetric I/O mode setup
[    1.163943] x2apic enabled
[    1.164951] Switched APIC routing to physical x2apic.
[    1.166048] kvm-guest: setup PV IPIs
[    1.166872] masked ExtINT on CPU#0
[    1.168960] ENABLING IO-APIC IRQs
[    1.169750] init IO_APIC IRQs
[    1.170382]  apic 0 pin 0 not connected
[    1.171268] IOAPIC[0]: Preconfigured routing entry (0-1 -> IRQ 1 Level:0 ActiveLow:0)
[    1.172958] IOAPIC[0]: Preconfigured routing entry (0-2 -> IRQ 0 Level:0 ActiveLow:0)
[    1.174648] IOAPIC[0]: Preconfigured routing entry (0-3 -> IRQ 3 Level:0 ActiveLow:0)
[    1.176306] IOAPIC[0]: Preconfigured routing entry (0-4 -> IRQ 4 Level:0 ActiveLow:0)
[    1.178010] IOAPIC[0]: Preconfigured routing entry (0-5 -> IRQ 5 Level:1 ActiveLow:0)
[    1.179698] IOAPIC[0]: Preconfigured routing entry (0-6 -> IRQ 6 Level:0 ActiveLow:0)
[    1.181359] IOAPIC[0]: Preconfigured routing entry (0-7 -> IRQ 7 Level:0 ActiveLow:0)
[    1.183058] IOAPIC[0]: Preconfigured routing entry (0-8 -> IRQ 8 Level:0 ActiveLow:0)
[    1.184741] IOAPIC[0]: Preconfigured routing entry (0-9 -> IRQ 9 Level:1 ActiveLow:0)
[    1.186415] IOAPIC[0]: Preconfigured routing entry (0-10 -> IRQ 10 Level:1 ActiveLow:0)
[    1.188130] IOAPIC[0]: Preconfigured routing entry (0-11 -> IRQ 11 Level:1 ActiveLow:0)
[    1.189882] IOAPIC[0]: Preconfigured routing entry (0-12 -> IRQ 12 Level:0 ActiveLow:0)
[    1.191590] IOAPIC[0]: Preconfigured routing entry (0-13 -> IRQ 13 Level:0 ActiveLow:0)
[    1.193276] IOAPIC[0]: Preconfigured routing entry (0-14 -> IRQ 14 Level:0 ActiveLow:0)
[    1.195044] IOAPIC[0]: Preconfigured routing entry (0-15 -> IRQ 15 Level:0 ActiveLow:0)
[    1.196686]  apic 0 pin 16 not connected
[    1.197496]  apic 0 pin 17 not connected
[    1.198303]  apic 0 pin 18 not connected
[    1.199115]  apic 0 pin 19 not connected
[    1.199930]  apic 0 pin 20 not connected
[    1.200752]  apic 0 pin 21 not connected
[    1.201566]  apic 0 pin 22 not connected
[    1.202373]  apic 0 pin 23 not connected
[    1.203325] ..TIMER: vector=0x30 apic1=0 pin1=2 apic2=-1 pin2=-1
[    1.204615] clocksource: tsc-early: mask: 0xffffffffffffffff max_cycles: 0x26d349e8249, max_idle_ns: 440795288087 ns
[    1.206809] Calibrating delay loop (skipped) preset value.. 5387.01 BogoMIPS (lpj=2693508)
[    1.207810] pid_max: default: 32768 minimum: 301
[    1.210131] LSM: Security Framework initializing
[    1.211167] Yama: becoming mindful.
[    1.212013] SELinux:  Initializing.
[    1.212812] SELinux: CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE is non-zero.  This is deprecated and will be rejected in a future kernel release.
[    1.213810] SELinux: https://github.com/SELinuxProject/selinux-kernel/wiki/DEPRECATE-checkreqprot
[    1.221115] Dentry cache hash table entries: 524288 (order: 10, 4194304 bytes, vmalloc)
[    1.224286] Inode-cache hash table entries: 262144 (order: 9, 2097152 bytes, vmalloc)
[    1.225148] Mount-cache hash table entries: 8192 (order: 4, 65536 bytes, vmalloc)
[    1.225965] Mountpoint-cache hash table entries: 8192 (order: 4, 65536 bytes, vmalloc)
[    1.231639] Disabling cpuset control group subsystem in v1 mounts
[    1.231969] Disabling cpu control group subsystem in v1 mounts
[    1.232832] Disabling cpuacct control group subsystem in v1 mounts
[    1.233841] Disabling io control group subsystem in v1 mounts
[    1.235361] Disabling memory control group subsystem in v1 mounts
[    1.235968] Disabling devices control group subsystem in v1 mounts
[    1.236879] Disabling freezer control group subsystem in v1 mounts
[    1.237867] Disabling net_cls control group subsystem in v1 mounts
[    1.238872] Disabling perf_event control group subsystem in v1 mounts
[    1.239847] Disabling net_prio control group subsystem in v1 mounts
[    1.240970] Disabling hugetlb control group subsystem in v1 mounts
[    1.241851] Disabling pids control group subsystem in v1 mounts
[    1.242887] Disabling rdma control group subsystem in v1 mounts
[    1.245404] x86/cpu: User Mode Instruction Prevention (UMIP) activated
[    1.245995] Last level iTLB entries: 4KB 0, 2MB 0, 4MB 0
[    1.246808] Last level dTLB entries: 4KB 0, 2MB 0, 4MB 0, 1GB 0
[    1.247835] Spectre V1 : Mitigation: usercopy/swapgs barriers and __user pointer sanitization
[    1.248819] Spectre V2 : Mitigation: Retpolines
[    1.249808] Spectre V2 : Spectre v2 / SpectreRSB mitigation: Filling RSB on context switch
[    1.250816] Spectre V2 : Spectre v2 / SpectreRSB : Filling RSB on VMEXIT
[    1.251808] Speculative Store Bypass: Vulnerable
[    1.252829] MDS: Vulnerable: Clear CPU buffers attempted, no microcode
[    1.253808] MMIO Stale Data: Unknown: No mitigations
[    1.306764] Freeing SMP alternatives memory: 48K
[    1.309040] smpboot: CPU0: Intel(R) Xeon(R) CPU E5-2680 0 @ 2.70GHz (family: 0x6, model: 0x2d, stepping: 0x7)
[    1.312655] cblist_init_generic: Setting adjustable number of callback queues.
[    1.312809] cblist_init_generic: Setting shift to 2 and lim to 1.
[    1.314066] cblist_init_generic: Setting shift to 2 and lim to 1.
[    1.315103] cblist_init_generic: Setting shift to 2 and lim to 1.
[    1.316083] Performance Events: SandyBridge events, full-width counters, Intel PMU driver.
[    1.316821] ... version:                2
[    1.317658] ... bit width:              48
[    1.317811] ... generic registers:      4
[    1.318680] ... value mask:             0000ffffffffffff
[    1.318811] ... max period:             00007fffffffffff
[    1.319820] ... fixed-purpose events:   3
[    1.320636] ... event mask:             000000070000000f
[    1.321718] rcu: Hierarchical SRCU implementation.
[    1.321810] rcu: 	Max phase no-delay instances is 400.
[    1.329606] smp: Bringing up secondary CPUs ...
[    1.331629] x86: Booting SMP configuration:
[    1.331821] .... node  #0, CPUs:      #1
[    0.060799] masked ExtINT on CPU#1
[    0.060799] smpboot: CPU 1 Converting physical 0 to logical die 1

[    1.337812] .... node  #1, CPUs:   #2
[    0.060799] masked ExtINT on CPU#2
[    0.060799] smpboot: CPU 2 Converting physical 0 to logical die 2
[    1.344039]  #3
[    0.060799] masked ExtINT on CPU#3
[    0.060799] smpboot: CPU 3 Converting physical 0 to logical die 3
[    1.347914] smp: Brought up 4 nodes, 4 CPUs
[    1.348826] smpboot: Max logical packages: 4
[    1.349707] smpboot: Total of 4 processors activated (21548.06 BogoMIPS)
[    1.357446] node 0 deferred pages initialised in 4ms
[    1.376022] node 1 deferred pages initialised in 21ms
[    1.388730] node 2 deferred pages initialised in 33ms
[    1.390457] node 3 deferred pages initialised in 32ms
[    1.392112] devtmpfs: initialized
[    1.394446] x86/mm: Memory block size: 128MB
[    1.423600] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 1911260446275000 ns
[    1.425902] futex hash table entries: 1024 (order: 4, 65536 bytes, vmalloc)
[    1.427833] pinctrl core: initialized pinctrl subsystem
[    1.442118] NET: Registered PF_NETLINK/PF_ROUTE protocol family
[    1.446100] DMA: preallocated 512 KiB GFP_KERNEL pool for atomic allocations
[    1.447944] DMA: preallocated 512 KiB GFP_KERNEL|GFP_DMA pool for atomic allocations
[    1.449930] DMA: preallocated 512 KiB GFP_KERNEL|GFP_DMA32 pool for atomic allocations
[    1.451089] audit: initializing netlink subsys (disabled)
[    1.453177] audit: type=2000 audit(1661955939.416:1): state=initialized audit_enabled=0 res=1
[    1.455396] thermal_sys: Registered thermal governor 'fair_share'
[    1.455402] thermal_sys: Registered thermal governor 'bang_bang'
[    1.455802] thermal_sys: Registered thermal governor 'step_wise'
[    1.457812] thermal_sys: Registered thermal governor 'user_space'
[    1.460199] cpuidle: using governor menu
[    1.462338] acpiphp: ACPI Hot Plug PCI Controller Driver version: 0.5
[    1.465802] PCI: Using configuration type 1 for base access
[    1.467042] core: PMU erratum BJ122, BV98, HSD29 workaround disabled, HT off
[    1.552652] kprobes: kprobe jump-optimization is enabled. All kprobes are optimized if possible.
[    1.557946] HugeTLB: registered 1.00 GiB page size, pre-allocated 0 pages
[    1.558811] HugeTLB: 16380 KiB vmemmap can be freed for a 1.00 GiB page
[    1.560812] HugeTLB: registered 2.00 MiB page size, pre-allocated 0 pages
[    1.561809] HugeTLB: 28 KiB vmemmap can be freed for a 2.00 MiB page
[    1.577836] cryptd: max_cpu_qlen set to 1000
[    1.604830] raid6: sse2x4   gen()  7627 MB/s
[    1.622221] raid6: sse2x2   gen()  5874 MB/s
[    1.638923] raid6: sse2x1   gen()  3493 MB/s
[    1.639786] raid6: using algorithm sse2x4 gen() 7627 MB/s
[    1.657003] raid6: .... xor() 4955 MB/s, rmw enabled
[    1.657824] raid6: using ssse3x2 recovery algorithm
[    1.660073] ACPI: Added _OSI(Module Device)
[    1.661812] ACPI: Added _OSI(Processor Device)
[    1.662754] ACPI: Added _OSI(3.0 _SCP Extensions)
[    1.662811] ACPI: Added _OSI(Processor Aggregator Device)
[    1.745802] ACPI: 1 ACPI AML tables successfully acquired and loaded
[    1.787024] ACPI: Interpreter enabled
[    1.788219] ACPI: PM: (supports S0 S3 S4 S5)
[    1.789820] ACPI: Using IOAPIC for interrupt routing
[    1.791145] PCI: Using host bridge windows from ACPI; if necessary, use "pci=nocrs" and report a bug
[    1.793811] PCI: Using E820 reservations for host bridge windows
[    1.799652] ACPI: Enabled 2 GPEs in block 00 to 0F
[    1.961301] ACPI: PCI Root Bridge [PCI0] (domain 0000 [bus 00-ff])
[    1.961889] acpi PNP0A03:00: _OSC: OS supports [ASPM ClockPM Segments MSI HPX-Type3]
[    1.963821] acpi PNP0A03:00: _OSC: not requesting OS control; OS requires [ExtendedConfig ASPM ClockPM MSI]
[    1.966393] acpi PNP0A03:00: fail to add MMCONFIG information, can't access extended PCI configuration space under this bridge.
[    1.985023] acpiphp: Slot [3] registered
[    1.986344] acpiphp: Slot [4] registered
[    1.987372] acpiphp: Slot [5] registered
[    1.989429] acpiphp: Slot [6] registered
[    1.990388] acpiphp: Slot [7] registered
[    1.991350] acpiphp: Slot [8] registered
[    1.993395] acpiphp: Slot [9] registered
[    1.994414] acpiphp: Slot [10] registered
[    1.996377] acpiphp: Slot [11] registered
[    1.997365] acpiphp: Slot [12] registered
[    1.998367] acpiphp: Slot [13] registered
[    2.000381] acpiphp: Slot [14] registered
[    2.001378] acpiphp: Slot [15] registered
[    2.002337] acpiphp: Slot [16] registered
[    2.004377] acpiphp: Slot [17] registered
[    2.005434] acpiphp: Slot [18] registered
[    2.006339] acpiphp: Slot [19] registered
[    2.008389] acpiphp: Slot [20] registered
[    2.009347] acpiphp: Slot [21] registered
[    2.010406] acpiphp: Slot [22] registered
[    2.012341] acpiphp: Slot [23] registered
[    2.013368] acpiphp: Slot [24] registered
[    2.015362] acpiphp: Slot [25] registered
[    2.016400] acpiphp: Slot [26] registered
[    2.017350] acpiphp: Slot [27] registered
[    2.019399] acpiphp: Slot [28] registered
[    2.020336] acpiphp: Slot [29] registered
[    2.021423] acpiphp: Slot [30] registered
[    2.023360] acpiphp: Slot [31] registered
[    2.024100] PCI host bridge to bus 0000:00
[    2.024819] pci_bus 0000:00: Unknown NUMA node; performance will be reduced
[    2.026845] pci_bus 0000:00: root bus resource [io  0x0000-0x0cf7 window]
[    2.027852] pci_bus 0000:00: root bus resource [io  0x0d00-0xffff window]
[    2.029855] pci_bus 0000:00: root bus resource [mem 0x000a0000-0x000bffff window]
[    2.031842] pci_bus 0000:00: root bus resource [mem 0xc0000000-0xfebfffff window]
[    2.033834] pci_bus 0000:00: root bus resource [mem 0x140000000-0x1bfffffff window]
[    2.035845] pci_bus 0000:00: root bus resource [bus 00-ff]
[    2.037310] pci 0000:00:00.0: [8086:1237] type 00 class 0x060000
[    2.043007] pci 0000:00:01.0: [8086:7000] type 00 class 0x060100
[    2.047811] pci 0000:00:01.1: [8086:7010] type 00 class 0x010180
[    2.053211] pci 0000:00:01.1: reg 0x20: [io  0xc080-0xc08f]
[    2.055219] pci 0000:00:01.1: legacy IDE quirk: reg 0x10: [io  0x01f0-0x01f7]
[    2.056812] pci 0000:00:01.1: legacy IDE quirk: reg 0x14: [io  0x03f6]
[    2.057818] pci 0000:00:01.1: legacy IDE quirk: reg 0x18: [io  0x0170-0x0177]
[    2.059817] pci 0000:00:01.1: legacy IDE quirk: reg 0x1c: [io  0x0376]
[    2.062012] pci 0000:00:01.3: [8086:7113] type 00 class 0x068000
[    2.064584] pci 0000:00:01.3: quirk: [io  0x0600-0x063f] claimed by PIIX4 ACPI
[    2.065879] pci 0000:00:01.3: quirk: [io  0x0700-0x070f] claimed by PIIX4 SMB
[    2.070217] pci 0000:00:02.0: [1234:1111] type 00 class 0x030000
[    2.073619] pci 0000:00:02.0: reg 0x10: [mem 0xfd000000-0xfdffffff pref]
[    2.077871] pci 0000:00:02.0: reg 0x18: [mem 0xfebf0000-0xfebf0fff]
[    2.084415] pci 0000:00:02.0: reg 0x30: [mem 0xfebe0000-0xfebeffff pref]
[    2.086567] pci 0000:00:02.0: Video device with shadowed ROM at [mem 0x000c0000-0x000dffff]
[    2.092651] pci 0000:00:03.0: [8086:100e] type 00 class 0x020000
[    2.094811] pci 0000:00:03.0: reg 0x10: [mem 0xfebc0000-0xfebdffff]
[    2.096790] pci 0000:00:03.0: reg 0x14: [io  0xc000-0xc03f]
[    2.103288] pci 0000:00:03.0: reg 0x30: [mem 0xfeb80000-0xfebbffff pref]
[    2.108452] pci 0000:00:04.0: [1af4:1009] type 00 class 0x000200
[    2.110811] pci 0000:00:04.0: reg 0x10: [io  0xc040-0xc07f]
[    2.113812] pci 0000:00:04.0: reg 0x14: [mem 0xfebf1000-0xfebf1fff]
[    2.118812] pci 0000:00:04.0: reg 0x20: [mem 0xfe000000-0xfe003fff 64bit pref]
[    2.127768] pci 0000:00:05.0: [8086:25ab] type 00 class 0x088000
[    2.129621] pci 0000:00:05.0: reg 0x10: [mem 0xfebf2000-0xfebf200f]
[    2.163360] ACPI: PCI: Interrupt link LNKA configured for IRQ 10
[    2.169295] ACPI: PCI: Interrupt link LNKB configured for IRQ 10
[    2.175248] ACPI: PCI: Interrupt link LNKC configured for IRQ 11
[    2.180246] ACPI: PCI: Interrupt link LNKD configured for IRQ 11
[    2.183617] ACPI: PCI: Interrupt link LNKS configured for IRQ 9
[    2.204866] iommu: Default domain type: Translated 
[    2.205811] iommu: DMA domain TLB invalidation policy: lazy mode 
[    2.211134] SCSI subsystem initialized
[    2.213019] libata version 3.00 loaded.
[    2.214656] ACPI: bus type USB registered
[    2.215580] usbcore: registered new interface driver usbfs
[    2.217154] usbcore: registered new interface driver hub
[    2.218979] usbcore: registered new device driver usb
[    2.221108] pps_core: LinuxPPS API ver. 1 registered
[    2.221810] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
[    2.223967] PTP clock support registered
[    2.226000] EDAC MC: Ver: 3.0.0
[    2.233655] NetLabel: Initializing
[    2.233816] NetLabel:  domain hash size = 128
[    2.234694] NetLabel:  protocols = UNLABELED CIPSOv4 CALIPSO
[    2.236385] NetLabel:  unlabeled traffic allowed by default
[    2.237835] PCI: Using ACPI for IRQ routing
[    2.238699] PCI: pci_cache_line_size set to 64 bytes
[    2.240033] e820: reserve RAM buffer [mem 0x0009fc00-0x0009ffff]
[    2.240923] e820: reserve RAM buffer [mem 0xbffdf000-0xbfffffff]
[    2.243954] pci 0000:00:02.0: vgaarb: setting as boot VGA device
[    2.244802] pci 0000:00:02.0: vgaarb: bridge control possible
[    2.244802] pci 0000:00:02.0: vgaarb: VGA device added: decodes=io+mem,owns=io+mem,locks=none
[    2.247816] vgaarb: loaded
[    2.249620] hpet0: at MMIO 0xfed00000, IRQs 2, 8, 0
[    2.250810] hpet0: 3 comparators, 64-bit 100.000000 MHz counter
[    2.257281] clocksource: Switched to clocksource kvm-clock
[    2.882280] VFS: Disk quotas dquot_6.6.0
[    2.883445] VFS: Dquot-cache hash table entries: 512 (order 0, 4096 bytes)
[    2.888015] pnp: PnP ACPI init
[    2.892970] pnp 00:03: [dma 2]
[    2.907746] pnp: PnP ACPI: found 6 devices
[    2.964680] clocksource: acpi_pm: mask: 0xffffff max_cycles: 0xffffff, max_idle_ns: 2085701024 ns
[    2.968309] NET: Registered PF_INET protocol family
[    2.970506] IP idents hash table entries: 65536 (order: 7, 524288 bytes, vmalloc)
[    2.977543] tcp_listen_portaddr_hash hash table entries: 2048 (order: 3, 32768 bytes, vmalloc)
[    2.979521] Table-perturb hash table entries: 65536 (order: 6, 262144 bytes, vmalloc)
[    2.981473] TCP established hash table entries: 32768 (order: 6, 262144 bytes, vmalloc)
[    2.983980] TCP bind hash table entries: 32768 (order: 8, 1048576 bytes, vmalloc)
[    2.986707] TCP: Hash tables configured (established 32768 bind 32768)
[    2.988876] UDP hash table entries: 2048 (order: 4, 65536 bytes, vmalloc)
[    2.990459] UDP-Lite hash table entries: 2048 (order: 4, 65536 bytes, vmalloc)
[    2.993357] NET: Registered PF_UNIX/PF_LOCAL protocol family
[    3.000362] RPC: Registered named UNIX socket transport module.
[    3.001961] RPC: Registered udp transport module.
[    3.003371] RPC: Registered tcp transport module.
[    3.004753] RPC: Registered tcp NFSv4.1 backchannel transport module.
[    3.006648] NET: Registered PF_XDP protocol family
[    3.008121] pci_bus 0000:00: resource 4 [io  0x0000-0x0cf7 window]
[    3.009458] pci_bus 0000:00: resource 5 [io  0x0d00-0xffff window]
[    3.010722] pci_bus 0000:00: resource 6 [mem 0x000a0000-0x000bffff window]
[    3.012113] pci_bus 0000:00: resource 7 [mem 0xc0000000-0xfebfffff window]
[    3.013511] pci_bus 0000:00: resource 8 [mem 0x140000000-0x1bfffffff window]
[    3.016088] pci 0000:00:01.0: PIIX3: Enabling Passive Release
[    3.017323] pci 0000:00:00.0: Limiting direct PCI/PCI transfers
[    3.018714] PCI: CLS 0 bytes, default 64
[    3.020689] PCI-DMA: Using software bounce buffering for IO (SWIOTLB)
[    3.022021] software IO TLB: mapped [mem 0x00000000bae00000-0x00000000bee00000] (64MB)
[    3.023936] clocksource: tsc: mask: 0xffffffffffffffff max_cycles: 0x26d349e8249, max_idle_ns: 440795288087 ns
[    3.042795] Initialise system trusted keyrings
[    3.043849] Key type blacklist registered
[    3.047402] workingset: timestamp_bits=36 max_order=20 bucket_order=0
[    3.159567] zbud: loaded
[    3.194654] 9p: Installing v9fs 9p2000 file system support
[    3.212129] NET: Registered PF_ALG protocol family
[    3.213186] xor: automatically using best checksumming function   avx       
[    3.214614] Key type asymmetric registered
[    3.215482] Asymmetric key parser 'x509' registered
[    3.216974] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 247)
[    3.219335] io scheduler mq-deadline registered
[    3.220318] io scheduler kyber registered
[    3.222748] io scheduler bfq registered
[    3.227900] atomic64_test: passed for x86-64 platform with CX8 and with SSE
[    3.235426] shpchp: Standard Hot Plug PCI Controller Driver version: 0.4
[    3.238991] input: Power Button as /devices/LNXSYSTM:00/LNXPWRBN:00/input/input0
[    3.242654] ACPI: button: Power Button [PWRF]
[    3.252396] ERST DBG: ERST support is disabled.
[    6.597399] ACPI: \_SB_.LNKD: Enabled at IRQ 11
[    6.602722] Serial: 8250/16550 driver, 4 ports, IRQ sharing enabled
[    6.604436] 00:05: ttyS0 at I/O 0x3f8 (irq = 4, base_baud = 115200) is a 16550A
[    6.612464] Non-volatile memory driver v1.3
[    6.624288] rdac: device handler registered
[    6.627027] hp_sw: device handler registered
[    6.628544] emc: device handler registered
[    6.629908] alua: device handler registered
[    6.630664] st: Version 20160209, fixed bufsize 32768, s/g segs 256
[    6.633930] ata_piix 0000:00:01.1: version 2.13
[    6.643512] scsi host0: ata_piix
[    6.648124] scsi host1: ata_piix
[    6.650026] ata1: PATA max MWDMA2 cmd 0x1f0 ctl 0x3f6 bmdma 0xc080 irq 14
[    6.651583] ata2: PATA max MWDMA2 cmd 0x170 ctl 0x376 bmdma 0xc088 irq 15
[    6.658983] e1000: Intel(R) PRO/1000 Network Driver
[    6.659919] e1000: Copyright (c) 1999-2006 Intel Corporation.
[    6.809005] ata2: found unknown device (class 0)
[    6.811464] ata2.00: ATAPI: QEMU DVD-ROM, 2.5+, max UDMA/100
[    6.812782] ata1.00: ATA-7: QEMU HARDDISK, 2.5+, max UDMA/100
[    6.813779] ata1.00: 20971520 sectors, multi 16: LBA48 
[    6.814682] ata1.01: ATA-7: QEMU HARDDISK, 2.5+, max UDMA/100
[    6.815660] ata1.01: 20971520 sectors, multi 16: LBA48 
[    6.819205] scsi 0:0:0:0: Direct-Access     ATA      QEMU HARDDISK    2.5+ PQ: 0 ANSI: 5
[    6.823395] sd 0:0:0:0: Attached scsi generic sg0 type 0
[    6.825138] sd 0:0:0:0: [sda] 20971520 512-byte logical blocks: (10.7 GB/10.0 GiB)
[    6.825418] scsi 0:0:1:0: Direct-Access     ATA      QEMU HARDDISK    2.5+ PQ: 0 ANSI: 5
[    6.826526] sd 0:0:0:0: [sda] Write Protect is off
[    6.828684] sd 0:0:0:0: [sda] Mode Sense: 00 3a 00 00
[    6.829701] sd 0:0:0:0: [sda] Write cache: enabled, read cache: enabled, doesn't support DPO or FUA
[    6.832037] scsi 0:0:1:0: Attached scsi generic sg1 type 0
[    6.832046] sd 0:0:0:0: [sda] Preferred minimum I/O size 512 bytes
[    6.834644] sd 0:0:1:0: [sdb] 20971520 512-byte logical blocks: (10.7 GB/10.0 GiB)
[    6.836676] sd 0:0:1:0: [sdb] Write Protect is off
[    6.837678] scsi 1:0:0:0: CD-ROM            QEMU     QEMU DVD-ROM     2.5+ PQ: 0 ANSI: 5
[    6.839412] sd 0:0:1:0: [sdb] Mode Sense: 00 3a 00 00
[    6.841524] sd 0:0:1:0: [sdb] Write cache: enabled, read cache: enabled, doesn't support DPO or FUA
[    6.843535] sd 0:0:1:0: [sdb] Preferred minimum I/O size 512 bytes
[    6.851297] sd 0:0:0:0: [sda] Attached SCSI disk
[    6.857693] sd 0:0:1:0: [sdb] Attached SCSI disk
[    6.867586] scsi 1:0:0:0: Attached scsi generic sg2 type 5
[   10.085509] ACPI: \_SB_.LNKC: Enabled at IRQ 10
[   10.421175] e1000 0000:00:03.0 eth0: (PCI:33MHz:32-bit) 52:54:00:12:34:56
[   10.422517] e1000 0000:00:03.0 eth0: Intel(R) PRO/1000 Network Connection
[   10.424040] e1000e: Intel(R) PRO/1000 Network Driver
[   10.424945] e1000e: Copyright(c) 1999 - 2015 Intel Corporation.
[   10.426236] igb: Intel(R) Gigabit Ethernet Network Driver
[   10.427179] igb: Copyright (c) 2007-2014 Intel Corporation.
[   10.428357] ixgbe: Intel(R) 10 Gigabit PCI Express Network Driver
[   10.429378] ixgbe: Copyright (c) 1999-2016 Intel Corporation.
[   10.431518] i40e: Intel(R) Ethernet Connection XL710 Network Driver
[   10.432649] i40e: Copyright (c) 2013 - 2019 Intel Corporation.
[   10.435679] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
[   10.436889] ehci-pci: EHCI PCI platform driver
[   10.437872] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
[   10.439015] ohci-pci: OHCI PCI platform driver
[   10.439954] uhci_hcd: USB Universal Host Controller Interface driver
[   10.442976] i8042: PNP: PS/2 Controller [PNP0303:KBD,PNP0f13:MOU] at 0x60,0x64 irq 1,12
[   10.445980] serio: i8042 KBD port at 0x60,0x64 irq 1
[   10.447522] serio: i8042 AUX port at 0x60,0x64 irq 12
[   10.449790] mousedev: PS/2 mouse device common for all mice
[   10.453048] rtc_cmos 00:00: RTC can wake from S4
[   10.453321] input: AT Translated Set 2 keyboard as /devices/platform/i8042/serio0/input/input1
[   10.457701] rtc_cmos 00:00: registered as rtc0
[   10.458753] rtc_cmos 00:00: setting system clock to 2022-08-31T14:25:48 UTC (1661955948)
[   10.459978] input: VirtualPS/2 VMware VMMouse as /devices/platform/i8042/serio1/input/input4
[   10.460786] rtc_cmos 00:00: alarms up to one day, y3k, 114 bytes nvram, hpet irqs
[   10.463950] input: VirtualPS/2 VMware VMMouse as /devices/platform/i8042/serio1/input/input3
[   10.465609] i6300ESB timer 0000:00:05.0: initialized. heartbeat=30 sec (nowayout=0)
[   10.467542] iTCO_vendor_support: vendor-support=0
[   10.469301] intel_pstate: CPU model not supported
[   10.479245] hid: raw HID events driver (C) Jiri Kosina
[   10.481408] usbcore: registered new interface driver usbhid
[   10.482891] usbhid: USB HID core driver
[   10.484045] drop_monitor: Initializing network drop monitor service
[   10.486389] ipip: IPv4 and MPLS over IPv4 tunneling driver
[   10.491133] gre: GRE over IPv4 demultiplexor driver
[   10.492678] ip_gre: GRE over IPv4 tunneling driver
[   10.502556] Initializing XFRM netlink socket
[   10.509703] NET: Registered PF_INET6 protocol family
[   10.520748] Segment Routing with IPv6
[   10.522117] In-situ OAM (IOAM) with IPv6
[   10.523601] NET: Registered PF_PACKET protocol family
[   10.526610] 9pnet: Installing 9P2000 support
[   10.532481] mpls_gso: MPLS GSO support
[   10.540653] IPI shorthand broadcast: enabled
[   10.541633] ... APIC ID:      00000000 (0)
[   10.542524] ... APIC VERSION: 00050014
[   10.542625] 0000000000000000000000000000000000000000000000000000000000000000
[   10.542625] 0000000000000000000000000000000000000000000000000000000000000000
[   10.542625] 0000000000000000000000000000000000000000000000000000000000000000

[   10.548077] number of MP IRQ sources: 15.
[   10.548968] number of IO-APIC #0 registers: 24.
[   10.549938] testing the IO APIC.......................
[   10.551070] IO APIC #0......
[   10.551693] .... register #00: 00000000
[   10.552540] .......    : physical APIC id: 00
[   10.553441] .......    : Delivery Type: 0
[   10.554272] .......    : LTS          : 0
[   10.555120] .... register #01: 00170011
[   10.555916] .......     : max redirection entries: 17
[   10.556959] .......     : PRQ implemented: 0
[   10.557858] .......     : IO APIC version: 11
[   10.558752] .... register #02: 00000000
[   10.559543] .......     : arbitration: 00
[   10.560384] .... IRQ redirection table:
[   10.561183] IOAPIC 0:
[   10.561702]  pin00, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.563339]  pin01, enabled , edge , high, V(23), IRR(0), S(0), physical, D(0001), M(0)
[   10.564991]  pin02, enabled , edge , high, V(30), IRR(0), S(0), physical, D(0000), M(0)
[   10.566618]  pin03, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.568269]  pin04, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.569894]  pin05, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.571522]  pin06, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.573179]  pin07, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.574812]  pin08, enabled , edge , high, V(23), IRR(0), S(0), physical, D(0000), M(0)
[   10.576468]  pin09, enabled , level, high, V(21), IRR(0), S(0), physical, D(0001), M(0)
[   10.578110]  pin0a, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.579738]  pin0b, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.581376]  pin0c, enabled , edge , high, V(22), IRR(0), S(0), physical, D(0000), M(0)
[   10.582997]  pin0d, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.584630]  pin0e, enabled , edge , high, V(21), IRR(0), S(0), physical, D(0000), M(0)
[   10.586255]  pin0f, enabled , edge , high, V(22), IRR(0), S(0), physical, D(0001), M(0)
[   10.587891]  pin10, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.589525]  pin11, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.591159]  pin12, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.592826]  pin13, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.594458]  pin14, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.596083]  pin15, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.597722]  pin16, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.599341]  pin17, disabled, edge , high, V(00), IRR(0), S(0), physical, D(0000), M(0)
[   10.600967] IRQ to pin mappings:
[   10.601638] IRQ0 -> 0:2
[   10.602174] IRQ1 -> 0:1
[   10.602750] IRQ3 -> 0:3
[   10.603413] IRQ4 -> 0:4
[   10.604041] IRQ5 -> 0:5
[   10.604681] IRQ6 -> 0:6
[   10.605280] IRQ7 -> 0:7
[   10.605876] IRQ8 -> 0:8
[   10.606469] IRQ9 -> 0:9
[   10.607065] IRQ10 -> 0:10
[   10.607681] IRQ11 -> 0:11
[   10.608319] IRQ12 -> 0:12
[   10.608952] IRQ13 -> 0:13
[   10.609576] IRQ14 -> 0:14
[   10.610207] IRQ15 -> 0:15
[   10.610856] .................................... done.
[   10.612243] AVX version of gcm_enc/dec engaged.
[   10.613395] AES CTR mode by8 optimization enabled
[   10.619348] sched_clock: Marking stable (10559131988, 59799912)->(10788362246, -169430346)
[   10.627155] registered taskstats version 1
[   10.628625] Loading compiled-in X.509 certificates
[   10.635577] Loaded X.509 cert 'Build time autogenerated kernel key: 29579404aca54ffde8d80f2b63dab776e63e62f1'
[   10.641626] Key type .fscrypt registered
[   10.642514] Key type fscrypt-provisioning registered
[   10.659750] Btrfs loaded, crc32c=crc32c-generic, zoned=yes, fsverity=no
[   10.668522] Key type encrypted registered
[   10.669632] ima: No TPM chip found, activating TPM-bypass!
[   10.671150] ima: Allocated hash algorithm: sha1
[   10.672436] ima: No architecture policies found
[   10.674016] evm: Initialising EVM extended attributes:
[   10.675364] evm: security.selinux
[   10.676208] evm: security.SMACK64 (disabled)
[   10.677244] evm: security.SMACK64EXEC (disabled)
[   10.678348] evm: security.SMACK64TRANSMUTE (disabled)
[   10.679470] evm: security.SMACK64MMAP (disabled)
[   10.680474] evm: security.apparmor
[   10.681181] evm: security.ima
[   10.681788] evm: security.capability
[   10.682529] evm: HMAC attrs: 0x1
[   10.724970] TAP version 14
[   10.725542] 1..4
[   10.726233]     # Subtest: kfence
[   10.726247]     1..25
[   10.727794]     # test_out_of_bounds_read: test_alloc: size=32, gfp=cc0, policy=left, cache=0
[   10.776958] ==================================================================
[   10.778973] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0x114/0x257

[   10.780817] Out-of-bounds read at 0xffff888136cb3fff (1B left of kfence-#89):
[   10.782229]  test_out_of_bounds_read+0x114/0x257
[   10.783157]  kunit_try_run_case+0x8e/0xc0
[   10.783986]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   10.785084]  kthread+0x179/0x1b0
[   10.785762]  ret_from_fork+0x22/0x30

[   10.786810] kfence-#89: 0xffff888136cb4000-0xffff888136cb401f, size=32, cache=kmalloc-32

[   10.788745] allocated by task 180 on cpu 1 at 10.776914s:
[   10.789844]  test_alloc+0x1fb/0x79c
[   10.790557]  test_out_of_bounds_read+0xfd/0x257
[   10.791462]  kunit_try_run_case+0x8e/0xc0
[   10.792305]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   10.793385]  kthread+0x179/0x1b0
[   10.794041]  ret_from_fork+0x22/0x30

[   10.795083] CPU: 1 PID: 180 Comm: kunit_try_catch Tainted: G                 N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   10.797330] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   10.799579] RIP: 0010:test_out_of_bounds_read+0x114/0x257
[   10.800682] Code: 00 00 00 ba c0 0c 00 00 4c 89 f6 4c 89 e7 e8 2a e5 ff ff 48 8d 78 ff 49 89 c7 48 89 7b b0 e8 d4 09 f3 fe 48 8d bd 78 ff ff ff <41> 8a 47 ff e8 74 53 f3 fe 84 c0 75 3b 48 8d 8b 60 ff ff ff 45 31
[   10.804339] RSP: 0000:ffffc900015efde0 EFLAGS: 00010246
[   10.805386] RAX: 0000000000000000 RBX: ffffc900015efea0 RCX: ffffffff825ee88c
[   10.806785] RDX: 1ffff11026d967ff RSI: ffff888136cb4000 RDI: ffffc900015efe40
[   10.808212] RBP: ffffc900015efec8 R08: ffffffff825ed395 R09: ffffea0004db2d07
[   10.809614] R10: fffff940009b65a0 R11: 0000000000000001 R12: ffffc90000647ab8
[   10.810998] R13: 1ffff920002bdfbc R14: 0000000000000020 R15: ffff888136cb4000
[   10.812409] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   10.813991] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   10.815125] CR2: ffff888136cb3fff CR3: 000000000360e001 CR4: 0000000000060ee0
[   10.816558] Call Trace:
[   10.817057]  <TASK>
[   10.817488]  ? test_out_of_bounds_write+0x193/0x193
[   10.818459]  ? preempt_count_add+0x7b/0xd0
[   10.819301]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   10.820237]  ? test_out_of_bounds_write+0x193/0x193
[   10.821213]  ? __lock_text_start+0x8/0x8
[   10.822003]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   10.822884]  ? kunit_try_catch_throw+0x40/0x40
[   10.823778]  kunit_try_run_case+0x8e/0xc0
[   10.824615]  ? kunit_catch_run_case+0x70/0x70
[   10.825492]  ? kunit_try_catch_throw+0x40/0x40
[   10.826381]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   10.827452]  kthread+0x179/0x1b0
[   10.828103]  ? kthread_complete_and_exit+0x20/0x20
[   10.829067]  ret_from_fork+0x22/0x30
[   10.829799]  </TASK>
[   10.830255] ==================================================================
[   10.831772]     # test_out_of_bounds_read: test_alloc: size=32, gfp=cc0, policy=right, cache=0
[   10.984973] ==================================================================
[   10.986406] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0x1a8/0x257

[   10.988174] Out-of-bounds read at 0xffff888136cb9000 (32B right of kfence-#91):
[   10.989635]  test_out_of_bounds_read+0x1a8/0x257
[   10.990559]  kunit_try_run_case+0x8e/0xc0
[   10.991370]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   10.992494]  kthread+0x179/0x1b0
[   10.993168]  ret_from_fork+0x22/0x30

[   10.994252] kfence-#91: 0xffff888136cb8fe0-0xffff888136cb8fff, size=32, cache=kmalloc-32

[   10.996194] allocated by task 180 on cpu 1 at 10.984940s:
[   10.997283]  test_alloc+0x1fb/0x79c
[   10.997987]  test_out_of_bounds_read+0x18f/0x257
[   10.998912]  kunit_try_run_case+0x8e/0xc0
[   10.999721]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   11.000835]  kthread+0x179/0x1b0
[   11.001490]  ret_from_fork+0x22/0x30

[   11.002537] CPU: 1 PID: 180 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   11.004775] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   11.007002] RIP: 0010:test_out_of_bounds_read+0x1a8/0x257
[   11.008070] Code: 02 00 00 00 ba c0 0c 00 00 4c 89 e7 e8 98 e4 ff ff 49 01 c6 49 89 c7 4c 89 f7 4c 89 73 b0 e8 40 09 f3 fe 48 8d bd 78 ff ff ff <41> 8a 06 e8 e1 52 f3 fe 84 c0 75 3b 48 8d 8b 60 ff ff ff 45 31 c0
[   11.011715] RSP: 0000:ffffc900015efde0 EFLAGS: 00010246
[   11.012782] RAX: 0000000000000000 RBX: ffffc900015efea0 RCX: ffffffff825ee920
[   11.014187] RDX: 1ffff11026d97200 RSI: ffff888136cb8fe0 RDI: ffffc900015efe40
[   11.015605] RBP: ffffc900015efec8 R08: ffffffff825ed395 R09: ffffea0004db2e07
[   11.017012] R10: fffff940009b65c0 R11: 0000000000000001 R12: ffffc90000647ab8
[   11.018416] R13: 1ffff920002bdfbc R14: ffff888136cb9000 R15: ffff888136cb8fe0
[   11.019820] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   11.021424] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   11.022546] CR2: ffff888136cb9000 CR3: 000000000360e001 CR4: 0000000000060ee0
[   11.023957] Call Trace:
[   11.024486]  <TASK>
[   11.024918]  ? test_out_of_bounds_write+0x193/0x193
[   11.025886]  ? preempt_count_add+0x7b/0xd0
[   11.026722]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   11.027627]  ? test_out_of_bounds_write+0x193/0x193
[   11.028612]  ? __lock_text_start+0x8/0x8
[   11.029407]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   11.030282]  ? kunit_try_catch_throw+0x40/0x40
[   11.031177]  kunit_try_run_case+0x8e/0xc0
[   11.031981]  ? kunit_catch_run_case+0x70/0x70
[   11.033098]  ? kunit_try_catch_throw+0x40/0x40
[   11.034246]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   11.035632]  kthread+0x179/0x1b0
[   11.036503]  ? kthread_complete_and_exit+0x20/0x20
[   11.037752]  ret_from_fork+0x22/0x30
[   11.038690]  </TASK>
[   11.039283] ==================================================================
[   11.041293]     ok 1 - test_out_of_bounds_read
[   11.041932]     # test_out_of_bounds_read-memcache: setup_test_cache: size=32, ctor=0x0
[   11.045598]     # test_out_of_bounds_read-memcache: test_alloc: size=32, gfp=cc0, policy=left, cache=1
[   11.296918] ==================================================================
[   11.298359] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0x114/0x257

[   11.300127] Out-of-bounds read at 0xffff888136cbdfff (1B left of kfence-#94):
[   11.301559]  test_out_of_bounds_read+0x114/0x257
[   11.302487]  kunit_try_run_case+0x8e/0xc0
[   11.303296]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   11.304384]  kthread+0x179/0x1b0
[   11.305040]  ret_from_fork+0x22/0x30

[   11.306070] kfence-#94: 0xffff888136cbe000-0xffff888136cbe01f, size=32, cache=test

[   11.307857] allocated by task 181 on cpu 1 at 11.296890s:
[   11.308942]  test_alloc+0x1ee/0x79c
[   11.309651]  test_out_of_bounds_read+0xfd/0x257
[   11.310561]  kunit_try_run_case+0x8e/0xc0
[   11.311364]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   11.312464]  kthread+0x179/0x1b0
[   11.313123]  ret_from_fork+0x22/0x30

[   11.314166] CPU: 1 PID: 181 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   11.316428] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   11.318652] RIP: 0010:test_out_of_bounds_read+0x114/0x257
[   11.319734] Code: 00 00 00 ba c0 0c 00 00 4c 89 f6 4c 89 e7 e8 2a e5 ff ff 48 8d 78 ff 49 89 c7 48 89 7b b0 e8 d4 09 f3 fe 48 8d bd 78 ff ff ff <41> 8a 47 ff e8 74 53 f3 fe 84 c0 75 3b 48 8d 8b 60 ff ff ff 45 31
[   11.323396] RSP: 0000:ffffc900015ffde0 EFLAGS: 00010246
[   11.324456] RAX: 0000000000000000 RBX: ffffc900015ffea0 RCX: ffffffff825ee88c
[   11.325853] RDX: 1ffff11026d97bff RSI: ffff888136cbe000 RDI: ffffc900015ffe40
[   11.327268] RBP: ffffc900015ffec8 R08: ffffffff825ed395 R09: ffffea0004db2f87
[   11.328690] R10: fffff940009b65f0 R11: 0000000000000001 R12: ffffc90000647ab8
[   11.330095] R13: 1ffff920002bffbc R14: 0000000000000020 R15: ffff888136cbe000
[   11.331515] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   11.333120] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   11.334264] CR2: ffff888136cbdfff CR3: 000000000360e001 CR4: 0000000000060ee0
[   11.335675] Call Trace:
[   11.336178]  <TASK>
[   11.336626]  ? test_out_of_bounds_write+0x193/0x193
[   11.337600]  ? preempt_count_add+0x7b/0xd0
[   11.338415]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   11.339319]  ? test_out_of_bounds_write+0x193/0x193
[   11.340298]  ? __lock_text_start+0x8/0x8
[   11.341096]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   11.341974]  ? kunit_try_catch_throw+0x40/0x40
[   11.342869]  kunit_try_run_case+0x8e/0xc0
[   11.343678]  ? kunit_catch_run_case+0x70/0x70
[   11.344580]  ? kunit_try_catch_throw+0x40/0x40
[   11.345476]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   11.346563]  kthread+0x179/0x1b0
[   11.347217]  ? kthread_complete_and_exit+0x20/0x20
[   11.348182]  ret_from_fork+0x22/0x30
[   11.348928]  </TASK>
[   11.349380] ==================================================================
[   11.350892]     # test_out_of_bounds_read-memcache: test_alloc: size=32, gfp=cc0, policy=right, cache=1
[   11.920945] ==================================================================
[   11.922438] BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0x1a8/0x257

[   11.924237] Out-of-bounds read at 0xffff888136ccb000 (32B right of kfence-#100):
[   11.925691]  test_out_of_bounds_read+0x1a8/0x257
[   11.926615]  kunit_try_run_case+0x8e/0xc0
[   11.927412]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   11.928494]  kthread+0x179/0x1b0
[   11.929149]  ret_from_fork+0x22/0x30

[   11.930198] kfence-#100: 0xffff888136ccafe0-0xffff888136ccafff, size=32, cache=test

[   11.931990] allocated by task 181 on cpu 1 at 11.920917s:
[   11.933067]  test_alloc+0x1ee/0x79c
[   11.933771]  test_out_of_bounds_read+0x18f/0x257
[   11.934720]  kunit_try_run_case+0x8e/0xc0
[   11.935524]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   11.936630]  kthread+0x179/0x1b0
[   11.937289]  ret_from_fork+0x22/0x30

[   11.938337] CPU: 1 PID: 181 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   11.940596] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   11.942811] RIP: 0010:test_out_of_bounds_read+0x1a8/0x257
[   11.943879] Code: 02 00 00 00 ba c0 0c 00 00 4c 89 e7 e8 98 e4 ff ff 49 01 c6 49 89 c7 4c 89 f7 4c 89 73 b0 e8 40 09 f3 fe 48 8d bd 78 ff ff ff <41> 8a 06 e8 e1 52 f3 fe 84 c0 75 3b 48 8d 8b 60 ff ff ff 45 31 c0
[   11.947502] RSP: 0000:ffffc900015ffde0 EFLAGS: 00010246
[   11.948564] RAX: 0000000000000000 RBX: ffffc900015ffea0 RCX: ffffffff825ee920
[   11.949963] RDX: 1ffff11026d99600 RSI: ffff888136ccafe0 RDI: ffffc900015ffe40
[   11.951365] RBP: ffffc900015ffec8 R08: ffffffff825ed395 R09: ffffea0004db3287
[   11.952778] R10: fffff940009b6650 R11: 0000000000000001 R12: ffffc90000647ab8
[   11.954222] R13: 1ffff920002bffbc R14: ffff888136ccb000 R15: ffff888136ccafe0
[   11.955602] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   11.957209] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   11.958329] CR2: ffff888136ccb000 CR3: 000000000360e001 CR4: 0000000000060ee0
[   11.959737] Call Trace:
[   11.960253]  <TASK>
[   11.960689]  ? test_out_of_bounds_write+0x193/0x193
[   11.961668]  ? preempt_count_add+0x7b/0xd0
[   11.962519]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   11.963441]  ? test_out_of_bounds_write+0x193/0x193
[   11.964443]  ? __lock_text_start+0x8/0x8
[   11.965234]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   11.966106]  ? kunit_try_catch_throw+0x40/0x40
[   11.966993]  kunit_try_run_case+0x8e/0xc0
[   11.967799]  ? kunit_catch_run_case+0x70/0x70
[   11.968677]  ? kunit_try_catch_throw+0x40/0x40
[   11.969565]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   11.970649]  kthread+0x179/0x1b0
[   11.971303]  ? kthread_complete_and_exit+0x20/0x20
[   11.972276]  ret_from_fork+0x22/0x30
[   11.973004]  </TASK>
[   11.973467] ==================================================================
[   12.025096]     ok 2 - test_out_of_bounds_read-memcache
[   12.026130]     # test_out_of_bounds_write: test_alloc: size=32, gfp=cc0, policy=left, cache=0
[   12.336944] ==================================================================
[   12.338378] BUG: KFENCE: out-of-bounds write in test_out_of_bounds_write+0xe1/0x193

[   12.340180] Out-of-bounds write at 0xffff888136cd1fff (1B left of kfence-#104):
[   12.341624]  test_out_of_bounds_write+0xe1/0x193
[   12.342551]  kunit_try_run_case+0x8e/0xc0
[   12.343364]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.344453]  kthread+0x179/0x1b0
[   12.345114]  ret_from_fork+0x22/0x30

[   12.346150] kfence-#104: 0xffff888136cd2000-0xffff888136cd201f, size=32, cache=kmalloc-32

[   12.348031] allocated by task 182 on cpu 1 at 12.336900s:
[   12.349138]  test_alloc+0x1fb/0x79c
[   12.349846]  test_out_of_bounds_write+0xd1/0x193
[   12.350763]  kunit_try_run_case+0x8e/0xc0
[   12.351576]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.352676]  kthread+0x179/0x1b0
[   12.353330]  ret_from_fork+0x22/0x30

[   12.354369] CPU: 1 PID: 182 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   12.356607] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   12.358861] RIP: 0010:test_out_of_bounds_write+0xe1/0x193
[   12.359944] Code: f4 ff ff b9 01 00 00 00 ba c0 0c 00 00 be 20 00 00 00 4c 89 e7 e8 e9 e6 ff ff 48 8d 78 ff 49 89 c6 48 89 7b b0 e8 f3 0b f3 fe <41> c6 46 ff 2a 48 8d 7d 80 e8 35 55 f3 fe 84 c0 75 3b 48 8d 8b 60
[   12.363611] RSP: 0000:ffffc900015ffde8 EFLAGS: 00010246
[   12.364667] RAX: 0000000000000000 RBX: ffffc900015ffea8 RCX: ffffffff825ee6cd
[   12.366088] RDX: 1ffff11026d9a3ff RSI: ffff888136cd2000 RDI: ffff888136cd1fff
[   12.367503] RBP: ffffc900015ffec8 R08: ffffffff825ed395 R09: ffffea0004db3487
[   12.368925] R10: fffff940009b6690 R11: 0000000000000001 R12: ffffc90000647ab8
[   12.370327] R13: 1ffff920002bffbd R14: ffff888136cd2000 R15: ffffc90000647ad0
[   12.371739] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   12.373316] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   12.374449] CR2: ffff888136cd1fff CR3: 000000000360e001 CR4: 0000000000060ee0
[   12.375859] Call Trace:
[   12.376394]  <TASK>
[   12.376833]  ? test_use_after_free_read+0x191/0x191
[   12.377814]  ? preempt_count_add+0x7b/0xd0
[   12.378648]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   12.379571]  ? test_use_after_free_read+0x191/0x191
[   12.380575]  ? __lock_text_start+0x8/0x8
[   12.381376]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   12.382252]  ? preempt_count_sub+0x18/0xc0
[   12.383093]  ? kunit_try_catch_throw+0x40/0x40
[   12.383992]  kunit_try_run_case+0x8e/0xc0
[   12.384817]  ? kunit_catch_run_case+0x70/0x70
[   12.385697]  ? kunit_try_catch_throw+0x40/0x40
[   12.386592]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.387679]  kthread+0x179/0x1b0
[   12.388347]  ? kthread_complete_and_exit+0x20/0x20
[   12.389307]  ret_from_fork+0x22/0x30
[   12.390066]  </TASK>
[   12.390530] ==================================================================
[   12.392083]     ok 3 - test_out_of_bounds_write
[   12.392739]     # test_out_of_bounds_write-memcache: setup_test_cache: size=32, ctor=0x0
[   12.395892]     # test_out_of_bounds_write-memcache: test_alloc: size=32, gfp=cc0, policy=left, cache=1
[   12.440936] ==================================================================
[   12.442378] BUG: KFENCE: out-of-bounds write in test_out_of_bounds_write+0xe1/0x193

[   12.444180] Out-of-bounds write at 0xffff888136cd3fff (1B left of kfence-#105):
[   12.445619]  test_out_of_bounds_write+0xe1/0x193
[   12.446544]  kunit_try_run_case+0x8e/0xc0
[   12.447360]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.448452]  kthread+0x179/0x1b0
[   12.449103]  ret_from_fork+0x22/0x30

[   12.450141] kfence-#105: 0xffff888136cd4000-0xffff888136cd401f, size=32, cache=test

[   12.451902] allocated by task 183 on cpu 1 at 12.440903s:
[   12.453000]  test_alloc+0x1ee/0x79c
[   12.453795]  test_out_of_bounds_write+0xd1/0x193
[   12.454735]  kunit_try_run_case+0x8e/0xc0
[   12.455553]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.456652]  kthread+0x179/0x1b0
[   12.457307]  ret_from_fork+0x22/0x30

[   12.458354] CPU: 1 PID: 183 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   12.460580] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   12.462797] RIP: 0010:test_out_of_bounds_write+0xe1/0x193
[   12.463867] Code: f4 ff ff b9 01 00 00 00 ba c0 0c 00 00 be 20 00 00 00 4c 89 e7 e8 e9 e6 ff ff 48 8d 78 ff 49 89 c6 48 89 7b b0 e8 f3 0b f3 fe <41> c6 46 ff 2a 48 8d 7d 80 e8 35 55 f3 fe 84 c0 75 3b 48 8d 8b 60
[   12.467507] RSP: 0000:ffffc9000160fde8 EFLAGS: 00010246
[   12.468575] RAX: 0000000000000000 RBX: ffffc9000160fea8 RCX: ffffffff825ee6cd
[   12.469977] RDX: 1ffff11026d9a7ff RSI: ffff888136cd4000 RDI: ffff888136cd3fff
[   12.471386] RBP: ffffc9000160fec8 R08: ffffffff825ed395 R09: ffffea0004db3507
[   12.472798] R10: fffff940009b66a0 R11: 0000000000000001 R12: ffffc90000647ab8
[   12.474202] R13: 1ffff920002c1fbd R14: ffff888136cd4000 R15: ffffc90000647ad0
[   12.475605] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   12.477212] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   12.478357] CR2: ffff888136cd3fff CR3: 000000000360e001 CR4: 0000000000060ee0
[   12.479766] Call Trace:
[   12.480274]  <TASK>
[   12.480707]  ? test_use_after_free_read+0x191/0x191
[   12.481671]  ? preempt_count_add+0x7b/0xd0
[   12.482498]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   12.483406]  ? test_use_after_free_read+0x191/0x191
[   12.484395]  ? __lock_text_start+0x8/0x8
[   12.485185]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   12.486063]  ? preempt_count_sub+0x18/0xc0
[   12.486885]  ? kunit_try_catch_throw+0x40/0x40
[   12.487772]  kunit_try_run_case+0x8e/0xc0
[   12.488598]  ? kunit_catch_run_case+0x70/0x70
[   12.489473]  ? kunit_try_catch_throw+0x40/0x40
[   12.490368]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.491449]  kthread+0x179/0x1b0
[   12.492104]  ? kthread_complete_and_exit+0x20/0x20
[   12.493079]  ret_from_fork+0x22/0x30
[   12.493815]  </TASK>
[   12.494264] ==================================================================
[   12.527889]     ok 4 - test_out_of_bounds_write-memcache
[   12.528831]     # test_use_after_free_read: test_alloc: size=32, gfp=cc0, policy=any, cache=0
[   12.544944] ==================================================================
[   12.546381] BUG: KFENCE: use-after-free read in test_use_after_free_read+0x103/0x191

[   12.548202] Use-after-free read at 0xffff888136cd6000 (in kfence-#106):
[   12.549507]  test_use_after_free_read+0x103/0x191
[   12.550455]  kunit_try_run_case+0x8e/0xc0
[   12.551263]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.552353]  kthread+0x179/0x1b0
[   12.553012]  ret_from_fork+0x22/0x30

[   12.554050] kfence-#106: 0xffff888136cd6000-0xffff888136cd601f, size=32, cache=kmalloc-32

[   12.555938] allocated by task 184 on cpu 1 at 12.544884s:
[   12.557039]  test_alloc+0x1fb/0x79c
[   12.557757]  test_use_after_free_read+0xd1/0x191
[   12.558689]  kunit_try_run_case+0x8e/0xc0
[   12.559494]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.560599]  kthread+0x179/0x1b0
[   12.561270]  ret_from_fork+0x22/0x30

[   12.562306] freed by task 184 on cpu 1 at 12.544915s:
[   12.563317]  __kmem_cache_free+0x23b/0x280
[   12.564147]  test_use_after_free_read+0xf3/0x191
[   12.565105]  kunit_try_run_case+0x8e/0xc0
[   12.565908]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.566986]  kthread+0x179/0x1b0
[   12.567643]  ret_from_fork+0x22/0x30

[   12.568686] CPU: 1 PID: 184 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   12.570917] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   12.573174] RIP: 0010:test_use_after_free_read+0x103/0x191
[   12.574268] Code: 89 43 b0 48 85 ff 74 0a 48 89 c6 e8 0c cc f2 fe eb 08 48 89 c7 e8 f2 9c e7 fe 4c 8b 73 b0 4c 89 f7 e8 06 0d f3 fe 48 8d 7d 80 <41> 8a 06 e8 aa 56 f3 fe 84 c0 75 3b 48 8d 8b 60 ff ff ff 45 31 c0
[   12.577910] RSP: 0000:ffffc9000160fde8 EFLAGS: 00010246
[   12.578963] RAX: 0000000000000000 RBX: ffffc9000160fea8 RCX: ffffffff825ee55a
[   12.580373] RDX: 1ffff11026d9ac00 RSI: 0000000000000008 RDI: ffffc9000160fe48
[   12.581771] RBP: ffffc9000160fec8 R08: 0000000000000001 R09: ffffffff84f27197
[   12.583190] R10: fffffbfff09e4e32 R11: 0000000000000001 R12: 1ffff920002c1fbd
[   12.584628] R13: ffffc90000647ab8 R14: ffff888136cd6000 R15: ffffc90000647ad0
[   12.586034] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   12.587623] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   12.588761] CR2: ffff888136cd6000 CR3: 000000000360e001 CR4: 0000000000060ee0
[   12.590168] Call Trace:
[   12.590670]  <TASK>
[   12.591113]  ? test_double_free+0x1a0/0x1a0
[   12.591951]  ? sysvec_apic_timer_interrupt+0xa0/0xc0
[   12.592959]  ? preempt_count_add+0x7b/0xd0
[   12.593782]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   12.594701]  ? test_double_free+0x1a0/0x1a0
[   12.595555]  ? __kthread_parkme+0xd8/0xf0
[   12.596379]  ? kunit_try_run_case+0x47/0xc0
[   12.597218]  ? preempt_count_sub+0x18/0xc0
[   12.598044]  ? kunit_try_catch_throw+0x40/0x40
[   12.598942]  kunit_try_run_case+0x8e/0xc0
[   12.599765]  ? kunit_catch_run_case+0x70/0x70
[   12.600657]  ? kunit_try_catch_throw+0x40/0x40
[   12.601542]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.602621]  kthread+0x179/0x1b0
[   12.603277]  ? kthread_complete_and_exit+0x20/0x20
[   12.604330]  ret_from_fork+0x22/0x30
[   12.605055]  </TASK>
[   12.605501] ==================================================================
[   12.607019]     ok 5 - test_use_after_free_read
[   12.607729]     # test_use_after_free_read-memcache: setup_test_cache: size=32, ctor=0x0
[   12.610909]     # test_use_after_free_read-memcache: test_alloc: size=32, gfp=cc0, policy=any, cache=1
[   12.648942] ==================================================================
[   12.650376] BUG: KFENCE: use-after-free read in test_use_after_free_read+0x103/0x191

[   12.652190] Use-after-free read at 0xffff888136cd8000 (in kfence-#107):
[   12.653506]  test_use_after_free_read+0x103/0x191
[   12.654438]  kunit_try_run_case+0x8e/0xc0
[   12.655240]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.656319]  kthread+0x179/0x1b0
[   12.656971]  ret_from_fork+0x22/0x30

[   12.658003] kfence-#107: 0xffff888136cd8000-0xffff888136cd801f, size=32, cache=test

[   12.659770] allocated by task 185 on cpu 1 at 12.648888s:
[   12.660864]  test_alloc+0x1ee/0x79c
[   12.661579]  test_use_after_free_read+0xd1/0x191
[   12.662504]  kunit_try_run_case+0x8e/0xc0
[   12.663318]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.664406]  kthread+0x179/0x1b0
[   12.665062]  ret_from_fork+0x22/0x30

[   12.666110] freed by task 185 on cpu 1 at 12.648918s:
[   12.667126]  test_use_after_free_read+0xe9/0x191
[   12.668049]  kunit_try_run_case+0x8e/0xc0
[   12.668892]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.669977]  kthread+0x179/0x1b0
[   12.670634]  ret_from_fork+0x22/0x30

[   12.671688] CPU: 1 PID: 185 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   12.673948] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   12.676183] RIP: 0010:test_use_after_free_read+0x103/0x191
[   12.677286] Code: 89 43 b0 48 85 ff 74 0a 48 89 c6 e8 0c cc f2 fe eb 08 48 89 c7 e8 f2 9c e7 fe 4c 8b 73 b0 4c 89 f7 e8 06 0d f3 fe 48 8d 7d 80 <41> 8a 06 e8 aa 56 f3 fe 84 c0 75 3b 48 8d 8b 60 ff ff ff 45 31 c0
[   12.680917] RSP: 0000:ffffc9000161fde8 EFLAGS: 00010246
[   12.681944] RAX: 0000000000000000 RBX: ffffc9000161fea8 RCX: ffffffff825ee55a
[   12.683338] RDX: 1ffff11026d9b000 RSI: 0000000000000008 RDI: ffffc9000161fe48
[   12.684750] RBP: ffffc9000161fec8 R08: 0000000000000001 R09: ffffffff84f27197
[   12.686142] R10: fffffbfff09e4e32 R11: 0000000000000001 R12: 1ffff920002c3fbd
[   12.687556] R13: ffffc90000647ab8 R14: ffff888136cd8000 R15: ffffc90000647ad0
[   12.688965] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   12.690549] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   12.691692] CR2: ffff888136cd8000 CR3: 000000000360e001 CR4: 0000000000060ee0
[   12.693126] Call Trace:
[   12.693638]  <TASK>
[   12.694073]  ? test_double_free+0x1a0/0x1a0
[   12.694924]  ? preempt_count_add+0x7b/0xd0
[   12.695748]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   12.696676]  ? test_double_free+0x1a0/0x1a0
[   12.697515]  ? __lock_text_start+0x8/0x8
[   12.698312]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   12.699182]  ? preempt_count_sub+0x18/0xc0
[   12.700006]  ? kunit_try_catch_throw+0x40/0x40
[   12.700909]  kunit_try_run_case+0x8e/0xc0
[   12.701718]  ? kunit_catch_run_case+0x70/0x70
[   12.702600]  ? kunit_try_catch_throw+0x40/0x40
[   12.703494]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.704576]  kthread+0x179/0x1b0
[   12.705235]  ? kthread_complete_and_exit+0x20/0x20
[   12.706194]  ret_from_fork+0x22/0x30
[   12.706928]  </TASK>
[   12.707374] ==================================================================
[   12.740854]     ok 6 - test_use_after_free_read-memcache
[   12.741638]     # test_double_free: test_alloc: size=32, gfp=cc0, policy=any, cache=0
[   12.752978] ==================================================================
[   12.754411] BUG: KFENCE: invalid free in __kmem_cache_free+0x23b/0x280

[   12.755992] Invalid free of 0xffff888136cdafe0 (in kfence-#108):
[   12.757192]  __kmem_cache_free+0x23b/0x280
[   12.758016]  test_double_free+0x113/0x1a0
[   12.758821]  kunit_try_run_case+0x8e/0xc0
[   12.759627]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.760719]  kthread+0x179/0x1b0
[   12.761379]  ret_from_fork+0x22/0x30

[   12.762432] kfence-#108: 0xffff888136cdafe0-0xffff888136cdafff, size=32, cache=kmalloc-32

[   12.764321] allocated by task 186 on cpu 1 at 12.752884s:
[   12.765418]  test_alloc+0x1fb/0x79c
[   12.766123]  test_double_free+0xcf/0x1a0
[   12.766920]  kunit_try_run_case+0x8e/0xc0
[   12.767728]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.768829]  kthread+0x179/0x1b0
[   12.769500]  ret_from_fork+0x22/0x30

[   12.770534] freed by task 186 on cpu 1 at 12.752927s:
[   12.771542]  __kmem_cache_free+0x23b/0x280
[   12.772380]  test_double_free+0xf1/0x1a0
[   12.773172]  kunit_try_run_case+0x8e/0xc0
[   12.773982]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.775053]  kthread+0x179/0x1b0
[   12.775711]  ret_from_fork+0x22/0x30

[   12.776757] CPU: 1 PID: 186 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   12.778987] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   12.781220] ==================================================================
[   12.782874]     # test_double_free: EXPECTATION FAILED at mm/kfence/kfence_test.c:396
                   Expected report_matches(&expect) to be true, but is false
[   12.785916]     not ok 7 - test_double_free
[   12.786286]     # test_double_free-memcache: setup_test_cache: size=32, ctor=0x0
[   12.789257]     # test_double_free-memcache: test_alloc: size=32, gfp=cc0, policy=any, cache=1
[   12.856944] ==================================================================
[   12.858384] BUG: KFENCE: invalid free in test_double_free+0x109/0x1a0

[   12.859947] Invalid free of 0xffff888136cdc000 (in kfence-#109):
[   12.861170]  test_double_free+0x109/0x1a0
[   12.861976]  kunit_try_run_case+0x8e/0xc0
[   12.862802]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.863886]  kthread+0x179/0x1b0
[   12.864554]  ret_from_fork+0x22/0x30

[   12.865594] kfence-#109: 0xffff888136cdc000-0xffff888136cdc01f, size=32, cache=test

[   12.867385] allocated by task 187 on cpu 1 at 12.856887s:
[   12.868463]  test_alloc+0x1ee/0x79c
[   12.869170]  test_double_free+0xcf/0x1a0
[   12.869966]  kunit_try_run_case+0x8e/0xc0
[   12.870779]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.871854]  kthread+0x179/0x1b0
[   12.872541]  ret_from_fork+0x22/0x30

[   12.873586] freed by task 187 on cpu 1 at 12.856915s:
[   12.874590]  test_double_free+0xe7/0x1a0
[   12.875394]  kunit_try_run_case+0x8e/0xc0
[   12.876244]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.877317]  kthread+0x179/0x1b0
[   12.877969]  ret_from_fork+0x22/0x30

[   12.879002] CPU: 1 PID: 187 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   12.881265] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   12.883504] ==================================================================
[   12.917862]     ok 8 - test_double_free-memcache
[   12.918628]     # test_invalid_addr_free: test_alloc: size=32, gfp=cc0, policy=any, cache=0
[   12.960979] ==================================================================
[   12.962412] BUG: KFENCE: invalid free in __kmem_cache_free+0x23b/0x280

[   12.963995] Invalid free of 0xffff888136cdefe1 (in kfence-#110):
[   12.965212]  __kmem_cache_free+0x23b/0x280
[   12.966041]  test_invalid_addr_free+0xfa/0x1a7
[   12.966936]  kunit_try_run_case+0x8e/0xc0
[   12.967746]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.968829]  kthread+0x179/0x1b0
[   12.969485]  ret_from_fork+0x22/0x30

[   12.970529] kfence-#110: 0xffff888136cdefe0-0xffff888136cdefff, size=32, cache=kmalloc-32

[   12.972427] allocated by task 188 on cpu 1 at 12.960887s:
[   12.973514]  test_alloc+0x1fb/0x79c
[   12.974217]  test_invalid_addr_free+0xd1/0x1a7
[   12.975105]  kunit_try_run_case+0x8e/0xc0
[   12.975913]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   12.977011]  kthread+0x179/0x1b0
[   12.977661]  ret_from_fork+0x22/0x30

[   12.978697] CPU: 1 PID: 188 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   12.980940] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   12.983176] ==================================================================
[   12.984872]     # test_invalid_addr_free: EXPECTATION FAILED at mm/kfence/kfence_test.c:413
                   Expected report_matches(&expect) to be true, but is false
[   12.988021]     not ok 9 - test_invalid_addr_free
[   12.988736]     # test_invalid_addr_free-memcache: setup_test_cache: size=32, ctor=0x0
[   12.991883]     # test_invalid_addr_free-memcache: test_alloc: size=32, gfp=cc0, policy=any, cache=1
[   13.064937] ==================================================================
[   13.066370] BUG: KFENCE: invalid free in test_invalid_addr_free+0xf0/0x1a7

[   13.068015] Invalid free of 0xffff888136ce0fe1 (in kfence-#111):
[   13.069216]  test_invalid_addr_free+0xf0/0x1a7
[   13.070102]  kunit_try_run_case+0x8e/0xc0
[   13.070903]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.071983]  kthread+0x179/0x1b0
[   13.072643]  ret_from_fork+0x22/0x30

[   13.073680] kfence-#111: 0xffff888136ce0fe0-0xffff888136ce0fff, size=32, cache=test

[   13.075462] allocated by task 189 on cpu 1 at 13.064885s:
[   13.076558]  test_alloc+0x1ee/0x79c
[   13.077277]  test_invalid_addr_free+0xd1/0x1a7
[   13.078158]  kunit_try_run_case+0x8e/0xc0
[   13.078969]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.080027]  kthread+0x179/0x1b0
[   13.080706]  ret_from_fork+0x22/0x30

[   13.081759] CPU: 1 PID: 189 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   13.084070] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   13.086333] ==================================================================
[   13.120934]     ok 10 - test_invalid_addr_free-memcache
[   13.121868]     # test_corruption: test_alloc: size=32, gfp=cc0, policy=left, cache=0
[   13.168947] ==================================================================
[   13.170381] BUG: KFENCE: memory corruption in __kmem_cache_free+0x23b/0x280

[   13.172049] Corrupted memory at 0xffff888136ce2020 [ 0x2a . . . . . . . . . . . . . . . ] (in kfence-#112):
[   13.174003]  __kmem_cache_free+0x23b/0x280
[   13.174825]  test_corruption+0x107/0x228
[   13.175613]  kunit_try_run_case+0x8e/0xc0
[   13.176428]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.177496]  kthread+0x179/0x1b0
[   13.178146]  ret_from_fork+0x22/0x30

[   13.179181] kfence-#112: 0xffff888136ce2000-0xffff888136ce201f, size=32, cache=kmalloc-32

[   13.181088] allocated by task 190 on cpu 1 at 13.168885s:
[   13.182157]  test_alloc+0x1fb/0x79c
[   13.182860]  test_corruption+0xd4/0x228
[   13.183628]  kunit_try_run_case+0x8e/0xc0
[   13.184458]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.185527]  kthread+0x179/0x1b0
[   13.186177]  ret_from_fork+0x22/0x30

[   13.187211] freed by task 190 on cpu 1 at 13.168916s:
[   13.188246]  __kmem_cache_free+0x23b/0x280
[   13.189065]  test_corruption+0x107/0x228
[   13.189852]  kunit_try_run_case+0x8e/0xc0
[   13.190657]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.191726]  kthread+0x179/0x1b0
[   13.192403]  ret_from_fork+0x22/0x30

[   13.193440] CPU: 1 PID: 190 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   13.195670] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   13.197915] ==================================================================
[   13.199580]     # test_corruption: EXPECTATION FAILED at mm/kfence/kfence_test.c:433
                   Expected report_matches(&expect) to be true, but is false
[   13.202525]     # test_corruption: test_alloc: size=32, gfp=cc0, policy=right, cache=0
[   13.272957] ==================================================================
[   13.274389] BUG: KFENCE: memory corruption in __kmem_cache_free+0x23b/0x280

[   13.276055] Corrupted memory at 0xffff888136ce4fdf [ 0x2a ] (in kfence-#113):
[   13.277486]  __kmem_cache_free+0x23b/0x280
[   13.278327]  test_corruption+0x199/0x228
[   13.279128]  kunit_try_run_case+0x8e/0xc0
[   13.279933]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.281019]  kthread+0x179/0x1b0
[   13.281687]  ret_from_fork+0x22/0x30

[   13.282725] kfence-#113: 0xffff888136ce4fe0-0xffff888136ce4fff, size=32, cache=kmalloc-32

[   13.284624] allocated by task 190 on cpu 1 at 13.272890s:
[   13.285710]  test_alloc+0x1fb/0x79c
[   13.286413]  test_corruption+0x166/0x228
[   13.287196]  kunit_try_run_case+0x8e/0xc0
[   13.287997]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.289083]  kthread+0x179/0x1b0
[   13.289734]  ret_from_fork+0x22/0x30

[   13.290764] freed by task 190 on cpu 1 at 13.272922s:
[   13.291778]  __kmem_cache_free+0x23b/0x280
[   13.292635]  test_corruption+0x199/0x228
[   13.293418]  kunit_try_run_case+0x8e/0xc0
[   13.294220]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.295289]  kthread+0x179/0x1b0
[   13.295944]  ret_from_fork+0x22/0x30

[   13.296984] CPU: 1 PID: 190 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   13.299212] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   13.301461] ==================================================================
[   13.303100]     # test_corruption: EXPECTATION FAILED at mm/kfence/kfence_test.c:439
                   Expected report_matches(&expect) to be true, but is false
[   13.306174]     not ok 11 - test_corruption
[   13.306687]     # test_corruption-memcache: setup_test_cache: size=32, ctor=0x0
[   13.309691]     # test_corruption-memcache: test_alloc: size=32, gfp=cc0, policy=left, cache=1
[   13.376927] ==================================================================
[   13.378360] BUG: KFENCE: memory corruption in test_corruption+0xfd/0x228

[   13.379971] Corrupted memory at 0xffff888136ce6020 [ 0x2a . . . . . . . . . . . . . . . ] (in kfence-#114):
[   13.381940]  test_corruption+0xfd/0x228
[   13.382717]  kunit_try_run_case+0x8e/0xc0
[   13.383521]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.384622]  kthread+0x179/0x1b0
[   13.385290]  ret_from_fork+0x22/0x30

[   13.386334] kfence-#114: 0xffff888136ce6000-0xffff888136ce601f, size=32, cache=test

[   13.388124] allocated by task 191 on cpu 1 at 13.376879s:
[   13.389207]  test_alloc+0x1ee/0x79c
[   13.389919]  test_corruption+0xd4/0x228
[   13.390697]  kunit_try_run_case+0x8e/0xc0
[   13.391501]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.392582]  kthread+0x179/0x1b0
[   13.393246]  ret_from_fork+0x22/0x30

[   13.394278] freed by task 191 on cpu 1 at 13.376917s:
[   13.395277]  test_corruption+0xfd/0x228
[   13.396044]  kunit_try_run_case+0x8e/0xc0
[   13.396872]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.397949]  kthread+0x179/0x1b0
[   13.398617]  ret_from_fork+0x22/0x30

[   13.399665] CPU: 1 PID: 191 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   13.401918] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   13.404159] ==================================================================
[   13.405638]     # test_corruption-memcache: test_alloc: size=32, gfp=cc0, policy=right, cache=1
[   13.688967] ==================================================================
[   13.690393] BUG: KFENCE: memory corruption in test_corruption+0x18f/0x228

[   13.692023] Corrupted memory at 0xffff888136cecfdf [ 0x2a ] (in kfence-#117):
[   13.693455]  test_corruption+0x18f/0x228
[   13.694256]  kunit_try_run_case+0x8e/0xc0
[   13.695077]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.696165]  kthread+0x179/0x1b0
[   13.696824]  ret_from_fork+0x22/0x30

[   13.697881] kfence-#117: 0xffff888136cecfe0-0xffff888136cecfff, size=32, cache=test

[   13.699680] allocated by task 191 on cpu 1 at 13.688886s:
[   13.700780]  test_alloc+0x1ee/0x79c
[   13.701502]  test_corruption+0x166/0x228
[   13.702299]  kunit_try_run_case+0x8e/0xc0
[   13.703119]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.704194]  kthread+0x179/0x1b0
[   13.704859]  ret_from_fork+0x22/0x30

[   13.705906] freed by task 191 on cpu 1 at 13.688941s:
[   13.706917]  test_corruption+0x18f/0x228
[   13.707714]  kunit_try_run_case+0x8e/0xc0
[   13.708549]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   13.709625]  kthread+0x179/0x1b0
[   13.710283]  ret_from_fork+0x22/0x30

[   13.711321] CPU: 1 PID: 191 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   13.713599] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   13.715854] ==================================================================
[   13.759484]     ok 12 - test_corruption-memcache
[   13.760796]     # test_free_bulk: test_alloc: size=203, gfp=cc0, policy=right, cache=0
[   14.000925]     # test_free_bulk: test_alloc: size=203, gfp=cc0, policy=none, cache=0
[   14.002530]     # test_free_bulk: test_alloc: size=203, gfp=cc0, policy=left, cache=0
[   14.532519]     # test_free_bulk: test_alloc: size=203, gfp=cc0, policy=none, cache=0
[   14.534136]     # test_free_bulk: test_alloc: size=203, gfp=cc0, policy=none, cache=0
[   14.535529]     # test_free_bulk: test_alloc: size=92, gfp=cc0, policy=right, cache=0
[   14.624896]     # test_free_bulk: test_alloc: size=92, gfp=cc0, policy=none, cache=0
[   14.626279]     # test_free_bulk: test_alloc: size=92, gfp=cc0, policy=left, cache=0
[   14.728893]     # test_free_bulk: test_alloc: size=92, gfp=cc0, policy=none, cache=0
[   14.730258]     # test_free_bulk: test_alloc: size=92, gfp=cc0, policy=none, cache=0
[   14.731656]     # test_free_bulk: test_alloc: size=93, gfp=cc0, policy=right, cache=0
[   14.832888]     # test_free_bulk: test_alloc: size=93, gfp=cc0, policy=none, cache=0
[   14.834271]     # test_free_bulk: test_alloc: size=93, gfp=cc0, policy=left, cache=0
[   14.958150]     # test_free_bulk: test_alloc: size=93, gfp=cc0, policy=none, cache=0
[   14.959463]     # test_free_bulk: test_alloc: size=93, gfp=cc0, policy=none, cache=0
[   14.960872]     # test_free_bulk: test_alloc: size=10, gfp=cc0, policy=right, cache=0
[   15.144894]     # test_free_bulk: test_alloc: size=10, gfp=cc0, policy=none, cache=0
[   15.146243]     # test_free_bulk: test_alloc: size=10, gfp=cc0, policy=left, cache=0
[   15.352877]     # test_free_bulk: test_alloc: size=10, gfp=cc0, policy=none, cache=0
[   15.354234]     # test_free_bulk: test_alloc: size=10, gfp=cc0, policy=none, cache=0
[   15.355622]     # test_free_bulk: test_alloc: size=171, gfp=cc0, policy=right, cache=0
[   15.456883]     # test_free_bulk: test_alloc: size=171, gfp=cc0, policy=none, cache=0
[   15.458275]     # test_free_bulk: test_alloc: size=171, gfp=cc0, policy=left, cache=0
[   15.566353]     # test_free_bulk: test_alloc: size=171, gfp=cc0, policy=none, cache=0
[   15.567751]     # test_free_bulk: test_alloc: size=171, gfp=cc0, policy=none, cache=0
[   15.569196]     ok 13 - test_free_bulk
[   15.570171]     # test_free_bulk-memcache: setup_test_cache: size=183, ctor=0x0
[   15.572570]     # test_free_bulk-memcache: test_alloc: size=183, gfp=cc0, policy=right, cache=1
[   15.671588]     # test_free_bulk-memcache: test_alloc: size=183, gfp=cc0, policy=none, cache=1
[   15.673160]     # test_free_bulk-memcache: test_alloc: size=183, gfp=cc0, policy=left, cache=1
[   15.771762]     # test_free_bulk-memcache: test_alloc: size=183, gfp=cc0, policy=none, cache=1
[   15.773246]     # test_free_bulk-memcache: test_alloc: size=183, gfp=cc0, policy=none, cache=1
[   15.809708]     # test_free_bulk-memcache: setup_test_cache: size=88, ctor=ctor_set_x
[   15.814281]     # test_free_bulk-memcache: test_alloc: size=88, gfp=cc0, policy=right, cache=1
[   15.882558]     # test_free_bulk-memcache: test_alloc: size=88, gfp=cc0, policy=none, cache=1
[   15.884057]     # test_free_bulk-memcache: test_alloc: size=88, gfp=cc0, policy=left, cache=1
[   16.100519]     # test_free_bulk-memcache: test_alloc: size=88, gfp=cc0, policy=none, cache=1
[   16.102032]     # test_free_bulk-memcache: test_alloc: size=88, gfp=cc0, policy=none, cache=1
[   16.136733]     # test_free_bulk-memcache: setup_test_cache: size=289, ctor=0x0
[   16.138907]     # test_free_bulk-memcache: test_alloc: size=289, gfp=cc0, policy=right, cache=1
[   16.288894]     # test_free_bulk-memcache: test_alloc: size=289, gfp=cc0, policy=none, cache=1
[   16.290571]     # test_free_bulk-memcache: test_alloc: size=289, gfp=cc0, policy=left, cache=1
[   16.600888]     # test_free_bulk-memcache: test_alloc: size=289, gfp=cc0, policy=none, cache=1
[   16.602334]     # test_free_bulk-memcache: test_alloc: size=289, gfp=cc0, policy=none, cache=1
[   16.635672]     # test_free_bulk-memcache: setup_test_cache: size=168, ctor=ctor_set_x
[   16.640447]     # test_free_bulk-memcache: test_alloc: size=168, gfp=cc0, policy=right, cache=1
[   16.704885]     # test_free_bulk-memcache: test_alloc: size=168, gfp=cc0, policy=none, cache=1
[   16.706278]     # test_free_bulk-memcache: test_alloc: size=168, gfp=cc0, policy=left, cache=1
[   16.912880]     # test_free_bulk-memcache: test_alloc: size=168, gfp=cc0, policy=none, cache=1
[   16.914273]     # test_free_bulk-memcache: test_alloc: size=168, gfp=cc0, policy=none, cache=1
[   16.939658]     # test_free_bulk-memcache: setup_test_cache: size=205, ctor=0x0
[   16.943960]     # test_free_bulk-memcache: test_alloc: size=205, gfp=cc0, policy=right, cache=1
[   17.016894]     # test_free_bulk-memcache: test_alloc: size=205, gfp=cc0, policy=none, cache=1
[   17.018334]     # test_free_bulk-memcache: test_alloc: size=205, gfp=cc0, policy=left, cache=1
[   17.848906]     # test_free_bulk-memcache: test_alloc: size=205, gfp=cc0, policy=none, cache=1
[   17.850424]     # test_free_bulk-memcache: test_alloc: size=205, gfp=cc0, policy=none, cache=1
[   17.885857]     ok 14 - test_free_bulk-memcache
[   17.886688]     ok 15 - test_init_on_free # SKIP Test requires: IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON)
[   17.889378]     ok 16 - test_init_on_free-memcache # SKIP Test requires: IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON)
[   17.893649]     # test_kmalloc_aligned_oob_read: test_alloc: size=73, gfp=cc0, policy=right, cache=0
[   17.959175] ==================================================================
[   17.960429] BUG: KFENCE: out-of-bounds read in test_kmalloc_aligned_oob_read+0x19a/0x248

[   17.962014] Out-of-bounds read at 0xffff888136d3f001 (81B right of kfence-#158):
[   17.963237]  test_kmalloc_aligned_oob_read+0x19a/0x248
[   17.964108]  kunit_try_run_case+0x8e/0xc0
[   17.964828]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   17.965740]  kthread+0x179/0x1b0
[   17.966289]  ret_from_fork+0x22/0x30

[   17.967161] kfence-#158: 0xffff888136d3efb0-0xffff888136d3eff8, size=73, cache=kmalloc-96

[   17.968765] allocated by task 196 on cpu 1 at 17.959123s:
[   17.969682]  test_alloc+0x1fb/0x79c
[   17.970273]  test_kmalloc_aligned_oob_read+0xd6/0x248
[   17.971122]  kunit_try_run_case+0x8e/0xc0
[   17.971811]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   17.972718]  kthread+0x179/0x1b0
[   17.973266]  ret_from_fork+0x22/0x30

[   17.974152] CPU: 1 PID: 196 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   17.976310] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   17.978555] RIP: 0010:test_kmalloc_aligned_oob_read+0x19a/0x248
[   17.979728] Code: b4 81 48 c7 83 68 ff ff ff 00 85 d3 82 e8 fa c6 55 ff 4f 8d 7c 3c 49 4c 89 ff 4c 89 7b b0 e8 c9 ff f2 fe 48 8d bd 78 ff ff ff <41> 8a 07 e8 6a 49 f3 fe 84 c0 75 3b 48 8d 8b 60 ff ff ff 45 31 c0
[   17.983374] RSP: 0000:ffffc9000168fde0 EFLAGS: 00010246
[   17.984430] RAX: 0000000000000000 RBX: ffffc9000168fea0 RCX: ffffffff825ef297
[   17.985822] RDX: 1ffff11026da7e00 RSI: ffff888136d3efb0 RDI: ffffc9000168fe40
[   17.987237] RBP: ffffc9000168fec8 R08: ffffffff825ed395 R09: ffffea0004db4f87
[   17.988677] R10: fffff940009b69f0 R11: 0000000000000001 R12: ffff888136d3efb0
[   17.990087] R13: 1ffff920002d1fbc R14: ffffc90000647ab8 R15: ffff888136d3f001
[   17.991484] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   17.993078] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   17.994201] CR2: ffff888136d3f001 CR3: 000000000360e001 CR4: 0000000000060ee0
[   17.995632] Call Trace:
[   17.996132]  <TASK>
[   17.996576]  ? test_gfpzero.cold+0x12/0x12
[   17.997399]  ? preempt_count_add+0x7b/0xd0
[   17.998238]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   17.999153]  ? test_gfpzero.cold+0x12/0x12
[   18.000015]  ? __lock_text_start+0x8/0x8
[   18.000862]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   18.001745]  ? kunit_try_catch_throw+0x40/0x40
[   18.002644]  kunit_try_run_case+0x8e/0xc0
[   18.003455]  ? kunit_catch_run_case+0x70/0x70
[   18.004336]  ? kunit_try_catch_throw+0x40/0x40
[   18.005229]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   18.006318]  kthread+0x179/0x1b0
[   18.006983]  ? kthread_complete_and_exit+0x20/0x20
[   18.007947]  ret_from_fork+0x22/0x30
[   18.008693]  </TASK>
[   18.009144] ==================================================================
[   18.010714]     ok 17 - test_kmalloc_aligned_oob_read
[   18.011267]     # test_kmalloc_aligned_oob_write: test_alloc: size=73, gfp=cc0, policy=right, cache=0
[   18.168246] ==================================================================
[   18.169674] BUG: KFENCE: memory corruption in __kmem_cache_free+0x23b/0x280

[   18.171354] Corrupted memory at 0xffff888136d42ff9 [ 0xac . . . . . . ] (in kfence-#160):
[   18.173010]  __kmem_cache_free+0x23b/0x280
[   18.173835]  test_kmalloc_aligned_oob_write+0x130/0x1c0
[   18.174875]  kunit_try_run_case+0x8e/0xc0
[   18.175690]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   18.176790]  kthread+0x179/0x1b0
[   18.177450]  ret_from_fork+0x22/0x30

[   18.178512] kfence-#160: 0xffff888136d42fb0-0xffff888136d42ff8, size=73, cache=kmalloc-96

[   18.180408] allocated by task 197 on cpu 1 at 18.168152s:
[   18.181482]  test_alloc+0x1fb/0x79c
[   18.182195]  test_kmalloc_aligned_oob_write+0xb4/0x1c0
[   18.183244]  kunit_try_run_case+0x8e/0xc0
[   18.184061]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   18.185150]  kthread+0x179/0x1b0
[   18.185809]  ret_from_fork+0x22/0x30

[   18.186846] freed by task 197 on cpu 1 at 18.168210s:
[   18.187858]  __kmem_cache_free+0x23b/0x280
[   18.188698]  test_kmalloc_aligned_oob_write+0x130/0x1c0
[   18.189741]  kunit_try_run_case+0x8e/0xc0
[   18.190549]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   18.191627]  kthread+0x179/0x1b0
[   18.192309]  ret_from_fork+0x22/0x30

[   18.193357] CPU: 1 PID: 197 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   18.195590] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   18.197849] ==================================================================
[   18.199552]     # test_kmalloc_aligned_oob_write: EXPECTATION FAILED at mm/kfence/kfence_test.c:505
                   Expected report_matches(&expect) to be true, but is false
[   18.202872]     not ok 18 - test_kmalloc_aligned_oob_write
[   18.203387]     # test_shrink_memcache: setup_test_cache: size=32, ctor=0x0
[   18.206621]     # test_shrink_memcache: test_alloc: size=32, gfp=cc0, policy=any, cache=1
[   18.281534]     ok 19 - test_shrink_memcache
[   18.282436]     # test_memcache_ctor: setup_test_cache: size=32, ctor=ctor_set_x
[   18.285443]     # test_memcache_ctor: test_alloc: size=32, gfp=cc0, policy=any, cache=1
[   18.380789]     ok 20 - test_memcache_ctor
[   18.381546] ==================================================================
[   18.384343] BUG: KFENCE: invalid read in test_invalid_access+0xb5/0x150

[   18.385946] Invalid read at 0xffff888136c0000a:
[   18.386850]  test_invalid_access+0xb5/0x150
[   18.387687]  kunit_try_run_case+0x8e/0xc0
[   18.388504]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   18.389572]  kthread+0x179/0x1b0
[   18.390245]  ret_from_fork+0x22/0x30

[   18.391302] CPU: 1 PID: 200 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   18.393580] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   18.395829] RIP: 0010:test_invalid_access+0xb5/0x150
[   18.396834] Code: 00 48 c7 45 90 f0 48 52 81 e8 e7 ab ff ff 4c 8b 2d 18 32 bc 02 c6 45 a0 00 49 8d 7d 0a 48 89 7d 98 e8 bf a8 ff ff 48 8d 7d 88 <41> 0f b6 45 0a e8 61 f2 ff ff 84 c0 74 43 48 b8 00 00 00 00 00 fc
[   18.400493] RSP: 0000:ffffc900016bfdf0 EFLAGS: 00010246
[   18.401532] RAX: 0000000000000000 RBX: 1ffff920002d7fbe RCX: ffffffff815249a1
[   18.402929] RDX: 1ffff11026d80001 RSI: 0000000000000008 RDI: ffffc900016bfe50
[   18.404542] RBP: ffffc900016bfec8 R08: ffffffff82d38580 R09: 0000000000000008
[   18.405999] R10: 0000000000000000 R11: ffffffff82d3a373 R12: ffffc90000647ab8
[   18.407409] R13: ffff888136c00000 R14: ffffffff81b4d150 R15: ffffc90000647ad0
[   18.408849] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   18.410440] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   18.411579] CR2: ffff888136c0000a CR3: 000000000360e001 CR4: 0000000000060ee0
[   18.413014] Call Trace:
[   18.413515]  <TASK>
[   18.413964]  ? test_free_bulk+0xd0/0xd0
[   18.414740]  ? preempt_count_add+0x7b/0xd0
[   18.415571]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   18.416485]  ? test_free_bulk+0xd0/0xd0
[   18.417321]  ? __lock_text_start+0x8/0x8
[   18.418162]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   18.419062]  ? preempt_count_sub+0x18/0xc0
[   18.419919]  kunit_try_run_case+0x8e/0xc0
[   18.420748]  ? kunit_catch_run_case+0x70/0x70
[   18.421682]  ? kunit_try_catch_throw+0x40/0x40
[   18.422579]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   18.423660]  kthread+0x179/0x1b0
[   18.424329]  ? kthread_complete_and_exit+0x20/0x20
[   18.425283]  ret_from_fork+0x22/0x30
[   18.426018]  </TASK>
[   18.426477] ==================================================================
[   18.428006]     ok 21 - test_invalid_access
[   18.428504]     # test_gfpzero: test_alloc: size=4096, gfp=cc0, policy=any, cache=0
[   18.480456]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   18.580606]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   18.680957]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   18.804495]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   18.894306]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.036037]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.098139]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.200988]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.305161]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.409494]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.513728]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.616976]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.720941]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.825450]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   19.928986]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.032951]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.137242]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.240926]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.345279]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.449217]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.553784]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.656960]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.760930]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.864972]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   20.968983]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.073558]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.176929]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.280939]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.385103]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.488959]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.592965]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.696960]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.800938]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   21.904955]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.008990]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.112949]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.216955]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.320957]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.425189]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.528973]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.632967]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.736932]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.841061]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   22.945631]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.049310]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.152948]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.256944]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.361240]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.464954]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.568953]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.673038]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.776927]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.880957]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   23.984959]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.088940]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.192959]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.297550]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.400948]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.504941]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.608959]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.712959]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.817623]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   24.921060]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.024960]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.129419]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.232953]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.336916]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.441067]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.544970]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.648961]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.752958]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.857192]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   25.960974]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.065564]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.168952]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.272936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.377081]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.480949]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.584957]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.688960]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.792953]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   26.897655]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.000965]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.104928]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.209094]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.312923]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.416955]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.521116]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.624949]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.728937]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.833065]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   27.937010]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.040963]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.145244]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.248957]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.352949]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.456929]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.560934]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.665503]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.768932]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.872925]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   28.977110]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.080927]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.184941]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.289214]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.392926]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.496937]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.601089]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.704937]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.808909]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   29.913421]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.016965]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.120930]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.225332]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.328908]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.432936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.537267]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.640934]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.744939]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.848907]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   30.953183]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.056941]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.160946]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.265439]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.368918]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.472934]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.577385]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.680935]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.784917]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.889295]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   31.992956]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.096931]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.201363]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.304932]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.409612]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.512937]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.616936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.721349]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.824910]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   32.928925]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.032936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.136945]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.241300]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.344917]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.449661]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.552933]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.656933]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.760913]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.864909]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   33.968963]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.073355]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.176931]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.280941]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.385394]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.488940]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.593680]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.696927]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.800936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   34.905420]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.008992]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.112948]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.217290]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.320926]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.424918]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.528934]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.632930]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.736933]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.840971]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   35.944932]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.049592]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.153100]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.256936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.360921]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.465010]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.568947]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.672929]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.777497]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.880899]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   36.984958]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.088914]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.193296]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.296928]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.400941]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.505286]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.608926]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.712923]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.817640]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   37.921013]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.024994]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.128938]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.233131]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.336929]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.440936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.544977]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.648938]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.752926]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.856956]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   38.960935]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.064947]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.168923]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.272931]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.377611]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.480916]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.584943]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.689562]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.792909]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   39.896913]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.001471]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.104936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.208942]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.313509]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.416908]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.520925]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.625270]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.728933]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.832938]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   40.936961]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.040945]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.145698]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.248944]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.352937]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.456923]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.560936]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.665580]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.769049]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.872948]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   41.976956]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.081569]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.185183]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.288944]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.392900]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.496934]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.601501]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.704966]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.808947]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   42.912924]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   43.016960]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   43.120938]     # test_gfpzero: test_alloc: size=4096, gfp=dc0, policy=any, cache=0
[   43.225462]     ok 22 - test_gfpzero
[   43.226537]     # test_memcache_typesafe_by_rcu: setup_test_cache: size=32, ctor=0x0
[   43.232598]     # test_memcache_typesafe_by_rcu: test_alloc: size=32, gfp=cc0, policy=any, cache=1
[   43.339098] ==================================================================
[   43.341616] BUG: KFENCE: use-after-free read in test_memcache_typesafe_by_rcu.cold+0x114/0x1ff

[   43.345091] Use-after-free read at 0xffff888136d4a000 (in kfence-#164):
[   43.347313]  test_memcache_typesafe_by_rcu.cold+0x114/0x1ff
[   43.348864]  kunit_try_run_case+0x8e/0xc0
[   43.349685]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.350762]  kthread+0x179/0x1b0
[   43.351425]  ret_from_fork+0x22/0x30

[   43.352481] kfence-#164: 0xffff888136d4a000-0xffff888136d4a01f, size=32, cache=test

[   43.354291] allocated by task 203 on cpu 2 at 43.328909s:
[   43.355376]  test_alloc+0x1ee/0x79c
[   43.356084]  test_memcache_typesafe_by_rcu.cold+0x2d/0x1ff
[   43.357177]  kunit_try_run_case+0x8e/0xc0
[   43.357980]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.359053]  kthread+0x179/0x1b0
[   43.359717]  ret_from_fork+0x22/0x30

[   43.360788] freed by task 0 on cpu 2 at 43.339030s:
[   43.361817]  rcu_do_batch+0x2ec/0x7e0
[   43.362564]  rcu_core+0x323/0x3d0
[   43.363240]  __do_softirq+0x11e/0x3ec
[   43.363979]  __irq_exit_rcu+0x146/0x190
[   43.364761]  sysvec_apic_timer_interrupt+0x93/0xc0
[   43.365717]  asm_sysvec_apic_timer_interrupt+0x16/0x20
[   43.366741]  default_idle+0x10/0x20
[   43.367450]  default_idle_call+0x5f/0x180
[   43.368277]  cpuidle_idle_call+0x245/0x2e0
[   43.369104]  do_idle+0xb1/0x130
[   43.369750]  cpu_startup_entry+0x19/0x20
[   43.370533]  start_secondary+0xb6/0xc0
[   43.371286]  secondary_startup_64_no_verify+0xe5/0xeb

[   43.372618] CPU: 2 PID: 203 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   43.374935] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   43.377222] RIP: 0010:test_memcache_typesafe_by_rcu.cold+0x114/0x1ff
[   43.378485] Code: ff ff 50 cd b4 81 48 c7 83 28 ff ff ff 00 85 d3 82 e8 aa ce 55 ff e8 d5 e1 c2 fe 4c 8b b3 70 ff ff ff 4c 89 f7 e8 76 07 f3 fe <49> 0f be 06 3c 2a 74 37 48 8d 4b a0 45 31 c0 ba 01 00 00 00 4c 89
[   43.382166] RSP: 0000:ffffc900016efda8 EFLAGS: 00010246
[   43.383216] RAX: 0000000000000000 RBX: ffffc900016efea8 RCX: ffffffff825eeaea
[   43.384630] RDX: 1ffff11026da9400 RSI: 0000000000000008 RDI: ffff888136d4a000
[   43.386032] RBP: ffffc900016efec8 R08: 0000000000000001 R09: ffffc900016efd57
[   43.387435] R10: fffff520002ddfaa R11: 0000000000000001 R12: ffffc90000647ab8
[   43.388848] R13: 1ffff920002ddfb5 R14: ffff888136d4a000 R15: ffffc90000647ad0
[   43.390255] FS:  0000000000000000(0000) GS:ffff88807ec00000(0000) knlGS:0000000000000000
[   43.391843] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   43.393001] CR2: ffff888136d4a000 CR3: 000000000360e001 CR4: 0000000000060ee0
[   43.394412] Call Trace:
[   43.394919]  <TASK>
[   43.395358]  ? test_memcache_alloc_bulk+0x340/0x340
[   43.396349]  ? _raw_spin_unlock+0x15/0x30
[   43.397177]  ? finish_task_switch.isra.0+0xe5/0x440
[   43.398165]  ? __switch_to+0x2fa/0x680
[   43.398931]  ? test_memcache_alloc_bulk+0x340/0x340
[   43.399909]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   43.400837]  ? __lock_text_start+0x8/0x8
[   43.401632]  ? __lock_text_start+0x8/0x8
[   43.402426]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   43.403324]  ? preempt_count_sub+0x18/0xc0
[   43.404170]  ? kunit_try_catch_throw+0x40/0x40
[   43.405084]  kunit_try_run_case+0x8e/0xc0
[   43.405903]  ? kunit_catch_run_case+0x70/0x70
[   43.406781]  ? kunit_try_catch_throw+0x40/0x40
[   43.407670]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.408759]  kthread+0x179/0x1b0
[   43.409416]  ? kthread_complete_and_exit+0x20/0x20
[   43.410379]  ret_from_fork+0x22/0x30
[   43.411110]  </TASK>
[   43.411564] ==================================================================
[   43.413398] ==================================================================
[   43.414839] BUG: KASAN: use-after-free in kobject_del+0x14/0x30
[   43.416049] Read of size 8 at addr ffff888040c9e890 by task kunit_try_catch/203

[   43.417850] CPU: 2 PID: 203 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   43.420109] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   43.422379] Call Trace:
[   43.422888]  <TASK>
[   43.423330]  dump_stack_lvl+0x34/0x48
[   43.424098]  print_address_description.constprop.0+0x1d/0x160
[   43.425265]  ? kobject_del+0x14/0x30
[   43.425994]  print_report.cold+0x4f/0x112
[   43.426814]  ? kobject_del+0x14/0x30
[   43.427639]  kasan_report+0xa3/0x130
[   43.428391]  ? kobject_del+0x14/0x30
[   43.429120]  ? kunit_try_catch_throw+0x40/0x40
[   43.430038]  kobject_del+0x14/0x30
[   43.430734]  kmem_cache_destroy+0x64/0xb0
[   43.431584]  test_exit+0x1a/0x30
[   43.432253]  kunit_try_run_case+0xb0/0xc0
[   43.433067]  ? kunit_catch_run_case+0x70/0x70
[   43.433945]  ? kunit_try_catch_throw+0x40/0x40
[   43.434839]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.435925]  kthread+0x179/0x1b0
[   43.436605]  ? kthread_complete_and_exit+0x20/0x20
[   43.437569]  ret_from_fork+0x22/0x30
[   43.438311]  </TASK>

[   43.439100] Allocated by task 203:
[   43.439806]  kasan_save_stack+0x1e/0x40
[   43.440597]  __kasan_slab_alloc+0x90/0xc0
[   43.441406]  kmem_cache_alloc+0x155/0x320
[   43.442223]  kmem_cache_create_usercopy+0x125/0x2d0
[   43.443209]  kmem_cache_create+0x12/0x20
[   43.444000]  setup_test_cache.part.0+0x113/0x197
[   43.444938]  test_memcache_typesafe_by_rcu.cold+0x14/0x1ff
[   43.446032]  kunit_try_run_case+0x8e/0xc0
[   43.446842]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.447918]  kthread+0x179/0x1b0
[   43.448588]  ret_from_fork+0x22/0x30

[   43.449633] Freed by task 61:
[   43.450243]  kasan_save_stack+0x1e/0x40
[   43.451018]  kasan_set_track+0x21/0x30
[   43.451775]  kasan_set_free_info+0x20/0x40
[   43.452647]  __kasan_slab_free+0x124/0x1b0
[   43.453478]  slab_free_freelist_hook+0x98/0x150
[   43.454400]  kmem_cache_free+0x19b/0x420
[   43.455197]  kobject_release+0x58/0x90
[   43.455954]  slab_caches_to_rcu_destroy_workfn+0xcc/0x100
[   43.457058]  process_one_work+0x395/0x690
[   43.457867]  worker_thread+0x8c/0x530
[   43.458610]  kthread+0x179/0x1b0
[   43.459270]  ret_from_fork+0x22/0x30

[   43.460317] The buggy address belongs to the object at ffff888040c9e800
                which belongs to the cache kmem_cache of size 256
[   43.462729] The buggy address is located 144 bytes inside of
                256-byte region [ffff888040c9e800, ffff888040c9e900)

[   43.465367] The buggy address belongs to the physical page:
[   43.466552] page:ffffea0001032780 refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x40c9e
[   43.468399] head:ffffea0001032780 order:1 compound_mapcount:0 compound_pincount:0
[   43.469873] flags: 0x4fffffc0010200(slab|head|node=1|zone=1|lastcpupid=0x1fffff)
[   43.471351] raw: 004fffffc0010200 ffffea000104e188 ffff8880400000f0 ffff888005842000
[   43.472908] raw: 0000000000000000 0000000000100010 00000001ffffffff 0000000000000000
[   43.474431] page dumped because: kasan: bad access detected

[   43.475847] Memory state around the buggy address:
[   43.476823]  ffff888040c9e780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   43.478246]  ffff888040c9e800: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   43.479670] >ffff888040c9e880: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   43.481109]                          ^
[   43.481866]  ffff888040c9e900: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   43.483282]  ffff888040c9e980: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   43.484711] ==================================================================
[   43.486181] Disabling lock debugging due to kernel taint
[   43.487272] ------------[ cut here ]------------
[   43.488227] refcount_t: underflow; use-after-free.
[   43.489297] WARNING: CPU: 2 PID: 203 at lib/refcount.c:28 refcount_warn_saturate+0xcd/0x120
[   43.490992] Modules linked in:
[   43.491622] CPU: 2 PID: 203 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   43.493910] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   43.496176] RIP: 0010:refcount_warn_saturate+0xcd/0x120
[   43.497251] Code: 90 47 57 02 01 e8 cd 20 a9 00 0f 0b eb 95 80 3d 7d 47 57 02 00 75 8c 48 c7 c7 20 74 e5 82 c6 05 6d 47 57 02 01 e8 ad 20 a9 00 <0f> 0b e9 72 ff ff ff 80 3d 58 47 57 02 00 0f 85 65 ff ff ff 48 c7
[   43.500932] RSP: 0000:ffffc900016efeb0 EFLAGS: 00010286
[   43.502001] RAX: 0000000000000000 RBX: 0000000000000003 RCX: 0000000000000000
[   43.503428] RDX: 0000000000000001 RSI: 0000000000000008 RDI: fffff520002ddfc8
[   43.504888] RBP: ffff888040c9e8b0 R08: ffffffff811863a8 R09: ffffc900016efbf7
[   43.506320] R10: fffff520002ddf7e R11: 0000000000000001 R12: ffffffff83bd60a0
[   43.507744] R13: 0000000000000000 R14: ffffffff81b4d150 R15: ffffc90000647ad0
[   43.509186] FS:  0000000000000000(0000) GS:ffff88807ec00000(0000) knlGS:0000000000000000
[   43.510786] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   43.511947] CR2: ffff888136d4a000 CR3: 000000000360e001 CR4: 0000000000060ee0
[   43.513407] Call Trace:
[   43.513944]  <TASK>
[   43.514392]  test_exit+0x1a/0x30
[   43.515068]  kunit_try_run_case+0xb0/0xc0
[   43.515910]  ? kunit_catch_run_case+0x70/0x70
[   43.516825]  ? kunit_try_catch_throw+0x40/0x40
[   43.517730]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.518873]  kthread+0x179/0x1b0
[   43.519551]  ? kthread_complete_and_exit+0x20/0x20
[   43.520534]  ret_from_fork+0x22/0x30
[   43.521304]  </TASK>
[   43.521768] ---[ end trace 0000000000000000 ]---
[   43.522777]     ok 23 - test_memcache_typesafe_by_rcu
[   43.523373]     # test_krealloc: test_alloc: size=32, gfp=cc0, policy=any, cache=0
[   43.536973] ==================================================================
[   43.538729] BUG: KFENCE: use-after-free read in test_krealloc+0x3c3/0x460

[   43.540615] Use-after-free read at 0xffff888136d4efe0 (in kfence-#166):
[   43.541935]  test_krealloc+0x3c3/0x460
[   43.542690]  kunit_try_run_case+0x8e/0xc0
[   43.543498]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.544601]  kthread+0x179/0x1b0
[   43.545269]  ret_from_fork+0x22/0x30

[   43.546316] kfence-#166: 0xffff888136d4efe0-0xffff888136d4efff, size=32, cache=kmalloc-32

[   43.548242] allocated by task 204 on cpu 1 at 43.536881s:
[   43.549523]  test_alloc+0x1fb/0x79c
[   43.550317]  test_krealloc+0xb6/0x460
[   43.551064]  kunit_try_run_case+0x8e/0xc0
[   43.551881]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.552960]  kthread+0x179/0x1b0
[   43.553627]  ret_from_fork+0x22/0x30

[   43.554686] freed by task 204 on cpu 1 at 43.536940s:
[   43.555713]  __kmem_cache_free+0x23b/0x280
[   43.556559]  krealloc+0x6e/0x100
[   43.557215]  test_krealloc+0x180/0x460
[   43.557973]  kunit_try_run_case+0x8e/0xc0
[   43.558777]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.559845]  kthread+0x179/0x1b0
[   43.560520]  ret_from_fork+0x22/0x30

[   43.561585] CPU: 1 PID: 204 Comm: kunit_try_catch Tainted: G    B   W        N 6.0.0-rc3-next-20220831-00002-g6db6c886e5af #245
[   43.564172] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014
[   43.566484] RIP: 0010:test_krealloc+0x3c3/0x460
[   43.567386] Code: 50 cd b4 81 48 c7 83 28 ff ff ff 00 85 d3 82 e8 91 e0 55 ff 4c 8b b3 70 ff ff ff 4c 89 f7 e8 62 19 f3 fe 48 8d bb 60 ff ff ff <41> 8a 06 e8 03 63 f3 fe 84 c0 75 38 48 8d 8b 20 ff ff ff 45 31 c0
[   43.571134] RSP: 0000:ffffc900016ffd88 EFLAGS: 00010246
[   43.572175] RAX: 0000000000000000 RBX: ffffc900016ffea0 RCX: ffffffff825ed8fe
[   43.573798] RDX: 1ffff11026da9dfc RSI: ffffffff82e5a5a0 RDI: ffffc900016ffe00
[   43.575274] RBP: ffffc900016ffec8 R08: ffffffff81186300 R09: ffffc900016ffa70
[   43.576695] R10: 0000000000000060 R11: 000000000000000c R12: ffffc90000647ab8
[   43.578107] R13: ffff8880067150f8 R14: ffff888136d4efe0 R15: 0000000000000041
[   43.579518] FS:  0000000000000000(0000) GS:ffff888014900000(0000) knlGS:0000000000000000
[   43.581119] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   43.582253] CR2: ffff888136d4efe0 CR3: 000000000360e001 CR4: 0000000000060ee0
[   43.583673] Call Trace:
[   43.584187]  <TASK>
[   43.584658]  ? test_alloc+0x79c/0x79c
[   43.585432]  ? _raw_spin_unlock+0x15/0x30
[   43.586276]  ? finish_task_switch.isra.0+0xe5/0x440
[   43.587310]  ? __switch_to+0x2fa/0x680
[   43.588138]  ? test_alloc+0x79c/0x79c
[   43.589000]  ? preempt_count_add+0x30/0xd0
[   43.589827]  ? _raw_spin_lock_irqsave+0x8d/0xf0
[   43.590735]  ? __lock_text_start+0x8/0x8
[   43.591550]  ? __lock_text_start+0x8/0x8
[   43.592384]  ? set_cpus_allowed_ptr+0x7e/0xb0
[   43.593269]  ? kunit_try_catch_throw+0x40/0x40
[   43.594199]  kunit_try_run_case+0x8e/0xc0
[   43.595129]  ? kunit_catch_run_case+0x70/0x70
[   43.596085]  ? kunit_try_catch_throw+0x40/0x40
[   43.597075]  kunit_generic_run_threadfn_adapter+0x29/0x50
[   43.598227]  kthread+0x179/0x1b0
[   43.598910]  ? kthread_complete_and_exit+0x20/0x20
[   43.599886]  ret_from_fork+0x22/0x30
[   43.600635]  </TASK>
[   43.601087] ==================================================================
[   43.602626]     ok 24 - test_krealloc
[   43.603263]     # test_memcache_alloc_bulk: setup_test_cache: size=32, ctor=0x0
[   43.647487]     ok 25 - test_memcache_alloc_bulk
[   43.649212] # kfence: pass:19 fail:4 skip:2 total:25
[   43.651302] # Totals: pass:19 fail:4 skip:2 total:25
[   43.653082] not ok 1 - kfence
[   43.656557]     # Subtest: damon
[   43.656580]     1..8
[   43.658999]     ok 1 - damon_test_target
[   43.660244]     ok 2 - damon_test_regions
[   43.661677]     ok 3 - damon_test_aggregate
[   43.663305]     ok 4 - damon_test_split_at
[   43.665093]     ok 5 - damon_test_merge_two
[   43.666537]     ok 6 - damon_test_merge_regions_of
[   43.668014]     ok 7 - damon_test_split_regions_of
[   43.669583]     ok 8 - damon_test_ops_registration
[   43.670638] # damon: pass:8 fail:0 skip:0 total:8
[   43.671650] # Totals: pass:8 fail:0 skip:0 total:8
[   43.672658] ok 2 - damon
[   43.674250]     # Subtest: damon-operations
[   43.674254]     1..6
[   43.675842]     ok 1 - damon_test_three_regions_in_vmas
[   43.677114]     ok 2 - damon_test_apply_three_regions1
[   43.678832]     ok 3 - damon_test_apply_three_regions2
[   43.680540]     ok 4 - damon_test_apply_three_regions3
[   43.682337]     ok 5 - damon_test_apply_three_regions4
[   43.684224]     ok 6 - damon_test_split_evenly
[   43.685314] # damon-operations: pass:6 fail:0 skip:0 total:6
[   43.686233] # Totals: pass:6 fail:0 skip:0 total:6
[   43.687380] ok 3 - damon-operations
[   43.689124]     # Subtest: damon-dbgfs
[   43.689128]     1..3
[   43.690605]     ok 1 - damon_dbgfs_test_str_to_ints
[   43.691671]     ok 2 - damon_dbgfs_test_set_targets
[   43.693671] damon-dbgfs: input: 3 10 20

[   43.696180] damon-dbgfs: input: 1 10 20
                1 14 26

[   43.699401] damon-dbgfs: input: 0 10 20
               1 30 40
                0 5 8
[   43.701686]     ok 3 - damon_dbgfs_test_set_init_regions
[   43.701695] # damon-dbgfs: pass:3 fail:0 skip:0 total:3
[   43.703914] # Totals: pass:3 fail:0 skip:0 total:3
[   43.705967] ok 4 - damon-dbgfs
[   43.710002] md: Waiting for all devices to be available before autodetect
[   43.711832] md: If you don't use raid, use raid=noautodetect
[   43.713293] md: Autodetecting RAID arrays.
[   43.714362] md: autorun ...
[   43.715103] md: ... autorun DONE.
[   43.738962] EXT4-fs (sda): mounted filesystem with ordered data mode. Quota mode: none.
[   43.741165] VFS: Mounted root (ext4 filesystem) on device 8:0.
[   43.748080] devtmpfs: mounted
[   43.779589] Freeing unused decrypted memory: 2036K
[   43.784192] Freeing unused kernel image (initmem) memory: 3244K
[   43.785930] Write protecting the kernel read-only data: 38912k
[   43.790659] Freeing unused kernel image (text/rodata gap) memory: 2036K
[   43.793892] Freeing unused kernel image (rodata/data gap) memory: 1128K
[   43.795767] Run /sbin/init as init process
[   43.796831]   with arguments:
[   43.797587]     /sbin/init
[   43.798300]     sched_debug
[   43.799045]     nokalsr
[   43.799689]     nokaslr
[   43.800365]   with environment:
[   43.801181]     HOME=/
[   43.801830]     TERM=linux
[   43.802532]     vga=normal
[   43.803250]     psi=no
[   43.803897]     movable_nodemask=0xc
[   44.352840] random: crng init done
[   44.358689] systemd[1]: systemd 232 running in system mode. (+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD +IDN)
[   44.363956] systemd[1]: Virtualization QEMU found in DMI (/sys/class/dmi/id/sys_vendor)
[   44.366117] systemd[1]: Found VM virtualization qemu
[   44.367468] systemd[1]: Detected virtualization qemu.
[   44.368849] systemd[1]: Detected architecture x86-64.
[   44.378953] systemd[1]: Set hostname to <debian-x86_64>.
[   44.386394] systemd[1]: Unified cgroup hierarchy is located at /sys/fs/cgroup.
[   44.414855] systemd[1]: Controller 'cpu' supported: yes
[   44.416235] systemd[1]: Controller 'cpuacct' supported: no
[   44.417911] systemd[1]: Controller 'io' supported: yes
[   44.502708] systemd-getty-generator[232]: Automatically adding serial getty for /dev/ttyS0.
[   44.514299] systemd-gpt-auto-generator[231]: /dev/sda: parent isn't a raw disk, ignoring.
[   44.522738] systemd-fstab-generator[233]: Parsing /etc/fstab
[   44.533322] systemd-sysv-generator[235]: Native unit for hwclock.service already exists, skipping.
[   44.538845] systemd-sysv-generator[235]: Native unit for redis-server.service already exists, skipping.
[   44.541839] systemd-sysv-generator[235]: Cannot find unit openipmi.service.
[   44.544105] systemd-sysv-generator[235]: Native unit for networking.service already exists, skipping.
[   44.547735] systemd-sysv-generator[235]: Native unit for kmod.service already exists, skipping.
[   44.550417] systemd-sysv-generator[235]: Native unit for ssh.service already exists, skipping.
[   44.553157] systemd-sysv-generator[235]: Native unit for cgproxy.service already exists, skipping.
[   44.556425] systemd-sysv-generator[235]: Cannot find unit bmc-watchdog.service.
[   44.559318] systemd-sysv-generator[235]: Native unit for rpcbind.service already exists, skipping.
[   44.562555] systemd-sysv-generator[235]: Cannot find unit kexec-load.service.
[   44.588113] printk: systemd-sysv-ge: 62 output lines suppressed due to ratelimiting
[   44.961312] systemd-journald[243]: Fixed min_use=1.0M max_use=154.4M max_size=19.3M min_size=512.0K keep_free=231.7M n_max_files=100
[   44.972130] systemd-journald[243]: Reserving 35157 entries in hash table.
[   44.974150] systemd-journald[243]: Vacuuming...
[   44.975005] systemd-journald[243]: Vacuuming done, freed 0B of archived journals from /run/log/journal/9693f4c7632e4077869b6976970bebd7.
[   44.976884] systemd-journald[243]: Flushing /dev/kmsg...
[   45.311033] systemd-journald[243]: systemd-journald running as pid 243
[   45.318046] systemd-journald[243]: Sent READY=1 notification.
[   45.319312] systemd-journald[243]: Sent WATCHDOG=1 notification.
[   45.323119] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   45.326041] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   49.392883] systemd[1]: redis-server.service: Forked /bin/run-parts as 331
[   49.416953] systemd[1]: redis-server.service: Changed start -> start-post
[   49.433906] systemd[1]: redis-server.service: User lookup succeeded: uid=108 gid=111
[   49.445900] systemd[1]: redis-server.service: User lookup succeeded: uid=108 gid=111
[   49.497897] systemd[1]: systemd-journald.service: Got notification message from PID 243 (FDSTORE=1)
[   49.509928] systemd[1]: systemd-journald.service: Added fd 56 (n/a) to fd store.
[   49.521911] systemd[1]: ssh.service: Got notification message from PID 330 (READY=1)
[   49.534875] systemd[1]: ssh.service: Changed start -> running
[   49.546931] systemd[1]: ssh.service: Job ssh.service/start finished, result=done
[   49.578917] systemd[1]: Child 331 (run-parts) died (code=exited, status=0/SUCCESS)
[   49.803331] BTRFS: device fsid 3c1023c9-540f-4198-8bf1-7e63d8f98654 devid 1 transid 23 /dev/sdb scanned by systemd-udevd (264)
[   50.040292] e1000 0000:00:03.0 ens3: renamed from eth0
[   50.632157] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   50.738114] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   50.829182] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   51.295028] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   51.903406] e1000: ens3 NIC Link is Up 1000 Mbps Full Duplex, Flow Control: RX
[   51.905243] IPv6: ADDRCONF(NETDEV_CHANGE): ens3: link becomes ready
[   51.908743] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   52.019354] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   52.133754] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   52.342014] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   52.399513] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[   52.857396] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[  124.065919] systemd-journald[243]: Successfully sent stream file descriptor to service manager.
[  139.427512] systemd-journald[243]: Sent WATCHDOG=1 notification.

--4uR9TydQqPng+7Dv
Content-Type: text/plain; charset="us-ascii"
Content-Disposition: attachment; filename="next.kconfig"

#
# Automatically generated file; DO NOT EDIT.
# Linux/x86 6.0.0-rc3 Kernel Configuration
#
CONFIG_CC_VERSION_TEXT="gcc (Ubuntu 10.3.0-1ubuntu1~20.10) 10.3.0"
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=100300
CONFIG_CLANG_VERSION=0
CONFIG_AS_IS_GNU=y
CONFIG_AS_VERSION=23501
CONFIG_LD_IS_BFD=y
CONFIG_LD_VERSION=23501
CONFIG_LLD_VERSION=0
CONFIG_CC_CAN_LINK=y
CONFIG_CC_CAN_LINK_STATIC=y
CONFIG_CC_HAS_ASM_INLINE=y
CONFIG_CC_HAS_NO_PROFILE_FN_ATTR=y
CONFIG_PAHOLE_VERSION=117
CONFIG_CONSTRUCTORS=y
CONFIG_IRQ_WORK=y
CONFIG_BUILDTIME_TABLE_SORT=y
CONFIG_THREAD_INFO_IN_TASK=y

#
# General setup
#
CONFIG_INIT_ENV_ARG_LIMIT=32
# CONFIG_COMPILE_TEST is not set
# CONFIG_WERROR is not set
CONFIG_LOCALVERSION=""
CONFIG_LOCALVERSION_AUTO=y
CONFIG_BUILD_SALT=""
CONFIG_HAVE_KERNEL_GZIP=y
CONFIG_HAVE_KERNEL_BZIP2=y
CONFIG_HAVE_KERNEL_LZMA=y
CONFIG_HAVE_KERNEL_XZ=y
CONFIG_HAVE_KERNEL_LZO=y
CONFIG_HAVE_KERNEL_LZ4=y
CONFIG_HAVE_KERNEL_ZSTD=y
CONFIG_KERNEL_GZIP=y
# CONFIG_KERNEL_BZIP2 is not set
# CONFIG_KERNEL_LZMA is not set
# CONFIG_KERNEL_XZ is not set
# CONFIG_KERNEL_LZO is not set
# CONFIG_KERNEL_LZ4 is not set
# CONFIG_KERNEL_ZSTD is not set
CONFIG_DEFAULT_INIT=""
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_SYSVIPC=y
CONFIG_SYSVIPC_SYSCTL=y
CONFIG_SYSVIPC_COMPAT=y
CONFIG_POSIX_MQUEUE=y
CONFIG_POSIX_MQUEUE_SYSCTL=y
# CONFIG_WATCH_QUEUE is not set
CONFIG_CROSS_MEMORY_ATTACH=y
# CONFIG_USELIB is not set
CONFIG_AUDIT=y
CONFIG_HAVE_ARCH_AUDITSYSCALL=y
CONFIG_AUDITSYSCALL=y

#
# IRQ subsystem
#
CONFIG_GENERIC_IRQ_PROBE=y
CONFIG_GENERIC_IRQ_SHOW=y
CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK=y
CONFIG_GENERIC_PENDING_IRQ=y
CONFIG_GENERIC_IRQ_MIGRATION=y
CONFIG_GENERIC_IRQ_INJECTION=y
CONFIG_HARDIRQS_SW_RESEND=y
CONFIG_IRQ_DOMAIN=y
CONFIG_IRQ_DOMAIN_HIERARCHY=y
CONFIG_GENERIC_MSI_IRQ=y
CONFIG_GENERIC_MSI_IRQ_DOMAIN=y
CONFIG_IRQ_MSI_IOMMU=y
CONFIG_GENERIC_IRQ_MATRIX_ALLOCATOR=y
CONFIG_GENERIC_IRQ_RESERVATION_MODE=y
CONFIG_IRQ_FORCED_THREADING=y
CONFIG_SPARSE_IRQ=y
# CONFIG_GENERIC_IRQ_DEBUGFS is not set
# end of IRQ subsystem

CONFIG_CLOCKSOURCE_WATCHDOG=y
CONFIG_ARCH_CLOCKSOURCE_INIT=y
CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE=y
CONFIG_GENERIC_TIME_VSYSCALL=y
CONFIG_GENERIC_CLOCKEVENTS=y
CONFIG_GENERIC_CLOCKEVENTS_BROADCAST=y
CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST=y
CONFIG_GENERIC_CMOS_UPDATE=y
CONFIG_HAVE_POSIX_CPU_TIMERS_TASK_WORK=y
CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y
# CONFIG_TIME_KUNIT_TEST is not set
CONFIG_CONTEXT_TRACKING=y
CONFIG_CONTEXT_TRACKING_IDLE=y

#
# Timers subsystem
#
CONFIG_TICK_ONESHOT=y
CONFIG_NO_HZ_COMMON=y
# CONFIG_HZ_PERIODIC is not set
# CONFIG_NO_HZ_IDLE is not set
CONFIG_NO_HZ_FULL=y
CONFIG_CONTEXT_TRACKING_USER=y
# CONFIG_CONTEXT_TRACKING_USER_FORCE is not set
CONFIG_NO_HZ=y
CONFIG_HIGH_RES_TIMERS=y
CONFIG_CLOCKSOURCE_WATCHDOG_MAX_SKEW_US=100
# end of Timers subsystem

CONFIG_BPF=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=y

#
# BPF subsystem
#
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
# CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set
# CONFIG_BPF_PRELOAD is not set
# CONFIG_BPF_LSM is not set
# end of BPF subsystem

CONFIG_PREEMPT_BUILD=y
# CONFIG_PREEMPT_NONE is not set
# CONFIG_PREEMPT_VOLUNTARY is not set
CONFIG_PREEMPT=y
CONFIG_PREEMPT_COUNT=y
CONFIG_PREEMPTION=y
CONFIG_PREEMPT_DYNAMIC=y
CONFIG_SCHED_CORE=y

#
# CPU/Task time and stats accounting
#
CONFIG_VIRT_CPU_ACCOUNTING=y
CONFIG_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_SCHED_AVG_IRQ=y
CONFIG_BSD_PROCESS_ACCT=y
CONFIG_BSD_PROCESS_ACCT_V3=y
CONFIG_TASKSTATS=y
CONFIG_TASK_DELAY_ACCT=y
CONFIG_TASK_XACCT=y
CONFIG_TASK_IO_ACCOUNTING=y
# CONFIG_PSI is not set
# end of CPU/Task time and stats accounting

CONFIG_CPU_ISOLATION=y

#
# RCU Subsystem
#
CONFIG_TREE_RCU=y
CONFIG_PREEMPT_RCU=y
# CONFIG_RCU_EXPERT is not set
CONFIG_SRCU=y
CONFIG_TREE_SRCU=y
CONFIG_TASKS_RCU_GENERIC=y
CONFIG_TASKS_RCU=y
CONFIG_TASKS_RUDE_RCU=y
CONFIG_TASKS_TRACE_RCU=y
CONFIG_RCU_STALL_COMMON=y
CONFIG_RCU_NEED_SEGCBLIST=y
CONFIG_RCU_NOCB_CPU=y
# CONFIG_RCU_NOCB_CPU_DEFAULT_ALL is not set
# end of RCU Subsystem

CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
# CONFIG_IKHEADERS is not set
CONFIG_LOG_BUF_SHIFT=20
CONFIG_LOG_CPU_MAX_BUF_SHIFT=12
CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT=13
# CONFIG_PRINTK_INDEX is not set
CONFIG_HAVE_UNSTABLE_SCHED_CLOCK=y

#
# Scheduler features
#
# CONFIG_UCLAMP_TASK is not set
# end of Scheduler features

CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=y
CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH=y
CONFIG_CC_HAS_INT128=y
CONFIG_CC_IMPLICIT_FALLTHROUGH="-Wimplicit-fallthrough=5"
CONFIG_GCC12_NO_ARRAY_BOUNDS=y
CONFIG_ARCH_SUPPORTS_INT128=y
CONFIG_NUMA_BALANCING=y
CONFIG_NUMA_BALANCING_DEFAULT_ENABLED=y
CONFIG_CGROUPS=y
CONFIG_PAGE_COUNTER=y
# CONFIG_CGROUP_FAVOR_DYNMODS is not set
CONFIG_MEMCG=y
CONFIG_MEMCG_SWAP=y
CONFIG_MEMCG_KMEM=y
CONFIG_BLK_CGROUP=y
CONFIG_CGROUP_WRITEBACK=y
CONFIG_CGROUP_SCHED=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_CFS_BANDWIDTH=y
CONFIG_RT_GROUP_SCHED=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_RDMA=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CPUSETS=y
CONFIG_PROC_PID_CPUSET=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_PERF=y
CONFIG_CGROUP_BPF=y
# CONFIG_CGROUP_MISC is not set
# CONFIG_CGROUP_DEBUG is not set
CONFIG_SOCK_CGROUP_DATA=y
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_TIME_NS=y
CONFIG_IPC_NS=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
# CONFIG_CHECKPOINT_RESTORE is not set
CONFIG_SCHED_AUTOGROUP=y
# CONFIG_SYSFS_DEPRECATED is not set
CONFIG_RELAY=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE=""
CONFIG_RD_GZIP=y
CONFIG_RD_BZIP2=y
CONFIG_RD_LZMA=y
CONFIG_RD_XZ=y
CONFIG_RD_LZO=y
CONFIG_RD_LZ4=y
CONFIG_RD_ZSTD=y
# CONFIG_BOOT_CONFIG is not set
CONFIG_INITRAMFS_PRESERVE_MTIME=y
CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y
# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
CONFIG_LD_ORPHAN_WARN=y
CONFIG_SYSCTL=y
CONFIG_HAVE_UID16=y
CONFIG_SYSCTL_EXCEPTION_TRACE=y
CONFIG_HAVE_PCSPKR_PLATFORM=y
# CONFIG_EXPERT is not set
CONFIG_UID16=y
CONFIG_MULTIUSER=y
CONFIG_SGETMASK_SYSCALL=y
CONFIG_SYSFS_SYSCALL=y
CONFIG_FHANDLE=y
CONFIG_POSIX_TIMERS=y
CONFIG_PRINTK=y
CONFIG_BUG=y
CONFIG_ELF_CORE=y
CONFIG_PCSPKR_PLATFORM=y
CONFIG_BASE_FULL=y
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_SHMEM=y
CONFIG_AIO=y
CONFIG_IO_URING=y
CONFIG_ADVISE_SYSCALLS=y
CONFIG_MEMBARRIER=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=y
CONFIG_KCMP=y
CONFIG_RSEQ=y
# CONFIG_EMBEDDED is not set
CONFIG_HAVE_PERF_EVENTS=y
CONFIG_GUEST_PERF_EVENTS=y

#
# Kernel Performance Events And Counters
#
CONFIG_PERF_EVENTS=y
# CONFIG_DEBUG_PERF_USE_VMALLOC is not set
# end of Kernel Performance Events And Counters

CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_PROFILING=y
CONFIG_TRACEPOINTS=y
# end of General setup

CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_X86=y
CONFIG_INSTRUCTION_DECODER=y
CONFIG_OUTPUT_FORMAT="elf64-x86-64"
CONFIG_LOCKDEP_SUPPORT=y
CONFIG_STACKTRACE_SUPPORT=y
CONFIG_MMU=y
CONFIG_ARCH_MMAP_RND_BITS_MIN=28
CONFIG_ARCH_MMAP_RND_BITS_MAX=32
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=8
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16
CONFIG_GENERIC_ISA_DMA=y
CONFIG_GENERIC_BUG=y
CONFIG_GENERIC_BUG_RELATIVE_POINTERS=y
CONFIG_ARCH_MAY_HAVE_PC_FDC=y
CONFIG_GENERIC_CALIBRATE_DELAY=y
CONFIG_ARCH_HAS_CPU_RELAX=y
CONFIG_ARCH_HIBERNATION_POSSIBLE=y
CONFIG_ARCH_NR_GPIO=1024
CONFIG_ARCH_SUSPEND_POSSIBLE=y
CONFIG_AUDIT_ARCH=y
CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000
CONFIG_HAVE_INTEL_TXT=y
CONFIG_X86_64_SMP=y
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_FIX_EARLYCON_MEM=y
CONFIG_DYNAMIC_PHYSICAL_MASK=y
CONFIG_PGTABLE_LEVELS=5
CONFIG_CC_HAS_SANE_STACKPROTECTOR=y

#
# Processor type and features
#
CONFIG_SMP=y
CONFIG_X86_FEATURE_NAMES=y
CONFIG_X86_X2APIC=y
CONFIG_X86_MPPARSE=y
# CONFIG_GOLDFISH is not set
CONFIG_X86_CPU_RESCTRL=y
CONFIG_X86_EXTENDED_PLATFORM=y
# CONFIG_X86_NUMACHIP is not set
# CONFIG_X86_VSMP is not set
CONFIG_X86_UV=y
# CONFIG_X86_GOLDFISH is not set
# CONFIG_X86_INTEL_MID is not set
CONFIG_X86_INTEL_LPSS=y
CONFIG_X86_AMD_PLATFORM_DEVICE=y
CONFIG_IOSF_MBI=y
# CONFIG_IOSF_MBI_DEBUG is not set
CONFIG_X86_SUPPORTS_MEMORY_FAILURE=y
# CONFIG_SCHED_OMIT_FRAME_POINTER is not set
CONFIG_HYPERVISOR_GUEST=y
CONFIG_PARAVIRT=y
# CONFIG_PARAVIRT_DEBUG is not set
CONFIG_PARAVIRT_SPINLOCKS=y
CONFIG_X86_HV_CALLBACK_VECTOR=y
CONFIG_XEN=y
# CONFIG_XEN_PV is not set
CONFIG_XEN_PVHVM=y
CONFIG_XEN_PVHVM_SMP=y
CONFIG_XEN_PVHVM_GUEST=y
CONFIG_XEN_SAVE_RESTORE=y
# CONFIG_XEN_DEBUG_FS is not set
# CONFIG_XEN_PVH is not set
CONFIG_KVM_GUEST=y
CONFIG_ARCH_CPUIDLE_HALTPOLL=y
# CONFIG_PVH is not set
CONFIG_PARAVIRT_TIME_ACCOUNTING=y
CONFIG_PARAVIRT_CLOCK=y
# CONFIG_JAILHOUSE_GUEST is not set
# CONFIG_ACRN_GUEST is not set
# CONFIG_INTEL_TDX_GUEST is not set
# CONFIG_MK8 is not set
# CONFIG_MPSC is not set
# CONFIG_MCORE2 is not set
# CONFIG_MATOM is not set
CONFIG_GENERIC_CPU=y
CONFIG_X86_INTERNODE_CACHE_SHIFT=6
CONFIG_X86_L1_CACHE_SHIFT=6
CONFIG_X86_TSC=y
CONFIG_X86_CMPXCHG64=y
CONFIG_X86_CMOV=y
CONFIG_X86_MINIMUM_CPU_FAMILY=64
CONFIG_X86_DEBUGCTLMSR=y
CONFIG_IA32_FEAT_CTL=y
CONFIG_X86_VMX_FEATURE_NAMES=y
CONFIG_CPU_SUP_INTEL=y
CONFIG_CPU_SUP_AMD=y
CONFIG_CPU_SUP_HYGON=y
CONFIG_CPU_SUP_CENTAUR=y
CONFIG_CPU_SUP_ZHAOXIN=y
CONFIG_HPET_TIMER=y
CONFIG_HPET_EMULATE_RTC=y
CONFIG_DMI=y
# CONFIG_GART_IOMMU is not set
CONFIG_BOOT_VESA_SUPPORT=y
CONFIG_MAXSMP=y
CONFIG_NR_CPUS_RANGE_BEGIN=8192
CONFIG_NR_CPUS_RANGE_END=8192
CONFIG_NR_CPUS_DEFAULT=8192
CONFIG_NR_CPUS=8192
CONFIG_SCHED_CLUSTER=y
CONFIG_SCHED_SMT=y
CONFIG_SCHED_MC=y
CONFIG_SCHED_MC_PRIO=y
CONFIG_X86_LOCAL_APIC=y
CONFIG_X86_IO_APIC=y
CONFIG_X86_REROUTE_FOR_BROKEN_BOOT_IRQS=y
CONFIG_X86_MCE=y
CONFIG_X86_MCELOG_LEGACY=y
CONFIG_X86_MCE_INTEL=y
CONFIG_X86_MCE_AMD=y
CONFIG_X86_MCE_THRESHOLD=y
CONFIG_X86_MCE_INJECT=m

#
# Performance monitoring
#
CONFIG_PERF_EVENTS_INTEL_UNCORE=m
CONFIG_PERF_EVENTS_INTEL_RAPL=m
CONFIG_PERF_EVENTS_INTEL_CSTATE=m
CONFIG_PERF_EVENTS_AMD_POWER=m
CONFIG_PERF_EVENTS_AMD_UNCORE=y
# CONFIG_PERF_EVENTS_AMD_BRS is not set
# end of Performance monitoring

CONFIG_X86_16BIT=y
CONFIG_X86_ESPFIX64=y
CONFIG_X86_VSYSCALL_EMULATION=y
CONFIG_X86_IOPL_IOPERM=y
CONFIG_MICROCODE=y
CONFIG_MICROCODE_INTEL=y
CONFIG_MICROCODE_AMD=y
# CONFIG_MICROCODE_LATE_LOADING is not set
CONFIG_X86_MSR=y
CONFIG_X86_CPUID=y
CONFIG_X86_5LEVEL=y
CONFIG_X86_DIRECT_GBPAGES=y
# CONFIG_X86_CPA_STATISTICS is not set
CONFIG_X86_MEM_ENCRYPT=y
CONFIG_AMD_MEM_ENCRYPT=y
# CONFIG_AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT is not set
CONFIG_NUMA=y
CONFIG_AMD_NUMA=y
CONFIG_X86_64_ACPI_NUMA=y
CONFIG_NUMA_EMU=y
CONFIG_NODES_SHIFT=10
CONFIG_ARCH_SPARSEMEM_ENABLE=y
CONFIG_ARCH_SPARSEMEM_DEFAULT=y
# CONFIG_ARCH_MEMORY_PROBE is not set
CONFIG_ARCH_PROC_KCORE_TEXT=y
CONFIG_ILLEGAL_POINTER_VALUE=0xdead000000000000
CONFIG_X86_PMEM_LEGACY_DEVICE=y
CONFIG_X86_PMEM_LEGACY=m
CONFIG_X86_CHECK_BIOS_CORRUPTION=y
# CONFIG_X86_BOOTPARAM_MEMORY_CORRUPTION_CHECK is not set
CONFIG_MTRR=y
CONFIG_MTRR_SANITIZER=y
CONFIG_MTRR_SANITIZER_ENABLE_DEFAULT=1
CONFIG_MTRR_SANITIZER_SPARE_REG_NR_DEFAULT=1
CONFIG_X86_PAT=y
CONFIG_ARCH_USES_PG_UNCACHED=y
CONFIG_X86_UMIP=y
CONFIG_CC_HAS_IBT=y
# CONFIG_X86_KERNEL_IBT is not set
CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=y
CONFIG_X86_INTEL_TSX_MODE_OFF=y
# CONFIG_X86_INTEL_TSX_MODE_ON is not set
# CONFIG_X86_INTEL_TSX_MODE_AUTO is not set
# CONFIG_X86_SGX is not set
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_EFI_MIXED=y
# CONFIG_HZ_100 is not set
# CONFIG_HZ_250 is not set
# CONFIG_HZ_300 is not set
CONFIG_HZ_1000=y
CONFIG_HZ=1000
CONFIG_SCHED_HRTICK=y
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
CONFIG_ARCH_HAS_KEXEC_PURGATORY=y
# CONFIG_KEXEC_SIG is not set
CONFIG_CRASH_DUMP=y
CONFIG_KEXEC_JUMP=y
CONFIG_PHYSICAL_START=0x1000000
CONFIG_RELOCATABLE=y
CONFIG_RANDOMIZE_BASE=y
CONFIG_X86_NEED_RELOCS=y
CONFIG_PHYSICAL_ALIGN=0x200000
CONFIG_DYNAMIC_MEMORY_LAYOUT=y
CONFIG_RANDOMIZE_MEMORY=y
CONFIG_RANDOMIZE_MEMORY_PHYSICAL_PADDING=0xa
CONFIG_HOTPLUG_CPU=y
CONFIG_BOOTPARAM_HOTPLUG_CPU0=y
# CONFIG_DEBUG_HOTPLUG_CPU0 is not set
# CONFIG_COMPAT_VDSO is not set
CONFIG_LEGACY_VSYSCALL_XONLY=y
# CONFIG_LEGACY_VSYSCALL_NONE is not set
# CONFIG_CMDLINE_BOOL is not set
CONFIG_MODIFY_LDT_SYSCALL=y
# CONFIG_STRICT_SIGALTSTACK_SIZE is not set
CONFIG_HAVE_LIVEPATCH=y
CONFIG_LIVEPATCH=y
# end of Processor type and features

CONFIG_CC_HAS_RETURN_THUNK=y
CONFIG_SPECULATION_MITIGATIONS=y
CONFIG_PAGE_TABLE_ISOLATION=y
CONFIG_RETPOLINE=y
CONFIG_RETHUNK=y
CONFIG_CPU_UNRET_ENTRY=y
CONFIG_CPU_IBPB_ENTRY=y
CONFIG_CPU_IBRS_ENTRY=y
CONFIG_ARCH_HAS_ADD_PAGES=y
CONFIG_ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE=y

#
# Power management and ACPI options
#
CONFIG_ARCH_HIBERNATION_HEADER=y
CONFIG_SUSPEND=y
CONFIG_SUSPEND_FREEZER=y
CONFIG_HIBERNATE_CALLBACKS=y
CONFIG_HIBERNATION=y
CONFIG_HIBERNATION_SNAPSHOT_DEV=y
CONFIG_PM_STD_PARTITION=""
CONFIG_PM_SLEEP=y
CONFIG_PM_SLEEP_SMP=y
# CONFIG_PM_AUTOSLEEP is not set
# CONFIG_PM_USERSPACE_AUTOSLEEP is not set
# CONFIG_PM_WAKELOCKS is not set
CONFIG_PM=y
CONFIG_PM_DEBUG=y
# CONFIG_PM_ADVANCED_DEBUG is not set
# CONFIG_PM_TEST_SUSPEND is not set
CONFIG_PM_SLEEP_DEBUG=y
# CONFIG_PM_TRACE_RTC is not set
CONFIG_PM_CLK=y
# CONFIG_WQ_POWER_EFFICIENT_DEFAULT is not set
# CONFIG_ENERGY_MODEL is not set
CONFIG_ARCH_SUPPORTS_ACPI=y
CONFIG_ACPI=y
CONFIG_ACPI_LEGACY_TABLES_LOOKUP=y
CONFIG_ARCH_MIGHT_HAVE_ACPI_PDC=y
CONFIG_ACPI_SYSTEM_POWER_STATES_SUPPORT=y
# CONFIG_ACPI_DEBUGGER is not set
CONFIG_ACPI_SPCR_TABLE=y
# CONFIG_ACPI_FPDT is not set
CONFIG_ACPI_LPIT=y
CONFIG_ACPI_SLEEP=y
CONFIG_ACPI_REV_OVERRIDE_POSSIBLE=y
CONFIG_ACPI_EC_DEBUGFS=m
CONFIG_ACPI_AC=y
CONFIG_ACPI_BATTERY=y
CONFIG_ACPI_BUTTON=y
CONFIG_ACPI_VIDEO=m
CONFIG_ACPI_FAN=y
CONFIG_ACPI_TAD=m
CONFIG_ACPI_DOCK=y
CONFIG_ACPI_CPU_FREQ_PSS=y
CONFIG_ACPI_PROCESSOR_CSTATE=y
CONFIG_ACPI_PROCESSOR_IDLE=y
CONFIG_ACPI_CPPC_LIB=y
CONFIG_ACPI_PROCESSOR=y
CONFIG_ACPI_IPMI=m
CONFIG_ACPI_HOTPLUG_CPU=y
CONFIG_ACPI_PROCESSOR_AGGREGATOR=m
CONFIG_ACPI_THERMAL=y
CONFIG_ACPI_PLATFORM_PROFILE=m
CONFIG_ARCH_HAS_ACPI_TABLE_UPGRADE=y
CONFIG_ACPI_TABLE_UPGRADE=y
# CONFIG_ACPI_DEBUG is not set
CONFIG_ACPI_PCI_SLOT=y
CONFIG_ACPI_CONTAINER=y
CONFIG_ACPI_HOTPLUG_MEMORY=y
CONFIG_ACPI_HOTPLUG_IOAPIC=y
CONFIG_ACPI_SBS=m
CONFIG_ACPI_HED=y
# CONFIG_ACPI_CUSTOM_METHOD is not set
CONFIG_ACPI_BGRT=y
CONFIG_ACPI_NFIT=m
# CONFIG_NFIT_SECURITY_DEBUG is not set
CONFIG_ACPI_NUMA=y
# CONFIG_ACPI_HMAT is not set
CONFIG_HAVE_ACPI_APEI=y
CONFIG_HAVE_ACPI_APEI_NMI=y
CONFIG_ACPI_APEI=y
CONFIG_ACPI_APEI_GHES=y
CONFIG_ACPI_APEI_PCIEAER=y
CONFIG_ACPI_APEI_MEMORY_FAILURE=y
CONFIG_ACPI_APEI_EINJ=m
CONFIG_ACPI_APEI_ERST_DEBUG=y
# CONFIG_ACPI_DPTF is not set
CONFIG_ACPI_WATCHDOG=y
CONFIG_ACPI_EXTLOG=m
CONFIG_ACPI_ADXL=y
# CONFIG_ACPI_CONFIGFS is not set
# CONFIG_ACPI_PFRUT is not set
CONFIG_ACPI_PCC=y
CONFIG_PMIC_OPREGION=y
CONFIG_ACPI_PRMT=y
CONFIG_X86_PM_TIMER=y

#
# CPU Frequency scaling
#
CONFIG_CPU_FREQ=y
CONFIG_CPU_FREQ_GOV_ATTR_SET=y
CONFIG_CPU_FREQ_GOV_COMMON=y
CONFIG_CPU_FREQ_STAT=y
CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE=y
# CONFIG_CPU_FREQ_DEFAULT_GOV_POWERSAVE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_USERSPACE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL is not set
CONFIG_CPU_FREQ_GOV_PERFORMANCE=y
CONFIG_CPU_FREQ_GOV_POWERSAVE=y
CONFIG_CPU_FREQ_GOV_USERSPACE=y
CONFIG_CPU_FREQ_GOV_ONDEMAND=y
CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y
CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y

#
# CPU frequency scaling drivers
#
CONFIG_X86_INTEL_PSTATE=y
# CONFIG_X86_PCC_CPUFREQ is not set
# CONFIG_X86_AMD_PSTATE is not set
# CONFIG_X86_AMD_PSTATE_UT is not set
CONFIG_X86_ACPI_CPUFREQ=m
CONFIG_X86_ACPI_CPUFREQ_CPB=y
CONFIG_X86_POWERNOW_K8=m
CONFIG_X86_AMD_FREQ_SENSITIVITY=m
# CONFIG_X86_SPEEDSTEP_CENTRINO is not set
CONFIG_X86_P4_CLOCKMOD=m

#
# shared options
#
CONFIG_X86_SPEEDSTEP_LIB=m
# end of CPU Frequency scaling

#
# CPU Idle
#
CONFIG_CPU_IDLE=y
# CONFIG_CPU_IDLE_GOV_LADDER is not set
CONFIG_CPU_IDLE_GOV_MENU=y
# CONFIG_CPU_IDLE_GOV_TEO is not set
# CONFIG_CPU_IDLE_GOV_HALTPOLL is not set
CONFIG_HALTPOLL_CPUIDLE=y
# end of CPU Idle

CONFIG_INTEL_IDLE=y
# end of Power management and ACPI options

#
# Bus options (PCI etc.)
#
CONFIG_PCI_DIRECT=y
CONFIG_PCI_MMCONFIG=y
CONFIG_PCI_XEN=y
CONFIG_MMCONF_FAM10H=y
CONFIG_ISA_DMA_API=y
CONFIG_AMD_NB=y
# end of Bus options (PCI etc.)

#
# Binary Emulations
#
CONFIG_IA32_EMULATION=y
# CONFIG_X86_X32_ABI is not set
CONFIG_COMPAT_32=y
CONFIG_COMPAT=y
CONFIG_COMPAT_FOR_U64_ALIGNMENT=y
# end of Binary Emulations

CONFIG_HAVE_KVM=y
CONFIG_HAVE_KVM_PFNCACHE=y
CONFIG_HAVE_KVM_IRQCHIP=y
CONFIG_HAVE_KVM_IRQFD=y
CONFIG_HAVE_KVM_IRQ_ROUTING=y
CONFIG_HAVE_KVM_DIRTY_RING=y
CONFIG_HAVE_KVM_EVENTFD=y
CONFIG_KVM_MMIO=y
CONFIG_KVM_ASYNC_PF=y
CONFIG_HAVE_KVM_MSI=y
CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT=y
CONFIG_KVM_VFIO=y
CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT=y
CONFIG_KVM_COMPAT=y
CONFIG_HAVE_KVM_IRQ_BYPASS=y
CONFIG_HAVE_KVM_NO_POLL=y
CONFIG_KVM_XFER_TO_GUEST_WORK=y
CONFIG_HAVE_KVM_PM_NOTIFIER=y
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=m
CONFIG_KVM_INTEL=m
# CONFIG_KVM_AMD is not set
# CONFIG_KVM_XEN is not set
CONFIG_AS_AVX512=y
CONFIG_AS_SHA1_NI=y
CONFIG_AS_SHA256_NI=y
CONFIG_AS_TPAUSE=y

#
# General architecture-dependent options
#
CONFIG_CRASH_CORE=y
CONFIG_KEXEC_CORE=y
CONFIG_HAVE_IMA_KEXEC=y
CONFIG_HOTPLUG_SMT=y
CONFIG_GENERIC_ENTRY=y
CONFIG_KPROBES=y
CONFIG_JUMP_LABEL=y
# CONFIG_STATIC_KEYS_SELFTEST is not set
# CONFIG_STATIC_CALL_SELFTEST is not set
CONFIG_OPTPROBES=y
CONFIG_KPROBES_ON_FTRACE=y
CONFIG_UPROBES=y
CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y
CONFIG_ARCH_USE_BUILTIN_BSWAP=y
CONFIG_KRETPROBES=y
CONFIG_KRETPROBE_ON_RETHOOK=y
CONFIG_USER_RETURN_NOTIFIER=y
CONFIG_HAVE_IOREMAP_PROT=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
CONFIG_HAVE_OPTPROBES=y
CONFIG_HAVE_KPROBES_ON_FTRACE=y
CONFIG_ARCH_CORRECT_STACKTRACE_ON_KRETPROBE=y
CONFIG_HAVE_FUNCTION_ERROR_INJECTION=y
CONFIG_HAVE_NMI=y
CONFIG_TRACE_IRQFLAGS_SUPPORT=y
CONFIG_TRACE_IRQFLAGS_NMI_SUPPORT=y
CONFIG_HAVE_ARCH_TRACEHOOK=y
CONFIG_HAVE_DMA_CONTIGUOUS=y
CONFIG_GENERIC_SMP_IDLE_THREAD=y
CONFIG_ARCH_HAS_FORTIFY_SOURCE=y
CONFIG_ARCH_HAS_SET_MEMORY=y
CONFIG_ARCH_HAS_SET_DIRECT_MAP=y
CONFIG_HAVE_ARCH_THREAD_STRUCT_WHITELIST=y
CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT=y
CONFIG_ARCH_WANTS_NO_INSTR=y
CONFIG_HAVE_ASM_MODVERSIONS=y
CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=y
CONFIG_HAVE_RSEQ=y
CONFIG_HAVE_RUST=y
CONFIG_HAVE_FUNCTION_ARG_ACCESS_API=y
CONFIG_HAVE_HW_BREAKPOINT=y
CONFIG_HAVE_MIXED_BREAKPOINTS_REGS=y
CONFIG_HAVE_USER_RETURN_NOTIFIER=y
CONFIG_HAVE_PERF_EVENTS_NMI=y
CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HAVE_PERF_REGS=y
CONFIG_HAVE_PERF_USER_STACK_DUMP=y
CONFIG_HAVE_ARCH_JUMP_LABEL=y
CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE=y
CONFIG_MMU_GATHER_TABLE_FREE=y
CONFIG_MMU_GATHER_RCU_TABLE_FREE=y
CONFIG_MMU_GATHER_MERGE_VMAS=y
CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG=y
CONFIG_HAVE_ALIGNED_STRUCT_PAGE=y
CONFIG_HAVE_CMPXCHG_LOCAL=y
CONFIG_HAVE_CMPXCHG_DOUBLE=y
CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION=y
CONFIG_ARCH_WANT_OLD_COMPAT_IPC=y
CONFIG_HAVE_ARCH_SECCOMP=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
# CONFIG_SECCOMP_CACHE_DEBUG is not set
CONFIG_HAVE_ARCH_STACKLEAK=y
CONFIG_HAVE_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_ARCH_SUPPORTS_LTO_CLANG=y
CONFIG_ARCH_SUPPORTS_LTO_CLANG_THIN=y
CONFIG_LTO_NONE=y
CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES=y
CONFIG_HAVE_CONTEXT_TRACKING_USER=y
CONFIG_HAVE_CONTEXT_TRACKING_USER_OFFSTACK=y
CONFIG_HAVE_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_HAVE_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_MOVE_PUD=y
CONFIG_HAVE_MOVE_PMD=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD=y
CONFIG_HAVE_ARCH_HUGE_VMAP=y
CONFIG_HAVE_ARCH_HUGE_VMALLOC=y
CONFIG_ARCH_WANT_HUGE_PMD_SHARE=y
CONFIG_HAVE_ARCH_SOFT_DIRTY=y
CONFIG_HAVE_MOD_ARCH_SPECIFIC=y
CONFIG_MODULES_USE_ELF_RELA=y
CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK=y
CONFIG_HAVE_SOFTIRQ_ON_OWN_STACK=y
CONFIG_ARCH_HAS_ELF_RANDOMIZE=y
CONFIG_HAVE_ARCH_MMAP_RND_BITS=y
CONFIG_HAVE_EXIT_THREAD=y
CONFIG_ARCH_MMAP_RND_BITS=28
CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=y
CONFIG_ARCH_MMAP_RND_COMPAT_BITS=8
CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES=y
CONFIG_PAGE_SIZE_LESS_THAN_64KB=y
CONFIG_PAGE_SIZE_LESS_THAN_256KB=y
CONFIG_HAVE_OBJTOOL=y
CONFIG_HAVE_JUMP_LABEL_HACK=y
CONFIG_HAVE_NOINSTR_HACK=y
CONFIG_HAVE_NOINSTR_VALIDATION=y
CONFIG_HAVE_UACCESS_VALIDATION=y
CONFIG_HAVE_STACK_VALIDATION=y
CONFIG_HAVE_RELIABLE_STACKTRACE=y
CONFIG_OLD_SIGSUSPEND3=y
CONFIG_COMPAT_OLD_SIGACTION=y
CONFIG_COMPAT_32BIT_TIME=y
CONFIG_HAVE_ARCH_VMAP_STACK=y
CONFIG_VMAP_STACK=y
CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET=y
# CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set
CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_ARCH_HAS_STRICT_MODULE_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
CONFIG_ARCH_USE_MEMREMAP_PROT=y
# CONFIG_LOCK_EVENT_COUNTS is not set
CONFIG_ARCH_HAS_MEM_ENCRYPT=y
CONFIG_ARCH_HAS_CC_PLATFORM=y
CONFIG_HAVE_STATIC_CALL=y
CONFIG_HAVE_STATIC_CALL_INLINE=y
CONFIG_HAVE_PREEMPT_DYNAMIC=y
CONFIG_HAVE_PREEMPT_DYNAMIC_CALL=y
CONFIG_ARCH_WANT_LD_ORPHAN_WARN=y
CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC=y
CONFIG_ARCH_SUPPORTS_PAGE_TABLE_CHECK=y
CONFIG_ARCH_HAS_ELFCORE_COMPAT=y
CONFIG_ARCH_HAS_PARANOID_L1D_FLUSH=y
CONFIG_DYNAMIC_SIGFRAME=y
CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG=y

#
# GCOV-based kernel profiling
#
# CONFIG_GCOV_KERNEL is not set
CONFIG_ARCH_HAS_GCOV_PROFILE_ALL=y
# end of GCOV-based kernel profiling

CONFIG_HAVE_GCC_PLUGINS=y
# end of General architecture-dependent options

CONFIG_RT_MUTEXES=y
CONFIG_BASE_SMALL=0
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULES=y
CONFIG_MODULE_FORCE_LOAD=y
CONFIG_MODULE_UNLOAD=y
# CONFIG_MODULE_FORCE_UNLOAD is not set
# CONFIG_MODULE_UNLOAD_TAINT_TRACKING is not set
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SRCVERSION_ALL is not set
CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE is not set
CONFIG_MODULE_SIG_ALL=y
# CONFIG_MODULE_SIG_SHA1 is not set
# CONFIG_MODULE_SIG_SHA224 is not set
CONFIG_MODULE_SIG_SHA256=y
# CONFIG_MODULE_SIG_SHA384 is not set
# CONFIG_MODULE_SIG_SHA512 is not set
CONFIG_MODULE_SIG_HASH="sha256"
CONFIG_MODULE_COMPRESS_NONE=y
# CONFIG_MODULE_COMPRESS_GZIP is not set
# CONFIG_MODULE_COMPRESS_XZ is not set
# CONFIG_MODULE_COMPRESS_ZSTD is not set
# CONFIG_MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS is not set
CONFIG_MODPROBE_PATH="/sbin/modprobe"
CONFIG_MODULES_TREE_LOOKUP=y
CONFIG_BLOCK=y
CONFIG_BLOCK_LEGACY_AUTOLOAD=y
CONFIG_BLK_CGROUP_RWSTAT=y
CONFIG_BLK_DEV_BSG_COMMON=y
CONFIG_BLK_ICQ=y
CONFIG_BLK_DEV_BSGLIB=y
CONFIG_BLK_DEV_INTEGRITY=y
CONFIG_BLK_DEV_INTEGRITY_T10=y
CONFIG_BLK_DEV_ZONED=y
CONFIG_BLK_DEV_THROTTLING=y
# CONFIG_BLK_DEV_THROTTLING_LOW is not set
CONFIG_BLK_WBT=y
CONFIG_BLK_WBT_MQ=y
# CONFIG_BLK_CGROUP_IOLATENCY is not set
# CONFIG_BLK_CGROUP_FC_APPID is not set
# CONFIG_BLK_CGROUP_IOCOST is not set
# CONFIG_BLK_CGROUP_IOPRIO is not set
CONFIG_BLK_DEBUG_FS=y
CONFIG_BLK_DEBUG_FS_ZONED=y
# CONFIG_BLK_SED_OPAL is not set
# CONFIG_BLK_INLINE_ENCRYPTION is not set

#
# Partition Types
#
CONFIG_PARTITION_ADVANCED=y
# CONFIG_ACORN_PARTITION is not set
# CONFIG_AIX_PARTITION is not set
CONFIG_OSF_PARTITION=y
CONFIG_AMIGA_PARTITION=y
# CONFIG_ATARI_PARTITION is not set
CONFIG_MAC_PARTITION=y
CONFIG_MSDOS_PARTITION=y
CONFIG_BSD_DISKLABEL=y
CONFIG_MINIX_SUBPARTITION=y
CONFIG_SOLARIS_X86_PARTITION=y
CONFIG_UNIXWARE_DISKLABEL=y
# CONFIG_LDM_PARTITION is not set
CONFIG_SGI_PARTITION=y
# CONFIG_ULTRIX_PARTITION is not set
CONFIG_SUN_PARTITION=y
CONFIG_KARMA_PARTITION=y
CONFIG_EFI_PARTITION=y
# CONFIG_SYSV68_PARTITION is not set
# CONFIG_CMDLINE_PARTITION is not set
# end of Partition Types

CONFIG_BLOCK_COMPAT=y
CONFIG_BLK_MQ_PCI=y
CONFIG_BLK_MQ_VIRTIO=y
CONFIG_BLK_MQ_RDMA=y
CONFIG_BLK_PM=y
CONFIG_BLOCK_HOLDER_DEPRECATED=y
CONFIG_BLK_MQ_STACKING=y

#
# IO Schedulers
#
CONFIG_MQ_IOSCHED_DEADLINE=y
CONFIG_MQ_IOSCHED_KYBER=y
CONFIG_IOSCHED_BFQ=y
CONFIG_BFQ_GROUP_IOSCHED=y
# CONFIG_BFQ_CGROUP_DEBUG is not set
# end of IO Schedulers

CONFIG_PREEMPT_NOTIFIERS=y
CONFIG_PADATA=y
CONFIG_ASN1=y
CONFIG_UNINLINE_SPIN_UNLOCK=y
CONFIG_ARCH_SUPPORTS_ATOMIC_RMW=y
CONFIG_MUTEX_SPIN_ON_OWNER=y
CONFIG_RWSEM_SPIN_ON_OWNER=y
CONFIG_LOCK_SPIN_ON_OWNER=y
CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y
CONFIG_QUEUED_SPINLOCKS=y
CONFIG_ARCH_USE_QUEUED_RWLOCKS=y
CONFIG_QUEUED_RWLOCKS=y
CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE=y
CONFIG_ARCH_HAS_SYNC_CORE_BEFORE_USERMODE=y
CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y
CONFIG_FREEZER=y

#
# Executable file formats
#
CONFIG_BINFMT_ELF=y
# CONFIG_BINFMT_ELF_KUNIT_TEST is not set
CONFIG_COMPAT_BINFMT_ELF=y
CONFIG_ELFCORE=y
CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_BINFMT_MISC=m
CONFIG_COREDUMP=y
# end of Executable file formats

#
# Memory Management options
#
CONFIG_ZPOOL=y
CONFIG_SWAP=y
CONFIG_ZSWAP=y
# CONFIG_ZSWAP_DEFAULT_ON is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_DEFLATE is not set
CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZO=y
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_842 is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZ4 is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZ4HC is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_ZSTD is not set
CONFIG_ZSWAP_COMPRESSOR_DEFAULT="lzo"
CONFIG_ZSWAP_ZPOOL_DEFAULT_ZBUD=y
# CONFIG_ZSWAP_ZPOOL_DEFAULT_Z3FOLD is not set
# CONFIG_ZSWAP_ZPOOL_DEFAULT_ZSMALLOC is not set
CONFIG_ZSWAP_ZPOOL_DEFAULT="zbud"
CONFIG_ZBUD=y
# CONFIG_Z3FOLD is not set
CONFIG_ZSMALLOC=y
CONFIG_ZSMALLOC_STAT=y

#
# SLAB allocator options
#
# CONFIG_SLAB is not set
CONFIG_SLUB=y
CONFIG_SLAB_MERGE_DEFAULT=y
CONFIG_SLAB_FREELIST_RANDOM=y
# CONFIG_SLAB_FREELIST_HARDENED is not set
# CONFIG_SLUB_STATS is not set
CONFIG_SLUB_CPU_PARTIAL=y
# end of SLAB allocator options

CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
# CONFIG_COMPAT_BRK is not set
CONFIG_SPARSEMEM=y
CONFIG_SPARSEMEM_EXTREME=y
CONFIG_SPARSEMEM_VMEMMAP_ENABLE=y
CONFIG_SPARSEMEM_VMEMMAP=y
CONFIG_HAVE_FAST_GUP=y
CONFIG_NUMA_KEEP_MEMINFO=y
CONFIG_MEMORY_ISOLATION=y
CONFIG_EXCLUSIVE_SYSTEM_RAM=y
CONFIG_HAVE_BOOTMEM_INFO_NODE=y
CONFIG_ARCH_ENABLE_MEMORY_HOTPLUG=y
CONFIG_ARCH_ENABLE_MEMORY_HOTREMOVE=y
CONFIG_MEMORY_HOTPLUG=y
# CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE is not set
CONFIG_MEMORY_HOTREMOVE=y
CONFIG_MHP_MEMMAP_ON_MEMORY=y
CONFIG_SPLIT_PTLOCK_CPUS=4
CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK=y
CONFIG_MEMORY_BALLOON=y
CONFIG_BALLOON_COMPACTION=y
CONFIG_COMPACTION=y
CONFIG_PAGE_REPORTING=y
CONFIG_MIGRATION=y
CONFIG_DEVICE_MIGRATION=y
CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION=y
CONFIG_ARCH_ENABLE_THP_MIGRATION=y
CONFIG_CONTIG_ALLOC=y
CONFIG_PHYS_ADDR_T_64BIT=y
CONFIG_MMU_NOTIFIER=y
CONFIG_KSM=y
CONFIG_DEFAULT_MMAP_MIN_ADDR=4096
CONFIG_ARCH_SUPPORTS_MEMORY_FAILURE=y
CONFIG_MEMORY_FAILURE=y
CONFIG_HWPOISON_INJECT=m
CONFIG_ARCH_WANT_GENERAL_HUGETLB=y
CONFIG_ARCH_WANTS_THP_SWAP=y
CONFIG_TRANSPARENT_HUGEPAGE=y
CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS=y
# CONFIG_TRANSPARENT_HUGEPAGE_MADVISE is not set
CONFIG_THP_SWAP=y
# CONFIG_READ_ONLY_THP_FOR_FS is not set
CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK=y
CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK=y
CONFIG_USE_PERCPU_NUMA_NODE_ID=y
CONFIG_HAVE_SETUP_PER_CPU_AREA=y
CONFIG_FRONTSWAP=y
CONFIG_CMA=y
# CONFIG_CMA_DEBUG is not set
# CONFIG_CMA_DEBUGFS is not set
# CONFIG_CMA_SYSFS is not set
CONFIG_CMA_AREAS=7
CONFIG_GENERIC_EARLY_IOREMAP=y
CONFIG_DEFERRED_STRUCT_PAGE_INIT=y
CONFIG_PAGE_IDLE_FLAG=y
CONFIG_IDLE_PAGE_TRACKING=y
CONFIG_ARCH_HAS_CACHE_LINE_SIZE=y
CONFIG_ARCH_HAS_CURRENT_STACK_POINTER=y
CONFIG_ARCH_HAS_PTE_DEVMAP=y
CONFIG_ZONE_DMA=y
CONFIG_ZONE_DMA32=y
CONFIG_ZONE_DEVICE=y
CONFIG_HMM_MIRROR=y
CONFIG_GET_FREE_REGION=y
CONFIG_DEVICE_PRIVATE=y
CONFIG_VMAP_PFN=y
CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y
CONFIG_ARCH_HAS_PKEYS=y
CONFIG_VM_EVENT_COUNTERS=y
# CONFIG_PERCPU_STATS is not set
# CONFIG_GUP_TEST is not set
CONFIG_ARCH_HAS_PTE_SPECIAL=y
CONFIG_MAPPING_DIRTY_HELPERS=y
CONFIG_SECRETMEM=y
# CONFIG_ANON_VMA_NAME is not set
CONFIG_USERFAULTFD=y
CONFIG_HAVE_ARCH_USERFAULTFD_WP=y
CONFIG_HAVE_ARCH_USERFAULTFD_MINOR=y
CONFIG_PTE_MARKER=y
CONFIG_PTE_MARKER_UFFD_WP=y
# CONFIG_LRU_GEN is not set

#
# Data Access Monitoring
#
CONFIG_DAMON=y
CONFIG_DAMON_KUNIT_TEST=y
CONFIG_DAMON_VADDR=y
CONFIG_DAMON_PADDR=y
CONFIG_DAMON_VADDR_KUNIT_TEST=y
# CONFIG_DAMON_SYSFS is not set
CONFIG_DAMON_DBGFS=y
CONFIG_DAMON_DBGFS_KUNIT_TEST=y
CONFIG_DAMON_RECLAIM=y
# CONFIG_DAMON_LRU_SORT is not set
# end of Data Access Monitoring
# end of Memory Management options

CONFIG_NET=y
CONFIG_COMPAT_NETLINK_MESSAGES=y
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_SKB_EXTENSIONS=y

#
# Networking options
#
CONFIG_PACKET=y
CONFIG_PACKET_DIAG=m
CONFIG_UNIX=y
CONFIG_UNIX_SCM=y
CONFIG_AF_UNIX_OOB=y
CONFIG_UNIX_DIAG=m
CONFIG_TLS=m
CONFIG_TLS_DEVICE=y
# CONFIG_TLS_TOE is not set
CONFIG_XFRM=y
CONFIG_XFRM_OFFLOAD=y
CONFIG_XFRM_ALGO=y
CONFIG_XFRM_USER=y
# CONFIG_XFRM_USER_COMPAT is not set
# CONFIG_XFRM_INTERFACE is not set
CONFIG_XFRM_SUB_POLICY=y
CONFIG_XFRM_MIGRATE=y
CONFIG_XFRM_STATISTICS=y
CONFIG_XFRM_AH=m
CONFIG_XFRM_ESP=m
CONFIG_XFRM_IPCOMP=m
CONFIG_NET_KEY=m
CONFIG_NET_KEY_MIGRATE=y
# CONFIG_SMC is not set
CONFIG_XDP_SOCKETS=y
# CONFIG_XDP_SOCKETS_DIAG is not set
CONFIG_INET=y
CONFIG_IP_MULTICAST=y
CONFIG_IP_ADVANCED_ROUTER=y
CONFIG_IP_FIB_TRIE_STATS=y
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_IP_ROUTE_MULTIPATH=y
CONFIG_IP_ROUTE_VERBOSE=y
CONFIG_IP_ROUTE_CLASSID=y
CONFIG_IP_PNP=y
CONFIG_IP_PNP_DHCP=y
# CONFIG_IP_PNP_BOOTP is not set
# CONFIG_IP_PNP_RARP is not set
CONFIG_NET_IPIP=y
CONFIG_NET_IPGRE_DEMUX=y
CONFIG_NET_IP_TUNNEL=y
CONFIG_NET_IPGRE=y
CONFIG_NET_IPGRE_BROADCAST=y
CONFIG_IP_MROUTE_COMMON=y
CONFIG_IP_MROUTE=y
CONFIG_IP_MROUTE_MULTIPLE_TABLES=y
CONFIG_IP_PIMSM_V1=y
CONFIG_IP_PIMSM_V2=y
CONFIG_SYN_COOKIES=y
CONFIG_NET_IPVTI=m
CONFIG_NET_UDP_TUNNEL=m
# CONFIG_NET_FOU is not set
# CONFIG_NET_FOU_IP_TUNNELS is not set
CONFIG_INET_AH=m
CONFIG_INET_ESP=m
CONFIG_INET_ESP_OFFLOAD=m
# CONFIG_INET_ESPINTCP is not set
CONFIG_INET_IPCOMP=m
CONFIG_INET_XFRM_TUNNEL=m
CONFIG_INET_TUNNEL=y
CONFIG_INET_DIAG=m
CONFIG_INET_TCP_DIAG=m
CONFIG_INET_UDP_DIAG=m
CONFIG_INET_RAW_DIAG=m
# CONFIG_INET_DIAG_DESTROY is not set
CONFIG_TCP_CONG_ADVANCED=y
CONFIG_TCP_CONG_BIC=m
CONFIG_TCP_CONG_CUBIC=y
CONFIG_TCP_CONG_WESTWOOD=m
CONFIG_TCP_CONG_HTCP=m
CONFIG_TCP_CONG_HSTCP=m
CONFIG_TCP_CONG_HYBLA=m
CONFIG_TCP_CONG_VEGAS=m
CONFIG_TCP_CONG_NV=m
CONFIG_TCP_CONG_SCALABLE=m
CONFIG_TCP_CONG_LP=m
CONFIG_TCP_CONG_VENO=m
CONFIG_TCP_CONG_YEAH=m
CONFIG_TCP_CONG_ILLINOIS=m
CONFIG_TCP_CONG_DCTCP=m
# CONFIG_TCP_CONG_CDG is not set
CONFIG_TCP_CONG_BBR=m
CONFIG_DEFAULT_CUBIC=y
# CONFIG_DEFAULT_RENO is not set
CONFIG_DEFAULT_TCP_CONG="cubic"
CONFIG_TCP_MD5SIG=y
CONFIG_IPV6=y
CONFIG_IPV6_ROUTER_PREF=y
CONFIG_IPV6_ROUTE_INFO=y
CONFIG_IPV6_OPTIMISTIC_DAD=y
CONFIG_INET6_AH=m
CONFIG_INET6_ESP=m
CONFIG_INET6_ESP_OFFLOAD=m
# CONFIG_INET6_ESPINTCP is not set
CONFIG_INET6_IPCOMP=m
CONFIG_IPV6_MIP6=m
# CONFIG_IPV6_ILA is not set
CONFIG_INET6_XFRM_TUNNEL=m
CONFIG_INET6_TUNNEL=m
CONFIG_IPV6_VTI=m
CONFIG_IPV6_SIT=m
CONFIG_IPV6_SIT_6RD=y
CONFIG_IPV6_NDISC_NODETYPE=y
CONFIG_IPV6_TUNNEL=m
CONFIG_IPV6_GRE=m
CONFIG_IPV6_MULTIPLE_TABLES=y
# CONFIG_IPV6_SUBTREES is not set
CONFIG_IPV6_MROUTE=y
CONFIG_IPV6_MROUTE_MULTIPLE_TABLES=y
CONFIG_IPV6_PIMSM_V2=y
# CONFIG_IPV6_SEG6_LWTUNNEL is not set
# CONFIG_IPV6_SEG6_HMAC is not set
# CONFIG_IPV6_RPL_LWTUNNEL is not set
# CONFIG_IPV6_IOAM6_LWTUNNEL is not set
CONFIG_NETLABEL=y
# CONFIG_MPTCP is not set
CONFIG_NETWORK_SECMARK=y
CONFIG_NET_PTP_CLASSIFY=y
CONFIG_NETWORK_PHY_TIMESTAMPING=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_BRIDGE_NETFILTER=m

#
# Core Netfilter Configuration
#
CONFIG_NETFILTER_INGRESS=y
CONFIG_NETFILTER_EGRESS=y
CONFIG_NETFILTER_SKIP_EGRESS=y
CONFIG_NETFILTER_NETLINK=m
CONFIG_NETFILTER_FAMILY_BRIDGE=y
CONFIG_NETFILTER_FAMILY_ARP=y
# CONFIG_NETFILTER_NETLINK_HOOK is not set
# CONFIG_NETFILTER_NETLINK_ACCT is not set
CONFIG_NETFILTER_NETLINK_QUEUE=m
CONFIG_NETFILTER_NETLINK_LOG=m
CONFIG_NETFILTER_NETLINK_OSF=m
CONFIG_NF_CONNTRACK=m
CONFIG_NF_LOG_SYSLOG=m
CONFIG_NETFILTER_CONNCOUNT=m
CONFIG_NF_CONNTRACK_MARK=y
CONFIG_NF_CONNTRACK_SECMARK=y
CONFIG_NF_CONNTRACK_ZONES=y
CONFIG_NF_CONNTRACK_PROCFS=y
CONFIG_NF_CONNTRACK_EVENTS=y
CONFIG_NF_CONNTRACK_TIMEOUT=y
CONFIG_NF_CONNTRACK_TIMESTAMP=y
CONFIG_NF_CONNTRACK_LABELS=y
CONFIG_NF_CT_PROTO_DCCP=y
CONFIG_NF_CT_PROTO_GRE=y
CONFIG_NF_CT_PROTO_SCTP=y
CONFIG_NF_CT_PROTO_UDPLITE=y
CONFIG_NF_CONNTRACK_AMANDA=m
CONFIG_NF_CONNTRACK_FTP=m
CONFIG_NF_CONNTRACK_H323=m
CONFIG_NF_CONNTRACK_IRC=m
CONFIG_NF_CONNTRACK_BROADCAST=m
CONFIG_NF_CONNTRACK_NETBIOS_NS=m
CONFIG_NF_CONNTRACK_SNMP=m
CONFIG_NF_CONNTRACK_PPTP=m
CONFIG_NF_CONNTRACK_SANE=m
CONFIG_NF_CONNTRACK_SIP=m
CONFIG_NF_CONNTRACK_TFTP=m
CONFIG_NF_CT_NETLINK=m
CONFIG_NF_CT_NETLINK_TIMEOUT=m
CONFIG_NF_CT_NETLINK_HELPER=m
CONFIG_NETFILTER_NETLINK_GLUE_CT=y
CONFIG_NF_NAT=m
CONFIG_NF_NAT_AMANDA=m
CONFIG_NF_NAT_FTP=m
CONFIG_NF_NAT_IRC=m
CONFIG_NF_NAT_SIP=m
CONFIG_NF_NAT_TFTP=m
CONFIG_NF_NAT_REDIRECT=y
CONFIG_NF_NAT_MASQUERADE=y
CONFIG_NETFILTER_SYNPROXY=m
CONFIG_NF_TABLES=m
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_NETDEV=y
CONFIG_NFT_NUMGEN=m
CONFIG_NFT_CT=m
CONFIG_NFT_CONNLIMIT=m
CONFIG_NFT_LOG=m
CONFIG_NFT_LIMIT=m
CONFIG_NFT_MASQ=m
CONFIG_NFT_REDIR=m
CONFIG_NFT_NAT=m
# CONFIG_NFT_TUNNEL is not set
CONFIG_NFT_OBJREF=m
CONFIG_NFT_QUEUE=m
CONFIG_NFT_QUOTA=m
CONFIG_NFT_REJECT=m
CONFIG_NFT_REJECT_INET=m
CONFIG_NFT_COMPAT=m
CONFIG_NFT_HASH=m
CONFIG_NFT_FIB=m
CONFIG_NFT_FIB_INET=m
# CONFIG_NFT_XFRM is not set
CONFIG_NFT_SOCKET=m
# CONFIG_NFT_OSF is not set
# CONFIG_NFT_TPROXY is not set
# CONFIG_NFT_SYNPROXY is not set
CONFIG_NF_DUP_NETDEV=m
CONFIG_NFT_DUP_NETDEV=m
CONFIG_NFT_FWD_NETDEV=m
CONFIG_NFT_FIB_NETDEV=m
# CONFIG_NFT_REJECT_NETDEV is not set
# CONFIG_NF_FLOW_TABLE is not set
CONFIG_NETFILTER_XTABLES=y
CONFIG_NETFILTER_XTABLES_COMPAT=y

#
# Xtables combined modules
#
CONFIG_NETFILTER_XT_MARK=m
CONFIG_NETFILTER_XT_CONNMARK=m
CONFIG_NETFILTER_XT_SET=m

#
# Xtables targets
#
CONFIG_NETFILTER_XT_TARGET_AUDIT=m
CONFIG_NETFILTER_XT_TARGET_CHECKSUM=m
CONFIG_NETFILTER_XT_TARGET_CLASSIFY=m
CONFIG_NETFILTER_XT_TARGET_CONNMARK=m
CONFIG_NETFILTER_XT_TARGET_CONNSECMARK=m
CONFIG_NETFILTER_XT_TARGET_CT=m
CONFIG_NETFILTER_XT_TARGET_DSCP=m
CONFIG_NETFILTER_XT_TARGET_HL=m
CONFIG_NETFILTER_XT_TARGET_HMARK=m
CONFIG_NETFILTER_XT_TARGET_IDLETIMER=m
# CONFIG_NETFILTER_XT_TARGET_LED is not set
CONFIG_NETFILTER_XT_TARGET_LOG=m
CONFIG_NETFILTER_XT_TARGET_MARK=m
CONFIG_NETFILTER_XT_NAT=m
CONFIG_NETFILTER_XT_TARGET_NETMAP=m
CONFIG_NETFILTER_XT_TARGET_NFLOG=m
CONFIG_NETFILTER_XT_TARGET_NFQUEUE=m
CONFIG_NETFILTER_XT_TARGET_NOTRACK=m
CONFIG_NETFILTER_XT_TARGET_RATEEST=m
CONFIG_NETFILTER_XT_TARGET_REDIRECT=m
CONFIG_NETFILTER_XT_TARGET_MASQUERADE=m
CONFIG_NETFILTER_XT_TARGET_TEE=m
CONFIG_NETFILTER_XT_TARGET_TPROXY=m
CONFIG_NETFILTER_XT_TARGET_TRACE=m
CONFIG_NETFILTER_XT_TARGET_SECMARK=m
CONFIG_NETFILTER_XT_TARGET_TCPMSS=m
CONFIG_NETFILTER_XT_TARGET_TCPOPTSTRIP=m

#
# Xtables matches
#
CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=m
CONFIG_NETFILTER_XT_MATCH_BPF=m
CONFIG_NETFILTER_XT_MATCH_CGROUP=m
CONFIG_NETFILTER_XT_MATCH_CLUSTER=m
CONFIG_NETFILTER_XT_MATCH_COMMENT=m
CONFIG_NETFILTER_XT_MATCH_CONNBYTES=m
CONFIG_NETFILTER_XT_MATCH_CONNLABEL=m
CONFIG_NETFILTER_XT_MATCH_CONNLIMIT=m
CONFIG_NETFILTER_XT_MATCH_CONNMARK=m
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=m
CONFIG_NETFILTER_XT_MATCH_CPU=m
CONFIG_NETFILTER_XT_MATCH_DCCP=m
CONFIG_NETFILTER_XT_MATCH_DEVGROUP=m
CONFIG_NETFILTER_XT_MATCH_DSCP=m
CONFIG_NETFILTER_XT_MATCH_ECN=m
CONFIG_NETFILTER_XT_MATCH_ESP=m
CONFIG_NETFILTER_XT_MATCH_HASHLIMIT=m
CONFIG_NETFILTER_XT_MATCH_HELPER=m
CONFIG_NETFILTER_XT_MATCH_HL=m
# CONFIG_NETFILTER_XT_MATCH_IPCOMP is not set
CONFIG_NETFILTER_XT_MATCH_IPRANGE=m
CONFIG_NETFILTER_XT_MATCH_IPVS=m
# CONFIG_NETFILTER_XT_MATCH_L2TP is not set
CONFIG_NETFILTER_XT_MATCH_LENGTH=m
CONFIG_NETFILTER_XT_MATCH_LIMIT=m
CONFIG_NETFILTER_XT_MATCH_MAC=m
CONFIG_NETFILTER_XT_MATCH_MARK=m
CONFIG_NETFILTER_XT_MATCH_MULTIPORT=m
# CONFIG_NETFILTER_XT_MATCH_NFACCT is not set
CONFIG_NETFILTER_XT_MATCH_OSF=m
CONFIG_NETFILTER_XT_MATCH_OWNER=m
CONFIG_NETFILTER_XT_MATCH_POLICY=m
CONFIG_NETFILTER_XT_MATCH_PHYSDEV=m
CONFIG_NETFILTER_XT_MATCH_PKTTYPE=m
CONFIG_NETFILTER_XT_MATCH_QUOTA=m
CONFIG_NETFILTER_XT_MATCH_RATEEST=m
CONFIG_NETFILTER_XT_MATCH_REALM=m
CONFIG_NETFILTER_XT_MATCH_RECENT=m
CONFIG_NETFILTER_XT_MATCH_SCTP=m
CONFIG_NETFILTER_XT_MATCH_SOCKET=m
CONFIG_NETFILTER_XT_MATCH_STATE=m
CONFIG_NETFILTER_XT_MATCH_STATISTIC=m
CONFIG_NETFILTER_XT_MATCH_STRING=m
CONFIG_NETFILTER_XT_MATCH_TCPMSS=m
# CONFIG_NETFILTER_XT_MATCH_TIME is not set
# CONFIG_NETFILTER_XT_MATCH_U32 is not set
# end of Core Netfilter Configuration

CONFIG_IP_SET=m
CONFIG_IP_SET_MAX=256
CONFIG_IP_SET_BITMAP_IP=m
CONFIG_IP_SET_BITMAP_IPMAC=m
CONFIG_IP_SET_BITMAP_PORT=m
CONFIG_IP_SET_HASH_IP=m
CONFIG_IP_SET_HASH_IPMARK=m
CONFIG_IP_SET_HASH_IPPORT=m
CONFIG_IP_SET_HASH_IPPORTIP=m
CONFIG_IP_SET_HASH_IPPORTNET=m
CONFIG_IP_SET_HASH_IPMAC=m
CONFIG_IP_SET_HASH_MAC=m
CONFIG_IP_SET_HASH_NETPORTNET=m
CONFIG_IP_SET_HASH_NET=m
CONFIG_IP_SET_HASH_NETNET=m
CONFIG_IP_SET_HASH_NETPORT=m
CONFIG_IP_SET_HASH_NETIFACE=m
CONFIG_IP_SET_LIST_SET=m
CONFIG_IP_VS=m
CONFIG_IP_VS_IPV6=y
# CONFIG_IP_VS_DEBUG is not set
CONFIG_IP_VS_TAB_BITS=12

#
# IPVS transport protocol load balancing support
#
CONFIG_IP_VS_PROTO_TCP=y
CONFIG_IP_VS_PROTO_UDP=y
CONFIG_IP_VS_PROTO_AH_ESP=y
CONFIG_IP_VS_PROTO_ESP=y
CONFIG_IP_VS_PROTO_AH=y
CONFIG_IP_VS_PROTO_SCTP=y

#
# IPVS scheduler
#
CONFIG_IP_VS_RR=m
CONFIG_IP_VS_WRR=m
CONFIG_IP_VS_LC=m
CONFIG_IP_VS_WLC=m
CONFIG_IP_VS_FO=m
CONFIG_IP_VS_OVF=m
CONFIG_IP_VS_LBLC=m
CONFIG_IP_VS_LBLCR=m
CONFIG_IP_VS_DH=m
CONFIG_IP_VS_SH=m
# CONFIG_IP_VS_MH is not set
CONFIG_IP_VS_SED=m
CONFIG_IP_VS_NQ=m
# CONFIG_IP_VS_TWOS is not set

#
# IPVS SH scheduler
#
CONFIG_IP_VS_SH_TAB_BITS=8

#
# IPVS MH scheduler
#
CONFIG_IP_VS_MH_TAB_INDEX=12

#
# IPVS application helper
#
CONFIG_IP_VS_FTP=m
CONFIG_IP_VS_NFCT=y
CONFIG_IP_VS_PE_SIP=m

#
# IP: Netfilter Configuration
#
CONFIG_NF_DEFRAG_IPV4=m
CONFIG_NF_SOCKET_IPV4=m
CONFIG_NF_TPROXY_IPV4=m
CONFIG_NF_TABLES_IPV4=y
CONFIG_NFT_REJECT_IPV4=m
CONFIG_NFT_DUP_IPV4=m
CONFIG_NFT_FIB_IPV4=m
CONFIG_NF_TABLES_ARP=y
CONFIG_NF_DUP_IPV4=m
CONFIG_NF_LOG_ARP=m
CONFIG_NF_LOG_IPV4=m
CONFIG_NF_REJECT_IPV4=m
CONFIG_NF_NAT_SNMP_BASIC=m
CONFIG_NF_NAT_PPTP=m
CONFIG_NF_NAT_H323=m
CONFIG_IP_NF_IPTABLES=m
CONFIG_IP_NF_MATCH_AH=m
CONFIG_IP_NF_MATCH_ECN=m
CONFIG_IP_NF_MATCH_RPFILTER=m
CONFIG_IP_NF_MATCH_TTL=m
CONFIG_IP_NF_FILTER=m
CONFIG_IP_NF_TARGET_REJECT=m
CONFIG_IP_NF_TARGET_SYNPROXY=m
CONFIG_IP_NF_NAT=m
CONFIG_IP_NF_TARGET_MASQUERADE=m
CONFIG_IP_NF_TARGET_NETMAP=m
CONFIG_IP_NF_TARGET_REDIRECT=m
CONFIG_IP_NF_MANGLE=m
# CONFIG_IP_NF_TARGET_CLUSTERIP is not set
CONFIG_IP_NF_TARGET_ECN=m
CONFIG_IP_NF_TARGET_TTL=m
CONFIG_IP_NF_RAW=m
CONFIG_IP_NF_SECURITY=m
CONFIG_IP_NF_ARPTABLES=m
CONFIG_IP_NF_ARPFILTER=m
CONFIG_IP_NF_ARP_MANGLE=m
# end of IP: Netfilter Configuration

#
# IPv6: Netfilter Configuration
#
CONFIG_NF_SOCKET_IPV6=m
CONFIG_NF_TPROXY_IPV6=m
CONFIG_NF_TABLES_IPV6=y
CONFIG_NFT_REJECT_IPV6=m
CONFIG_NFT_DUP_IPV6=m
CONFIG_NFT_FIB_IPV6=m
CONFIG_NF_DUP_IPV6=m
CONFIG_NF_REJECT_IPV6=m
CONFIG_NF_LOG_IPV6=m
CONFIG_IP6_NF_IPTABLES=m
CONFIG_IP6_NF_MATCH_AH=m
CONFIG_IP6_NF_MATCH_EUI64=m
CONFIG_IP6_NF_MATCH_FRAG=m
CONFIG_IP6_NF_MATCH_OPTS=m
CONFIG_IP6_NF_MATCH_HL=m
CONFIG_IP6_NF_MATCH_IPV6HEADER=m
CONFIG_IP6_NF_MATCH_MH=m
CONFIG_IP6_NF_MATCH_RPFILTER=m
CONFIG_IP6_NF_MATCH_RT=m
# CONFIG_IP6_NF_MATCH_SRH is not set
# CONFIG_IP6_NF_TARGET_HL is not set
CONFIG_IP6_NF_FILTER=m
CONFIG_IP6_NF_TARGET_REJECT=m
CONFIG_IP6_NF_TARGET_SYNPROXY=m
CONFIG_IP6_NF_MANGLE=m
CONFIG_IP6_NF_RAW=m
CONFIG_IP6_NF_SECURITY=m
CONFIG_IP6_NF_NAT=m
CONFIG_IP6_NF_TARGET_MASQUERADE=m
CONFIG_IP6_NF_TARGET_NPT=m
# end of IPv6: Netfilter Configuration

CONFIG_NF_DEFRAG_IPV6=m
CONFIG_NF_TABLES_BRIDGE=m
# CONFIG_NFT_BRIDGE_META is not set
CONFIG_NFT_BRIDGE_REJECT=m
# CONFIG_NF_CONNTRACK_BRIDGE is not set
CONFIG_BRIDGE_NF_EBTABLES=m
CONFIG_BRIDGE_EBT_BROUTE=m
CONFIG_BRIDGE_EBT_T_FILTER=m
CONFIG_BRIDGE_EBT_T_NAT=m
CONFIG_BRIDGE_EBT_802_3=m
CONFIG_BRIDGE_EBT_AMONG=m
CONFIG_BRIDGE_EBT_ARP=m
CONFIG_BRIDGE_EBT_IP=m
CONFIG_BRIDGE_EBT_IP6=m
CONFIG_BRIDGE_EBT_LIMIT=m
CONFIG_BRIDGE_EBT_MARK=m
CONFIG_BRIDGE_EBT_PKTTYPE=m
CONFIG_BRIDGE_EBT_STP=m
CONFIG_BRIDGE_EBT_VLAN=m
CONFIG_BRIDGE_EBT_ARPREPLY=m
CONFIG_BRIDGE_EBT_DNAT=m
CONFIG_BRIDGE_EBT_MARK_T=m
CONFIG_BRIDGE_EBT_REDIRECT=m
CONFIG_BRIDGE_EBT_SNAT=m
CONFIG_BRIDGE_EBT_LOG=m
CONFIG_BRIDGE_EBT_NFLOG=m
# CONFIG_BPFILTER is not set
# CONFIG_IP_DCCP is not set
CONFIG_IP_SCTP=m
# CONFIG_SCTP_DBG_OBJCNT is not set
# CONFIG_SCTP_DEFAULT_COOKIE_HMAC_MD5 is not set
CONFIG_SCTP_DEFAULT_COOKIE_HMAC_SHA1=y
# CONFIG_SCTP_DEFAULT_COOKIE_HMAC_NONE is not set
CONFIG_SCTP_COOKIE_HMAC_MD5=y
CONFIG_SCTP_COOKIE_HMAC_SHA1=y
CONFIG_INET_SCTP_DIAG=m
# CONFIG_RDS is not set
CONFIG_TIPC=m
# CONFIG_TIPC_MEDIA_IB is not set
CONFIG_TIPC_MEDIA_UDP=y
CONFIG_TIPC_CRYPTO=y
CONFIG_TIPC_DIAG=m
CONFIG_ATM=m
CONFIG_ATM_CLIP=m
# CONFIG_ATM_CLIP_NO_ICMP is not set
CONFIG_ATM_LANE=m
# CONFIG_ATM_MPOA is not set
CONFIG_ATM_BR2684=m
# CONFIG_ATM_BR2684_IPFILTER is not set
CONFIG_L2TP=m
CONFIG_L2TP_DEBUGFS=m
CONFIG_L2TP_V3=y
CONFIG_L2TP_IP=m
CONFIG_L2TP_ETH=m
CONFIG_STP=m
CONFIG_GARP=m
CONFIG_MRP=m
CONFIG_BRIDGE=m
CONFIG_BRIDGE_IGMP_SNOOPING=y
CONFIG_BRIDGE_VLAN_FILTERING=y
# CONFIG_BRIDGE_MRP is not set
# CONFIG_BRIDGE_CFM is not set
# CONFIG_NET_DSA is not set
CONFIG_VLAN_8021Q=m
CONFIG_VLAN_8021Q_GVRP=y
CONFIG_VLAN_8021Q_MVRP=y
CONFIG_LLC=m
# CONFIG_LLC2 is not set
# CONFIG_ATALK is not set
# CONFIG_X25 is not set
# CONFIG_LAPB is not set
# CONFIG_PHONET is not set
CONFIG_6LOWPAN=m
# CONFIG_6LOWPAN_DEBUGFS is not set
# CONFIG_6LOWPAN_NHC is not set
CONFIG_IEEE802154=m
# CONFIG_IEEE802154_NL802154_EXPERIMENTAL is not set
CONFIG_IEEE802154_SOCKET=m
CONFIG_IEEE802154_6LOWPAN=m
CONFIG_MAC802154=m
CONFIG_NET_SCHED=y

#
# Queueing/Scheduling
#
CONFIG_NET_SCH_CBQ=m
CONFIG_NET_SCH_HTB=m
CONFIG_NET_SCH_HFSC=m
CONFIG_NET_SCH_ATM=m
CONFIG_NET_SCH_PRIO=m
CONFIG_NET_SCH_MULTIQ=m
CONFIG_NET_SCH_RED=m
CONFIG_NET_SCH_SFB=m
CONFIG_NET_SCH_SFQ=m
CONFIG_NET_SCH_TEQL=m
CONFIG_NET_SCH_TBF=m
# CONFIG_NET_SCH_CBS is not set
# CONFIG_NET_SCH_ETF is not set
# CONFIG_NET_SCH_TAPRIO is not set
CONFIG_NET_SCH_GRED=m
CONFIG_NET_SCH_DSMARK=m
CONFIG_NET_SCH_NETEM=m
CONFIG_NET_SCH_DRR=m
CONFIG_NET_SCH_MQPRIO=m
# CONFIG_NET_SCH_SKBPRIO is not set
CONFIG_NET_SCH_CHOKE=m
CONFIG_NET_SCH_QFQ=m
CONFIG_NET_SCH_CODEL=m
CONFIG_NET_SCH_FQ_CODEL=y
# CONFIG_NET_SCH_CAKE is not set
CONFIG_NET_SCH_FQ=m
CONFIG_NET_SCH_HHF=m
CONFIG_NET_SCH_PIE=m
# CONFIG_NET_SCH_FQ_PIE is not set
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_SCH_PLUG=m
# CONFIG_NET_SCH_ETS is not set
CONFIG_NET_SCH_DEFAULT=y
# CONFIG_DEFAULT_FQ is not set
# CONFIG_DEFAULT_CODEL is not set
CONFIG_DEFAULT_FQ_CODEL=y
# CONFIG_DEFAULT_SFQ is not set
# CONFIG_DEFAULT_PFIFO_FAST is not set
CONFIG_DEFAULT_NET_SCH="fq_codel"

#
# Classification
#
CONFIG_NET_CLS=y
CONFIG_NET_CLS_BASIC=m
CONFIG_NET_CLS_TCINDEX=m
CONFIG_NET_CLS_ROUTE4=m
CONFIG_NET_CLS_FW=m
CONFIG_NET_CLS_U32=m
CONFIG_CLS_U32_PERF=y
CONFIG_CLS_U32_MARK=y
CONFIG_NET_CLS_RSVP=m
CONFIG_NET_CLS_RSVP6=m
CONFIG_NET_CLS_FLOW=m
CONFIG_NET_CLS_CGROUP=y
CONFIG_NET_CLS_BPF=m
CONFIG_NET_CLS_FLOWER=m
CONFIG_NET_CLS_MATCHALL=m
CONFIG_NET_EMATCH=y
CONFIG_NET_EMATCH_STACK=32
CONFIG_NET_EMATCH_CMP=m
CONFIG_NET_EMATCH_NBYTE=m
CONFIG_NET_EMATCH_U32=m
CONFIG_NET_EMATCH_META=m
CONFIG_NET_EMATCH_TEXT=m
# CONFIG_NET_EMATCH_CANID is not set
CONFIG_NET_EMATCH_IPSET=m
# CONFIG_NET_EMATCH_IPT is not set
CONFIG_NET_CLS_ACT=y
CONFIG_NET_ACT_POLICE=m
CONFIG_NET_ACT_GACT=m
CONFIG_GACT_PROB=y
CONFIG_NET_ACT_MIRRED=m
CONFIG_NET_ACT_SAMPLE=m
# CONFIG_NET_ACT_IPT is not set
CONFIG_NET_ACT_NAT=m
CONFIG_NET_ACT_PEDIT=m
CONFIG_NET_ACT_SIMP=m
CONFIG_NET_ACT_SKBEDIT=m
CONFIG_NET_ACT_CSUM=m
# CONFIG_NET_ACT_MPLS is not set
CONFIG_NET_ACT_VLAN=m
CONFIG_NET_ACT_BPF=m
# CONFIG_NET_ACT_CONNMARK is not set
# CONFIG_NET_ACT_CTINFO is not set
CONFIG_NET_ACT_SKBMOD=m
# CONFIG_NET_ACT_IFE is not set
CONFIG_NET_ACT_TUNNEL_KEY=m
# CONFIG_NET_ACT_GATE is not set
# CONFIG_NET_TC_SKB_EXT is not set
CONFIG_NET_SCH_FIFO=y
CONFIG_DCB=y
CONFIG_DNS_RESOLVER=m
# CONFIG_BATMAN_ADV is not set
CONFIG_OPENVSWITCH=m
CONFIG_OPENVSWITCH_GRE=m
CONFIG_VSOCKETS=m
CONFIG_VSOCKETS_DIAG=m
CONFIG_VSOCKETS_LOOPBACK=m
CONFIG_VMWARE_VMCI_VSOCKETS=m
CONFIG_VIRTIO_VSOCKETS=m
CONFIG_VIRTIO_VSOCKETS_COMMON=m
CONFIG_HYPERV_VSOCKETS=m
CONFIG_NETLINK_DIAG=m
CONFIG_MPLS=y
CONFIG_NET_MPLS_GSO=y
CONFIG_MPLS_ROUTING=m
CONFIG_MPLS_IPTUNNEL=m
CONFIG_NET_NSH=y
# CONFIG_HSR is not set
CONFIG_NET_SWITCHDEV=y
CONFIG_NET_L3_MASTER_DEV=y
# CONFIG_QRTR is not set
# CONFIG_NET_NCSI is not set
CONFIG_PCPU_DEV_REFCNT=y
CONFIG_RPS=y
CONFIG_RFS_ACCEL=y
CONFIG_SOCK_RX_QUEUE_MAPPING=y
CONFIG_XPS=y
CONFIG_CGROUP_NET_PRIO=y
CONFIG_CGROUP_NET_CLASSID=y
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_BQL=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_NET_FLOW_LIMIT=y

#
# Network testing
#
CONFIG_NET_PKTGEN=m
CONFIG_NET_DROP_MONITOR=y
# end of Network testing
# end of Networking options

# CONFIG_HAMRADIO is not set
CONFIG_CAN=m
CONFIG_CAN_RAW=m
CONFIG_CAN_BCM=m
CONFIG_CAN_GW=m
# CONFIG_CAN_J1939 is not set
# CONFIG_CAN_ISOTP is not set
CONFIG_BT=m
CONFIG_BT_BREDR=y
CONFIG_BT_RFCOMM=m
CONFIG_BT_RFCOMM_TTY=y
CONFIG_BT_BNEP=m
CONFIG_BT_BNEP_MC_FILTER=y
CONFIG_BT_BNEP_PROTO_FILTER=y
CONFIG_BT_HIDP=m
CONFIG_BT_HS=y
CONFIG_BT_LE=y
# CONFIG_BT_6LOWPAN is not set
# CONFIG_BT_LEDS is not set
# CONFIG_BT_MSFTEXT is not set
# CONFIG_BT_AOSPEXT is not set
CONFIG_BT_DEBUGFS=y
# CONFIG_BT_SELFTEST is not set
# CONFIG_BT_FEATURE_DEBUG is not set

#
# Bluetooth device drivers
#
# CONFIG_BT_HCIBTUSB is not set
# CONFIG_BT_HCIBTSDIO is not set
CONFIG_BT_HCIUART=m
CONFIG_BT_HCIUART_H4=y
CONFIG_BT_HCIUART_BCSP=y
CONFIG_BT_HCIUART_ATH3K=y
# CONFIG_BT_HCIUART_INTEL is not set
# CONFIG_BT_HCIUART_AG6XX is not set
# CONFIG_BT_HCIBCM203X is not set
# CONFIG_BT_HCIBPA10X is not set
# CONFIG_BT_HCIBFUSB is not set
CONFIG_BT_HCIVHCI=m
CONFIG_BT_MRVL=m
# CONFIG_BT_MRVL_SDIO is not set
# CONFIG_BT_MTKSDIO is not set
# CONFIG_BT_VIRTIO is not set
# end of Bluetooth device drivers

# CONFIG_AF_RXRPC is not set
# CONFIG_AF_KCM is not set
CONFIG_STREAM_PARSER=y
# CONFIG_MCTP is not set
CONFIG_FIB_RULES=y
CONFIG_WIRELESS=y
CONFIG_WEXT_CORE=y
CONFIG_WEXT_PROC=y
CONFIG_CFG80211=m
# CONFIG_NL80211_TESTMODE is not set
# CONFIG_CFG80211_DEVELOPER_WARNINGS is not set
CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=y
CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS=y
CONFIG_CFG80211_DEFAULT_PS=y
# CONFIG_CFG80211_DEBUGFS is not set
CONFIG_CFG80211_CRDA_SUPPORT=y
CONFIG_CFG80211_WEXT=y
CONFIG_MAC80211=m
CONFIG_MAC80211_HAS_RC=y
CONFIG_MAC80211_RC_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT="minstrel_ht"
CONFIG_MAC80211_MESH=y
CONFIG_MAC80211_LEDS=y
CONFIG_MAC80211_DEBUGFS=y
# CONFIG_MAC80211_MESSAGE_TRACING is not set
# CONFIG_MAC80211_DEBUG_MENU is not set
CONFIG_MAC80211_STA_HASH_MAX_SIZE=0
CONFIG_RFKILL=m
CONFIG_RFKILL_LEDS=y
CONFIG_RFKILL_INPUT=y
# CONFIG_RFKILL_GPIO is not set
CONFIG_NET_9P=y
CONFIG_NET_9P_FD=y
CONFIG_NET_9P_VIRTIO=y
# CONFIG_NET_9P_XEN is not set
# CONFIG_NET_9P_RDMA is not set
# CONFIG_NET_9P_DEBUG is not set
# CONFIG_CAIF is not set
CONFIG_CEPH_LIB=m
# CONFIG_CEPH_LIB_PRETTYDEBUG is not set
CONFIG_CEPH_LIB_USE_DNS_RESOLVER=y
# CONFIG_NFC is not set
CONFIG_PSAMPLE=m
# CONFIG_NET_IFE is not set
CONFIG_LWTUNNEL=y
CONFIG_LWTUNNEL_BPF=y
CONFIG_DST_CACHE=y
CONFIG_GRO_CELLS=y
CONFIG_SOCK_VALIDATE_XMIT=y
CONFIG_NET_SELFTESTS=y
CONFIG_NET_SOCK_MSG=y
CONFIG_NET_DEVLINK=y
CONFIG_PAGE_POOL=y
# CONFIG_PAGE_POOL_STATS is not set
CONFIG_FAILOVER=m
CONFIG_ETHTOOL_NETLINK=y
# CONFIG_NETDEV_ADDR_LIST_TEST is not set

#
# Device Drivers
#
CONFIG_HAVE_EISA=y
# CONFIG_EISA is not set
CONFIG_HAVE_PCI=y
CONFIG_PCI=y
CONFIG_PCI_DOMAINS=y
CONFIG_PCIEPORTBUS=y
CONFIG_HOTPLUG_PCI_PCIE=y
CONFIG_PCIEAER=y
CONFIG_PCIEAER_INJECT=m
CONFIG_PCIE_ECRC=y
CONFIG_PCIEASPM=y
CONFIG_PCIEASPM_DEFAULT=y
# CONFIG_PCIEASPM_POWERSAVE is not set
# CONFIG_PCIEASPM_POWER_SUPERSAVE is not set
# CONFIG_PCIEASPM_PERFORMANCE is not set
CONFIG_PCIE_PME=y
CONFIG_PCIE_DPC=y
# CONFIG_PCIE_PTM is not set
# CONFIG_PCIE_EDR is not set
CONFIG_PCI_MSI=y
CONFIG_PCI_MSI_IRQ_DOMAIN=y
CONFIG_PCI_QUIRKS=y
# CONFIG_PCI_DEBUG is not set
# CONFIG_PCI_REALLOC_ENABLE_AUTO is not set
CONFIG_PCI_STUB=y
CONFIG_PCI_PF_STUB=m
CONFIG_PCI_ATS=y
CONFIG_PCI_LOCKLESS_CONFIG=y
CONFIG_PCI_IOV=y
CONFIG_PCI_PRI=y
CONFIG_PCI_PASID=y
# CONFIG_PCI_P2PDMA is not set
CONFIG_PCI_LABEL=y
CONFIG_PCI_HYPERV=m
CONFIG_VGA_ARB=y
CONFIG_VGA_ARB_MAX_GPUS=64
CONFIG_HOTPLUG_PCI=y
CONFIG_HOTPLUG_PCI_ACPI=y
CONFIG_HOTPLUG_PCI_ACPI_IBM=m
# CONFIG_HOTPLUG_PCI_CPCI is not set
CONFIG_HOTPLUG_PCI_SHPC=y

#
# PCI controller drivers
#
CONFIG_VMD=y
CONFIG_PCI_HYPERV_INTERFACE=m

#
# DesignWare PCI Core Support
#
# CONFIG_PCIE_DW_PLAT_HOST is not set
# CONFIG_PCI_MESON is not set
# end of DesignWare PCI Core Support

#
# Mobiveil PCIe Core Support
#
# end of Mobiveil PCIe Core Support

#
# Cadence PCIe controllers support
#
# end of Cadence PCIe controllers support
# end of PCI controller drivers

#
# PCI Endpoint
#
# CONFIG_PCI_ENDPOINT is not set
# end of PCI Endpoint

#
# PCI switch controller drivers
#
# CONFIG_PCI_SW_SWITCHTEC is not set
# end of PCI switch controller drivers

# CONFIG_CXL_BUS is not set
# CONFIG_PCCARD is not set
# CONFIG_RAPIDIO is not set

#
# Generic Driver Options
#
CONFIG_AUXILIARY_BUS=y
# CONFIG_UEVENT_HELPER is not set
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
# CONFIG_DEVTMPFS_SAFE is not set
CONFIG_STANDALONE=y
CONFIG_PREVENT_FIRMWARE_BUILD=y

#
# Firmware loader
#
CONFIG_FW_LOADER=y
CONFIG_FW_LOADER_PAGED_BUF=y
CONFIG_FW_LOADER_SYSFS=y
CONFIG_EXTRA_FIRMWARE=""
CONFIG_FW_LOADER_USER_HELPER=y
# CONFIG_FW_LOADER_USER_HELPER_FALLBACK is not set
# CONFIG_FW_LOADER_COMPRESS is not set
CONFIG_FW_CACHE=y
# CONFIG_FW_UPLOAD is not set
# end of Firmware loader

CONFIG_ALLOW_DEV_COREDUMP=y
# CONFIG_DEBUG_DRIVER is not set
# CONFIG_DEBUG_DEVRES is not set
# CONFIG_DEBUG_TEST_DRIVER_REMOVE is not set
# CONFIG_PM_QOS_KUNIT_TEST is not set
# CONFIG_TEST_ASYNC_DRIVER_PROBE is not set
# CONFIG_DRIVER_PE_KUNIT_TEST is not set
CONFIG_SYS_HYPERVISOR=y
CONFIG_GENERIC_CPU_AUTOPROBE=y
CONFIG_GENERIC_CPU_VULNERABILITIES=y
CONFIG_REGMAP=y
CONFIG_REGMAP_I2C=m
CONFIG_REGMAP_SPI=m
CONFIG_DMA_SHARED_BUFFER=y
# CONFIG_DMA_FENCE_TRACE is not set
# end of Generic Driver Options

#
# Bus devices
#
# CONFIG_MHI_BUS is not set
# CONFIG_MHI_BUS_EP is not set
# end of Bus devices

CONFIG_CONNECTOR=y
CONFIG_PROC_EVENTS=y

#
# Firmware Drivers
#

#
# ARM System Control and Management Interface Protocol
#
# end of ARM System Control and Management Interface Protocol

CONFIG_EDD=m
# CONFIG_EDD_OFF is not set
CONFIG_FIRMWARE_MEMMAP=y
CONFIG_DMIID=y
CONFIG_DMI_SYSFS=y
CONFIG_DMI_SCAN_MACHINE_NON_EFI_FALLBACK=y
# CONFIG_ISCSI_IBFT is not set
CONFIG_FW_CFG_SYSFS=y
# CONFIG_FW_CFG_SYSFS_CMDLINE is not set
CONFIG_SYSFB=y
# CONFIG_SYSFB_SIMPLEFB is not set
# CONFIG_GOOGLE_FIRMWARE is not set

#
# EFI (Extensible Firmware Interface) Support
#
CONFIG_EFI_ESRT=y
CONFIG_EFI_VARS_PSTORE=y
CONFIG_EFI_VARS_PSTORE_DEFAULT_DISABLE=y
CONFIG_EFI_RUNTIME_MAP=y
# CONFIG_EFI_FAKE_MEMMAP is not set
CONFIG_EFI_DXE_MEM_ATTRIBUTES=y
CONFIG_EFI_RUNTIME_WRAPPERS=y
CONFIG_EFI_GENERIC_STUB_INITRD_CMDLINE_LOADER=y
# CONFIG_EFI_BOOTLOADER_CONTROL is not set
# CONFIG_EFI_CAPSULE_LOADER is not set
# CONFIG_EFI_TEST is not set
CONFIG_EFI_DEV_PATH_PARSER=y
CONFIG_APPLE_PROPERTIES=y
# CONFIG_RESET_ATTACK_MITIGATION is not set
# CONFIG_EFI_RCI2_TABLE is not set
# CONFIG_EFI_DISABLE_PCI_DMA is not set
CONFIG_EFI_EARLYCON=y
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS=y
# CONFIG_EFI_DISABLE_RUNTIME is not set
# CONFIG_EFI_COCO_SECRET is not set
# end of EFI (Extensible Firmware Interface) Support

CONFIG_UEFI_CPER=y
CONFIG_UEFI_CPER_X86=y

#
# Tegra firmware driver
#
# end of Tegra firmware driver
# end of Firmware Drivers

# CONFIG_GNSS is not set
# CONFIG_MTD is not set
# CONFIG_OF is not set
CONFIG_ARCH_MIGHT_HAVE_PC_PARPORT=y
CONFIG_PARPORT=m
CONFIG_PARPORT_PC=m
CONFIG_PARPORT_SERIAL=m
# CONFIG_PARPORT_PC_FIFO is not set
# CONFIG_PARPORT_PC_SUPERIO is not set
# CONFIG_PARPORT_AX88796 is not set
CONFIG_PARPORT_1284=y
CONFIG_PNP=y
# CONFIG_PNP_DEBUG_MESSAGES is not set

#
# Protocols
#
CONFIG_PNPACPI=y
CONFIG_BLK_DEV=y
CONFIG_BLK_DEV_NULL_BLK=m
CONFIG_BLK_DEV_NULL_BLK_FAULT_INJECTION=y
# CONFIG_BLK_DEV_FD is not set
CONFIG_CDROM=m
# CONFIG_PARIDE is not set
# CONFIG_BLK_DEV_PCIESSD_MTIP32XX is not set
# CONFIG_ZRAM is not set
CONFIG_BLK_DEV_LOOP=m
CONFIG_BLK_DEV_LOOP_MIN_COUNT=0
# CONFIG_BLK_DEV_DRBD is not set
CONFIG_BLK_DEV_NBD=m
CONFIG_BLK_DEV_RAM=m
CONFIG_BLK_DEV_RAM_COUNT=16
CONFIG_BLK_DEV_RAM_SIZE=16384
CONFIG_CDROM_PKTCDVD=m
CONFIG_CDROM_PKTCDVD_BUFFERS=8
# CONFIG_CDROM_PKTCDVD_WCACHE is not set
# CONFIG_ATA_OVER_ETH is not set
CONFIG_XEN_BLKDEV_FRONTEND=m
CONFIG_VIRTIO_BLK=m
CONFIG_BLK_DEV_RBD=m
# CONFIG_BLK_DEV_UBLK is not set

#
# NVME Support
#
CONFIG_NVME_CORE=m
CONFIG_BLK_DEV_NVME=m
CONFIG_NVME_MULTIPATH=y
# CONFIG_NVME_VERBOSE_ERRORS is not set
# CONFIG_NVME_HWMON is not set
CONFIG_NVME_FABRICS=m
# CONFIG_NVME_RDMA is not set
CONFIG_NVME_FC=m
# CONFIG_NVME_TCP is not set
# CONFIG_NVME_AUTH is not set
CONFIG_NVME_TARGET=m
# CONFIG_NVME_TARGET_PASSTHRU is not set
CONFIG_NVME_TARGET_LOOP=m
# CONFIG_NVME_TARGET_RDMA is not set
CONFIG_NVME_TARGET_FC=m
CONFIG_NVME_TARGET_FCLOOP=m
# CONFIG_NVME_TARGET_TCP is not set
# CONFIG_NVME_TARGET_AUTH is not set
# end of NVME Support

#
# Misc devices
#
CONFIG_SENSORS_LIS3LV02D=m
# CONFIG_AD525X_DPOT is not set
# CONFIG_DUMMY_IRQ is not set
# CONFIG_IBM_ASM is not set
# CONFIG_PHANTOM is not set
CONFIG_TIFM_CORE=m
CONFIG_TIFM_7XX1=m
# CONFIG_ICS932S401 is not set
CONFIG_ENCLOSURE_SERVICES=m
CONFIG_SGI_XP=m
CONFIG_HP_ILO=m
CONFIG_SGI_GRU=m
# CONFIG_SGI_GRU_DEBUG is not set
CONFIG_APDS9802ALS=m
CONFIG_ISL29003=m
CONFIG_ISL29020=m
CONFIG_SENSORS_TSL2550=m
CONFIG_SENSORS_BH1770=m
CONFIG_SENSORS_APDS990X=m
# CONFIG_HMC6352 is not set
# CONFIG_DS1682 is not set
CONFIG_VMWARE_BALLOON=m
# CONFIG_LATTICE_ECP3_CONFIG is not set
# CONFIG_SRAM is not set
# CONFIG_DW_XDATA_PCIE is not set
# CONFIG_PCI_ENDPOINT_TEST is not set
# CONFIG_XILINX_SDFEC is not set
CONFIG_MISC_RTSX=m
# CONFIG_C2PORT is not set

#
# EEPROM support
#
# CONFIG_EEPROM_AT24 is not set
# CONFIG_EEPROM_AT25 is not set
CONFIG_EEPROM_LEGACY=m
CONFIG_EEPROM_MAX6875=m
CONFIG_EEPROM_93CX6=m
# CONFIG_EEPROM_93XX46 is not set
# CONFIG_EEPROM_IDT_89HPESX is not set
# CONFIG_EEPROM_EE1004 is not set
# end of EEPROM support

CONFIG_CB710_CORE=m
# CONFIG_CB710_DEBUG is not set
CONFIG_CB710_DEBUG_ASSUMPTIONS=y

#
# Texas Instruments shared transport line discipline
#
# CONFIG_TI_ST is not set
# end of Texas Instruments shared transport line discipline

CONFIG_SENSORS_LIS3_I2C=m
CONFIG_ALTERA_STAPL=m
CONFIG_INTEL_MEI=m
CONFIG_INTEL_MEI_ME=m
# CONFIG_INTEL_MEI_TXE is not set
# CONFIG_INTEL_MEI_GSC is not set
# CONFIG_INTEL_MEI_HDCP is not set
# CONFIG_INTEL_MEI_PXP is not set
CONFIG_VMWARE_VMCI=m
# CONFIG_GENWQE is not set
# CONFIG_ECHO is not set
# CONFIG_BCM_VK is not set
# CONFIG_MISC_ALCOR_PCI is not set
CONFIG_MISC_RTSX_PCI=m
# CONFIG_MISC_RTSX_USB is not set
# CONFIG_HABANA_AI is not set
# CONFIG_UACCE is not set
CONFIG_PVPANIC=y
# CONFIG_PVPANIC_MMIO is not set
# CONFIG_PVPANIC_PCI is not set
# end of Misc devices

#
# SCSI device support
#
CONFIG_SCSI_MOD=y
CONFIG_RAID_ATTRS=m
CONFIG_SCSI_COMMON=y
CONFIG_SCSI=y
CONFIG_SCSI_DMA=y
CONFIG_SCSI_NETLINK=y
CONFIG_SCSI_PROC_FS=y

#
# SCSI support type (disk, tape, CD-ROM)
#
CONFIG_BLK_DEV_SD=y
CONFIG_CHR_DEV_ST=y
CONFIG_BLK_DEV_SR=m
CONFIG_CHR_DEV_SG=y
CONFIG_BLK_DEV_BSG=y
CONFIG_CHR_DEV_SCH=m
CONFIG_SCSI_ENCLOSURE=m
CONFIG_SCSI_CONSTANTS=y
CONFIG_SCSI_LOGGING=y
CONFIG_SCSI_SCAN_ASYNC=y

#
# SCSI Transports
#
CONFIG_SCSI_SPI_ATTRS=m
CONFIG_SCSI_FC_ATTRS=m
CONFIG_SCSI_ISCSI_ATTRS=m
CONFIG_SCSI_SAS_ATTRS=m
CONFIG_SCSI_SAS_LIBSAS=m
CONFIG_SCSI_SAS_ATA=y
CONFIG_SCSI_SAS_HOST_SMP=y
CONFIG_SCSI_SRP_ATTRS=m
# end of SCSI Transports

CONFIG_SCSI_LOWLEVEL=y
# CONFIG_ISCSI_TCP is not set
# CONFIG_ISCSI_BOOT_SYSFS is not set
# CONFIG_SCSI_CXGB3_ISCSI is not set
# CONFIG_SCSI_CXGB4_ISCSI is not set
# CONFIG_SCSI_BNX2_ISCSI is not set
# CONFIG_BE2ISCSI is not set
# CONFIG_BLK_DEV_3W_XXXX_RAID is not set
# CONFIG_SCSI_HPSA is not set
# CONFIG_SCSI_3W_9XXX is not set
# CONFIG_SCSI_3W_SAS is not set
# CONFIG_SCSI_ACARD is not set
# CONFIG_SCSI_AACRAID is not set
# CONFIG_SCSI_AIC7XXX is not set
# CONFIG_SCSI_AIC79XX is not set
# CONFIG_SCSI_AIC94XX is not set
# CONFIG_SCSI_MVSAS is not set
# CONFIG_SCSI_MVUMI is not set
# CONFIG_SCSI_ADVANSYS is not set
# CONFIG_SCSI_ARCMSR is not set
# CONFIG_SCSI_ESAS2R is not set
# CONFIG_MEGARAID_NEWGEN is not set
# CONFIG_MEGARAID_LEGACY is not set
# CONFIG_MEGARAID_SAS is not set
CONFIG_SCSI_MPT3SAS=m
CONFIG_SCSI_MPT2SAS_MAX_SGE=128
CONFIG_SCSI_MPT3SAS_MAX_SGE=128
# CONFIG_SCSI_MPT2SAS is not set
# CONFIG_SCSI_MPI3MR is not set
# CONFIG_SCSI_SMARTPQI is not set
# CONFIG_SCSI_HPTIOP is not set
# CONFIG_SCSI_BUSLOGIC is not set
# CONFIG_SCSI_MYRB is not set
# CONFIG_SCSI_MYRS is not set
# CONFIG_VMWARE_PVSCSI is not set
# CONFIG_XEN_SCSI_FRONTEND is not set
CONFIG_HYPERV_STORAGE=m
# CONFIG_LIBFC is not set
# CONFIG_SCSI_SNIC is not set
# CONFIG_SCSI_DMX3191D is not set
# CONFIG_SCSI_FDOMAIN_PCI is not set
CONFIG_SCSI_ISCI=m
# CONFIG_SCSI_IPS is not set
# CONFIG_SCSI_INITIO is not set
# CONFIG_SCSI_INIA100 is not set
# CONFIG_SCSI_PPA is not set
# CONFIG_SCSI_IMM is not set
# CONFIG_SCSI_STEX is not set
# CONFIG_SCSI_SYM53C8XX_2 is not set
# CONFIG_SCSI_IPR is not set
# CONFIG_SCSI_QLOGIC_1280 is not set
# CONFIG_SCSI_QLA_FC is not set
# CONFIG_SCSI_QLA_ISCSI is not set
# CONFIG_SCSI_LPFC is not set
# CONFIG_SCSI_EFCT is not set
# CONFIG_SCSI_DC395x is not set
# CONFIG_SCSI_AM53C974 is not set
# CONFIG_SCSI_WD719X is not set
CONFIG_SCSI_DEBUG=m
# CONFIG_SCSI_PMCRAID is not set
# CONFIG_SCSI_PM8001 is not set
# CONFIG_SCSI_BFA_FC is not set
# CONFIG_SCSI_VIRTIO is not set
# CONFIG_SCSI_CHELSIO_FCOE is not set
CONFIG_SCSI_DH=y
CONFIG_SCSI_DH_RDAC=y
CONFIG_SCSI_DH_HP_SW=y
CONFIG_SCSI_DH_EMC=y
CONFIG_SCSI_DH_ALUA=y
# end of SCSI device support

CONFIG_ATA=y
CONFIG_SATA_HOST=y
CONFIG_PATA_TIMINGS=y
CONFIG_ATA_VERBOSE_ERROR=y
CONFIG_ATA_FORCE=y
CONFIG_ATA_ACPI=y
# CONFIG_SATA_ZPODD is not set
CONFIG_SATA_PMP=y

#
# Controllers with non-SFF native interface
#
CONFIG_SATA_AHCI=y
CONFIG_SATA_MOBILE_LPM_POLICY=0
CONFIG_SATA_AHCI_PLATFORM=y
# CONFIG_SATA_INIC162X is not set
# CONFIG_SATA_ACARD_AHCI is not set
# CONFIG_SATA_SIL24 is not set
CONFIG_ATA_SFF=y

#
# SFF controllers with custom DMA interface
#
# CONFIG_PDC_ADMA is not set
# CONFIG_SATA_QSTOR is not set
# CONFIG_SATA_SX4 is not set
CONFIG_ATA_BMDMA=y

#
# SATA SFF controllers with BMDMA
#
CONFIG_ATA_PIIX=y
# CONFIG_SATA_DWC is not set
# CONFIG_SATA_MV is not set
# CONFIG_SATA_NV is not set
# CONFIG_SATA_PROMISE is not set
# CONFIG_SATA_SIL is not set
# CONFIG_SATA_SIS is not set
# CONFIG_SATA_SVW is not set
# CONFIG_SATA_ULI is not set
# CONFIG_SATA_VIA is not set
# CONFIG_SATA_VITESSE is not set

#
# PATA SFF controllers with BMDMA
#
# CONFIG_PATA_ALI is not set
# CONFIG_PATA_AMD is not set
# CONFIG_PATA_ARTOP is not set
# CONFIG_PATA_ATIIXP is not set
# CONFIG_PATA_ATP867X is not set
# CONFIG_PATA_CMD64X is not set
# CONFIG_PATA_CYPRESS is not set
# CONFIG_PATA_EFAR is not set
# CONFIG_PATA_HPT366 is not set
# CONFIG_PATA_HPT37X is not set
# CONFIG_PATA_HPT3X2N is not set
# CONFIG_PATA_HPT3X3 is not set
# CONFIG_PATA_IT8213 is not set
# CONFIG_PATA_IT821X is not set
# CONFIG_PATA_JMICRON is not set
# CONFIG_PATA_MARVELL is not set
# CONFIG_PATA_NETCELL is not set
# CONFIG_PATA_NINJA32 is not set
# CONFIG_PATA_NS87415 is not set
# CONFIG_PATA_OLDPIIX is not set
# CONFIG_PATA_OPTIDMA is not set
# CONFIG_PATA_PDC2027X is not set
# CONFIG_PATA_PDC_OLD is not set
# CONFIG_PATA_RADISYS is not set
# CONFIG_PATA_RDC is not set
# CONFIG_PATA_SCH is not set
# CONFIG_PATA_SERVERWORKS is not set
# CONFIG_PATA_SIL680 is not set
# CONFIG_PATA_SIS is not set
# CONFIG_PATA_TOSHIBA is not set
# CONFIG_PATA_TRIFLEX is not set
# CONFIG_PATA_VIA is not set
# CONFIG_PATA_WINBOND is not set

#
# PIO-only SFF controllers
#
# CONFIG_PATA_CMD640_PCI is not set
# CONFIG_PATA_MPIIX is not set
# CONFIG_PATA_NS87410 is not set
# CONFIG_PATA_OPTI is not set
# CONFIG_PATA_RZ1000 is not set

#
# Generic fallback / legacy drivers
#
# CONFIG_PATA_ACPI is not set
CONFIG_ATA_GENERIC=m
# CONFIG_PATA_LEGACY is not set
CONFIG_MD=y
CONFIG_BLK_DEV_MD=y
CONFIG_MD_AUTODETECT=y
CONFIG_MD_LINEAR=m
CONFIG_MD_RAID0=m
CONFIG_MD_RAID1=m
CONFIG_MD_RAID10=m
CONFIG_MD_RAID456=m
CONFIG_MD_MULTIPATH=m
CONFIG_MD_FAULTY=m
CONFIG_MD_CLUSTER=m
# CONFIG_BCACHE is not set
CONFIG_BLK_DEV_DM_BUILTIN=y
CONFIG_BLK_DEV_DM=m
CONFIG_DM_DEBUG=y
CONFIG_DM_BUFIO=m
# CONFIG_DM_DEBUG_BLOCK_MANAGER_LOCKING is not set
CONFIG_DM_BIO_PRISON=m
CONFIG_DM_PERSISTENT_DATA=m
# CONFIG_DM_UNSTRIPED is not set
CONFIG_DM_CRYPT=m
CONFIG_DM_SNAPSHOT=m
CONFIG_DM_THIN_PROVISIONING=m
CONFIG_DM_CACHE=m
CONFIG_DM_CACHE_SMQ=m
CONFIG_DM_WRITECACHE=m
# CONFIG_DM_EBS is not set
CONFIG_DM_ERA=m
# CONFIG_DM_CLONE is not set
CONFIG_DM_MIRROR=m
CONFIG_DM_LOG_USERSPACE=m
CONFIG_DM_RAID=m
CONFIG_DM_ZERO=m
CONFIG_DM_MULTIPATH=m
CONFIG_DM_MULTIPATH_QL=m
CONFIG_DM_MULTIPATH_ST=m
# CONFIG_DM_MULTIPATH_HST is not set
# CONFIG_DM_MULTIPATH_IOA is not set
CONFIG_DM_DELAY=m
# CONFIG_DM_DUST is not set
CONFIG_DM_UEVENT=y
CONFIG_DM_FLAKEY=m
CONFIG_DM_VERITY=m
# CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG is not set
# CONFIG_DM_VERITY_FEC is not set
CONFIG_DM_SWITCH=m
CONFIG_DM_LOG_WRITES=m
CONFIG_DM_INTEGRITY=m
# CONFIG_DM_ZONED is not set
CONFIG_DM_AUDIT=y
CONFIG_TARGET_CORE=m
CONFIG_TCM_IBLOCK=m
CONFIG_TCM_FILEIO=m
CONFIG_TCM_PSCSI=m
CONFIG_TCM_USER2=m
CONFIG_LOOPBACK_TARGET=m
CONFIG_ISCSI_TARGET=m
# CONFIG_SBP_TARGET is not set
# CONFIG_FUSION is not set

#
# IEEE 1394 (FireWire) support
#
CONFIG_FIREWIRE=m
CONFIG_FIREWIRE_OHCI=m
CONFIG_FIREWIRE_SBP2=m
CONFIG_FIREWIRE_NET=m
# CONFIG_FIREWIRE_NOSY is not set
# end of IEEE 1394 (FireWire) support

CONFIG_MACINTOSH_DRIVERS=y
CONFIG_MAC_EMUMOUSEBTN=y
CONFIG_NETDEVICES=y
CONFIG_MII=m
CONFIG_NET_CORE=y
# CONFIG_BONDING is not set
# CONFIG_DUMMY is not set
# CONFIG_WIREGUARD is not set
# CONFIG_EQUALIZER is not set
# CONFIG_NET_FC is not set
# CONFIG_IFB is not set
# CONFIG_NET_TEAM is not set
# CONFIG_MACVLAN is not set
# CONFIG_IPVLAN is not set
# CONFIG_VXLAN is not set
# CONFIG_GENEVE is not set
# CONFIG_BAREUDP is not set
# CONFIG_GTP is not set
# CONFIG_AMT is not set
# CONFIG_MACSEC is not set
CONFIG_NETCONSOLE=m
CONFIG_NETCONSOLE_DYNAMIC=y
CONFIG_NETPOLL=y
CONFIG_NET_POLL_CONTROLLER=y
CONFIG_TUN=m
# CONFIG_TUN_VNET_CROSS_LE is not set
CONFIG_VETH=m
# CONFIG_VIRTIO_NET is not set
# CONFIG_NLMON is not set
# CONFIG_NET_VRF is not set
# CONFIG_VSOCKMON is not set
# CONFIG_ARCNET is not set
CONFIG_ATM_DRIVERS=y
# CONFIG_ATM_DUMMY is not set
# CONFIG_ATM_TCP is not set
# CONFIG_ATM_LANAI is not set
# CONFIG_ATM_ENI is not set
# CONFIG_ATM_NICSTAR is not set
# CONFIG_ATM_IDT77252 is not set
# CONFIG_ATM_IA is not set
# CONFIG_ATM_FORE200E is not set
# CONFIG_ATM_HE is not set
# CONFIG_ATM_SOLOS is not set
CONFIG_ETHERNET=y
CONFIG_MDIO=y
CONFIG_NET_VENDOR_3COM=y
# CONFIG_VORTEX is not set
# CONFIG_TYPHOON is not set
CONFIG_NET_VENDOR_ADAPTEC=y
# CONFIG_ADAPTEC_STARFIRE is not set
CONFIG_NET_VENDOR_AGERE=y
# CONFIG_ET131X is not set
CONFIG_NET_VENDOR_ALACRITECH=y
# CONFIG_SLICOSS is not set
CONFIG_NET_VENDOR_ALTEON=y
# CONFIG_ACENIC is not set
# CONFIG_ALTERA_TSE is not set
CONFIG_NET_VENDOR_AMAZON=y
# CONFIG_ENA_ETHERNET is not set
CONFIG_NET_VENDOR_AMD=y
# CONFIG_AMD8111_ETH is not set
# CONFIG_PCNET32 is not set
# CONFIG_AMD_XGBE is not set
CONFIG_NET_VENDOR_AQUANTIA=y
# CONFIG_AQTION is not set
CONFIG_NET_VENDOR_ARC=y
CONFIG_NET_VENDOR_ASIX=y
# CONFIG_SPI_AX88796C is not set
CONFIG_NET_VENDOR_ATHEROS=y
# CONFIG_ATL2 is not set
# CONFIG_ATL1 is not set
# CONFIG_ATL1E is not set
# CONFIG_ATL1C is not set
# CONFIG_ALX is not set
# CONFIG_CX_ECAT is not set
CONFIG_NET_VENDOR_BROADCOM=y
# CONFIG_B44 is not set
# CONFIG_BCMGENET is not set
# CONFIG_BNX2 is not set
# CONFIG_CNIC is not set
# CONFIG_TIGON3 is not set
# CONFIG_BNX2X is not set
# CONFIG_SYSTEMPORT is not set
# CONFIG_BNXT is not set
CONFIG_NET_VENDOR_CADENCE=y
# CONFIG_MACB is not set
CONFIG_NET_VENDOR_CAVIUM=y
# CONFIG_THUNDER_NIC_PF is not set
# CONFIG_THUNDER_NIC_VF is not set
# CONFIG_THUNDER_NIC_BGX is not set
# CONFIG_THUNDER_NIC_RGX is not set
CONFIG_CAVIUM_PTP=y
# CONFIG_LIQUIDIO is not set
# CONFIG_LIQUIDIO_VF is not set
CONFIG_NET_VENDOR_CHELSIO=y
# CONFIG_CHELSIO_T1 is not set
# CONFIG_CHELSIO_T3 is not set
# CONFIG_CHELSIO_T4 is not set
# CONFIG_CHELSIO_T4VF is not set
CONFIG_NET_VENDOR_CISCO=y
# CONFIG_ENIC is not set
CONFIG_NET_VENDOR_CORTINA=y
CONFIG_NET_VENDOR_DAVICOM=y
# CONFIG_DM9051 is not set
# CONFIG_DNET is not set
CONFIG_NET_VENDOR_DEC=y
# CONFIG_NET_TULIP is not set
CONFIG_NET_VENDOR_DLINK=y
# CONFIG_DL2K is not set
# CONFIG_SUNDANCE is not set
CONFIG_NET_VENDOR_EMULEX=y
# CONFIG_BE2NET is not set
CONFIG_NET_VENDOR_ENGLEDER=y
# CONFIG_TSNEP is not set
CONFIG_NET_VENDOR_EZCHIP=y
CONFIG_NET_VENDOR_FUNGIBLE=y
# CONFIG_FUN_ETH is not set
CONFIG_NET_VENDOR_GOOGLE=y
# CONFIG_GVE is not set
CONFIG_NET_VENDOR_HUAWEI=y
# CONFIG_HINIC is not set
CONFIG_NET_VENDOR_I825XX=y
CONFIG_NET_VENDOR_INTEL=y
# CONFIG_E100 is not set
CONFIG_E1000=y
CONFIG_E1000E=y
CONFIG_E1000E_HWTS=y
CONFIG_IGB=y
CONFIG_IGB_HWMON=y
# CONFIG_IGBVF is not set
# CONFIG_IXGB is not set
CONFIG_IXGBE=y
CONFIG_IXGBE_HWMON=y
# CONFIG_IXGBE_DCB is not set
CONFIG_IXGBE_IPSEC=y
# CONFIG_IXGBEVF is not set
CONFIG_I40E=y
# CONFIG_I40E_DCB is not set
# CONFIG_I40EVF is not set
# CONFIG_ICE is not set
# CONFIG_FM10K is not set
# CONFIG_IGC is not set
CONFIG_NET_VENDOR_WANGXUN=y
# CONFIG_NGBE is not set
# CONFIG_TXGBE is not set
# CONFIG_JME is not set
CONFIG_NET_VENDOR_LITEX=y
CONFIG_NET_VENDOR_MARVELL=y
# CONFIG_MVMDIO is not set
# CONFIG_SKGE is not set
# CONFIG_SKY2 is not set
# CONFIG_OCTEON_EP is not set
# CONFIG_PRESTERA is not set
CONFIG_NET_VENDOR_MELLANOX=y
# CONFIG_MLX4_EN is not set
# CONFIG_MLX5_CORE is not set
# CONFIG_MLXSW_CORE is not set
# CONFIG_MLXFW is not set
CONFIG_NET_VENDOR_MICREL=y
# CONFIG_KS8842 is not set
# CONFIG_KS8851 is not set
# CONFIG_KS8851_MLL is not set
# CONFIG_KSZ884X_PCI is not set
CONFIG_NET_VENDOR_MICROCHIP=y
# CONFIG_ENC28J60 is not set
# CONFIG_ENCX24J600 is not set
# CONFIG_LAN743X is not set
CONFIG_NET_VENDOR_MICROSEMI=y
CONFIG_NET_VENDOR_MICROSOFT=y
# CONFIG_MICROSOFT_MANA is not set
CONFIG_NET_VENDOR_MYRI=y
# CONFIG_MYRI10GE is not set
# CONFIG_FEALNX is not set
CONFIG_NET_VENDOR_NI=y
# CONFIG_NI_XGE_MANAGEMENT_ENET is not set
CONFIG_NET_VENDOR_NATSEMI=y
# CONFIG_NATSEMI is not set
# CONFIG_NS83820 is not set
CONFIG_NET_VENDOR_NETERION=y
# CONFIG_S2IO is not set
CONFIG_NET_VENDOR_NETRONOME=y
# CONFIG_NFP is not set
CONFIG_NET_VENDOR_8390=y
# CONFIG_NE2K_PCI is not set
CONFIG_NET_VENDOR_NVIDIA=y
# CONFIG_FORCEDETH is not set
CONFIG_NET_VENDOR_OKI=y
# CONFIG_ETHOC is not set
CONFIG_NET_VENDOR_PACKET_ENGINES=y
# CONFIG_HAMACHI is not set
# CONFIG_YELLOWFIN is not set
CONFIG_NET_VENDOR_PENSANDO=y
# CONFIG_IONIC is not set
CONFIG_NET_VENDOR_QLOGIC=y
# CONFIG_QLA3XXX is not set
# CONFIG_QLCNIC is not set
# CONFIG_NETXEN_NIC is not set
# CONFIG_QED is not set
CONFIG_NET_VENDOR_BROCADE=y
# CONFIG_BNA is not set
CONFIG_NET_VENDOR_QUALCOMM=y
# CONFIG_QCOM_EMAC is not set
# CONFIG_RMNET is not set
CONFIG_NET_VENDOR_RDC=y
# CONFIG_R6040 is not set
CONFIG_NET_VENDOR_REALTEK=y
# CONFIG_ATP is not set
# CONFIG_8139CP is not set
# CONFIG_8139TOO is not set
CONFIG_R8169=y
CONFIG_NET_VENDOR_RENESAS=y
CONFIG_NET_VENDOR_ROCKER=y
# CONFIG_ROCKER is not set
CONFIG_NET_VENDOR_SAMSUNG=y
# CONFIG_SXGBE_ETH is not set
CONFIG_NET_VENDOR_SEEQ=y
CONFIG_NET_VENDOR_SILAN=y
# CONFIG_SC92031 is not set
CONFIG_NET_VENDOR_SIS=y
# CONFIG_SIS900 is not set
# CONFIG_SIS190 is not set
CONFIG_NET_VENDOR_SOLARFLARE=y
# CONFIG_SFC is not set
# CONFIG_SFC_FALCON is not set
# CONFIG_SFC_SIENA is not set
CONFIG_NET_VENDOR_SMSC=y
# CONFIG_EPIC100 is not set
# CONFIG_SMSC911X is not set
# CONFIG_SMSC9420 is not set
CONFIG_NET_VENDOR_SOCIONEXT=y
CONFIG_NET_VENDOR_STMICRO=y
# CONFIG_STMMAC_ETH is not set
CONFIG_NET_VENDOR_SUN=y
# CONFIG_HAPPYMEAL is not set
# CONFIG_SUNGEM is not set
# CONFIG_CASSINI is not set
# CONFIG_NIU is not set
CONFIG_NET_VENDOR_SYNOPSYS=y
# CONFIG_DWC_XLGMAC is not set
CONFIG_NET_VENDOR_TEHUTI=y
# CONFIG_TEHUTI is not set
CONFIG_NET_VENDOR_TI=y
# CONFIG_TI_CPSW_PHY_SEL is not set
# CONFIG_TLAN is not set
CONFIG_NET_VENDOR_VERTEXCOM=y
# CONFIG_MSE102X is not set
CONFIG_NET_VENDOR_VIA=y
# CONFIG_VIA_RHINE is not set
# CONFIG_VIA_VELOCITY is not set
CONFIG_NET_VENDOR_WIZNET=y
# CONFIG_WIZNET_W5100 is not set
# CONFIG_WIZNET_W5300 is not set
CONFIG_NET_VENDOR_XILINX=y
# CONFIG_XILINX_EMACLITE is not set
# CONFIG_XILINX_AXI_EMAC is not set
# CONFIG_XILINX_LL_TEMAC is not set
# CONFIG_FDDI is not set
# CONFIG_HIPPI is not set
# CONFIG_NET_SB1000 is not set
CONFIG_PHYLIB=y
CONFIG_SWPHY=y
# CONFIG_LED_TRIGGER_PHY is not set
CONFIG_FIXED_PHY=y

#
# MII PHY device drivers
#
# CONFIG_AMD_PHY is not set
# CONFIG_ADIN_PHY is not set
# CONFIG_ADIN1100_PHY is not set
# CONFIG_AQUANTIA_PHY is not set
# CONFIG_AX88796B_PHY is not set
# CONFIG_BROADCOM_PHY is not set
# CONFIG_BCM54140_PHY is not set
# CONFIG_BCM7XXX_PHY is not set
# CONFIG_BCM84881_PHY is not set
# CONFIG_BCM87XX_PHY is not set
# CONFIG_CICADA_PHY is not set
# CONFIG_CORTINA_PHY is not set
# CONFIG_DAVICOM_PHY is not set
# CONFIG_ICPLUS_PHY is not set
# CONFIG_LXT_PHY is not set
# CONFIG_INTEL_XWAY_PHY is not set
# CONFIG_LSI_ET1011C_PHY is not set
# CONFIG_MARVELL_PHY is not set
# CONFIG_MARVELL_10G_PHY is not set
# CONFIG_MARVELL_88X2222_PHY is not set
# CONFIG_MAXLINEAR_GPHY is not set
# CONFIG_MEDIATEK_GE_PHY is not set
# CONFIG_MICREL_PHY is not set
# CONFIG_MICROCHIP_PHY is not set
# CONFIG_MICROCHIP_T1_PHY is not set
# CONFIG_MICROSEMI_PHY is not set
# CONFIG_MOTORCOMM_PHY is not set
# CONFIG_NATIONAL_PHY is not set
# CONFIG_NXP_C45_TJA11XX_PHY is not set
# CONFIG_NXP_TJA11XX_PHY is not set
# CONFIG_QSEMI_PHY is not set
CONFIG_REALTEK_PHY=y
# CONFIG_RENESAS_PHY is not set
# CONFIG_ROCKCHIP_PHY is not set
# CONFIG_SMSC_PHY is not set
# CONFIG_STE10XP is not set
# CONFIG_TERANETICS_PHY is not set
# CONFIG_DP83822_PHY is not set
# CONFIG_DP83TC811_PHY is not set
# CONFIG_DP83848_PHY is not set
# CONFIG_DP83867_PHY is not set
# CONFIG_DP83869_PHY is not set
# CONFIG_DP83TD510_PHY is not set
# CONFIG_VITESSE_PHY is not set
# CONFIG_XILINX_GMII2RGMII is not set
# CONFIG_MICREL_KS8995MA is not set
CONFIG_CAN_DEV=m
CONFIG_CAN_VCAN=m
# CONFIG_CAN_VXCAN is not set
CONFIG_CAN_NETLINK=y
CONFIG_CAN_CALC_BITTIMING=y
# CONFIG_CAN_CAN327 is not set
# CONFIG_CAN_KVASER_PCIEFD is not set
CONFIG_CAN_SLCAN=m
CONFIG_CAN_C_CAN=m
CONFIG_CAN_C_CAN_PLATFORM=m
CONFIG_CAN_C_CAN_PCI=m
CONFIG_CAN_CC770=m
# CONFIG_CAN_CC770_ISA is not set
CONFIG_CAN_CC770_PLATFORM=m
# CONFIG_CAN_CTUCANFD_PCI is not set
# CONFIG_CAN_IFI_CANFD is not set
# CONFIG_CAN_M_CAN is not set
# CONFIG_CAN_PEAK_PCIEFD is not set
CONFIG_CAN_SJA1000=m
CONFIG_CAN_EMS_PCI=m
# CONFIG_CAN_F81601 is not set
CONFIG_CAN_KVASER_PCI=m
CONFIG_CAN_PEAK_PCI=m
CONFIG_CAN_PEAK_PCIEC=y
CONFIG_CAN_PLX_PCI=m
# CONFIG_CAN_SJA1000_ISA is not set
CONFIG_CAN_SJA1000_PLATFORM=m
CONFIG_CAN_SOFTING=m

#
# CAN SPI interfaces
#
# CONFIG_CAN_HI311X is not set
# CONFIG_CAN_MCP251X is not set
# CONFIG_CAN_MCP251XFD is not set
# end of CAN SPI interfaces

#
# CAN USB interfaces
#
# CONFIG_CAN_8DEV_USB is not set
# CONFIG_CAN_EMS_USB is not set
# CONFIG_CAN_ESD_USB is not set
# CONFIG_CAN_ETAS_ES58X is not set
# CONFIG_CAN_GS_USB is not set
# CONFIG_CAN_KVASER_USB is not set
# CONFIG_CAN_MCBA_USB is not set
# CONFIG_CAN_PEAK_USB is not set
# CONFIG_CAN_UCAN is not set
# end of CAN USB interfaces

# CONFIG_CAN_DEBUG_DEVICES is not set
CONFIG_MDIO_DEVICE=y
CONFIG_MDIO_BUS=y
CONFIG_FWNODE_MDIO=y
CONFIG_ACPI_MDIO=y
CONFIG_MDIO_DEVRES=y
# CONFIG_MDIO_BITBANG is not set
# CONFIG_MDIO_BCM_UNIMAC is not set
# CONFIG_MDIO_MVUSB is not set
# CONFIG_MDIO_THUNDER is not set

#
# MDIO Multiplexers
#

#
# PCS device drivers
#
# end of PCS device drivers

# CONFIG_PLIP is not set
# CONFIG_PPP is not set
# CONFIG_SLIP is not set
CONFIG_USB_NET_DRIVERS=y
# CONFIG_USB_CATC is not set
# CONFIG_USB_KAWETH is not set
# CONFIG_USB_PEGASUS is not set
# CONFIG_USB_RTL8150 is not set
CONFIG_USB_RTL8152=m
# CONFIG_USB_LAN78XX is not set
# CONFIG_USB_USBNET is not set
# CONFIG_USB_HSO is not set
# CONFIG_USB_IPHETH is not set
CONFIG_WLAN=y
CONFIG_WLAN_VENDOR_ADMTEK=y
# CONFIG_ADM8211 is not set
CONFIG_WLAN_VENDOR_ATH=y
# CONFIG_ATH_DEBUG is not set
# CONFIG_ATH5K is not set
# CONFIG_ATH5K_PCI is not set
# CONFIG_ATH9K is not set
# CONFIG_ATH9K_HTC is not set
# CONFIG_CARL9170 is not set
# CONFIG_ATH6KL is not set
# CONFIG_AR5523 is not set
# CONFIG_WIL6210 is not set
# CONFIG_ATH10K is not set
# CONFIG_WCN36XX is not set
# CONFIG_ATH11K is not set
CONFIG_WLAN_VENDOR_ATMEL=y
# CONFIG_ATMEL is not set
# CONFIG_AT76C50X_USB is not set
CONFIG_WLAN_VENDOR_BROADCOM=y
# CONFIG_B43 is not set
# CONFIG_B43LEGACY is not set
# CONFIG_BRCMSMAC is not set
# CONFIG_BRCMFMAC is not set
CONFIG_WLAN_VENDOR_CISCO=y
# CONFIG_AIRO is not set
CONFIG_WLAN_VENDOR_INTEL=y
# CONFIG_IPW2100 is not set
# CONFIG_IPW2200 is not set
# CONFIG_IWL4965 is not set
# CONFIG_IWL3945 is not set
# CONFIG_IWLWIFI is not set
# CONFIG_IWLMEI is not set
CONFIG_WLAN_VENDOR_INTERSIL=y
# CONFIG_HOSTAP is not set
# CONFIG_HERMES is not set
# CONFIG_P54_COMMON is not set
CONFIG_WLAN_VENDOR_MARVELL=y
# CONFIG_LIBERTAS is not set
# CONFIG_LIBERTAS_THINFIRM is not set
# CONFIG_MWIFIEX is not set
# CONFIG_MWL8K is not set
CONFIG_WLAN_VENDOR_MEDIATEK=y
# CONFIG_MT7601U is not set
# CONFIG_MT76x0U is not set
# CONFIG_MT76x0E is not set
# CONFIG_MT76x2E is not set
# CONFIG_MT76x2U is not set
# CONFIG_MT7603E is not set
# CONFIG_MT7615E is not set
# CONFIG_MT7663U is not set
# CONFIG_MT7663S is not set
# CONFIG_MT7915E is not set
# CONFIG_MT7921E is not set
# CONFIG_MT7921S is not set
# CONFIG_MT7921U is not set
CONFIG_WLAN_VENDOR_MICROCHIP=y
# CONFIG_WILC1000_SDIO is not set
# CONFIG_WILC1000_SPI is not set
CONFIG_WLAN_VENDOR_PURELIFI=y
# CONFIG_PLFXLC is not set
CONFIG_WLAN_VENDOR_RALINK=y
# CONFIG_RT2X00 is not set
CONFIG_WLAN_VENDOR_REALTEK=y
# CONFIG_RTL8180 is not set
# CONFIG_RTL8187 is not set
CONFIG_RTL_CARDS=m
# CONFIG_RTL8192CE is not set
# CONFIG_RTL8192SE is not set
# CONFIG_RTL8192DE is not set
# CONFIG_RTL8723AE is not set
# CONFIG_RTL8723BE is not set
# CONFIG_RTL8188EE is not set
# CONFIG_RTL8192EE is not set
# CONFIG_RTL8821AE is not set
# CONFIG_RTL8192CU is not set
# CONFIG_RTL8XXXU is not set
# CONFIG_RTW88 is not set
# CONFIG_RTW89 is not set
CONFIG_WLAN_VENDOR_RSI=y
# CONFIG_RSI_91X is not set
CONFIG_WLAN_VENDOR_SILABS=y
# CONFIG_WFX is not set
CONFIG_WLAN_VENDOR_ST=y
# CONFIG_CW1200 is not set
CONFIG_WLAN_VENDOR_TI=y
# CONFIG_WL1251 is not set
# CONFIG_WL12XX is not set
# CONFIG_WL18XX is not set
# CONFIG_WLCORE is not set
CONFIG_WLAN_VENDOR_ZYDAS=y
# CONFIG_USB_ZD1201 is not set
# CONFIG_ZD1211RW is not set
CONFIG_WLAN_VENDOR_QUANTENNA=y
# CONFIG_QTNFMAC_PCIE is not set
CONFIG_MAC80211_HWSIM=m
# CONFIG_USB_NET_RNDIS_WLAN is not set
# CONFIG_VIRT_WIFI is not set
# CONFIG_WAN is not set
CONFIG_IEEE802154_DRIVERS=m
# CONFIG_IEEE802154_FAKELB is not set
# CONFIG_IEEE802154_AT86RF230 is not set
# CONFIG_IEEE802154_MRF24J40 is not set
# CONFIG_IEEE802154_CC2520 is not set
# CONFIG_IEEE802154_ATUSB is not set
# CONFIG_IEEE802154_ADF7242 is not set
# CONFIG_IEEE802154_CA8210 is not set
# CONFIG_IEEE802154_MCR20A is not set
# CONFIG_IEEE802154_HWSIM is not set

#
# Wireless WAN
#
# CONFIG_WWAN is not set
# end of Wireless WAN

CONFIG_XEN_NETDEV_FRONTEND=y
# CONFIG_VMXNET3 is not set
# CONFIG_FUJITSU_ES is not set
# CONFIG_HYPERV_NET is not set
CONFIG_NETDEVSIM=m
# CONFIG_NET_FAILOVER is not set
# CONFIG_ISDN is not set

#
# Input device support
#
CONFIG_INPUT=y
CONFIG_INPUT_LEDS=y
CONFIG_INPUT_FF_MEMLESS=m
CONFIG_INPUT_SPARSEKMAP=m
# CONFIG_INPUT_MATRIXKMAP is not set
CONFIG_INPUT_VIVALDIFMAP=y

#
# Userland interfaces
#
CONFIG_INPUT_MOUSEDEV=y
# CONFIG_INPUT_MOUSEDEV_PSAUX is not set
CONFIG_INPUT_MOUSEDEV_SCREEN_X=1024
CONFIG_INPUT_MOUSEDEV_SCREEN_Y=768
CONFIG_INPUT_JOYDEV=m
CONFIG_INPUT_EVDEV=y
# CONFIG_INPUT_EVBUG is not set

#
# Input Device Drivers
#
CONFIG_INPUT_KEYBOARD=y
# CONFIG_KEYBOARD_ADP5588 is not set
# CONFIG_KEYBOARD_ADP5589 is not set
# CONFIG_KEYBOARD_APPLESPI is not set
CONFIG_KEYBOARD_ATKBD=y
# CONFIG_KEYBOARD_QT1050 is not set
# CONFIG_KEYBOARD_QT1070 is not set
# CONFIG_KEYBOARD_QT2160 is not set
# CONFIG_KEYBOARD_DLINK_DIR685 is not set
# CONFIG_KEYBOARD_LKKBD is not set
# CONFIG_KEYBOARD_GPIO is not set
# CONFIG_KEYBOARD_GPIO_POLLED is not set
# CONFIG_KEYBOARD_TCA6416 is not set
# CONFIG_KEYBOARD_TCA8418 is not set
# CONFIG_KEYBOARD_MATRIX is not set
# CONFIG_KEYBOARD_LM8323 is not set
# CONFIG_KEYBOARD_LM8333 is not set
# CONFIG_KEYBOARD_MAX7359 is not set
# CONFIG_KEYBOARD_MCS is not set
# CONFIG_KEYBOARD_MPR121 is not set
# CONFIG_KEYBOARD_NEWTON is not set
# CONFIG_KEYBOARD_OPENCORES is not set
# CONFIG_KEYBOARD_SAMSUNG is not set
# CONFIG_KEYBOARD_STOWAWAY is not set
# CONFIG_KEYBOARD_SUNKBD is not set
# CONFIG_KEYBOARD_TM2_TOUCHKEY is not set
# CONFIG_KEYBOARD_XTKBD is not set
# CONFIG_KEYBOARD_CYPRESS_SF is not set
CONFIG_INPUT_MOUSE=y
CONFIG_MOUSE_PS2=y
CONFIG_MOUSE_PS2_ALPS=y
CONFIG_MOUSE_PS2_BYD=y
CONFIG_MOUSE_PS2_LOGIPS2PP=y
CONFIG_MOUSE_PS2_SYNAPTICS=y
CONFIG_MOUSE_PS2_SYNAPTICS_SMBUS=y
CONFIG_MOUSE_PS2_CYPRESS=y
CONFIG_MOUSE_PS2_LIFEBOOK=y
CONFIG_MOUSE_PS2_TRACKPOINT=y
CONFIG_MOUSE_PS2_ELANTECH=y
CONFIG_MOUSE_PS2_ELANTECH_SMBUS=y
CONFIG_MOUSE_PS2_SENTELIC=y
# CONFIG_MOUSE_PS2_TOUCHKIT is not set
CONFIG_MOUSE_PS2_FOCALTECH=y
CONFIG_MOUSE_PS2_VMMOUSE=y
CONFIG_MOUSE_PS2_SMBUS=y
CONFIG_MOUSE_SERIAL=m
# CONFIG_MOUSE_APPLETOUCH is not set
# CONFIG_MOUSE_BCM5974 is not set
CONFIG_MOUSE_CYAPA=m
CONFIG_MOUSE_ELAN_I2C=m
CONFIG_MOUSE_ELAN_I2C_I2C=y
CONFIG_MOUSE_ELAN_I2C_SMBUS=y
CONFIG_MOUSE_VSXXXAA=m
# CONFIG_MOUSE_GPIO is not set
CONFIG_MOUSE_SYNAPTICS_I2C=m
# CONFIG_MOUSE_SYNAPTICS_USB is not set
# CONFIG_INPUT_JOYSTICK is not set
# CONFIG_INPUT_TABLET is not set
# CONFIG_INPUT_TOUCHSCREEN is not set
# CONFIG_INPUT_MISC is not set
CONFIG_RMI4_CORE=m
CONFIG_RMI4_I2C=m
CONFIG_RMI4_SPI=m
CONFIG_RMI4_SMB=m
CONFIG_RMI4_F03=y
CONFIG_RMI4_F03_SERIO=m
CONFIG_RMI4_2D_SENSOR=y
CONFIG_RMI4_F11=y
CONFIG_RMI4_F12=y
CONFIG_RMI4_F30=y
CONFIG_RMI4_F34=y
# CONFIG_RMI4_F3A is not set
# CONFIG_RMI4_F54 is not set
CONFIG_RMI4_F55=y

#
# Hardware I/O ports
#
CONFIG_SERIO=y
CONFIG_ARCH_MIGHT_HAVE_PC_SERIO=y
CONFIG_SERIO_I8042=y
CONFIG_SERIO_SERPORT=y
# CONFIG_SERIO_CT82C710 is not set
# CONFIG_SERIO_PARKBD is not set
# CONFIG_SERIO_PCIPS2 is not set
CONFIG_SERIO_LIBPS2=y
CONFIG_SERIO_RAW=m
CONFIG_SERIO_ALTERA_PS2=m
# CONFIG_SERIO_PS2MULT is not set
CONFIG_SERIO_ARC_PS2=m
CONFIG_HYPERV_KEYBOARD=m
# CONFIG_SERIO_GPIO_PS2 is not set
# CONFIG_USERIO is not set
# CONFIG_GAMEPORT is not set
# end of Hardware I/O ports
# end of Input device support

#
# Character devices
#
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_CONSOLE_TRANSLATIONS=y
CONFIG_VT_CONSOLE=y
CONFIG_VT_CONSOLE_SLEEP=y
CONFIG_HW_CONSOLE=y
CONFIG_VT_HW_CONSOLE_BINDING=y
CONFIG_UNIX98_PTYS=y
# CONFIG_LEGACY_PTYS is not set
CONFIG_LDISC_AUTOLOAD=y

#
# Serial drivers
#
CONFIG_SERIAL_EARLYCON=y
CONFIG_SERIAL_8250=y
# CONFIG_SERIAL_8250_DEPRECATED_OPTIONS is not set
CONFIG_SERIAL_8250_PNP=y
# CONFIG_SERIAL_8250_16550A_VARIANTS is not set
# CONFIG_SERIAL_8250_FINTEK is not set
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_DMA=y
CONFIG_SERIAL_8250_PCI=y
CONFIG_SERIAL_8250_EXAR=y
CONFIG_SERIAL_8250_NR_UARTS=64
CONFIG_SERIAL_8250_RUNTIME_UARTS=4
CONFIG_SERIAL_8250_EXTENDED=y
CONFIG_SERIAL_8250_MANY_PORTS=y
CONFIG_SERIAL_8250_SHARE_IRQ=y
# CONFIG_SERIAL_8250_DETECT_IRQ is not set
CONFIG_SERIAL_8250_RSA=y
CONFIG_SERIAL_8250_DWLIB=y
CONFIG_SERIAL_8250_DW=y
# CONFIG_SERIAL_8250_RT288X is not set
CONFIG_SERIAL_8250_LPSS=y
CONFIG_SERIAL_8250_MID=y
CONFIG_SERIAL_8250_PERICOM=y

#
# Non-8250 serial port support
#
# CONFIG_SERIAL_MAX3100 is not set
# CONFIG_SERIAL_MAX310X is not set
# CONFIG_SERIAL_UARTLITE is not set
CONFIG_SERIAL_CORE=y
CONFIG_SERIAL_CORE_CONSOLE=y
CONFIG_SERIAL_JSM=m
# CONFIG_SERIAL_LANTIQ is not set
# CONFIG_SERIAL_SCCNXP is not set
# CONFIG_SERIAL_SC16IS7XX is not set
# CONFIG_SERIAL_ALTERA_JTAGUART is not set
# CONFIG_SERIAL_ALTERA_UART is not set
CONFIG_SERIAL_ARC=m
CONFIG_SERIAL_ARC_NR_PORTS=1
# CONFIG_SERIAL_RP2 is not set
# CONFIG_SERIAL_FSL_LPUART is not set
# CONFIG_SERIAL_FSL_LINFLEXUART is not set
# CONFIG_SERIAL_SPRD is not set
# end of Serial drivers

CONFIG_SERIAL_MCTRL_GPIO=y
CONFIG_SERIAL_NONSTANDARD=y
# CONFIG_MOXA_INTELLIO is not set
# CONFIG_MOXA_SMARTIO is not set
CONFIG_SYNCLINK_GT=m
CONFIG_N_HDLC=m
CONFIG_N_GSM=m
CONFIG_NOZOMI=m
# CONFIG_NULL_TTY is not set
CONFIG_HVC_DRIVER=y
CONFIG_HVC_IRQ=y
CONFIG_HVC_XEN=y
CONFIG_HVC_XEN_FRONTEND=y
# CONFIG_SERIAL_DEV_BUS is not set
CONFIG_PRINTER=m
# CONFIG_LP_CONSOLE is not set
CONFIG_PPDEV=m
CONFIG_VIRTIO_CONSOLE=m
CONFIG_IPMI_HANDLER=m
CONFIG_IPMI_DMI_DECODE=y
CONFIG_IPMI_PLAT_DATA=y
CONFIG_IPMI_PANIC_EVENT=y
CONFIG_IPMI_PANIC_STRING=y
CONFIG_IPMI_DEVICE_INTERFACE=m
CONFIG_IPMI_SI=m
CONFIG_IPMI_SSIF=m
CONFIG_IPMI_WATCHDOG=m
CONFIG_IPMI_POWEROFF=m
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_TIMERIOMEM=m
CONFIG_HW_RANDOM_INTEL=m
CONFIG_HW_RANDOM_AMD=m
# CONFIG_HW_RANDOM_BA431 is not set
CONFIG_HW_RANDOM_VIA=m
CONFIG_HW_RANDOM_VIRTIO=y
# CONFIG_HW_RANDOM_XIPHERA is not set
# CONFIG_APPLICOM is not set
# CONFIG_MWAVE is not set
CONFIG_DEVMEM=y
CONFIG_NVRAM=y
CONFIG_DEVPORT=y
CONFIG_HPET=y
CONFIG_HPET_MMAP=y
# CONFIG_HPET_MMAP_DEFAULT is not set
CONFIG_HANGCHECK_TIMER=m
CONFIG_UV_MMTIMER=m
CONFIG_TCG_TPM=y
CONFIG_HW_RANDOM_TPM=y
CONFIG_TCG_TIS_CORE=y
CONFIG_TCG_TIS=y
# CONFIG_TCG_TIS_SPI is not set
# CONFIG_TCG_TIS_I2C is not set
# CONFIG_TCG_TIS_I2C_CR50 is not set
CONFIG_TCG_TIS_I2C_ATMEL=m
CONFIG_TCG_TIS_I2C_INFINEON=m
CONFIG_TCG_TIS_I2C_NUVOTON=m
CONFIG_TCG_NSC=m
CONFIG_TCG_ATMEL=m
CONFIG_TCG_INFINEON=m
# CONFIG_TCG_XEN is not set
CONFIG_TCG_CRB=y
# CONFIG_TCG_VTPM_PROXY is not set
CONFIG_TCG_TIS_ST33ZP24=m
CONFIG_TCG_TIS_ST33ZP24_I2C=m
# CONFIG_TCG_TIS_ST33ZP24_SPI is not set
CONFIG_TELCLOCK=m
# CONFIG_XILLYBUS is not set
# CONFIG_XILLYUSB is not set
# CONFIG_RANDOM_TRUST_CPU is not set
# CONFIG_RANDOM_TRUST_BOOTLOADER is not set
# end of Character devices

#
# I2C support
#
CONFIG_I2C=y
CONFIG_ACPI_I2C_OPREGION=y
CONFIG_I2C_BOARDINFO=y
CONFIG_I2C_COMPAT=y
CONFIG_I2C_CHARDEV=m
CONFIG_I2C_MUX=m

#
# Multiplexer I2C Chip support
#
# CONFIG_I2C_MUX_GPIO is not set
# CONFIG_I2C_MUX_LTC4306 is not set
# CONFIG_I2C_MUX_PCA9541 is not set
# CONFIG_I2C_MUX_PCA954x is not set
# CONFIG_I2C_MUX_REG is not set
CONFIG_I2C_MUX_MLXCPLD=m
# end of Multiplexer I2C Chip support

CONFIG_I2C_HELPER_AUTO=y
CONFIG_I2C_SMBUS=y
CONFIG_I2C_ALGOBIT=y
CONFIG_I2C_ALGOPCA=m

#
# I2C Hardware Bus support
#

#
# PC SMBus host controller drivers
#
# CONFIG_I2C_ALI1535 is not set
# CONFIG_I2C_ALI1563 is not set
# CONFIG_I2C_ALI15X3 is not set
CONFIG_I2C_AMD756=m
CONFIG_I2C_AMD756_S4882=m
CONFIG_I2C_AMD8111=m
# CONFIG_I2C_AMD_MP2 is not set
CONFIG_I2C_I801=y
CONFIG_I2C_ISCH=m
CONFIG_I2C_ISMT=m
CONFIG_I2C_PIIX4=m
CONFIG_I2C_NFORCE2=m
CONFIG_I2C_NFORCE2_S4985=m
# CONFIG_I2C_NVIDIA_GPU is not set
# CONFIG_I2C_SIS5595 is not set
# CONFIG_I2C_SIS630 is not set
CONFIG_I2C_SIS96X=m
CONFIG_I2C_VIA=m
CONFIG_I2C_VIAPRO=m

#
# ACPI drivers
#
CONFIG_I2C_SCMI=m

#
# I2C system bus drivers (mostly embedded / system-on-chip)
#
# CONFIG_I2C_CBUS_GPIO is not set
CONFIG_I2C_DESIGNWARE_CORE=m
# CONFIG_I2C_DESIGNWARE_SLAVE is not set
CONFIG_I2C_DESIGNWARE_PLATFORM=m
# CONFIG_I2C_DESIGNWARE_AMDPSP is not set
CONFIG_I2C_DESIGNWARE_BAYTRAIL=y
# CONFIG_I2C_DESIGNWARE_PCI is not set
# CONFIG_I2C_EMEV2 is not set
# CONFIG_I2C_GPIO is not set
# CONFIG_I2C_OCORES is not set
CONFIG_I2C_PCA_PLATFORM=m
CONFIG_I2C_SIMTEC=m
# CONFIG_I2C_XILINX is not set

#
# External I2C/SMBus adapter drivers
#
# CONFIG_I2C_DIOLAN_U2C is not set
# CONFIG_I2C_CP2615 is not set
CONFIG_I2C_PARPORT=m
# CONFIG_I2C_ROBOTFUZZ_OSIF is not set
# CONFIG_I2C_TAOS_EVM is not set
# CONFIG_I2C_TINY_USB is not set

#
# Other I2C/SMBus bus drivers
#
CONFIG_I2C_MLXCPLD=m
# CONFIG_I2C_VIRTIO is not set
# end of I2C Hardware Bus support

CONFIG_I2C_STUB=m
# CONFIG_I2C_SLAVE is not set
# CONFIG_I2C_DEBUG_CORE is not set
# CONFIG_I2C_DEBUG_ALGO is not set
# CONFIG_I2C_DEBUG_BUS is not set
# end of I2C support

# CONFIG_I3C is not set
CONFIG_SPI=y
# CONFIG_SPI_DEBUG is not set
CONFIG_SPI_MASTER=y
# CONFIG_SPI_MEM is not set

#
# SPI Master Controller Drivers
#
# CONFIG_SPI_ALTERA is not set
# CONFIG_SPI_AXI_SPI_ENGINE is not set
# CONFIG_SPI_BITBANG is not set
# CONFIG_SPI_BUTTERFLY is not set
# CONFIG_SPI_CADENCE is not set
# CONFIG_SPI_DESIGNWARE is not set
# CONFIG_SPI_NXP_FLEXSPI is not set
# CONFIG_SPI_GPIO is not set
# CONFIG_SPI_LM70_LLP is not set
# CONFIG_SPI_MICROCHIP_CORE is not set
# CONFIG_SPI_MICROCHIP_CORE_QSPI is not set
# CONFIG_SPI_LANTIQ_SSC is not set
# CONFIG_SPI_OC_TINY is not set
# CONFIG_SPI_PXA2XX is not set
# CONFIG_SPI_ROCKCHIP is not set
# CONFIG_SPI_SC18IS602 is not set
# CONFIG_SPI_SIFIVE is not set
# CONFIG_SPI_MXIC is not set
# CONFIG_SPI_XCOMM is not set
# CONFIG_SPI_XILINX is not set
# CONFIG_SPI_ZYNQMP_GQSPI is not set
# CONFIG_SPI_AMD is not set

#
# SPI Multiplexer support
#
# CONFIG_SPI_MUX is not set

#
# SPI Protocol Masters
#
# CONFIG_SPI_SPIDEV is not set
# CONFIG_SPI_LOOPBACK_TEST is not set
# CONFIG_SPI_TLE62X0 is not set
# CONFIG_SPI_SLAVE is not set
CONFIG_SPI_DYNAMIC=y
# CONFIG_SPMI is not set
# CONFIG_HSI is not set
CONFIG_PPS=y
# CONFIG_PPS_DEBUG is not set

#
# PPS clients support
#
# CONFIG_PPS_CLIENT_KTIMER is not set
CONFIG_PPS_CLIENT_LDISC=m
CONFIG_PPS_CLIENT_PARPORT=m
CONFIG_PPS_CLIENT_GPIO=m

#
# PPS generators support
#

#
# PTP clock support
#
CONFIG_PTP_1588_CLOCK=y
CONFIG_PTP_1588_CLOCK_OPTIONAL=y
# CONFIG_DP83640_PHY is not set
# CONFIG_PTP_1588_CLOCK_INES is not set
CONFIG_PTP_1588_CLOCK_KVM=m
# CONFIG_PTP_1588_CLOCK_IDT82P33 is not set
# CONFIG_PTP_1588_CLOCK_IDTCM is not set
# CONFIG_PTP_1588_CLOCK_VMW is not set
# end of PTP clock support

CONFIG_PINCTRL=y
CONFIG_PINMUX=y
CONFIG_PINCONF=y
CONFIG_GENERIC_PINCONF=y
# CONFIG_DEBUG_PINCTRL is not set
# CONFIG_PINCTRL_AMD is not set
# CONFIG_PINCTRL_MCP23S08 is not set
# CONFIG_PINCTRL_SX150X is not set

#
# Intel pinctrl drivers
#
CONFIG_PINCTRL_BAYTRAIL=y
# CONFIG_PINCTRL_CHERRYVIEW is not set
# CONFIG_PINCTRL_LYNXPOINT is not set
CONFIG_PINCTRL_INTEL=y
# CONFIG_PINCTRL_ALDERLAKE is not set
CONFIG_PINCTRL_BROXTON=m
CONFIG_PINCTRL_CANNONLAKE=m
CONFIG_PINCTRL_CEDARFORK=m
CONFIG_PINCTRL_DENVERTON=m
# CONFIG_PINCTRL_ELKHARTLAKE is not set
# CONFIG_PINCTRL_EMMITSBURG is not set
CONFIG_PINCTRL_GEMINILAKE=m
# CONFIG_PINCTRL_ICELAKE is not set
# CONFIG_PINCTRL_JASPERLAKE is not set
# CONFIG_PINCTRL_LAKEFIELD is not set
CONFIG_PINCTRL_LEWISBURG=m
# CONFIG_PINCTRL_METEORLAKE is not set
CONFIG_PINCTRL_SUNRISEPOINT=m
# CONFIG_PINCTRL_TIGERLAKE is not set
# end of Intel pinctrl drivers

#
# Renesas pinctrl drivers
#
# end of Renesas pinctrl drivers

CONFIG_GPIOLIB=y
CONFIG_GPIOLIB_FASTPATH_LIMIT=512
CONFIG_GPIO_ACPI=y
CONFIG_GPIOLIB_IRQCHIP=y
# CONFIG_DEBUG_GPIO is not set
CONFIG_GPIO_CDEV=y
CONFIG_GPIO_CDEV_V1=y
CONFIG_GPIO_GENERIC=m

#
# Memory mapped GPIO drivers
#
CONFIG_GPIO_AMDPT=m
# CONFIG_GPIO_DWAPB is not set
# CONFIG_GPIO_EXAR is not set
# CONFIG_GPIO_GENERIC_PLATFORM is not set
CONFIG_GPIO_ICH=m
# CONFIG_GPIO_MB86S7X is not set
# CONFIG_GPIO_VX855 is not set
# CONFIG_GPIO_AMD_FCH is not set
# end of Memory mapped GPIO drivers

#
# Port-mapped I/O GPIO drivers
#
# CONFIG_GPIO_F7188X is not set
# CONFIG_GPIO_IT87 is not set
# CONFIG_GPIO_SCH is not set
# CONFIG_GPIO_SCH311X is not set
# CONFIG_GPIO_WINBOND is not set
# CONFIG_GPIO_WS16C48 is not set
# end of Port-mapped I/O GPIO drivers

#
# I2C GPIO expanders
#
# CONFIG_GPIO_ADP5588 is not set
# CONFIG_GPIO_MAX7300 is not set
# CONFIG_GPIO_MAX732X is not set
# CONFIG_GPIO_PCA953X is not set
# CONFIG_GPIO_PCA9570 is not set
# CONFIG_GPIO_PCF857X is not set
# CONFIG_GPIO_TPIC2810 is not set
# end of I2C GPIO expanders

#
# MFD GPIO expanders
#
# end of MFD GPIO expanders

#
# PCI GPIO expanders
#
# CONFIG_GPIO_AMD8111 is not set
# CONFIG_GPIO_BT8XX is not set
# CONFIG_GPIO_ML_IOH is not set
# CONFIG_GPIO_PCI_IDIO_16 is not set
# CONFIG_GPIO_PCIE_IDIO_24 is not set
# CONFIG_GPIO_RDC321X is not set
# end of PCI GPIO expanders

#
# SPI GPIO expanders
#
# CONFIG_GPIO_MAX3191X is not set
# CONFIG_GPIO_MAX7301 is not set
# CONFIG_GPIO_MC33880 is not set
# CONFIG_GPIO_PISOSR is not set
# CONFIG_GPIO_XRA1403 is not set
# end of SPI GPIO expanders

#
# USB GPIO expanders
#
# end of USB GPIO expanders

#
# Virtual GPIO drivers
#
# CONFIG_GPIO_AGGREGATOR is not set
# CONFIG_GPIO_MOCKUP is not set
# CONFIG_GPIO_VIRTIO is not set
# CONFIG_GPIO_SIM is not set
# end of Virtual GPIO drivers

# CONFIG_W1 is not set
CONFIG_POWER_RESET=y
# CONFIG_POWER_RESET_RESTART is not set
CONFIG_POWER_SUPPLY=y
# CONFIG_POWER_SUPPLY_DEBUG is not set
CONFIG_POWER_SUPPLY_HWMON=y
# CONFIG_PDA_POWER is not set
# CONFIG_IP5XXX_POWER is not set
# CONFIG_TEST_POWER is not set
# CONFIG_CHARGER_ADP5061 is not set
# CONFIG_BATTERY_CW2015 is not set
# CONFIG_BATTERY_DS2780 is not set
# CONFIG_BATTERY_DS2781 is not set
# CONFIG_BATTERY_DS2782 is not set
# CONFIG_BATTERY_SAMSUNG_SDI is not set
# CONFIG_BATTERY_SBS is not set
# CONFIG_CHARGER_SBS is not set
# CONFIG_MANAGER_SBS is not set
# CONFIG_BATTERY_BQ27XXX is not set
# CONFIG_BATTERY_MAX17040 is not set
# CONFIG_BATTERY_MAX17042 is not set
# CONFIG_CHARGER_MAX8903 is not set
# CONFIG_CHARGER_LP8727 is not set
# CONFIG_CHARGER_GPIO is not set
# CONFIG_CHARGER_LT3651 is not set
# CONFIG_CHARGER_LTC4162L is not set
# CONFIG_CHARGER_MAX77976 is not set
# CONFIG_CHARGER_BQ2415X is not set
# CONFIG_CHARGER_BQ24257 is not set
# CONFIG_CHARGER_BQ24735 is not set
# CONFIG_CHARGER_BQ2515X is not set
# CONFIG_CHARGER_BQ25890 is not set
# CONFIG_CHARGER_BQ25980 is not set
# CONFIG_CHARGER_BQ256XX is not set
# CONFIG_BATTERY_GAUGE_LTC2941 is not set
# CONFIG_BATTERY_GOLDFISH is not set
# CONFIG_BATTERY_RT5033 is not set
# CONFIG_CHARGER_RT9455 is not set
# CONFIG_CHARGER_BD99954 is not set
# CONFIG_BATTERY_UG3105 is not set
CONFIG_HWMON=y
CONFIG_HWMON_VID=m
# CONFIG_HWMON_DEBUG_CHIP is not set

#
# Native drivers
#
CONFIG_SENSORS_ABITUGURU=m
CONFIG_SENSORS_ABITUGURU3=m
# CONFIG_SENSORS_AD7314 is not set
CONFIG_SENSORS_AD7414=m
CONFIG_SENSORS_AD7418=m
CONFIG_SENSORS_ADM1025=m
CONFIG_SENSORS_ADM1026=m
CONFIG_SENSORS_ADM1029=m
CONFIG_SENSORS_ADM1031=m
# CONFIG_SENSORS_ADM1177 is not set
CONFIG_SENSORS_ADM9240=m
CONFIG_SENSORS_ADT7X10=m
# CONFIG_SENSORS_ADT7310 is not set
CONFIG_SENSORS_ADT7410=m
CONFIG_SENSORS_ADT7411=m
CONFIG_SENSORS_ADT7462=m
CONFIG_SENSORS_ADT7470=m
CONFIG_SENSORS_ADT7475=m
# CONFIG_SENSORS_AHT10 is not set
# CONFIG_SENSORS_AQUACOMPUTER_D5NEXT is not set
# CONFIG_SENSORS_AS370 is not set
CONFIG_SENSORS_ASC7621=m
# CONFIG_SENSORS_AXI_FAN_CONTROL is not set
CONFIG_SENSORS_K8TEMP=m
CONFIG_SENSORS_K10TEMP=m
CONFIG_SENSORS_FAM15H_POWER=m
CONFIG_SENSORS_APPLESMC=m
CONFIG_SENSORS_ASB100=m
# CONFIG_SENSORS_ASPEED is not set
CONFIG_SENSORS_ATXP1=m
# CONFIG_SENSORS_CORSAIR_CPRO is not set
# CONFIG_SENSORS_CORSAIR_PSU is not set
# CONFIG_SENSORS_DRIVETEMP is not set
CONFIG_SENSORS_DS620=m
CONFIG_SENSORS_DS1621=m
CONFIG_SENSORS_DELL_SMM=m
# CONFIG_I8K is not set
CONFIG_SENSORS_I5K_AMB=m
CONFIG_SENSORS_F71805F=m
CONFIG_SENSORS_F71882FG=m
CONFIG_SENSORS_F75375S=m
CONFIG_SENSORS_FSCHMD=m
# CONFIG_SENSORS_FTSTEUTATES is not set
CONFIG_SENSORS_GL518SM=m
CONFIG_SENSORS_GL520SM=m
CONFIG_SENSORS_G760A=m
# CONFIG_SENSORS_G762 is not set
# CONFIG_SENSORS_HIH6130 is not set
CONFIG_SENSORS_IBMAEM=m
CONFIG_SENSORS_IBMPEX=m
CONFIG_SENSORS_I5500=m
CONFIG_SENSORS_CORETEMP=m
CONFIG_SENSORS_IT87=m
CONFIG_SENSORS_JC42=m
# CONFIG_SENSORS_POWR1220 is not set
CONFIG_SENSORS_LINEAGE=m
# CONFIG_SENSORS_LTC2945 is not set
# CONFIG_SENSORS_LTC2947_I2C is not set
# CONFIG_SENSORS_LTC2947_SPI is not set
# CONFIG_SENSORS_LTC2990 is not set
# CONFIG_SENSORS_LTC2992 is not set
CONFIG_SENSORS_LTC4151=m
CONFIG_SENSORS_LTC4215=m
# CONFIG_SENSORS_LTC4222 is not set
CONFIG_SENSORS_LTC4245=m
# CONFIG_SENSORS_LTC4260 is not set
CONFIG_SENSORS_LTC4261=m
# CONFIG_SENSORS_MAX1111 is not set
# CONFIG_SENSORS_MAX127 is not set
CONFIG_SENSORS_MAX16065=m
CONFIG_SENSORS_MAX1619=m
CONFIG_SENSORS_MAX1668=m
CONFIG_SENSORS_MAX197=m
# CONFIG_SENSORS_MAX31722 is not set
# CONFIG_SENSORS_MAX31730 is not set
# CONFIG_SENSORS_MAX6620 is not set
# CONFIG_SENSORS_MAX6621 is not set
CONFIG_SENSORS_MAX6639=m
CONFIG_SENSORS_MAX6650=m
CONFIG_SENSORS_MAX6697=m
# CONFIG_SENSORS_MAX31790 is not set
CONFIG_SENSORS_MCP3021=m
# CONFIG_SENSORS_MLXREG_FAN is not set
# CONFIG_SENSORS_TC654 is not set
# CONFIG_SENSORS_TPS23861 is not set
# CONFIG_SENSORS_MR75203 is not set
# CONFIG_SENSORS_ADCXX is not set
CONFIG_SENSORS_LM63=m
# CONFIG_SENSORS_LM70 is not set
CONFIG_SENSORS_LM73=m
CONFIG_SENSORS_LM75=m
CONFIG_SENSORS_LM77=m
CONFIG_SENSORS_LM78=m
CONFIG_SENSORS_LM80=m
CONFIG_SENSORS_LM83=m
CONFIG_SENSORS_LM85=m
CONFIG_SENSORS_LM87=m
CONFIG_SENSORS_LM90=m
CONFIG_SENSORS_LM92=m
CONFIG_SENSORS_LM93=m
CONFIG_SENSORS_LM95234=m
CONFIG_SENSORS_LM95241=m
CONFIG_SENSORS_LM95245=m
CONFIG_SENSORS_PC87360=m
CONFIG_SENSORS_PC87427=m
# CONFIG_SENSORS_NCT6683 is not set
CONFIG_SENSORS_NCT6775_CORE=m
CONFIG_SENSORS_NCT6775=m
# CONFIG_SENSORS_NCT6775_I2C is not set
# CONFIG_SENSORS_NCT7802 is not set
# CONFIG_SENSORS_NCT7904 is not set
# CONFIG_SENSORS_NPCM7XX is not set
# CONFIG_SENSORS_NZXT_KRAKEN2 is not set
# CONFIG_SENSORS_NZXT_SMART2 is not set
CONFIG_SENSORS_PCF8591=m
CONFIG_PMBUS=m
CONFIG_SENSORS_PMBUS=m
# CONFIG_SENSORS_ADM1266 is not set
CONFIG_SENSORS_ADM1275=m
# CONFIG_SENSORS_BEL_PFE is not set
# CONFIG_SENSORS_BPA_RS600 is not set
# CONFIG_SENSORS_DELTA_AHE50DC_FAN is not set
# CONFIG_SENSORS_FSP_3Y is not set
# CONFIG_SENSORS_IBM_CFFPS is not set
# CONFIG_SENSORS_DPS920AB is not set
# CONFIG_SENSORS_INSPUR_IPSPS is not set
# CONFIG_SENSORS_IR35221 is not set
# CONFIG_SENSORS_IR36021 is not set
# CONFIG_SENSORS_IR38064 is not set
# CONFIG_SENSORS_IRPS5401 is not set
# CONFIG_SENSORS_ISL68137 is not set
CONFIG_SENSORS_LM25066=m
# CONFIG_SENSORS_LT7182S is not set
CONFIG_SENSORS_LTC2978=m
# CONFIG_SENSORS_LTC3815 is not set
# CONFIG_SENSORS_MAX15301 is not set
CONFIG_SENSORS_MAX16064=m
# CONFIG_SENSORS_MAX16601 is not set
# CONFIG_SENSORS_MAX20730 is not set
# CONFIG_SENSORS_MAX20751 is not set
# CONFIG_SENSORS_MAX31785 is not set
CONFIG_SENSORS_MAX34440=m
CONFIG_SENSORS_MAX8688=m
# CONFIG_SENSORS_MP2888 is not set
# CONFIG_SENSORS_MP2975 is not set
# CONFIG_SENSORS_MP5023 is not set
# CONFIG_SENSORS_PIM4328 is not set
# CONFIG_SENSORS_PLI1209BC is not set
# CONFIG_SENSORS_PM6764TR is not set
# CONFIG_SENSORS_PXE1610 is not set
# CONFIG_SENSORS_Q54SJ108A2 is not set
# CONFIG_SENSORS_STPDDC60 is not set
# CONFIG_SENSORS_TPS40422 is not set
# CONFIG_SENSORS_TPS53679 is not set
CONFIG_SENSORS_UCD9000=m
CONFIG_SENSORS_UCD9200=m
# CONFIG_SENSORS_XDPE152 is not set
# CONFIG_SENSORS_XDPE122 is not set
CONFIG_SENSORS_ZL6100=m
# CONFIG_SENSORS_SBTSI is not set
# CONFIG_SENSORS_SBRMI is not set
CONFIG_SENSORS_SHT15=m
CONFIG_SENSORS_SHT21=m
# CONFIG_SENSORS_SHT3x is not set
# CONFIG_SENSORS_SHT4x is not set
# CONFIG_SENSORS_SHTC1 is not set
CONFIG_SENSORS_SIS5595=m
CONFIG_SENSORS_DME1737=m
CONFIG_SENSORS_EMC1403=m
# CONFIG_SENSORS_EMC2103 is not set
# CONFIG_SENSORS_EMC2305 is not set
CONFIG_SENSORS_EMC6W201=m
CONFIG_SENSORS_SMSC47M1=m
CONFIG_SENSORS_SMSC47M192=m
CONFIG_SENSORS_SMSC47B397=m
CONFIG_SENSORS_SCH56XX_COMMON=m
CONFIG_SENSORS_SCH5627=m
CONFIG_SENSORS_SCH5636=m
# CONFIG_SENSORS_STTS751 is not set
# CONFIG_SENSORS_SMM665 is not set
# CONFIG_SENSORS_ADC128D818 is not set
CONFIG_SENSORS_ADS7828=m
# CONFIG_SENSORS_ADS7871 is not set
CONFIG_SENSORS_AMC6821=m
CONFIG_SENSORS_INA209=m
CONFIG_SENSORS_INA2XX=m
# CONFIG_SENSORS_INA238 is not set
# CONFIG_SENSORS_INA3221 is not set
# CONFIG_SENSORS_TC74 is not set
CONFIG_SENSORS_THMC50=m
CONFIG_SENSORS_TMP102=m
# CONFIG_SENSORS_TMP103 is not set
# CONFIG_SENSORS_TMP108 is not set
CONFIG_SENSORS_TMP401=m
CONFIG_SENSORS_TMP421=m
# CONFIG_SENSORS_TMP464 is not set
# CONFIG_SENSORS_TMP513 is not set
CONFIG_SENSORS_VIA_CPUTEMP=m
CONFIG_SENSORS_VIA686A=m
CONFIG_SENSORS_VT1211=m
CONFIG_SENSORS_VT8231=m
# CONFIG_SENSORS_W83773G is not set
CONFIG_SENSORS_W83781D=m
CONFIG_SENSORS_W83791D=m
CONFIG_SENSORS_W83792D=m
CONFIG_SENSORS_W83793=m
CONFIG_SENSORS_W83795=m
# CONFIG_SENSORS_W83795_FANCTRL is not set
CONFIG_SENSORS_W83L785TS=m
CONFIG_SENSORS_W83L786NG=m
CONFIG_SENSORS_W83627HF=m
CONFIG_SENSORS_W83627EHF=m
# CONFIG_SENSORS_XGENE is not set

#
# ACPI drivers
#
CONFIG_SENSORS_ACPI_POWER=m
CONFIG_SENSORS_ATK0110=m
# CONFIG_SENSORS_ASUS_WMI is not set
# CONFIG_SENSORS_ASUS_EC is not set
CONFIG_THERMAL=y
# CONFIG_THERMAL_NETLINK is not set
# CONFIG_THERMAL_STATISTICS is not set
CONFIG_THERMAL_EMERGENCY_POWEROFF_DELAY_MS=0
CONFIG_THERMAL_HWMON=y
CONFIG_THERMAL_WRITABLE_TRIPS=y
CONFIG_THERMAL_DEFAULT_GOV_STEP_WISE=y
# CONFIG_THERMAL_DEFAULT_GOV_FAIR_SHARE is not set
# CONFIG_THERMAL_DEFAULT_GOV_USER_SPACE is not set
CONFIG_THERMAL_GOV_FAIR_SHARE=y
CONFIG_THERMAL_GOV_STEP_WISE=y
CONFIG_THERMAL_GOV_BANG_BANG=y
CONFIG_THERMAL_GOV_USER_SPACE=y
# CONFIG_THERMAL_EMULATION is not set

#
# Intel thermal drivers
#
CONFIG_INTEL_POWERCLAMP=m
CONFIG_X86_THERMAL_VECTOR=y
CONFIG_X86_PKG_TEMP_THERMAL=m
CONFIG_INTEL_SOC_DTS_IOSF_CORE=m
# CONFIG_INTEL_SOC_DTS_THERMAL is not set

#
# ACPI INT340X thermal drivers
#
CONFIG_INT340X_THERMAL=m
CONFIG_ACPI_THERMAL_REL=m
# CONFIG_INT3406_THERMAL is not set
CONFIG_PROC_THERMAL_MMIO_RAPL=m
# end of ACPI INT340X thermal drivers

CONFIG_INTEL_PCH_THERMAL=m
# CONFIG_INTEL_TCC_COOLING is not set
# CONFIG_INTEL_MENLOW is not set
# CONFIG_INTEL_HFI_THERMAL is not set
# end of Intel thermal drivers

CONFIG_WATCHDOG=y
CONFIG_WATCHDOG_CORE=y
# CONFIG_WATCHDOG_NOWAYOUT is not set
CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y
CONFIG_WATCHDOG_OPEN_TIMEOUT=0
CONFIG_WATCHDOG_SYSFS=y
# CONFIG_WATCHDOG_HRTIMER_PRETIMEOUT is not set

#
# Watchdog Pretimeout Governors
#
# CONFIG_WATCHDOG_PRETIMEOUT_GOV is not set

#
# Watchdog Device Drivers
#
CONFIG_SOFT_WATCHDOG=m
CONFIG_WDAT_WDT=m
# CONFIG_XILINX_WATCHDOG is not set
# CONFIG_ZIIRAVE_WATCHDOG is not set
# CONFIG_MLX_WDT is not set
# CONFIG_CADENCE_WATCHDOG is not set
# CONFIG_DW_WATCHDOG is not set
# CONFIG_MAX63XX_WATCHDOG is not set
# CONFIG_ACQUIRE_WDT is not set
# CONFIG_ADVANTECH_WDT is not set
CONFIG_ALIM1535_WDT=m
CONFIG_ALIM7101_WDT=m
# CONFIG_EBC_C384_WDT is not set
CONFIG_F71808E_WDT=m
CONFIG_SP5100_TCO=m
CONFIG_SBC_FITPC2_WATCHDOG=m
# CONFIG_EUROTECH_WDT is not set
CONFIG_IB700_WDT=m
CONFIG_IBMASR=m
# CONFIG_WAFER_WDT is not set
CONFIG_I6300ESB_WDT=y
CONFIG_IE6XX_WDT=m
CONFIG_ITCO_WDT=y
CONFIG_ITCO_VENDOR_SUPPORT=y
CONFIG_IT8712F_WDT=m
CONFIG_IT87_WDT=m
CONFIG_HP_WATCHDOG=m
CONFIG_HPWDT_NMI_DECODING=y
# CONFIG_SC1200_WDT is not set
# CONFIG_PC87413_WDT is not set
CONFIG_NV_TCO=m
# CONFIG_60XX_WDT is not set
# CONFIG_CPU5_WDT is not set
CONFIG_SMSC_SCH311X_WDT=m
# CONFIG_SMSC37B787_WDT is not set
# CONFIG_TQMX86_WDT is not set
CONFIG_VIA_WDT=m
CONFIG_W83627HF_WDT=m
CONFIG_W83877F_WDT=m
CONFIG_W83977F_WDT=m
CONFIG_MACHZ_WDT=m
# CONFIG_SBC_EPX_C3_WATCHDOG is not set
CONFIG_INTEL_MEI_WDT=m
# CONFIG_NI903X_WDT is not set
# CONFIG_NIC7018_WDT is not set
# CONFIG_MEN_A21_WDT is not set
CONFIG_XEN_WDT=m

#
# PCI-based Watchdog Cards
#
CONFIG_PCIPCWATCHDOG=m
CONFIG_WDTPCI=m

#
# USB-based Watchdog Cards
#
# CONFIG_USBPCWATCHDOG is not set
CONFIG_SSB_POSSIBLE=y
# CONFIG_SSB is not set
CONFIG_BCMA_POSSIBLE=y
CONFIG_BCMA=m
CONFIG_BCMA_HOST_PCI_POSSIBLE=y
CONFIG_BCMA_HOST_PCI=y
# CONFIG_BCMA_HOST_SOC is not set
CONFIG_BCMA_DRIVER_PCI=y
CONFIG_BCMA_DRIVER_GMAC_CMN=y
CONFIG_BCMA_DRIVER_GPIO=y
# CONFIG_BCMA_DEBUG is not set

#
# Multifunction device drivers
#
CONFIG_MFD_CORE=y
# CONFIG_MFD_AS3711 is not set
# CONFIG_PMIC_ADP5520 is not set
# CONFIG_MFD_AAT2870_CORE is not set
# CONFIG_MFD_BCM590XX is not set
# CONFIG_MFD_BD9571MWV is not set
# CONFIG_MFD_AXP20X_I2C is not set
# CONFIG_MFD_MADERA is not set
# CONFIG_PMIC_DA903X is not set
# CONFIG_MFD_DA9052_SPI is not set
# CONFIG_MFD_DA9052_I2C is not set
# CONFIG_MFD_DA9055 is not set
# CONFIG_MFD_DA9062 is not set
# CONFIG_MFD_DA9063 is not set
# CONFIG_MFD_DA9150 is not set
# CONFIG_MFD_DLN2 is not set
# CONFIG_MFD_MC13XXX_SPI is not set
# CONFIG_MFD_MC13XXX_I2C is not set
# CONFIG_MFD_MP2629 is not set
# CONFIG_HTC_PASIC3 is not set
# CONFIG_HTC_I2CPLD is not set
# CONFIG_MFD_INTEL_QUARK_I2C_GPIO is not set
CONFIG_LPC_ICH=y
CONFIG_LPC_SCH=m
CONFIG_MFD_INTEL_LPSS=y
CONFIG_MFD_INTEL_LPSS_ACPI=y
CONFIG_MFD_INTEL_LPSS_PCI=y
# CONFIG_MFD_INTEL_PMC_BXT is not set
# CONFIG_MFD_IQS62X is not set
# CONFIG_MFD_JANZ_CMODIO is not set
# CONFIG_MFD_KEMPLD is not set
# CONFIG_MFD_88PM800 is not set
# CONFIG_MFD_88PM805 is not set
# CONFIG_MFD_88PM860X is not set
# CONFIG_MFD_MAX14577 is not set
# CONFIG_MFD_MAX77693 is not set
# CONFIG_MFD_MAX77843 is not set
# CONFIG_MFD_MAX8907 is not set
# CONFIG_MFD_MAX8925 is not set
# CONFIG_MFD_MAX8997 is not set
# CONFIG_MFD_MAX8998 is not set
# CONFIG_MFD_MT6360 is not set
# CONFIG_MFD_MT6370 is not set
# CONFIG_MFD_MT6397 is not set
# CONFIG_MFD_MENF21BMC is not set
# CONFIG_EZX_PCAP is not set
# CONFIG_MFD_VIPERBOARD is not set
# CONFIG_MFD_RETU is not set
# CONFIG_MFD_PCF50633 is not set
# CONFIG_MFD_SY7636A is not set
# CONFIG_MFD_RDC321X is not set
# CONFIG_MFD_RT4831 is not set
# CONFIG_MFD_RT5033 is not set
# CONFIG_MFD_RT5120 is not set
# CONFIG_MFD_RC5T583 is not set
# CONFIG_MFD_SI476X_CORE is not set
CONFIG_MFD_SM501=m
CONFIG_MFD_SM501_GPIO=y
# CONFIG_MFD_SKY81452 is not set
# CONFIG_MFD_SYSCON is not set
# CONFIG_MFD_TI_AM335X_TSCADC is not set
# CONFIG_MFD_LP3943 is not set
# CONFIG_MFD_LP8788 is not set
# CONFIG_MFD_TI_LMU is not set
# CONFIG_MFD_PALMAS is not set
# CONFIG_TPS6105X is not set
# CONFIG_TPS65010 is not set
# CONFIG_TPS6507X is not set
# CONFIG_MFD_TPS65086 is not set
# CONFIG_MFD_TPS65090 is not set
# CONFIG_MFD_TI_LP873X is not set
# CONFIG_MFD_TPS6586X is not set
# CONFIG_MFD_TPS65910 is not set
# CONFIG_MFD_TPS65912_I2C is not set
# CONFIG_MFD_TPS65912_SPI is not set
# CONFIG_TWL4030_CORE is not set
# CONFIG_TWL6040_CORE is not set
# CONFIG_MFD_WL1273_CORE is not set
# CONFIG_MFD_LM3533 is not set
# CONFIG_MFD_TQMX86 is not set
CONFIG_MFD_VX855=m
# CONFIG_MFD_ARIZONA_I2C is not set
# CONFIG_MFD_ARIZONA_SPI is not set
# CONFIG_MFD_WM8400 is not set
# CONFIG_MFD_WM831X_I2C is not set
# CONFIG_MFD_WM831X_SPI is not set
# CONFIG_MFD_WM8350_I2C is not set
# CONFIG_MFD_WM8994 is not set
# CONFIG_MFD_ATC260X_I2C is not set
# CONFIG_MFD_INTEL_M10_BMC is not set
# end of Multifunction device drivers

# CONFIG_REGULATOR is not set
CONFIG_RC_CORE=m
CONFIG_LIRC=y
CONFIG_RC_MAP=m
CONFIG_RC_DECODERS=y
CONFIG_IR_IMON_DECODER=m
CONFIG_IR_JVC_DECODER=m
CONFIG_IR_MCE_KBD_DECODER=m
CONFIG_IR_NEC_DECODER=m
CONFIG_IR_RC5_DECODER=m
CONFIG_IR_RC6_DECODER=m
# CONFIG_IR_RCMM_DECODER is not set
CONFIG_IR_SANYO_DECODER=m
# CONFIG_IR_SHARP_DECODER is not set
CONFIG_IR_SONY_DECODER=m
# CONFIG_IR_XMP_DECODER is not set
CONFIG_RC_DEVICES=y
CONFIG_IR_ENE=m
CONFIG_IR_FINTEK=m
# CONFIG_IR_IGORPLUGUSB is not set
# CONFIG_IR_IGUANA is not set
# CONFIG_IR_IMON is not set
# CONFIG_IR_IMON_RAW is not set
CONFIG_IR_ITE_CIR=m
# CONFIG_IR_MCEUSB is not set
CONFIG_IR_NUVOTON=m
# CONFIG_IR_REDRAT3 is not set
CONFIG_IR_SERIAL=m
CONFIG_IR_SERIAL_TRANSMITTER=y
# CONFIG_IR_STREAMZAP is not set
# CONFIG_IR_TOY is not set
# CONFIG_IR_TTUSBIR is not set
CONFIG_IR_WINBOND_CIR=m
# CONFIG_RC_ATI_REMOTE is not set
# CONFIG_RC_LOOPBACK is not set
# CONFIG_RC_XBOX_DVD is not set

#
# CEC support
#
CONFIG_MEDIA_CEC_SUPPORT=y
# CONFIG_CEC_CH7322 is not set
# CONFIG_CEC_GPIO is not set
# CONFIG_CEC_SECO is not set
# CONFIG_USB_PULSE8_CEC is not set
# CONFIG_USB_RAINSHADOW_CEC is not set
# end of CEC support

CONFIG_MEDIA_SUPPORT=m
# CONFIG_MEDIA_SUPPORT_FILTER is not set
# CONFIG_MEDIA_SUBDRV_AUTOSELECT is not set

#
# Media device types
#
CONFIG_MEDIA_CAMERA_SUPPORT=y
CONFIG_MEDIA_ANALOG_TV_SUPPORT=y
CONFIG_MEDIA_DIGITAL_TV_SUPPORT=y
CONFIG_MEDIA_RADIO_SUPPORT=y
CONFIG_MEDIA_SDR_SUPPORT=y
CONFIG_MEDIA_PLATFORM_SUPPORT=y
CONFIG_MEDIA_TEST_SUPPORT=y
# end of Media device types

#
# Media core support
#
CONFIG_VIDEO_DEV=m
CONFIG_MEDIA_CONTROLLER=y
CONFIG_DVB_CORE=m
# end of Media core support

#
# Video4Linux options
#
CONFIG_VIDEO_V4L2_I2C=y
# CONFIG_VIDEO_ADV_DEBUG is not set
# CONFIG_VIDEO_FIXED_MINOR_RANGES is not set
# end of Video4Linux options

#
# Media controller options
#
# CONFIG_MEDIA_CONTROLLER_DVB is not set
# end of Media controller options

#
# Digital TV options
#
# CONFIG_DVB_MMAP is not set
CONFIG_DVB_NET=y
CONFIG_DVB_MAX_ADAPTERS=16
CONFIG_DVB_DYNAMIC_MINORS=y
# CONFIG_DVB_DEMUX_SECTION_LOSS_LOG is not set
# CONFIG_DVB_ULE_DEBUG is not set
# end of Digital TV options

#
# Media drivers
#

#
# Media drivers
#
# CONFIG_MEDIA_USB_SUPPORT is not set
# CONFIG_MEDIA_PCI_SUPPORT is not set
CONFIG_RADIO_ADAPTERS=m
# CONFIG_RADIO_MAXIRADIO is not set
# CONFIG_RADIO_SAA7706H is not set
# CONFIG_RADIO_SHARK is not set
# CONFIG_RADIO_SHARK2 is not set
# CONFIG_RADIO_SI4713 is not set
# CONFIG_RADIO_TEA5764 is not set
# CONFIG_RADIO_TEF6862 is not set
# CONFIG_RADIO_WL1273 is not set
# CONFIG_USB_DSBR is not set
# CONFIG_USB_KEENE is not set
# CONFIG_USB_MA901 is not set
# CONFIG_USB_MR800 is not set
# CONFIG_USB_RAREMONO is not set
# CONFIG_RADIO_SI470X is not set
CONFIG_MEDIA_PLATFORM_DRIVERS=y
# CONFIG_V4L_PLATFORM_DRIVERS is not set
# CONFIG_SDR_PLATFORM_DRIVERS is not set
# CONFIG_DVB_PLATFORM_DRIVERS is not set
# CONFIG_V4L_MEM2MEM_DRIVERS is not set

#
# Allegro DVT media platform drivers
#

#
# Amlogic media platform drivers
#

#
# Amphion drivers
#

#
# Aspeed media platform drivers
#

#
# Atmel media platform drivers
#

#
# Cadence media platform drivers
#
# CONFIG_VIDEO_CADENCE_CSI2RX is not set
# CONFIG_VIDEO_CADENCE_CSI2TX is not set

#
# Chips&Media media platform drivers
#

#
# Intel media platform drivers
#

#
# Marvell media platform drivers
#

#
# Mediatek media platform drivers
#

#
# NVidia media platform drivers
#

#
# NXP media platform drivers
#

#
# Qualcomm media platform drivers
#

#
# Renesas media platform drivers
#

#
# Rockchip media platform drivers
#

#
# Samsung media platform drivers
#

#
# STMicroelectronics media platform drivers
#

#
# Sunxi media platform drivers
#

#
# Texas Instruments drivers
#

#
# VIA media platform drivers
#

#
# Xilinx media platform drivers
#

#
# MMC/SDIO DVB adapters
#
# CONFIG_SMS_SDIO_DRV is not set
# CONFIG_V4L_TEST_DRIVERS is not set
# CONFIG_DVB_TEST_DRIVERS is not set

#
# FireWire (IEEE 1394) Adapters
#
# CONFIG_DVB_FIREDTV is not set
CONFIG_VIDEOBUF2_CORE=m
CONFIG_VIDEOBUF2_V4L2=m
CONFIG_VIDEOBUF2_MEMOPS=m
CONFIG_VIDEOBUF2_VMALLOC=m
# end of Media drivers

#
# Media ancillary drivers
#
CONFIG_MEDIA_ATTACH=y
CONFIG_VIDEO_IR_I2C=m

#
# Camera sensor devices
#
# CONFIG_VIDEO_AR0521 is not set
# CONFIG_VIDEO_HI556 is not set
# CONFIG_VIDEO_HI846 is not set
# CONFIG_VIDEO_HI847 is not set
# CONFIG_VIDEO_IMX208 is not set
# CONFIG_VIDEO_IMX214 is not set
# CONFIG_VIDEO_IMX219 is not set
# CONFIG_VIDEO_IMX258 is not set
# CONFIG_VIDEO_IMX274 is not set
# CONFIG_VIDEO_IMX290 is not set
# CONFIG_VIDEO_IMX319 is not set
# CONFIG_VIDEO_IMX355 is not set
# CONFIG_VIDEO_MT9M001 is not set
# CONFIG_VIDEO_MT9M032 is not set
# CONFIG_VIDEO_MT9M111 is not set
# CONFIG_VIDEO_MT9P031 is not set
# CONFIG_VIDEO_MT9T001 is not set
# CONFIG_VIDEO_MT9T112 is not set
# CONFIG_VIDEO_MT9V011 is not set
# CONFIG_VIDEO_MT9V032 is not set
# CONFIG_VIDEO_MT9V111 is not set
# CONFIG_VIDEO_NOON010PC30 is not set
# CONFIG_VIDEO_OG01A1B is not set
# CONFIG_VIDEO_OV02A10 is not set
# CONFIG_VIDEO_OV08D10 is not set
# CONFIG_VIDEO_OV13858 is not set
# CONFIG_VIDEO_OV13B10 is not set
# CONFIG_VIDEO_OV2640 is not set
# CONFIG_VIDEO_OV2659 is not set
# CONFIG_VIDEO_OV2680 is not set
# CONFIG_VIDEO_OV2685 is not set
# CONFIG_VIDEO_OV2740 is not set
# CONFIG_VIDEO_OV5647 is not set
# CONFIG_VIDEO_OV5648 is not set
# CONFIG_VIDEO_OV5670 is not set
# CONFIG_VIDEO_OV5675 is not set
# CONFIG_VIDEO_OV5693 is not set
# CONFIG_VIDEO_OV5695 is not set
# CONFIG_VIDEO_OV6650 is not set
# CONFIG_VIDEO_OV7251 is not set
# CONFIG_VIDEO_OV7640 is not set
# CONFIG_VIDEO_OV7670 is not set
# CONFIG_VIDEO_OV772X is not set
# CONFIG_VIDEO_OV7740 is not set
# CONFIG_VIDEO_OV8856 is not set
# CONFIG_VIDEO_OV8865 is not set
# CONFIG_VIDEO_OV9640 is not set
# CONFIG_VIDEO_OV9650 is not set
# CONFIG_VIDEO_OV9734 is not set
# CONFIG_VIDEO_RDACM20 is not set
# CONFIG_VIDEO_RDACM21 is not set
# CONFIG_VIDEO_RJ54N1 is not set
# CONFIG_VIDEO_S5C73M3 is not set
# CONFIG_VIDEO_S5K4ECGX is not set
# CONFIG_VIDEO_S5K5BAF is not set
# CONFIG_VIDEO_S5K6A3 is not set
# CONFIG_VIDEO_S5K6AA is not set
# CONFIG_VIDEO_SR030PC30 is not set
# CONFIG_VIDEO_VS6624 is not set
# CONFIG_VIDEO_CCS is not set
# CONFIG_VIDEO_ET8EK8 is not set
# CONFIG_VIDEO_M5MOLS is not set
# end of Camera sensor devices

#
# Lens drivers
#
# CONFIG_VIDEO_AD5820 is not set
# CONFIG_VIDEO_AK7375 is not set
# CONFIG_VIDEO_DW9714 is not set
# CONFIG_VIDEO_DW9768 is not set
# CONFIG_VIDEO_DW9807_VCM is not set
# end of Lens drivers

#
# Flash devices
#
# CONFIG_VIDEO_ADP1653 is not set
# CONFIG_VIDEO_LM3560 is not set
# CONFIG_VIDEO_LM3646 is not set
# end of Flash devices

#
# Audio decoders, processors and mixers
#
# CONFIG_VIDEO_CS3308 is not set
# CONFIG_VIDEO_CS5345 is not set
# CONFIG_VIDEO_CS53L32A is not set
# CONFIG_VIDEO_MSP3400 is not set
# CONFIG_VIDEO_SONY_BTF_MPX is not set
# CONFIG_VIDEO_TDA7432 is not set
# CONFIG_VIDEO_TDA9840 is not set
# CONFIG_VIDEO_TEA6415C is not set
# CONFIG_VIDEO_TEA6420 is not set
# CONFIG_VIDEO_TLV320AIC23B is not set
# CONFIG_VIDEO_TVAUDIO is not set
# CONFIG_VIDEO_UDA1342 is not set
# CONFIG_VIDEO_VP27SMPX is not set
# CONFIG_VIDEO_WM8739 is not set
# CONFIG_VIDEO_WM8775 is not set
# end of Audio decoders, processors and mixers

#
# RDS decoders
#
# CONFIG_VIDEO_SAA6588 is not set
# end of RDS decoders

#
# Video decoders
#
# CONFIG_VIDEO_ADV7180 is not set
# CONFIG_VIDEO_ADV7183 is not set
# CONFIG_VIDEO_ADV7604 is not set
# CONFIG_VIDEO_ADV7842 is not set
# CONFIG_VIDEO_BT819 is not set
# CONFIG_VIDEO_BT856 is not set
# CONFIG_VIDEO_BT866 is not set
# CONFIG_VIDEO_KS0127 is not set
# CONFIG_VIDEO_ML86V7667 is not set
# CONFIG_VIDEO_SAA7110 is not set
# CONFIG_VIDEO_SAA711X is not set
# CONFIG_VIDEO_TC358743 is not set
# CONFIG_VIDEO_TVP514X is not set
# CONFIG_VIDEO_TVP5150 is not set
# CONFIG_VIDEO_TVP7002 is not set
# CONFIG_VIDEO_TW2804 is not set
# CONFIG_VIDEO_TW9903 is not set
# CONFIG_VIDEO_TW9906 is not set
# CONFIG_VIDEO_TW9910 is not set
# CONFIG_VIDEO_VPX3220 is not set

#
# Video and audio decoders
#
# CONFIG_VIDEO_SAA717X is not set
# CONFIG_VIDEO_CX25840 is not set
# end of Video decoders

#
# Video encoders
#
# CONFIG_VIDEO_AD9389B is not set
# CONFIG_VIDEO_ADV7170 is not set
# CONFIG_VIDEO_ADV7175 is not set
# CONFIG_VIDEO_ADV7343 is not set
# CONFIG_VIDEO_ADV7393 is not set
# CONFIG_VIDEO_ADV7511 is not set
# CONFIG_VIDEO_AK881X is not set
# CONFIG_VIDEO_SAA7127 is not set
# CONFIG_VIDEO_SAA7185 is not set
# CONFIG_VIDEO_THS8200 is not set
# end of Video encoders

#
# Video improvement chips
#
# CONFIG_VIDEO_UPD64031A is not set
# CONFIG_VIDEO_UPD64083 is not set
# end of Video improvement chips

#
# Audio/Video compression chips
#
# CONFIG_VIDEO_SAA6752HS is not set
# end of Audio/Video compression chips

#
# SDR tuner chips
#
# CONFIG_SDR_MAX2175 is not set
# end of SDR tuner chips

#
# Miscellaneous helper chips
#
# CONFIG_VIDEO_I2C is not set
# CONFIG_VIDEO_M52790 is not set
# CONFIG_VIDEO_ST_MIPID02 is not set
# CONFIG_VIDEO_THS7303 is not set
# end of Miscellaneous helper chips

#
# Media SPI Adapters
#
CONFIG_CXD2880_SPI_DRV=m
# CONFIG_VIDEO_GS1662 is not set
# end of Media SPI Adapters

CONFIG_MEDIA_TUNER=m

#
# Customize TV tuners
#
CONFIG_MEDIA_TUNER_E4000=m
CONFIG_MEDIA_TUNER_FC0011=m
CONFIG_MEDIA_TUNER_FC0012=m
CONFIG_MEDIA_TUNER_FC0013=m
CONFIG_MEDIA_TUNER_FC2580=m
CONFIG_MEDIA_TUNER_IT913X=m
CONFIG_MEDIA_TUNER_M88RS6000T=m
CONFIG_MEDIA_TUNER_MAX2165=m
CONFIG_MEDIA_TUNER_MC44S803=m
CONFIG_MEDIA_TUNER_MSI001=m
CONFIG_MEDIA_TUNER_MT2060=m
CONFIG_MEDIA_TUNER_MT2063=m
CONFIG_MEDIA_TUNER_MT20XX=m
CONFIG_MEDIA_TUNER_MT2131=m
CONFIG_MEDIA_TUNER_MT2266=m
CONFIG_MEDIA_TUNER_MXL301RF=m
CONFIG_MEDIA_TUNER_MXL5005S=m
CONFIG_MEDIA_TUNER_MXL5007T=m
CONFIG_MEDIA_TUNER_QM1D1B0004=m
CONFIG_MEDIA_TUNER_QM1D1C0042=m
CONFIG_MEDIA_TUNER_QT1010=m
CONFIG_MEDIA_TUNER_R820T=m
CONFIG_MEDIA_TUNER_SI2157=m
CONFIG_MEDIA_TUNER_SIMPLE=m
CONFIG_MEDIA_TUNER_TDA18212=m
CONFIG_MEDIA_TUNER_TDA18218=m
CONFIG_MEDIA_TUNER_TDA18250=m
CONFIG_MEDIA_TUNER_TDA18271=m
CONFIG_MEDIA_TUNER_TDA827X=m
CONFIG_MEDIA_TUNER_TDA8290=m
CONFIG_MEDIA_TUNER_TDA9887=m
CONFIG_MEDIA_TUNER_TEA5761=m
CONFIG_MEDIA_TUNER_TEA5767=m
CONFIG_MEDIA_TUNER_TUA9001=m
CONFIG_MEDIA_TUNER_XC2028=m
CONFIG_MEDIA_TUNER_XC4000=m
CONFIG_MEDIA_TUNER_XC5000=m
# end of Customize TV tuners

#
# Customise DVB Frontends
#

#
# Multistandard (satellite) frontends
#
CONFIG_DVB_M88DS3103=m
CONFIG_DVB_MXL5XX=m
CONFIG_DVB_STB0899=m
CONFIG_DVB_STB6100=m
CONFIG_DVB_STV090x=m
CONFIG_DVB_STV0910=m
CONFIG_DVB_STV6110x=m
CONFIG_DVB_STV6111=m

#
# Multistandard (cable + terrestrial) frontends
#
CONFIG_DVB_DRXK=m
CONFIG_DVB_MN88472=m
CONFIG_DVB_MN88473=m
CONFIG_DVB_SI2165=m
CONFIG_DVB_TDA18271C2DD=m

#
# DVB-S (satellite) frontends
#
CONFIG_DVB_CX24110=m
CONFIG_DVB_CX24116=m
CONFIG_DVB_CX24117=m
CONFIG_DVB_CX24120=m
CONFIG_DVB_CX24123=m
CONFIG_DVB_DS3000=m
CONFIG_DVB_MB86A16=m
CONFIG_DVB_MT312=m
CONFIG_DVB_S5H1420=m
CONFIG_DVB_SI21XX=m
CONFIG_DVB_STB6000=m
CONFIG_DVB_STV0288=m
CONFIG_DVB_STV0299=m
CONFIG_DVB_STV0900=m
CONFIG_DVB_STV6110=m
CONFIG_DVB_TDA10071=m
CONFIG_DVB_TDA10086=m
CONFIG_DVB_TDA8083=m
CONFIG_DVB_TDA8261=m
CONFIG_DVB_TDA826X=m
CONFIG_DVB_TS2020=m
CONFIG_DVB_TUA6100=m
CONFIG_DVB_TUNER_CX24113=m
CONFIG_DVB_TUNER_ITD1000=m
CONFIG_DVB_VES1X93=m
CONFIG_DVB_ZL10036=m
CONFIG_DVB_ZL10039=m

#
# DVB-T (terrestrial) frontends
#
CONFIG_DVB_AF9013=m
CONFIG_DVB_CX22700=m
CONFIG_DVB_CX22702=m
CONFIG_DVB_CXD2820R=m
CONFIG_DVB_CXD2841ER=m
CONFIG_DVB_DIB3000MB=m
CONFIG_DVB_DIB3000MC=m
CONFIG_DVB_DIB7000M=m
CONFIG_DVB_DIB7000P=m
CONFIG_DVB_DIB9000=m
CONFIG_DVB_DRXD=m
CONFIG_DVB_EC100=m
CONFIG_DVB_L64781=m
CONFIG_DVB_MT352=m
CONFIG_DVB_NXT6000=m
CONFIG_DVB_RTL2830=m
CONFIG_DVB_RTL2832=m
CONFIG_DVB_RTL2832_SDR=m
CONFIG_DVB_S5H1432=m
CONFIG_DVB_SI2168=m
CONFIG_DVB_SP887X=m
CONFIG_DVB_STV0367=m
CONFIG_DVB_TDA10048=m
CONFIG_DVB_TDA1004X=m
CONFIG_DVB_ZD1301_DEMOD=m
CONFIG_DVB_ZL10353=m
CONFIG_DVB_CXD2880=m

#
# DVB-C (cable) frontends
#
CONFIG_DVB_STV0297=m
CONFIG_DVB_TDA10021=m
CONFIG_DVB_TDA10023=m
CONFIG_DVB_VES1820=m

#
# ATSC (North American/Korean Terrestrial/Cable DTV) frontends
#
CONFIG_DVB_AU8522=m
CONFIG_DVB_AU8522_DTV=m
CONFIG_DVB_AU8522_V4L=m
CONFIG_DVB_BCM3510=m
CONFIG_DVB_LG2160=m
CONFIG_DVB_LGDT3305=m
CONFIG_DVB_LGDT3306A=m
CONFIG_DVB_LGDT330X=m
CONFIG_DVB_MXL692=m
CONFIG_DVB_NXT200X=m
CONFIG_DVB_OR51132=m
CONFIG_DVB_OR51211=m
CONFIG_DVB_S5H1409=m
CONFIG_DVB_S5H1411=m

#
# ISDB-T (terrestrial) frontends
#
CONFIG_DVB_DIB8000=m
CONFIG_DVB_MB86A20S=m
CONFIG_DVB_S921=m

#
# ISDB-S (satellite) & ISDB-T (terrestrial) frontends
#
CONFIG_DVB_MN88443X=m
CONFIG_DVB_TC90522=m

#
# Digital terrestrial only tuners/PLL
#
CONFIG_DVB_PLL=m
CONFIG_DVB_TUNER_DIB0070=m
CONFIG_DVB_TUNER_DIB0090=m

#
# SEC control devices for DVB-S
#
CONFIG_DVB_A8293=m
CONFIG_DVB_AF9033=m
CONFIG_DVB_ASCOT2E=m
CONFIG_DVB_ATBM8830=m
CONFIG_DVB_HELENE=m
CONFIG_DVB_HORUS3A=m
CONFIG_DVB_ISL6405=m
CONFIG_DVB_ISL6421=m
CONFIG_DVB_ISL6423=m
CONFIG_DVB_IX2505V=m
CONFIG_DVB_LGS8GL5=m
CONFIG_DVB_LGS8GXX=m
CONFIG_DVB_LNBH25=m
CONFIG_DVB_LNBH29=m
CONFIG_DVB_LNBP21=m
CONFIG_DVB_LNBP22=m
CONFIG_DVB_M88RS2000=m
CONFIG_DVB_TDA665x=m
CONFIG_DVB_DRX39XYJ=m

#
# Common Interface (EN50221) controller drivers
#
CONFIG_DVB_CXD2099=m
CONFIG_DVB_SP2=m
# end of Customise DVB Frontends

#
# Tools to develop new frontends
#
# CONFIG_DVB_DUMMY_FE is not set
# end of Media ancillary drivers

#
# Graphics support
#
CONFIG_APERTURE_HELPERS=y
# CONFIG_AGP is not set
CONFIG_INTEL_GTT=m
CONFIG_VGA_SWITCHEROO=y
CONFIG_DRM=m
CONFIG_DRM_MIPI_DSI=y
# CONFIG_DRM_KUNIT_TEST is not set
CONFIG_DRM_KMS_HELPER=m
CONFIG_DRM_FBDEV_EMULATION=y
CONFIG_DRM_FBDEV_OVERALLOC=100
CONFIG_DRM_LOAD_EDID_FIRMWARE=y
CONFIG_DRM_DISPLAY_HELPER=m
CONFIG_DRM_DISPLAY_DP_HELPER=y
CONFIG_DRM_DISPLAY_HDCP_HELPER=y
CONFIG_DRM_DISPLAY_HDMI_HELPER=y
CONFIG_DRM_DP_AUX_CHARDEV=y
# CONFIG_DRM_DP_CEC is not set
CONFIG_DRM_TTM=m
CONFIG_DRM_BUDDY=m
CONFIG_DRM_VRAM_HELPER=m
CONFIG_DRM_TTM_HELPER=m
CONFIG_DRM_GEM_SHMEM_HELPER=m

#
# I2C encoder or helper chips
#
CONFIG_DRM_I2C_CH7006=m
CONFIG_DRM_I2C_SIL164=m
# CONFIG_DRM_I2C_NXP_TDA998X is not set
# CONFIG_DRM_I2C_NXP_TDA9950 is not set
# end of I2C encoder or helper chips

#
# ARM devices
#
# end of ARM devices

# CONFIG_DRM_RADEON is not set
# CONFIG_DRM_AMDGPU is not set
# CONFIG_DRM_NOUVEAU is not set
CONFIG_DRM_I915=m
CONFIG_DRM_I915_FORCE_PROBE=""
CONFIG_DRM_I915_CAPTURE_ERROR=y
CONFIG_DRM_I915_COMPRESS_ERROR=y
CONFIG_DRM_I915_USERPTR=y
# CONFIG_DRM_I915_GVT_KVMGT is not set
CONFIG_DRM_I915_REQUEST_TIMEOUT=20000
CONFIG_DRM_I915_FENCE_TIMEOUT=10000
CONFIG_DRM_I915_USERFAULT_AUTOSUSPEND=250
CONFIG_DRM_I915_HEARTBEAT_INTERVAL=2500
CONFIG_DRM_I915_PREEMPT_TIMEOUT=640
CONFIG_DRM_I915_MAX_REQUEST_BUSYWAIT=8000
CONFIG_DRM_I915_STOP_TIMEOUT=100
CONFIG_DRM_I915_TIMESLICE_DURATION=1
# CONFIG_DRM_VGEM is not set
# CONFIG_DRM_VKMS is not set
CONFIG_DRM_VMWGFX=m
CONFIG_DRM_VMWGFX_FBCON=y
# CONFIG_DRM_VMWGFX_MKSSTATS is not set
CONFIG_DRM_GMA500=m
# CONFIG_DRM_UDL is not set
CONFIG_DRM_AST=m
CONFIG_DRM_MGAG200=m
CONFIG_DRM_QXL=m
CONFIG_DRM_VIRTIO_GPU=m
CONFIG_DRM_PANEL=y

#
# Display Panels
#
# CONFIG_DRM_PANEL_RASPBERRYPI_TOUCHSCREEN is not set
# CONFIG_DRM_PANEL_WIDECHIPS_WS2401 is not set
# end of Display Panels

CONFIG_DRM_BRIDGE=y
CONFIG_DRM_PANEL_BRIDGE=y

#
# Display Interface Bridges
#
# CONFIG_DRM_ANALOGIX_ANX78XX is not set
# end of Display Interface Bridges

# CONFIG_DRM_ETNAVIV is not set
CONFIG_DRM_BOCHS=m
CONFIG_DRM_CIRRUS_QEMU=m
# CONFIG_DRM_GM12U320 is not set
# CONFIG_DRM_PANEL_MIPI_DBI is not set
# CONFIG_DRM_SIMPLEDRM is not set
# CONFIG_TINYDRM_HX8357D is not set
# CONFIG_TINYDRM_ILI9163 is not set
# CONFIG_TINYDRM_ILI9225 is not set
# CONFIG_TINYDRM_ILI9341 is not set
# CONFIG_TINYDRM_ILI9486 is not set
# CONFIG_TINYDRM_MI0283QT is not set
# CONFIG_TINYDRM_REPAPER is not set
# CONFIG_TINYDRM_ST7586 is not set
# CONFIG_TINYDRM_ST7735R is not set
# CONFIG_DRM_XEN_FRONTEND is not set
# CONFIG_DRM_VBOXVIDEO is not set
# CONFIG_DRM_GUD is not set
# CONFIG_DRM_SSD130X is not set
# CONFIG_DRM_HYPERV is not set
# CONFIG_DRM_LEGACY is not set
CONFIG_DRM_PANEL_ORIENTATION_QUIRKS=y
CONFIG_DRM_NOMODESET=y
CONFIG_DRM_PRIVACY_SCREEN=y

#
# Frame buffer Devices
#
CONFIG_FB_CMDLINE=y
CONFIG_FB_NOTIFY=y
CONFIG_FB=y
# CONFIG_FIRMWARE_EDID is not set
CONFIG_FB_CFB_FILLRECT=y
CONFIG_FB_CFB_COPYAREA=y
CONFIG_FB_CFB_IMAGEBLIT=y
CONFIG_FB_SYS_FILLRECT=m
CONFIG_FB_SYS_COPYAREA=m
CONFIG_FB_SYS_IMAGEBLIT=m
# CONFIG_FB_FOREIGN_ENDIAN is not set
CONFIG_FB_SYS_FOPS=m
CONFIG_FB_DEFERRED_IO=y
# CONFIG_FB_MODE_HELPERS is not set
CONFIG_FB_TILEBLITTING=y

#
# Frame buffer hardware drivers
#
# CONFIG_FB_CIRRUS is not set
# CONFIG_FB_PM2 is not set
# CONFIG_FB_CYBER2000 is not set
# CONFIG_FB_ARC is not set
# CONFIG_FB_ASILIANT is not set
# CONFIG_FB_IMSTT is not set
# CONFIG_FB_VGA16 is not set
# CONFIG_FB_UVESA is not set
CONFIG_FB_VESA=y
CONFIG_FB_EFI=y
# CONFIG_FB_N411 is not set
# CONFIG_FB_HGA is not set
# CONFIG_FB_OPENCORES is not set
# CONFIG_FB_S1D13XXX is not set
# CONFIG_FB_NVIDIA is not set
# CONFIG_FB_RIVA is not set
# CONFIG_FB_I740 is not set
# CONFIG_FB_LE80578 is not set
# CONFIG_FB_MATROX is not set
# CONFIG_FB_RADEON is not set
# CONFIG_FB_ATY128 is not set
# CONFIG_FB_ATY is not set
# CONFIG_FB_S3 is not set
# CONFIG_FB_SAVAGE is not set
# CONFIG_FB_SIS is not set
# CONFIG_FB_VIA is not set
# CONFIG_FB_NEOMAGIC is not set
# CONFIG_FB_KYRO is not set
# CONFIG_FB_3DFX is not set
# CONFIG_FB_VOODOO1 is not set
# CONFIG_FB_VT8623 is not set
# CONFIG_FB_TRIDENT is not set
# CONFIG_FB_ARK is not set
# CONFIG_FB_PM3 is not set
# CONFIG_FB_CARMINE is not set
# CONFIG_FB_SM501 is not set
# CONFIG_FB_SMSCUFX is not set
# CONFIG_FB_UDL is not set
# CONFIG_FB_IBM_GXT4500 is not set
# CONFIG_FB_VIRTUAL is not set
# CONFIG_XEN_FBDEV_FRONTEND is not set
# CONFIG_FB_METRONOME is not set
# CONFIG_FB_MB862XX is not set
CONFIG_FB_HYPERV=m
# CONFIG_FB_SIMPLE is not set
# CONFIG_FB_SSD1307 is not set
# CONFIG_FB_SM712 is not set
# end of Frame buffer Devices

#
# Backlight & LCD device support
#
CONFIG_LCD_CLASS_DEVICE=m
# CONFIG_LCD_L4F00242T03 is not set
# CONFIG_LCD_LMS283GF05 is not set
# CONFIG_LCD_LTV350QV is not set
# CONFIG_LCD_ILI922X is not set
# CONFIG_LCD_ILI9320 is not set
# CONFIG_LCD_TDO24M is not set
# CONFIG_LCD_VGG2432A4 is not set
CONFIG_LCD_PLATFORM=m
# CONFIG_LCD_AMS369FG06 is not set
# CONFIG_LCD_LMS501KF03 is not set
# CONFIG_LCD_HX8357 is not set
# CONFIG_LCD_OTM3225A is not set
CONFIG_BACKLIGHT_CLASS_DEVICE=y
# CONFIG_BACKLIGHT_KTD253 is not set
# CONFIG_BACKLIGHT_PWM is not set
CONFIG_BACKLIGHT_APPLE=m
# CONFIG_BACKLIGHT_QCOM_WLED is not set
# CONFIG_BACKLIGHT_SAHARA is not set
# CONFIG_BACKLIGHT_ADP8860 is not set
# CONFIG_BACKLIGHT_ADP8870 is not set
# CONFIG_BACKLIGHT_LM3630A is not set
# CONFIG_BACKLIGHT_LM3639 is not set
CONFIG_BACKLIGHT_LP855X=m
# CONFIG_BACKLIGHT_GPIO is not set
# CONFIG_BACKLIGHT_LV5207LP is not set
# CONFIG_BACKLIGHT_BD6107 is not set
# CONFIG_BACKLIGHT_ARCXCNN is not set
# end of Backlight & LCD device support

CONFIG_HDMI=y

#
# Console display driver support
#
CONFIG_VGA_CONSOLE=y
CONFIG_DUMMY_CONSOLE=y
CONFIG_DUMMY_CONSOLE_COLUMNS=80
CONFIG_DUMMY_CONSOLE_ROWS=25
CONFIG_FRAMEBUFFER_CONSOLE=y
# CONFIG_FRAMEBUFFER_CONSOLE_LEGACY_ACCELERATION is not set
CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY=y
CONFIG_FRAMEBUFFER_CONSOLE_ROTATION=y
# CONFIG_FRAMEBUFFER_CONSOLE_DEFERRED_TAKEOVER is not set
# end of Console display driver support

CONFIG_LOGO=y
# CONFIG_LOGO_LINUX_MONO is not set
# CONFIG_LOGO_LINUX_VGA16 is not set
CONFIG_LOGO_LINUX_CLUT224=y
# end of Graphics support

# CONFIG_SOUND is not set

#
# HID support
#
CONFIG_HID=y
CONFIG_HID_BATTERY_STRENGTH=y
CONFIG_HIDRAW=y
CONFIG_UHID=m
CONFIG_HID_GENERIC=y

#
# Special HID drivers
#
CONFIG_HID_A4TECH=m
# CONFIG_HID_ACCUTOUCH is not set
CONFIG_HID_ACRUX=m
# CONFIG_HID_ACRUX_FF is not set
CONFIG_HID_APPLE=m
# CONFIG_HID_APPLEIR is not set
CONFIG_HID_ASUS=m
CONFIG_HID_AUREAL=m
CONFIG_HID_BELKIN=m
# CONFIG_HID_BETOP_FF is not set
# CONFIG_HID_BIGBEN_FF is not set
CONFIG_HID_CHERRY=m
CONFIG_HID_CHICONY=m
# CONFIG_HID_CORSAIR is not set
# CONFIG_HID_COUGAR is not set
# CONFIG_HID_MACALLY is not set
CONFIG_HID_CMEDIA=m
# CONFIG_HID_CP2112 is not set
# CONFIG_HID_CREATIVE_SB0540 is not set
CONFIG_HID_CYPRESS=m
CONFIG_HID_DRAGONRISE=m
# CONFIG_DRAGONRISE_FF is not set
# CONFIG_HID_EMS_FF is not set
# CONFIG_HID_ELAN is not set
CONFIG_HID_ELECOM=m
# CONFIG_HID_ELO is not set
CONFIG_HID_EZKEY=m
# CONFIG_HID_FT260 is not set
CONFIG_HID_GEMBIRD=m
CONFIG_HID_GFRM=m
# CONFIG_HID_GLORIOUS is not set
# CONFIG_HID_HOLTEK is not set
# CONFIG_HID_VIVALDI is not set
# CONFIG_HID_GT683R is not set
CONFIG_HID_KEYTOUCH=m
CONFIG_HID_KYE=m
# CONFIG_HID_UCLOGIC is not set
CONFIG_HID_WALTOP=m
# CONFIG_HID_VIEWSONIC is not set
# CONFIG_HID_XIAOMI is not set
CONFIG_HID_GYRATION=m
CONFIG_HID_ICADE=m
CONFIG_HID_ITE=m
CONFIG_HID_JABRA=m
CONFIG_HID_TWINHAN=m
CONFIG_HID_KENSINGTON=m
CONFIG_HID_LCPOWER=m
CONFIG_HID_LED=m
CONFIG_HID_LENOVO=m
# CONFIG_HID_LETSKETCH is not set
CONFIG_HID_LOGITECH=m
CONFIG_HID_LOGITECH_DJ=m
CONFIG_HID_LOGITECH_HIDPP=m
# CONFIG_LOGITECH_FF is not set
# CONFIG_LOGIRUMBLEPAD2_FF is not set
# CONFIG_LOGIG940_FF is not set
# CONFIG_LOGIWHEELS_FF is not set
CONFIG_HID_MAGICMOUSE=y
# CONFIG_HID_MALTRON is not set
# CONFIG_HID_MAYFLASH is not set
# CONFIG_HID_MEGAWORLD_FF is not set
# CONFIG_HID_REDRAGON is not set
CONFIG_HID_MICROSOFT=m
CONFIG_HID_MONTEREY=m
CONFIG_HID_MULTITOUCH=m
# CONFIG_HID_NINTENDO is not set
CONFIG_HID_NTI=m
# CONFIG_HID_NTRIG is not set
CONFIG_HID_ORTEK=m
CONFIG_HID_PANTHERLORD=m
# CONFIG_PANTHERLORD_FF is not set
# CONFIG_HID_PENMOUNT is not set
CONFIG_HID_PETALYNX=m
CONFIG_HID_PICOLCD=m
CONFIG_HID_PICOLCD_FB=y
CONFIG_HID_PICOLCD_BACKLIGHT=y
CONFIG_HID_PICOLCD_LCD=y
CONFIG_HID_PICOLCD_LEDS=y
CONFIG_HID_PICOLCD_CIR=y
CONFIG_HID_PLANTRONICS=m
# CONFIG_HID_RAZER is not set
CONFIG_HID_PRIMAX=m
# CONFIG_HID_RETRODE is not set
# CONFIG_HID_ROCCAT is not set
CONFIG_HID_SAITEK=m
CONFIG_HID_SAMSUNG=m
# CONFIG_HID_SEMITEK is not set
# CONFIG_HID_SIGMAMICRO is not set
# CONFIG_HID_SONY is not set
CONFIG_HID_SPEEDLINK=m
# CONFIG_HID_STEAM is not set
CONFIG_HID_STEELSERIES=m
CONFIG_HID_SUNPLUS=m
CONFIG_HID_RMI=m
CONFIG_HID_GREENASIA=m
# CONFIG_GREENASIA_FF is not set
CONFIG_HID_HYPERV_MOUSE=m
CONFIG_HID_SMARTJOYPLUS=m
# CONFIG_SMARTJOYPLUS_FF is not set
CONFIG_HID_TIVO=m
CONFIG_HID_TOPSEED=m
CONFIG_HID_THINGM=m
CONFIG_HID_THRUSTMASTER=m
# CONFIG_THRUSTMASTER_FF is not set
# CONFIG_HID_UDRAW_PS3 is not set
# CONFIG_HID_U2FZERO is not set
# CONFIG_HID_WACOM is not set
CONFIG_HID_WIIMOTE=m
CONFIG_HID_XINMO=m
CONFIG_HID_ZEROPLUS=m
# CONFIG_ZEROPLUS_FF is not set
CONFIG_HID_ZYDACRON=m
CONFIG_HID_SENSOR_HUB=y
CONFIG_HID_SENSOR_CUSTOM_SENSOR=m
CONFIG_HID_ALPS=m
# CONFIG_HID_MCP2221 is not set
# end of Special HID drivers

#
# USB HID support
#
CONFIG_USB_HID=y
# CONFIG_HID_PID is not set
# CONFIG_USB_HIDDEV is not set
# end of USB HID support

#
# I2C HID support
#
# CONFIG_I2C_HID_ACPI is not set
# end of I2C HID support

#
# Intel ISH HID support
#
CONFIG_INTEL_ISH_HID=m
# CONFIG_INTEL_ISH_FIRMWARE_DOWNLOADER is not set
# end of Intel ISH HID support

#
# AMD SFH HID Support
#
# CONFIG_AMD_SFH_HID is not set
# end of AMD SFH HID Support
# end of HID support

CONFIG_USB_OHCI_LITTLE_ENDIAN=y
CONFIG_USB_SUPPORT=y
CONFIG_USB_COMMON=y
# CONFIG_USB_LED_TRIG is not set
# CONFIG_USB_ULPI_BUS is not set
# CONFIG_USB_CONN_GPIO is not set
CONFIG_USB_ARCH_HAS_HCD=y
CONFIG_USB=y
CONFIG_USB_PCI=y
CONFIG_USB_ANNOUNCE_NEW_DEVICES=y

#
# Miscellaneous USB options
#
CONFIG_USB_DEFAULT_PERSIST=y
# CONFIG_USB_FEW_INIT_RETRIES is not set
# CONFIG_USB_DYNAMIC_MINORS is not set
# CONFIG_USB_OTG is not set
# CONFIG_USB_OTG_PRODUCTLIST is not set
CONFIG_USB_LEDS_TRIGGER_USBPORT=y
CONFIG_USB_AUTOSUSPEND_DELAY=2
CONFIG_USB_MON=y

#
# USB Host Controller Drivers
#
# CONFIG_USB_C67X00_HCD is not set
CONFIG_USB_XHCI_HCD=y
# CONFIG_USB_XHCI_DBGCAP is not set
CONFIG_USB_XHCI_PCI=y
# CONFIG_USB_XHCI_PCI_RENESAS is not set
# CONFIG_USB_XHCI_PLATFORM is not set
CONFIG_USB_EHCI_HCD=y
CONFIG_USB_EHCI_ROOT_HUB_TT=y
CONFIG_USB_EHCI_TT_NEWSCHED=y
CONFIG_USB_EHCI_PCI=y
# CONFIG_USB_EHCI_FSL is not set
# CONFIG_USB_EHCI_HCD_PLATFORM is not set
# CONFIG_USB_OXU210HP_HCD is not set
# CONFIG_USB_ISP116X_HCD is not set
# CONFIG_USB_FOTG210_HCD is not set
# CONFIG_USB_MAX3421_HCD is not set
CONFIG_USB_OHCI_HCD=y
CONFIG_USB_OHCI_HCD_PCI=y
# CONFIG_USB_OHCI_HCD_PLATFORM is not set
CONFIG_USB_UHCI_HCD=y
# CONFIG_USB_SL811_HCD is not set
# CONFIG_USB_R8A66597_HCD is not set
# CONFIG_USB_HCD_BCMA is not set
# CONFIG_USB_HCD_TEST_MODE is not set
# CONFIG_USB_XEN_HCD is not set

#
# USB Device Class drivers
#
# CONFIG_USB_ACM is not set
# CONFIG_USB_PRINTER is not set
# CONFIG_USB_WDM is not set
# CONFIG_USB_TMC is not set

#
# NOTE: USB_STORAGE depends on SCSI but BLK_DEV_SD may
#

#
# also be needed; see USB_STORAGE Help for more info
#
CONFIG_USB_STORAGE=m
# CONFIG_USB_STORAGE_DEBUG is not set
# CONFIG_USB_STORAGE_REALTEK is not set
# CONFIG_USB_STORAGE_DATAFAB is not set
# CONFIG_USB_STORAGE_FREECOM is not set
# CONFIG_USB_STORAGE_ISD200 is not set
# CONFIG_USB_STORAGE_USBAT is not set
# CONFIG_USB_STORAGE_SDDR09 is not set
# CONFIG_USB_STORAGE_SDDR55 is not set
# CONFIG_USB_STORAGE_JUMPSHOT is not set
# CONFIG_USB_STORAGE_ALAUDA is not set
# CONFIG_USB_STORAGE_ONETOUCH is not set
# CONFIG_USB_STORAGE_KARMA is not set
# CONFIG_USB_STORAGE_CYPRESS_ATACB is not set
# CONFIG_USB_STORAGE_ENE_UB6250 is not set
# CONFIG_USB_UAS is not set

#
# USB Imaging devices
#
# CONFIG_USB_MDC800 is not set
# CONFIG_USB_MICROTEK is not set
# CONFIG_USBIP_CORE is not set
# CONFIG_USB_CDNS_SUPPORT is not set
# CONFIG_USB_MUSB_HDRC is not set
# CONFIG_USB_DWC3 is not set
# CONFIG_USB_DWC2 is not set
# CONFIG_USB_CHIPIDEA is not set
# CONFIG_USB_ISP1760 is not set

#
# USB port drivers
#
# CONFIG_USB_USS720 is not set
CONFIG_USB_SERIAL=m
CONFIG_USB_SERIAL_GENERIC=y
# CONFIG_USB_SERIAL_SIMPLE is not set
# CONFIG_USB_SERIAL_AIRCABLE is not set
# CONFIG_USB_SERIAL_ARK3116 is not set
# CONFIG_USB_SERIAL_BELKIN is not set
# CONFIG_USB_SERIAL_CH341 is not set
# CONFIG_USB_SERIAL_WHITEHEAT is not set
# CONFIG_USB_SERIAL_DIGI_ACCELEPORT is not set
# CONFIG_USB_SERIAL_CP210X is not set
# CONFIG_USB_SERIAL_CYPRESS_M8 is not set
# CONFIG_USB_SERIAL_EMPEG is not set
# CONFIG_USB_SERIAL_FTDI_SIO is not set
# CONFIG_USB_SERIAL_VISOR is not set
# CONFIG_USB_SERIAL_IPAQ is not set
# CONFIG_USB_SERIAL_IR is not set
# CONFIG_USB_SERIAL_EDGEPORT is not set
# CONFIG_USB_SERIAL_EDGEPORT_TI is not set
# CONFIG_USB_SERIAL_F81232 is not set
# CONFIG_USB_SERIAL_F8153X is not set
# CONFIG_USB_SERIAL_GARMIN is not set
# CONFIG_USB_SERIAL_IPW is not set
# CONFIG_USB_SERIAL_IUU is not set
# CONFIG_USB_SERIAL_KEYSPAN_PDA is not set
# CONFIG_USB_SERIAL_KEYSPAN is not set
# CONFIG_USB_SERIAL_KLSI is not set
# CONFIG_USB_SERIAL_KOBIL_SCT is not set
# CONFIG_USB_SERIAL_MCT_U232 is not set
# CONFIG_USB_SERIAL_METRO is not set
# CONFIG_USB_SERIAL_MOS7720 is not set
# CONFIG_USB_SERIAL_MOS7840 is not set
# CONFIG_USB_SERIAL_MXUPORT is not set
# CONFIG_USB_SERIAL_NAVMAN is not set
# CONFIG_USB_SERIAL_PL2303 is not set
# CONFIG_USB_SERIAL_OTI6858 is not set
# CONFIG_USB_SERIAL_QCAUX is not set
# CONFIG_USB_SERIAL_QUALCOMM is not set
# CONFIG_USB_SERIAL_SPCP8X5 is not set
# CONFIG_USB_SERIAL_SAFE is not set
# CONFIG_USB_SERIAL_SIERRAWIRELESS is not set
# CONFIG_USB_SERIAL_SYMBOL is not set
# CONFIG_USB_SERIAL_TI is not set
# CONFIG_USB_SERIAL_CYBERJACK is not set
# CONFIG_USB_SERIAL_OPTION is not set
# CONFIG_USB_SERIAL_OMNINET is not set
# CONFIG_USB_SERIAL_OPTICON is not set
# CONFIG_USB_SERIAL_XSENS_MT is not set
# CONFIG_USB_SERIAL_WISHBONE is not set
# CONFIG_USB_SERIAL_SSU100 is not set
# CONFIG_USB_SERIAL_QT2 is not set
# CONFIG_USB_SERIAL_UPD78F0730 is not set
# CONFIG_USB_SERIAL_XR is not set
CONFIG_USB_SERIAL_DEBUG=m

#
# USB Miscellaneous drivers
#
# CONFIG_USB_EMI62 is not set
# CONFIG_USB_EMI26 is not set
# CONFIG_USB_ADUTUX is not set
# CONFIG_USB_SEVSEG is not set
# CONFIG_USB_LEGOTOWER is not set
# CONFIG_USB_LCD is not set
# CONFIG_USB_CYPRESS_CY7C63 is not set
# CONFIG_USB_CYTHERM is not set
# CONFIG_USB_IDMOUSE is not set
# CONFIG_USB_FTDI_ELAN is not set
# CONFIG_USB_APPLEDISPLAY is not set
# CONFIG_APPLE_MFI_FASTCHARGE is not set
# CONFIG_USB_SISUSBVGA is not set
# CONFIG_USB_LD is not set
# CONFIG_USB_TRANCEVIBRATOR is not set
# CONFIG_USB_IOWARRIOR is not set
# CONFIG_USB_TEST is not set
# CONFIG_USB_EHSET_TEST_FIXTURE is not set
# CONFIG_USB_ISIGHTFW is not set
# CONFIG_USB_YUREX is not set
# CONFIG_USB_EZUSB_FX2 is not set
# CONFIG_USB_HUB_USB251XB is not set
# CONFIG_USB_HSIC_USB3503 is not set
# CONFIG_USB_HSIC_USB4604 is not set
# CONFIG_USB_LINK_LAYER_TEST is not set
# CONFIG_USB_CHAOSKEY is not set
# CONFIG_USB_ATM is not set

#
# USB Physical Layer drivers
#
# CONFIG_NOP_USB_XCEIV is not set
# CONFIG_USB_GPIO_VBUS is not set
# CONFIG_USB_ISP1301 is not set
# end of USB Physical Layer drivers

# CONFIG_USB_GADGET is not set
CONFIG_TYPEC=y
# CONFIG_TYPEC_TCPM is not set
CONFIG_TYPEC_UCSI=y
# CONFIG_UCSI_CCG is not set
CONFIG_UCSI_ACPI=y
# CONFIG_UCSI_STM32G0 is not set
# CONFIG_TYPEC_TPS6598X is not set
# CONFIG_TYPEC_RT1719 is not set
# CONFIG_TYPEC_STUSB160X is not set
# CONFIG_TYPEC_WUSB3801 is not set

#
# USB Type-C Multiplexer/DeMultiplexer Switch support
#
# CONFIG_TYPEC_MUX_FSA4480 is not set
# CONFIG_TYPEC_MUX_PI3USB30532 is not set
# end of USB Type-C Multiplexer/DeMultiplexer Switch support

#
# USB Type-C Alternate Mode drivers
#
# CONFIG_TYPEC_DP_ALTMODE is not set
# end of USB Type-C Alternate Mode drivers

# CONFIG_USB_ROLE_SWITCH is not set
CONFIG_MMC=m
CONFIG_MMC_BLOCK=m
CONFIG_MMC_BLOCK_MINORS=8
CONFIG_SDIO_UART=m
# CONFIG_MMC_TEST is not set

#
# MMC/SD/SDIO Host Controller Drivers
#
# CONFIG_MMC_DEBUG is not set
CONFIG_MMC_SDHCI=m
CONFIG_MMC_SDHCI_IO_ACCESSORS=y
CONFIG_MMC_SDHCI_PCI=m
CONFIG_MMC_RICOH_MMC=y
CONFIG_MMC_SDHCI_ACPI=m
CONFIG_MMC_SDHCI_PLTFM=m
# CONFIG_MMC_SDHCI_F_SDH30 is not set
# CONFIG_MMC_WBSD is not set
# CONFIG_MMC_TIFM_SD is not set
# CONFIG_MMC_SPI is not set
# CONFIG_MMC_CB710 is not set
# CONFIG_MMC_VIA_SDMMC is not set
# CONFIG_MMC_VUB300 is not set
# CONFIG_MMC_USHC is not set
# CONFIG_MMC_USDHI6ROL0 is not set
# CONFIG_MMC_REALTEK_PCI is not set
CONFIG_MMC_CQHCI=m
# CONFIG_MMC_HSQ is not set
# CONFIG_MMC_TOSHIBA_PCI is not set
# CONFIG_MMC_MTK is not set
# CONFIG_MMC_SDHCI_XENON is not set
# CONFIG_SCSI_UFSHCD is not set
# CONFIG_MEMSTICK is not set
CONFIG_NEW_LEDS=y
CONFIG_LEDS_CLASS=y
# CONFIG_LEDS_CLASS_FLASH is not set
# CONFIG_LEDS_CLASS_MULTICOLOR is not set
# CONFIG_LEDS_BRIGHTNESS_HW_CHANGED is not set

#
# LED drivers
#
# CONFIG_LEDS_APU is not set
CONFIG_LEDS_LM3530=m
# CONFIG_LEDS_LM3532 is not set
# CONFIG_LEDS_LM3642 is not set
# CONFIG_LEDS_PCA9532 is not set
# CONFIG_LEDS_GPIO is not set
CONFIG_LEDS_LP3944=m
# CONFIG_LEDS_LP3952 is not set
# CONFIG_LEDS_LP50XX is not set
# CONFIG_LEDS_PCA955X is not set
# CONFIG_LEDS_PCA963X is not set
# CONFIG_LEDS_DAC124S085 is not set
# CONFIG_LEDS_PWM is not set
# CONFIG_LEDS_BD2802 is not set
CONFIG_LEDS_INTEL_SS4200=m
# CONFIG_LEDS_LT3593 is not set
# CONFIG_LEDS_TCA6507 is not set
# CONFIG_LEDS_TLC591XX is not set
# CONFIG_LEDS_LM355x is not set
# CONFIG_LEDS_IS31FL319X is not set

#
# LED driver for blink(1) USB RGB LED is under Special HID drivers (HID_THINGM)
#
CONFIG_LEDS_BLINKM=m
CONFIG_LEDS_MLXCPLD=m
# CONFIG_LEDS_MLXREG is not set
# CONFIG_LEDS_USER is not set
# CONFIG_LEDS_NIC78BX is not set
# CONFIG_LEDS_TI_LMU_COMMON is not set

#
# Flash and Torch LED drivers
#

#
# RGB LED drivers
#

#
# LED Triggers
#
CONFIG_LEDS_TRIGGERS=y
CONFIG_LEDS_TRIGGER_TIMER=m
CONFIG_LEDS_TRIGGER_ONESHOT=m
# CONFIG_LEDS_TRIGGER_DISK is not set
CONFIG_LEDS_TRIGGER_HEARTBEAT=m
CONFIG_LEDS_TRIGGER_BACKLIGHT=m
# CONFIG_LEDS_TRIGGER_CPU is not set
# CONFIG_LEDS_TRIGGER_ACTIVITY is not set
CONFIG_LEDS_TRIGGER_GPIO=m
CONFIG_LEDS_TRIGGER_DEFAULT_ON=m

#
# iptables trigger is under Netfilter config (LED target)
#
CONFIG_LEDS_TRIGGER_TRANSIENT=m
CONFIG_LEDS_TRIGGER_CAMERA=m
# CONFIG_LEDS_TRIGGER_PANIC is not set
# CONFIG_LEDS_TRIGGER_NETDEV is not set
# CONFIG_LEDS_TRIGGER_PATTERN is not set
CONFIG_LEDS_TRIGGER_AUDIO=m
# CONFIG_LEDS_TRIGGER_TTY is not set

#
# Simple LED drivers
#
# CONFIG_ACCESSIBILITY is not set
CONFIG_INFINIBAND=m
CONFIG_INFINIBAND_USER_MAD=m
CONFIG_INFINIBAND_USER_ACCESS=m
CONFIG_INFINIBAND_USER_MEM=y
CONFIG_INFINIBAND_ON_DEMAND_PAGING=y
CONFIG_INFINIBAND_ADDR_TRANS=y
CONFIG_INFINIBAND_ADDR_TRANS_CONFIGFS=y
CONFIG_INFINIBAND_VIRT_DMA=y
# CONFIG_INFINIBAND_EFA is not set
# CONFIG_INFINIBAND_ERDMA is not set
# CONFIG_MLX4_INFINIBAND is not set
# CONFIG_INFINIBAND_MTHCA is not set
# CONFIG_INFINIBAND_OCRDMA is not set
# CONFIG_INFINIBAND_USNIC is not set
# CONFIG_INFINIBAND_RDMAVT is not set
CONFIG_RDMA_RXE=m
CONFIG_RDMA_SIW=m
CONFIG_INFINIBAND_IPOIB=m
# CONFIG_INFINIBAND_IPOIB_CM is not set
CONFIG_INFINIBAND_IPOIB_DEBUG=y
# CONFIG_INFINIBAND_IPOIB_DEBUG_DATA is not set
CONFIG_INFINIBAND_SRP=m
CONFIG_INFINIBAND_SRPT=m
# CONFIG_INFINIBAND_ISER is not set
# CONFIG_INFINIBAND_ISERT is not set
# CONFIG_INFINIBAND_RTRS_CLIENT is not set
# CONFIG_INFINIBAND_RTRS_SERVER is not set
# CONFIG_INFINIBAND_OPA_VNIC is not set
CONFIG_EDAC_ATOMIC_SCRUB=y
CONFIG_EDAC_SUPPORT=y
CONFIG_EDAC=y
CONFIG_EDAC_LEGACY_SYSFS=y
# CONFIG_EDAC_DEBUG is not set
CONFIG_EDAC_DECODE_MCE=m
CONFIG_EDAC_GHES=y
CONFIG_EDAC_AMD64=m
CONFIG_EDAC_E752X=m
CONFIG_EDAC_I82975X=m
CONFIG_EDAC_I3000=m
CONFIG_EDAC_I3200=m
CONFIG_EDAC_IE31200=m
CONFIG_EDAC_X38=m
CONFIG_EDAC_I5400=m
CONFIG_EDAC_I7CORE=m
CONFIG_EDAC_I5000=m
CONFIG_EDAC_I5100=m
CONFIG_EDAC_I7300=m
CONFIG_EDAC_SBRIDGE=m
CONFIG_EDAC_SKX=m
# CONFIG_EDAC_I10NM is not set
CONFIG_EDAC_PND2=m
# CONFIG_EDAC_IGEN6 is not set
CONFIG_RTC_LIB=y
CONFIG_RTC_MC146818_LIB=y
CONFIG_RTC_CLASS=y
CONFIG_RTC_HCTOSYS=y
CONFIG_RTC_HCTOSYS_DEVICE="rtc0"
# CONFIG_RTC_SYSTOHC is not set
# CONFIG_RTC_DEBUG is not set
# CONFIG_RTC_LIB_KUNIT_TEST is not set
CONFIG_RTC_NVMEM=y

#
# RTC interfaces
#
CONFIG_RTC_INTF_SYSFS=y
CONFIG_RTC_INTF_PROC=y
CONFIG_RTC_INTF_DEV=y
# CONFIG_RTC_INTF_DEV_UIE_EMUL is not set
# CONFIG_RTC_DRV_TEST is not set

#
# I2C RTC drivers
#
# CONFIG_RTC_DRV_ABB5ZES3 is not set
# CONFIG_RTC_DRV_ABEOZ9 is not set
# CONFIG_RTC_DRV_ABX80X is not set
CONFIG_RTC_DRV_DS1307=m
# CONFIG_RTC_DRV_DS1307_CENTURY is not set
CONFIG_RTC_DRV_DS1374=m
# CONFIG_RTC_DRV_DS1374_WDT is not set
CONFIG_RTC_DRV_DS1672=m
CONFIG_RTC_DRV_MAX6900=m
CONFIG_RTC_DRV_RS5C372=m
CONFIG_RTC_DRV_ISL1208=m
CONFIG_RTC_DRV_ISL12022=m
CONFIG_RTC_DRV_X1205=m
CONFIG_RTC_DRV_PCF8523=m
# CONFIG_RTC_DRV_PCF85063 is not set
# CONFIG_RTC_DRV_PCF85363 is not set
CONFIG_RTC_DRV_PCF8563=m
CONFIG_RTC_DRV_PCF8583=m
CONFIG_RTC_DRV_M41T80=m
CONFIG_RTC_DRV_M41T80_WDT=y
CONFIG_RTC_DRV_BQ32K=m
# CONFIG_RTC_DRV_S35390A is not set
CONFIG_RTC_DRV_FM3130=m
# CONFIG_RTC_DRV_RX8010 is not set
CONFIG_RTC_DRV_RX8581=m
CONFIG_RTC_DRV_RX8025=m
CONFIG_RTC_DRV_EM3027=m
# CONFIG_RTC_DRV_RV3028 is not set
# CONFIG_RTC_DRV_RV3032 is not set
# CONFIG_RTC_DRV_RV8803 is not set
# CONFIG_RTC_DRV_SD3078 is not set

#
# SPI RTC drivers
#
# CONFIG_RTC_DRV_M41T93 is not set
# CONFIG_RTC_DRV_M41T94 is not set
# CONFIG_RTC_DRV_DS1302 is not set
# CONFIG_RTC_DRV_DS1305 is not set
# CONFIG_RTC_DRV_DS1343 is not set
# CONFIG_RTC_DRV_DS1347 is not set
# CONFIG_RTC_DRV_DS1390 is not set
# CONFIG_RTC_DRV_MAX6916 is not set
# CONFIG_RTC_DRV_R9701 is not set
CONFIG_RTC_DRV_RX4581=m
# CONFIG_RTC_DRV_RS5C348 is not set
# CONFIG_RTC_DRV_MAX6902 is not set
# CONFIG_RTC_DRV_PCF2123 is not set
# CONFIG_RTC_DRV_MCP795 is not set
CONFIG_RTC_I2C_AND_SPI=y

#
# SPI and I2C RTC drivers
#
CONFIG_RTC_DRV_DS3232=m
CONFIG_RTC_DRV_DS3232_HWMON=y
# CONFIG_RTC_DRV_PCF2127 is not set
CONFIG_RTC_DRV_RV3029C2=m
# CONFIG_RTC_DRV_RV3029_HWMON is not set
# CONFIG_RTC_DRV_RX6110 is not set

#
# Platform RTC drivers
#
CONFIG_RTC_DRV_CMOS=y
CONFIG_RTC_DRV_DS1286=m
CONFIG_RTC_DRV_DS1511=m
CONFIG_RTC_DRV_DS1553=m
# CONFIG_RTC_DRV_DS1685_FAMILY is not set
CONFIG_RTC_DRV_DS1742=m
CONFIG_RTC_DRV_DS2404=m
CONFIG_RTC_DRV_STK17TA8=m
# CONFIG_RTC_DRV_M48T86 is not set
CONFIG_RTC_DRV_M48T35=m
CONFIG_RTC_DRV_M48T59=m
CONFIG_RTC_DRV_MSM6242=m
CONFIG_RTC_DRV_BQ4802=m
CONFIG_RTC_DRV_RP5C01=m
CONFIG_RTC_DRV_V3020=m

#
# on-CPU RTC drivers
#
# CONFIG_RTC_DRV_FTRTC010 is not set

#
# HID Sensor RTC drivers
#
# CONFIG_RTC_DRV_GOLDFISH is not set
CONFIG_DMADEVICES=y
# CONFIG_DMADEVICES_DEBUG is not set

#
# DMA Devices
#
CONFIG_DMA_ENGINE=y
CONFIG_DMA_VIRTUAL_CHANNELS=y
CONFIG_DMA_ACPI=y
# CONFIG_ALTERA_MSGDMA is not set
CONFIG_INTEL_IDMA64=m
# CONFIG_INTEL_IDXD is not set
# CONFIG_INTEL_IDXD_COMPAT is not set
CONFIG_INTEL_IOATDMA=m
# CONFIG_PLX_DMA is not set
# CONFIG_AMD_PTDMA is not set
# CONFIG_QCOM_HIDMA_MGMT is not set
# CONFIG_QCOM_HIDMA is not set
CONFIG_DW_DMAC_CORE=y
CONFIG_DW_DMAC=m
CONFIG_DW_DMAC_PCI=y
# CONFIG_DW_EDMA is not set
# CONFIG_DW_EDMA_PCIE is not set
CONFIG_HSU_DMA=y
# CONFIG_SF_PDMA is not set
# CONFIG_INTEL_LDMA is not set

#
# DMA Clients
#
CONFIG_ASYNC_TX_DMA=y
CONFIG_DMATEST=m
CONFIG_DMA_ENGINE_RAID=y

#
# DMABUF options
#
CONFIG_SYNC_FILE=y
# CONFIG_SW_SYNC is not set
# CONFIG_UDMABUF is not set
# CONFIG_DMABUF_MOVE_NOTIFY is not set
# CONFIG_DMABUF_DEBUG is not set
# CONFIG_DMABUF_SELFTESTS is not set
# CONFIG_DMABUF_HEAPS is not set
# CONFIG_DMABUF_SYSFS_STATS is not set
# end of DMABUF options

CONFIG_DCA=m
# CONFIG_AUXDISPLAY is not set
# CONFIG_PANEL is not set
CONFIG_UIO=m
CONFIG_UIO_CIF=m
CONFIG_UIO_PDRV_GENIRQ=m
# CONFIG_UIO_DMEM_GENIRQ is not set
CONFIG_UIO_AEC=m
CONFIG_UIO_SERCOS3=m
CONFIG_UIO_PCI_GENERIC=m
# CONFIG_UIO_NETX is not set
# CONFIG_UIO_PRUSS is not set
# CONFIG_UIO_MF624 is not set
CONFIG_UIO_HV_GENERIC=m
CONFIG_VFIO=m
CONFIG_VFIO_IOMMU_TYPE1=m
CONFIG_VFIO_VIRQFD=m
CONFIG_VFIO_NOIOMMU=y
CONFIG_VFIO_PCI_CORE=m
CONFIG_VFIO_PCI_MMAP=y
CONFIG_VFIO_PCI_INTX=y
CONFIG_VFIO_PCI=m
# CONFIG_VFIO_PCI_VGA is not set
# CONFIG_VFIO_PCI_IGD is not set
CONFIG_VFIO_MDEV=m
CONFIG_IRQ_BYPASS_MANAGER=m
# CONFIG_VIRT_DRIVERS is not set
CONFIG_VIRTIO_ANCHOR=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI_LIB=y
CONFIG_VIRTIO_PCI_LIB_LEGACY=y
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_LEGACY=y
# CONFIG_VIRTIO_PMEM is not set
CONFIG_VIRTIO_BALLOON=m
CONFIG_VIRTIO_MEM=m
CONFIG_VIRTIO_INPUT=m
# CONFIG_VIRTIO_MMIO is not set
CONFIG_VIRTIO_DMA_SHARED_BUFFER=m
# CONFIG_VDPA is not set
CONFIG_VHOST_IOTLB=m
CONFIG_VHOST=m
CONFIG_VHOST_MENU=y
CONFIG_VHOST_NET=m
# CONFIG_VHOST_SCSI is not set
CONFIG_VHOST_VSOCK=m
# CONFIG_VHOST_CROSS_ENDIAN_LEGACY is not set

#
# Microsoft Hyper-V guest support
#
CONFIG_HYPERV=m
CONFIG_HYPERV_TIMER=y
CONFIG_HYPERV_UTILS=m
CONFIG_HYPERV_BALLOON=m
# end of Microsoft Hyper-V guest support

#
# Xen driver support
#
# CONFIG_XEN_BALLOON is not set
CONFIG_XEN_DEV_EVTCHN=m
# CONFIG_XEN_BACKEND is not set
CONFIG_XENFS=m
CONFIG_XEN_COMPAT_XENFS=y
CONFIG_XEN_SYS_HYPERVISOR=y
CONFIG_XEN_XENBUS_FRONTEND=y
# CONFIG_XEN_GNTDEV is not set
# CONFIG_XEN_GRANT_DEV_ALLOC is not set
# CONFIG_XEN_GRANT_DMA_ALLOC is not set
# CONFIG_XEN_PVCALLS_FRONTEND is not set
CONFIG_XEN_PRIVCMD=m
CONFIG_XEN_EFI=y
CONFIG_XEN_AUTO_XLATE=y
CONFIG_XEN_ACPI=y
# CONFIG_XEN_UNPOPULATED_ALLOC is not set
# CONFIG_XEN_VIRTIO is not set
# end of Xen driver support

# CONFIG_GREYBUS is not set
# CONFIG_COMEDI is not set
# CONFIG_STAGING is not set
# CONFIG_CHROME_PLATFORMS is not set
CONFIG_MELLANOX_PLATFORM=y
CONFIG_MLXREG_HOTPLUG=m
# CONFIG_MLXREG_IO is not set
# CONFIG_MLXREG_LC is not set
# CONFIG_NVSW_SN2201 is not set
CONFIG_SURFACE_PLATFORMS=y
# CONFIG_SURFACE3_WMI is not set
# CONFIG_SURFACE_3_POWER_OPREGION is not set
# CONFIG_SURFACE_GPE is not set
# CONFIG_SURFACE_HOTPLUG is not set
# CONFIG_SURFACE_PRO3_BUTTON is not set
CONFIG_X86_PLATFORM_DEVICES=y
CONFIG_ACPI_WMI=m
CONFIG_WMI_BMOF=m
# CONFIG_HUAWEI_WMI is not set
# CONFIG_UV_SYSFS is not set
CONFIG_MXM_WMI=m
# CONFIG_PEAQ_WMI is not set
# CONFIG_NVIDIA_WMI_EC_BACKLIGHT is not set
# CONFIG_XIAOMI_WMI is not set
# CONFIG_GIGABYTE_WMI is not set
# CONFIG_YOGABOOK_WMI is not set
CONFIG_ACERHDF=m
# CONFIG_ACER_WIRELESS is not set
CONFIG_ACER_WMI=m
# CONFIG_AMD_PMF is not set
# CONFIG_AMD_PMC is not set
# CONFIG_AMD_HSMP is not set
# CONFIG_ADV_SWBUTTON is not set
CONFIG_APPLE_GMUX=m
CONFIG_ASUS_LAPTOP=m
# CONFIG_ASUS_WIRELESS is not set
CONFIG_ASUS_WMI=m
CONFIG_ASUS_NB_WMI=m
# CONFIG_ASUS_TF103C_DOCK is not set
# CONFIG_MERAKI_MX100 is not set
CONFIG_EEEPC_LAPTOP=m
CONFIG_EEEPC_WMI=m
# CONFIG_X86_PLATFORM_DRIVERS_DELL is not set
CONFIG_AMILO_RFKILL=m
CONFIG_FUJITSU_LAPTOP=m
CONFIG_FUJITSU_TABLET=m
# CONFIG_GPD_POCKET_FAN is not set
CONFIG_HP_ACCEL=m
# CONFIG_WIRELESS_HOTKEY is not set
CONFIG_HP_WMI=m
# CONFIG_IBM_RTL is not set
CONFIG_IDEAPAD_LAPTOP=m
CONFIG_SENSORS_HDAPS=m
CONFIG_THINKPAD_ACPI=m
# CONFIG_THINKPAD_ACPI_DEBUGFACILITIES is not set
# CONFIG_THINKPAD_ACPI_DEBUG is not set
# CONFIG_THINKPAD_ACPI_UNSAFE_LEDS is not set
CONFIG_THINKPAD_ACPI_VIDEO=y
CONFIG_THINKPAD_ACPI_HOTKEY_POLL=y
# CONFIG_THINKPAD_LMI is not set
# CONFIG_INTEL_ATOMISP2_PM is not set
# CONFIG_INTEL_SAR_INT1092 is not set
CONFIG_INTEL_PMC_CORE=m

#
# Intel Speed Select Technology interface support
#
# CONFIG_INTEL_SPEED_SELECT_INTERFACE is not set
# end of Intel Speed Select Technology interface support

CONFIG_INTEL_WMI=y
# CONFIG_INTEL_WMI_SBL_FW_UPDATE is not set
CONFIG_INTEL_WMI_THUNDERBOLT=m

#
# Intel Uncore Frequency Control
#
# CONFIG_INTEL_UNCORE_FREQ_CONTROL is not set
# end of Intel Uncore Frequency Control

CONFIG_INTEL_HID_EVENT=m
CONFIG_INTEL_VBTN=m
# CONFIG_INTEL_INT0002_VGPIO is not set
CONFIG_INTEL_OAKTRAIL=m
# CONFIG_INTEL_ISHTP_ECLITE is not set
# CONFIG_INTEL_PUNIT_IPC is not set
CONFIG_INTEL_RST=m
# CONFIG_INTEL_SMARTCONNECT is not set
CONFIG_INTEL_TURBO_MAX_3=y
# CONFIG_INTEL_VSEC is not set
CONFIG_MSI_LAPTOP=m
CONFIG_MSI_WMI=m
# CONFIG_PCENGINES_APU2 is not set
# CONFIG_BARCO_P50_GPIO is not set
CONFIG_SAMSUNG_LAPTOP=m
CONFIG_SAMSUNG_Q10=m
CONFIG_TOSHIBA_BT_RFKILL=m
# CONFIG_TOSHIBA_HAPS is not set
# CONFIG_TOSHIBA_WMI is not set
CONFIG_ACPI_CMPC=m
CONFIG_COMPAL_LAPTOP=m
# CONFIG_LG_LAPTOP is not set
CONFIG_PANASONIC_LAPTOP=m
CONFIG_SONY_LAPTOP=m
CONFIG_SONYPI_COMPAT=y
# CONFIG_SYSTEM76_ACPI is not set
CONFIG_TOPSTAR_LAPTOP=m
# CONFIG_SERIAL_MULTI_INSTANTIATE is not set
CONFIG_MLX_PLATFORM=m
CONFIG_INTEL_IPS=m
# CONFIG_INTEL_SCU_PCI is not set
# CONFIG_INTEL_SCU_PLATFORM is not set
# CONFIG_SIEMENS_SIMATIC_IPC is not set
# CONFIG_WINMATE_FM07_KEYS is not set
CONFIG_P2SB=y
CONFIG_HAVE_CLK=y
CONFIG_HAVE_CLK_PREPARE=y
CONFIG_COMMON_CLK=y
# CONFIG_LMK04832 is not set
# CONFIG_COMMON_CLK_MAX9485 is not set
# CONFIG_COMMON_CLK_SI5341 is not set
# CONFIG_COMMON_CLK_SI5351 is not set
# CONFIG_COMMON_CLK_SI544 is not set
# CONFIG_COMMON_CLK_CDCE706 is not set
# CONFIG_COMMON_CLK_CS2000_CP is not set
# CONFIG_COMMON_CLK_PWM is not set
# CONFIG_XILINX_VCU is not set
# CONFIG_CLK_KUNIT_TEST is not set
# CONFIG_CLK_GATE_KUNIT_TEST is not set
CONFIG_HWSPINLOCK=y

#
# Clock Source drivers
#
CONFIG_CLKEVT_I8253=y
CONFIG_I8253_LOCK=y
CONFIG_CLKBLD_I8253=y
# end of Clock Source drivers

CONFIG_MAILBOX=y
CONFIG_PCC=y
# CONFIG_ALTERA_MBOX is not set
CONFIG_IOMMU_IOVA=y
CONFIG_IOASID=y
CONFIG_IOMMU_API=y
CONFIG_IOMMU_SUPPORT=y

#
# Generic IOMMU Pagetable Support
#
CONFIG_IOMMU_IO_PGTABLE=y
# end of Generic IOMMU Pagetable Support

# CONFIG_IOMMU_DEBUGFS is not set
# CONFIG_IOMMU_DEFAULT_DMA_STRICT is not set
CONFIG_IOMMU_DEFAULT_DMA_LAZY=y
# CONFIG_IOMMU_DEFAULT_PASSTHROUGH is not set
CONFIG_IOMMU_DMA=y
CONFIG_AMD_IOMMU=y
CONFIG_AMD_IOMMU_V2=m
CONFIG_DMAR_TABLE=y
CONFIG_INTEL_IOMMU=y
# CONFIG_INTEL_IOMMU_SVM is not set
# CONFIG_INTEL_IOMMU_DEFAULT_ON is not set
CONFIG_INTEL_IOMMU_FLOPPY_WA=y
# CONFIG_INTEL_IOMMU_SCALABLE_MODE_DEFAULT_ON is not set
CONFIG_IRQ_REMAP=y
CONFIG_HYPERV_IOMMU=y
# CONFIG_VIRTIO_IOMMU is not set

#
# Remoteproc drivers
#
# CONFIG_REMOTEPROC is not set
# end of Remoteproc drivers

#
# Rpmsg drivers
#
# CONFIG_RPMSG_QCOM_GLINK_RPM is not set
# CONFIG_RPMSG_VIRTIO is not set
# end of Rpmsg drivers

# CONFIG_SOUNDWIRE is not set

#
# SOC (System On Chip) specific Drivers
#

#
# Amlogic SoC drivers
#
# end of Amlogic SoC drivers

#
# Broadcom SoC drivers
#
# end of Broadcom SoC drivers

#
# NXP/Freescale QorIQ SoC drivers
#
# end of NXP/Freescale QorIQ SoC drivers

#
# fujitsu SoC drivers
#
# end of fujitsu SoC drivers

#
# i.MX SoC drivers
#
# end of i.MX SoC drivers

#
# Enable LiteX SoC Builder specific drivers
#
# end of Enable LiteX SoC Builder specific drivers

#
# Qualcomm SoC drivers
#
# end of Qualcomm SoC drivers

# CONFIG_SOC_TI is not set

#
# Xilinx SoC drivers
#
# end of Xilinx SoC drivers
# end of SOC (System On Chip) specific Drivers

# CONFIG_PM_DEVFREQ is not set
# CONFIG_EXTCON is not set
# CONFIG_MEMORY is not set
# CONFIG_IIO is not set
CONFIG_NTB=m
# CONFIG_NTB_MSI is not set
# CONFIG_NTB_AMD is not set
# CONFIG_NTB_IDT is not set
# CONFIG_NTB_INTEL is not set
# CONFIG_NTB_EPF is not set
# CONFIG_NTB_SWITCHTEC is not set
# CONFIG_NTB_PINGPONG is not set
# CONFIG_NTB_TOOL is not set
# CONFIG_NTB_PERF is not set
# CONFIG_NTB_TRANSPORT is not set
CONFIG_PWM=y
CONFIG_PWM_SYSFS=y
# CONFIG_PWM_DEBUG is not set
# CONFIG_PWM_CLK is not set
# CONFIG_PWM_DWC is not set
CONFIG_PWM_LPSS=m
CONFIG_PWM_LPSS_PCI=m
CONFIG_PWM_LPSS_PLATFORM=m
# CONFIG_PWM_PCA9685 is not set

#
# IRQ chip support
#
# end of IRQ chip support

# CONFIG_IPACK_BUS is not set
# CONFIG_RESET_CONTROLLER is not set

#
# PHY Subsystem
#
# CONFIG_GENERIC_PHY is not set
# CONFIG_USB_LGM_PHY is not set
# CONFIG_PHY_CAN_TRANSCEIVER is not set

#
# PHY drivers for Broadcom platforms
#
# CONFIG_BCM_KONA_USB2_PHY is not set
# end of PHY drivers for Broadcom platforms

# CONFIG_PHY_PXA_28NM_HSIC is not set
# CONFIG_PHY_PXA_28NM_USB2 is not set
# CONFIG_PHY_INTEL_LGM_EMMC is not set
# end of PHY Subsystem

CONFIG_POWERCAP=y
CONFIG_INTEL_RAPL_CORE=m
CONFIG_INTEL_RAPL=m
# CONFIG_IDLE_INJECT is not set
# CONFIG_MCB is not set

#
# Performance monitor support
#
# end of Performance monitor support

CONFIG_RAS=y
# CONFIG_RAS_CEC is not set
# CONFIG_USB4 is not set

#
# Android
#
# CONFIG_ANDROID_BINDER_IPC is not set
# end of Android

CONFIG_LIBNVDIMM=m
CONFIG_BLK_DEV_PMEM=m
CONFIG_ND_CLAIM=y
CONFIG_ND_BTT=m
CONFIG_BTT=y
CONFIG_ND_PFN=m
CONFIG_NVDIMM_PFN=y
CONFIG_NVDIMM_DAX=y
CONFIG_NVDIMM_KEYS=y
CONFIG_DAX=y
CONFIG_DEV_DAX=m
CONFIG_DEV_DAX_PMEM=m
CONFIG_DEV_DAX_KMEM=m
CONFIG_NVMEM=y
CONFIG_NVMEM_SYSFS=y
# CONFIG_NVMEM_RMEM is not set

#
# HW tracing support
#
CONFIG_STM=m
# CONFIG_STM_PROTO_BASIC is not set
# CONFIG_STM_PROTO_SYS_T is not set
CONFIG_STM_DUMMY=m
CONFIG_STM_SOURCE_CONSOLE=m
CONFIG_STM_SOURCE_HEARTBEAT=m
CONFIG_STM_SOURCE_FTRACE=m
CONFIG_INTEL_TH=m
CONFIG_INTEL_TH_PCI=m
CONFIG_INTEL_TH_ACPI=m
CONFIG_INTEL_TH_GTH=m
CONFIG_INTEL_TH_STH=m
CONFIG_INTEL_TH_MSU=m
CONFIG_INTEL_TH_PTI=m
# CONFIG_INTEL_TH_DEBUG is not set
# end of HW tracing support

# CONFIG_FPGA is not set
# CONFIG_TEE is not set
# CONFIG_SIOX is not set
# CONFIG_SLIMBUS is not set
# CONFIG_INTERCONNECT is not set
# CONFIG_COUNTER is not set
# CONFIG_MOST is not set
# CONFIG_PECI is not set
# CONFIG_HTE is not set
# end of Device Drivers

#
# File systems
#
CONFIG_DCACHE_WORD_ACCESS=y
# CONFIG_VALIDATE_FS_PARSER is not set
CONFIG_FS_IOMAP=y
CONFIG_EXT2_FS=m
CONFIG_EXT2_FS_XATTR=y
CONFIG_EXT2_FS_POSIX_ACL=y
CONFIG_EXT2_FS_SECURITY=y
# CONFIG_EXT3_FS is not set
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
# CONFIG_EXT4_DEBUG is not set
CONFIG_EXT4_KUNIT_TESTS=m
CONFIG_JBD2=y
# CONFIG_JBD2_DEBUG is not set
CONFIG_FS_MBCACHE=y
# CONFIG_REISERFS_FS is not set
# CONFIG_JFS_FS is not set
CONFIG_XFS_FS=m
CONFIG_XFS_SUPPORT_V4=y
CONFIG_XFS_QUOTA=y
CONFIG_XFS_POSIX_ACL=y
CONFIG_XFS_RT=y
CONFIG_XFS_ONLINE_SCRUB=y
CONFIG_XFS_ONLINE_REPAIR=y
CONFIG_XFS_DEBUG=y
CONFIG_XFS_ASSERT_FATAL=y
CONFIG_GFS2_FS=m
CONFIG_GFS2_FS_LOCKING_DLM=y
CONFIG_OCFS2_FS=m
CONFIG_OCFS2_FS_O2CB=m
CONFIG_OCFS2_FS_USERSPACE_CLUSTER=m
CONFIG_OCFS2_FS_STATS=y
CONFIG_OCFS2_DEBUG_MASKLOG=y
# CONFIG_OCFS2_DEBUG_FS is not set
CONFIG_BTRFS_FS=y
CONFIG_BTRFS_FS_POSIX_ACL=y
# CONFIG_BTRFS_FS_CHECK_INTEGRITY is not set
# CONFIG_BTRFS_FS_RUN_SANITY_TESTS is not set
# CONFIG_BTRFS_DEBUG is not set
# CONFIG_BTRFS_ASSERT is not set
# CONFIG_BTRFS_FS_REF_VERIFY is not set
# CONFIG_NILFS2_FS is not set
CONFIG_F2FS_FS=m
CONFIG_F2FS_STAT_FS=y
CONFIG_F2FS_FS_XATTR=y
CONFIG_F2FS_FS_POSIX_ACL=y
CONFIG_F2FS_FS_SECURITY=y
# CONFIG_F2FS_CHECK_FS is not set
# CONFIG_F2FS_FAULT_INJECTION is not set
# CONFIG_F2FS_FS_COMPRESSION is not set
CONFIG_F2FS_IOSTAT=y
# CONFIG_F2FS_UNFAIR_RWSEM is not set
# CONFIG_ZONEFS_FS is not set
CONFIG_FS_DAX=y
CONFIG_FS_DAX_PMD=y
CONFIG_FS_POSIX_ACL=y
CONFIG_EXPORTFS=y
CONFIG_EXPORTFS_BLOCK_OPS=y
CONFIG_FILE_LOCKING=y
CONFIG_FS_ENCRYPTION=y
CONFIG_FS_ENCRYPTION_ALGS=y
# CONFIG_FS_VERITY is not set
CONFIG_FSNOTIFY=y
CONFIG_DNOTIFY=y
CONFIG_INOTIFY_USER=y
CONFIG_FANOTIFY=y
CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y
CONFIG_QUOTA=y
CONFIG_QUOTA_NETLINK_INTERFACE=y
CONFIG_PRINT_QUOTA_WARNING=y
# CONFIG_QUOTA_DEBUG is not set
CONFIG_QUOTA_TREE=y
# CONFIG_QFMT_V1 is not set
CONFIG_QFMT_V2=y
CONFIG_QUOTACTL=y
CONFIG_AUTOFS4_FS=y
CONFIG_AUTOFS_FS=y
CONFIG_FUSE_FS=m
CONFIG_CUSE=m
# CONFIG_VIRTIO_FS is not set
CONFIG_OVERLAY_FS=m
# CONFIG_OVERLAY_FS_REDIRECT_DIR is not set
# CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW is not set
# CONFIG_OVERLAY_FS_INDEX is not set
# CONFIG_OVERLAY_FS_XINO_AUTO is not set
# CONFIG_OVERLAY_FS_METACOPY is not set

#
# Caches
#
CONFIG_NETFS_SUPPORT=y
CONFIG_NETFS_STATS=y
CONFIG_FSCACHE=m
CONFIG_FSCACHE_STATS=y
# CONFIG_FSCACHE_DEBUG is not set
CONFIG_CACHEFILES=m
# CONFIG_CACHEFILES_DEBUG is not set
# CONFIG_CACHEFILES_ERROR_INJECTION is not set
# CONFIG_CACHEFILES_ONDEMAND is not set
# end of Caches

#
# CD-ROM/DVD Filesystems
#
CONFIG_ISO9660_FS=m
CONFIG_JOLIET=y
CONFIG_ZISOFS=y
CONFIG_UDF_FS=m
# end of CD-ROM/DVD Filesystems

#
# DOS/FAT/EXFAT/NT Filesystems
#
CONFIG_FAT_FS=m
CONFIG_MSDOS_FS=m
CONFIG_VFAT_FS=m
CONFIG_FAT_DEFAULT_CODEPAGE=437
CONFIG_FAT_DEFAULT_IOCHARSET="ascii"
# CONFIG_FAT_DEFAULT_UTF8 is not set
# CONFIG_FAT_KUNIT_TEST is not set
# CONFIG_EXFAT_FS is not set
# CONFIG_NTFS_FS is not set
# CONFIG_NTFS3_FS is not set
# end of DOS/FAT/EXFAT/NT Filesystems

#
# Pseudo filesystems
#
CONFIG_PROC_FS=y
CONFIG_PROC_KCORE=y
CONFIG_PROC_VMCORE=y
CONFIG_PROC_VMCORE_DEVICE_DUMP=y
CONFIG_PROC_SYSCTL=y
CONFIG_PROC_PAGE_MONITOR=y
CONFIG_PROC_CHILDREN=y
CONFIG_PROC_PID_ARCH_STATUS=y
CONFIG_PROC_CPU_RESCTRL=y
CONFIG_KERNFS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_TMPFS_XATTR=y
# CONFIG_TMPFS_INODE64 is not set
CONFIG_HUGETLBFS=y
CONFIG_HUGETLB_PAGE=y
CONFIG_ARCH_WANT_HUGETLB_PAGE_OPTIMIZE_VMEMMAP=y
CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP=y
# CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP_DEFAULT_ON is not set
CONFIG_MEMFD_CREATE=y
CONFIG_ARCH_HAS_GIGANTIC_PAGE=y
CONFIG_CONFIGFS_FS=y
CONFIG_EFIVAR_FS=y
# end of Pseudo filesystems

CONFIG_MISC_FILESYSTEMS=y
# CONFIG_ORANGEFS_FS is not set
# CONFIG_ADFS_FS is not set
# CONFIG_AFFS_FS is not set
# CONFIG_ECRYPT_FS is not set
# CONFIG_HFS_FS is not set
# CONFIG_HFSPLUS_FS is not set
# CONFIG_BEFS_FS is not set
# CONFIG_BFS_FS is not set
# CONFIG_EFS_FS is not set
CONFIG_CRAMFS=m
CONFIG_CRAMFS_BLOCKDEV=y
CONFIG_SQUASHFS=m
# CONFIG_SQUASHFS_FILE_CACHE is not set
CONFIG_SQUASHFS_FILE_DIRECT=y
# CONFIG_SQUASHFS_DECOMP_SINGLE is not set
# CONFIG_SQUASHFS_DECOMP_MULTI is not set
CONFIG_SQUASHFS_DECOMP_MULTI_PERCPU=y
CONFIG_SQUASHFS_XATTR=y
CONFIG_SQUASHFS_ZLIB=y
# CONFIG_SQUASHFS_LZ4 is not set
CONFIG_SQUASHFS_LZO=y
CONFIG_SQUASHFS_XZ=y
# CONFIG_SQUASHFS_ZSTD is not set
# CONFIG_SQUASHFS_4K_DEVBLK_SIZE is not set
# CONFIG_SQUASHFS_EMBEDDED is not set
CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE=3
# CONFIG_VXFS_FS is not set
CONFIG_MINIX_FS=m
# CONFIG_OMFS_FS is not set
# CONFIG_HPFS_FS is not set
# CONFIG_QNX4FS_FS is not set
# CONFIG_QNX6FS_FS is not set
# CONFIG_ROMFS_FS is not set
CONFIG_PSTORE=y
CONFIG_PSTORE_DEFAULT_KMSG_BYTES=10240
CONFIG_PSTORE_DEFLATE_COMPRESS=y
# CONFIG_PSTORE_LZO_COMPRESS is not set
# CONFIG_PSTORE_LZ4_COMPRESS is not set
# CONFIG_PSTORE_LZ4HC_COMPRESS is not set
# CONFIG_PSTORE_842_COMPRESS is not set
# CONFIG_PSTORE_ZSTD_COMPRESS is not set
CONFIG_PSTORE_COMPRESS=y
CONFIG_PSTORE_DEFLATE_COMPRESS_DEFAULT=y
CONFIG_PSTORE_COMPRESS_DEFAULT="deflate"
# CONFIG_PSTORE_CONSOLE is not set
# CONFIG_PSTORE_PMSG is not set
# CONFIG_PSTORE_FTRACE is not set
CONFIG_PSTORE_RAM=m
# CONFIG_PSTORE_BLK is not set
# CONFIG_SYSV_FS is not set
# CONFIG_UFS_FS is not set
# CONFIG_EROFS_FS is not set
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NFS_FS=y
# CONFIG_NFS_V2 is not set
CONFIG_NFS_V3=y
CONFIG_NFS_V3_ACL=y
CONFIG_NFS_V4=m
# CONFIG_NFS_SWAP is not set
CONFIG_NFS_V4_1=y
CONFIG_NFS_V4_2=y
CONFIG_PNFS_FILE_LAYOUT=m
CONFIG_PNFS_BLOCK=m
CONFIG_PNFS_FLEXFILE_LAYOUT=m
CONFIG_NFS_V4_1_IMPLEMENTATION_ID_DOMAIN="kernel.org"
# CONFIG_NFS_V4_1_MIGRATION is not set
CONFIG_NFS_V4_SECURITY_LABEL=y
CONFIG_ROOT_NFS=y
# CONFIG_NFS_USE_LEGACY_DNS is not set
CONFIG_NFS_USE_KERNEL_DNS=y
CONFIG_NFS_DEBUG=y
CONFIG_NFS_DISABLE_UDP_SUPPORT=y
# CONFIG_NFS_V4_2_READ_PLUS is not set
CONFIG_NFSD=m
CONFIG_NFSD_V2_ACL=y
CONFIG_NFSD_V3_ACL=y
CONFIG_NFSD_V4=y
CONFIG_NFSD_PNFS=y
# CONFIG_NFSD_BLOCKLAYOUT is not set
CONFIG_NFSD_SCSILAYOUT=y
# CONFIG_NFSD_FLEXFILELAYOUT is not set
# CONFIG_NFSD_V4_2_INTER_SSC is not set
CONFIG_NFSD_V4_SECURITY_LABEL=y
CONFIG_GRACE_PERIOD=y
CONFIG_LOCKD=y
CONFIG_LOCKD_V4=y
CONFIG_NFS_ACL_SUPPORT=y
CONFIG_NFS_COMMON=y
CONFIG_NFS_V4_2_SSC_HELPER=y
CONFIG_SUNRPC=y
CONFIG_SUNRPC_GSS=m
CONFIG_SUNRPC_BACKCHANNEL=y
CONFIG_RPCSEC_GSS_KRB5=m
# CONFIG_SUNRPC_DISABLE_INSECURE_ENCTYPES is not set
CONFIG_SUNRPC_DEBUG=y
CONFIG_SUNRPC_XPRT_RDMA=m
CONFIG_CEPH_FS=m
# CONFIG_CEPH_FSCACHE is not set
CONFIG_CEPH_FS_POSIX_ACL=y
# CONFIG_CEPH_FS_SECURITY_LABEL is not set
CONFIG_CIFS=m
# CONFIG_CIFS_STATS2 is not set
CONFIG_CIFS_ALLOW_INSECURE_LEGACY=y
CONFIG_CIFS_UPCALL=y
CONFIG_CIFS_XATTR=y
CONFIG_CIFS_POSIX=y
CONFIG_CIFS_DEBUG=y
# CONFIG_CIFS_DEBUG2 is not set
# CONFIG_CIFS_DEBUG_DUMP_KEYS is not set
CONFIG_CIFS_DFS_UPCALL=y
# CONFIG_CIFS_SWN_UPCALL is not set
# CONFIG_CIFS_SMB_DIRECT is not set
# CONFIG_CIFS_FSCACHE is not set
# CONFIG_SMB_SERVER is not set
CONFIG_SMBFS_COMMON=m
# CONFIG_CODA_FS is not set
# CONFIG_AFS_FS is not set
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y
CONFIG_9P_FS_SECURITY=y
CONFIG_NLS=y
CONFIG_NLS_DEFAULT="utf8"
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_CODEPAGE_737=m
CONFIG_NLS_CODEPAGE_775=m
CONFIG_NLS_CODEPAGE_850=m
CONFIG_NLS_CODEPAGE_852=m
CONFIG_NLS_CODEPAGE_855=m
CONFIG_NLS_CODEPAGE_857=m
CONFIG_NLS_CODEPAGE_860=m
CONFIG_NLS_CODEPAGE_861=m
CONFIG_NLS_CODEPAGE_862=m
CONFIG_NLS_CODEPAGE_863=m
CONFIG_NLS_CODEPAGE_864=m
CONFIG_NLS_CODEPAGE_865=m
CONFIG_NLS_CODEPAGE_866=m
CONFIG_NLS_CODEPAGE_869=m
CONFIG_NLS_CODEPAGE_936=m
CONFIG_NLS_CODEPAGE_950=m
CONFIG_NLS_CODEPAGE_932=m
CONFIG_NLS_CODEPAGE_949=m
CONFIG_NLS_CODEPAGE_874=m
CONFIG_NLS_ISO8859_8=m
CONFIG_NLS_CODEPAGE_1250=m
CONFIG_NLS_CODEPAGE_1251=m
CONFIG_NLS_ASCII=y
CONFIG_NLS_ISO8859_1=m
CONFIG_NLS_ISO8859_2=m
CONFIG_NLS_ISO8859_3=m
CONFIG_NLS_ISO8859_4=m
CONFIG_NLS_ISO8859_5=m
CONFIG_NLS_ISO8859_6=m
CONFIG_NLS_ISO8859_7=m
CONFIG_NLS_ISO8859_9=m
CONFIG_NLS_ISO8859_13=m
CONFIG_NLS_ISO8859_14=m
CONFIG_NLS_ISO8859_15=m
CONFIG_NLS_KOI8_R=m
CONFIG_NLS_KOI8_U=m
CONFIG_NLS_MAC_ROMAN=m
CONFIG_NLS_MAC_CELTIC=m
CONFIG_NLS_MAC_CENTEURO=m
CONFIG_NLS_MAC_CROATIAN=m
CONFIG_NLS_MAC_CYRILLIC=m
CONFIG_NLS_MAC_GAELIC=m
CONFIG_NLS_MAC_GREEK=m
CONFIG_NLS_MAC_ICELAND=m
CONFIG_NLS_MAC_INUIT=m
CONFIG_NLS_MAC_ROMANIAN=m
CONFIG_NLS_MAC_TURKISH=m
CONFIG_NLS_UTF8=m
CONFIG_DLM=m
# CONFIG_DLM_DEPRECATED_API is not set
CONFIG_DLM_DEBUG=y
# CONFIG_UNICODE is not set
CONFIG_IO_WQ=y
# end of File systems

#
# Security options
#
CONFIG_KEYS=y
# CONFIG_KEYS_REQUEST_CACHE is not set
CONFIG_PERSISTENT_KEYRINGS=y
CONFIG_TRUSTED_KEYS=y
CONFIG_TRUSTED_KEYS_TPM=y
CONFIG_ENCRYPTED_KEYS=y
# CONFIG_USER_DECRYPTED_DATA is not set
# CONFIG_KEY_DH_OPERATIONS is not set
# CONFIG_SECURITY_DMESG_RESTRICT is not set
CONFIG_SECURITY=y
CONFIG_SECURITY_WRITABLE_HOOKS=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
# CONFIG_SECURITY_INFINIBAND is not set
CONFIG_SECURITY_NETWORK_XFRM=y
CONFIG_SECURITY_PATH=y
CONFIG_INTEL_TXT=y
CONFIG_LSM_MMAP_MIN_ADDR=65535
CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=y
CONFIG_HARDENED_USERCOPY=y
# CONFIG_FORTIFY_SOURCE is not set
# CONFIG_STATIC_USERMODEHELPER is not set
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DISABLE=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=1
CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS=9
CONFIG_SECURITY_SELINUX_SID2STR_CACHE_SIZE=256
# CONFIG_SECURITY_SMACK is not set
# CONFIG_SECURITY_TOMOYO is not set
CONFIG_SECURITY_APPARMOR=y
# CONFIG_SECURITY_APPARMOR_DEBUG is not set
CONFIG_SECURITY_APPARMOR_INTROSPECT_POLICY=y
CONFIG_SECURITY_APPARMOR_HASH=y
CONFIG_SECURITY_APPARMOR_HASH_DEFAULT=y
CONFIG_SECURITY_APPARMOR_EXPORT_BINARY=y
CONFIG_SECURITY_APPARMOR_PARANOID_LOAD=y
# CONFIG_SECURITY_APPARMOR_KUNIT_TEST is not set
# CONFIG_SECURITY_LOADPIN is not set
CONFIG_SECURITY_YAMA=y
# CONFIG_SECURITY_SAFESETID is not set
# CONFIG_SECURITY_LOCKDOWN_LSM is not set
# CONFIG_SECURITY_LANDLOCK is not set
CONFIG_INTEGRITY=y
CONFIG_INTEGRITY_SIGNATURE=y
CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y
CONFIG_INTEGRITY_TRUSTED_KEYRING=y
# CONFIG_INTEGRITY_PLATFORM_KEYRING is not set
CONFIG_INTEGRITY_AUDIT=y
CONFIG_IMA=y
# CONFIG_IMA_KEXEC is not set
CONFIG_IMA_MEASURE_PCR_IDX=10
CONFIG_IMA_LSM_RULES=y
CONFIG_IMA_NG_TEMPLATE=y
# CONFIG_IMA_SIG_TEMPLATE is not set
CONFIG_IMA_DEFAULT_TEMPLATE="ima-ng"
CONFIG_IMA_DEFAULT_HASH_SHA1=y
# CONFIG_IMA_DEFAULT_HASH_SHA256 is not set
# CONFIG_IMA_DEFAULT_HASH_SHA512 is not set
CONFIG_IMA_DEFAULT_HASH="sha1"
# CONFIG_IMA_WRITE_POLICY is not set
# CONFIG_IMA_READ_POLICY is not set
CONFIG_IMA_APPRAISE=y
# CONFIG_IMA_ARCH_POLICY is not set
# CONFIG_IMA_APPRAISE_BUILD_POLICY is not set
CONFIG_IMA_APPRAISE_BOOTPARAM=y
# CONFIG_IMA_APPRAISE_MODSIG is not set
CONFIG_IMA_TRUSTED_KEYRING=y
# CONFIG_IMA_BLACKLIST_KEYRING is not set
# CONFIG_IMA_LOAD_X509 is not set
CONFIG_IMA_MEASURE_ASYMMETRIC_KEYS=y
CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS=y
# CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT is not set
# CONFIG_IMA_DISABLE_HTABLE is not set
CONFIG_EVM=y
CONFIG_EVM_ATTR_FSUUID=y
# CONFIG_EVM_ADD_XATTRS is not set
# CONFIG_EVM_LOAD_X509 is not set
CONFIG_DEFAULT_SECURITY_SELINUX=y
# CONFIG_DEFAULT_SECURITY_APPARMOR is not set
# CONFIG_DEFAULT_SECURITY_DAC is not set
CONFIG_LSM="lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"

#
# Kernel hardening options
#

#
# Memory initialization
#
CONFIG_INIT_STACK_NONE=y
# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set
# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set
# end of Memory initialization

CONFIG_RANDSTRUCT_NONE=y
# end of Kernel hardening options
# end of Security options

CONFIG_XOR_BLOCKS=y
CONFIG_ASYNC_CORE=m
CONFIG_ASYNC_MEMCPY=m
CONFIG_ASYNC_XOR=m
CONFIG_ASYNC_PQ=m
CONFIG_ASYNC_RAID6_RECOV=m
CONFIG_CRYPTO=y

#
# Crypto core or helper
#
CONFIG_CRYPTO_ALGAPI=y
CONFIG_CRYPTO_ALGAPI2=y
CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_AEAD2=y
CONFIG_CRYPTO_SKCIPHER=y
CONFIG_CRYPTO_SKCIPHER2=y
CONFIG_CRYPTO_HASH=y
CONFIG_CRYPTO_HASH2=y
CONFIG_CRYPTO_RNG=y
CONFIG_CRYPTO_RNG2=y
CONFIG_CRYPTO_RNG_DEFAULT=y
CONFIG_CRYPTO_AKCIPHER2=y
CONFIG_CRYPTO_AKCIPHER=y
CONFIG_CRYPTO_KPP2=y
CONFIG_CRYPTO_KPP=m
CONFIG_CRYPTO_ACOMP2=y
CONFIG_CRYPTO_MANAGER=y
CONFIG_CRYPTO_MANAGER2=y
CONFIG_CRYPTO_USER=m
CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=y
CONFIG_CRYPTO_GF128MUL=y
CONFIG_CRYPTO_NULL=y
CONFIG_CRYPTO_NULL2=y
CONFIG_CRYPTO_PCRYPT=m
CONFIG_CRYPTO_CRYPTD=y
CONFIG_CRYPTO_AUTHENC=m
CONFIG_CRYPTO_TEST=m
CONFIG_CRYPTO_SIMD=y
# end of Crypto core or helper

#
# Public-key cryptography
#
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_DH=m
# CONFIG_CRYPTO_DH_RFC7919_GROUPS is not set
CONFIG_CRYPTO_ECC=m
CONFIG_CRYPTO_ECDH=m
# CONFIG_CRYPTO_ECDSA is not set
# CONFIG_CRYPTO_ECRDSA is not set
# CONFIG_CRYPTO_SM2 is not set
# CONFIG_CRYPTO_CURVE25519 is not set
# end of Public-key cryptography

#
# Block ciphers
#
CONFIG_CRYPTO_AES=y
# CONFIG_CRYPTO_AES_TI is not set
CONFIG_CRYPTO_ANUBIS=m
# CONFIG_CRYPTO_ARIA is not set
CONFIG_CRYPTO_BLOWFISH=m
CONFIG_CRYPTO_BLOWFISH_COMMON=m
CONFIG_CRYPTO_CAMELLIA=m
CONFIG_CRYPTO_CAST_COMMON=m
CONFIG_CRYPTO_CAST5=m
CONFIG_CRYPTO_CAST6=m
CONFIG_CRYPTO_DES=m
CONFIG_CRYPTO_FCRYPT=m
CONFIG_CRYPTO_KHAZAD=m
CONFIG_CRYPTO_SEED=m
CONFIG_CRYPTO_SERPENT=m
# CONFIG_CRYPTO_SM4_GENERIC is not set
CONFIG_CRYPTO_TEA=m
CONFIG_CRYPTO_TWOFISH=m
CONFIG_CRYPTO_TWOFISH_COMMON=m
# end of Block ciphers

#
# Length-preserving ciphers and modes
#
# CONFIG_CRYPTO_ADIANTUM is not set
CONFIG_CRYPTO_ARC4=m
CONFIG_CRYPTO_CHACHA20=m
CONFIG_CRYPTO_CBC=y
CONFIG_CRYPTO_CFB=y
CONFIG_CRYPTO_CTR=y
CONFIG_CRYPTO_CTS=y
CONFIG_CRYPTO_ECB=y
# CONFIG_CRYPTO_HCTR2 is not set
# CONFIG_CRYPTO_KEYWRAP is not set
CONFIG_CRYPTO_LRW=m
# CONFIG_CRYPTO_OFB is not set
CONFIG_CRYPTO_PCBC=m
CONFIG_CRYPTO_XTS=y
# end of Length-preserving ciphers and modes

#
# AEAD (authenticated encryption with associated data) ciphers
#
# CONFIG_CRYPTO_AEGIS128 is not set
CONFIG_CRYPTO_CHACHA20POLY1305=m
CONFIG_CRYPTO_CCM=m
CONFIG_CRYPTO_GCM=y
CONFIG_CRYPTO_SEQIV=y
CONFIG_CRYPTO_ECHAINIV=m
CONFIG_CRYPTO_ESSIV=m
# end of AEAD (authenticated encryption with associated data) ciphers

#
# Hashes, digests, and MACs
#
CONFIG_CRYPTO_BLAKE2B=y
# CONFIG_CRYPTO_BLAKE2S is not set
CONFIG_CRYPTO_CMAC=m
CONFIG_CRYPTO_GHASH=y
CONFIG_CRYPTO_HMAC=y
CONFIG_CRYPTO_MD4=m
CONFIG_CRYPTO_MD5=y
CONFIG_CRYPTO_MICHAEL_MIC=m
CONFIG_CRYPTO_POLY1305=m
CONFIG_CRYPTO_RMD160=m
CONFIG_CRYPTO_SHA1=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_SHA3=m
# CONFIG_CRYPTO_SM3_GENERIC is not set
# CONFIG_CRYPTO_STREEBOG is not set
CONFIG_CRYPTO_VMAC=m
CONFIG_CRYPTO_WP512=m
CONFIG_CRYPTO_XCBC=m
CONFIG_CRYPTO_XXHASH=y
# end of Hashes, digests, and MACs

#
# CRCs (cyclic redundancy checks)
#
CONFIG_CRYPTO_CRC32C=y
CONFIG_CRYPTO_CRC32=m
CONFIG_CRYPTO_CRCT10DIF=y
CONFIG_CRYPTO_CRC64_ROCKSOFT=y
# end of CRCs (cyclic redundancy checks)

#
# Compression
#
CONFIG_CRYPTO_DEFLATE=y
CONFIG_CRYPTO_LZO=y
# CONFIG_CRYPTO_842 is not set
# CONFIG_CRYPTO_LZ4 is not set
# CONFIG_CRYPTO_LZ4HC is not set
# CONFIG_CRYPTO_ZSTD is not set
# end of Compression

#
# Random number generation
#
CONFIG_CRYPTO_ANSI_CPRNG=m
CONFIG_CRYPTO_DRBG_MENU=y
CONFIG_CRYPTO_DRBG_HMAC=y
CONFIG_CRYPTO_DRBG_HASH=y
CONFIG_CRYPTO_DRBG_CTR=y
CONFIG_CRYPTO_DRBG=y
CONFIG_CRYPTO_JITTERENTROPY=y
# end of Random number generation

#
# Userspace interface
#
CONFIG_CRYPTO_USER_API=y
CONFIG_CRYPTO_USER_API_HASH=y
CONFIG_CRYPTO_USER_API_SKCIPHER=y
CONFIG_CRYPTO_USER_API_RNG=y
# CONFIG_CRYPTO_USER_API_RNG_CAVP is not set
CONFIG_CRYPTO_USER_API_AEAD=y
CONFIG_CRYPTO_USER_API_ENABLE_OBSOLETE=y
# CONFIG_CRYPTO_STATS is not set
# end of Userspace interface

CONFIG_CRYPTO_HASH_INFO=y

#
# Accelerated Cryptographic Algorithms for CPU (x86)
#
# CONFIG_CRYPTO_CURVE25519_X86 is not set
CONFIG_CRYPTO_AES_NI_INTEL=y
CONFIG_CRYPTO_BLOWFISH_X86_64=m
CONFIG_CRYPTO_CAMELLIA_X86_64=m
CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64=m
CONFIG_CRYPTO_CAMELLIA_AESNI_AVX2_X86_64=m
CONFIG_CRYPTO_CAST5_AVX_X86_64=m
CONFIG_CRYPTO_CAST6_AVX_X86_64=m
CONFIG_CRYPTO_DES3_EDE_X86_64=m
CONFIG_CRYPTO_SERPENT_SSE2_X86_64=m
CONFIG_CRYPTO_SERPENT_AVX_X86_64=m
CONFIG_CRYPTO_SERPENT_AVX2_X86_64=m
# CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64 is not set
# CONFIG_CRYPTO_SM4_AESNI_AVX2_X86_64 is not set
CONFIG_CRYPTO_TWOFISH_X86_64=m
CONFIG_CRYPTO_TWOFISH_X86_64_3WAY=m
CONFIG_CRYPTO_TWOFISH_AVX_X86_64=m
CONFIG_CRYPTO_CHACHA20_X86_64=m
# CONFIG_CRYPTO_AEGIS128_AESNI_SSE2 is not set
# CONFIG_CRYPTO_NHPOLY1305_SSE2 is not set
# CONFIG_CRYPTO_NHPOLY1305_AVX2 is not set
# CONFIG_CRYPTO_BLAKE2S_X86 is not set
# CONFIG_CRYPTO_POLYVAL_CLMUL_NI is not set
CONFIG_CRYPTO_POLY1305_X86_64=m
CONFIG_CRYPTO_SHA1_SSSE3=y
CONFIG_CRYPTO_SHA256_SSSE3=y
CONFIG_CRYPTO_SHA512_SSSE3=m
# CONFIG_CRYPTO_SM3_AVX_X86_64 is not set
CONFIG_CRYPTO_GHASH_CLMUL_NI_INTEL=m
CONFIG_CRYPTO_CRC32C_INTEL=m
CONFIG_CRYPTO_CRC32_PCLMUL=m
CONFIG_CRYPTO_CRCT10DIF_PCLMUL=m
# end of Accelerated Cryptographic Algorithms for CPU (x86)

CONFIG_CRYPTO_HW=y
CONFIG_CRYPTO_DEV_PADLOCK=m
CONFIG_CRYPTO_DEV_PADLOCK_AES=m
CONFIG_CRYPTO_DEV_PADLOCK_SHA=m
# CONFIG_CRYPTO_DEV_ATMEL_ECC is not set
# CONFIG_CRYPTO_DEV_ATMEL_SHA204A is not set
CONFIG_CRYPTO_DEV_CCP=y
CONFIG_CRYPTO_DEV_CCP_DD=m
CONFIG_CRYPTO_DEV_SP_CCP=y
CONFIG_CRYPTO_DEV_CCP_CRYPTO=m
CONFIG_CRYPTO_DEV_SP_PSP=y
# CONFIG_CRYPTO_DEV_CCP_DEBUGFS is not set
CONFIG_CRYPTO_DEV_QAT=m
CONFIG_CRYPTO_DEV_QAT_DH895xCC=m
CONFIG_CRYPTO_DEV_QAT_C3XXX=m
CONFIG_CRYPTO_DEV_QAT_C62X=m
# CONFIG_CRYPTO_DEV_QAT_4XXX is not set
CONFIG_CRYPTO_DEV_QAT_DH895xCCVF=m
CONFIG_CRYPTO_DEV_QAT_C3XXXVF=m
CONFIG_CRYPTO_DEV_QAT_C62XVF=m
CONFIG_CRYPTO_DEV_NITROX=m
CONFIG_CRYPTO_DEV_NITROX_CNN55XX=m
# CONFIG_CRYPTO_DEV_VIRTIO is not set
# CONFIG_CRYPTO_DEV_SAFEXCEL is not set
# CONFIG_CRYPTO_DEV_AMLOGIC_GXL is not set
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
# CONFIG_PKCS8_PRIVATE_KEY_PARSER is not set
CONFIG_PKCS7_MESSAGE_PARSER=y
# CONFIG_PKCS7_TEST_KEY is not set
CONFIG_SIGNED_PE_FILE_VERIFICATION=y
# CONFIG_FIPS_SIGNATURE_SELFTEST is not set

#
# Certificates for signature checking
#
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_MODULE_SIG_KEY_TYPE_RSA=y
# CONFIG_MODULE_SIG_KEY_TYPE_ECDSA is not set
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS=""
# CONFIG_SYSTEM_EXTRA_CERTIFICATE is not set
# CONFIG_SECONDARY_TRUSTED_KEYRING is not set
CONFIG_SYSTEM_BLACKLIST_KEYRING=y
CONFIG_SYSTEM_BLACKLIST_HASH_LIST=""
# CONFIG_SYSTEM_REVOCATION_LIST is not set
# CONFIG_SYSTEM_BLACKLIST_AUTH_UPDATE is not set
# end of Certificates for signature checking

CONFIG_BINARY_PRINTF=y

#
# Library routines
#
CONFIG_RAID6_PQ=y
CONFIG_RAID6_PQ_BENCHMARK=y
# CONFIG_PACKING is not set
CONFIG_BITREVERSE=y
CONFIG_GENERIC_STRNCPY_FROM_USER=y
CONFIG_GENERIC_STRNLEN_USER=y
CONFIG_GENERIC_NET_UTILS=y
CONFIG_CORDIC=m
# CONFIG_PRIME_NUMBERS is not set
CONFIG_RATIONAL=y
CONFIG_GENERIC_PCI_IOMAP=y
CONFIG_GENERIC_IOMAP=y
CONFIG_ARCH_USE_CMPXCHG_LOCKREF=y
CONFIG_ARCH_HAS_FAST_MULTIPLIER=y
CONFIG_ARCH_USE_SYM_ANNOTATIONS=y

#
# Crypto library routines
#
CONFIG_CRYPTO_LIB_UTILS=y
CONFIG_CRYPTO_LIB_AES=y
CONFIG_CRYPTO_LIB_ARC4=m
CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC=y
CONFIG_CRYPTO_ARCH_HAVE_LIB_CHACHA=m
CONFIG_CRYPTO_LIB_CHACHA_GENERIC=m
# CONFIG_CRYPTO_LIB_CHACHA is not set
# CONFIG_CRYPTO_LIB_CURVE25519 is not set
CONFIG_CRYPTO_LIB_DES=m
CONFIG_CRYPTO_LIB_POLY1305_RSIZE=11
CONFIG_CRYPTO_ARCH_HAVE_LIB_POLY1305=m
CONFIG_CRYPTO_LIB_POLY1305_GENERIC=m
# CONFIG_CRYPTO_LIB_POLY1305 is not set
# CONFIG_CRYPTO_LIB_CHACHA20POLY1305 is not set
CONFIG_CRYPTO_LIB_SHA1=y
CONFIG_CRYPTO_LIB_SHA256=y
# end of Crypto library routines

CONFIG_CRC_CCITT=y
CONFIG_CRC16=y
CONFIG_CRC_T10DIF=y
CONFIG_CRC64_ROCKSOFT=y
CONFIG_CRC_ITU_T=m
CONFIG_CRC32=y
# CONFIG_CRC32_SELFTEST is not set
CONFIG_CRC32_SLICEBY8=y
# CONFIG_CRC32_SLICEBY4 is not set
# CONFIG_CRC32_SARWATE is not set
# CONFIG_CRC32_BIT is not set
CONFIG_CRC64=y
# CONFIG_CRC4 is not set
CONFIG_CRC7=m
CONFIG_LIBCRC32C=y
CONFIG_CRC8=m
CONFIG_XXHASH=y
# CONFIG_RANDOM32_SELFTEST is not set
CONFIG_ZLIB_INFLATE=y
CONFIG_ZLIB_DEFLATE=y
CONFIG_LZO_COMPRESS=y
CONFIG_LZO_DECOMPRESS=y
CONFIG_LZ4_DECOMPRESS=y
CONFIG_ZSTD_COMPRESS=y
CONFIG_ZSTD_DECOMPRESS=y
CONFIG_XZ_DEC=y
CONFIG_XZ_DEC_X86=y
CONFIG_XZ_DEC_POWERPC=y
CONFIG_XZ_DEC_IA64=y
CONFIG_XZ_DEC_ARM=y
CONFIG_XZ_DEC_ARMTHUMB=y
CONFIG_XZ_DEC_SPARC=y
# CONFIG_XZ_DEC_MICROLZMA is not set
CONFIG_XZ_DEC_BCJ=y
# CONFIG_XZ_DEC_TEST is not set
CONFIG_DECOMPRESS_GZIP=y
CONFIG_DECOMPRESS_BZIP2=y
CONFIG_DECOMPRESS_LZMA=y
CONFIG_DECOMPRESS_XZ=y
CONFIG_DECOMPRESS_LZO=y
CONFIG_DECOMPRESS_LZ4=y
CONFIG_DECOMPRESS_ZSTD=y
CONFIG_GENERIC_ALLOCATOR=y
CONFIG_REED_SOLOMON=m
CONFIG_REED_SOLOMON_ENC8=y
CONFIG_REED_SOLOMON_DEC8=y
CONFIG_TEXTSEARCH=y
CONFIG_TEXTSEARCH_KMP=m
CONFIG_TEXTSEARCH_BM=m
CONFIG_TEXTSEARCH_FSM=m
CONFIG_INTERVAL_TREE=y
CONFIG_XARRAY_MULTI=y
CONFIG_ASSOCIATIVE_ARRAY=y
CONFIG_HAS_IOMEM=y
CONFIG_HAS_IOPORT_MAP=y
CONFIG_HAS_DMA=y
CONFIG_DMA_OPS=y
CONFIG_NEED_SG_DMA_LENGTH=y
CONFIG_NEED_DMA_MAP_STATE=y
CONFIG_ARCH_DMA_ADDR_T_64BIT=y
CONFIG_ARCH_HAS_FORCE_DMA_UNENCRYPTED=y
CONFIG_SWIOTLB=y
CONFIG_DMA_COHERENT_POOL=y
CONFIG_DMA_CMA=y
# CONFIG_DMA_PERNUMA_CMA is not set

#
# Default contiguous memory area size:
#
CONFIG_CMA_SIZE_MBYTES=200
CONFIG_CMA_SIZE_SEL_MBYTES=y
# CONFIG_CMA_SIZE_SEL_PERCENTAGE is not set
# CONFIG_CMA_SIZE_SEL_MIN is not set
# CONFIG_CMA_SIZE_SEL_MAX is not set
CONFIG_CMA_ALIGNMENT=8
# CONFIG_DMA_API_DEBUG is not set
# CONFIG_DMA_MAP_BENCHMARK is not set
CONFIG_SGL_ALLOC=y
CONFIG_CHECK_SIGNATURE=y
CONFIG_CPUMASK_OFFSTACK=y
CONFIG_CPU_RMAP=y
CONFIG_DQL=y
CONFIG_GLOB=y
# CONFIG_GLOB_SELFTEST is not set
CONFIG_NLATTR=y
CONFIG_CLZ_TAB=y
CONFIG_IRQ_POLL=y
CONFIG_MPILIB=y
CONFIG_SIGNATURE=y
CONFIG_DIMLIB=y
CONFIG_OID_REGISTRY=y
CONFIG_UCS2_STRING=y
CONFIG_HAVE_GENERIC_VDSO=y
CONFIG_GENERIC_GETTIMEOFDAY=y
CONFIG_GENERIC_VDSO_TIME_NS=y
CONFIG_FONT_SUPPORT=y
# CONFIG_FONTS is not set
CONFIG_FONT_8x8=y
CONFIG_FONT_8x16=y
CONFIG_SG_POOL=y
CONFIG_ARCH_HAS_PMEM_API=y
CONFIG_MEMREGION=y
CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE=y
CONFIG_ARCH_HAS_COPY_MC=y
CONFIG_ARCH_STACKWALK=y
CONFIG_STACKDEPOT=y
CONFIG_STACKDEPOT_ALWAYS_INIT=y
CONFIG_SBITMAP=y
# end of Library routines

CONFIG_ASN1_ENCODER=y

#
# Kernel hacking
#

#
# printk and dmesg options
#
CONFIG_PRINTK_TIME=y
# CONFIG_PRINTK_CALLER is not set
# CONFIG_STACKTRACE_BUILD_ID is not set
CONFIG_CONSOLE_LOGLEVEL_DEFAULT=7
CONFIG_CONSOLE_LOGLEVEL_QUIET=4
CONFIG_MESSAGE_LOGLEVEL_DEFAULT=4
CONFIG_BOOT_PRINTK_DELAY=y
# CONFIG_DYNAMIC_DEBUG is not set
# CONFIG_DYNAMIC_DEBUG_CORE is not set
CONFIG_SYMBOLIC_ERRNAME=y
CONFIG_DEBUG_BUGVERBOSE=y
# end of printk and dmesg options

CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_MISC=y

#
# Compile-time checks and compiler options
#
CONFIG_DEBUG_INFO=y
# CONFIG_DEBUG_INFO_NONE is not set
# CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT is not set
CONFIG_DEBUG_INFO_DWARF4=y
# CONFIG_DEBUG_INFO_DWARF5 is not set
CONFIG_DEBUG_INFO_REDUCED=y
CONFIG_DEBUG_INFO_LEVEL=2
# CONFIG_DEBUG_MACRO_DEFINITIONS is not set
# CONFIG_DEBUG_INFO_COMPRESSED is not set
# CONFIG_DEBUG_INFO_SPLIT is not set
CONFIG_GDB_SCRIPTS=y
CONFIG_FRAME_WARN=2048
CONFIG_STRIP_ASM_SYMS=y
# CONFIG_READABLE_ASM is not set
# CONFIG_HEADERS_INSTALL is not set
CONFIG_DEBUG_SECTION_MISMATCH=y
CONFIG_SECTION_MISMATCH_WARN_ONLY=y
CONFIG_OBJTOOL=y
# CONFIG_DEBUG_FORCE_WEAK_PER_CPU is not set
# end of Compile-time checks and compiler options

#
# Generic Kernel Debugging Instruments
#
CONFIG_MAGIC_SYSRQ=y
CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x1
CONFIG_MAGIC_SYSRQ_SERIAL=y
CONFIG_MAGIC_SYSRQ_SERIAL_SEQUENCE=""
CONFIG_DEBUG_FS=y
CONFIG_DEBUG_FS_ALLOW_ALL=y
# CONFIG_DEBUG_FS_DISALLOW_MOUNT is not set
# CONFIG_DEBUG_FS_ALLOW_NONE is not set
CONFIG_HAVE_ARCH_KGDB=y
# CONFIG_KGDB is not set
CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL=y
# CONFIG_UBSAN is not set
CONFIG_HAVE_ARCH_KCSAN=y
# end of Generic Kernel Debugging Instruments

#
# Networking Debugging
#
# CONFIG_NET_DEV_REFCNT_TRACKER is not set
# CONFIG_NET_NS_REFCNT_TRACKER is not set
# CONFIG_DEBUG_NET is not set
# end of Networking Debugging

#
# Memory Debugging
#
# CONFIG_PAGE_EXTENSION is not set
# CONFIG_DEBUG_PAGEALLOC is not set
CONFIG_SLUB_DEBUG=y
# CONFIG_SLUB_DEBUG_ON is not set
# CONFIG_PAGE_OWNER is not set
# CONFIG_PAGE_TABLE_CHECK is not set
# CONFIG_PAGE_POISONING is not set
# CONFIG_DEBUG_PAGE_REF is not set
# CONFIG_DEBUG_RODATA_TEST is not set
CONFIG_ARCH_HAS_DEBUG_WX=y
# CONFIG_DEBUG_WX is not set
CONFIG_GENERIC_PTDUMP=y
# CONFIG_PTDUMP_DEBUGFS is not set
# CONFIG_DEBUG_OBJECTS is not set
# CONFIG_SHRINKER_DEBUG is not set
CONFIG_HAVE_DEBUG_KMEMLEAK=y
# CONFIG_DEBUG_KMEMLEAK is not set
# CONFIG_DEBUG_STACK_USAGE is not set
# CONFIG_SCHED_STACK_END_CHECK is not set
CONFIG_ARCH_HAS_DEBUG_VM_PGTABLE=y
# CONFIG_DEBUG_VM is not set
# CONFIG_DEBUG_VM_PGTABLE is not set
CONFIG_ARCH_HAS_DEBUG_VIRTUAL=y
# CONFIG_DEBUG_VIRTUAL is not set
CONFIG_DEBUG_MEMORY_INIT=y
# CONFIG_DEBUG_PER_CPU_MAPS is not set
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_CC_HAS_WORKING_NOSANITIZE_ADDRESS=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=y
CONFIG_KASAN_VMALLOC=y
# CONFIG_KASAN_KUNIT_TEST is not set
# CONFIG_KASAN_MODULE_TEST is not set
CONFIG_HAVE_ARCH_KFENCE=y
CONFIG_KFENCE=y
CONFIG_KFENCE_SAMPLE_INTERVAL=100
CONFIG_KFENCE_NUM_OBJECTS=255
# CONFIG_KFENCE_DEFERRABLE is not set
CONFIG_KFENCE_STRESS_TEST_FAULTS=0
CONFIG_KFENCE_KUNIT_TEST=y
# end of Memory Debugging

CONFIG_DEBUG_SHIRQ=y

#
# Debug Oops, Lockups and Hangs
#
CONFIG_PANIC_ON_OOPS=y
CONFIG_PANIC_ON_OOPS_VALUE=1
CONFIG_PANIC_TIMEOUT=0
CONFIG_LOCKUP_DETECTOR=y
CONFIG_SOFTLOCKUP_DETECTOR=y
# CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC is not set
CONFIG_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HARDLOCKUP_CHECK_TIMESTAMP=y
CONFIG_HARDLOCKUP_DETECTOR=y
CONFIG_BOOTPARAM_HARDLOCKUP_PANIC=y
# CONFIG_DETECT_HUNG_TASK is not set
# CONFIG_WQ_WATCHDOG is not set
# CONFIG_TEST_LOCKUP is not set
# end of Debug Oops, Lockups and Hangs

#
# Scheduler Debugging
#
CONFIG_SCHED_DEBUG=y
CONFIG_SCHED_INFO=y
CONFIG_SCHEDSTATS=y
# end of Scheduler Debugging

# CONFIG_DEBUG_TIMEKEEPING is not set
CONFIG_DEBUG_PREEMPT=y

#
# Lock Debugging (spinlocks, mutexes, etc...)
#
CONFIG_LOCK_DEBUGGING_SUPPORT=y
# CONFIG_PROVE_LOCKING is not set
# CONFIG_LOCK_STAT is not set
# CONFIG_DEBUG_RT_MUTEXES is not set
# CONFIG_DEBUG_SPINLOCK is not set
# CONFIG_DEBUG_MUTEXES is not set
# CONFIG_DEBUG_WW_MUTEX_SLOWPATH is not set
# CONFIG_DEBUG_RWSEMS is not set
# CONFIG_DEBUG_LOCK_ALLOC is not set
CONFIG_DEBUG_ATOMIC_SLEEP=y
# CONFIG_DEBUG_LOCKING_API_SELFTESTS is not set
CONFIG_LOCK_TORTURE_TEST=m
# CONFIG_WW_MUTEX_SELFTEST is not set
# CONFIG_SCF_TORTURE_TEST is not set
# CONFIG_CSD_LOCK_WAIT_DEBUG is not set
# end of Lock Debugging (spinlocks, mutexes, etc...)

# CONFIG_DEBUG_IRQFLAGS is not set
CONFIG_STACKTRACE=y
# CONFIG_WARN_ALL_UNSEEDED_RANDOM is not set
# CONFIG_DEBUG_KOBJECT is not set

#
# Debug kernel data structures
#
CONFIG_DEBUG_LIST=y
# CONFIG_DEBUG_PLIST is not set
# CONFIG_DEBUG_SG is not set
# CONFIG_DEBUG_NOTIFIERS is not set
CONFIG_BUG_ON_DATA_CORRUPTION=y
# CONFIG_DEBUG_MAPLE_TREE is not set
# end of Debug kernel data structures

# CONFIG_DEBUG_CREDENTIALS is not set

#
# RCU Debugging
#
CONFIG_TORTURE_TEST=m
# CONFIG_RCU_SCALE_TEST is not set
CONFIG_RCU_TORTURE_TEST=m
# CONFIG_RCU_REF_SCALE_TEST is not set
CONFIG_RCU_CPU_STALL_TIMEOUT=60
CONFIG_RCU_EXP_CPU_STALL_TIMEOUT=0
# CONFIG_RCU_TRACE is not set
# CONFIG_RCU_EQS_DEBUG is not set
# end of RCU Debugging

# CONFIG_DEBUG_WQ_FORCE_RR_CPU is not set
# CONFIG_CPU_HOTPLUG_STATE_CONTROL is not set
CONFIG_LATENCYTOP=y
CONFIG_USER_STACKTRACE_SUPPORT=y
CONFIG_NOP_TRACER=y
CONFIG_HAVE_RETHOOK=y
CONFIG_RETHOOK=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS=y
CONFIG_HAVE_FTRACE_MCOUNT_RECORD=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_HAVE_FENTRY=y
CONFIG_HAVE_OBJTOOL_MCOUNT=y
CONFIG_HAVE_C_RECORDMCOUNT=y
CONFIG_HAVE_BUILDTIME_MCOUNT_SORT=y
CONFIG_BUILDTIME_MCOUNT_SORT=y
CONFIG_TRACER_MAX_TRACE=y
CONFIG_TRACE_CLOCK=y
CONFIG_RING_BUFFER=y
CONFIG_EVENT_TRACING=y
CONFIG_CONTEXT_SWITCH_TRACER=y
CONFIG_TRACING=y
CONFIG_GENERIC_TRACER=y
CONFIG_TRACING_SUPPORT=y
CONFIG_FTRACE=y
# CONFIG_BOOTTIME_TRACING is not set
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y
# CONFIG_FPROBE is not set
CONFIG_FUNCTION_PROFILER=y
CONFIG_STACK_TRACER=y
# CONFIG_IRQSOFF_TRACER is not set
# CONFIG_PREEMPT_TRACER is not set
CONFIG_SCHED_TRACER=y
CONFIG_HWLAT_TRACER=y
# CONFIG_OSNOISE_TRACER is not set
# CONFIG_TIMERLAT_TRACER is not set
# CONFIG_MMIOTRACE is not set
CONFIG_FTRACE_SYSCALLS=y
CONFIG_TRACER_SNAPSHOT=y
# CONFIG_TRACER_SNAPSHOT_PER_CPU_SWAP is not set
CONFIG_BRANCH_PROFILE_NONE=y
# CONFIG_PROFILE_ANNOTATED_BRANCHES is not set
# CONFIG_PROFILE_ALL_BRANCHES is not set
CONFIG_BLK_DEV_IO_TRACE=y
CONFIG_KPROBE_EVENTS=y
# CONFIG_KPROBE_EVENTS_ON_NOTRACE is not set
CONFIG_UPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y
CONFIG_DYNAMIC_EVENTS=y
CONFIG_PROBE_EVENTS=y
# CONFIG_BPF_KPROBE_OVERRIDE is not set
CONFIG_FTRACE_MCOUNT_RECORD=y
CONFIG_FTRACE_MCOUNT_USE_CC=y
CONFIG_TRACING_MAP=y
CONFIG_SYNTH_EVENTS=y
CONFIG_HIST_TRIGGERS=y
# CONFIG_TRACE_EVENT_INJECT is not set
# CONFIG_TRACEPOINT_BENCHMARK is not set
CONFIG_RING_BUFFER_BENCHMARK=m
# CONFIG_TRACE_EVAL_MAP_FILE is not set
# CONFIG_FTRACE_RECORD_RECURSION is not set
# CONFIG_FTRACE_STARTUP_TEST is not set
# CONFIG_FTRACE_SORT_STARTUP_TEST is not set
# CONFIG_RING_BUFFER_STARTUP_TEST is not set
# CONFIG_RING_BUFFER_VALIDATE_TIME_DELTAS is not set
# CONFIG_PREEMPTIRQ_DELAY_TEST is not set
# CONFIG_SYNTH_EVENT_GEN_TEST is not set
# CONFIG_KPROBE_EVENT_GEN_TEST is not set
# CONFIG_HIST_TRIGGERS_DEBUG is not set
# CONFIG_RV is not set
CONFIG_PROVIDE_OHCI1394_DMA_INIT=y
# CONFIG_SAMPLES is not set
CONFIG_HAVE_SAMPLE_FTRACE_DIRECT=y
CONFIG_HAVE_SAMPLE_FTRACE_DIRECT_MULTI=y
CONFIG_ARCH_HAS_DEVMEM_IS_ALLOWED=y
CONFIG_STRICT_DEVMEM=y
# CONFIG_IO_STRICT_DEVMEM is not set

#
# x86 Debugging
#
CONFIG_EARLY_PRINTK_USB=y
CONFIG_X86_VERBOSE_BOOTUP=y
CONFIG_EARLY_PRINTK=y
CONFIG_EARLY_PRINTK_DBGP=y
CONFIG_EARLY_PRINTK_USB_XDBC=y
# CONFIG_EFI_PGT_DUMP is not set
# CONFIG_DEBUG_TLBFLUSH is not set
CONFIG_HAVE_MMIOTRACE_SUPPORT=y
# CONFIG_X86_DECODER_SELFTEST is not set
CONFIG_IO_DELAY_0X80=y
# CONFIG_IO_DELAY_0XED is not set
# CONFIG_IO_DELAY_UDELAY is not set
# CONFIG_IO_DELAY_NONE is not set
CONFIG_DEBUG_BOOT_PARAMS=y
# CONFIG_CPA_DEBUG is not set
# CONFIG_DEBUG_ENTRY is not set
# CONFIG_DEBUG_NMI_SELFTEST is not set
# CONFIG_X86_DEBUG_FPU is not set
# CONFIG_PUNIT_ATOM_DEBUG is not set
CONFIG_UNWINDER_ORC=y
# CONFIG_UNWINDER_FRAME_POINTER is not set
# end of x86 Debugging

#
# Kernel Testing and Coverage
#
CONFIG_KUNIT=y
# CONFIG_KUNIT_DEBUGFS is not set
CONFIG_KUNIT_TEST=m
CONFIG_KUNIT_EXAMPLE_TEST=m
# CONFIG_KUNIT_ALL_TESTS is not set
# CONFIG_NOTIFIER_ERROR_INJECTION is not set
CONFIG_FUNCTION_ERROR_INJECTION=y
CONFIG_FAULT_INJECTION=y
# CONFIG_FAILSLAB is not set
# CONFIG_FAIL_PAGE_ALLOC is not set
# CONFIG_FAULT_INJECTION_USERCOPY is not set
CONFIG_FAIL_MAKE_REQUEST=y
# CONFIG_FAIL_IO_TIMEOUT is not set
# CONFIG_FAIL_FUTEX is not set
CONFIG_FAULT_INJECTION_DEBUG_FS=y
# CONFIG_FAIL_FUNCTION is not set
# CONFIG_FAIL_MMC_REQUEST is not set
# CONFIG_FAIL_SUNRPC is not set
# CONFIG_FAULT_INJECTION_STACKTRACE_FILTER is not set
CONFIG_ARCH_HAS_KCOV=y
CONFIG_CC_HAS_SANCOV_TRACE_PC=y
# CONFIG_KCOV is not set
CONFIG_RUNTIME_TESTING_MENU=y
# CONFIG_LKDTM is not set
# CONFIG_CPUMASK_KUNIT_TEST is not set
# CONFIG_TEST_LIST_SORT is not set
# CONFIG_TEST_MIN_HEAP is not set
# CONFIG_TEST_SORT is not set
# CONFIG_TEST_DIV64 is not set
# CONFIG_KPROBES_SANITY_TEST is not set
# CONFIG_BACKTRACE_SELF_TEST is not set
# CONFIG_TEST_REF_TRACKER is not set
# CONFIG_RBTREE_TEST is not set
# CONFIG_REED_SOLOMON_TEST is not set
# CONFIG_INTERVAL_TREE_TEST is not set
# CONFIG_PERCPU_TEST is not set
CONFIG_ATOMIC64_SELFTEST=y
# CONFIG_ASYNC_RAID6_TEST is not set
# CONFIG_TEST_HEXDUMP is not set
# CONFIG_STRING_SELFTEST is not set
# CONFIG_TEST_STRING_HELPERS is not set
# CONFIG_TEST_STRSCPY is not set
# CONFIG_TEST_KSTRTOX is not set
# CONFIG_TEST_PRINTF is not set
# CONFIG_TEST_SCANF is not set
# CONFIG_TEST_BITMAP is not set
# CONFIG_TEST_UUID is not set
# CONFIG_TEST_XARRAY is not set
# CONFIG_TEST_RHASHTABLE is not set
# CONFIG_TEST_SIPHASH is not set
# CONFIG_TEST_IDA is not set
# CONFIG_TEST_LKM is not set
# CONFIG_TEST_BITOPS is not set
# CONFIG_TEST_VMALLOC is not set
# CONFIG_TEST_USER_COPY is not set
CONFIG_TEST_BPF=m
# CONFIG_TEST_BLACKHOLE_DEV is not set
# CONFIG_FIND_BIT_BENCHMARK is not set
# CONFIG_TEST_FIRMWARE is not set
# CONFIG_TEST_SYSCTL is not set
# CONFIG_BITFIELD_KUNIT is not set
# CONFIG_HASH_KUNIT_TEST is not set
# CONFIG_RESOURCE_KUNIT_TEST is not set
CONFIG_SYSCTL_KUNIT_TEST=m
CONFIG_LIST_KUNIT_TEST=m
# CONFIG_LINEAR_RANGES_TEST is not set
# CONFIG_CMDLINE_KUNIT_TEST is not set
# CONFIG_BITS_TEST is not set
# CONFIG_SLUB_KUNIT_TEST is not set
# CONFIG_RATIONAL_KUNIT_TEST is not set
# CONFIG_MEMCPY_KUNIT_TEST is not set
# CONFIG_IS_SIGNED_TYPE_KUNIT_TEST is not set
# CONFIG_OVERFLOW_KUNIT_TEST is not set
# CONFIG_STACKINIT_KUNIT_TEST is not set
# CONFIG_TEST_UDELAY is not set
# CONFIG_TEST_STATIC_KEYS is not set
# CONFIG_TEST_KMOD is not set
# CONFIG_TEST_MEMCAT_P is not set
# CONFIG_TEST_MEMINIT is not set
# CONFIG_TEST_HMM is not set
# CONFIG_TEST_FREE_PAGES is not set
# CONFIG_TEST_FPU is not set
# CONFIG_TEST_CLOCKSOURCE_WATCHDOG is not set
CONFIG_ARCH_USE_MEMTEST=y
# CONFIG_MEMTEST is not set
# CONFIG_HYPERV_TESTING is not set
# end of Kernel Testing and Coverage

#
# Rust hacking
#
# end of Rust hacking
# end of Kernel hacking

--4uR9TydQqPng+7Dv--
