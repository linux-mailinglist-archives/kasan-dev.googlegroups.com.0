Return-Path: <kasan-dev+bncBDN7L7O25EIBBN6RYKMAMGQEKMIWZVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A27B5A970F
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 14:42:32 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id x10-20020a2ea98a000000b00261b06603cfsf5267463ljq.17
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 05:42:32 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=XRisvkotwXCeg7nIHz2+OZ6YCSJRuWCRgmG8eR46ETo=;
        b=lIBqsZeUHrz0ZS4jVBALkSWY0FaaBdJGohI2SvAR/H+IRZ2k+KC4vFNSj44BcaEvr4
         WviSOZFOuMHzmJClwLMI0AYJESk0tUCxl372VQBxiUbG9yR5LKtzgVJWok4D4Gr9138s
         3zgZ/tEbd1UC/ls+H9YhzKfJ4ZjIsWtbJJS6LTooK7XX9dKFMQ+5zj0x+BliC4rXGx+l
         /uxW+YMI6nXhmbeiSPR4NVaLOrc0nFkfTgR/xMbXULSxcmOTktv7pBUROlGF5Hf0RauL
         p+oGNY5c029z1pI2nBC2ykBdf7WfUm97BOIGdgCeHKqh94yfQPkr/Lj8MjZD99oc3QNX
         I5FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=XRisvkotwXCeg7nIHz2+OZ6YCSJRuWCRgmG8eR46ETo=;
        b=5SDVjLsCbOuEfSIjtoRPAXG8/PmNPbzjuhBtjqiu0fxSwfHhwGI9l6yyLaSMHBLxVq
         T6YZC/XHYjD1UYMYXQMEprIAbfh51D6ra0n/HPwjqSRlukIchE3bIbpuA0z17QyreIIc
         09a3Dz1s/ctIwmpc82vw081AunuxNoLQJwqwvwLD+jdfaYZq5hukB+JiNafTMjv8BPGl
         8ewCK/235XGTb+w90ZmzMCBGSax0EOwojTVTxXVPqxp9daG4zwkeAehNeK8IvIGW8MQ8
         zGx3FNlfrZSCO/9mnszhodkRHs7OVMStZFg/1IBYN0visiFdQLPX+prlDu/vAL+YxJVV
         pmvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo19HRETivOOkPpIdFkdfcGRvYyleE6ZXexiwZ7bPNCxxXPj4E65
	89Qwp3TTkLFfpmn54281xCg=
X-Google-Smtp-Source: AA6agR79HaJz+KbXXX4WCUHFjAQXg8dRdR3NTfVJ4f+13c5+XMpkuE161JLrwyZ+NyCLHZr9R2l/DA==
X-Received: by 2002:a2e:a812:0:b0:261:8f2d:9530 with SMTP id l18-20020a2ea812000000b002618f2d9530mr9017190ljq.251.1662036152051;
        Thu, 01 Sep 2022 05:42:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a912:0:b0:25d:4f02:5abf with SMTP id j18-20020a2ea912000000b0025d4f025abfls310751ljq.2.-pod-prod-gmail;
 Thu, 01 Sep 2022 05:42:30 -0700 (PDT)
X-Received: by 2002:a2e:b892:0:b0:25f:e0f4:8911 with SMTP id r18-20020a2eb892000000b0025fe0f48911mr9193247ljp.25.1662036150865;
        Thu, 01 Sep 2022 05:42:30 -0700 (PDT)
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id p15-20020a2ea4cf000000b002652a5a5536si430292ljm.2.2022.09.01.05.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Sep 2022 05:42:30 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6500,9779,10457"; a="278720014"
X-IronPort-AV: E=Sophos;i="5.93,280,1654585200"; 
   d="scan'208";a="278720014"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Sep 2022 05:42:28 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,280,1654585200"; 
   d="scan'208";a="680842289"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by fmsmga004.fm.intel.com with ESMTP; 01 Sep 2022 05:42:28 -0700
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 1 Sep 2022 05:42:27 -0700
Received: from fmsmsx609.amr.corp.intel.com (10.18.126.89) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 1 Sep 2022 05:42:27 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx609.amr.corp.intel.com (10.18.126.89) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 1 Sep 2022 05:42:27 -0700
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (104.47.56.169)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 1 Sep 2022 05:42:27 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=aBBqmnb4u8tXaI6gY6iTtHZxb4KPPCdVWEVXHdZeQjuivxsa1CC8GFynknVAaG667i1QogMnfs3hBQ0+WlLOb+TxQUcX+c17TKGGD6AaQand6W73B1xSb8MLDUq+/lPPbFjAyrNKjyIRk4DhzOHZedk5TayIksBkTwpGB2GtcotlsY+p4dAuZNN/v9D57ojqXEFGip+vWlx26FbNgsU5dUDqsPnzdim7guNKQqKy74cz6ISruQ+7gvxjTn3849qDGcTU5P3A1t2//IQQ4qY0yLQzxvwgn/sI0YYVUkuB6VWLQclN9w2H9AUFw0UxZYUCobHlAw1K/K0Gup2aw4gZhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=SN8WNdV0ecosQV6MnOwstUYMDouImeM0AQxZeGYVh9w=;
 b=WSaWBscp6P6Pjn4Zxv/kqfqkm5eCV91LvON2FXwiYqErdtiextnZ1AG6M7nbkc5P7sUZSgN+AWhDEoUGb9kk/rvvlH8Ypvh77Q0DwmRGDeldu3NiiFslTP25+ozKOxUs1WzKVjhc9rc5WVgcbUrx1cdlEXLumHq4V5NfBM+8nOGxn4C3tzHjdObRm6uI+TyYQBG1mYI+u1UJCMC6mUmJGy+rd01SPTpbw/JRBpHOjnHDxbE25j9TYEisxcNsxWNSQg92ZwT0bEKkA/YmpZlibJZIKGODb4jjif1e8U43XvKQNX6GmKDEAlceuceuwBWCagF9sJDl0eFXg3ewHotc9A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by BN6PR11MB0019.namprd11.prod.outlook.com (2603:10b6:405:69::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5588.10; Thu, 1 Sep
 2022 12:42:26 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::d446:1cb8:3071:f4e8]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::d446:1cb8:3071:f4e8%5]) with mapi id 15.20.5588.012; Thu, 1 Sep 2022
 12:42:26 +0000
Date: Thu, 1 Sep 2022 20:41:51 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Marco Elver <elver@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip
 list
Message-ID: <YxCoj7XKPFU7UOX8@feng-clx>
References: <20220831073051.3032-1-feng.tang@intel.com>
 <Yw9qeSyrdhnLOA8s@hyeyoo>
 <CANpmjNMFOmtu3B5NCgrbrbkXk=FVfxSKGOEQvBhELSXRSv_1uQ@mail.gmail.com>
 <7edc9d38-da50-21c8-ea79-f003f386c29b@suse.cz>
 <YxAKXt+a/pqtUmDz@feng-clx>
 <111e54ab-67d7-2932-150d-3bfd46827b30@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <111e54ab-67d7-2932-150d-3bfd46827b30@suse.cz>
X-ClientProxiedBy: SG2PR04CA0210.apcprd04.prod.outlook.com
 (2603:1096:4:187::7) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: ad6382d2-8ffb-4631-1a0b-08da8c176c57
X-MS-TrafficTypeDiagnostic: BN6PR11MB0019:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: YlWAFaZ06GjAN/gjZ3Et5BRCshydCFo5Xn1M8ggwASTEcWwiopJc8VxxBXSmvJjfPE8X7ZPsbI6Nne57pnyBkT638QV8Mjfk4WVZ9T7tuMyyBOfJXNzmVJOtKayLeEOeVzkV8FItGEADbj2Ai4emmJXbUCkcgkNQxGwXcZQlJggE8+jbQE+oDcwYCoUT19yYoQzcN61ROdFWUa+fqHFUNIMX9PV3QCkSnBEKVlQlsaTWp64gIvysjmt1LsOPUX+4lW8V/KZsWBxUF4qeh0IqXX0STSojK2fWmbsP0mXsmyXn0zjwFBxUz/pbKFoYLQD6qNN7nZGSfKX/RNH0VO9V/agsENkmq9vbppicDZg+5ajiXQdfA+a3oOF8ORv8W9SJQ5RxZW8Wb7e7DpXhHd4dpFhm513kTXjbojmYoIXNkyp6QwFMPMdxdLLqGt7pXqMgEfIcImqidYaItkqgW+WhNTgpXfu7S+3SDNeMjZp0I6wroxXwX0Mt45mZDAeAYogwBAm+VTvrn4waRyQZ8aVuKSt6muqhn0WxRU/ZWV94H4LNU+KkhtmlkiryjGAf404SG+qPNFan0QTAVG5PfCa0fk+dJiEA9GmWdCdwdx703HkBgSIuqWqC/rZbJH47hRXHjleImCNaCaMLWm0yMij/HMSYsheiyl8ig3tRZM+9ZJ2KMNZOcwydjmNtSbEVkMmp3deESsRXi4E7q69fG3ngAg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(366004)(136003)(396003)(376002)(39860400002)(346002)(478600001)(6486002)(6916009)(54906003)(316002)(66946007)(66476007)(66556008)(4326008)(8676002)(44832011)(186003)(5660300002)(8936002)(2906002)(86362001)(83380400001)(9686003)(6666004)(6512007)(26005)(38100700002)(6506007)(41300700001)(33716001)(82960400001)(53546011);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?VWKcGKoGxPZIwz0e8Tg7kqHhIxTNS1MUN5ozY1nChvN5iGglAQm8sSuQLCLP?=
 =?us-ascii?Q?4JU73LGmuLvPfgQgVMZN/6spFw/ymMtLy1GyCTgDO4bfXLdsUWcO9E7ZPIkV?=
 =?us-ascii?Q?rGyNDb8qh2IoafkcY3p/kVRRT7qjl6kjABlsLtDniFHmrFc7fsevb6pvZx1f?=
 =?us-ascii?Q?lh1piMBG3OQ5OM5nAm8o909h6Ns7RkD5td3/XmssTCw7msBDdsw8MBbBXori?=
 =?us-ascii?Q?ewye4P3vcag8Doy2Sjtbbm6VbGpfy1fA2XwZOj9DgSxsfKpeofgreX7rrNJu?=
 =?us-ascii?Q?pS5jvMBXxHCPJXuXxEEM3BknQcjucU6ZK0MgOjXVfbd5DhZ5SzefDqx69AQ/?=
 =?us-ascii?Q?ymtH5Zngd6HQ6Oa0P5hD7tJrVXkAcE5EBHkMQEeOZifL3NKiUxnixFgRdxof?=
 =?us-ascii?Q?6NGVQpz/vsxy2k0R/icqHkTxp+py0v2fOgLi3osYzk8f4U0PmOjv+M5U+2AF?=
 =?us-ascii?Q?u+B8urmKh5QVB61h8jfF4eAAG18+IOl+C3LNyCy1bmvbwjPUZmC8BYk1i830?=
 =?us-ascii?Q?X0YTKQwx3M4wCTTNIS71488K5becsCEBend9u++ge3YQAzXDppVTGVA4aUld?=
 =?us-ascii?Q?v9X23zMidjRbVJhfziZtLf07vShaxcGP2mzMON7Wn/XHfl9OHOsZli68mOwh?=
 =?us-ascii?Q?8Qyv84Ynya/DqDF2f4B7eH5SM1F0NlrXjEvCvKKFiID6gfCfKbHGQDQpmY+g?=
 =?us-ascii?Q?kHBo8E90sux/rJTNH6UHZdk+4VLVe5vOw4dKj8EyBZJhqnzW4d3g/q35X4YK?=
 =?us-ascii?Q?E7dRweMusZJI82SZ2TQTDjExEoTshqVvsTCM5EB2lc8CZQZvRIv9pYjSYm6o?=
 =?us-ascii?Q?aueXE9qqbkehya83lkVQFNp0UmNDb3YRfK7KyBk1jz5Na5GnGLnSXQjAX8W9?=
 =?us-ascii?Q?WGkztzFA30s4We2kCTABZ/buUiP5YpO5PV5ndmlciCvJY/ZAlpoQb9DrPgMu?=
 =?us-ascii?Q?VrIT2/ZhBhX7QGcSNj9MAXA0FKlFeDeQ7A7c9qNJm4UyaOB36XymqqZtAjpE?=
 =?us-ascii?Q?jpErDxh/N9G33bXISe9mIvtQhDR9OQqN10tu1oy9aptrT1dgPBHw9Rzv9X75?=
 =?us-ascii?Q?Awc8NH8PsfxrtpkpuUUa5H6P8J1HBDi8MBAONDDH8qjiM5pR0X2dd0xR+H6A?=
 =?us-ascii?Q?B3BE818A3Y6tyLsBtYH5tbxzy8yt8UvRkUorprjYXs1CjKxj30KBgFxDJM0Y?=
 =?us-ascii?Q?kXycse7P1IkMGnHKX75dpazmbg/k6xf1nl2g1VDAD6PZdZavkN0DOnkkZm/q?=
 =?us-ascii?Q?DK5LreK9zKIjUo/RhUDyslHmLAXIGvITRLqX1c8R0FhE05Oj8Q3EhHOSETYc?=
 =?us-ascii?Q?puidwru0tnHrvwCT/tPOK7duYSznA2yxkVhRk+Mp6GUiCOyg7Zqqxs2bdsFm?=
 =?us-ascii?Q?Tedu0XwRGg26HHWGo9Q2bbkDVM9XxqtZXupo335SND5tflwSFykpO7pKwqXB?=
 =?us-ascii?Q?T1CtVTefYrwQmEzEwnmU/VPS95Un1tx5SX79SADgIDFV4QzA1X6+Il3sbK6F?=
 =?us-ascii?Q?fKA5ZVVGJCRdv4m63l1EYtl1DycQhIeiLnjJ7GVIyriiXHsRiqflQr5G3Lyc?=
 =?us-ascii?Q?IvTSvcyi7YrRzAUnbELC9mVP+J5rtxsI2eoVlV3+?=
X-MS-Exchange-CrossTenant-Network-Message-Id: ad6382d2-8ffb-4631-1a0b-08da8c176c57
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Sep 2022 12:42:25.9879
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: KW9y5gaAUwA4+dgzcsiqZOV/OMEyRC0T4gAgBqBLZXbjbfj9eDz2Z5BhMZivzq1LkYhBt4OilNcfRTSguIPBGA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN6PR11MB0019
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JgJCBf+L;       arc=fail
 (signature failed);       spf=softfail (google.com: domain of transitioning
 feng.tang@intel.com does not designate 134.134.136.126 as permitted sender)
 smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Sep 01, 2022 at 04:47:11PM +0800, Vlastimil Babka wrote:
> On 9/1/22 03:26, Feng Tang wrote:
> > On Thu, Sep 01, 2022 at 12:16:17AM +0800, Vlastimil Babka wrote:
> >> On 8/31/22 16:21, Marco Elver wrote:
> >> > On Wed, 31 Aug 2022 at 16:04, Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
> >> > 
> >> >> Maybe you can include those functions too?
> >> >>
> >> >> - __kmem_cache_alloc_node
> >> >> - kmalloc_[node_]trace, kmalloc_large[_node]
> >> > 
> >> > This is only required if they are allocator "root" functions when
> >> > entering allocator code (or may be tail called by a allocator "root"
> >> > function). Because get_stack_skipnr() looks for one of the listed
> >> > function prefixes in the whole stack trace.
> >> > 
> >> > The reason __kmem_cache_free() is now required is because it is tail
> >> > called by kfree() which disappears from the stack trace if the
> >> > compiler does tail-call-optimization.
> >> 
> >> I checked and I have this jmp tail call, yet all test pass here.
> >> But I assume the right commit to amend is
> >> 05a1c2e50809 ("mm/sl[au]b: generalize kmalloc subsystem")
> >> 
> >> Could you Feng maybe verify that that commit is the first that fails the
> >> tests, and parent commit of that is OK? Thanks.
> > 
> > Yes, 05a1c2e50809 is the first commit that I saw the 4 kfence failed
> > kunit cases.
> 
> Thanks, squashed your patch there and pushed new for-next.

Thanks! Just re-pulled slab tree's 'for-next' branch and the error
can't be reproduced with it.

- Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxCoj7XKPFU7UOX8%40feng-clx.
