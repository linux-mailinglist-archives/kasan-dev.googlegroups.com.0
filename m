Return-Path: <kasan-dev+bncBDN7L7O25EIBBCXWY2OAMGQEN3OJUFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 24B0B646CA4
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Dec 2022 11:23:09 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id l6-20020ac25546000000b004b55de13741sf373111lfk.6
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Dec 2022 02:23:09 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gxiDFpM0IDrg9I4ffQrIC//g8RoQ1jQXdPfzuE81rpU=;
        b=hy72Ld5R8F7l4Rby7X+dX49vfaIjLqJku953VR7Y+g/U68Bg62Uf82tRAVDx3BBI0h
         WIRIq+zb9/iqj6WCSJi5iOGNqMTcRd+pUbwEoGtynvUw1HlQJ7YUake5/LPNWUupqZ9j
         O7RUfr0lTpvHkc6qU7vYrAh4bUfmlGI19Yt9NEImtJcmQdLWQ+YHjvvtAge/SzLelWJa
         Mh0kvPLOD1EY0ufNDN81P4Lu2p2bC9TH3CMkK+BlXkC9xoeQG0OK74HRe2eVPKoCyJRx
         73kxWPOp8y+LBwYyHT7HIcX0u92KtpOvVytUpeVdFUniVRCmHySjACBJ+sXEDzdI6ZmU
         APsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gxiDFpM0IDrg9I4ffQrIC//g8RoQ1jQXdPfzuE81rpU=;
        b=RYk2TA6i092AEpIpqyN5/QyOjZ7HxvbmvVAon0NBMy6/WcPJsZKeIaGKJDFzi5+6xO
         ViXEVb0xuRpEAwDiXoxhd60S0DWUy2CdKyOoEfApnYllVkO6/6YU0YtYYIP45fziN4bA
         fFd6c+7uNvUbFrvrah62lEAfzmOx/jGjnnx7GPVbqBW/8/sJVP5HiAjRqthiTm+wvubd
         KbegohmTbFtiJgWtfT7DgXqMMKRl9fIytMD3yUd/75FeYr8vuOtLycAs6xnUUYyp62xr
         qkO1ITxLeNmoaKldJlTdk2hdZfGn8xxd4rqrzlareSh13c0kq2M2+babGWXmbORpSCXO
         ndwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plzNHsN+Aoe7umemCwLs4piCF0Jm2mYffTk0y6LsbVJQ/hlBeKy
	cnIwhr3SSjxJwyS25bL0c6c=
X-Google-Smtp-Source: AA0mqf4mI0V3d3cjiWSsPRbQhLQ/vLDuq4wPRlyGYSNfSfJOO0AVqVU0+s7Us283AWo9r8yA7IOXCg==
X-Received: by 2002:a05:651c:150d:b0:26f:ebb8:7a0d with SMTP id e13-20020a05651c150d00b0026febb87a0dmr24412868ljf.474.1670494987153;
        Thu, 08 Dec 2022 02:23:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1208:b0:277:22e9:929f with SMTP id
 i8-20020a05651c120800b0027722e9929fls830335lja.5.-pod-prod-gmail; Thu, 08 Dec
 2022 02:23:05 -0800 (PST)
X-Received: by 2002:a2e:be08:0:b0:277:2123:120d with SMTP id z8-20020a2ebe08000000b002772123120dmr546442ljq.5.1670494985733;
        Thu, 08 Dec 2022 02:23:05 -0800 (PST)
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id g15-20020a2eb5cf000000b0027a0c7ad60bsi359607ljn.1.2022.12.08.02.23.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Dec 2022 02:23:05 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6500,9779,10554"; a="344178189"
X-IronPort-AV: E=Sophos;i="5.96,227,1665471600"; 
   d="scan'208";a="344178189"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Dec 2022 02:23:02 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10554"; a="753499719"
X-IronPort-AV: E=Sophos;i="5.96,227,1665471600"; 
   d="scan'208";a="753499719"
Received: from fmsmsx603.amr.corp.intel.com ([10.18.126.83])
  by fmsmga002.fm.intel.com with ESMTP; 08 Dec 2022 02:23:01 -0800
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.16; Thu, 8 Dec 2022 02:23:01 -0800
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.16; Thu, 8 Dec 2022 02:23:00 -0800
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.16 via Frontend Transport; Thu, 8 Dec 2022 02:23:00 -0800
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (104.47.66.46) by
 edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.16; Thu, 8 Dec 2022 02:23:00 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=ZNaYeAwi7qeDjhsjJ9b34kr730LcBewRW6qIglNxcJuj/9IaNZeko91QuNMNQY9rtUoivdYMEWTBkSiWjzeQ54CXRBIpskwhmYCjgbHV5gvY8EB7434GObUkBpD27y5v9/fbpOlwe4pO1CJZNsqLFhFYdvIZU+p/bFtbxHPkSWO4VYPXpxLfJtgKkb+tgi6e7Zj8Yo7QuAYxDfcrgRkPKtgogGTa5CVj/uekx6DXYKnY9S0WsA/IIIGc0pevpBMaHrl9eLG47QMRbPHJ8y/Ie0f6lrM+Xxjp74Inx7lkDE/p4ArmgTm8CHRyNLy1CWznlhnRkO8OQU2htzXu6th7gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HCLiU5M71RDn3EZfse5qCm6V5JSZh2DooSTLJmT1Ewk=;
 b=A8j42qs6CLVmVRkCjREfM6h4uDA3lkyKy1NITSA7WrQOSjsWji9ngWQzH2Fv7Scoo1sfkcY4X37S+Xp4ICGf+QhfPEMcTy8F20gNcfMLlN8O5IvqLKgQ3QlIYiPi5NPcWtKYhVsJ+CDw7ZlY3RoUGsQEHgYDYU4V2bErFh1mHOnghHeEaA+EhtHW0iBX41X7ZEWzJb7fmLNo1aiZRBsmLbexxeCa+SuQBDbbNi7d95PlXPgcQUCb2wuVBlBisBZwFBhfQJ/UulhkBRpTF5u4CtLt5HM3etw8twgWLb+eIXWhSQUmnsaXKnR2/H55oCuLeI6izzIbLNfCtz7hUix99A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by MN2PR11MB4630.namprd11.prod.outlook.com (2603:10b6:208:24e::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5880.14; Thu, 8 Dec
 2022 10:22:58 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb%6]) with mapi id 15.20.5880.014; Thu, 8 Dec 2022
 10:22:58 +0000
Date: Thu, 8 Dec 2022 18:19:50 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Kees Cook <keescook@chromium.org>, Jakub Kicinski <kuba@kernel.org>,
	<syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com>, Eric Dumazet
	<edumazet@google.com>, "David S. Miller" <davem@davemloft.net>, Paolo Abeni
	<pabeni@redhat.com>, Pavel Begunkov <asml.silence@gmail.com>, pepsipu
	<soopthegoop@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, "Andrii
 Nakryiko" <andrii@kernel.org>, <ast@kernel.org>, bpf <bpf@vger.kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>, Hao Luo <haoluo@google.com>, "Jesper
 Dangaard Brouer" <hawk@kernel.org>, John Fastabend
	<john.fastabend@gmail.com>, <jolsa@kernel.org>, KP Singh
	<kpsingh@kernel.org>, <martin.lau@linux.dev>, Stanislav Fomichev
	<sdf@google.com>, <song@kernel.org>, Yonghong Song <yhs@fb.com>,
	<netdev@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, Rasesh Mody
	<rmody@marvell.com>, Ariel Elior <aelior@marvell.com>, Manish Chopra
	<manishc@marvell.com>, Menglong Dong <imagedong@tencent.com>, David Ahern
	<dsahern@kernel.org>, Richard Gobert <richardbgobert@gmail.com>, "Andrey
 Konovalov" <andreyknvl@gmail.com>, David Rientjes <rientjes@google.com>,
	<GR-Linux-NIC-Dev@marvell.com>, <linux-hardening@vger.kernel.org>
Subject: Re: [PATCH net-next v3] skbuff: Introduce slab_build_skb()
Message-ID: <Y5G6RnoyZC78UO4q@feng-clx>
References: <20221208060256.give.994-kees@kernel.org>
 <6923d6a9-7728-fc71-f963-3617e5361732@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6923d6a9-7728-fc71-f963-3617e5361732@suse.cz>
X-ClientProxiedBy: SI2PR01CA0036.apcprd01.prod.exchangelabs.com
 (2603:1096:4:192::22) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|MN2PR11MB4630:EE_
X-MS-Office365-Filtering-Correlation-Id: 057287f2-e0d3-4bed-7a2e-08dad9062d67
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: fvd7fnLM/ionTWV/wERScwTkrfJQFYoIFc42PYIIMMGZf5U52HHJ+lTIeFbLH5wCKkbFEvZOXC+/vmLcKCPyPN0hycn147Z0iW8QkbsqNI3dIUNLKAX5zN6ywmvs22HAi4drM+EcqEJ9EVZuomFT971qw5vn1NHmwgTclOry/7EQk+oqriZ6K+J7JCyP2OdvsJOcQnEqyaBOPPGB36VOTazvXlS4II7Dc0NTcnqrSYXIrtODBQuWYZ86/mPeihp6NhrIfGvdkXNqJeZr37Qp0zMaRZU+k4gBx+2sl9PtFluOXYE3Y3+AHKYjxvVwCWmbk6BI7WKo2M3z+gtz75nQ/T5NGtjoqCMGR7AAAyFItjGWGyMfnguVmDiN6BscwZWQUV0r4dvRwErqTYWnQSXquOaWYStV9CGh7l/2rtyJOj9JbeqpoZIGhH1Suw9I09DC0e/ALoZsRlMKj2Ee5rHs9yyVXbAb5fz+zWIm6ZDiryAhFGdRLA0sG4UeKn34O5LgXFIHUxX9+QMZPf+cZJMR1pv5IEUXKQWDok2iaUbaquccmIvtdkWMpUAKG9ovLSYQLuV7IThM9F+lGclGWczi8W/vm9utUIAh/UEss0tWo3ZppVY6JYh4+9PlHkxEKHkqRoQyqtF6bL5QEAwtDG1YhoPxUeN2wQexKwz/s2lmdf7XQoVHIKpzdzcZuiq9IMSL/OcOyTHIKO+JDdEkXLqpIQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(39860400002)(396003)(366004)(136003)(346002)(376002)(451199015)(33716001)(6916009)(6666004)(82960400001)(316002)(2906002)(54906003)(53546011)(966005)(44832011)(6486002)(478600001)(6506007)(8676002)(41300700001)(86362001)(186003)(38100700002)(4326008)(8936002)(9686003)(66556008)(26005)(83380400001)(5660300002)(66476007)(7416002)(66946007)(6512007)(7406005);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?w4f5NMh0OpjLZnN+CNxRmF+wK2OOm7cf1caArr8af5lYbxdJxyopqtBO/agK?=
 =?us-ascii?Q?BxKWcYuMcVhIee0wOcgyZm6KIpJJgekJPOcJLG9ZfVHDdTiIIVWULlR/Cdui?=
 =?us-ascii?Q?br2GTyAjy70yGoy+q5L9xRjO+mbDzgdMevo5scmeTVNSBmVC6teKnbvtY/jH?=
 =?us-ascii?Q?X+e1WUIqPeCotyvHcIl8oUSPsRn04WAST0lRMD/RDiFSBXWohbT0Xp7axWIS?=
 =?us-ascii?Q?hkHGZQWFlWdUDHUstfx45c2PwAYF/dcCEGStgwRv/4+3po1N5EbMH2ASx8Wt?=
 =?us-ascii?Q?vciySkp3lIAgHihooZ9qbfyPHj/nS73wn3skDw4u2ugq4/0V+1zJ9Ah9U4ht?=
 =?us-ascii?Q?3kktVZXTedQfmlFi64e+OJePcNEm3tMmmFTUqbid80+q3f6HbkTGr8DVY4F+?=
 =?us-ascii?Q?9yXdl6E7SBNKx+Fgp5sxTfO4MQ5hyxjLmeKIt+DLZgr9kdxTm125+e7skBc6?=
 =?us-ascii?Q?SbVViJWgO18mNiCFuMQTHFVSdRAQJspL4aIUGphPmCx5Pt5wrcLXarSAql2y?=
 =?us-ascii?Q?EWz6TEcTL+y7W8t+rG+EltbTpeTGPLQ9xzZo2jJgkgJ5KSP0SfoMCuNdGd3Z?=
 =?us-ascii?Q?pmC7620hsZWV3n9NJRjvgFiKqAI8L8dRKRmwfuOVcUx6Uh79e8VUnmiZYI1R?=
 =?us-ascii?Q?WdoDUdWLIuVHZO3tHp8LQqKcWETepTbV0sp1OKUXygAYOcTX3XfP4IuKmdXx?=
 =?us-ascii?Q?g+4MdUR7praMERKrlcWYCPI7Dny/Kp3+ZrHTyol4Q5ZSNTSKFSjManzr3q10?=
 =?us-ascii?Q?IWdXDLEWI2HNY9EB6GLyKDAYZ30qK8A/O9airI6eRpc+D8w6rk33O+tx5ntq?=
 =?us-ascii?Q?YLYqSZFlHjJTgH9GRgVF5ba8nwEfn0Fj1CWNsjHuPiy89cKm9BnbwxqsTc0b?=
 =?us-ascii?Q?LIbNR3bUK/h4nR0UhXFIg5XQ+YIZCp3ZKsbM8tmw0msJjVdRwEx9ROPlBL6m?=
 =?us-ascii?Q?imlPTn15X0lP3E2p/iWVLDjlLb1Rof0aTDqy5/EkFWj0jypZsKk6jGbjAiZa?=
 =?us-ascii?Q?Wpb2lPOEXoRDJiKccjG7+b0V7D/rAkSp/wgHpjjiBx8lBnbt44eGs15RpzWN?=
 =?us-ascii?Q?p0n+Ba5JHteL6KHfpQ+XRtaxRQ/qxMiB6cXW4OK5NwCzwrePHSs3trH+WrOr?=
 =?us-ascii?Q?h1JKdaP2Ee5WPJ469P3nwcuwYB1zuQfXpo837It/85cqoTH0D8ln1oeZRWkC?=
 =?us-ascii?Q?SlbnAyyrGjFFzKDhMv8hQJD0eZBFIF0/5V0QDkFfVas8K8jY8XxLudqQQ4TL?=
 =?us-ascii?Q?pG2kIMBM/8qRg8FytSdMGQWrGYjUd0GEfeYqqu+dj16z7sClYvWjMC8T9bM+?=
 =?us-ascii?Q?aEwyI8TFbmt+X2UqeZbO3tP93+wRxxkrWgsA+4/4YkUbnCvOcxBkt3pGfH18?=
 =?us-ascii?Q?GY7S+ovuvDMM0BvT0QdHjVGDWqGhsFskNP93Ce3jq088Dv9+5puzxvh1JGn4?=
 =?us-ascii?Q?KeBWX/QKH6/AH4isDQPF/XEiu20kzcBX0p1yNmcaPDyizzujRiSHuxoqjSij?=
 =?us-ascii?Q?Fp9zOdPpO1Ruev54d938MWTcW7wpxd5UJSbCASquFKkzpkVKtZ0jNbFs6Hz4?=
 =?us-ascii?Q?OTwUyMp+6u3GXMRnglHZXNTux7dcufz/MAGTH8rJ?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 057287f2-e0d3-4bed-7a2e-08dad9062d67
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Dec 2022 10:22:58.3633
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: U3p3sCT6jbHx2oS75b9WuLiMglR9DY7Wo++v0iSvpCbc1P37hNtYfQyfTpDEyRxsirLBmXpsoirkzbVZ9h+0Eg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR11MB4630
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=gGmLn8cA;       arc=fail
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

On Thu, Dec 08, 2022 at 09:13:41AM +0100, Vlastimil Babka wrote:
> On 12/8/22 07:02, Kees Cook wrote:
> > syzkaller reported:
> > 
> >   BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
> >   Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295
> > 
> > For bpf_prog_test_run_skb(), which uses a kmalloc()ed buffer passed to
> > build_skb().
> > 
> > When build_skb() is passed a frag_size of 0, it means the buffer came
> > from kmalloc. In these cases, ksize() is used to find its actual size,
> > but since the allocation may not have been made to that size, actually
> > perform the krealloc() call so that all the associated buffer size
> > checking will be correctly notified (and use the "new" pointer so that
> > compiler hinting works correctly). Split this logic out into a new
> > interface, slab_build_skb(), but leave the original 0 checking for now
> > to catch any stragglers.
> > 
> > Reported-by: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
> > Link: https://groups.google.com/g/syzkaller-bugs/c/UnIKxTtU5-0/m/-wbXinkgAQAJ
> > Fixes: 38931d8989b5 ("mm: Make ksize() a reporting-only function")
> > Cc: Jakub Kicinski <kuba@kernel.org>
> > Cc: Eric Dumazet <edumazet@google.com>
> > Cc: "David S. Miller" <davem@davemloft.net>
> > Cc: Paolo Abeni <pabeni@redhat.com>
> > Cc: Pavel Begunkov <asml.silence@gmail.com>
> > Cc: pepsipu <soopthegoop@gmail.com>
> > Cc: syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com
> > Cc: Vlastimil Babka <vbabka@suse.cz>
> > Cc: kasan-dev <kasan-dev@googlegroups.com>
> > Cc: Andrii Nakryiko <andrii@kernel.org>
> > Cc: ast@kernel.org
> > Cc: bpf <bpf@vger.kernel.org>
> > Cc: Daniel Borkmann <daniel@iogearbox.net>
> > Cc: Hao Luo <haoluo@google.com>
> > Cc: Jesper Dangaard Brouer <hawk@kernel.org>
> > Cc: John Fastabend <john.fastabend@gmail.com>
> > Cc: jolsa@kernel.org
> > Cc: KP Singh <kpsingh@kernel.org>
> > Cc: martin.lau@linux.dev
> > Cc: Stanislav Fomichev <sdf@google.com>
> > Cc: song@kernel.org
> > Cc: Yonghong Song <yhs@fb.com>
> > Cc: netdev@vger.kernel.org
> > Cc: LKML <linux-kernel@vger.kernel.org>
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> > v3:
> > - make sure "resized" is passed back so compiler hints survive
> > - update kerndoc (kuba)
> > v2: https://lore.kernel.org/lkml/20221208000209.gonna.368-kees@kernel.org
> > v1: https://lore.kernel.org/netdev/20221206231659.never.929-kees@kernel.org/
> > ---
> >  drivers/net/ethernet/broadcom/bnx2.c      |  2 +-
> >  drivers/net/ethernet/qlogic/qed/qed_ll2.c |  2 +-
> >  include/linux/skbuff.h                    |  1 +
> >  net/bpf/test_run.c                        |  2 +-
> >  net/core/skbuff.c                         | 70 ++++++++++++++++++++---
> >  5 files changed, 66 insertions(+), 11 deletions(-)
> > 
> > diff --git a/drivers/net/ethernet/broadcom/bnx2.c b/drivers/net/ethernet/broadcom/bnx2.c
> > index fec57f1982c8..b2230a4a2086 100644
> > --- a/drivers/net/ethernet/broadcom/bnx2.c
> > +++ b/drivers/net/ethernet/broadcom/bnx2.c
> > @@ -3045,7 +3045,7 @@ bnx2_rx_skb(struct bnx2 *bp, struct bnx2_rx_ring_info *rxr, u8 *data,
> >  
> >  	dma_unmap_single(&bp->pdev->dev, dma_addr, bp->rx_buf_use_size,
> >  			 DMA_FROM_DEVICE);
> > -	skb = build_skb(data, 0);
> > +	skb = slab_build_skb(data);
> >  	if (!skb) {
> >  		kfree(data);
> >  		goto error;
> > diff --git a/drivers/net/ethernet/qlogic/qed/qed_ll2.c b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
> > index ed274f033626..e5116a86cfbc 100644
> > --- a/drivers/net/ethernet/qlogic/qed/qed_ll2.c
> > +++ b/drivers/net/ethernet/qlogic/qed/qed_ll2.c
> > @@ -200,7 +200,7 @@ static void qed_ll2b_complete_rx_packet(void *cxt,
> >  	dma_unmap_single(&cdev->pdev->dev, buffer->phys_addr,
> >  			 cdev->ll2->rx_size, DMA_FROM_DEVICE);
> >  
> > -	skb = build_skb(buffer->data, 0);
> > +	skb = slab_build_skb(buffer->data);
> >  	if (!skb) {
> >  		DP_INFO(cdev, "Failed to build SKB\n");
> >  		kfree(buffer->data);
> > diff --git a/include/linux/skbuff.h b/include/linux/skbuff.h
> > index 7be5bb4c94b6..0b391b635430 100644
> > --- a/include/linux/skbuff.h
> > +++ b/include/linux/skbuff.h
> > @@ -1253,6 +1253,7 @@ struct sk_buff *build_skb_around(struct sk_buff *skb,
> >  void skb_attempt_defer_free(struct sk_buff *skb);
> >  
> >  struct sk_buff *napi_build_skb(void *data, unsigned int frag_size);
> > +struct sk_buff *slab_build_skb(void *data);
> >  
> >  /**
> >   * alloc_skb - allocate a network buffer
> > diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
> > index 13d578ce2a09..611b1f4082cf 100644
> > --- a/net/bpf/test_run.c
> > +++ b/net/bpf/test_run.c
> > @@ -1130,7 +1130,7 @@ int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
> >  	}
> >  	sock_init_data(NULL, sk);
> >  
> > -	skb = build_skb(data, 0);
> > +	skb = slab_build_skb(data);
> >  	if (!skb) {
> >  		kfree(data);
> >  		kfree(ctx);
> > diff --git a/net/core/skbuff.c b/net/core/skbuff.c
> > index 1d9719e72f9d..ae5a6f7db37b 100644
> > --- a/net/core/skbuff.c
> > +++ b/net/core/skbuff.c
> > @@ -269,12 +269,10 @@ static struct sk_buff *napi_skb_cache_get(void)
> >  	return skb;
> >  }
> >  
> > -/* Caller must provide SKB that is memset cleared */
> > -static void __build_skb_around(struct sk_buff *skb, void *data,
> > -			       unsigned int frag_size)
> > +static inline void __finalize_skb_around(struct sk_buff *skb, void *data,
> > +					 unsigned int size)
> >  {
> >  	struct skb_shared_info *shinfo;
> > -	unsigned int size = frag_size ? : ksize(data);
> >  
> >  	size -= SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
> >  
> > @@ -296,15 +294,71 @@ static void __build_skb_around(struct sk_buff *skb, void *data,
> >  	skb_set_kcov_handle(skb, kcov_common_handle());
> >  }
> >  
> > +static inline void *__slab_build_skb(struct sk_buff *skb, void *data,
> > +				     unsigned int *size)
> > +{
> > +	void *resized;
> > +
> > +	/* Must find the allocation size (and grow it to match). */
> > +	*size = ksize(data);
> > +	/* krealloc() will immediately return "data" when
> > +	 * "ksize(data)" is requested: it is the existing upper
> > +	 * bounds. As a result, GFP_ATOMIC will be ignored. Note
> > +	 * that this "new" pointer needs to be passed back to the
> > +	 * caller for use so the __alloc_size hinting will be
> > +	 * tracked correctly.
> > +	 */
> > +	resized = krealloc(data, *size, GFP_ATOMIC);
> 
> Hmm, I just realized, this trick will probably break the new kmalloc size
> tracking from Feng Tang (CC'd)? We need to make krealloc() update the stored
> size, right? And even worse if slab_debug redzoning is enabled and after
> commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
> kmalloc space than requested") where the lack of update will result in
> redzone check failures.

I think it's still safe, as currently we skip the kmalloc redzone check
by calling skip_orig_size_check() inside __ksize(). But as we have plan
to remove this skip_orig_size_check() after all ksize() usage has been
sanitized, we need to cover this krealloc() case.

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y5G6RnoyZC78UO4q%40feng-clx.
