Return-Path: <kasan-dev+bncBD2KV7O4UQOBBY5W52LQMGQE7UGTLYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id E5CE6595D45
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 15:28:04 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id a16-20020a2e9810000000b00261872eb09asf1636024ljj.17
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 06:28:04 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=8LatVlAa0Lz2wyiWmVZBfHubFVDgvQMdO1xbGIOoHYU=;
        b=F6pWjdM1ia8ABrWagKxd5vitjY2SZ/3uHqXKqhx0GJeGuowbak4QvsVEAmPbw9WEsM
         P566Ogps3XgUrqu4m4ZeVtC9Ph1n68HdipySFX6h6R4n3zciy7eDjHd4df17R0uAMz8H
         Njdfj8xRxcF8+1R0SZtjFEUJ77hw24X2nDctfyv66FmWkrJHYeEG6TEn/p6oAzTrk3MY
         +8hGYPJvizbHVm5aNoVgOe7uZIYX7zqR2reBtxcHAJnEqKjw8RahojqBIECUPNucWzFm
         t2qCsr9EpkN9TG4BXUQv6vvA7HPP0dGyxa+mEDpzABECPxdibd2plYoe09bjiyEZ9BjN
         OuNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc;
        bh=8LatVlAa0Lz2wyiWmVZBfHubFVDgvQMdO1xbGIOoHYU=;
        b=V/KYpWjj2FVXD6NRQs/ZXam1CdSOltrUxOkWQfAdQkevYJ5wV/B9OHtM3vNMPZvPNl
         YawitY7pId9dBeGBwYdJjMiuqo6Ujd4QU4nPytjqHD5D/+3bzyeKqvA77N9OnJn9L7x5
         IC590L7n+mWwH2MVz+W4N9v60OJVxv6o7HOkBFrkTBaMEw8jtGUMEvOfMPXUsBgks/lo
         /ZH878lQ4j/cNV16YYEcUecjluMeGc5huxkgBvkmHUxrAdO0tFnHpmd0h3gLjcchkyOS
         DI66JysH6DeJ2HBa69x5Enxzu+utkvQfCxmJjdIqhB9xsgtZ6UBhY0mZLUJ7/nq9vsab
         fHLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo185teaSBP94n7VMW8QxsuT+TKqqs8JWERumffMR/gEt6O/qVoA
	hZO5D4Ukqls3GYoGBA+PJZw=
X-Google-Smtp-Source: AA6agR4wpLBa2hrmzObUnXzraWDBAyH9TbXkz9Wytioe3u+P/TVC54fQT3uLVtwD6owfufN9l9D7gA==
X-Received: by 2002:a05:651c:c86:b0:261:8700:2631 with SMTP id bz6-20020a05651c0c8600b0026187002631mr3549316ljb.404.1660656484104;
        Tue, 16 Aug 2022 06:28:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3217:0:b0:25d:9c9e:d165 with SMTP id y23-20020a2e3217000000b0025d9c9ed165ls2117778ljy.7.-pod-prod-gmail;
 Tue, 16 Aug 2022 06:28:01 -0700 (PDT)
X-Received: by 2002:a2e:8090:0:b0:25e:5916:ddf4 with SMTP id i16-20020a2e8090000000b0025e5916ddf4mr6084744ljg.11.1660656481154;
        Tue, 16 Aug 2022 06:28:01 -0700 (PDT)
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id i6-20020a2ea226000000b0025ebe667378si1051390ljm.6.2022.08.16.06.28.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Aug 2022 06:28:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6400,9594,10440"; a="293490522"
X-IronPort-AV: E=Sophos;i="5.93,241,1654585200"; 
   d="scan'208";a="293490522"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Aug 2022 06:27:58 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,241,1654585200"; 
   d="scan'208";a="635891397"
Received: from fmsmsx603.amr.corp.intel.com ([10.18.126.83])
  by orsmga008.jf.intel.com with ESMTP; 16 Aug 2022 06:27:57 -0700
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28; Tue, 16 Aug 2022 06:27:57 -0700
Received: from fmsmsx608.amr.corp.intel.com (10.18.126.88) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28; Tue, 16 Aug 2022 06:27:57 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx608.amr.corp.intel.com (10.18.126.88) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28 via Frontend Transport; Tue, 16 Aug 2022 06:27:57 -0700
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.168)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.28; Tue, 16 Aug 2022 06:27:56 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=HEEMUj9yxlvH/svOlPbmfPYycqNzaY2iB5oojXU+ASjH0BrSonCoJVaTk4EGAGxdQX4YH3jN+OCXNc+8WHYR23UVQt8LNHMz6uD2Y8kq7CJf6Lyu8ciBX4HocGgsQVLV3iin831lNQKH/C0bm58Y2SOvagYK+SwRD+X66FHcG75OJYHVDdypdHl9ioGXApx1ACcJTta+JZor7Tb9+/ZeARc91+qFik8eQSFvkJwPYaLroBQ7/EriIVxWTKD82NeqobYjaUBMSxl8LBe9j5Q79b0DN3EspRBI+QMmUTLOFi40IL8EuvcJKdCAxgWieOH2SlrV3ssWWQjoKv3/Q8P6Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=hCs8pYdo/eWhqA9X+SeB53K7soOBRkusStSV6ZkC5Lw=;
 b=AH1crtr/JV2OxphOkqedEOpxoA95JJj/SXPD0e1IPH1KkPNZjSoNoOKsuqvZnxYXJbET5fICsqDa/gouxFn1Gy/hkfDyMBsnI1feiD4/m+O+IKDoJoa4HuXS/1jAih5wv64eXOBLW9snNc0znC+jAisYRfpsYbCBCxNh+3KFAk1uZu/Bn09S7/9usCaQ/7fuNXsaEU1TWs8LmeHm9d98tL401CYeidjPJSJdG3o9NDt+9if7JIRV5LxX2E6atCLyW/gr8GioAk9cI/QeO7KZ65mroCBJ4u+1ONAG3nksnLE6dZuFwOrP61CS0CULd5RamkRXNbbg/Qtd0CasJ7UmeA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from SJ1PR11MB6297.namprd11.prod.outlook.com (2603:10b6:a03:458::8)
 by DM6PR11MB2716.namprd11.prod.outlook.com (2603:10b6:5:c7::26) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5504.14; Tue, 16 Aug
 2022 13:27:54 +0000
Received: from SJ1PR11MB6297.namprd11.prod.outlook.com
 ([fe80::f906:b045:d73e:8e49]) by SJ1PR11MB6297.namprd11.prod.outlook.com
 ([fe80::f906:b045:d73e:8e49%9]) with mapi id 15.20.5525.010; Tue, 16 Aug 2022
 13:27:54 +0000
Date: Tue, 16 Aug 2022 21:27:39 +0800
From: Oliver Sang <oliver.sang@intel.com>
To: Feng Tang <feng.tang@intel.com>
CC: Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, lkp
	<lkp@intel.com>, LKML <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org"
	<linux-mm@kvack.org>, "lkp@lists.01.org" <lkp@lists.01.org>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>,
	Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, "Alexander
 Potapenko" <glider@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [mm/slub] 3616799128:
 BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
Message-ID: <YvubS48W0dE7uA4E@xsang-OptiPlex-9020>
References: <YujKCxu2lJJFm73P@feng-skl>
 <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
 <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz>
 <CACT4Y+asjzrBu8ogRDt9hYYaAB3tZ2pK5HBkzkuMp106vQwKWQ@mail.gmail.com>
 <YukoZEm4Q6CSEKKj@feng-skl>
 <CACT4Y+Y6M5MqSGC0MERFqkxgKYK+LrMYvW5xPH5kUA2mFh5_Xw@mail.gmail.com>
 <YutnCD5dPie/yoIk@feng-clx>
 <CACT4Y+Zzzj7+LwUwyMoBketXFBHRksnx148B1aLATZ48AU9o3w@mail.gmail.com>
 <Yuu6B0vUuXvtEG8b@feng-clx>
 <Yvn1b8y20Mr0gfUQ@feng-clx>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yvn1b8y20Mr0gfUQ@feng-clx>
X-ClientProxiedBy: SG2PR04CA0191.apcprd04.prod.outlook.com
 (2603:1096:4:14::29) To SJ1PR11MB6297.namprd11.prod.outlook.com
 (2603:10b6:a03:458::8)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: d48c2c7a-678d-4d50-539a-08da7f8b2002
X-MS-TrafficTypeDiagnostic: DM6PR11MB2716:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: h48j3x0jfO4DwzJag1zSiCVS4X+tNxyPYSNzj6+2WhDyjiNXzTqc11AHz2LCJ/geWvCCnLV73DXOkiPaG4KT8S9O04pfG0Zk7Nw/2TsWG2iXFspfe9fjL0m9GnG7IEVpa+WaVrFRQCIVlttlepzRZ6ZxKRGFns5iZrgl697kqla/4Nrpy5WiqyMqtaN4fRsJHz+IScFtN4v50JamPKxb4F+z5ImREG19D4N+Xp5WClBYrwuaJGVIbKDi5WE3pvEvf0ksirmd72PhMEuSB6ftqkz5uLdFjrIFfC0k1uCR9GqXh/zQA8nXJW9xvn//spNKL/ShUgufzkALJY/q02KEC2XacdcagDl0jEihAJp+wqvB/cwMnEAmzo/c+k8KnXbOX5VppSJmunitjSsE86FMVyCK3bMUMwKimWaePaVMDQlzAltYVQ3WFkjyI/Cy39FWBpyQWLva1+UD541Bc0vn/VfoeoBN1vppfiC6+o6UpCS4bzwbq1dtMEgzIOyuVJG5DT+5GAMcYwDkRwOG1hxbPvrVI1fpzvGMMQwjT4xpxLpQIUJFaAOZjCEw3FFYwltgainHvDDSmJvotuBvlXKq0TzA+kt6aIDnF0uoOG7B/J1dTNgnXZgy8WIm8dXjN6DgoKwWABRrv3mKUOBMS5Kw+Bns4wAeR1J4gWodYs9i0yxRVyzTbI9Iqao1juYpkW0iD2bL1KZWfvc2zhDxMPR7o8Qfl7aUu3KIoqWyPEp1HFqk/afaUTejghS3PLZY3M9Kf43D7raKvaGx4I2MKNc8qQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SJ1PR11MB6297.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(396003)(136003)(366004)(346002)(39860400002)(376002)(8676002)(4326008)(66556008)(316002)(54906003)(66476007)(6636002)(33716001)(5660300002)(6862004)(7416002)(2906002)(8936002)(44832011)(82960400001)(66946007)(38100700002)(86362001)(186003)(6506007)(6666004)(41300700001)(478600001)(966005)(6486002)(26005)(6512007)(9686003)(83380400001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?k+W4Rx/hcpgOkk5ndvRPUPf/OiYap1ry3O39wBrwbN2/KtUJ/LEh3fcd0D45?=
 =?us-ascii?Q?xl3+6LiOe5u8b6oGtmuaAyGRKB3rxrQUjPkw592m7tQ8ot/0/0Cq/bpFOITc?=
 =?us-ascii?Q?rUtitcsqCvIrev6TYnGVFU/A04Oc7JhNMA1in85v3cjI7IrOiFjufRVzEsxw?=
 =?us-ascii?Q?6G5JLwtyri06dVvVkz0sGWcejXZMGqiNbs9qbbID/71ypXimSRBPb0jUCnO4?=
 =?us-ascii?Q?Oh9Foc+diT4++ABaexmoHDwOEeClABv4fZRkOH6QufKhUvJtWee0SVRF5o//?=
 =?us-ascii?Q?3/wBfOHOB1rVkMlt/JX30nRO7zLyA79FDBKRiyep4GsN4zmYStI5LbyQu0XM?=
 =?us-ascii?Q?yIUWSq8YCyHmG8prr3v6COGFEQrJQKvKpp5jG4xGvvlLAiw6sZwLPX4f9eSO?=
 =?us-ascii?Q?bFd60cdb5zIKCd2q01wn6r2fFR8vDOFJG3oou87KR0pxHqmCC6+8qfFpSLxu?=
 =?us-ascii?Q?XdTdoQ+bs5L804MmdVzlLf3wZ7vggUQE+zjAaI/2jfRMIJd/FN+bC/0RF85v?=
 =?us-ascii?Q?J+qt+UcAfcS1bjvYOHO6WgYAoUv3Muvr3Zu0tG3zz8/RJBxH8U1sVtMH0bDp?=
 =?us-ascii?Q?sz68wrmlCkprRAO49cMA0YnpHVJxNIUFhyHyAE4kqgWX4eXj8s+ZX6pAI1FT?=
 =?us-ascii?Q?+Q7VrF1AYOxHHikD/Rdc/iIdHWE01hswpWTKAOVPXDpKcniamzSbbYCSfNlv?=
 =?us-ascii?Q?xB+cA1E/vW9StIMKgcyyNvZJm9UZ5v2X29nJK4AFM1uY4+bm7asI6rocN6Un?=
 =?us-ascii?Q?j6lKe6hDXd8gvMYotd9MRpIFFWLg3ftBtaNMV3VYFE+HKHKKyorIEeEaqIcm?=
 =?us-ascii?Q?8UJZp8CtqDABSSPnJnuojEqxM+t8q8LAbseDrXuAv23NCcuvUwV9lEbpDYdr?=
 =?us-ascii?Q?3V/CACGmT/M4UuJthT0rbgmAHJEOhBuvtC84wjROSfOHTzF4JnJ0YAEAmqJd?=
 =?us-ascii?Q?qd888XAr1DQoN7D2SxJZIiwuYovXyYAixGoT/mrr3iSKHtzy5ToI12Y6W74A?=
 =?us-ascii?Q?1LxeXu46Dv92iYzsIk5A+RrCp+k4ZwbtLG6hNRzk+pqvx2k+K3HLgFfO/TpW?=
 =?us-ascii?Q?yfT1hjwqFZSDwDfUdlM0vXFC6g9uegRroa7svoM8nud6XTH5aVsqcBAGAMhV?=
 =?us-ascii?Q?FPrENUy2qq+nhzncEbSD+jeGOZKL5bx2RTaDcXgeScQMv2fWaqUe6Ur+5eWT?=
 =?us-ascii?Q?S6vocIvHYyPThJOgjkbEUU7Z5PLLESC9fQ1IkqXHjoUcCGernlg6sIOv/6dj?=
 =?us-ascii?Q?NafUGuzwEcozJS5V/lJYrMC76l95j1/JEraGfQp5yQL/o9Z7CqSQs3QZAcgt?=
 =?us-ascii?Q?UR/SwsX45iUw1lXFjmxYOpREsw8mn8IehWNd7Y9KJL1JPIKdaOmlcNwkdh9D?=
 =?us-ascii?Q?T4PTxyQRXR4ugQYOdBJ9ly39RiLFKKq7IhZZiN6gzzVXCUzqBEqh4YbX/vXd?=
 =?us-ascii?Q?vlSo2p1yaKwIATUBKL0hvwlaKlcOoPm0aQF3QZ+pqSVeYJgR+30GxhTIPtr6?=
 =?us-ascii?Q?8MzHuy5hU8ASurQJNZFlW/v0cciQDtDo7BgvjK/SOM5WTHUZ+iO4tEBuM9CO?=
 =?us-ascii?Q?1c587EwR/KawmppPuDOv1lEaYSSVfwqFRVEoz5Z7ORs110eonSh1hEF3PzNj?=
 =?us-ascii?Q?Mw=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: d48c2c7a-678d-4d50-539a-08da7f8b2002
X-MS-Exchange-CrossTenant-AuthSource: SJ1PR11MB6297.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Aug 2022 13:27:54.4457
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: A1ua8xa0C+voX+SF1hvTrN9mcxAWt6Hf45g2UVxAh6pLvH0yAL4oEGFr1920KmrhjexUDjpnKwpUZW+BBTk1sQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR11MB2716
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NTiO5n8i;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 134.134.136.65 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
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

Hi Feng,

On Mon, Aug 15, 2022 at 03:27:43PM +0800, Feng Tang wrote:
> Hi Oliver,
> 
> Could you help to check if the below combined patch fix the problem
> you reported? thanks!

I applied below patch upon 3616799128:
28b34693c816e9 (linux-devel/fixup-3616799128) fix for 3616799128: BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
3616799128612e (linux-review/Feng-Tang/mm-slub-some-debug-enhancements/20220727-151318) mm/slub: extend redzone check to cover extra allocated kmalloc space than requested
acc77d62f91ccc mm/slub: only zero the requested size of buffer for kzalloc


confirmed the issue gone:

=========================================================================================
compiler/kconfig/rootfs/sleep/tbox_group/testcase:
  gcc-11/x86_64-randconfig-a005-20220117/debian-11.1-x86_64-20220510.cgz/300/vm-snb/boot


acc77d62f91ccca2 3616799128612e04ed919579e2c 28b34693c816e9fcbe42bdd341e
---------------- --------------------------- ---------------------------
       fail:runs  %reproduction    fail:runs  %reproduction    fail:runs
           |             |             |             |             |
           :20          95%          19:20           0%            :22    dmesg.BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
           :20          95%          19:20           0%            :22    dmesg.BUG_kmalloc-#(Tainted:G_B):kmalloc_Redzone_overwritten



> 
> - Feng
> 
> ---
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b092277bf48d6..293bdaa0ba09c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
>  struct kasan_cache {
>  	int alloc_meta_offset;
>  	int free_meta_offset;
> +	/* size of free_meta data saved in object's data area */
> +	int free_meta_size_in_object;
>  	bool is_kmalloc;
>  };
>  
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f1..9d2994dbe4e7a 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -200,6 +200,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
>  			*size = ok_size;
>  		}
> +	} else {
> +		cache->kasan_info.free_meta_size_in_object = sizeof(struct kasan_free_meta);
>  	}
>  
>  	/* Calculate size with optimal redzone. */
> diff --git a/mm/slub.c b/mm/slub.c
> index added2653bb03..272dcdbaaa03b 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
>  	if (!slub_debug_orig_size(s))
>  		return;
>  
> +#ifdef CONFIG_KASAN_GENERIC
> +	/*
> +	 * kasn could save its free meta data in the start part of object
> +	 * area, so skip the redzone check if kasan's meta data size is
> +	 * bigger enough to possibly overlap with kmalloc redzone
> +	 */
> +	if (s->kasan_info.free_meta_size_in_object * 2 > s->object_size)
> +		orig_size = s->object_size;
> +#endif
> +
>  	p += get_info_end(s);
>  	p += sizeof(struct track) * 2;
>  
> On Thu, Aug 04, 2022 at 08:22:31PM +0800, Tang, Feng wrote:
> > On Thu, Aug 04, 2022 at 06:47:58PM +0800, Dmitry Vyukov wrote:
> > >  On Thu, 4 Aug 2022 at 08:29, Feng Tang <feng.tang@intel.com> wrote:
> > [...]
> > > >
> > > > ---8<---
> > > > From c4fc739ea4d5222f0aba4b42b59668d64a010082 Mon Sep 17 00:00:00 2001
> > > > From: Feng Tang <feng.tang@intel.com>
> > > > Date: Thu, 4 Aug 2022 13:25:35 +0800
> > > > Subject: [PATCH] mm: kasan: Add free_meta size info in struct kasan_cache
> > > >
> > > > When kasan is enabled for slab/slub, it may save kasan' free_meta
> > > > data in the former part of slab object data area in slab object
> > > > free path, which works fine.
> > > >
> > > > There is ongoing effort to extend slub's debug function which will
> > > > redzone the latter part of kmalloc object area, and when both of
> > > > the debug are enabled, there is possible conflict, especially when
> > > > the kmalloc object has small size, as caught by 0Day bot [1]
> > > >
> > > > For better information for slab/slub, add free_meta's data size
> > > > info 'kasan_cache', so that its users can take right action to
> > > > avoid data conflict.
> > > >
> > > > [1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
> > > > Reported-by: kernel test robot <oliver.sang@intel.com>
> > > > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > > 
> > > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> >  
> > Thanks for your suggestion and review!
> > 
> > > I assume there will be a second patch that uses
> > > free_meta_size_in_object  in slub debug code.
> >  
> > Yes, it will be called in the slub kmalloc object redzone debug code.
> > 
> > Thanks,
> > Feng
> > 
> > > > ---
> > > >  include/linux/kasan.h | 2 ++
> > > >  mm/kasan/common.c     | 2 ++
> > > >  2 files changed, 4 insertions(+)
> > > >
> > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > index b092277bf48d..293bdaa0ba09 100644
> > > > --- a/include/linux/kasan.h
> > > > +++ b/include/linux/kasan.h
> > > > @@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
> > > >  struct kasan_cache {
> > > >         int alloc_meta_offset;
> > > >         int free_meta_offset;
> > > > +       /* size of free_meta data saved in object's data area */
> > > > +       int free_meta_size_in_object;
> > > >         bool is_kmalloc;
> > > >  };
> > > >
> > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > > index 78be2beb7453..a627efa267d1 100644
> > > > --- a/mm/kasan/common.c
> > > > +++ b/mm/kasan/common.c
> > > > @@ -201,6 +201,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
> > > >                         cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
> > > >                         *size = ok_size;
> > > >                 }
> > > > +       } else {
> > > > +               cache->kasan_info.free_meta_size_in_object = sizeof(struct kasan_free_meta);
> > > >         }
> > > >
> > > >         /* Calculate size with optimal redzone. */
> > > > --
> > > > 2.27.0
> > > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YvubS48W0dE7uA4E%40xsang-OptiPlex-9020.
