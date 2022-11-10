Return-Path: <kasan-dev+bncBDN7L7O25EIBBGPMWONQMGQEBNVFMTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B53246242BA
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 14:01:13 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id c5-20020a1c3505000000b003c56da8e894sf2653834wma.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 05:01:13 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8MaXp8skDi5ZqaDK6nGcrPEjXk/THXIBEhdnl5f5D/4=;
        b=LYWcVGSYjWJPYRnSCmOKVTTBW46iCqOMx3rQPB4AhuudBh/0hdx9WQCH7TLx2uKnrM
         ngZXbp6Es7iFL+TmzmoC25GnSHAD6XpUOCP2+WlSe5HogVA2FIRxhQ/zKGpEjLQgKgXS
         +vetD+nQjICcL8ILLMyEflfYhS/gaZ7x9rxSiGI/J80QDZsORf9Kk09eqN9/lpdPU3IL
         pEgM732ADxj1TLoip8SrQ72/7Sg+iLYWKBYDZpQRM3KP4av54+wVxnjg1NbCzCagl2rX
         9n2tA2wtM/Uib08emjNu693sYbX8WashqLsXKPADe8jHczKc5F0Iak2xXbtNKDhREYi/
         lrgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8MaXp8skDi5ZqaDK6nGcrPEjXk/THXIBEhdnl5f5D/4=;
        b=wZjlb7Z5tfqMIAsE3RqiTwGiKC+xz5jk1MVnQaIP95sEN2mA7uFqH8VduP8Hen764Z
         MLzd6wjR79vOPoeh+Pq5XG6XPlG3/ehA8e1NrXNvhrPknfrJuAxRo0HeLxsvIZLsuQv+
         zH4GFS7beZ1C8yywAxpMvUUoAjJdYHBkMyX54v2SGsoeKuhnZfCWnPuIfBqhuKUSE7ie
         yc7baL8xPoCCRqM4Pza2+3KpvwOQL7/lWMcrj11Ml+/xLCKdgV3w14jkjQzp3NvHYWTt
         1cOnt9eNlrxcXOQrn0n+ykrzaf6XxHOiE3t8SvOTdnW9qEIHnWtXLgACVf+3ka9i38uG
         q1ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2IXGBbZ1omZzi78R7fxAv2qm93KJkfEyCC5xgFjP6ij72N6AUf
	9ZonAqBTj6CqVtg/y/CxMRo=
X-Google-Smtp-Source: AMsMyM6dBRYvS4SPsaP1Vzh1/+TGAdHxpesr57QPcIj3NLPyA0yU89pjjI5B/rwH4FuZGM1Y5v2Qpw==
X-Received: by 2002:a05:600c:4b27:b0:3cf:67ab:3ac6 with SMTP id i39-20020a05600c4b2700b003cf67ab3ac6mr42272757wmp.35.1668085273273;
        Thu, 10 Nov 2022 05:01:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce96:0:b0:3cd:d7d0:14b6 with SMTP id q22-20020a7bce96000000b003cdd7d014b6ls930784wmj.1.-pod-control-gmail;
 Thu, 10 Nov 2022 05:01:12 -0800 (PST)
X-Received: by 2002:a1c:7517:0:b0:3cf:9c1a:2fd0 with SMTP id o23-20020a1c7517000000b003cf9c1a2fd0mr826113wmc.3.1668085272123;
        Thu, 10 Nov 2022 05:01:12 -0800 (PST)
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id ay26-20020a5d6f1a000000b0024165c0a706si13330wrb.1.2022.11.10.05.01.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Nov 2022 05:01:12 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10526"; a="375546836"
X-IronPort-AV: E=Sophos;i="5.96,153,1665471600"; 
   d="scan'208";a="375546836"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Nov 2022 05:00:45 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10526"; a="882346356"
X-IronPort-AV: E=Sophos;i="5.96,153,1665471600"; 
   d="scan'208";a="882346356"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by fmsmga006.fm.intel.com with ESMTP; 10 Nov 2022 05:00:45 -0800
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 10 Nov 2022 05:00:44 -0800
Received: from fmsedg601.ED.cps.intel.com (10.1.192.135) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 10 Nov 2022 05:00:44 -0800
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (104.47.56.49) by
 edgegateway.intel.com (192.55.55.70) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 10 Nov 2022 05:00:43 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=faoGe6Rmy8Po/yT9gwfMMLXk7J6BuLidDWKyJEssWeFnAnG4HoO7TYnYYR+yp1AN2KVrYGzMiO30x0+zywGBkRMQOnE+rA6hAWMRc7InwcELBOE6P+zwYxh7J9LXHftixbFxdsWGkyqUnlt9YJD4iNfWpwNW7jRenhOT3a4xlMMZgQ7XCLTVKUhXHn0aWBnv+Mfe/HNWY+LzBnzYMPP7wSX7HtiYTWgiwEnl4YddyCkLaNIoqWuRaFgz2Z2877JAoYuggKLpw/PcxXurWM5xU354kzrD/iZdKfOIj1SMmAR6gD/FnVBpAgBBY3sB1L7EAqCAfgjTT66dQBWdeYG7Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=I4ZT4R6g2ZJKfU2lRiFC+nrXXf+MXzqfgzE0MA3wJq8=;
 b=dtYEUsU8GBO3eJI4JYm3JH7lbihZG+VWns05o01z/Gq+TwiySehfq8ZHGmHWbj35CVL/jRPugIz2CuQR25CbAkDd1Jhm75+w25tLz69IMt4epvwnGZD+6ZQdTGpoyGJVD2hCP2NC48YLvlGNyNpq1R6IY3Ep0LaC4AsMT505aMDSj8qLzZsdgdM8YhDgQo7SB3DPiHREPtgy7W45UWe+DJOJ22UtV/Iup/MY/nW+fusCzRxIURYkL9zbx5+t2tDRwFMIPSVwdQ6GagSm1rFd4LPDNXTO9adFrS8mQpbvJzQAMy0quzXIIyUx6WGGeZjUcms9iyLIspT8a8UAWtia8g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by IA1PR11MB6324.namprd11.prod.outlook.com (2603:10b6:208:388::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5791.27; Thu, 10 Nov
 2022 13:00:38 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b%3]) with mapi id 15.20.5791.027; Thu, 10 Nov 2022
 13:00:38 +0000
Date: Thu, 10 Nov 2022 20:57:23 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter
	<cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, "Kees
 Cook" <keescook@chromium.org>, "Hansen, Dave" <dave.hansen@intel.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH v7 1/3] mm/slub: only zero requested size of buffer for
 kzalloc when debug enabled
Message-ID: <Y2z1M4zc2Re5Fsdl@feng-clx>
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <20221021032405.1825078-2-feng.tang@intel.com>
 <09074855-f0ee-8e4f-a190-4fad583953c3@suse.cz>
 <Y2xuAiZD9IEMwkSh@feng-clx>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y2xuAiZD9IEMwkSh@feng-clx>
X-ClientProxiedBy: SG2PR02CA0090.apcprd02.prod.outlook.com
 (2603:1096:4:90::30) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|IA1PR11MB6324:EE_
X-MS-Office365-Filtering-Correlation-Id: e0271127-6c89-4a12-65a8-08dac31b90a7
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: +WQgYw2GbupPzwMo3c+MYJtVeLIfVZ3G8qjUAWlafI+f8UhQNKaPmxzw9pYEGf5D9XiYmGTjW5b5eSTT+sCPE3abyK/8Y+8Ktfsycfk0QfwIVTNIwtw0Jx2OdapRdfznSJEtjXapGrV9/GJMO/rhJtiI8g9qMF1yTMQoNGuBYHaXLqVhzQAy3NmiqtV2tb6bSLF3Gw0gjzJ034SapeWiYd1qyJnXXH3MsD0bptjl7NTadxRaSUmgba6viODQoUskagKSLI1j7luGiQv4xEOQZ/leTSfMjtDh5ib8X/U7/W26fumNGLL8wHo42duPeQNI2ew0bwCLvuNjAWDozaUZXdJ0yQuyVqAAbheffvoYW8Ozd5e+PpQLnyKv0kmCUIc6ivQrPvSrxZku4XbrmC7w0Vge66WhEclQ10Wy+Z4EqKh5RwnKz/paa6I8kNRD5gA23DF3Z2aw5N5Tct52rhtXmgimmn4ItldjwEhLdSj1a3qXRN0Co8JCfOm/Jyy6G+ZpwCB3UWmtI9kMR/AGDhrUljFWNWtSX/cb8tG4AsBltox3WkoZumBijfufbo12r7PxnYX5Fd8CuQ0OT7MlSM9jCrTuKr8do74WQRp9aJ5t55F1ee9XgSkQ3QORSDW/btmhqAbjHJAGzRwXRqkPHWigzzt+6bR9W2xnzBPQdAGkP168Xa5Aq9puQrGHJYAebBINKMog+jyY71qeG3AbhtPbpd2JuKN7a1N9n+DoRgGvkmUa4MlXyUjCMSKxhJf8kEKD1ENPbrL6RyBRTf0KUmp0rg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(136003)(376002)(396003)(346002)(39860400002)(366004)(451199015)(6486002)(966005)(478600001)(6666004)(54906003)(6916009)(33716001)(5660300002)(6506007)(316002)(26005)(66556008)(66946007)(4326008)(38100700002)(82960400001)(66476007)(8676002)(53546011)(7416002)(9686003)(186003)(86362001)(41300700001)(8936002)(6512007)(44832011)(2906002)(83380400001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?YGfyzronEWuA+Wtk+kd6mixXg5T0ckCbTivo2ZCF+15u3BWbjIo17w6cXe01?=
 =?us-ascii?Q?f71RdNoVRswB1bNZq+KkfQNcKEt9olE0Wjrk8J4k3Q4o3C5dmpsnneqGdSvy?=
 =?us-ascii?Q?KUQKEKtDzfCjypltPZ/XpeZbueEhPuzGa2UfhT0wLUK6ivCe6ZgvLk4qjU8M?=
 =?us-ascii?Q?q4TAN+9Hid+ObmQPVoo2IaLlC5pSqAQ4WexaaH04KpKqXc0qFmQHy8GW8cKF?=
 =?us-ascii?Q?/m3Se64mO74Biim+01gt+sbBUtYr2ptnmtNWFP1Ap01zhO9UTrtJMfx2cJiJ?=
 =?us-ascii?Q?ZgkqQQGRWEFzjrkmhDiqHnCDMJp5Qf7FTp1ncHP9cZekP047qKb6yqHx2Xfy?=
 =?us-ascii?Q?eDda635aiQkbp5NsuuEOPQTdzgkPc3YtjYK9kt66bW07km5C8RGWOaq1yCEY?=
 =?us-ascii?Q?jsafk8sqFV2YFmGb4t8L88FIrrRBZvTn8oYAMD01SRhWWieKr3GSg3PVlzE0?=
 =?us-ascii?Q?IQr5Mo13kS/JpIBbJXeVBdLIrivNC5Q2uLf7LMC5efRNGzaBbAUZg3tO2A6c?=
 =?us-ascii?Q?32tc0hZrxa3f+JrFby4Bk5f8TRIEDLh5prEx3j/P4Um7muKOzhFIw7tNt2Di?=
 =?us-ascii?Q?+LHn2LrLYbr21furmSYJjSv82zIGwjbAOfFAmAu7zXAP7M36MbaMcRLYRU/a?=
 =?us-ascii?Q?K19CHvYxZWPv9Nv2Kxrns6zX7z7xgpYp4EGQZgBRD3folBxYHOd+5roVGEDH?=
 =?us-ascii?Q?lqy3/SumUZRYzsa8XZEi16l7SRXzwuiDRY9W/jCnKmkWH3V4+NJ4rShT9C0w?=
 =?us-ascii?Q?69Wes7hitStcNvZYXxaxXh2M6b6TS7JF5ezruNshn0FVo3hSvRDMQ541KCzo?=
 =?us-ascii?Q?Ldg6CRmoqvNInSz1NE6so0MCyUd8wiXcnPu7szERgg8Q110IVn4Esc/kI1jU?=
 =?us-ascii?Q?3NOdcwWLDwkj6ZNOSnTKYIP0eqD464+sH4cWR0QVG5ME82KTKnwlfqquX8zI?=
 =?us-ascii?Q?QFujmvD2ViOsZNnqzNlq1p6e4ftGQHDsRSJi0dnpwg+z9XZmvpjeOdLVqgKP?=
 =?us-ascii?Q?mKMXYw25vXMYMTeFhVhy9NHBxDuMIt1ANA43AsOpyMXFBP/6LfGSI2N4xKHw?=
 =?us-ascii?Q?yqpKNB5oHCmbZgt17bs8a7/BLYKLBZ/0Ee48eUbkvVMCj4q/1CAHZB29zEJ6?=
 =?us-ascii?Q?WAtlQQojhPQ0V1VPjO1iCrfIxBkKnQgG2HXCanHhHRc7vFZ507ddj0vKdjEU?=
 =?us-ascii?Q?xCnKA05XTU2lzEPforb2P3ZB5xwnz+uETrEQOrpC+v6j5vn8v8/5nlf38PB/?=
 =?us-ascii?Q?B3Sfe+Qj57ugZvAZeBoSAtis6G0kcRFiP5wPyvVUvO1KCwBht2i/qvDADZoY?=
 =?us-ascii?Q?7PyPDxrNKioOg2Mz0u9yDH6PrQ2HeVThJwLrzXnu1A9VqVEM3SA0dgDmAF+u?=
 =?us-ascii?Q?mhISER1tfMDgh0wCkaOkIaXhBTKABzI0JEcUQTa7eIyQKBvRUWFzPm5dUw3e?=
 =?us-ascii?Q?G/c5vP8/HTl6mpSgXjnkUqAhNbGdfSXXfKHcCVMz4VVSjmp7yQUJDHxAsp79?=
 =?us-ascii?Q?lujxsRFAcrJrRJZFjbFKhbJaZTPkbnNVR1d0KDal+SD/NVHxEg7cMGyOLBxz?=
 =?us-ascii?Q?PS/OFuGkvRJd6dvr1UTOyuKQVBZTvPuqfj/LBvb6?=
X-MS-Exchange-CrossTenant-Network-Message-Id: e0271127-6c89-4a12-65a8-08dac31b90a7
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Nov 2022 13:00:38.7268
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8L6/duzjLYNsZWgtPtwD1qcTmIcg0xxc/U+zUmF60ZPIxVT9YrDXii7dzYqii2PYKE0q9ntkkq64p1NtvvWR9Q==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB6324
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=LdsrT0hp;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Thu, Nov 10, 2022 at 11:20:34AM +0800, Tang, Feng wrote:
> On Wed, Nov 09, 2022 at 03:28:19PM +0100, Vlastimil Babka wrote:
[...]
> > > +	/*
> > > +	 * For kmalloc object, the allocated memory size(object_size) is likely
> > > +	 * larger than the requested size(orig_size). If redzone check is
> > > +	 * enabled for the extra space, don't zero it, as it will be redzoned
> > > +	 * soon. The redzone operation for this extra space could be seen as a
> > > +	 * replacement of current poisoning under certain debug option, and
> > > +	 * won't break other sanity checks.
> > > +	 */
> > > +	if (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
> > 
> > Shouldn't we check SLAB_RED_ZONE instead? Otherwise a debugging could be
> > specified so that SLAB_RED_ZONE is set but SLAB_STORE_USER?
> 
> Thanks for the catch!
> 
> I will add check for SLAB_RED_ZONE. The SLAB_STORE_USER is for
> checking whether 'orig_size' field exists. In earlier discussion,
> we make 'orig_size' depend on STORE_USER, https://lore.kernel.org/lkml/1b0fa66c-f855-1c00-e024-b2b823b18678@suse.cz/ 

Below is the updated patch, please review, thanks! 

- Feng

-----8>----
From b2a92f0c2518ef80fcda340f1ad37b418ee32d85 Mon Sep 17 00:00:00 2001
From: Feng Tang <feng.tang@intel.com>
Date: Thu, 20 Oct 2022 20:47:31 +0800
Subject: [PATCH 1/3] mm/slub: only zero requested size of buffer for kzalloc
 when debug enabled

kzalloc/kmalloc will round up the request size to a fixed size
(mostly power of 2), so the allocated memory could be more than
requested. Currently kzalloc family APIs will zero all the
allocated memory.

To detect out-of-bound usage of the extra allocated memory, only
zero the requested part, so that redzone sanity check could be
added to the extra space later.

For kzalloc users who will call ksize() later and utilize this
extra space, please be aware that the space is not zeroed any
more when debug is enabled. (Thanks to Kees Cook's effort to
sanitize all ksize() user cases [1], this won't be a big issue).

[1]. https://lore.kernel.org/all/20220922031013.2150682-1-keescook@chromium.org/#r
Signed-off-by: Feng Tang <feng.tang@intel.com>
Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
---
 mm/slab.c |  7 ++++---
 mm/slab.h | 19 +++++++++++++++++--
 mm/slub.c | 10 +++++++---
 3 files changed, 28 insertions(+), 8 deletions(-)

diff --git a/mm/slab.c b/mm/slab.c
index 4b265174b6d5..1eddec4a50e4 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3258,7 +3258,8 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
 	init = slab_want_init_on_alloc(flags, cachep);
 
 out:
-	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
+	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init,
+				cachep->object_size);
 	return objp;
 }
 
@@ -3511,13 +3512,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 * Done outside of the IRQ disabled section.
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
-				slab_want_init_on_alloc(flags, s));
+			slab_want_init_on_alloc(flags, s), s->object_size);
 	/* FIXME: Trace call missing. Christoph would like a bulk variant */
 	return size;
 error:
 	local_irq_enable();
 	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
diff --git a/mm/slab.h b/mm/slab.h
index 8c4aafb00bd6..2551214392c7 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -730,12 +730,27 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
 
 static inline void slab_post_alloc_hook(struct kmem_cache *s,
 					struct obj_cgroup *objcg, gfp_t flags,
-					size_t size, void **p, bool init)
+					size_t size, void **p, bool init,
+					unsigned int orig_size)
 {
+	unsigned int zero_size = s->object_size;
 	size_t i;
 
 	flags &= gfp_allowed_mask;
 
+	/*
+	 * For kmalloc object, the allocated memory size(object_size) is likely
+	 * larger than the requested size(orig_size). If redzone check is
+	 * enabled for the extra space, don't zero it, as it will be redzoned
+	 * soon. The redzone operation for this extra space could be seen as a
+	 * replacement of current poisoning under certain debug option, and
+	 * won't break other sanity checks.
+	 */
+	if (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
+	    (s->flags & SLAB_RED_ZONE) &&
+	    (s->flags & SLAB_KMALLOC))
+		zero_size = orig_size;
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_alloc and initialization memset must be
@@ -746,7 +761,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 	for (i = 0; i < size; i++) {
 		p[i] = kasan_slab_alloc(s, p[i], flags, init);
 		if (p[i] && init && !kasan_has_integrated_init())
-			memset(p[i], 0, s->object_size);
+			memset(p[i], 0, zero_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
 		kmsan_slab_alloc(s, p[i], flags);
diff --git a/mm/slub.c b/mm/slub.c
index 0a14e7bc278c..13490f317f5f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3387,7 +3387,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
 	init = slab_want_init_on_alloc(gfpflags, s);
 
 out:
-	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
+	/*
+	 * When init equals 'true', like for kzalloc() family, only
+	 * @orig_size bytes might be zeroed instead of s->object_size
+	 */
+	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init, orig_size);
 
 	return object;
 }
@@ -3844,11 +3848,11 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
 	 * Done outside of the IRQ disabled fastpath loop.
 	 */
 	slab_post_alloc_hook(s, objcg, flags, size, p,
-				slab_want_init_on_alloc(flags, s));
+			slab_want_init_on_alloc(flags, s), s->object_size);
 	return i;
 error:
 	slub_put_cpu_ptr(s->cpu_slab);
-	slab_post_alloc_hook(s, objcg, flags, i, p, false);
+	slab_post_alloc_hook(s, objcg, flags, i, p, false, s->object_size);
 	kmem_cache_free_bulk(s, i, p);
 	return 0;
 }
-- 
2.34.1



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2z1M4zc2Re5Fsdl%40feng-clx.
