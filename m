Return-Path: <kasan-dev+bncBDZYPUPHYEJBBLVG4CPAMGQES2QRUNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AD2B06819BB
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 19:57:50 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id k34-20020a05600c1ca200b003db30c3ed63sf7650052wms.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 10:57:50 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i/SGPOWoLwyb2s+8zX3mTlS/dwuhkohdKYTPN/AHYUI=;
        b=Lo1JzAzGUpYCI8FaDh3wmMOAFIj0u7w6rZbcwCY9emrJ9TKkW1KKq8OnMtI1z/lwhA
         MjAwDq39It3nz+bnDO0Fq80sMPvbgZZKlPyxK7F296Pps2qA7Z0dZpguWGqM4Vh6XA2Z
         Uoia3xpYmHaKcjcuVvgTqtSK2Pbs68K5jMoffZA61oSm9tK0Wj+vRVKQVX86a3GLShGP
         p4TL+zfZTslqRjsGpg2DM+PDDFaZlLaYO/yfGjlt9bM06nbBpcbRVqr66rgWrdFDrhJ6
         lM460BzeG7GKbnX5yynBtZKiGG+qb9woXoU0oHblsvrrcG1Ow64k7nIgs/7k6bkQLght
         tWpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i/SGPOWoLwyb2s+8zX3mTlS/dwuhkohdKYTPN/AHYUI=;
        b=Gv1qliwyZs6i8IvjL15fuisTL7hfKvwWLWT36UdxG7lMuwM4z1wwsUbpBN7qaOcD7/
         YrL9/j+/ylqCepAYGjL7r23Sh8ECz7v6Jui0bvDe9b0FbE99hD+NQoRY8ZLSmxRJCeHL
         eDqGb3GOO49gX74+3iL9Nb7aPr3juW+TT4f1LAKI1Xtt+1/sKq0t+BQwZsncWaqDtuh7
         ARcdslhmpJMckC4/xG2dboAeZGUGMcf8jtADJz6Iz0ZHZ/DrLr9Fon2xURYrGYXic2JL
         /3Myj++zKPvyUG7kwbJibG68ExA1MhDgz3lW6V4n7kZjipADCKZDFOpB4kQKGSF2dQFc
         nGlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXqc4uk4uLX6FzjxuI6K314c3t3RvQO2N7T/HSFdYgDq6dB+K+T
	TEfJk67bFq1lf8+Judq6zNg=
X-Google-Smtp-Source: AK7set94jLr1h7+trWpAicFaXMKeyO+8IVS8hkTlI5PHpwF/jM+z8bkR5J6rOwXx800nwbUI9wEUnA==
X-Received: by 2002:adf:e449:0:b0:2bf:e0f2:f0a1 with SMTP id t9-20020adfe449000000b002bfe0f2f0a1mr305443wrm.712.1675105070225;
        Mon, 30 Jan 2023 10:57:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ccf:b0:3dc:5674:6707 with SMTP id
 fk15-20020a05600c0ccf00b003dc56746707ls2397593wmb.2.-pod-canary-gmail; Mon,
 30 Jan 2023 10:57:48 -0800 (PST)
X-Received: by 2002:a05:600c:19c8:b0:3dc:353c:8b44 with SMTP id u8-20020a05600c19c800b003dc353c8b44mr13035886wmq.5.1675105068501;
        Mon, 30 Jan 2023 10:57:48 -0800 (PST)
Received: from mga06.intel.com (mga06b.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id bi21-20020a05600c3d9500b003dc43c78e98si531099wmb.0.2023.01.30.10.57.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 30 Jan 2023 10:57:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dan.j.williams@intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6500,9779,10606"; a="390009003"
X-IronPort-AV: E=Sophos;i="5.97,258,1669104000"; 
   d="scan'208";a="390009003"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 30 Jan 2023 10:57:45 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10606"; a="732802654"
X-IronPort-AV: E=Sophos;i="5.97,258,1669104000"; 
   d="scan'208";a="732802654"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by fmsmga004.fm.intel.com with ESMTP; 30 Jan 2023 10:57:36 -0800
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.16; Mon, 30 Jan 2023 10:57:28 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.16 via Frontend Transport; Mon, 30 Jan 2023 10:57:28 -0800
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.101)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.16; Mon, 30 Jan 2023 10:57:27 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=T7u2UgG9xXHB55z0kmHvAR48xd3hSkuIVyH1S+Qj0AQEvnqZQ1eZvFdwxvnwC3tBIfyV+f09mi4rycT4Lwy9jEAcr93Zz0MVEo14S+AGuV+9bcdJnTzjboQsqC3rp4wilYAUSAFL9BXcy3kRdzo8Llohvmrtq413T1+V7VcgEPD9HBBWn991qv8fzcfWbCzRabdVfH/5cb69hI5BFbtjavz0dVkyk0tVlOzYcbDDuFo640YQ2QStt4MFhj58Iuw/rsiPYBGzE7JlYeFD2xhm6Kx69O3PuwIZINySfrj34+QpooMxwlt2T8NSDHfnVVBdrTNh4Yt7iNT9dywMW4G43Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=03HohyCV8hbOh/3uzXBvYlhWwLl3VC7jMMxfvoy3cTg=;
 b=oNKEjWnOJ7Mgd+rUs03HNb5Mia7AsgbnElUoCLlS7JdMoBKXVdH44UUhnxKY8XaQiP5zJhUMa18jfgAvFt5Zw9jmDcybY0W71whXltOnUrYrPXYlx7b24Akwqz2hWS+yzAHJTdej5dR6suCLsb/bAcdnu3jV9FpaH43/q0HfO3TN3fWUgrx8gX/JM6n7XT/1bpuguxEOMmr/OcyaN1swoGu03PJRaoAMoWhuoORF6MH8FAjhuKTe5Yv2yy6TaklHnRF8LXlltyfjMfmmqhp8fviCkNNZYa2g+qlK1SJ3yUgVwv0P7dGHW9A1+CaGHWr0K/FE0zX/72VbHcgWHtTe7Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from PH8PR11MB8107.namprd11.prod.outlook.com (2603:10b6:510:256::6)
 by DM4PR11MB7352.namprd11.prod.outlook.com (2603:10b6:8:103::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6043.36; Mon, 30 Jan
 2023 18:57:20 +0000
Received: from PH8PR11MB8107.namprd11.prod.outlook.com
 ([fe80::421b:865b:f356:7dfc]) by PH8PR11MB8107.namprd11.prod.outlook.com
 ([fe80::421b:865b:f356:7dfc%5]) with mapi id 15.20.6043.022; Mon, 30 Jan 2023
 18:57:20 +0000
Date: Mon, 30 Jan 2023 10:57:16 -0800
From: Dan Williams <dan.j.williams@intel.com>
To: Alexander Potapenko <glider@google.com>, Dan Williams
	<dan.j.williams@intel.com>
CC: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, "Andy
 Lutomirski" <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov
	<bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
	<cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, "Ilya
 Leoshkevich" <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe
	<axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook
	<keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
	<willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
	<penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
	<pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner
	<tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum
	<vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux Memory Management List
	<linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, LKML
	<linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
Message-ID: <63d8130c30bb5_ea22229489@dwillia2-xfh.jf.intel.com.notmuch>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
 <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=XNfrpTxWYYLnG5L-ogKmxvWvLGTzgqbT7sWxnFgnu7_w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=XNfrpTxWYYLnG5L-ogKmxvWvLGTzgqbT7sWxnFgnu7_w@mail.gmail.com>
X-ClientProxiedBy: BYAPR02CA0059.namprd02.prod.outlook.com
 (2603:10b6:a03:54::36) To PH8PR11MB8107.namprd11.prod.outlook.com
 (2603:10b6:510:256::6)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH8PR11MB8107:EE_|DM4PR11MB7352:EE_
X-MS-Office365-Filtering-Correlation-Id: 5b2b3d86-5b06-44e6-a420-08db02f3d055
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: tHMFwM2XPpBZ2VG2G5R34Qyl9vHPF74psISEZEopU/VmdUfppuZhYqv6ir35ZqAvAX/ducgcDFrp/yPyeS9HBu6JbP0uj0JJLGCiZPHRpFM+hMfp4X9X08aFi/aM1ZrPspvWDK3vR7MYBNmD1fo5ZM8jHyhLLnVa/8YqU/lL4JfkM3LciKsToDALJk+9XE+mgLJB+IblL/8UZO3/zXpiAhjgtJsRTZ1ADldRA1yTeyMjHnyDi8Tz3GNL3Y2fkhCHi4ga94XLVRNy1eatfexMpeHkHfQzLXezjpooGqm5RZdui6lmVjQZL1oY0K+6iscKMF7Tg0Og1kNX1iLVJ9wh3zhHGwfhNZWxyWU2ECnnHQWnv6BHHmzQlDKfnRd6YH+DJz1ToSa90NImJapsRDmXCGX3L7xB7EirxpU62uZX79gFyb8bWE8FWCnF9w/QM7IG0rS6D/xJ/t+/NFvknzEaaqxnpk8MHD3fYH5rqhWMRFZq2JPxGOO+mz+5nJzHbZh7EbWFs9QgPGI/nolm75nPR5criDRCgEnV15/rY4ebvwR//QqRqXeYl0NmhOAxspv5oLzcz2kOleWgSIijc9yErv8lO73xxUw7UGJ1oILxnVgVktrvRv3YdxYAy8zYp7gpuA9yVDn4tCYJK/J5hq+7XS/P8wJ7NWtdRRdj45XpjLw=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH8PR11MB8107.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230025)(136003)(346002)(376002)(39860400002)(396003)(366004)(451199018)(66556008)(41300700001)(66946007)(66476007)(8676002)(4326008)(8936002)(316002)(54906003)(2906002)(5660300002)(7406005)(966005)(6486002)(478600001)(186003)(26005)(6512007)(9686003)(6666004)(6506007)(83380400001)(7416002)(110136005)(38100700002)(86362001)(82960400001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?vCxdsbNwRYyZ/6y7OuiE0xg3w0jk81CDNXgDBA+rCIHF8hco3+dmKUa0PQGZ?=
 =?us-ascii?Q?IWbLDePv7SAr5IyaDbI9tUtd0lCJelon0OyRCODxRLJqsXv/vNvbehHCcQNA?=
 =?us-ascii?Q?DL9ECOp3hG5sY+SIGK6lXjQ+/js0dSH7X8SCGt4QAP+TioAxSXS9hntbEOYz?=
 =?us-ascii?Q?G4xiFzTctMPdIEVas20z4hgj/tZG8Y/I2yTTGJCoj1iFLMaVkUpwOrv+1aNh?=
 =?us-ascii?Q?rFGpBSHzfZEllh4CHD/TivUxOH7yC3OjngoJ3VYbz2UN+rzntObBlIv6kPNz?=
 =?us-ascii?Q?rDpQ2j/68l1DRTdim6VBcJBY3+dX1N4Q3avc0ZoIbV3gCWkC//tFWCNKWM+S?=
 =?us-ascii?Q?RlIK+O7mmHGBS56FMjnhALYzmLTfVliSN/WHN+CO0Uk6TFYnciWMcacNKNlg?=
 =?us-ascii?Q?9T1ktQNGD4rn/5NGJG53vACQYr0Cc4GIO1hqklJ/g3eHdhDeJHGwYYEEqdU0?=
 =?us-ascii?Q?+mN1nJifQhMEN0r1M9CZAlmz11SddxTdsWLZTLcMl165K8sTJcmWDiQ3uqrw?=
 =?us-ascii?Q?8tjAoYPJOzb6u1QsK9XyO32OGFIKrCpp3qNa7QQaXwGXgqGoAE4E5e4P3lzd?=
 =?us-ascii?Q?Nu2XYZyE+U/6fBU/FRkXGVDYXsEBSczs1g8IS8E2OUbwgmO99GNp3vbehwUB?=
 =?us-ascii?Q?zmPybUUmUzfZRVhiicL+9WSC0JLAMN2AtBligDzDn26jrMQ5nVHiz78Bw167?=
 =?us-ascii?Q?Q+iO/bD/zKsFLPY6TSwqy8OIeCs0EwcoYCgjEPiaj4+INYCbl/Dk2/XHmq9B?=
 =?us-ascii?Q?xH6rAKqS8sA9M2Aq/k2AJ0uCHt/F4+vXarIS1nezrINUM8coHGakjnqg7jA2?=
 =?us-ascii?Q?3uqM3H7ulQTjLdVvDOn0w/qJbrykQV8pn7VM9HKfRzShiTvcf80jkFLm6wgy?=
 =?us-ascii?Q?Rb8gY21rmP8Hcv4Ju6tew/7HU4rUUCW5xvFwxxu3L508xNivKjqYh9lJtPT5?=
 =?us-ascii?Q?/SqptRQ1hcDpoi2+Pqdk5C4OaSCI0zVoCmrPmEB0m2mBmwFB3A6hBx3Hpoaj?=
 =?us-ascii?Q?ULqyks9JRgtU+p5T14Stn78SW3V8btWHL1h5oRvXrA5X/uGPz7O6o5F5gumU?=
 =?us-ascii?Q?XLPFxEsGjGit50jcXEd35tL1ETkYjf6ePRmzEerVaIsXOGX/wX8O8uXK5spP?=
 =?us-ascii?Q?J0GafqYz3+i8m71AKljebKGBR4bExjHlfN7Hp8fnaxYIk4E3DNrD+hr91HLG?=
 =?us-ascii?Q?xEZNbWT1uL56ksYW8GFhhdYfdQo58Hdl/Bqst5EPUEDFxQ45dx1j0VhVQo1o?=
 =?us-ascii?Q?rm7ibEvGSRkDssWJy7+2LgtWxfbNK2MPfwa64uwzzcFAX3DkcVqMSIveiAbs?=
 =?us-ascii?Q?Vo30JDPr7So22l8LEz1Ams7MSHpM0MmLedU+bya11WjQMkhhUrq/26PFK+CV?=
 =?us-ascii?Q?sx4isC0ZmPlaB/Vl5UjNaPGqYCSiUFCfsMZPhepIGosa+eY83fFrHF80Zc0g?=
 =?us-ascii?Q?liRCQcQ53bEZm1WOAjCPL2SpJ9xrTJ4y7Z7yKnX0I6WG0SDqMClQhZAEBITe?=
 =?us-ascii?Q?Dse92oZdvtZnKGs9oSfOCeuApc1QGWs3Tu9UmO7MW4YkfeeTI6H6NMKR7LdS?=
 =?us-ascii?Q?qIgI5E2AZl4aU0DYTyrEwPWsiLtdtFnr5aSp7ucbwrH+8d8QjPJRWrVEJyPt?=
 =?us-ascii?Q?1A=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 5b2b3d86-5b06-44e6-a420-08db02f3d055
X-MS-Exchange-CrossTenant-AuthSource: PH8PR11MB8107.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Jan 2023 18:57:20.1139
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: o6gOwz72dDyVMQ8aUnJS56hxIuduqrNAiYfNUomfdWJw0YTPRvm3YI24aVLmJ0s3wbp4jjAv3wvzrDw2T1mxiS2zS5ttxmxWqdzm1TiWjwc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR11MB7352
X-OriginatorOrg: intel.com
X-Original-Sender: dan.j.williams@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="PR5WXZ/7";       arc=fail
 (signature failed);       spf=pass (google.com: domain of dan.j.williams@intel.com
 designates 134.134.136.31 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
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

Alexander Potapenko wrote:
[..]
> >
> > diff --git a/drivers/nvdimm/Kconfig b/drivers/nvdimm/Kconfig
> > index 79d93126453d..5693869b720b 100644
> > --- a/drivers/nvdimm/Kconfig
> > +++ b/drivers/nvdimm/Kconfig
> > @@ -63,6 +63,7 @@ config NVDIMM_PFN
> >         bool "PFN: Map persistent (device) memory"
> >         default LIBNVDIMM
> >         depends on ZONE_DEVICE
> > +       depends on !KMSAN
> >         select ND_CLAIM
> >         help
> >           Map persistent memory, i.e. advertise it to the memory
> >
> 
> Looks like we still don't have a resolution for this problem.
> I have the following options in mind:
> 
> 1. Set MAX_STRUCT_PAGE_SIZE to 80 (i.e. increase it by 2*sizeof(struct
> page *) added by KMSAN) instead of 128.
> 2. Disable storing of struct pages on device for KMSAN builds.
> 
> , but if those are infeasible, we can always go for:
> 
> 3. Disable KMSAN for NVDIMM and reflect it in Documentation. I am
> happy to send the patch if we decide this is the best option.

I copied you on the new proposal here:

https://lore.kernel.org/nvdimm/167467815773.463042.7022545814443036382.stgit@dwillia2-xfh.jf.intel.com/

It disables PMEM namespace creation with page-array reservations when
sizeof(struct page) > 64.

Note, it was pre-existing behavior for PMEM namespaces with too small of
a reservation to fail to enable. That gives me confidence that the
restriction to lose some PMEM namespace access with these memory debug
facilities is acceptable.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/63d8130c30bb5_ea22229489%40dwillia2-xfh.jf.intel.com.notmuch.
