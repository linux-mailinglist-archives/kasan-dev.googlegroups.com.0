Return-Path: <kasan-dev+bncBDN7L7O25EIBBAXBW6NQMGQEFAIRL6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E3156625414
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Nov 2022 07:49:38 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id m34-20020a05600c3b2200b003cf549cb32bsf3976527wms.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 22:49:38 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZqAjcVXiezh/Re1aoRKRns9UU52Ds1IMCHdSu5KK2gY=;
        b=WBAwMbNEZgbHYGmHSqcyV57KMEvDKGAa68VBpBTqTA7NnouJhbp2CIolIy6UpN+bhh
         EIe6cLzi1P++C5/zhKTPSzfYqYFIzGsv2aniDcJ5GTcpeKChBATc8EixYZJuWV5blPe3
         rkxPHOCXw79UT6ZXs8O+Xdtp8qlTDk/tuJiNgDwgEcV/NHk8d/1cDgyjnBvsEEiVgMtg
         hugcrvzFMvUiUtXtFhpe/v9PVzTDAvTfgdv/y6SBxAlp9cDZq3RmXPQftTAx3M9tuK0f
         xAh0K61XEm/gLsNCqnFnf3s2jAtPxUAV8kG+V6lQMW9uZS58hyuU55BMHatk+yePvcdG
         Y7YA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZqAjcVXiezh/Re1aoRKRns9UU52Ds1IMCHdSu5KK2gY=;
        b=df4wuL/BVU3Woae7lTwraSM4H8dnqLXMNHkiBa8GC2BnBnwMd6jI5jsttaLKcnpjv/
         FFckLFH9wujNHZPh//vu0mXGY0cQVWNT1qPY3hLmYH7kAGjYksaRSQS7uLMVYmaLeIcM
         c/0ng6geO38S8OSbAwgeUGRZ1pd/OP/Shr2sRbj4dPLsQLHJpOCsJDITq4HAFcRc39du
         76NnoyQBT9/qe3wZ1LhbKp8UFLZ8d7yYQ3OYGUJoAbLsZRIqEpPM8RE5mn8K30/lXnqz
         DZDbnyLocmTZ+4V4yD7ce0uc9/Smf6zWGlb023MZVYvgNhJra4HvG261G5S75Zk6oMHC
         e3Zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pknrpWZk/rHJjQ1glYtgVsPfKV+Mo7MlR2nccsgKML8cYAN1rbx
	vYytcMhlXTDklPvtLhgrpBE=
X-Google-Smtp-Source: AA0mqf7oPWYxYy06X0VOESZ2yaY3vqQiza+ZEUX+GsWVzixct/MbisVR3lAz0YISTFlASGJ1smIdaQ==
X-Received: by 2002:adf:ba52:0:b0:236:55a7:cf2 with SMTP id t18-20020adfba52000000b0023655a70cf2mr366411wrg.270.1668149378560;
        Thu, 10 Nov 2022 22:49:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce11:0:b0:3c6:efd6:9cd8 with SMTP id m17-20020a7bce11000000b003c6efd69cd8ls2032409wmc.0.-pod-control-gmail;
 Thu, 10 Nov 2022 22:49:37 -0800 (PST)
X-Received: by 2002:a05:600c:4143:b0:3c6:bc31:20ed with SMTP id h3-20020a05600c414300b003c6bc3120edmr248522wmm.41.1668149377572;
        Thu, 10 Nov 2022 22:49:37 -0800 (PST)
Received: from mga06.intel.com (mga06b.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id s1-20020a1cf201000000b003c8340cb9a1si60373wmc.2.2022.11.10.22.49.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Nov 2022 22:49:37 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6500,9779,10527"; a="373668899"
X-IronPort-AV: E=Sophos;i="5.96,156,1665471600"; 
   d="scan'208";a="373668899"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Nov 2022 22:49:35 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10527"; a="588469902"
X-IronPort-AV: E=Sophos;i="5.96,156,1665471600"; 
   d="scan'208";a="588469902"
Received: from fmsmsx603.amr.corp.intel.com ([10.18.126.83])
  by orsmga003.jf.intel.com with ESMTP; 10 Nov 2022 22:49:35 -0800
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 10 Nov 2022 22:49:34 -0800
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 10 Nov 2022 22:49:34 -0800
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 10 Nov 2022 22:49:34 -0800
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.101)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 10 Nov 2022 22:49:33 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=TwwrDkrcdeA6gE799wud3ogLtkoge6mGbzOPF5X3atyWiH+DmX1k8voX9RgapDyoRRt3KLaNA23Te/KagwkaIVoxVjMZ1HY5kWrSttQbM/r8AnVvDgGz/M/HHtDH/7JCgSI4GoyRBXhJzT7MT0rQSGt0WEngdBR0whtxwiGdIZV09bPZMI3BF3UP4xssLlFnEjMokwbHWfPB946spQk5xkSCZ4zvxKJx8y5V0jrBk3BDz0mKveqjWxGMI1/kYj3YsP9lIazxnL1aDNMxRubbrN2THiaCZqaQB1SbKfmVzMn/sqSeK2hlQNxWAUCsPNw/AWJ5jhIOb8fREpXNfgPrTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=bu350R8A1z/Vsz8+LDCd+tMpiG33eNMGtf9ZSMnjpGY=;
 b=FWuYC6DU8ejkN/0Q4Z/5c3bV0nABBxt9/kcaMg5ySPPn4sYrIrhjXcuU9eClg1r177G6ntTSqxi+gVBklBK41bljXP/luNLcdekbUHT8qaVHE+EVB3ElnLL6+lDSCaoQLALkYFeE8K8aR+catQoW+Xi7niLImrdEfNlQTVS5uebGe2dGgVO5rcrDGmx4RIywxQ8zvVPtjrRCSeM5b1k2UpDguOWexdSjruMsNu2DOPadUMfam1YvVh+oj/N8x1GEal1h27fW6b8vsZWZCnzUof9cIAhXzrKKUBpUqq2bJY1Di2+8S3WI7jPOCpbmD1KBT/kEw+X6tYQpiS1I37Q4dA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by SJ0PR11MB4943.namprd11.prod.outlook.com (2603:10b6:a03:2ad::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5813.12; Fri, 11 Nov
 2022 06:49:30 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb%4]) with mapi id 15.20.5813.013; Fri, 11 Nov 2022
 06:49:30 +0000
Date: Fri, 11 Nov 2022 14:46:12 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter
	<cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, "Kees
 Cook" <keescook@chromium.org>, Dave Hansen <dave.hansen@intel.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH v7 3/3] mm/slub: extend redzone check to extra allocated
 kmalloc space than requested
Message-ID: <Y23vtK4tuBogff+m@feng-clx>
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <20221021032405.1825078-4-feng.tang@intel.com>
 <e2dd7c7c-b0b7-344a-de37-4624f5339bce@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e2dd7c7c-b0b7-344a-de37-4624f5339bce@suse.cz>
X-ClientProxiedBy: SGAP274CA0024.SGPP274.PROD.OUTLOOK.COM (2603:1096:4:b6::36)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|SJ0PR11MB4943:EE_
X-MS-Office365-Filtering-Correlation-Id: b8eea6ea-66ee-4d52-0de2-08dac3b0e1e8
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: TwBgLEWtUyTcfLQKTEPI4EZr8EpqlcS+NXgPAFmLTQjgQ4Ti5o72qLkGTQ61h9YKo+yV1EYUv38KVZlcqMgVOfsyvaj2+479V1zEx5sOcCVXVpILJv5TMWvdf371upf6/BFfIFaRDaSd76IonMj5Yz3INOYmvVpb75R9Prwv+v6L0BuvggsEp+ndamSfTxdjPjNskUs10fxZfXUqSKSu7ZSoc+vYrZ7UzfjI9FCngwv+iwyKVd1/le74MRbEdk86KhfTnmjInp1Yza3OJXOjjo4sGLTEgfrk6aH6IqxUzhaULG6wxbD+kx0t5zDvso9m/2gDw1FqW2vh4vt+MQoHN3n/86eTSiwbyBMxyXMQENyVqrOJYbxcQGPI5lCn9lKNGoGYf1W675tlOYTfAB2wizD0lQI2F44F/TvLf2AK8DUMs6FDzCYtiuDyEkw3xwtpwdV18e4kIskjOR3L3xWAWGIbHajjIHV0SsFfsjcA5Su5c2l2+fgHA1dv4d1pWzbFKFJkaetSKzNok4g37WBR8PfSyD3lLPpE2/c7PjwaP62QSiPfvG0osZT/FnDcNOf3n8xWxEH19ZRj11N3XbIz8RUa9mXtwHK9rJizTAcEWZTapAUo1u42/fDBUapMBCvf1b+h+8tyqS+IZMZWsv7OK2JULlNORKjRQvpJC3guya5jpvxMlR1A0+fkUT+MF/1WhPeTavInZIue/N8Vio2HFdeLVKW8avL71hNQhSom43qN64Z+l2fwA2dA9ksDdFu0
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(396003)(366004)(39860400002)(346002)(136003)(376002)(451199015)(53546011)(82960400001)(186003)(8676002)(7416002)(66946007)(2906002)(5660300002)(83380400001)(44832011)(26005)(86362001)(8936002)(9686003)(66476007)(6512007)(38100700002)(66556008)(4326008)(41300700001)(6506007)(316002)(6486002)(478600001)(54906003)(6916009)(6666004)(33716001)(67856001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Y/qTSbVhUE+WF/Va+mow6Ow65ypURdENJ3wJ49tl0aJOWYQnY3h0mLSVCnIC?=
 =?us-ascii?Q?e0dMXpxTd4Xz5U0ghebVjvAK7S3lgJS070PvyiPyY+WWZ8LYqYmsszvh3Hef?=
 =?us-ascii?Q?/xZS78Q+ugCdBbE4/iAR2nDs9Mjd2LVMlvP5VjRjEX64MQTpWaRxVT2jMWeA?=
 =?us-ascii?Q?WFIqUgTk2gHVdq9J7on8FKQniXOENpRIxMOBSZ03Qa7LDg2buKKntTAXFqUL?=
 =?us-ascii?Q?KKzGxuqxcMShy9TGERC+/vmgztd9u0K6OZB0bE6MsiSyDZxEeuQWCiF9U5S8?=
 =?us-ascii?Q?HU705hsqizCnfM63Hx1hFLbOoZMnj6ROSyu8dqcak2RWYD+CJMOhRdOw9w5k?=
 =?us-ascii?Q?BTAquowshPm7dL/8NT6x8kbZZtEEFjtMCNoq7+YF32gv/ZV/Aw0YNinnt/zB?=
 =?us-ascii?Q?57w0jLeetnnNoJUO0cYUc2/4thSvIjo5bxYUyd9JcJQC6I1LbsGef1I6Ifiy?=
 =?us-ascii?Q?my/u64qZMuj1TifDLm1g15LyjPcZq2Eq4iuazBwAFETKIxh8iQ7O2M7WQs7I?=
 =?us-ascii?Q?etf67WL3cqHbNJoDsfs0FO33uSLmv+HRvycPyjmUzovXRMCEaUYpk34+GkYA?=
 =?us-ascii?Q?ap2cZaTaP/ouQeapDPrhhL1nAA8Z3ZRViikBNOUpXVKU2YMMF61oj2Ex3E1I?=
 =?us-ascii?Q?h2iTfJeyRngZuVeZLH/ePKtA81BfJ7sY4iehVjF4coVRSCqdyNVDyoqA96e1?=
 =?us-ascii?Q?yRJnrn3ECItGmCWZmCGzbFrDp9EjLOaJJbuAr0J1jEWqlZDAgWdaRLzoLZUg?=
 =?us-ascii?Q?0LTGis2lQowrkxLQBpjoA9UOO0n081hTyg74HI2ecE6eTCZ0BBxKOJNF230m?=
 =?us-ascii?Q?Q30fNgCbsal91Kmu9OcwIvTop9LCyG1x6iYeNJCtfMgQSm4Rconm7N+T41vh?=
 =?us-ascii?Q?rjYe+5Y9LEaSSr1pwMlfPwrBr2HlvetcSJQoeVyUKeWZB5FFxCPqnIqCIxTu?=
 =?us-ascii?Q?p4qXcTf42p29XX9mR4sCQFQwberfwi9Bk6QLEtGB6NfTqcrDC/jT8EKHNTD4?=
 =?us-ascii?Q?Wi+/l6l9O+QO/UGcAmPRl1GLplCEXrHVpiDCu3LnMHcdcbFVc4PJVYsv8UuR?=
 =?us-ascii?Q?vI2xEErC0GtCBiACyVgCVTlVD4NAatx1zBujmmWXtZajLIR+258yKMEUlrGr?=
 =?us-ascii?Q?SdNEsWCACTjGPFgXgg86dXP0mRwYwXBbudrAkdsbrLUR+VZYmo+v3CNSODws?=
 =?us-ascii?Q?Mv3EKjYwKtrE+YK2L8qAzE+62Pc/wIwgI3qxA85gfHdWpI6LQ1pWJ1wQEU89?=
 =?us-ascii?Q?0CArMI36wqvMv1cj6nrWcLpTecWm0PEU/t571pPuJ4UwrApetNlP0xVKH+O0?=
 =?us-ascii?Q?b1O3F0Oj7SqnTZrjsEnG+MGkkW1LOcLPY8ps6NWKNBn+nouaJYgDhaKCHTJ3?=
 =?us-ascii?Q?zT5EUlLXei2eY9Wv6baUWcFmxRjMMwAeQwY7N6fwo64WOlpRveNf+oqHQn5c?=
 =?us-ascii?Q?N1+uAwJSZaVaN3S9gL2nGAOVp+jYJgSGAO3SeDtXBxx7kpCek4CYSzIZIB+/?=
 =?us-ascii?Q?oYSqQTbn7IYAzXWskfQJCTgC2iD/3bAxn868q2NoJw2rjr4ogD/wed9iWlHT?=
 =?us-ascii?Q?thzd0/t7DhWBTdC/q4bvomgBS8yJK4eX4q54zRlt?=
X-MS-Exchange-CrossTenant-Network-Message-Id: b8eea6ea-66ee-4d52-0de2-08dac3b0e1e8
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Nov 2022 06:49:30.0431
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 5geahhHxIaldGxcQBZsbLJh8UuMQhHHCUOXF1q0eAlojzL8mlNJ4BxYBMIF53FR2a61ZLX/R2DZPS+5mhg1NIw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR11MB4943
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="N/olO4xy";       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 134.134.136.31 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Thu, Nov 10, 2022 at 04:48:35PM +0100, Vlastimil Babka wrote:
> On 10/21/22 05:24, Feng Tang wrote:
> > kmalloc will round up the request size to a fixed size (mostly power
> > of 2), so there could be a extra space than what is requested, whose
> > size is the actual buffer size minus original request size.
> > 
> > To better detect out of bound access or abuse of this space, add
> > redzone sanity check for it.
> > 
> > In current kernel, some kmalloc user already knows the existence of
> > the space and utilizes it after calling 'ksize()' to know the real
> > size of the allocated buffer. So we skip the sanity check for objects
> > which have been called with ksize(), as treating them as legitimate
> > users.
> 
> Hm so once Kees's effort is finished and all ksize() users behave correctly,
> we can drop all that skip_orig_size_check() code, right?

Yes, will update the commit log.

> > In some cases, the free pointer could be saved inside the latter
> > part of object data area, which may overlap the redzone part(for
> > small sizes of kmalloc objects). As suggested by Hyeonggon Yoo,
> > force the free pointer to be in meta data area when kmalloc redzone
> > debug is enabled, to make all kmalloc objects covered by redzone
> > check.
> > 
> > Suggested-by: Vlastimil Babka <vbabka@suse.cz>
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
> Looks fine, but a suggestion below:
> 
[...]
> > @@ -966,13 +982,27 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
> >  static void init_object(struct kmem_cache *s, void *object, u8 val)
> >  {
> >  	u8 *p = kasan_reset_tag(object);
> > +	unsigned int orig_size = s->object_size;
> >  
> > -	if (s->flags & SLAB_RED_ZONE)
> > +	if (s->flags & SLAB_RED_ZONE) {
> >  		memset(p - s->red_left_pad, val, s->red_left_pad);
> >  
> > +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
> > +			orig_size = get_orig_size(s, object);
> > +
> > +			/*
> > +			 * Redzone the extra allocated space by kmalloc
> > +			 * than requested.
> > +			 */
> > +			if (orig_size < s->object_size)
> > +				memset(p + orig_size, val,
> > +				       s->object_size - orig_size);
> 
> Wondering if we can remove this if - memset and instead below:
> 
> > +		}
> > +	}
> > +
> >  	if (s->flags & __OBJECT_POISON) {
> > -		memset(p, POISON_FREE, s->object_size - 1);
> > -		p[s->object_size - 1] = POISON_END;
> > +		memset(p, POISON_FREE, orig_size - 1);
> > +		p[orig_size - 1] = POISON_END;
> >  	}
> >  
> >  	if (s->flags & SLAB_RED_ZONE)
> 
> This continues by:
>     memset(p + s->object_size, val, s->inuse - s->object_size);
> Instead we could do this, no?
>     memset(p + orig_size, val, s->inuse - orig_size);

Yep, the code is much simpler and cleaner! thanks
 
I also change the name from 'orig_size' to 'poison_size', as below:

Thanks,
Feng

-----8>-----

From 21dc7a27bb9206937ec5cc584a70da452fc249c6 Mon Sep 17 00:00:00 2001
From: Feng Tang <feng.tang@intel.com>
Date: Wed, 12 Oct 2022 13:39:09 +0800
Subject: [PATCH 3/3] mm/slub: extend redzone check to extra allocated kmalloc
 space than requested

kmalloc will round up the request size to a fixed size (mostly power
of 2), so there could be a extra space than what is requested, whose
size is the actual buffer size minus original request size.

To better detect out of bound access or abuse of this space, add
redzone sanity check for it.

In current kernel, some kmalloc user already knows the existence of
the space and utilizes it after calling 'ksize()' to know the real
size of the allocated buffer. So we skip the sanity check for objects
which have been called with ksize(), as treating them as legitimate
users. Kees Cook is working on sanitizing all these user cases,
by using kmalloc_size_roundup() to avoid ambiguous usages. And after
this is done, this special handling for ksize() can be removed.

In some cases, the free pointer could be saved inside the latter
part of object data area, which may overlap the redzone part(for
small sizes of kmalloc objects). As suggested by Hyeonggon Yoo,
force the free pointer to be in meta data area when kmalloc redzone
debug is enabled, to make all kmalloc objects covered by redzone
check.

Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
---
 mm/slab.h        |  4 ++++
 mm/slab_common.c |  4 ++++
 mm/slub.c        | 50 +++++++++++++++++++++++++++++++++++++++++++-----
 3 files changed, 53 insertions(+), 5 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 2551214392c7..de9ef5b4931e 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -896,4 +896,8 @@ void __check_heap_object(const void *ptr, unsigned long n,
 }
 #endif
 
+#ifdef CONFIG_SLUB_DEBUG
+void skip_orig_size_check(struct kmem_cache *s, const void *object);
+#endif
+
 #endif /* MM_SLAB_H */
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 0042fb2730d1..8276022f0da4 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1037,6 +1037,10 @@ size_t __ksize(const void *object)
 		return folio_size(folio);
 	}
 
+#ifdef CONFIG_SLUB_DEBUG
+	skip_orig_size_check(folio_slab(folio)->slab_cache, object);
+#endif
+
 	return slab_ksize(folio_slab(folio)->slab_cache);
 }
 
diff --git a/mm/slub.c b/mm/slub.c
index 8d26187de915..03b7f4056619 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -829,6 +829,17 @@ static inline void set_orig_size(struct kmem_cache *s,
 	if (!slub_debug_orig_size(s))
 		return;
 
+#ifdef CONFIG_KASAN_GENERIC
+	/*
+	 * KASAN could save its free meta data in object's data area at
+	 * offset 0, if the size is larger than 'orig_size', it will
+	 * overlap the data redzone in [orig_size+1, object_size], and
+	 * the check should be skipped.
+	 */
+	if (kasan_metadata_size(s, true) > orig_size)
+		orig_size = s->object_size;
+#endif
+
 	p += get_info_end(s);
 	p += sizeof(struct track) * 2;
 
@@ -848,6 +859,11 @@ static inline unsigned int get_orig_size(struct kmem_cache *s, void *object)
 	return *(unsigned int *)p;
 }
 
+void skip_orig_size_check(struct kmem_cache *s, const void *object)
+{
+	set_orig_size(s, (void *)object, s->object_size);
+}
+
 static void slab_bug(struct kmem_cache *s, char *fmt, ...)
 {
 	struct va_format vaf;
@@ -966,17 +982,28 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
 static void init_object(struct kmem_cache *s, void *object, u8 val)
 {
 	u8 *p = kasan_reset_tag(object);
+	unsigned int poison_size = s->object_size;
 
-	if (s->flags & SLAB_RED_ZONE)
+	if (s->flags & SLAB_RED_ZONE) {
 		memset(p - s->red_left_pad, val, s->red_left_pad);
 
+		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
+			/*
+			 * Redzone the extra allocated space by kmalloc than
+			 * requested, and the poison size will be limited to
+			 * the original request size accordingly.
+			 */
+			poison_size = get_orig_size(s, object);
+		}
+	}
+
 	if (s->flags & __OBJECT_POISON) {
-		memset(p, POISON_FREE, s->object_size - 1);
-		p[s->object_size - 1] = POISON_END;
+		memset(p, POISON_FREE, poison_size - 1);
+		p[poison_size - 1] = POISON_END;
 	}
 
 	if (s->flags & SLAB_RED_ZONE)
-		memset(p + s->object_size, val, s->inuse - s->object_size);
+		memset(p + poison_size, val, s->inuse - poison_size);
 }
 
 static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
@@ -1120,6 +1147,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 {
 	u8 *p = object;
 	u8 *endobject = object + s->object_size;
+	unsigned int orig_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
 		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
@@ -1129,6 +1157,17 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 		if (!check_bytes_and_report(s, slab, object, "Right Redzone",
 			endobject, val, s->inuse - s->object_size))
 			return 0;
+
+		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
+			orig_size = get_orig_size(s, object);
+
+			if (s->object_size > orig_size  &&
+				!check_bytes_and_report(s, slab, object,
+					"kmalloc Redzone", p + orig_size,
+					val, s->object_size - orig_size)) {
+				return 0;
+			}
+		}
 	} else {
 		if ((s->flags & SLAB_POISON) && s->object_size < s->inuse) {
 			check_bytes_and_report(s, slab, p, "Alignment padding",
@@ -4199,7 +4238,8 @@ static int calculate_sizes(struct kmem_cache *s)
 	 */
 	s->inuse = size;
 
-	if ((flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
+	if (slub_debug_orig_size(s) ||
+	    (flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
 	    ((flags & SLAB_RED_ZONE) && s->object_size < sizeof(void *)) ||
 	    s->ctor) {
 		/*
-- 
2.34.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y23vtK4tuBogff%2Bm%40feng-clx.
