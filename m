Return-Path: <kasan-dev+bncBDN7L7O25EIBBDGZ6WMAMGQEH7UAKYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id D18395B4C23
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Sep 2022 07:05:17 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id y11-20020a05651c220b00b0025e4bd7731fsf1471684ljq.3
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 22:05:17 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=e1vkYvZkRbyUFMOCOPmCyfUVu/LM9VWFO0XKxPWS3bY=;
        b=MYlAQ91RYUFpTrL1BcERCb5T9XEQnuiooeYf9Zl29oMK/oDicUSYyaoQf/pwhMH06F
         L2kKdhzq/DxYsY/qAmkdBojt39yjBXBQP4HT+5fkwuNe/Bfjm9gMj3nbL4PFaSdlSvnd
         7a0jS8Dc0cOaq9W5xYjaHvVWOcCK463EhVOf6K4lEyt6Rzdfg2O9+HPTKLy68uS2oNx/
         ib5fKS0qjk61Vg/a6+pM2aU3CeoVp7pkQnkXFlXpYVoqHNifIGeo3+RuhiS8mwdinRTX
         RMPVBbrC5Gk4EUYyQ4ANsY5BPWLi73GSiMGVMmI7MXMCl2qyX5ZT668McpwN8vv74+X+
         7EWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=e1vkYvZkRbyUFMOCOPmCyfUVu/LM9VWFO0XKxPWS3bY=;
        b=ON6vC831BUHcviWFT9zLOUfBWfNWN38rL4h84f1V5QcwFVCa9DAYivPF1OOxr9IXpU
         6ZH2FOTYLYqLfMW9q1SqCtJzFTRWY+35GRLhUBPar5EwlABHHj6bi76PQFTSRgZ4yQ81
         TiY2IUbtliki8fVDCVX7DvUSpnXjflsxyg1Z5ecDCYA06kD9ZMiGWTmuI/xLSF92EhuZ
         4uo8r+WvsLJ+RLkCu1vKr76oIJobV8QH6B0RBit6IYPkwG6fbNRpoTRDY9bhp3tnw5La
         ZxD4R4BUJ8yUN9dInnuY7mTdhKy2d9BQb031Myc88yZhhV8MuFOzy9ROSkJ7OfijvGaX
         Npwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0EhXIFBnn9idJzloxKWqsOURaV3/f3LUKh8gxn4INVLHGLD41p
	TqChpZ2he0HNm6Bo3yXFxOY=
X-Google-Smtp-Source: AA6agR7iciEwFBP8q/8BriNGoAIvYYIwJvbwYWPiBjZVHYiz6X/tg5nABV1pGy9swQP9k9/HRaiV8Q==
X-Received: by 2002:a05:6512:3c8c:b0:498:f7ba:9a69 with SMTP id h12-20020a0565123c8c00b00498f7ba9a69mr3791496lfv.8.1662872717074;
        Sat, 10 Sep 2022 22:05:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:57c9:0:b0:492:f1b2:ac20 with SMTP id k9-20020ac257c9000000b00492f1b2ac20ls299648lfo.1.-pod-prod-gmail;
 Sat, 10 Sep 2022 22:05:15 -0700 (PDT)
X-Received: by 2002:a05:6512:3984:b0:499:b142:9a52 with SMTP id j4-20020a056512398400b00499b1429a52mr1654841lfu.253.1662872715890;
        Sat, 10 Sep 2022 22:05:15 -0700 (PDT)
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id p4-20020ac24ec4000000b00497f1948428si119921lfr.8.2022.09.10.22.05.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 10 Sep 2022 22:05:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6500,9779,10466"; a="277428229"
X-IronPort-AV: E=Sophos;i="5.93,307,1654585200"; 
   d="scan'208";a="277428229"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2022 22:05:12 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,307,1654585200"; 
   d="scan'208";a="677673720"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by fmsmga008.fm.intel.com with ESMTP; 10 Sep 2022 22:05:12 -0700
Received: from fmsmsx609.amr.corp.intel.com (10.18.126.89) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Sat, 10 Sep 2022 22:05:11 -0700
Received: from fmsmsx608.amr.corp.intel.com (10.18.126.88) by
 fmsmsx609.amr.corp.intel.com (10.18.126.89) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Sat, 10 Sep 2022 22:05:11 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx608.amr.corp.intel.com (10.18.126.88) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Sat, 10 Sep 2022 22:05:11 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.109)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Sat, 10 Sep 2022 22:05:11 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=EbYDeqtta1wJVR4a2ZZbzqeSu54o53mF5YWGu42zK3/nbP+/nXpW5avlBr7bpPT5xXMFPKfAUGeNs5RxANo6X1+HAjU6xvhWfIjt2BUGfGfAONR+IOU9UXFJEbAdA4W8lAfUC44oHAtv8XcdIyI8AoroTh1J5+5lQ3xL99s+n8eJwyI8sYmEchON173CFWBkPQEWCIaB78kHnEH1dhCBigRqGIQ+9PpjmCs89XJUZKu2WqV/p+ravrTkQT2TMj+VMFL4L3uy7k/ZrYeZNv8w1WVbQc9NdeCur2OgDMdZYzgzLkHwMv3dcImtCvMKePEsZlSAfRx+eSFS4u3gEu2ACg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=DdGLT4ozILpTTJh2uS3pxCJ1zPmQ8Vr1h3z/eT1ctXg=;
 b=nBSB5j1N4ORYqvSNW8rOAvYP2RN/FrHx4Ll2AhbrZGmtHvC7rWoWhmuDrsJ3Q3a8C9f15d7dMLCGfUA77cxJ2T5wgYPh94XZNMnoumoXlBcCs4m5WrxHkk9Aow/6KqXKYDBs3xZIDCKZZ6v5ahMxv/4Sy6cKP1FMI08pxjbPJulvwFPsJZPR2CQX0FiRb0EB3NXtzo2MHQwuiIM36njOfTUCySYOdfqNiLPlOWM24+Zsf1B2U07ulBwQ3V/QVRzyfGNc7pNb82bZ8F7E6Be2hwgYv3V8Fh/xXYFUvg/nAgitOwJUygGPMI5jlX2GDkrNvxDrgyOJXkPhykoBvPIgww==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by DM6PR11MB4515.namprd11.prod.outlook.com (2603:10b6:5:2a9::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5612.12; Sun, 11 Sep
 2022 05:05:09 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e%7]) with mapi id 15.20.5588.015; Sun, 11 Sep 2022
 05:05:09 +0000
Date: Sun, 11 Sep 2022 13:04:34 +0800
From: Feng Tang <feng.tang@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Alexander Potapenko <glider@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, "Christoph
 Lameter" <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, "Hansen,
 Dave" <dave.hansen@intel.com>, Linux Memory Management List
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, kasan-dev
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH v5 2/4] mm/slub: only zero the requested size of buffer
 for kzalloc
Message-ID: <Yx1sYjzSYyQsOfCn@feng-clx>
References: <20220907071023.3838692-1-feng.tang@intel.com>
 <20220907071023.3838692-3-feng.tang@intel.com>
 <CA+fCnZdSUi6mC1e42bztst2tvhc-sLZdnj=Sr=doqxOokXmwTg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdSUi6mC1e42bztst2tvhc-sLZdnj=Sr=doqxOokXmwTg@mail.gmail.com>
X-ClientProxiedBy: SG2PR06CA0222.apcprd06.prod.outlook.com
 (2603:1096:4:68::30) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 1defcde8-40fd-4fc6-7096-08da93b332dd
X-MS-TrafficTypeDiagnostic: DM6PR11MB4515:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: YrqF7Vp+eIooeaKRya9TlR/BfREyhQfoxDYUhZ+kSSOHphg31/pbhEcBVU4LoNnf3CB31EsDH012RrLERBwPWnQWv+a9V0h/d8WwKah9sj6MkpP1GtRSCcWItGf3FR3b3vwJwqHyH3R5YZ/nv1TTAL6CiN17JV675tIt0ScjUkd6T9JwGcsQgfArmGMDt5HPQ1nr8aopTxEKHAz1vM8BH/4EF+M7gR/QOCgRD6VCeyr/zGOBnQSSsRDZgS6+SOfhQo9qVJrPJ704Kcu17UUodx+YmksyxGTWdAnv5ZUQR98QcpR7xYVFCbmOwmQGYyCVNEh3r5E391EAA/d2BnolkqABPvjCjdRhT0YcpRf2YkOGYOmG2m2OmDVFQ5v/bimmm1B/HJCiC/4/kTwcXP/Xcuef9i/+HPjRNkM1ec9Eu52ojWt84s3WEs/rt9E/DSQEjiInIgjbi5jRin9ceuQ2CEIih9lqoCbgSSnRcta2yUDhJmaxX7yBmazQ6rKjOH3/srJlRSl9S0iNoC5YplzdpzlShBg4PfBRtcsWxiJ64Q/Ih5PWUTNE2K42s38QZiN0YAvohOhbmpwo6QYmpnbXtUfzi+PFMeEq3QTZHDsBO8QE6fK463tT9vaDgm9+1BaHNgdmTuNfxo1Ce/6Sr5O3o4VCTcB6I/oxpZ7NiBWsloxjJUOwy5njFtm6g/OTce1Pb4hnNHsNUOfcY8okEGXQbnmkWUeDOgmxip6/cC+G8rH6n2BF8eu4cJxmt3+gI0zJ
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(396003)(136003)(366004)(39860400002)(376002)(346002)(6506007)(53546011)(26005)(41300700001)(9686003)(6666004)(6486002)(83380400001)(186003)(44832011)(2906002)(8936002)(5660300002)(7416002)(6512007)(33716001)(478600001)(54906003)(6916009)(316002)(66556008)(66946007)(66476007)(4326008)(8676002)(38100700002)(82960400001)(86362001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?2KWZzLftFL0d0Qlg/62aPC/fXyddf0Ht4U7MNjfRgB2OadcZFifzcPuXyXWq?=
 =?us-ascii?Q?08ArLYlNUGM2gVfv/u39q4/+92AvHoD+6D1wBC8gVMdK40+pEirKL6TxpdhO?=
 =?us-ascii?Q?EDHvrfQaLDMdXJddkRyNoEY2C8qSQEPGm0Nnp7TjlmCo48RZ1BnavgR8s11u?=
 =?us-ascii?Q?woBEeTPtJhrr9jqVEZBa5X5jGQH0ZTieEiruh7/3fgCOmn4g/HWu4qH3TUNv?=
 =?us-ascii?Q?BKNKaZt/rMkC93kp3b+V1X6FAmNjeyznt2GtHyTV0FWjgRpeDzI6oOr5isda?=
 =?us-ascii?Q?DmG0RVkPUYbcWEHuZEoQ8SCzd4E/6ZsHmu8gMsX9sSBF+npwkRReGOwz990b?=
 =?us-ascii?Q?jrXIND0eb4S6F4xnbwIhQ8dFSSgH+8WrwgVjuXJ7VwuPh/MgaqajaKbSguX2?=
 =?us-ascii?Q?Ny/CSD+hpXvM2npS7wYAB0VaXg0GxwZkA5z1fGcxcFP5kn8LPpmvh7zdJhVi?=
 =?us-ascii?Q?3TzWs839Ua51rMOzeK7idZGkWdp0xSBlWA5vT+P5tx7nxK/809RQINiTq05W?=
 =?us-ascii?Q?c4J24gsBHnrG1LeCmVS5cjc4vY24rtPtpdBM4PDEMaJeW8LaG+pb9V8KRfEq?=
 =?us-ascii?Q?xpFm74Mf9EVarKDY3kAXji/O0zFmqJcnI3pxdVm1yFzooopTkF11MWXhndYv?=
 =?us-ascii?Q?bJdkWiGsuoS6R+EOeGlf8bdWevhbPqFZodmi4KadPWRaP7OLMPbNHI9x80jr?=
 =?us-ascii?Q?k54NnKpyvZeKGtk8TTan8wYKzgaYpfiUBgei+sBQnZiPAf+Lldx8n5h+bWL0?=
 =?us-ascii?Q?vVS5cfDxbkjPXOBn1QTdkc4os/RECkHAUG71zICVc9p2juW7JDtQJauQEgvN?=
 =?us-ascii?Q?en5lN2e/MWew+chu+JTNGzb5oISHNjHGUfGqGQjl/MQcJpYpVfpcgkvmAkGP?=
 =?us-ascii?Q?Ps3+tzsJC4tB3nj60My6pEOS+xtGWPT9vRVDt7zkWNNE8le6OHJlexY6NhLJ?=
 =?us-ascii?Q?YNDOYpW4jfQElfTZNZB0BDJKS5CPhYfb+gu/Z0+d5YHy/TYmIeRh/WkuEQUN?=
 =?us-ascii?Q?LKwpPLb9Kqb98jMS+fTqZbECwTRTwX6D7pyVwcAbbNo6L7b3S10JMKD0uhI3?=
 =?us-ascii?Q?rHKKebXNbyZGHMLGo+dPZMF4tsHP2EmEg0LtQdvQRsS5NmDVP6ePSfLFqjmD?=
 =?us-ascii?Q?CZ8EnUfanZ1dvOpYl6OaszE9fOtdzTEHsbm0LPjrISQQfbfdRwQnJ4ThE4lh?=
 =?us-ascii?Q?UQpLDpbt5vkQsTbmsCBjrbD68h93CfXUStC/3bSaO5hG5+LZFK7IUXwYGc79?=
 =?us-ascii?Q?ZtkjrfFpFk1c9s01f+eZJ63cluFIoUZKF3CeXXQraiKjUI2CsgLpaiXthJ7v?=
 =?us-ascii?Q?8X+3Au9CIStQJnWlms4W+KuAEgz1wJOu5reMeyixnyEaflw/w2XH27PxE8Z+?=
 =?us-ascii?Q?lCJV9Tsqf7bQQLVatUaMxw79zjIb8eV1FZ4L6tmRomfqg0fRv3ccOLk5QhmM?=
 =?us-ascii?Q?4iVCh8S5mBh/dklz/Uh1VZvPIOMe4umPgHLHBW1cXt+WTrIg+ESN9lOexJaw?=
 =?us-ascii?Q?wmJ37flSB7OjZZxOIvpQwEyK1kONoS+pTZx+0X/p0J9FzHjZT7HSrLwq+N/9?=
 =?us-ascii?Q?uHtdWEcj15VpewbWMhQnBkdu0LEBtDhQGFaOaH4x?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 1defcde8-40fd-4fc6-7096-08da93b332dd
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Sep 2022 05:05:08.9243
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: rsN1voqP4TtxYKsYYXqCg1ezDxllD9yFY2DciNpx3PQEzQKnDq59B0KIJi7sl4sCMGAQJStdDQ1Q1JwIGV/0hw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR11MB4515
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lIWVKY43;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.136 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Sun, Sep 11, 2022 at 07:11:18AM +0800, Andrey Konovalov wrote:
> On Wed, Sep 7, 2022 at 9:10 AM Feng Tang <feng.tang@intel.com> wrote:
> >
> > kzalloc/kmalloc will round up the request size to a fixed size
> > (mostly power of 2), so the allocated memory could be more than
> > requested. Currently kzalloc family APIs will zero all the
> > allocated memory.
> >
> > To detect out-of-bound usage of the extra allocated memory, only
> > zero the requested part, so that sanity check could be added to
> > the extra space later.
> >
> > For kzalloc users who will call ksize() later and utilize this
> > extra space, please be aware that the space is not zeroed any
> > more.
> >
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > ---
> >  mm/slab.c | 6 +++---
> >  mm/slab.h | 9 +++++++--
> >  mm/slub.c | 6 +++---
> >  3 files changed, 13 insertions(+), 8 deletions(-)
> >
> > diff --git a/mm/slab.c b/mm/slab.c
> > index a5486ff8362a..73ecaa7066e1 100644
> > --- a/mm/slab.c
> > +++ b/mm/slab.c
> > @@ -3253,7 +3253,7 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
> >         init = slab_want_init_on_alloc(flags, cachep);
> >
> >  out:
> > -       slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> > +       slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init, 0);
> >         return objp;
> >  }
> >
> > @@ -3506,13 +3506,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
> >          * Done outside of the IRQ disabled section.
> >          */
> >         slab_post_alloc_hook(s, objcg, flags, size, p,
> > -                               slab_want_init_on_alloc(flags, s));
> > +                               slab_want_init_on_alloc(flags, s), 0);
> >         /* FIXME: Trace call missing. Christoph would like a bulk variant */
> >         return size;
> >  error:
> >         local_irq_enable();
> >         cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> > -       slab_post_alloc_hook(s, objcg, flags, i, p, false);
> > +       slab_post_alloc_hook(s, objcg, flags, i, p, false, 0);
> >         kmem_cache_free_bulk(s, i, p);
> >         return 0;
> >  }
> > diff --git a/mm/slab.h b/mm/slab.h
> > index d0ef9dd44b71..20f9e2a9814f 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -730,12 +730,17 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
> >
> >  static inline void slab_post_alloc_hook(struct kmem_cache *s,
> >                                         struct obj_cgroup *objcg, gfp_t flags,
> > -                                       size_t size, void **p, bool init)
> > +                                       size_t size, void **p, bool init,
> > +                                       unsigned int orig_size)
> >  {
> >         size_t i;
> >
> >         flags &= gfp_allowed_mask;
> >
> > +       /* If original request size(kmalloc) is not set, use object_size */
> > +       if (!orig_size)
> > +               orig_size = s->object_size;
> > +
> >         /*
> >          * As memory initialization might be integrated into KASAN,
> >          * kasan_slab_alloc and initialization memset must be
> > @@ -746,7 +751,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
> >         for (i = 0; i < size; i++) {
> >                 p[i] = kasan_slab_alloc(s, p[i], flags, init);
> >                 if (p[i] && init && !kasan_has_integrated_init())
> > -                       memset(p[i], 0, s->object_size);
> > +                       memset(p[i], 0, orig_size);
> 
> Arguably, with slab_want_init_on_alloc(), all allocated memory should
> be zeroed to prevent possibility of info-leaks, even unused paddings.
> Perhaps, Alexander can give his opinion here.

Initially, I thought about only zero the requested part(orig_size)
when slub_debug is enabled for that slab. But from the profiling,
zeroing 4096+1 bytes and zeroing 8192 bytes, has obvious difference
in execution time (about 10 us vs 18 us).

Semantics wise, requesting 'A' bytes being zeroed and expecting
'A+B' zeroed bytes is not very valid, IMHO

Also this 2/4 patch is also a preparation for 4/4 of redzone
extension, without it, the redzone initialization will be
overridden by the zeroing.

Thanks,
Feng

> Thanks!
> 
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yx1sYjzSYyQsOfCn%40feng-clx.
