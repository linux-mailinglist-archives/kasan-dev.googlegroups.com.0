Return-Path: <kasan-dev+bncBDN7L7O25EIBBR7TRWNQMGQEIYU4AKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 49F3261788D
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 09:20:24 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id v23-20020a1cf717000000b003bff630f31asf187491wmh.5
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 01:20:24 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3rIeq8pMvftRyE1M7BQahQYmWT+JwilQr+5urCjUiWU=;
        b=LN4/SnVnHjbcEeIdZZF30ArbiLk9zund6M6p87Wh32b53FdzjGyEemPmeQjwSzBART
         dd0efi41sXztXOmgmvxoqzZC84kL6wJxpIxTmMPSlF4ILK3nYp/CYIFhzMuZVaD0+cpi
         /wwOnU11sdtv/WZFM/rwxvilWF0NudRCIh/bkRIdwg+iU2HQ6aQIRTeybdkeLfaFEbkJ
         iz7P5J2/udkLN5q+cbV2NpXGgJOUfw83iU+7j8Avu3Qg7ezez0QAuaqdgJ7jvmV/L+5Q
         /UDs4Qyh9FVxFLUeHrSwC5hXLdqIRnX4rn+fpnNpcFY8u5IpTM6yCw6NHdLx99EG+doD
         2R1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3rIeq8pMvftRyE1M7BQahQYmWT+JwilQr+5urCjUiWU=;
        b=Ewfb302KoOjDnVSLkel1KNk79x10xcQFem0afKdPhW02m6jnbzVkkGbNyGUqCZ3qLr
         nN7jdk6jQjfud9zrfH87S/qrdCX4iqu4CpcRrWFACA69BNMlFU8RIacgmN1V3P0/S/43
         U2NfTjSkxUNp16u89vvB7zt8KDna6tZx+/AzgsZtJiUYBKNYI7610MWIFxEXEushLTEW
         yYKNbEOjGmHedTtC7suKTKFOfs4pRkLYaWbvwNtyRhsLZbTVMIzIHy74iwycHMaqF6uz
         9q5HgQZ8pefBt3dAUsmhJLb+NqwQ+VC5e+DdaYKDN7y0jUXpS0bUwwoa5oCpX0bxCe91
         68YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0wNsaJtK1egllN1Ry6kSGesEx4gfO3wGKTQbofVKzfwaKIMXbn
	LW8kOJIYktYV1LMz7BgUVxg=
X-Google-Smtp-Source: AMsMyM4fMU3DkwC4uh/1JZeT7eYHho8Sh5KE8MyjjELKs/4HYQhprfmG0JiR/5OWpRdmq+R9Kvlzog==
X-Received: by 2002:a7b:cd99:0:b0:3cf:7556:a52c with SMTP id y25-20020a7bcd99000000b003cf7556a52cmr12089340wmj.53.1667463623698;
        Thu, 03 Nov 2022 01:20:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22b:0:b0:228:ddd7:f40e with SMTP id k11-20020adfd22b000000b00228ddd7f40els2107646wrh.3.-pod-prod-gmail;
 Thu, 03 Nov 2022 01:20:22 -0700 (PDT)
X-Received: by 2002:a5d:4a0c:0:b0:236:5d98:1be4 with SMTP id m12-20020a5d4a0c000000b002365d981be4mr17705868wrq.590.1667463622711;
        Thu, 03 Nov 2022 01:20:22 -0700 (PDT)
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id n23-20020a7bc5d7000000b003cf1536d24dsi18760wmk.0.2022.11.03.01.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Nov 2022 01:20:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6500,9779,10519"; a="310732809"
X-IronPort-AV: E=Sophos;i="5.95,235,1661842800"; 
   d="scan'208";a="310732809"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 Nov 2022 01:20:20 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10519"; a="585706073"
X-IronPort-AV: E=Sophos;i="5.95,235,1661842800"; 
   d="scan'208";a="585706073"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orsmga003.jf.intel.com with ESMTP; 03 Nov 2022 01:20:20 -0700
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 3 Nov 2022 01:20:19 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 3 Nov 2022 01:20:19 -0700
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.100)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 3 Nov 2022 01:20:19 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=TBcr6BsC0+at7UET0ra7MavJjXr5eqzalB9y5k4w/5HSjaPmikibJjc/2a7AKMDvgEHXt9WkHQHwp8hOo44UwYTyiNEqBc/Ce6DDuRIHY9cayE0VAIM8jqCixlxPwU1t21JcDeS3DtsnkswqE8SOspX4jrj4qieQCyDRH/nHqGE263V+4lCnFiM3MS6aDo2Acz6gNMOFObdlHPmd1mJ1YMetwR8PX3bmd4x0glHphCRdLcTksSDKT+2oW1NZ399d+qMUOiAE/LsbcmRXptTOKDn5jXSAHSQWWZ6eEHEwC2Bi4uEQS8kxnjtOAkhTVhuaRUqEgQvAvt+6Zxyn0eIi6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aW34Vh8EJBL7I8evjlti9ozyo5Sz1u+eiIZ0N1X68xc=;
 b=doDn72AJbG3H1Xm7CeynRtUpo3YBDvA/VREUPKA+Mp1UzYhzo/jetjyiil4ia0gwPUsqW3owlPaA9chXjA3ryiEQIfCDHq1tE2PSTtt9KM0kqbES/4LfrlprsfbhKuOV7t978BjNXNvNwY5khy+ttNcU9w8n8jvEa6QUNK7C3ILavrOeTH4LZOYfmRxXWPMWQvZxcF/Sa/2NujUcWkArokcXeCwICZZXVr48Wp15sR63lEkVrwOl3ENaBs/9j1ZsBOIqayVdtoVbK9tSnjv4smaqTx6OhkU5Vqc4KfROVxU9YmJmC/ZynvDt6GfWdJxxd0kKo88fbYYHGV9xKY8hrw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by SN7PR11MB7565.namprd11.prod.outlook.com (2603:10b6:806:344::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5769.14; Thu, 3 Nov
 2022 08:20:12 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b%3]) with mapi id 15.20.5769.021; Thu, 3 Nov 2022
 08:20:12 +0000
Date: Thu, 3 Nov 2022 16:16:57 +0800
From: Feng Tang <feng.tang@intel.com>
To: John Thomson <lists@johnthomson.fastmail.com.au>
CC: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Dmitry Vyukov <dvyukov@google.com>, "Jonathan
 Corbet" <corbet@lwn.net>, Andrey Konovalov <andreyknvl@gmail.com>, "Hansen,
 Dave" <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Robin Murphy
	<robin.murphy@arm.com>, John Garry <john.garry@huawei.com>, Kefeng Wang
	<wangkefeng.wang@huawei.com>, Thomas Bogendoerfer
	<tsbogend@alpha.franken.de>, John Crispin <john@phrozen.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2N4+dqhezRgk87k@feng-clx>
References: <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <Y2D4D52h5VVa8QpE@hyeyoo>
 <Y2ElURkvmGD5csMc@feng-clx>
 <70002fbe-34ec-468e-af67-97e4bf97819b@app.fastmail.com>
 <Y2IJSR6NLVyVTsDY@feng-clx>
 <Y2IZNqpABkdxxPjv@hyeyoo>
 <Y2NrRt5FF+zi4Vf1@feng-clx>
 <f479b9cc-1301-410c-a36e-80c365964566@app.fastmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f479b9cc-1301-410c-a36e-80c365964566@app.fastmail.com>
X-ClientProxiedBy: SI2PR02CA0012.apcprd02.prod.outlook.com
 (2603:1096:4:194::7) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|SN7PR11MB7565:EE_
X-MS-Office365-Filtering-Correlation-Id: 9fc455c7-354c-4c5f-a791-08dabd743a72
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: gzyDSqtJCSqrO+FVHxuYkmEB9A3FRAjWzJ8Ah5kXeJPgmGqtOJ7bFT20qraWDj2MwMQ7Vrk0nB8nFHJuFYQt6rranSfASBljFB6+E2EoybN0R7ndbR61h2VaoD2Ak8wuz7r9UQ03ud8Ggj613K1xVkgkCA0rKtjizXYvBbj3RwV+x+kFgG+zzMrw/wCpxaqjcz9BXVBBDyr3Kv9MGr+SshjuslmEs4za6AoTX5cB8bBM62TO3UKpMHGCJX8C9cwT4JtITK5eVn/oReItSwyqCD414J38i16xuZfU33wUlsrR/ddZG/mjonpSdOdkDZShvJKVXKnsOP1lPFcj9qmkR8fkIRpqYTPMJQXY/C0PTQvuxjTjP5V8oLTip9xdPs42V4jQXKQoLo3L2mde/xzFUflcL028ZhjLHAMferfGzAB4f6jd4TlbmL8sAzFWa2H+bLcp6hlkhaAAR7lunDwYZDBxAsyPDeTxcu9a+83xwpSXVVvJpG13918jPsOqr8gFPD3Ns2MTJF1V7wodh7ekd/Wpc9+tlH1NSUbiI8lDxkKSwtigEXLv+Fu+MbJWm7MQ4ayI/G2eRjqBfCkpwzmG3Il09q9IE5dCpsFhHqdL6Qd/hBva6H87ZL5fH0prcY/5JmR0bZwOwAP3hPWyAqEqKkvj6a9SnDTolL/eHuh2QQKjG5gBWfUJRFPWFEuEWtPyOBFlupYE58w7+76BG1SEfqUG6BDUy5hfLliabJbfXHnD9cvjUr4M2g5OTx2Ctza6UywzC3mkzpCPPzFrYG1r2c4LmaBKqJdXFOJ36YrODqo=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(39860400002)(376002)(396003)(136003)(366004)(346002)(451199015)(478600001)(6486002)(33716001)(45080400002)(82960400001)(966005)(6916009)(6512007)(38100700002)(8936002)(4326008)(186003)(83380400001)(316002)(86362001)(6666004)(66556008)(66476007)(66946007)(41300700001)(6506007)(26005)(54906003)(44832011)(8676002)(2906002)(9686003)(5660300002)(7416002)(67856001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?aL5dR+7Ne4BPbyJt55oK7YR4BHFYscMiofGoALtZeLbbEbuzWJLa3AgreId2?=
 =?us-ascii?Q?eCymeONfB3OSaorDiUlkh4e3VF0Kl/XiwerKNapDpUICHKUvD/qh4g+3froq?=
 =?us-ascii?Q?ekC1GB1ERrkor1XR711lWpAGoDV0kI5nyFN+hBlAvFoQzbT7O6NWZHruMdNw?=
 =?us-ascii?Q?PlP7/TrGAFSzOJ2OtH8tDJaIdsviKxk75CZFolCAeIH/U7cAgyLyry60jYVH?=
 =?us-ascii?Q?03Aujvm5AkZ0ITw71rkQwgnjNIr5rklMFXR2NXzc6foiclMz+T1ipspp/Wbn?=
 =?us-ascii?Q?kZVqbdyTj3ntJ5uJel31Fot0MwPd2YClbpgLO4JfDQ087vU3sD6NkcK/tkUM?=
 =?us-ascii?Q?JrzdneD6qSzHAfINzrELVIDKyM8ThZzAvyrpi06XoKvXsIk3WhcNJYEDdMig?=
 =?us-ascii?Q?RV6l4vkRffBlpBOK08SsVYneVgAGXlmL8KYbm1xs+/Z6MvM346Zk0UOlJPz8?=
 =?us-ascii?Q?GYQLF6QSqg6WAGz4UXi6UPY7sO+NGE9VA+e+4//CSXy6ehqfL2TIkHQtIoNu?=
 =?us-ascii?Q?t6ha1TFJXoClRLn1vxCJ8LpPhhKIbbHIQg8xnUDoxUQk61rxs7/pzyupLBQt?=
 =?us-ascii?Q?Q0UXvPDEBOvXDCO5xlKlMI8TJV7SeKHEig2jqbONbH7Xg30E28GvvKVwpkD/?=
 =?us-ascii?Q?iTgritIEVNkthWdNdPtcc5eGNC6jF8cCVqBBE5NMnctLbu0y9rz0K1S46MTE?=
 =?us-ascii?Q?BH/xrVcAHVYaR48QE61SNpRoe+MyIXJ8mjXEteQvVAfzZnCc5y5DCp1Nngpn?=
 =?us-ascii?Q?zBAqWmXk1i9Xz9l/oJBM2oDEwDFI5O7u/M/tl8D0qPp1UOkCgN/sREIbBQc4?=
 =?us-ascii?Q?6h5HFIRRu7pPS2hMd+7X+jo+YukX9ewALfWsasz9VhNxOu2Sc6YNnFpsklOd?=
 =?us-ascii?Q?A0Ostbo1sTiAOINjUl0fBnVroKLm+0N2x7uSSKQKJoVfrnMxzdn4yZcziOcw?=
 =?us-ascii?Q?ZrRx1W2kpyEdjVQZwq8DiBscfD+k3ay8x0SsKqzrrUHH911KOB2x/3Y5BkXR?=
 =?us-ascii?Q?aOyHXbErgfaagWvapWP/Y5Av5LMalgVEuFCPh95XcProYr5m0YfeZsdgjK0V?=
 =?us-ascii?Q?OYlwC4AUHdUbZxmuCOYihhGND3DYReQdGEG7cEkQ1zXof0RPwZl9Gug9MYLb?=
 =?us-ascii?Q?uaT0OdEvFnTo4HfDwu4CuqTrRBKCTwN8Y9SWbKhWjBSeaMaCdkW3xfwrKqIC?=
 =?us-ascii?Q?RABVMho3wA7N4cEYBRgwOU31qrdT7eKmJUTxDVtpVN++Ma8s1d58c8TxJvM4?=
 =?us-ascii?Q?a1bUKadUF5sKMhn0odL692b4ap6GxYaz+mf66/w++S8JfQlTJLVaWoREh3/8?=
 =?us-ascii?Q?7q1c9amvX4IBtrwPXISnhyTst/37hIrJm7MNYqGUM0zHUKFr+RmyYwvBQ3k4?=
 =?us-ascii?Q?0i4ExV/NO3JRq4trmzkBvo8J7p/LwDtJOtb/hTmYbC5lqW/xlA794qjiVt01?=
 =?us-ascii?Q?e1rLEAgI1040VJ1ZacLyRHt4cUfGbQ8Y3fSCsC7j9GKvfHjT+i8rnEtA3LpH?=
 =?us-ascii?Q?rxfXeGl5nVCoLioJW8cePHEtUUp8O1jCnciBaMk6epbEjQRe2bNJW8vrUsl6?=
 =?us-ascii?Q?RsqHkjAnfNPYxkNAVFFltvB8bKGFGU8sunI3HTL7?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 9fc455c7-354c-4c5f-a791-08dabd743a72
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 03 Nov 2022 08:20:12.2981
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 9GZzhDotdqARZam/1HO7zJbPp6Vv//sHUyuua21vW6/sz6IVRKS1c/krP/QTHgGyYKJNfzzTgVedZznrziKeFA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SN7PR11MB7565
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=EPTqjTFQ;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 134.134.136.24 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Thu, Nov 03, 2022 at 07:45:49AM +0000, John Thomson wrote:
> On Thu, 3 Nov 2022, at 07:18, Feng Tang wrote:
> > On Wed, Nov 02, 2022 at 04:16:06PM +0900, Hyeonggon Yoo wrote:
> >> On Wed, Nov 02, 2022 at 02:08:09PM +0800, Feng Tang wrote:
> > [...]
> >> > > transfer started ......................................... transfer ok, time=2.11s
> >> > > setting up elf image... OK
> >> > > jumping to kernel code
> >> > > zimage at:     80B842A0 810B4BC0
> >> > > 
> >> > > Uncompressing Linux at load address 80001000
> >> > > 
> >> > > Copy device tree to address  80B80EE0
> >> > > 
> >> > > Now, booting the kernel...
> >> > > 
> >> > > [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #73 SMP Wed Nov  2 05:10:01 AEST 2022
> >> > > [    0.000000] ------------[ cut here ]------------
> >> > > [    0.000000] WARNING: CPU: 0 PID: 0 at mm/slub.c:3416 kmem_cache_alloc+0x5a4/0x5e8
> >> > > [    0.000000] Modules linked in:
> >> > > [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #73
> >> > > [    0.000000] Stack : 810fff78 80084d98 00000000 00000004 00000000 00000000 80889d04 80c90000
> >> > > [    0.000000]         80920000 807bd328 8089d368 80923bd3 00000000 00000001 80889cb0 00000000
> >> > > [    0.000000]         00000000 00000000 807bd328 8084bcb1 00000002 00000002 00000001 6d6f4320
> >> > > [    0.000000]         00000000 80c97d3d 80c97d68 fffffffc 807bd328 00000000 00000000 00000000
> >> > > [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000020 80010000 80010000
> >> > > [    0.000000]         ...
> >> > > [    0.000000] Call Trace:
> >> > > [    0.000000] [<80008260>] show_stack+0x28/0xf0
> >> > > [    0.000000] [<8070c958>] dump_stack_lvl+0x60/0x80
> >> > > [    0.000000] [<8002e184>] __warn+0xc4/0xf8
> >> > > [    0.000000] [<8002e210>] warn_slowpath_fmt+0x58/0xa4
> >> > > [    0.000000] [<801c0fac>] kmem_cache_alloc+0x5a4/0x5e8
> >> > > [    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
> >> > > [    0.000000] [<80928060>] prom_init+0x44/0xf0
> >> > > [    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
> >> > > [    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
> >> > > [    0.000000] 
> >> > > [    0.000000] ---[ end trace 0000000000000000 ]---
> >> > > [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> >> > > [    0.000000] printk: bootconsole [early0] enabled
> >> > > 
> >> > > Thank you for working through this with me.
> >> > > I will try to address the root cause in mt7621.c.
> >> > > It looks like other arch/** soc_device_register users use postcore_initcall, device_initcall,
> >> > > or the ARM DT_MACHINE_START .init_machine. A quick hack to use postcore_initcall in mt7621
> >> > > avoided this zero ptr kmem_cache passed to kmem_cache_alloc_lru.
> >> > 
> >> > If IIUC, the prom_soc_init() is only called once in kernel, can the
> >> > 'soc_dev_attr' just be defined as a global data structure instead
> >> > of calling kzalloc(), as its size is small only containing 7 pointers.
> >> 
> >> But soc_device_registers() too uses kmalloc. I think calling it
> >> after slab initialization will be best solution - if that is correct.
> >
> > Yes, you are right, there is other kmalloc() down the call chain.
> >
> > Hi John,
> >
> > Will you verify and submit a patch for your proposal of deferring
> > calling prom_soc_init()? thanks
> >
> > - Feng
> 
> Hi Feng,
> 
> My proposed mt7621.c changes are RFC here:
> https://lore.kernel.org/lkml/20221103050538.1930758-1-git@johnthomson.fastmail.com.au/

Great!

> That series lets me boot the v6.1-rc3 kernel. I have only tried it with my config (as sent earlier). If there are other suspect config settings that I should test, please let me know?
> I used device_initcall, but postcore_initcall also works fine.

I'm not sure which order is better, due to lack of mips platform
knowledge.

> I rephrased Vlastimil's explanation and used it in patch 3 description.
> I have not referenced a Fixes tag yet (unsure which/if any I should use)

With older version, the kernel boots fine with soc_dev_init() not
being actually called, and I don't know if they also need to get
this called.

Thanks,
Feng

> Cheers,
> -- 
>   John Thomson
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2N4%2BdqhezRgk87k%40feng-clx.
