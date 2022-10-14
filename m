Return-Path: <kasan-dev+bncBDN7L7O25EIBBPXVUONAMGQELFLXSPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id AD14F5FE880
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 07:59:27 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id f14-20020a2e950e000000b0026fa4066f3csf1670079ljh.21
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 22:59:27 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tMWH9ktMgBMtItKTfxXWK9jxwte/LcjNDAxtfdbP/3I=;
        b=JfN60bPHCcgaHJrxAbTVl9eQ3gXsiqkr9SifzXwYBW3jNd02ecBQGQPX+Vppr9kN1L
         +frK2TEsGz70YT7O0J+kVGcxeH8/8jmPsjo/XXbaFAFqwt6UVj7u0IgvsaXVMijlrRtp
         aAXmoZRRlHyvW7a0I5dx4uNNZmNq8CwTlmPcToZjsLbTECdcAxjlFpHidHDDlzqZ5Z0R
         o9TctJQl3oeP2TVSz8l1W5qd4yzKY79S+Po/L+1CCYvdjJhOLNxAuP8V9YjcrzCqmZ6x
         SmZOgEayB0xZ7L9YKJT4Nk09GljgvHto+iZiVYi2n2qoHRagqh45Clk6QKf1JEeGLTtx
         K2iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tMWH9ktMgBMtItKTfxXWK9jxwte/LcjNDAxtfdbP/3I=;
        b=oZnJEBA+GiJxT185F+4/bS7EraB5JvrwalF6UQkxqcompCHx5nWnfDvFc7B3ZyGnDy
         r+z8cdzB7jR/SB7lGjbtQNLhn9qYPbilhZ/Zk89KpBpHx0vOAV2sYBitUOUq7P5JkCvv
         tej4T4h8OTkYyjoL+2QUCaXM4IPaZx6xFw6WTrIJ8Rs14op8A0Pe30dtRBSkMANUnP3u
         vn5ooKzM3MjYptGcZGVcpyaP/Ji4xCxqXZoiEL8Axp2ykqwfJO3BVpqurpz/tEm2WeHe
         XBkpM5PdHovVRi6fH0d17HVUOgXM9IRl357Ci3qLDNa4AZ33B5Fcf2Q5MUtoTnLAOQ+z
         TmbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf175EWp3I01O03Z2ydwJqZ6fpE4UZh64q00rbvNRIRsuC91joYv
	hjjdvs+rd8oHTuunU2icin0=
X-Google-Smtp-Source: AMsMyM6fBsik1RAah3xQofD2HAvcZbPcCmEud4Nq5B4uC5N0CBYmxqjifcC1oaNn/x1cCD5yqhMENQ==
X-Received: by 2002:a05:651c:210:b0:26f:ab6a:87f5 with SMTP id y16-20020a05651c021000b0026fab6a87f5mr1212529ljn.506.1665727166827;
        Thu, 13 Oct 2022 22:59:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2103:b0:4a2:3951:eac8 with SMTP id
 q3-20020a056512210300b004a23951eac8ls2496342lfr.0.-pod-prod-gmail; Thu, 13
 Oct 2022 22:59:25 -0700 (PDT)
X-Received: by 2002:ac2:5cda:0:b0:4a2:2436:112a with SMTP id f26-20020ac25cda000000b004a22436112amr1222518lfq.295.1665727165661;
        Thu, 13 Oct 2022 22:59:25 -0700 (PDT)
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id f14-20020a056512360e00b0048b12871da5si49724lfs.4.2022.10.13.22.59.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Oct 2022 22:59:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6500,9779,10499"; a="285019221"
X-IronPort-AV: E=Sophos;i="5.95,182,1661842800"; 
   d="scan'208";a="285019221"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 13 Oct 2022 22:59:22 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10499"; a="658470119"
X-IronPort-AV: E=Sophos;i="5.95,182,1661842800"; 
   d="scan'208";a="658470119"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by orsmga008.jf.intel.com with ESMTP; 13 Oct 2022 22:59:22 -0700
Received: from orsmsx612.amr.corp.intel.com (10.22.229.25) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 13 Oct 2022 22:59:21 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx612.amr.corp.intel.com (10.22.229.25) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 13 Oct 2022 22:59:21 -0700
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.106)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 13 Oct 2022 22:59:21 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=nndG1+gaQReMWg3msol5CrEML5REvj+kQAzI0CwG0gf8hxl7mqxGiSWTurg1PmovwIyQVL04NkVHzTmwJMdfJ4XMvJXCQ3RMJDhEKgkFs3W3lfpLcNxuOXfvvsjO8fIZW3WWIUVRTgpXrGoZQw0wcL/p9iO2UIVK+mtJf8iBtrlutIi6LVFpeZtC+JpUJVqR3OxgSjPiU4DAfQOphbkbR8ivNXY1gVWlKvKm1XmcfY1OYUcJcCF+Cc7ZW8h0nJ3BpSTNxHfP/w6fyYna6AxSaJC8TJ+Hf3N6ktfwGAyh685y9yyPSe+4FOgFf3QxVclQou1zAjh6pz4PaWDaRTtl/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=zA/9xWelJqryFKdUVCR5aCI3rZH6huCyHGC0HL6K9pA=;
 b=G8RH/t/E1HamyOf6C6zrUF5PjxyR2l+UvmqKoAhb7oIuNisitfx07BaZWn3jaBeCCbMRt1b9PSNn1kXO0/LIlbqvHBRgCtWMCKvG7qsy62P2JhP6DfsoRj2v0PN6I7ETGCqSE788x3TZ42q1Y++lJvjvg7YSNppVDUboctUt0iuj1PABAwelemBoQBuleg42Ep7P3QUzLiyjmKnk7L9WV8iYVSUy4ZYNRR8HfsI5L0X4H3AIEr7AwiuKRHtas6QL2D/CLRPZ32DtaTj+CCH+YAA77husHUDI23dd8vQid0knfo34pE4iY0QmUQTzbHgOGMpXKStmLFwU2fH8pvVjqQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by LV2PR11MB6072.namprd11.prod.outlook.com (2603:10b6:408:176::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5723.22; Fri, 14 Oct
 2022 05:59:19 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::3f8d:1406:50e2:7bcc]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::3f8d:1406:50e2:7bcc%3]) with mapi id 15.20.5723.022; Fri, 14 Oct 2022
 05:59:19 +0000
Date: Fri, 14 Oct 2022 13:59:03 +0800
From: Feng Tang <feng.tang@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>, "Hansen, Dave" <dave.hansen@intel.com>,
	Linux Memory Management List <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, "Kees
 Cook" <keescook@chromium.org>
Subject: Re: [PATCH v6 2/4] mm/slub: only zero the requested size of buffer
 for kzalloc
Message-ID: <Y0j6p1TSaLo18qQP@feng-clx>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-3-feng.tang@intel.com>
 <CA+fCnZfSv98uvxop7YN_L-F=WNVkb5rcwa6Nmf5yN-59p8Sr4Q@mail.gmail.com>
 <YzJi/NmT3jW1jw4C@feng-clx>
 <CA+fCnZdvqZzCU_LO178ZsPDvs-Unkh2iZ4Rq5Amb=zS31aWFpA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdvqZzCU_LO178ZsPDvs-Unkh2iZ4Rq5Amb=zS31aWFpA@mail.gmail.com>
X-ClientProxiedBy: SG2PR06CA0252.apcprd06.prod.outlook.com
 (2603:1096:4:ac::36) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|LV2PR11MB6072:EE_
X-MS-Office365-Filtering-Correlation-Id: bbe646c1-ce29-4ec4-5606-08daada93b84
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: VlZCsYnWVaxYbdtopn/rj7URkO+3LE/NYAtPgsWaIlZJtxQr5zY2o63bDN1SX2eWtlKjjbHS0Zg9d/6dlm3Ul1ymL7FvlvQuy53oDJ9CRg7W89h1BiDHYI7wSRBGwAGxKquyX/65MSypYg6kXSCoVv25XWaQ38+E55m4tdj2Nf3LjHz9FlDi2F1MULmZhm+1hK9svJD1Reg9GpA7c9wFZCiX0S+uV6p7BWsya3+t68jw/2nd0OaBWZKiLz70d7TwqOe5zW9+JrfqTQc8UBd5tcTzffhWaZw/i3qGUmrUSBOCWQbkq3yVdNRl69pfQe3KNxqjy5s0DIhoyYiu/CSJOyU2dEtlHI2EwU+QnjO+v8fO/INPPd7+QmbbJud6TIOKmmWqR+g0pv6WLnLWIqkLOocVghKitQOjWC8T852AQXVLlp7CX4RWlRZYFZgONGQczzlJ5gMSLYN9ZQOJhYQRVQoSJrTpc4s4fBW7Q5Tjc1wqYNCaoN9sfqEoywlzHgghlgt3LpdcpCn0V1kXajT99fC+vRfXlZB1M2ws4aq3V5gmKCUoDNXKJB1MvCJGXAUmTqnbrOg2Tm1f98A/gOeT+Cl6zsRK2fZ7XNPYl72JUo+EeTUWNRwtmuX4UkF0pLp7CMtHRLhSt9CAdBfiHuCg+G2iXffY+2WnCqj30c9sbEFUlFmIUxtXVY+ajiHoN8TMFj4xZDomWQpS1DK5/IU7wQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(396003)(376002)(366004)(39860400002)(346002)(136003)(451199015)(86362001)(2906002)(7416002)(6506007)(6666004)(5660300002)(44832011)(186003)(33716001)(478600001)(6916009)(54906003)(6486002)(4326008)(8936002)(26005)(8676002)(53546011)(66556008)(66476007)(41300700001)(82960400001)(38100700002)(66946007)(316002)(9686003)(6512007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uA82IrKNArHYl+N4bhxmcCdxMvo4aZkSyisI8LJiustWboxWfkVT6n/gGdv2?=
 =?us-ascii?Q?gxEYgcwe8X1b86Zxo+VPZmQq4H9u0t7+i8SB5WdDZU8OZB7jFcY+CdJO04uS?=
 =?us-ascii?Q?ux5fZqXdNr1YFwlVAhRvuffeWZElbzz+ofoMOO5xBy05qiCGImL3T7jU5Opa?=
 =?us-ascii?Q?ZI/aNWJ+b4CUaDQY550VGw2R96QULlQ9+dXrXLT+p3gfkssrpv8Pk9Nwo7s3?=
 =?us-ascii?Q?Jf8Z3Ae1dyWlJvoozZG+YaVmimRB8HeXrDQtJCj4VRohcIVDeaHQE1v8XQBD?=
 =?us-ascii?Q?AMQ704Otc63knbdgab0qtNs/YTn7b43Xh+xAcQH5ZUA6aucROJcHoOJCEHug?=
 =?us-ascii?Q?9EMz4JXcIsMrtHDy6Ow9DBmQm8TrxnAOjtYd0qJKRIe3MS5xEA3gRpJ4sl55?=
 =?us-ascii?Q?QgXEssL+++VstbmWBqtL+FSHu2hRTnwBTYeIrjzirllsGPx8MbZXWKj93buZ?=
 =?us-ascii?Q?4vNGovjZrnQNjogmDuhIrGWP7OvcXUq++YVAoJXi+I5aE1C0gXlaUvD3cSEl?=
 =?us-ascii?Q?Pn5CadntAwN2IshuBMm5Os5N12Oq0iSmvNvzoWt+Qjw1m5d0wOZQlJSkp9U0?=
 =?us-ascii?Q?/Mw2HXy+g5PgUYZgbhuUZqxIawmMDgXaOU/UTrp+oGJbLoAEbDMGUvITAI8B?=
 =?us-ascii?Q?oqzHprEa/KcxTJAfuz5ERV9F26LU4cU1/CHhH6u2PQv7TgNydSc2mv4CQTfr?=
 =?us-ascii?Q?g9Ge5bOwAIv6RJjQDwTtrjZH2YUa+tGzL2kgvXA2lQ7I6TMRls6lnc22L+cQ?=
 =?us-ascii?Q?awFAZ2LzhvLCyLP8RmFrSLW7t+gqu2FBlQwvnbJmT5zyqcJudHUQNMNIseV2?=
 =?us-ascii?Q?6dO+74Nt2aCCJXqcHU5BUtSG4cctqtX7RNfi7vLi7hh9nhshkL0uaFSYdUM0?=
 =?us-ascii?Q?nCENOYOk/tPIfD78So6E56Cw26YLxYYcQzKfkzWF89JuGtepZdGm3redZQMA?=
 =?us-ascii?Q?UGR3bti5eYVRYpH0c4s+8OYQyLnMDmYVcEvxvGFQlV0ccZwX9v+mt6WoKl5a?=
 =?us-ascii?Q?lXDEw3tXRN0PxzvdEmLikbHEBHbLjZWHLvz5Zra/1d/2QNoAcmqSe888iR6O?=
 =?us-ascii?Q?rgXlhFPdgxnj+yPARn2Gyi2d32VWojdL/f1tkE5poC+N+cLbbVj+o6YfLTaU?=
 =?us-ascii?Q?vXHmOwgG6KOQ6cUbiAUXFCPm+OZCCRfHrUgD5d0vjJV26uNkIiTwhoaYTgRO?=
 =?us-ascii?Q?Yf90bNE9svPMuvP1e++IM5b2oPhRo5fp6Uczrzv2HN/0PBja0jgjU9tHncpW?=
 =?us-ascii?Q?XYJxoWxb35gJBsNedFY11Z9Y5sg83ExBJiIbPNUaaYT3z3WvnNvnrOkIi3ZG?=
 =?us-ascii?Q?fmOhRGbJfT8rLQcp0QXhPYc2ZJf6sGP2jce/BdPupxL7qsvWhRZmw8PHYD6J?=
 =?us-ascii?Q?ijGWO4Y9QfZs1gA2NrdU+MFznhnZGmYbelZ7Y1In0lnkN7OtF6HRK5NSAWMI?=
 =?us-ascii?Q?AjeRJ6kuLvvR6SOCeqnRSqlVQtHtyHuJulHqTise1zaD6K6h/92lzbvGmVrS?=
 =?us-ascii?Q?Ph5Drmdzo2e6ZtYEuWoBV9bZySDpBn+lS5atzqh16HTqtA//rL5DVis9+XUJ?=
 =?us-ascii?Q?C5+84BTn7LUEV8I/18bSZULo9P+Fsw9u1xUncdnQ?=
X-MS-Exchange-CrossTenant-Network-Message-Id: bbe646c1-ce29-4ec4-5606-08daada93b84
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Oct 2022 05:59:19.0027
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: nZrpLUh4rQsByi6UH60w6o4kgnCH0ZD7uYuLFwAuctFaNZXTUe/PjU8PaSwmyEVl6fcowsmuc+Jf/cRTQMuYig==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV2PR11MB6072
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=WRfg9zim;       arc=fail
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

On Thu, Oct 13, 2022 at 10:00:57PM +0800, Andrey Konovalov wrote:
> On Tue, Sep 27, 2022 at 4:42 AM Feng Tang <feng.tang@intel.com> wrote:
> >
> > > > @@ -746,7 +747,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
> > > >         for (i = 0; i < size; i++) {
> > > >                 p[i] = kasan_slab_alloc(s, p[i], flags, init);
> > > >                 if (p[i] && init && !kasan_has_integrated_init())
> > > > -                       memset(p[i], 0, s->object_size);
> > > > +                       memset(p[i], 0, orig_size);
> > >
> > > Note that when KASAN is enabled and has integrated init, it will
> > > initialize the whole object, which leads to an inconsistency with this
> > > change.
> >
> > Do you mean for kzalloc() only? or there is some kasan check newly added?
> 
> Hi Feng,
> 
> I mean that when init is true and kasan_has_integrated_init() is true
> (with HW_TAGS mode), kasan_slab_alloc() initializes the whole object.
> Which is inconsistent with the memset() of only orig_size when
> !kasan_has_integrated_init(). But I think this is fine assuming SLAB
> poisoning happens later. But please add a comment.
 
I see now. Will add some comment. thanks!

- Feng

> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y0j6p1TSaLo18qQP%40feng-clx.
