Return-Path: <kasan-dev+bncBDN7L7O25EIBBWFQRWNQMGQEMSVWUZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FD3F617677
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 06:57:46 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id e23-20020a2e9e17000000b0026e8e74be94sf310534ljk.3
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Nov 2022 22:57:46 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JK8w2N0R7IdKFnm3gQIyeJXVIa+fPbFF3AnKdh/xN34=;
        b=RabwD6emtSy+d1uLIJqirkIPFoit6Ua+IT51VtUBJ6qz1WzpJ/oaUMWOFgSUZVlVNw
         pZS3609L/GWNwjkKWh60G2g8unMrj2zHF4IRXRx/pJM1ux2BQj6AAHEcm67VixLWHcn7
         N0Xt1uyfZQ+/BpyE1CqLuZpxeXywmyHb8juQm79JPlRVOJqBujNWWWi6+KbEZJ9IyP0+
         p0eIN9OGAXt/mDyTz0YMrXf8A5vrQMclVX0chq57EjvU0SIu+noQk7KKRSZemXl1mlJ5
         4tc3ad6UcuJwO4xpNl8Oc7PRHOnY1FCMbY3Sb6onPusVODYxmgIIyhIAEMc/Tn0JVgDb
         St9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JK8w2N0R7IdKFnm3gQIyeJXVIa+fPbFF3AnKdh/xN34=;
        b=Tkn8OA02sMEtqZ8K6pMaBNy/pjkBf7tlGSpQw6eOIuLduKEDPzYta5RYdBzPTqlX4S
         G2fCqkeD3oagjoBUSgjsjq07H3n6KTMefjVzefNyuAgOiXK5Lw0vVajbg3hkY1lRmWOr
         bByIMvya8+//I9tR4Hwh1cVGZARFH7qttyM9SfVEjFpD2djGBoc+U8FVLydCrH5RKMP1
         W0AK5IdIDUM18LaFmL1JdGt5gyB/WSdq7dzbCQghppRLdP5zO2wKKi2RMQaSsebU4V8Y
         3AYsFf/di7j1gFiPyYbym5bdxcGUFOQE21cSlHQAdG47YvQqb5g2Rl3vcKocxua7/NFo
         lkkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3ozwFEZOcKMVZg80GwoVNGs1pnO8lmXUN2grE14octiXxj/0Q6
	581vfKzYyTkR9xLU8HF2S0U=
X-Google-Smtp-Source: AMsMyM7oDPbuu2PERD+a/T9WFI3es4eB3deqCes37vO5TRz3hLSs6iRmd0acRYwW+BFEhtLDjwYYGw==
X-Received: by 2002:a2e:984e:0:b0:277:139d:78a9 with SMTP id e14-20020a2e984e000000b00277139d78a9mr11821865ljj.232.1667455065190;
        Wed, 02 Nov 2022 22:57:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1114:b0:277:a9d:9351 with SMTP id
 e20-20020a05651c111400b002770a9d9351ls143810ljo.7.-pod-prod-gmail; Wed, 02
 Nov 2022 22:57:44 -0700 (PDT)
X-Received: by 2002:a05:651c:160c:b0:264:a5ae:7dd2 with SMTP id f12-20020a05651c160c00b00264a5ae7dd2mr10960661ljq.80.1667455063968;
        Wed, 02 Nov 2022 22:57:43 -0700 (PDT)
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id 24-20020ac25f58000000b004abdb5d1128si375397lfz.2.2022.11.02.22.57.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 02 Nov 2022 22:57:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6500,9779,10519"; a="310707783"
X-IronPort-AV: E=Sophos;i="5.95,235,1661842800"; 
   d="scan'208";a="310707783"
Received: from orsmga002.jf.intel.com ([10.7.209.21])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Nov 2022 22:57:41 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10519"; a="634541468"
X-IronPort-AV: E=Sophos;i="5.95,235,1661842800"; 
   d="scan'208";a="634541468"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by orsmga002.jf.intel.com with ESMTP; 02 Nov 2022 22:57:40 -0700
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 2 Nov 2022 22:57:40 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Wed, 2 Nov 2022 22:57:40 -0700
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (104.47.58.168)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Wed, 2 Nov 2022 22:57:40 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=IeCAuZGG1rmvhtRaRjoouBfa99Mr6BsAtepw6tTU0Lb0dge1lLfANGQvgwBIllrQUBdQEqWZQamPQi2tXkDs4h9Vjaaz/xETxkLefGvYCsaJ1ILwgupJrROxScCbLfyJlPBK/lLWRrixTgRvAe8fRZDRD1ltzJXTtZUtGPQ9bHk2fPVMiiKtgVk9l1KrlTnfVG+GCVuuPhqTN+MONDD10+BLRQjBS+3rKbj9aCddHoxS54N2280cRGwFR9RVv2NM1tHdmlntyd1jB6yMA8GY5cvk1HgiZGIP+yyx4NhH/xJdRWeaSevb38/zb/uRC2v3klr64fDD81HQUH8KEsa2Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=m3M98at0EBU1qFE2VHRHDEjZPviDTefFawf+xmHNPKY=;
 b=FaMDcabrkvoWRIVO+qbzQC6ek+T0Ip84a+UOAqs+/ver3/7Jpxe1q/tqU9DeFkpjfb3K/A+F/KfblQtxDh8EBJtjnqSJEBhjGhwk6GEHNLYRthEddRRExjtc1jDsDlNVhxH+MeG+mr9Na2Lf9VgIgc05rQT1EXKMAhVIRX3W+lj38mmoagpbG8Ivl6T65aAf5unhFZ+d9i/9PPegj+0kiq1uJo2lkjTosLingHLmFGSVzkYjBjX8ZH/PWnsN/pjyTBwKWnfXFLhr0JTflCkvzZBp71q17CuQjVcYabQS8RFc9DzD2xDg2niBDRaBwFpUAJfdD4SXVzkMIG1AK4O/vg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by PH0PR11MB5127.namprd11.prod.outlook.com (2603:10b6:510:3c::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5769.21; Thu, 3 Nov
 2022 05:57:36 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b%3]) with mapi id 15.20.5769.021; Thu, 3 Nov 2022
 05:57:36 +0000
Date: Thu, 3 Nov 2022 13:54:18 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: John Thomson <lists@johnthomson.fastmail.com.au>, Hyeonggon Yoo
	<42.hyeyoo@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Christoph
 Lameter" <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Dmitry Vyukov <dvyukov@google.com>, "Jonathan
 Corbet" <corbet@lwn.net>, Andrey Konovalov <andreyknvl@gmail.com>, "Hansen,
 Dave" <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Robin Murphy
	<robin.murphy@arm.com>, John Garry <john.garry@huawei.com>, Kefeng Wang
	<wangkefeng.wang@huawei.com>, Thomas Bogendoerfer
	<tsbogend@alpha.franken.de>, "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y2NXiiAF6V2DnBrB@feng-clx>
References: <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
 <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz>
X-ClientProxiedBy: SI1PR02CA0025.apcprd02.prod.outlook.com
 (2603:1096:4:1f4::13) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|PH0PR11MB5127:EE_
X-MS-Office365-Filtering-Correlation-Id: cd32acd4-f9a6-4d48-1b45-08dabd604ee2
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: mpCQQPGViYzWQHAdgxiZlnZPIdUgsAmSunnF6UPb/pnQ/x2VFxTGBDMx84DawsnUDZkcF77bB/TnbbExbIybplv4UtDi3nVm3s3Vpjq3VIHRcwNl4NC7b5ubr4EfFszdkSw2zvBpU9iCwldAio2mneDZmxOnyAwAFRZTbuQewyYHLAdtcq4MS1UYl7l7OR0ixWw6YtaesvXn9u349XS5qSdihMIijjfB2o6637d5R65gM9iimClitTGebQPGyY7KCMAh5dvZckI5Oz25/5b68dlvBTZYxf3BWAyNQpP8w5m3mNK8GOaO25SVOD9NLdYwtKhea7MlIKIY/52vcCq+swwzWwcWDQE15UoOTchce6ENIEaoo38Do0pBHyNePFpxkkg30i5ynKkX6qFtd0c5ydAS8JNULDAwEhKttQMnnTFLFuZ8OqDTn/ORTDNxPmfaYb2Luv0k24ckAgIYv742n412Hdq01ct2OJ0f06EBh8n86s2kc95+yrZrQoyb87K93c1OmBPVmbb/wGNqawq1d93NX2RCUuolxQ69fIkjhKMdheaHi8HzoAThXRn1nsFwXmJWZ53Xr3W4q4fB8bMzE3QrikavYOeZCPsXtHxUtupnONwgNZ2riDAQYrP9F7cUlf3YAlrXaKSZlVymk4dCC3dPzUjXa5XHibSJvEN9SrtvcaZ77yuVOBekYzZdB/OFaDaQaGoRYlUv58fVZrk4Yw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(376002)(346002)(136003)(39860400002)(366004)(396003)(451199015)(6916009)(6486002)(478600001)(41300700001)(26005)(6506007)(53546011)(66476007)(4326008)(66556008)(44832011)(66946007)(2906002)(7416002)(186003)(9686003)(5660300002)(6512007)(8676002)(8936002)(316002)(38100700002)(83380400001)(82960400001)(33716001)(54906003)(86362001)(6666004);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?F1g85QKyX+Gig6B3qCGxhbdsMEdmExNFC/wqpo5gJhXofMm8IZbfinBaoS+O?=
 =?us-ascii?Q?rdcQRfWZkZgj/6j/ebdvCaDMt8j+8DlQtfXE0+3mQGTuHtKVNISupFmDqKUW?=
 =?us-ascii?Q?lDOeefzuMbxboEv0tpS1m/9CWek+aFa3gwuwPPyySr951cMBg3vDHzb7Lm5D?=
 =?us-ascii?Q?8uCJo0qJxH72MZ7yg2yfF0TgNitFac98JjVvXP/8o7KQiPAeyq1Ls7k54ipn?=
 =?us-ascii?Q?MfEVhNAaRyc8Zb8XudZuyaREviopSz3VOxheP+/9GAi8F9GEOU5BiQT6pk77?=
 =?us-ascii?Q?dubewbz1QLhVZMNcrIj04PMAGo7LdszNqSFO3ISlmk8JM8WO3zDk0ZqdvB9+?=
 =?us-ascii?Q?RKiV1jbFbyYrPDZsA0BREmb+J9VmYW9L+UDj38Y55F+AXZ8O9Mh7eFST3lXQ?=
 =?us-ascii?Q?xXAeVpKcGVmxEy3d0Efd7r/EJqJbEry7097YptdC4L2uw4OLFEg0gZyAOiLh?=
 =?us-ascii?Q?Om0dxxwGAUqV5VUAbNhMSkubw/IFDxz8/dDJ3D79KBxxQ68LNIGYYpVEF/jQ?=
 =?us-ascii?Q?X4HWmgY0whm034D9F3KMywAy9/OfYtAELGKrcj5jCNHr0+hxGBp7VJat+fLB?=
 =?us-ascii?Q?81X5JkyA66+fmZ7xfsiGrppUmpc7VOdzoLgLNGIHrUT5lRy7VMYaqR7z/Wjk?=
 =?us-ascii?Q?bKFEDGmwQ74voFv9quHzO75QGh3tAqqnjRMJ9R3/NESSLj14URmsbPsognwN?=
 =?us-ascii?Q?6kfPJO06b/XNqri/6ZISYYIBtcVod9Knbvq8UY8zqMzzMwwtF7LKnd7ae7//?=
 =?us-ascii?Q?j2HNKIJoF4r0hNuFb+3K+aq43x547vIhQYZCgsLU0v0xbiOL23OvUf8Yuoqj?=
 =?us-ascii?Q?PkestRBeWN9/0+HUnGKOelJ6+vm5zogBBmvQRrYnW6lS4ZqYT8F+7eWW8stM?=
 =?us-ascii?Q?k4lB9f/MOVjNevplOmMWY1YU29n1VkVNyTXzqwGiHAQi2m+L7Fk6FvQMaSn5?=
 =?us-ascii?Q?s5CHcz3E6Sve3b1wIrBQUKoSZDy/cSIrIe4U8mHD0KgQF39kljUd4lUWMQdf?=
 =?us-ascii?Q?sIWkKd7TfhNX5jrI2CfiFa/pjfDPDsXYBdHjp8sowqbuQleJl6VWkLKvcDUV?=
 =?us-ascii?Q?7ypne5dFdN3p7PXn97FpzJtADs2K7EynamL7F4gQeuYR3PGSGwCpfpUA6ha8?=
 =?us-ascii?Q?NEhSDuB1S5dFu3VEITbxAxZeBGziFNHoPK8fycT8VEy3E2bo8O6PlgtjXKWm?=
 =?us-ascii?Q?Jo7ZqAueOh9MiurIWfbowZ4NJutsP5/9nrBWcygOO/yumXI0IYDC702B3y/2?=
 =?us-ascii?Q?SFhF5mY5LjA7/K4ot4/j6785/ZRnkV76gbbTKzd9Gkt0Fwo4v3nyScvZ8/o0?=
 =?us-ascii?Q?Z7Fe/5kVLsr0Qe7arcPWnrL4D9dq5C8PUDIbIU/eo9tukU6sSbYUNT/s82Hd?=
 =?us-ascii?Q?zVhmhdhGcStf4q1VeVqk7xgwnarqvOLMjVjlcqTj3u8BkYbm6kHiAS0go/N2?=
 =?us-ascii?Q?Bm2uQdwNAUQD5v3qokchOt8LfIZGOL57EwkVk6Tncy3MKqv5bxzy4OkHw2JM?=
 =?us-ascii?Q?Wd3ureUYlC81ovSTXLzzvWodW69KEW1KY/a0RBjMzNu7MZHUtXLkizWoFoAP?=
 =?us-ascii?Q?R3AReiAj1QSYQ+tku3dzZK1CzjxMOvKeUD5+4uMm?=
X-MS-Exchange-CrossTenant-Network-Message-Id: cd32acd4-f9a6-4d48-1b45-08dabd604ee2
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 03 Nov 2022 05:57:36.6484
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: e2aQgi7/C+zsY2l1DqoZoDrAmxNwfbBAKS08OB7TArHrP6XA0olmGuus1hb1BQpLWyhiKSp2j+ZhNaJvlg1yrg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR11MB5127
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=giMFOtgx;       arc=fail
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

On Wed, Nov 02, 2022 at 04:22:37PM +0800, Vlastimil Babka wrote:
> On 11/1/22 11:33, John Thomson wrote:
[...]
> > 
> > [    0.000000] Linux version 6.1.0-rc3+ (john@john) (mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0, GNU ld (GNU Binutils) 2.39) #62 SMP Tue Nov  1 19:49:52 AEST 2022
> > [    0.000000] slub: __kmem_cache_alloc_lru called with kmem_cache ptr: 0x0
> > [    0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 6.1.0-rc3+ #62
> > [    0.000000] Stack : 810fff78 80084d98 80889d00 00000004 00000000 00000000 80889d5c 80c90000
> > [    0.000000]         80920000 807bd380 8089d368 80923bd3 00000000 00000001 80889d08 00000000
> > [    0.000000]         00000000 00000000 807bd380 8084bd51 00000002 00000002 00000001 6d6f4320
> > [    0.000000]         00000000 80c97ce9 80c97d14 fffffffc 807bd380 00000000 00000003 00000dc0
> > [    0.000000]         00000000 a0000000 80910000 8110a0b4 00000000 00000020 80010000 80010000
> > [    0.000000]         ...
> > [    0.000000] Call Trace:
> > [    0.000000] [<80008260>] show_stack+0x28/0xf0
> > [    0.000000] [<8070cdc0>] dump_stack_lvl+0x60/0x80
> > [    0.000000] [<801c1428>] kmem_cache_alloc+0x5c0/0x740
> > [    0.000000] [<8092856c>] prom_soc_init+0x1fc/0x2b4
> > [    0.000000] [<80928060>] prom_init+0x44/0xf0
> > [    0.000000] [<80929214>] setup_arch+0x4c/0x6a8
> > [    0.000000] [<809257e0>] start_kernel+0x88/0x7c0
> > [    0.000000] 
> > [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> 
> The stack means CONFIG_TRACING=n, is that right?
 
Yes, from the kconfig, CONFIG_TRACING is not set.

> That would mean
> prom_soc_init()
>   soc_dev_init()
>     kzalloc() -> kmalloc()
>       kmalloc_trace()  // after #else /* CONFIG_TRACING */
>         kmem_cache_alloc(s, flags);
> 
> Looks like this path is a small bug in the wasting detection patch, as we
> throw away size there.

Yes, from the code reading and log from John, it is.

One strange thing is, I reset the code to v6.0, and found that 
__kmem_cache_alloc_lru() also access the 's->object_size'

void *__kmem_cache_alloc_lru(struct kmem_cache *s, struct list_lru *lru,
			     gfp_t gfpflags)
{
	void *ret = slab_alloc(s, lru, gfpflags, _RET_IP_, s->object_size);
	...
}

And from John's dump_stack() info, this call is also where the NULL pointer
happens, which I still can't figue out.

> AFAICS before this patch, we "survive" "kmem_cache *s" being NULL as
> slab_pre_alloc_hook() will happen to return NULL and we bail out from
> slab_alloc_node(). But this is a side-effect, not an intended protection.
> Also the CONFIG_TRACING variant of kmalloc_trace() would have called
> trace_kmalloc dereferencing s->size anyway even before this patch.
> 
> I don't think we should add WARNS in the slab hot paths just to prevent this
> rare error of using slab too early. At most VM_WARN... would be acceptable
> but still not necessary as crashing immediately from a NULL pointer is
> sufficient.
> 
> So IMHO mips should fix their soc init, 

Yes, for the mips fix, John has proposed to defer the calling of prom_soc_init(),
which looks reasonable.

> and we should look into the
> CONFIG_TRACING=n variant of kmalloc_trace(), to pass orig_size properly.

You mean check if the pointer is NULL and bail out early. 

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2NXiiAF6V2DnBrB%40feng-clx.
