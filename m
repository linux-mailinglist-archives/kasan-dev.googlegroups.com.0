Return-Path: <kasan-dev+bncBDN7L7O25EIBBJ6GZGMQMGQERXGODVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C6755EB7D8
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 04:42:48 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id b5-20020a05600c4e0500b003b499f99acesf7959066wmq.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 19:42:48 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=QZN2epYTjAnlgbR2EsLyK7AOj9HOJTIUj2umH07O24I=;
        b=XmugTJ1vgytzdwYh6rdcwWTm+25aqIElXOvzZueAyn1p1qPnm1ZNaBnTecIwCpfc9V
         WpzZMCIaxMpVzpSiqbBNCjxx4DNph1Qz3ZKRaCQVSzpnjq76uhNzkMiZBR63V5gGiXn0
         nKoDHOIcXQQGg6VquH7njt2Wk2Xsyc4ZpknecLiYX/Vlx8UWLlvVD+aMN3P95bJsTBd4
         DrjZTzLc0giwtiA1LE3wlYgs4YWdhmzzo9GfTg9xrRBw7T0R88O7vcvv/gtFMSZBRRLh
         LfQ/fYy2kuGhYbxpFaZRm8EktfbnWwy2+NAVp1kGKcXxl5KUCzQjpZnITkhuTubMRica
         F4lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=QZN2epYTjAnlgbR2EsLyK7AOj9HOJTIUj2umH07O24I=;
        b=fN/BKdu+upYc5+VFJyZKvNutjx4DffFGEeXomuavlAoaVTQ7pWyJpWH6L7LYDxVfBf
         8BzUj2k7iZSApcNPqxEdIYyQM4MfZd2M9L7bNQGJ3n6esfEihJ0c2J89nmSYbjrRcF61
         T4d5Bz8McJ+5OhJv3etPqgO4SfbAHyb95UVkJENsJ4Mns/9BY5xW51OO9oMCjFyaa5Pc
         94G18usjsNTBSUR6r0f0ooxP2fVW4JbVSOv+9E5NnupTSSgovtBsEiWwMq5CBgbtSD5U
         2TApwQRmL6dKNhCl4EZt+lG8jcHJvf0jsK/HOBhIpishxKrEgZHeUbEVwAyo9OnioSfi
         gH9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1iHT7p4XlKOHO46ri+hLcZT7Q6yuXmf0K5bPQnELZMLIprvt6e
	221psP2bCSuLK/XNIusVA9k=
X-Google-Smtp-Source: AMsMyM57mcMJAKOAFWRt9j+tfgUnGsuebmYG34TVNXKsjuUCeilcl31k/tFMkbp7iYu2YKo+fjFjkQ==
X-Received: by 2002:a5d:6dc1:0:b0:22b:1256:c3e5 with SMTP id d1-20020a5d6dc1000000b0022b1256c3e5mr16197198wrz.336.1664246567840;
        Mon, 26 Sep 2022 19:42:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce96:0:b0:3b4:a307:9032 with SMTP id q22-20020a7bce96000000b003b4a3079032ls332087wmj.2.-pod-control-gmail;
 Mon, 26 Sep 2022 19:42:46 -0700 (PDT)
X-Received: by 2002:a05:600c:19cf:b0:3b4:c8b6:15c6 with SMTP id u15-20020a05600c19cf00b003b4c8b615c6mr977274wmq.85.1664246566804;
        Mon, 26 Sep 2022 19:42:46 -0700 (PDT)
Received: from mga09.intel.com (mga09.intel.com. [134.134.136.24])
        by gmr-mx.google.com with ESMTPS id l129-20020a1c2587000000b003a5a534292csi19838wml.3.2022.09.26.19.42.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 19:42:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.24 as permitted sender) client-ip=134.134.136.24;
X-IronPort-AV: E=McAfee;i="6500,9779,10482"; a="302103701"
X-IronPort-AV: E=Sophos;i="5.93,347,1654585200"; 
   d="scan'208";a="302103701"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 26 Sep 2022 19:42:44 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10482"; a="683802645"
X-IronPort-AV: E=Sophos;i="5.93,347,1654585200"; 
   d="scan'208";a="683802645"
Received: from fmsmsx603.amr.corp.intel.com ([10.18.126.83])
  by fmsmga008.fm.intel.com with ESMTP; 26 Sep 2022 19:42:44 -0700
Received: from fmsmsx612.amr.corp.intel.com (10.18.126.92) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Mon, 26 Sep 2022 19:42:44 -0700
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx612.amr.corp.intel.com (10.18.126.92) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Mon, 26 Sep 2022 19:42:43 -0700
Received: from fmsedg602.ED.cps.intel.com (10.1.192.136) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Mon, 26 Sep 2022 19:42:43 -0700
Received: from NAM11-CO1-obe.outbound.protection.outlook.com (104.47.56.175)
 by edgegateway.intel.com (192.55.55.71) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Mon, 26 Sep 2022 19:42:42 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Gwdx2lcKmp37sWrEkWUu4zMRUfwP3SSkdHbNcEZqj5/REEW1fIB5LsBD8sCQY7IaSDDxaix8Hg4IOuLWgAMPdFTeuV+76t+3kRnQtd139j9sRaQASLP2BG/ubPsQRNv9sfwRdJ2LZxyTda0elxcsfwcxOKoG9TlFThvbbutenPbNCQHY11+ohVPq+fYx51iZcY/qfJZdZOxQyPv2tQ8s5BeIuHtNSENVuei5r1IPF76Zmmjn9ygJ+wLLvw510E9xVgRVi1nm0XNwd0/6L+CY9gqOzviYZTzCq07fRmnAwUXr0aTYeonHQZFhO68z/OoKVY9W7Da7XtywYynSkfgMpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IP/gjSm/m3YqoWtwRK7Qun82te7Y51Y3IJLUJG3FZSc=;
 b=DsinSqigkfxWdoJVS9JWXgEZq34wurr1Srm4k4AgmwQOT+DlyQpQccuLmh1ypJBXothNjo9x38CDRFLA0rVk9XxVTZoGwPLfDGcAnDwK6UQVlXjQ/StTuk1/FYeMWWgTPIokNLLZnpZU7HTumwhpisRk9C+7QYrqOcQ85j7sAIWVqmX5Y1biJOYiDw6QNWjtjmfxUx4DLnqLr+cqmHPKwn/1JMDsTnvaMZZd+1VlaMl1uCnPjMXbwYBlyS21omH0qhQXrpTegpFy7JzRGaQfc3/VJ/1aNIz9HRdC6YdTdKqvgEPmTZRapp/XOCHAbxanBS4QriQ16cVwGwrUos/+Mw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by MN0PR11MB6033.namprd11.prod.outlook.com (2603:10b6:208:374::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5654.26; Tue, 27 Sep
 2022 02:42:39 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::ccec:43dc:464f:4100]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::ccec:43dc:464f:4100%7]) with mapi id 15.20.5654.025; Tue, 27 Sep 2022
 02:42:38 +0000
Date: Tue, 27 Sep 2022 10:42:04 +0800
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
Message-ID: <YzJi/NmT3jW1jw4C@feng-clx>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-3-feng.tang@intel.com>
 <CA+fCnZfSv98uvxop7YN_L-F=WNVkb5rcwa6Nmf5yN-59p8Sr4Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfSv98uvxop7YN_L-F=WNVkb5rcwa6Nmf5yN-59p8Sr4Q@mail.gmail.com>
X-ClientProxiedBy: SG2PR02CA0057.apcprd02.prod.outlook.com
 (2603:1096:4:54::21) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|MN0PR11MB6033:EE_
X-MS-Office365-Filtering-Correlation-Id: 40c91d59-3440-4c7c-001d-08daa031f105
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: O2ywnQ+4HwgwvsBxhD/SOvTeiWqbdZCL8x/vk5KkbXOlTe6iiKrdgxb6ej0XYnvFQNb0OyeZTQS1P5jgg30pEXow3qPbaQGzr0oQ/S8l2HGrdO/l2IyvMomon7IQ2hO1WSx9rhaO6vMsmYZ8TzY6bm/lWnN8IrCL0uFRLFBZhei+c2UxPkNfRQCKM9XRW4ny0ZNlgooZmta8kSnM94d8CPoWRTpQBLIX3Kpo/f1YnvWpyqtKipJoAUEXSYoD3Bg+eb/ulJNHpxh3pEzzUCx/yxzgjESc+xeRGJqEN93Auqq7RrG9scldw9R2Cu/Zg8z3YFPW0KNuYwx3fy8EeBkCt+eALHecP3HOqayYLBPhk+ZwMmrmd+oSzyGqv32dez3s5Ptd5U84exSJL7qy2pMuKy+lbMkkT/LVDHXmqHzq7LUQ7xaqlfdL32AXRiPq080R4GE6HlbI/RKnRCC8sWdKq9OBnC4DRvmbY5p2gJhz2Y8kVE6VlZX3wT2sgpFe51bBw3wG3fhQfCipf6K8IefvpJ0a556HIc2gKaYJgR2G1J2Nai/uhttUVmHpCTLgMEWLD6mIF3xb7XLDuLadBT3g3lNEYmNkJvawztpxMzH8m4oO//m4r+Q9OcORyLs4jfgIDSwAsIDqsFGPVG9gWTdMJvIvMGmoZWEJdZORBjLsa3UvkpjyFBhIs9MZyCfLO3QVM2ajRSNAhTw62rQ+fyJJEg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(366004)(376002)(346002)(136003)(396003)(39860400002)(451199015)(5660300002)(66946007)(8676002)(66556008)(4326008)(82960400001)(9686003)(6512007)(26005)(33716001)(44832011)(7416002)(83380400001)(41300700001)(6666004)(66476007)(53546011)(186003)(2906002)(6506007)(8936002)(38100700002)(478600001)(6486002)(316002)(54906003)(6916009)(86362001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?hcLik5lu73V11U7g5Dr37BW9t18rppbBo2Iwe+70cW9G4eCQTK9HmBxk4HuF?=
 =?us-ascii?Q?wu9EPhyr1d6cHPGnb+xHpZF0jGAg2gY9n1ov1tbfIgcY5hqsM9fJCYjr7N/N?=
 =?us-ascii?Q?+9DUzLjYSXHLfh8qiAGpqWT5ypRdrwKe1oupBvhUWKrEHL8hSd7V87FgRlLW?=
 =?us-ascii?Q?6eUHCS8ECm7mbHY8jIzzH+nWvzRrLheCMNlswwt5lhU2IQmTe+W8/f03oLdB?=
 =?us-ascii?Q?fNmDheZ52MZ1F7QQnpZqDX2NnXYnHxIMz7TVPwxMqshBaEdZ/3TuPm3rwAKo?=
 =?us-ascii?Q?8pjyYwz7CGa17CFVdpkZUq4kp1HWamc1FVOfqw3zLZRHqfPyD3Iob9JCVgBI?=
 =?us-ascii?Q?dHp53PrLG9DpF2jPBUaSVGWjl51a1k/2Sw5CmPneIHbyhlxSHj3r3kCNzqPI?=
 =?us-ascii?Q?sivtyHbed+lVXB5TDupJNQCrXfcR0eRi/KCZSkJEHOHQ006HrRDXUZ/uHC6Y?=
 =?us-ascii?Q?3sxv8zMPYiZAPSejDMG1zmkaLjPzdDyeVUvm7ueEPRLMlSVDnOMmx9h83/e6?=
 =?us-ascii?Q?P1yRA/9GV3ORsF0fQ68YJPc4eX7bqzOmywztU9rkCELN7W9MbM5KTDfnowiz?=
 =?us-ascii?Q?+rCMMDdX7pKH2YwkqnCmx0oR8e+XekrNxV6xmGkcFRp22/jDQ+MD3WdcBV77?=
 =?us-ascii?Q?lcPRFLi56KjkOS2kyuZYcWnuogToHbtKxjX0TOCOiTGcKKvDJroCGhqhkeVw?=
 =?us-ascii?Q?AiQH5KLYKaJFzahA8AZQlabh2osHYDqJfSXOHcbOtrwP2a1x9+zEGiWAGX+4?=
 =?us-ascii?Q?mCB18XQT6DkDKNZh1bxNFGBpBdczPvmW4smDypPQM3gh9fukIADvyQRCfRLi?=
 =?us-ascii?Q?a25BaRQR3BlK13Zuo8jptgbnvnN43hVmo4Y/QnMnI48anFL+RpUbl/e69C+V?=
 =?us-ascii?Q?urzElOORDyaVbheZIL9RhQ82rUauuXPCfKRTIOmKwTjOIbatpPKpmLu4RoMY?=
 =?us-ascii?Q?2/5XruILmiZdATUIyVLJmyZL6+rT0N+r7dC0veBemCFuLrQqoX2GxAQ50iDD?=
 =?us-ascii?Q?YasM0XCqiMFG/CoDu3rKPLwBf0vlmC2UilbSbwgrtHUDs4n9Wne3C5ubEZGV?=
 =?us-ascii?Q?tBtjTizKP6CpbKkTzjMeKQLpOHS6uD7z2H6Q7M54LDsuzZhxhDiq5D0ishqc?=
 =?us-ascii?Q?jXkmx6OXEad3rJT7a6NV0fU06NiBvDklfehnQApLHxPYy/oRtI+0JxIYPrHK?=
 =?us-ascii?Q?wxo33kvhU/s1yGt7f+G5y//KjF9iX7H14zzjszfh531IEIHYCdV4MEzkpDKG?=
 =?us-ascii?Q?KQ+wfU2F7H65CxFjwpr23l2xSDY/+UPiHalEac3g6SuPNxZX6uXBBd93nhq1?=
 =?us-ascii?Q?YA25tPzpizsUCM+4Oc38NKohQLYHo24W/I0687jFWxsaGeSVybVq4TqogkvH?=
 =?us-ascii?Q?Gt12K/wkG7dRqVb/kYonb2QqsDxEuH6A3iGQHOTzJF+TwrZOfBKcCPe4XOyw?=
 =?us-ascii?Q?1U1KS0LUjf6BVhqJSRrkhvXYCqyNH/+fPw6HknikvaeTTtx1Ve/oSv6bmMVY?=
 =?us-ascii?Q?3wXuaCYsQT5Q1uEzPh1kZGr/Njmm8qkjPlUHJWyekDScghNdQllMhX3vcUJk?=
 =?us-ascii?Q?6jLP2QxSGWXLwarqG0J8Dx3cY5Jd5XXPDbzsYsVq?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 40c91d59-3440-4c7c-001d-08daa031f105
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Sep 2022 02:42:38.7886
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: onETR1kvd+ni7K2UUPC2h/2SGgrBWUTPdDK8Gndt+RmIYFYvHk1I8X5lJPfkdX9xZuKlWh5lULPg4+C3XyA5Qg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN0PR11MB6033
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=FWYs7II2;       arc=fail
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

On Tue, Sep 27, 2022 at 03:11:24AM +0800, Andrey Konovalov wrote:
> On Tue, Sep 13, 2022 at 8:54 AM Feng Tang <feng.tang@intel.com> wrote:
> >
> 
> Hi Feng,
> 
> > kzalloc/kmalloc will round up the request size to a fixed size
> > (mostly power of 2), so the allocated memory could be more than
> > requested. Currently kzalloc family APIs will zero all the
> > allocated memory.
> >
> > To detect out-of-bound usage of the extra allocated memory, only
> > zero the requested part, so that sanity check could be added to
> > the extra space later.
> 
> I still don't like the idea of only zeroing the requested memory and
> not the whole object. Considering potential info-leak vulnerabilities.
> 
> Can we only do this when SLAB_DEBUG is enabled?

Good point! will add slub_debug_orig_size(s) check. 

> > Performance wise, smaller zeroing length also brings shorter
> > execution time, as shown from test data on various server/desktop
> > platforms.
> >
> > For kzalloc users who will call ksize() later and utilize this
> > extra space, please be aware that the space is not zeroed any
> > more.
> 
> CC Kees
 
Thanks for adding Kees, who provided review from security point
of review.

> >
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > ---
> >  mm/slab.c |  7 ++++---
> >  mm/slab.h |  5 +++--
> >  mm/slub.c | 10 +++++++---
[...]
> > @@ -730,7 +730,8 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
> >
> >  static inline void slab_post_alloc_hook(struct kmem_cache *s,
> >                                         struct obj_cgroup *objcg, gfp_t flags,
> > -                                       size_t size, void **p, bool init)
> > +                                       size_t size, void **p, bool init,
> > +                                       unsigned int orig_size)
> >  {
> >         size_t i;
> >
> > @@ -746,7 +747,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
> >         for (i = 0; i < size; i++) {
> >                 p[i] = kasan_slab_alloc(s, p[i], flags, init);
> >                 if (p[i] && init && !kasan_has_integrated_init())
> > -                       memset(p[i], 0, s->object_size);
> > +                       memset(p[i], 0, orig_size);
> 
> Note that when KASAN is enabled and has integrated init, it will
> initialize the whole object, which leads to an inconsistency with this
> change.

Do you mean for kzalloc() only? or there is some kasan check newly added?

I'm not familiar with kasan code, and during development, I usually
enabled KASAN and KFENCE configs and did catch some bugs, while 0Day
bot also reported some. And with latest v6 patchset, I haven't seen
kasan/kfence failed cases.

And for generic slub objects, when slub_debug is enabled, the object
data area could be already modified like in init_object() 

	if (s->flags & __OBJECT_POISON) {
		memset(p, POISON_FREE, s->object_size - 1);
		p[s->object_size - 1] = POISON_END;
	}

slub-redzone check actually splitis it into 2 regions [0, orig_size-1],
and [orig_size, object_size-1], and adds different sanity check to
them.

Anyway, I'll go check the latest linux-next tree.

Thanks,
Feng



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzJi/NmT3jW1jw4C%40feng-clx.
