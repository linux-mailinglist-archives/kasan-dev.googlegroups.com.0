Return-Path: <kasan-dev+bncBDN7L7O25EIBBNPF6GNQMGQEILFNMYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A7E0363358A
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Nov 2022 07:56:54 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id l42-20020a05600c1d2a00b003cf8e70c1ecsf10554162wms.4
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 22:56:54 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CWVIbAj9u0FjmPAp0edJkLmRwvUp56cTPXVu6dQf7Cg=;
        b=bdME/xOkocgm75iVKy4pC9B/FMa4o/MWx+wv2zxYRTeg8pWu1wr8Hl+3qYYJpZ24S+
         Z4ak0iW78Pwc1sldnD1CT67v7uY3SaU/3X1Ym51wkxfGBHXlTi5x/LdjysV5bZ651Hym
         gNTijVFZBo8lIT7CvbSLTrQwUoWawDOC4BHEC4IRS/+7eKh3722/xxhitDU/UBG7tENS
         prgPWvODMztPLjt4RxPA4Ngbrle41myJin/Ln/GaKE3Z38Bx0biglgcn2F1LoFNP5c9T
         X0rpp7cq8mB1Zc7x1jmfA7U5wfPaZBzf2K3vhKGZIQWCvjbdnfMU4QoG3QJgYvvonGys
         uNyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CWVIbAj9u0FjmPAp0edJkLmRwvUp56cTPXVu6dQf7Cg=;
        b=DhqI+kc7+Rb8bZe2UQuXAI/YBJJETZNn35iK7UaLMvD6COoBFZ+eHkfRvhyrckRlO7
         3q7/0/tPHugFMrC7Dlk4PbIu7tHz7ApUWFc5MoHaVJQhhAaocpGTvAYzfEK5aQVYT1x4
         T6pvHGaEeoEYQfi2wsF6A7ZUghuKmMUkhqQcgMr5rura52tDLxIQ8vxLM4QXVtq8MeL5
         fSDNplvtwygfWjnfhYLcae3UzS2hFw++M/da32aOEyj8BvCmVLlFQsHjvq0FbflG8xz3
         +QAJ82j674pQlj9F9MbddVxikMSPZPLBZr1oNv5V1tTO6L3OgOCIrYhO+ICWeH+W6gAC
         MeWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmbddy0fqjXfPwEdwOczkQQGH6Po7HaYAltlHcU0wXW0JA7Cirm
	pXART885ZWf0Tb9iyEzIuJU=
X-Google-Smtp-Source: AA0mqf7Rv/dLHng08Tydc1or4stHWDadGZ+Ku3x0mLNP6sR83IokV0LFWRV2tWxawT+/WOQHgyJlLQ==
X-Received: by 2002:a05:6000:c6:b0:22e:2f42:36c4 with SMTP id q6-20020a05600000c600b0022e2f4236c4mr12677174wrx.87.1669100214045;
        Mon, 21 Nov 2022 22:56:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e27:b0:3c6:c1ff:1fd with SMTP id
 ay39-20020a05600c1e2700b003c6c1ff01fdls8675621wmb.2.-pod-canary-gmail; Mon,
 21 Nov 2022 22:56:53 -0800 (PST)
X-Received: by 2002:a05:600c:4e46:b0:3cf:8762:23d9 with SMTP id e6-20020a05600c4e4600b003cf876223d9mr2703521wmq.112.1669100213075;
        Mon, 21 Nov 2022 22:56:53 -0800 (PST)
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id v4-20020a5d59c4000000b0023675b014acsi415705wry.6.2022.11.21.22.56.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 22:56:52 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10538"; a="301297121"
X-IronPort-AV: E=Sophos;i="5.96,183,1665471600"; 
   d="scan'208";a="301297121"
Received: from fmsmga007.fm.intel.com ([10.253.24.52])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2022 22:56:49 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10538"; a="643613392"
X-IronPort-AV: E=Sophos;i="5.96,183,1665471600"; 
   d="scan'208";a="643613392"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by fmsmga007.fm.intel.com with ESMTP; 21 Nov 2022 22:56:48 -0800
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Mon, 21 Nov 2022 22:56:48 -0800
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Mon, 21 Nov 2022 22:56:48 -0800
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.168)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Mon, 21 Nov 2022 22:56:48 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=bl6ejJR5OR7LTWxojtJMkcHiT2pCoNf6/+uyghX1SceUKT2hXXB9Vir8ZnQyHu6JCaYTdfD7cOr0124xU/MmOsFvlao2s5Ogc5WN+BusRfB7AZt47ySa6779vsUrUtMPNrW7YZ073e9gCrcfuImweFUTV+4kAWK12wGzajMf0fbXhQzZxnXijeDqFSYINMNwArrziWURcLk46qAGfwc0ILbrJDV2p0bvbsV61Oxmo38SYnCcuqcj/G1AUs4v3fldFNdH7T6HKY3EASzJOTvdztqrDkpgrTdmN8IJpDFeq+6LmOmUjwtvNhnBvFbzfpDAMNmh/mLbkvR5ocHXAZ8G+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=aOXNC7G9VxZQldbrtF3kM0EQqYy7yoUUv7QfojSeMYk=;
 b=ch8nM59tX9FthG4wYWI+1NAS6euRPexi7VgVfo6+loVBp/ib7Wv+ur2Y7VqtuUHZ54BSiIuJCzLl6mo5kIa4lzxJpnpKUSCokDiuXfUrV/ML5/YVJbsPzw+dk+LLq/pXm7HvgNkoLhc4rmbm4gjiKpWZQfK3jyc1tZNbKEcZ/YVvKlHLC9yfDFxzcckUgvJfjbYOfFD8tC1HpXekXsyOogkrt18mqArnVeUk2JxhPvmmFDvg5EKGF2Ry90Lg8tOFZRArvDBNO4Ji7zDOekPtz/HZItpyFyZUnabVkoShWzGTeHeX99wbvOKTfYu0cnUdX1I7+dDH6i/oDLpW6zniPw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by IA1PR11MB7366.namprd11.prod.outlook.com (2603:10b6:208:422::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5834.15; Tue, 22 Nov
 2022 06:56:46 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb%5]) with mapi id 15.20.5834.015; Tue, 22 Nov 2022
 06:56:46 +0000
Date: Tue, 22 Nov 2022 14:53:32 +0800
From: Feng Tang <feng.tang@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	<linux-mm@kvack.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -next 2/2] mm/kasan: simplify is_kmalloc check
Message-ID: <Y3xx7JUaRfRXRriw@feng-clx>
References: <20221121135024.1655240-1-feng.tang@intel.com>
 <20221121135024.1655240-2-feng.tang@intel.com>
 <CA+fCnZenKqb9_a2e5b25-DQ3uAKPgm=+tTDOP+D9c6wbDSjMNA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZenKqb9_a2e5b25-DQ3uAKPgm=+tTDOP+D9c6wbDSjMNA@mail.gmail.com>
X-ClientProxiedBy: SGBP274CA0008.SGPP274.PROD.OUTLOOK.COM (2603:1096:4:b0::20)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|IA1PR11MB7366:EE_
X-MS-Office365-Filtering-Correlation-Id: 531281ac-428b-4016-f828-08dacc56b8a7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: k9NDnonjgd1eSXn6Mce/2AeFr/RI0bHmCDzBcwDmkWKifz/UP7dCY6rDtIj8ImJMiq+SEhXwcQwOEFBNZbdu7g5KYBwBk05Q+1OkmSKEMXcKRyq70ckUwoiEEUTspCujJUxxPxvHAZkukME6ki/Kp0ZAvOqR4KEjLM+y/N1fOzWuEtg6SmRROuFPjtikSVueRDjybh7WM2+KszNkUX+YdNIg6NqGIsNKZA+WQcKnhlsaVw6VpTzX99tXZ6PuJo019fDzUHECjwZ8mEoKouHTE44D/vn8f0Gh0JzSf3mryx8AkiHKMJeZBWQccRg+WZJmq0HW2qmEOpMKp0vMVZhnIv9wSIdZKc8ixuiWQW2eVkNQHqkbgbQEFZH8QVW3lngLIVGki3RXRtkvx/qEj99OEM8R9KknCoEij0TIjwJIOvPG4q5NL0/dat+GQuy98yRbbtwg759/XUJSa55BfjjF2vocoUdhEyBqEc5PVB8vx7rO6w++ZrA5tbeNtvO7UuJW5iuV+l79US5GMkgDN9xBG+JuryEFVtIbAGlz/GHE5RIAeBMBhzqxBoan8daib1LeVq/pN0RbhtyC+EYlk/EikEIYyViP9yc47a41D0FypyXjNT7dwWKITwin+lAdKXtS46f9u49QNEYcGObDtsqeEw==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(376002)(396003)(39860400002)(346002)(366004)(136003)(451199015)(82960400001)(54906003)(33716001)(41300700001)(2906002)(38100700002)(478600001)(6486002)(66946007)(4326008)(66556008)(66476007)(86362001)(8936002)(8676002)(7416002)(5660300002)(44832011)(316002)(6916009)(186003)(53546011)(83380400001)(26005)(9686003)(6512007)(6506007)(6666004);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?hIxeKnFY2gxgO+p0c9raeW++/0CpT/W3JZRelGlJIO8BdiCIFRwic5bBlqLv?=
 =?us-ascii?Q?DcLR384e/bvaWNhh8IHx2wNY4Dao4dtGGQ1yB0ia15vZKeKTGku+Cbwf/uzq?=
 =?us-ascii?Q?s2gTSmKan1HIy4S8o+nEkmXTp69uKSgIa55Kb1tuim9jc/ZuPDG6Zuex4bW6?=
 =?us-ascii?Q?+J5Lm5F8Vip/nbmoFkDu0izm6gwa2NvV66y/akLbLpHW3jarafVmzyCrG0a8?=
 =?us-ascii?Q?Hi90QaaVSM+tQhWBD3vOCteyihvEtEPyWSWRU10cn7sIzZKLFDLx9elycE5a?=
 =?us-ascii?Q?Ry7xSd2l5VrUdRBMjxm+KlJVen0Bck+zdJ72CunewcwDfuYpS6SwBRk9zpwx?=
 =?us-ascii?Q?jYZ2Dk1Thei8TaGK8TDab6ur0mlLasBCKSLHaOByDHi1Z2VkWxFsPBymTxKT?=
 =?us-ascii?Q?mlAmeEx2WnwvRFNOdig34IIq/GN9H1WVJyazVg2snn2PQ6ZKmsgv4asEB/fH?=
 =?us-ascii?Q?362FxKWYBpkkgnz3K7cg/AjKbccoRk5trUVszhvxE/tOw9+8i9jB8NaZq/Kj?=
 =?us-ascii?Q?qouORsCXVktwTG3EMkYVsOgYPSxhhoeBHC/yY1ZaMGnrafS2KqreawvIfMy1?=
 =?us-ascii?Q?Jcw6z59BNcGquLGXh7Pc8nqWhLbt8HiHI41sLJpNbrDqQHqiwxQU7Wy0AoE2?=
 =?us-ascii?Q?xcO7C3YQWL6+kN1ZeamC6GpC+XQlWoR8jwStQMRXflHeM+k6EkcS1z8E9vCH?=
 =?us-ascii?Q?VyFADB0eJwCfI4mWMmu/UILzMSqWIOcp71M8BWfft+2MjKwVlAaQ6aiHpZW+?=
 =?us-ascii?Q?Tj72Hglhr0kSQe7hUl1Wx32smAFvxRsVQNHgrAc9oRKD8qliqUfnoVUOi5rv?=
 =?us-ascii?Q?2LuCr7Pzn4zC13NbeilpaKtdAaiUmMQdqewxRotSAE77vEpxClbO1+pe3ldl?=
 =?us-ascii?Q?fYjAY6fTRwNL2gGuIp9qstZnt01iKQ/QoUSYy6KQ8uqdiElWCKeZ5mcnIHI0?=
 =?us-ascii?Q?l53Ieq9U3jMGqaA6QhpG4DsR00NFMzZsod3r0ODTsRQWKqwScP+aTSjilYpm?=
 =?us-ascii?Q?Fq1NnR4Qa+KoU9qIQVQdqaQlUOLkfxlEe1qLRKNzNfKbJ3z0olrVEOKR2t9L?=
 =?us-ascii?Q?l8X9IMgHWWIIVA4uQ6VtlyT6Lte699uI19rzzyqyipC9Ahw6o56FeuNIQZgU?=
 =?us-ascii?Q?YhwAitKRNy6iqq5n/bLR6vFpyLWwu9NFlFbF5bGa6RAHc092EYlvf4j0OK4p?=
 =?us-ascii?Q?vEm62Hzbnu16eYnyvR8/Bb+L0sk7G9Lw+s4Ma+oPassSVjG+l6u50gDxdrlL?=
 =?us-ascii?Q?WyPPdn+CwcrlTQ82ShpaPVssofNxqS+DsQ0cafZT2FMNZINmJyh4PTrPmRpF?=
 =?us-ascii?Q?0+uthgP0WQp8NXWGMNnjF7wM4zZimoPwn6WZSDmG5irfcOQsaI1a+7pSWnOJ?=
 =?us-ascii?Q?TAQsnN10JW3LB/1ZJcANKIQz75DrCUi7vC42scdyYOSToDeRjX+aw22uwLdO?=
 =?us-ascii?Q?pRaGcedFwBVzgGRVaOjXs4pWTS9Gu2iLBLwAKVJaKi47vruF4SKn5RsFkHE2?=
 =?us-ascii?Q?RZc8OoPEqL6lHq+VPcAxF4UMtfYru610+Gg6r31EJtOtV06gfEDkrbkrIqEZ?=
 =?us-ascii?Q?W8+n+gokq9ZJm/+SDC6eMikU33EvhrowZSBiEAOP?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 531281ac-428b-4016-f828-08dacc56b8a7
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Nov 2022 06:56:46.5178
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: MSavPj78hBtjSMiaE9iALkULkMUoDIxSKAbb2qa4GXNz+nb64rkFQ+deYLITeb9deh/LkUorNqZ3gmS544SMjQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB7366
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Ha+kZ7Xs;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Mon, Nov 21, 2022 at 04:15:32PM +0100, Andrey Konovalov wrote:
> On Mon, Nov 21, 2022 at 2:53 PM Feng Tang <feng.tang@intel.com> wrote:
> >
> > Use new is_kmalloc_cache() to simplify the code of checking whether
> > a kmem_cache is a kmalloc cache.
> >
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> 
> Hi Feng,
> 
> Nice simplification!
> 
> > ---
> >  include/linux/kasan.h | 9 ---------
> >  mm/kasan/common.c     | 9 ++-------
> >  mm/slab_common.c      | 1 -
> >  3 files changed, 2 insertions(+), 17 deletions(-)
> >
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index dff604912687..fc46f5d6f404 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -102,7 +102,6 @@ struct kasan_cache {
> >         int alloc_meta_offset;
> >         int free_meta_offset;
> >  #endif
> > -       bool is_kmalloc;
> >  };
> 
> We can go even further here, and only define the kasan_cache struct
> and add the kasan_info field to kmem_cache when CONFIG_KASAN_GENERIC
> is enabled.

Good idea. thanks!

I mainly checked the kasan_cache related code, and make an add-on
patch below, please let me know if my understanding is wrong or I
missed anything.

Thanks,
Feng

---
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 0ac6505367ee..f2e41290094e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -96,14 +96,6 @@ static inline bool kasan_has_integrated_init(void)
 }
 
 #ifdef CONFIG_KASAN
-
-struct kasan_cache {
-#ifdef CONFIG_KASAN_GENERIC
-	int alloc_meta_offset;
-	int free_meta_offset;
-#endif
-};
-
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
 {
@@ -293,6 +285,11 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
 #ifdef CONFIG_KASAN_GENERIC
 
+struct kasan_cache {
+	int alloc_meta_offset;
+	int free_meta_offset;
+};
+
 size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
 slab_flags_t kasan_never_merge(void);
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
diff --git a/include/linux/slab_def.h b/include/linux/slab_def.h
index f0ffad6a3365..39f7f1f95de2 100644
--- a/include/linux/slab_def.h
+++ b/include/linux/slab_def.h
@@ -72,7 +72,7 @@ struct kmem_cache {
 	int obj_offset;
 #endif /* CONFIG_DEBUG_SLAB */
 
-#ifdef CONFIG_KASAN
+#ifdef CONFIG_KASAN_GENERIC
 	struct kasan_cache kasan_info;
 #endif
 
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index f9c68a9dac04..4e7cdada4bbb 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -132,7 +132,7 @@ struct kmem_cache {
 	unsigned int *random_seq;
 #endif
 
-#ifdef CONFIG_KASAN
+#ifdef CONFIG_KASAN_GENERIC
 	struct kasan_cache kasan_info;
 #endif
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3xx7JUaRfRXRriw%40feng-clx.
