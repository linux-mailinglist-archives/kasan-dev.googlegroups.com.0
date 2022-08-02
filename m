Return-Path: <kasan-dev+bncBDN7L7O25EIBBDWRUSLQMGQEPYAJURA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 09AC7587D40
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 15:37:19 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id c66-20020a1c3545000000b003a37b7e0764sf9324769wma.5
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 06:37:19 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UWO6R/ul3WjlCDQmW+A76XvyXUWLTgP8slDyyEFDSvQ=;
        b=GoVYsWwlNskg/K9djk5010w48cLO3DoOOq1uKeNhNKPM7VnpZK4+OMmb4XNL5alMep
         XnUlAJ3gPyF3jK9mROVFnAk3D2mukEZNgFn6f1TEie6qrEOkXCA8K5tHFocu49+PLg5h
         +rypZqof7wh0PSv9SilOPhEuaPKhwC+amDGNWi05PtISwfUjEypCpgnVtafOxjVi6Goc
         FP8QIYYchE8GX49s3suGUCyTAkOARxakgzxlSzVWAQLpbqFhlxm1AqtniCX09QG5S/Nd
         bzoctyWEloju+8l5YwMMwe+bd89/yBLL7p8p6Mf5wm1S45VGdjoC1ZPti8owQTHaslBU
         3FpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:content-disposition:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UWO6R/ul3WjlCDQmW+A76XvyXUWLTgP8slDyyEFDSvQ=;
        b=VolQU6Sn0N6wKRbxZkEPFlvUe+CVGd8AXZJZg2Ov1S2uaZxzZE1eSLmI3AjU5sVstr
         W1oTemoOsZ3H6dppwXWQyw8iwH9k2If6myCTqUO3NmVZX3hTmYCEmN1bf8SJUing9KAL
         Fuc7MF9A5QaLh59RJotnhgIxo6uTbUBrU43SJyiVOChUuR8En+fCYZ0oC0MseaOxkkHP
         upqIxAhdTuPx9w6bXqOxy/VjKTt610Mtl7w371c6TkSMyp16gDAHopeh5n99pmTWasXu
         GknO+bNwpIc2kMHlQxZJUIyhDr6bhljsHQgriQNeGykNOHdA1mWljAR3nEsQzxMAJLe7
         jkfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0wiROEOYPzjqHMQ9bMKCt8CkTRQzqa1FTQBp6a0mcy2OeO8HZB
	H1T9QTBZ64YSKny1mrUsjsQ=
X-Google-Smtp-Source: AA6agR7xpk4pF1yg7vRJzblS9fboeckfInH8KIaA0RufP+G09WIM03BMfEWXcTQpC6ZKCGwOvZRdHA==
X-Received: by 2002:a05:6000:1847:b0:21d:c149:263 with SMTP id c7-20020a056000184700b0021dc1490263mr12964851wri.449.1659447438620;
        Tue, 02 Aug 2022 06:37:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:253:b0:21d:a0b5:24ab with SMTP id
 m19-20020a056000025300b0021da0b524abls17324721wrz.1.-pod-prod-gmail; Tue, 02
 Aug 2022 06:37:17 -0700 (PDT)
X-Received: by 2002:adf:e102:0:b0:21b:af5d:6f15 with SMTP id t2-20020adfe102000000b0021baf5d6f15mr13128637wrz.648.1659447437655;
        Tue, 02 Aug 2022 06:37:17 -0700 (PDT)
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id l6-20020a1c2506000000b003a4a0cedad1si81870wml.4.2022.08.02.06.37.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Aug 2022 06:37:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6400,9594,10427"; a="290623184"
X-IronPort-AV: E=Sophos;i="5.93,211,1654585200"; 
   d="scan'208";a="290623184"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 02 Aug 2022 06:37:15 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,211,1654585200"; 
   d="scan'208";a="661626031"
Received: from fmsmsx603.amr.corp.intel.com ([10.18.126.83])
  by fmsmga008.fm.intel.com with ESMTP; 02 Aug 2022 06:37:14 -0700
Received: from fmsmsx608.amr.corp.intel.com (10.18.126.88) by
 fmsmsx603.amr.corp.intel.com (10.18.126.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28; Tue, 2 Aug 2022 06:37:14 -0700
Received: from fmsmsx604.amr.corp.intel.com (10.18.126.84) by
 fmsmsx608.amr.corp.intel.com (10.18.126.88) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28; Tue, 2 Aug 2022 06:37:13 -0700
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx604.amr.corp.intel.com (10.18.126.84) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28 via Frontend Transport; Tue, 2 Aug 2022 06:37:13 -0700
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (104.47.59.170)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.28; Tue, 2 Aug 2022 06:37:13 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=XR5IGlWduA8WPLYR1N7km/OuebVA2bnpozK7iRb1OJs02++qdOwSqmlbQAhkZlBUIAe8FA+lFW4asu6LjE00vMAhFqnks8AlokYVxsOnGDFHdk7+w6U0Usgy6g4U1RqpB2PODRa6R3w8ZIcnHXZNe/aHzK1VDfGY0SiIO4ILyHaPfrYJwya4+nOi23afHY1WwjYqvVhk+RX9lnRmyzB3wfkcREb9aIa5QAhFqYD/OUC8RUsQqZq9dXFKqG0Xg3jlxU/kevkME5BDC1/vBzurKIYhZgg4IbGyNriYtR60IocFbCXt2YwD1/M9yxeCWP9hrDuuhjGObhG9PfX8a2ZJDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5nvIwKZ1Hik+X+sSu/tUZmvnLz252t1ZKQDPz/OLOAQ=;
 b=AoWMB5NjvwCgfIRz6BguPhhGw5rfREOWtXkOmYAXkcABssGIgP3JVno+E7kNqrMrEdK74Fxu6I/y7ULPEjpjhthatXwOFaDDCMikL3XbEitO4WzG8RokCD4iRpICjtUCmntKHcLhIzrt750C8B/4eZSKLgnytv1XXlOlnM5hYZrWPqARId1HozYQvFWFyvyK2MhlwHEi8yYU7Acvlej0aAV4R1Pz9nBhaiuiB7SfW7nfCdKUCivzc+w84F+KFai3pfaaFU6nMEzNtPAIbVyjKM5a3AhKP4azQ5NqGOExOBkN3rG7VKXOgK06ZIvB86weF6hXT+PyYHuUIg8+9pWKCw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by SJ1PR11MB6156.namprd11.prod.outlook.com (2603:10b6:a03:45d::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5482.16; Tue, 2 Aug
 2022 13:37:10 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::8525:4565:6b49:dc55]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::8525:4565:6b49:dc55%6]) with mapi id 15.20.5458.024; Tue, 2 Aug 2022
 13:37:10 +0000
Date: Tue, 2 Aug 2022 21:36:36 +0800
From: Feng Tang <feng.tang@intel.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Vlastimil Babka <vbabka@suse.cz>, "Sang, Oliver" <oliver.sang@intel.com>,
	lkp <lkp@intel.com>, LKML <linux-kernel@vger.kernel.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "lkp@lists.01.org"
	<lkp@lists.01.org>, Andrew Morton <akpm@linux-foundation.org>, "Christoph
 Lameter" <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen,
 Dave" <dave.hansen@intel.com>, Robin Murphy <robin.murphy@arm.com>, "John
 Garry" <john.garry@huawei.com>, Kefeng Wang <wangkefeng.wang@huawei.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [mm/slub] 3616799128:
 BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
Message-ID: <YukoZEm4Q6CSEKKj@feng-skl>
References: <20220727071042.8796-4-feng.tang@intel.com>
 <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl>
 <Yudw5ge/lJ26Hksk@feng-skl>
 <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl>
 <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
 <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz>
 <CACT4Y+asjzrBu8ogRDt9hYYaAB3tZ2pK5HBkzkuMp106vQwKWQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+asjzrBu8ogRDt9hYYaAB3tZ2pK5HBkzkuMp106vQwKWQ@mail.gmail.com>
X-ClientProxiedBy: SG2PR03CA0088.apcprd03.prod.outlook.com
 (2603:1096:4:7c::16) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 1d695832-4efe-4533-d452-08da748c19dc
X-MS-TrafficTypeDiagnostic: SJ1PR11MB6156:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 04DN5C4mz9YmAjKa7Y0kDIHQWji8n/XZO7B9dzzKsV6WLyXVyVjgsbsCOM3sdYEHfg9+oDflbK9iRvmpm1qovQa5NZU56aOrH2c82OpHyHEPAoYjPfMhUnxjOQZWWDdcdTm0k8eQqZiS3PnfKb5+SQG1G9p8CNyvTlQLsXkvyVoRFjRDL7dyNe+5EAGClMVoa6ywf6VMzK3WtDRfaaQfQ5w2QIMFEjvZgxO24UHsfS4QWj1BPJMk11Lp2Tzbw54EQWYkalkBlvaCZGLZLq4J9Y4kovRTbnzrfMcqyveP8m/vZhrw6r/AGJpPg97N+YR9xPZm2SymUXNIffOH/uhw85wKWOf0BTrFU6nRPQzGsLLeijB2FaTnIPJTLstaHRSF18zzaH+ANtmyBiVJycOZY1U+AxkJenXLusgHumcDC0dvuNMbsJvbigjYlUZKAh63Oo2qMngARqTEhNklJHa3UpMOJxULWz6zduSF5rmADXT8ZqklrvO3IZLzV7S/UGo3pug/1P1BwDEeNzd6P1pu63aad1Q8J/ra2fkMz7GT4X2unWIpL5Ah59VROs2VqNC9jrFJ/LWzJ5+/25pRBrJogUlRE2bVwLJgSul53n0Zlf9eSh+sSvD+2/5OOJkuAiRLtJzNocx33oxQFoQJ6zPMMFlSOQWfF8kzkr+BDytjUXhiQ2T1+eM0KO5h+rg8FuOV31Z7J7FwSUl48Qb54z1aAbVLwzg8n/pkJjjYnN4sOHCvtHJma+a6s1qiDlsf0eaq
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(396003)(366004)(39860400002)(376002)(346002)(136003)(83380400001)(8676002)(4326008)(8936002)(5660300002)(86362001)(7416002)(2906002)(33716001)(186003)(66946007)(316002)(6916009)(54906003)(53546011)(6486002)(38100700002)(44832011)(66556008)(478600001)(66476007)(41300700001)(6512007)(26005)(9686003)(6666004)(6506007)(82960400001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?YLZf2CfAdlHSOJsnVhJLsLO8v7wqmAT3Zk8EyDs2yV+Kf4Y2pOwbhrYgMiw1?=
 =?us-ascii?Q?ty4zOXj/Chifmmtb0714BSN+zw26Vnh53UcoGLQZKQJrKZ+at6L932pBlNlI?=
 =?us-ascii?Q?OyyDNP5MoylYZXg8HjpYopmy3S+KUooPLUGQD7xORyPUiQwFPrevd0fe/Aub?=
 =?us-ascii?Q?r7SMCo9vzCTN2R1inuy3W228Y42r/mkmYAuokl5WCh8P/hGMREGDH/+7ww3h?=
 =?us-ascii?Q?0xm6MOHIIij/nnu7mjmLuVqucoTn2PL99CAjnrltid56AyqiTELJc8LPQpZr?=
 =?us-ascii?Q?LpXhe2EV1yv0tnAbzOvnDp532st3vZHrzsDIjow5Zcmz97KBZNTM4xzHUSBu?=
 =?us-ascii?Q?sOvWTkE2aXVWfPcpYWlc2LNOYkUJDoFlCcmMjHKiiFs2RwE/jGNfqcZXMLsn?=
 =?us-ascii?Q?NpvVCP7roJFqD+PfhOO5uoqh3cbjLs4b6xIMac+Sl+YoZL3c2Y9T219jhHFk?=
 =?us-ascii?Q?ZMr4X6YNFu5EjvaS0abtBUSCbRPrORBuj8tGrZrMPvrCVAkJpHtgLRhE1Rtk?=
 =?us-ascii?Q?rWHdY+s6whqc5rVVLiX3gTZinj9gFew2vqi+AGFojcuYtOKTeTf7Fsi9G9C7?=
 =?us-ascii?Q?7lSB2Cp5CmxZpcjnSmOaNUt30Xoa+wGiLJCSy8q/q/lNXFzTgE+uQGdr2jiX?=
 =?us-ascii?Q?iKAkyGbbBfftGFkYV96o0YNNXi7jjrdWHWEPfcRrj62jjDUEhsfh0hhfqotK?=
 =?us-ascii?Q?bKMRAm8Uz/wDFkjw6IFtrNCKt9Nwngt188Y/qPT/DZN0+tnaMlfxmseAiKka?=
 =?us-ascii?Q?yTpsR+6oZNOlFP9wdHZVE+F8bv2erGDi3TJlcupxVKsoTcJJCO5afQUAeTF1?=
 =?us-ascii?Q?l+0VW87U1gzvDJgPUThaSVe6RbbiYTGjkgLOc5RF0BA9Yydg4rgeOVP3vABd?=
 =?us-ascii?Q?mNmQ4PHcbXPUdVWgCQ6+3bKrbJ9mv/GIAo0JVh/xETKZTqFjnQ+WPELZv//A?=
 =?us-ascii?Q?up3w4TzzMY/h/PN5lo0qDW3g/16XUUTCuBPhfDHc+88ACgeT85elI+kCVGEC?=
 =?us-ascii?Q?+30XMymzDDb7WopMTIVL6riyjgkmNqFOlnwMzAAB24jAkoAh8PmKY2fD11f8?=
 =?us-ascii?Q?PI6YIgXOAVtSLaDeUZ3g6nrAOIgpbUIwdlnw1wluoEv07F1RWyD0HK/sZT+f?=
 =?us-ascii?Q?b0V4RkiXBgXaC46GOwWtYVEUb3Z2CjWwOInG2jxoglXXNEaOTKcq+SZ/MOIo?=
 =?us-ascii?Q?5LZnHiQb96NnHzONCRyghDW2m+PUqLrEVfEyPmKoeIR2g+rJjXVcGmUGqfGt?=
 =?us-ascii?Q?+9GSFCdog44q3FHUoXAS9PDWA/KufooaQ7LzfX0CxUEN6QJ8M3xCXtsBfFH4?=
 =?us-ascii?Q?8dZtMN/Xk0L017QC/5kHhl3cruI15911A65QKw2Q+SvtxZ9z5jKf05pVRv2f?=
 =?us-ascii?Q?nrd8fPFt56cr4B1XAH/z93B61uADauJVIvqIB8Kf1iUbKe3H9ZaF4CSlkIVg?=
 =?us-ascii?Q?NCM7SNVJzpW8rskGi0ErNrsHSMiIX/8nFdGwQTxrMztVYQJGVzk4hFpXyFRQ?=
 =?us-ascii?Q?nH3OTdjxGZ/U+2DkKTqcZlQGUrh9z0HqPj8W5/fLANQFbQeY2G81uA7Y2RuG?=
 =?us-ascii?Q?RP6RP+xrcnBas/skle7iHgikURvQu/tSXygVn/TS?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 1d695832-4efe-4533-d452-08da748c19dc
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 02 Aug 2022 13:37:10.6367
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 1PbDXE+VhfmU8u3niPTf6lc+WBoWZhz58PZfQ63OP2wEAyyK4HjWqU2yaG/FqGnM2A4Kg05xsOd9JSexp9PJJA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ1PR11MB6156
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="Zz/fU4Jf";       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Tue, Aug 02, 2022 at 06:30:44PM +0800, Dmitry Vyukov wrote:
> .On Tue, 2 Aug 2022 at 11:43, Vlastimil Babka <vbabka@suse.cz> wrote:
> >
> > On 8/2/22 09:06, Dmitry Vyukov wrote:
> > > On Tue, 2 Aug 2022 at 08:55, Feng Tang <feng.tang@intel.com> wrote:
> > >>
> > >> On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
> > >> > On 8/1/22 08:21, Feng Tang wrote:
> > >> [snip]
> > >> > > Cc kansan  mail list.
> > >> > >
> > >> > > This is really related with KASAN debug, that in free path, some
> > >> > > kmalloc redzone ([orig_size+1, object_size]) area is written by
> > >> > > kasan to save free meta info.
> > >> > >
> > >> > > The callstack is:
> > >> > >
> > >> > >   kfree
> > >> > >     slab_free
> > >> > >       slab_free_freelist_hook
> > >> > >           slab_free_hook
> > >> > >             __kasan_slab_free
> > >> > >               ____kasan_slab_free
> > >> > >                 kasan_set_free_info
> > >> > >                   kasan_set_track
> > >> > >
> > >> > > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> > >> > > tracks: alloc_track and free_track, for x86_64 test platform, most
> > >> > > of the slabs will reserve space for alloc_track, and reuse the
> > >> > > 'object' area for free_track.  The kasan free_track is 16 bytes
> > >> > > large, that it will occupy the whole 'kmalloc-16's object area,
> > >> > > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> > >> > > error is triggered.
> > >> > >
> > >> > > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> > >> > > conflict with kmalloc-redzone which stay in the latter part of
> > >> > > kmalloc area.
> > >> > >
> > >> > > So the solution I can think of is:
> > >> > > * skip the kmalloc-redzone for kmalloc-16 only, or
> > >> > > * skip kmalloc-redzone if kasan is enabled, or
> > >> > > * let kasan reserve the free meta (16 bytes) outside of object
> > >> > >   just like for alloc meta
> > >> >
> > >> > Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> > >> > enabled, we bump the stored orig_size from <16 to 16? Similar to what
> > >> > __ksize() does.
> > >>
> > >> How about the following patch:
> > >>
> > >> ---
> > >> diff --git a/mm/slub.c b/mm/slub.c
> > >> index added2653bb0..33bbac2afaef 100644
> > >> --- a/mm/slub.c
> > >> +++ b/mm/slub.c
> > >> @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
> > >>         if (!slub_debug_orig_size(s))
> > >>                 return;
> > >>
> > >> +#ifdef CONFIG_KASAN
> > >> +       /*
> > >> +        * When kasan is enabled, it could save its free meta data in the
> > >> +        * start part of object area, so skip the kmalloc redzone check
> > >> +        * for small kmalloc slabs to avoid the data conflict.
> > >> +        */
> > >> +       if (s->object_size <= 32)
> > >> +               orig_size = s->object_size;
> > >> +#endif
> > >> +
> > >>         p += get_info_end(s);
> > >>         p += sizeof(struct track) * 2;
> > >>
> > >> I extend the size to 32 for potential's kasan meta data size increase.
> > >> This is tested locally, if people are OK with it, I can ask for 0Day's
> > >> help to verify this.
> >
> > Is there maybe some KASAN macro we can use instead of hardcoding 32?
> 
> kasan_free_meta is placed in the object data after freeing, so it can
> be sizeof(kasan_free_meta)

'kasan_free_meta' is defined in mm/kasan/kasan.h, to use it we need to
include "../kasan/kasan.h" in slub.c, or move its definition to
"include/linux/kasan.h"

Another idea is to save the info in kasan_info, like:

---
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b092277bf48d..97e899948d0b 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -100,6 +100,7 @@ static inline bool kasan_has_integrated_init(void)
 struct kasan_cache {
 	int alloc_meta_offset;
 	int free_meta_offset;
+	int free_meta_size;
 	bool is_kmalloc;
 };
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c40c0e7b3b5f..7bd82c5ec264 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -178,6 +178,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 		return;
 	}
 
+	cache->kasan_info.free_meta_size = sizeof(struct free_meta_offset);
+
 	/*
 	 * Add free meta into redzone when it's not possible to store
 	 * it in the object. This is the case when:

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YukoZEm4Q6CSEKKj%40feng-skl.
