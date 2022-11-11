Return-Path: <kasan-dev+bncBDN7L7O25EIBBRERXCNQMGQEB3VYELA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3969F625560
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Nov 2022 09:33:09 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id i14-20020adfa50e000000b0023652707418sf816790wrb.20
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Nov 2022 00:33:09 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4kSq6wOBycH1pCaRU9ovNqjy7hXVbECPTaOQdysF0CQ=;
        b=hqZXmTcu6kE6GmBuWGYtnQcU+77NljvOZWszf2RuaaCcwR+/uoxXxtiQeNWFjNWcTx
         5NmfdT1fXHPq5XvmmYvNFLV6NvNNmtVBdpHie0lYrn9AF5N+tbf8TFGEX41Kf3zDwMl7
         jf/azqFxQJZZIShYFj89n4qlBjL0i3dj4BPb3pejxCXhQ+A/qNfzPWw6IXxz69KstxFH
         zfUPEuzSEKDSfdk8jQUTW08JnSSPPPObqwgbtO6wC5244i6OrIJF2MjSv6DmxigwO63B
         YuPwJJuwTJcWY1wzeO+LZxi7X2DZbjD+rkXKCtPVajuMZq+MNUVKTvkZ488MBkU7XxLr
         QEbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4kSq6wOBycH1pCaRU9ovNqjy7hXVbECPTaOQdysF0CQ=;
        b=5N/88ihWQIZ8GR770ktaEzTD5G3z/Qf9V7jJEYkNIJ9DVHa4doyFdF39DZTcN8I5D/
         vhm/HEDXtjTTiYZTOmaTSM4ncz4wzkLPYVjrEJE3Caw2rqB2MYtXitoEHDZfQvzQr18s
         S2SieqXJUQGJ7zeauqUgzU7RDe63OAWQ/W1v021zef8iWRQmlQ+JWAUNj3tDHdhgmPfZ
         Sbjuu6fQQdaOClssORUlcDSKDHoYR40++8EeBnbR5WN2HBKcd4bGOGjKLKu9Gy8MYqgP
         3fyJgE8Z83wrg/0QqrdzS0zcojNE2ee+F9IEe8wYzCitPYNO8nlvO7XQbKS0zcNTO3qx
         yBgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmv4b9nvJ/CsTDOUQVvogfdGBzDfD5ciF0Uw5uzxaTi1xnxfW+n
	IgMpcQNwpqiuL777iHj4F3o=
X-Google-Smtp-Source: AA0mqf6i9RxtbyzEfZ2WbpDb28p6to3JS8rW4GfrO5+A5NzWTgDN/xlJkUtj8jIiqiheKN7QS7vX+A==
X-Received: by 2002:a5d:540c:0:b0:22c:e002:74c0 with SMTP id g12-20020a5d540c000000b0022ce00274c0mr595258wrv.593.1668155588797;
        Fri, 11 Nov 2022 00:33:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ce11:0:b0:3c6:efd6:9cd8 with SMTP id m17-20020a7bce11000000b003c6efd69cd8ls2140888wmc.0.-pod-control-gmail;
 Fri, 11 Nov 2022 00:33:07 -0800 (PST)
X-Received: by 2002:a7b:c054:0:b0:3a5:cb0e:8242 with SMTP id u20-20020a7bc054000000b003a5cb0e8242mr474141wmc.188.1668155587838;
        Fri, 11 Nov 2022 00:33:07 -0800 (PST)
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id d14-20020a05600c34ce00b003c6c0197f3dsi307003wmq.2.2022.11.11.00.33.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 11 Nov 2022 00:33:07 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6500,9779,10527"; a="310269271"
X-IronPort-AV: E=Sophos;i="5.96,156,1665471600"; 
   d="scan'208";a="310269271"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 11 Nov 2022 00:33:05 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10527"; a="615423560"
X-IronPort-AV: E=Sophos;i="5.96,156,1665471600"; 
   d="scan'208";a="615423560"
Received: from fmsmsx602.amr.corp.intel.com ([10.18.126.82])
  by orsmga006.jf.intel.com with ESMTP; 11 Nov 2022 00:33:05 -0800
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Fri, 11 Nov 2022 00:33:04 -0800
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Fri, 11 Nov 2022 00:33:04 -0800
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Fri, 11 Nov 2022 00:33:04 -0800
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (104.47.55.104)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Fri, 11 Nov 2022 00:33:04 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Qrq5P9j2u6mgMUfUL+Chr5R0hPex0cTRKzMUOoCFTX/L4+nV11QivrPtcIlJOAl3KmKvnkCDI2YNTge1wRmHmI2GcBhGL5od51JsmJ+24+8ILBxKBE6IgtrrFrDjusGCikrjNL1y8GrYr5eyF60CiaBy46ZqZIhOUk/1dwJ/aynPifCLCJlgJavRRBS3HYdPdVXm4fvNVX+uUGZBBJzm9VkCYDrdsPLuj5zwhWpTvBFjCkEVZbQmuc95SfX2TLPRFDAGuviFH0YwSLHGVVbTq0nQ3uHcArLHdjAlUHoZkUOYrL8ej1xosC3EdhAj8vsR+GL5dUjMb/g0XXHZrVHhyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ELtJPQP2atiOLXmD8Se9LjPtYEfHHH2Bkpef02Hw5Zg=;
 b=clVB/alE6/nzZhOtG5De2In+TnXFvFY3m0uRuV27CGMC+RqzcH0qKTeWR9Gn18FECbzItoo7e8VWBIPQrTdk4yshieyWUnk9tzasDdM+FM/mzyyWrLbio6R3WF9GDAAgvFBy0nZkslszbMiMtS4saie4xIf6LUUcfdQKuYhyTWaySXsDZYLqy3D0vA4Jee2k9cNlnnir0n5ddWhejymlUVbly+adZr0PuTrkYWmHcqbFxTdrLw5hdGfc0DeiJ96UoWeFWCWjAfcdH13XYkkc0PsctU9CrMXM1uwqHRAsGKlFgTTboyeR2rPDAv+d4bgIiYZOekk/Q2LtVaZqtlqG+g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by MN2PR11MB4599.namprd11.prod.outlook.com (2603:10b6:208:26d::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5813.14; Fri, 11 Nov
 2022 08:33:00 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb%4]) with mapi id 15.20.5813.013; Fri, 11 Nov 2022
 08:33:00 +0000
Date: Fri, 11 Nov 2022 16:29:43 +0800
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
Subject: Re: [PATCH v7 0/3] mm/slub: extend redzone check for kmalloc objects
Message-ID: <Y24H998aujvYXjkV@feng-clx>
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <f9da0749-c109-1251-8489-de3cfb50ab24@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f9da0749-c109-1251-8489-de3cfb50ab24@suse.cz>
X-ClientProxiedBy: SI2P153CA0003.APCP153.PROD.OUTLOOK.COM
 (2603:1096:4:140::20) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|MN2PR11MB4599:EE_
X-MS-Office365-Filtering-Correlation-Id: e4b3ab60-46ec-4f97-a333-08dac3bf5686
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: KJN03ZC6UDm15+SJqWon3Cf/Jix7tjUGJ/DShJ8BJ1n4lW69iQ4xmbtU6kLCvu9e6Sou4CVjCKVFwUJQYxyOktHGsWP5CuMnl6BE8Ei+D7bMhQecFBy3mKGZ+srVqEOORhJHGqXLF73N+0f/DP5GK9L549g0Luo2tiCa3sJOLSeTgE2oDFr6J6Z3MK3zxsfC6RTWXpLheLtTt0DBi5HGakUjBei4VQ0jp8hPwDavdikkzN0PS4ba44m37Kolcr2RNtpnVboiNuk7wYLpMqHf/WYvv69DmhITl81yDVPCmD8lKqIhvCrOr1A44PvmnGOsosBASEiLtrQVsbHayH8TDC20mVfsR9HMvcls90y1b/RvwPetd7ri4QRU1XTop3SOq2xRXfbZcgT3smynWXS8nma5k90h3eyuH1MUb3IsF8ST474zY5pmU9WaUdKMOouZubVWcHg8pHD8xglzFYbd3X4jn77QogeQXLnrNW360aOgMS1CBAwMbhObdVYwmkbr1mlWxZac076xXVLiPkYrdZXteDdS5Vkp20Ccc7XfiYMzqJKjSJYaXUoUMmFQnl+0mQBn6IUTpVnlWjXZy/HtXVeKjozL9NUQCQmagRF0tqOjuJhbWllep0Gz+yH/tQzZVJRe1Hx3G8X0tRtQa9ht+XLkbD7QEY4lYH6GJaDkglYPvcMvRUxeM/H5qo7BtT8vtrQtMpBl3CzCTAxjGNDVew==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(376002)(39860400002)(366004)(346002)(396003)(136003)(451199015)(186003)(5660300002)(7416002)(8936002)(33716001)(6666004)(53546011)(6506007)(316002)(6916009)(41300700001)(54906003)(9686003)(4326008)(8676002)(26005)(6512007)(86362001)(66946007)(66476007)(66556008)(478600001)(83380400001)(44832011)(82960400001)(38100700002)(2906002)(6486002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?xp9NVgGXR9FlqHlaoHaIOoUaRgQQ0iHu/dUS9cXxptNqw8+Psn4iIglJkasT?=
 =?us-ascii?Q?YefeQSLDOcHNOgz0alTVMS1Ve3ta1IiAmYCqUvlwvto5KQlF4X7M+fll+nCh?=
 =?us-ascii?Q?T+cFoL82jDxCASFm3u1v1lQDtjcM82SmYj2yexkYC2RQf11yMq4VFLDXJ1KQ?=
 =?us-ascii?Q?MB4TK+alIUdaH83jXDDKdVpjuQP7DJD4spuDrsGlh8Ho7wICIAyvzbcCnvcP?=
 =?us-ascii?Q?bMz7j14PJMwcZ7rspsNaMWck2920unvWiKPR/DuuCLxPYmU1N7ng3DsQZG1B?=
 =?us-ascii?Q?/Et66srIo9oUOhN6MpQEKMjOC0z3DPQ0TdflYhSrZ4WwAPr2tUamQImoIFoz?=
 =?us-ascii?Q?Eubvuu+2GwTLIQrSFNnfPZemVd6zpxhKeL1CSs/CBmk51Lf7rs19++4bwQU1?=
 =?us-ascii?Q?jnAQJVz1ODFyP2u0uQW4FWC0zy+4D5A78QX1C4ox4We9NS/g2oQsZJ0WElza?=
 =?us-ascii?Q?sBeBzYJol8J7ZEnEzI8+CX6tdtUBsAvzmQHF2VRqUkEzUxVmLX4DQjRSU5xm?=
 =?us-ascii?Q?ZqJ9V/2obxAN+7QNap+jrwNesXNWe/QfKYGw8R1Bc6LInes882X8biLRvoaX?=
 =?us-ascii?Q?P16GCvdufmRgb+n+W3yylaV3kxJ9ewaiKAE99IBVmmbLuiEHwp+wDAX3qWvl?=
 =?us-ascii?Q?ItYby639Bxmditq5FMWt6CLDDJOI33BC2l4l+b5Yy7Q9bI2dwDSQlzRvCh6C?=
 =?us-ascii?Q?WE23FFO0CfKStulqU0mL937iuzVLEeLJPMr5vfRLMf5lpwowM0Az8jlE2m4Y?=
 =?us-ascii?Q?d8Z2kYBY8OWl7Lu5uCcrlaBs39sWFjXCiVhZW5B8FywiL2Ep9/9HC1I/sYOI?=
 =?us-ascii?Q?1CwFlujC1OcRL8u2CkI4IAWF/N9YW7VLXWg6OzejSo64PiXEXPzebpIVBtcT?=
 =?us-ascii?Q?Z5WOMr+zdWcunm5f63NF3oerMLKre5PImU+h7Sk+barQ4l1YXXsXcLP+mrKo?=
 =?us-ascii?Q?3VFQ3FwioaudAMfALf7geDvzmI7Lb4y14V6yc750YczheUS59XyQ8/Hw5aJG?=
 =?us-ascii?Q?hpmUlCBXr1FXSfg/Yr0GgpGNA/HYZo01X8C+phElTv/PrrKhPe4BL0OVxGQb?=
 =?us-ascii?Q?xtmnrJgcDIZCLiNNu5LFysJM9bOCSRT1clM+J2BTfq4pPlcHp4uL5nPPdV7E?=
 =?us-ascii?Q?a20Eb5Fiv2sGAA5M13C98naK+WElOpEwUG+HPjcgAf0geC0/VSiOF9ubb8UB?=
 =?us-ascii?Q?bRvEHC9ngQSpZcifqZ936HgGxBH9hmcMjX2P5uPqLn0fqNqBtpp76x0EMNpB?=
 =?us-ascii?Q?yb13iH7XFNorSxBFvSqYzAT0B+u1kus9nzSk1BhsJVkvsJd45MVWQxy7fm4E?=
 =?us-ascii?Q?dX8wgLXkSybqq8xV/KvgogRPiZKEZerDwhaT3tHF67LEGKB+yzEun/2HVawI?=
 =?us-ascii?Q?IdOw9RFod7wHe9J2eIwG+CUrhTuBJrFl/6eaCxxt6gh4rxq4E3ozJG2J7zeQ?=
 =?us-ascii?Q?pvphbVe8ZKq84H4k5JbNzVDmarEqpSKxkuRV5qOYOMUK13hfyM100hpmuN70?=
 =?us-ascii?Q?4gmsC5NiJU0llpoJ4kZ8TrXJY0RhlUlY+7o1Uf7GgcI+Zj1SJvuE1xL9aSJm?=
 =?us-ascii?Q?nkJHswfMlJ3b+5EcM1rYksJ2aMywpiTIZ15bBLZB?=
X-MS-Exchange-CrossTenant-Network-Message-Id: e4b3ab60-46ec-4f97-a333-08dac3bf5686
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Nov 2022 08:32:59.9972
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 5ccFgd5oJm9uqkEauj9Ac4ZHocn1Vw46RsU1glAdT/vl7uSqGo4ZfQ52vMNy2e9YLSMr7XDKjuxVAebb+ixx5A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR11MB4599
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=OORJHJVV;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.120 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Fri, Nov 11, 2022 at 04:16:32PM +0800, Vlastimil Babka wrote:
> On 10/21/22 05:24, Feng Tang wrote:
> > kmalloc's API family is critical for mm, and one of its nature is that
> > it will round up the request size to a fixed one (mostly power of 2).
> > When user requests memory for '2^n + 1' bytes, actually 2^(n+1) bytes
> > could be allocated, so there is an extra space than what is originally
> > requested.
> > 
> > This patchset tries to extend the redzone sanity check to the extra
> > kmalloced buffer than requested, to better detect un-legitimate access
> > to it. (dependson SLAB_STORE_USER & SLAB_RED_ZONE)
> > 
> > The redzone part has been tested with code below:
> > 
> > 	for (shift = 3; shift <= 12; shift++) {
> > 		size = 1 << shift;
> > 		buf = kmalloc(size + 4, GFP_KERNEL);
> > 		/* We have 96, 196 kmalloc size, which is not power of 2 */
> > 		if (size == 64 || size == 128)
> > 			oob_size = 16;
> > 		else
> > 			oob_size = size - 4;
> > 		memset(buf + size + 4, 0xee, oob_size);
> > 		kfree(buf);
> > 	}
> 
> Sounds like a new slub_kunit test would be useful? :) doesn't need to be
> that exhaustive wrt all sizes, we could just pick one and check that a write
> beyond requested kmalloc size is detected?

Just git-grepped out slub_kunit.c :), will try to add a case to it.
I'll also check if the case will also be caught by other sanitizer
tools like kasan/kfence etc.

Thanks,
Feng


> Thanks!
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y24H998aujvYXjkV%40feng-clx.
