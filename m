Return-Path: <kasan-dev+bncBDOZ354D4ENRBWHRX2NQMGQE67N4BXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 003D1626A14
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Nov 2022 16:16:41 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id l42-20020a05600c1d2a00b003cf8e70c1ecsf6192407wms.4
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Nov 2022 07:16:41 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-disposition:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KlhQ3c5vb5JVNm0XY93bAahDdh7k1mB5+W4g+rGqCDg=;
        b=nBqqrqiZ/PZg0ReNrd1jP4JuMXHCD8pveQI6QVqNvNN4D72x3J5DNIYcyrWIic2qV8
         oy+n6MbDVFeawHiNoeqt9j+xBHlWkzT5Lm8taWepgqCG8DCBlbucvZR7qEhLDMkyRFb7
         e55lS9wiRXkpAb+BQAfBKj/sYYhgGntnbf5GkAshC8RPtkZSu+tBZpLLvXEeY4pO12Xm
         9NLHQjfjD8scWik+sQROiOyFWEMsSoIebULJFfVRniB6HanmRxe/JJk9OIwiRii4i0wN
         h5iPs83UJmctXvyoQKjRAM0KeHsMdcGbPmzMnEN9C1SGw7va7m/mRDHbjGDHlndtwe7i
         +kwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-disposition:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KlhQ3c5vb5JVNm0XY93bAahDdh7k1mB5+W4g+rGqCDg=;
        b=pJ/+ApvYQp1eHYNrhwkgBJqkqkwb2sxQYjeYBCC3i3/y8/fEkQWW5HOlyVqWvjYjP2
         /+za1BjKkqJZbP1dApFqCOZf41I4OM9xmys5Brw3bm0H9OHksd4vbUQ0W7apNPjMoqbU
         Ho7is2e69HARIuqMmN8L5teLxi5l4RanYI/LgUNIoOvtiar+PNiX6zVPwC4ZENri/fpw
         ezpL23rgwoM7zOzgyqgs52WulDIo0ysEEvbiABEzCyMKcfnC97gyiTTZkPT9UvhuQQeI
         P6q+M0A131cVthq4Re7ywP3WA2POdm2r3uHHn3jR2xVJA3LNo7tPa09hhYow8vSVur9e
         83yA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plNi3PzKzeKKDXoJex5g43Iw8cKEWmiHiNO2acPWGOQGhcxWb5L
	Rxwj2z5inK6Qgncg/JMqi0Y=
X-Google-Smtp-Source: AA0mqf6eRlqobuhdpexS0zWXKwW9H9z3Vmw8naOtih+ts2iRpzsocQXIl9hJwlGQr3a407udlp8qVA==
X-Received: by 2002:adf:e3c1:0:b0:236:64ae:9699 with SMTP id k1-20020adfe3c1000000b0023664ae9699mr3696702wrm.581.1668266201201;
        Sat, 12 Nov 2022 07:16:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1c19:b0:225:6559:3374 with SMTP id
 ba25-20020a0560001c1900b0022565593374ls9297739wrb.2.-pod-prod-gmail; Sat, 12
 Nov 2022 07:16:40 -0800 (PST)
X-Received: by 2002:a5d:6e07:0:b0:238:3d63:5736 with SMTP id h7-20020a5d6e07000000b002383d635736mr3757958wrz.513.1668266199338;
        Sat, 12 Nov 2022 07:16:39 -0800 (PST)
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id bk2-20020a0560001d8200b0024165c0a706si154149wrb.1.2022.11.12.07.16.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 12 Nov 2022 07:16:39 -0800 (PST)
Received-SPF: pass (google.com: domain of yujie.liu@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10529"; a="376001608"
X-IronPort-AV: E=Sophos;i="5.96,159,1665471600"; 
   d="xz'?yaml'?scan'208";a="376001608"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Nov 2022 07:16:36 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10529"; a="762924537"
X-IronPort-AV: E=Sophos;i="5.96,159,1665471600"; 
   d="xz'?yaml'?scan'208";a="762924537"
Received: from orsmsx601.amr.corp.intel.com ([10.22.229.14])
  by orsmga004.jf.intel.com with ESMTP; 12 Nov 2022 07:16:35 -0800
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX601.amr.corp.intel.com (10.22.229.14) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Sat, 12 Nov 2022 07:16:35 -0800
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Sat, 12 Nov 2022 07:16:35 -0800
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.109)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Sat, 12 Nov 2022 07:16:34 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=NKqbuqmGpjG8wbFyyOeEnGT/J5ay/MdXNkhCIrsbafgppGjHekAnt/yuny42n2bHbFUSb3T2Tmw3/B+UdqaBwhAcYyY7TORDFoafHCLgr5bMqGqP0cKdtQ19ycnlATjSxshmoud+/+xvJsHfoIrPJwAksI/idIS0yYOgcMLzJIPjzFw0PfSLGfnWeH/uBRHr/0arkTrB6/UHQz+CLORyo71/Bzje1y/T4IcV0ldbjmlUFsIcAjRrTcI9tKax6hsuv1mtFUBnQ1qjLJ69IORogXXNOgXTd/NfS0LIAkBzbwiXSPAehUHalgrIxZCtGw0G+V8d/iQLJyGbpbB7AB/4tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=x6Ijp/RNGdJz9bSeRHAwL68o2+XBP/YIOd6XzgMqvAE=;
 b=CM+WkQGff7LnIXdJVkZdl2OKlfKlQofCeYKrDVGatJxP2D6H9m+ueRrGMhiM4AHLkpC5UQohbF7krGTshREI43vD1Chk7YrESBsRwHtwV3swf1n7e4P/NuIyEUCN+35n8BvUrUDMRsVgq/D8FObxP7DrjH15Q+D2z80ZR0GIn+uN0hOFunyW2FJyHGWQbZdqBcJsXPiAboZOtRi78TiezWbHHxt+oWQEk7NyErsoHUkYD1QYtEykFOOs1HGlNNyW6NEShuvDzbI5pzuXB3qQzdfn/oBw61WC/yL3d5YIsCu17schHZftMD96RO1hMMf6T/AnxTvccGgZ7s65RHRv7w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from CY5PR11MB6392.namprd11.prod.outlook.com (2603:10b6:930:37::15)
 by MW4PR11MB6716.namprd11.prod.outlook.com (2603:10b6:303:20d::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5813.13; Sat, 12 Nov
 2022 15:16:30 +0000
Received: from CY5PR11MB6392.namprd11.prod.outlook.com
 ([fe80::a397:a46c:3d1b:c35d]) by CY5PR11MB6392.namprd11.prod.outlook.com
 ([fe80::a397:a46c:3d1b:c35d%8]) with mapi id 15.20.5813.016; Sat, 12 Nov 2022
 15:16:30 +0000
Date: Sat, 12 Nov 2022 23:14:42 +0800
From: kernel test robot <yujie.liu@intel.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, Dave Hansen
	<dave.hansen@linux.intel.com>, Yujie Liu <yujie.liu@intel.com>,
	<linux-kernel@vger.kernel.org>, <x86@kernel.org>,
	<kasan-dev@googlegroups.com>, Han Ning <ning.han@intel.com>
Subject: [tip:x86/mm] [x86/kasan] 9fd429c280:
 BUG:unable_to_handle_page_fault_for_address
Message-ID: <202211121255.f840971-yujie.liu@intel.com>
Content-Type: multipart/mixed; boundary="b8seNkh+w+eqQ5nt"
Content-Disposition: inline
X-ClientProxiedBy: SI2PR02CA0043.apcprd02.prod.outlook.com
 (2603:1096:4:196::12) To CY5PR11MB6392.namprd11.prod.outlook.com
 (2603:10b6:930:37::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CY5PR11MB6392:EE_|MW4PR11MB6716:EE_
X-MS-Office365-Filtering-Correlation-Id: 25b2f0a6-d596-4d1a-31ea-08dac4c0df94
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: QfWFA3B2YCt84tIHgPlqfBYbUVCh9UnzPW9wmNdwUcpLOi8tshNG+Os7nwiwyW9C2ZNNzusm3VAC3mpnHl+MUy2b56MgWAiqTK1iLFq+Ny5npgoq0FVoKQRxZoWSQYHTXaRjFWB9yd6yKBWJir8lkoRsujneIsdI6RSc31ZLMYfxhBE9JECgMkNBAHOeb93Wp1P34vgS56Klj29hkRQxHPKK3yB9cLnqrW+KFGwevdUXB57J/+oCoTMOoXvlL55uBcViyeQS7eYl5bJV1rKImJtVToH/0hIT+bamJIaT2hsujBHrCBk3OMnicrZqZr5vRFqw6vuY5vQew9h+1eSeMtXV4GL7yyMHOs7xqEnNTNB1cDu1LEvl9VPKLKLPdwTFRPMyKKLSFcDIiSfFfKkt/cOzN3ogffJaO8k5A8P3BQKPMyV3/KgGkPj27J/JT+21x3ss6CKxW9vrUAZwjWdhNYiBbeAoPYojjxt8Ao3TwXLmQDXVqxTAWi5Wd1sHzqCVpBgn14NAg12eLfP9e9SRbIFWcTwvt97Im6AoYx2sIpUp2iknTfKXQIxtSc30qFaDv455kBtuT28jgsuVOLizcJDcMQATyXqlyabbDAezmH/uHM/AbNooxsY+9n6yKqNcrQKK7TsdsfGW0BqGh8nQxFf5d8SVJxtlNwDthgkk165BlUaS3YLa68wv9NWsFmyLhwqCiNCxe6OrJyjcx+sSyqPWR49WtiPVqiR+7nfnXbj6xurXX9+ItDBjIb/xxpYfnW0K4M1LehyyFwG3vo7AcBq2L1VW6BvPBT2D1jnzsQu3pOcrx+xvToO7MwuP4r0CycWWfFfpAzAgqtlC0t7Kcg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CY5PR11MB6392.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(136003)(396003)(376002)(39860400002)(366004)(346002)(451199015)(38100700002)(186003)(2616005)(1076003)(82960400001)(21490400003)(86362001)(26005)(6666004)(6512007)(44144004)(6916009)(66556008)(6486002)(966005)(478600001)(6506007)(54906003)(316002)(66946007)(66476007)(2906002)(8936002)(4326008)(235185007)(41300700001)(5660300002)(36756003)(8676002)(83380400001)(2700100001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?BAKagGb0LwtapgyCtCDTLghAccWIsnzwUuftgUhLFKur428JBWQ6aNbBleNA?=
 =?us-ascii?Q?gyyhuyo09hnZiwhScANCr0e/oy69VAmftPv3iNEVypWG9RAJRX9/tJwu5pv0?=
 =?us-ascii?Q?2i7WKdqZv1PdnbPG3iVY0/9DCHcBUb8ZJGSg43vL+YqUsOyJ3GEt3jPfTmiT?=
 =?us-ascii?Q?bpTaCqsVYRZn7NZHin1V5RrtRRZy+lMvar5DhNPJpyU9xHtyls//oe3ATr6L?=
 =?us-ascii?Q?6tm92daLVAGCMwyTpIQALFLNXAWi42CDu/b7k3J9z89m1H9ATpKq9cyKLBcj?=
 =?us-ascii?Q?ILK8bFd4oxcjOG4si4o6SLD6OTq1IhGn0SVhenFXgnOPjP7pUeUpAhOnCZCW?=
 =?us-ascii?Q?8LH3ZsZKaI/iwhxzC5TtxeA+PRijTmlW06yCU8jZ3v3SLnoEH/Q86mo2ZRqu?=
 =?us-ascii?Q?OmU3ml0KqUXS9o6vX/zyuPA8w2TWKzIBzFMlis4UwZBTDEWsUq0d6kxKcenk?=
 =?us-ascii?Q?buaqnP9Zqh47gFxfpVABz9tkPTB6gfb2HW2sNcIfpZxdp5Whozr5RE3iVqQB?=
 =?us-ascii?Q?P4OCwA7DZfBDwvH28sXhRCL0lUDcY8JEr6aNtMPeeTDqJRidvoTPzOFEtmxN?=
 =?us-ascii?Q?YcXV+gL3wDIbBSHxaHfjM7I2884HBDxnkmkZTB1qUv2XBsCV0iwiPcZgo6gY?=
 =?us-ascii?Q?EYOa93i9D8V1Fg9z/LfcJPAwH+NiuPfkGXdkjnkwDTHAdLThM3X59p89UwlY?=
 =?us-ascii?Q?hXA3Yc4+9Un+Sklkoz0ssq/koItHFt9wIcBEQrpEEMIiEXzokMHIAG8T1klW?=
 =?us-ascii?Q?6GQvytIuFNP2MU049Pk1p9ydStq2lQowGGhyqoR/xSJe/FjJuojPi5TRzCoc?=
 =?us-ascii?Q?Svt2VE+99SITTyV1Y6eX7569Li6k0/USAiezRh/tjS32iOhIAwHS7qWNzOGW?=
 =?us-ascii?Q?hnTUVCla9EPoqdq7ssngX9XFCDH3voublcGQLC+6wqENzK7M3HJzpJBCDhN0?=
 =?us-ascii?Q?otsqTtjZccy/QOh0LrDsrdlA6K8TYDBfRWcOBPOax3dm4ndFtI6HJcEGpZIK?=
 =?us-ascii?Q?KWgbMiM9+1CyqsOsv1zBVOc+jipTLg/Em5JpVjIZIyIUcTAE9zKVw2Eg6+Qq?=
 =?us-ascii?Q?e9Y4R0b8u+LuZKj9Q9MIK3AxuvkJBFIszXvb30omG+/DkuTdr9zFrTEmXImk?=
 =?us-ascii?Q?SR1X3jDxGPPwjqD6ZLhP4T9zZyTSD81W/hR65RuMqYNUDbntc4DecevsGATS?=
 =?us-ascii?Q?O/HWVVwHTi8UdxYRkHVvfefAcQ+Ixd/NpRnFQY9Qkz4r7OK1QNP4q7qm1PFW?=
 =?us-ascii?Q?oiuf7d0lLj0WsoPdMJI7saQoIh9tMoRtE3FSv1KMwb6hVdWEM1wWKfW6gaRa?=
 =?us-ascii?Q?8Bi9GacbFksHVBu7bNy6/mn8O27y80M5r2FyDW1naW1vaQ1hoMIR+LBUKlRM?=
 =?us-ascii?Q?oHaxGmfHaYl42beNLhqelxYzUC++0kRuEVA9vD9qDfNO6l70R+dR/ggLBb4+?=
 =?us-ascii?Q?yoEnfbQnUY90XYd7WuyGi468OOZVGF4A3aemKadeZubDBrBJEU6FurJHyQV0?=
 =?us-ascii?Q?j3D2wp/4P0Vx83rpHAIwFone0XydrJL7nsuBqWuti9h6DJxRE11emcR+xNuf?=
 =?us-ascii?Q?NAvIZ8KTrToEO1HgBA4VrKw81htJ34VN8GZKbjd3R/hrBQrCHsviS7v4vAz9?=
 =?us-ascii?Q?Pw=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 25b2f0a6-d596-4d1a-31ea-08dac4c0df94
X-MS-Exchange-CrossTenant-AuthSource: CY5PR11MB6392.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Nov 2022 15:16:29.8890
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: MRyzM0kDDrvH32xdJUthvETksc6ES+uioXWUnRjyBWo4hzqXTTpGLlz2npDP6OemtcN3e8NwdFBLudzhOQfI2g==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR11MB6716
X-OriginatorOrg: intel.com
X-Original-Sender: yujie.liu@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=JYuKpJsB;       arc=fail (body
 hash mismatch);       spf=pass (google.com: domain of yujie.liu@intel.com
 designates 134.134.136.100 as permitted sender) smtp.mailfrom=yujie.liu@intel.com;
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

--b8seNkh+w+eqQ5nt
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

Greeting,

FYI, we noticed BUG:unable_to_handle_page_fault_for_address due to commit (=
built with gcc-11):

commit: 9fd429c28073fa40f5465cd6e4769a0af80bf398 ("x86/kasan: Map shadow fo=
r percpu pages on demand")
https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git x86/mm

[test failed on linux-next/master f8f60f322f0640c8edda2942ca5f84b7a27c417a]

on test machine: 128 threads 2 sockets Intel(R) Xeon(R) Platinum 8358 CPU @=
 2.60GHz (Ice Lake) with 128G memory

caused below changes (please refer to attached dmesg/kmsg for entire log/ba=
cktrace):


[  158.064712][ T8416] BUG: unable to handle page fault for address: fffffb=
c00012de04
[  158.074534][ T8416] #PF: supervisor read access in kernel mode
[  158.074537][ T8416] #PF: error_code(0x0000) - not-present page
[  158.095763][ T8416] PGD 207e210067 P4D 1fef217067 PUD 1fef216067 PMD 103=
344b067 PTE 0
[  158.095770][ T8416] Oops: 0000 [#1] SMP KASAN NOPTI
[  158.095773][ T8416] CPU: 34 PID: 8416 Comm: umip_test_basic Not tainted =
6.1.0-rc2-00001-g9fd429c28073 #1
[ 158.107429][ T8416] RIP: 0010:get_desc (arch/x86/lib/insn-eval.c:660)=20
[ 158.107435][ T8416] Code: b7 02 00 00 83 e0 07 38 c2 0f 9e c1 84 d2 0f 95=
 c0 84 c1 0f 85 a2 02 00 00 48 ba 00 00 00 00 00 fc ff df 48 89 d8 48 c1 e8=
 03 <0f> b6 0c 10 48 8d 43 07 48 89 c6 48 c1 ee 03 0f b6 14 16 48 89 de
All code
=3D=3D=3D=3D=3D=3D=3D=3D
   0:	b7 02                	mov    $0x2,%bh
   2:	00 00                	add    %al,(%rax)
   4:	83 e0 07             	and    $0x7,%eax
   7:	38 c2                	cmp    %al,%dl
   9:	0f 9e c1             	setle  %cl
   c:	84 d2                	test   %dl,%dl
   e:	0f 95 c0             	setne  %al
  11:	84 c1                	test   %al,%cl
  13:	0f 85 a2 02 00 00    	jne    0x2bb
  19:	48 ba 00 00 00 00 00 	movabs $0xdffffc0000000000,%rdx
  20:	fc ff df=20
  23:	48 89 d8             	mov    %rbx,%rax
  26:	48 c1 e8 03          	shr    $0x3,%rax
  2a:*	0f b6 0c 10          	movzbl (%rax,%rdx,1),%ecx		<-- trapping instru=
ction
  2e:	48 8d 43 07          	lea    0x7(%rbx),%rax
  32:	48 89 c6             	mov    %rax,%rsi
  35:	48 c1 ee 03          	shr    $0x3,%rsi
  39:	0f b6 14 16          	movzbl (%rsi,%rdx,1),%edx
  3d:	48 89 de             	mov    %rbx,%rsi

Code starting with the faulting instruction
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
   0:	0f b6 0c 10          	movzbl (%rax,%rdx,1),%ecx
   4:	48 8d 43 07          	lea    0x7(%rbx),%rax
   8:	48 89 c6             	mov    %rax,%rsi
   b:	48 c1 ee 03          	shr    $0x3,%rsi
   f:	0f b6 14 16          	movzbl (%rsi,%rdx,1),%edx
  13:	48 89 de             	mov    %rbx,%rsi
[  158.107438][ T8416] RSP: 0000:ffa0000031fb7c20 EFLAGS: 00010a02
[  158.107440][ T8416] RAX: 1fffffc00012de04 RBX: fffffe000096f020 RCX: 000=
0000000000001
[  158.107442][ T8416] RDX: dffffc0000000000 RSI: 0000000000000001 RDI: ffa=
0000031fb7ce0
[  158.107443][ T8416] RBP: 1ff40000063f6f98 R08: 0000000000000000 R09: 000=
0000000000000
[  158.107444][ T8416] R10: 0000000000000000 R11: 0000000000000000 R12: ffa=
0000031fb7ce0
[  158.107446][ T8416] R13: 1ff40000063f6f85 R14: 0000000000000000 R15: 000=
0000000000000
[  158.107447][ T8416] FS:  0000000000000000(0000) GS:ff11001fed300000(0063=
) knlGS:00000000f7eeb340
[  158.107449][ T8416] CS:  0010 DS: 002b ES: 002b CR0: 0000000080050033
[  158.107450][ T8416] CR2: fffffbc00012de04 CR3: 000000109c3d0006 CR4: 000=
0000000771ee0
[  158.107452][ T8416] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 000=
0000000000000
[  158.107453][ T8416] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 000=
0000000000400
[  158.107454][ T8416] PKRU: 55555554
[  158.107455][ T8416] Call Trace:
[  158.107456][ T8416]  <TASK>
[ 158.107457][ T8416] ? get_segment_selector (arch/x86/lib/insn-eval.c:622)=
=20
[ 158.107460][ T8416] ? __mod_lruvec_page_state (arch/x86/include/asm/preem=
pt.h:85 include/linux/rcupdate.h:99 include/linux/rcupdate.h:770 mm/memcont=
rol.c:843)=20
[ 158.107465][ T8416] insn_get_seg_base (arch/x86/lib/insn-eval.c:725)=20
[ 158.107467][ T8416] ? do_read_fault (mm/memory.c:4523 mm/memory.c:4549)=
=20
[ 158.107471][ T8416] ? pt_regs_offset (arch/x86/lib/insn-eval.c:682)=20
[ 158.107473][ T8416] ? _raw_spin_lock_irq (arch/x86/include/asm/atomic.h:2=
02 include/linux/atomic/atomic-instrumented.h:543 include/asm-generic/qspin=
lock.h:111 include/linux/spinlock.h:186 include/linux/spinlock_api_smp.h:12=
0 kernel/locking/spinlock.c:170)=20
[ 158.107478][ T8416] ? _raw_spin_lock_bh (kernel/locking/spinlock.c:169)=
=20
[  158.109757][ T1590]
[ 158.117492][ T8416] insn_fetch_from_user (arch/x86/lib/insn-eval.c:1476 a=
rch/x86/lib/insn-eval.c:1505)=20
[ 158.117496][ T8416] fixup_umip_exception (arch/x86/kernel/umip.c:353)=20
[ 158.131844][ T8416] ? emulate_umip_insn (arch/x86/kernel/umip.c:337)=20
[ 158.146371][ T8416] ? __ia32_sys_pidfd_send_signal (kernel/signal.c:4088)=
=20
[ 158.146376][ T8416] ? __might_fault (mm/memory.c:5648)=20
[ 158.171730][ T8416] ? __ia32_compat_sys_rt_sigaction (kernel/signal.c:446=
4 kernel/signal.c:4435 kernel/signal.c:4435)=20
[ 158.171733][ T8416] ? __ia32_sys_rt_sigaction (kernel/signal.c:4435)=20
[ 158.187382][ T8416] exc_general_protection (arch/x86/kernel/traps.c:733 a=
rch/x86/kernel/traps.c:721)=20
[ 158.187386][ T8416] asm_exc_general_protection (arch/x86/include/asm/idte=
ntry.h:564)=20
[  158.203024][ T8416] RIP: 0023:0x8049aaf
[ 158.203026][ T8416] Code: 55 ee 8b 45 dc 01 d0 c6 00 00 83 45 dc 01 83 7d=
 dc 05 7e eb 83 ec 08 8d 45 ee 50 8d 83 44 d6 ff ff 50 e8 54 f6 ff ff 83 c4=
 10 <0f> 01 45 ee 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 ec 08 6a
All code
=3D=3D=3D=3D=3D=3D=3D=3D
   0:	55                   	push   %rbp
   1:	ee                   	out    %al,(%dx)
   2:	8b 45 dc             	mov    -0x24(%rbp),%eax
   5:	01 d0                	add    %edx,%eax
   7:	c6 00 00             	movb   $0x0,(%rax)
   a:	83 45 dc 01          	addl   $0x1,-0x24(%rbp)
   e:	83 7d dc 05          	cmpl   $0x5,-0x24(%rbp)
  12:	7e eb                	jle    0xffffffffffffffff
  14:	83 ec 08             	sub    $0x8,%esp
  17:	8d 45 ee             	lea    -0x12(%rbp),%eax
  1a:	50                   	push   %rax
  1b:	8d 83 44 d6 ff ff    	lea    -0x29bc(%rbx),%eax
  21:	50                   	push   %rax
  22:	e8 54 f6 ff ff       	callq  0xfffffffffffff67b
  27:	83 c4 10             	add    $0x10,%esp
  2a:*	0f 01 45 ee          	sgdt   -0x12(%rbp)		<-- trapping instruction
  2e:	90                   	nop
  2f:	90                   	nop
  30:	90                   	nop
  31:	90                   	nop
  32:	90                   	nop
  33:	90                   	nop
  34:	90                   	nop
  35:	90                   	nop
  36:	90                   	nop
  37:	90                   	nop
  38:	90                   	nop
  39:	90                   	nop
  3a:	90                   	nop
  3b:	90                   	nop
  3c:	83 ec 08             	sub    $0x8,%esp
  3f:	6a                   	.byte 0x6a

Code starting with the faulting instruction
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
   0:	0f 01 45 ee          	sgdt   -0x12(%rbp)
   4:	90                   	nop
   5:	90                   	nop
   6:	90                   	nop
   7:	90                   	nop
   8:	90                   	nop
   9:	90                   	nop
   a:	90                   	nop
   b:	90                   	nop
   c:	90                   	nop
   d:	90                   	nop
   e:	90                   	nop
   f:	90                   	nop
  10:	90                   	nop
  11:	90                   	nop
  12:	83 ec 08             	sub    $0x8,%esp
  15:	6a                   	.byte 0x6a


We are sorry that the testcase and reproducing steps are not available
for this case. Hope the call trace can help to investigate, and we can
also help to do further verification if needed. Thanks.


If you fix the issue, kindly add following tag
| Reported-by: kernel test robot <yujie.liu@intel.com>
| Link: https://lore.kernel.org/oe-lkp/202211121255.f840971-yujie.liu@intel=
.com


--=20
0-DAY CI Kernel Test Service
https://01.org/lkp

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202211121255.f840971-yujie.liu%40intel.com.

--b8seNkh+w+eqQ5nt
Content-Type: text/plain; charset="us-ascii"
Content-Disposition: attachment;
	filename="config-6.1.0-rc2-00001-g9fd429c28073"

#
# Automatically generated file; DO NOT EDIT.
# Linux/x86_64 6.1.0-rc2 Kernel Configuration
#
CONFIG_CC_VERSION_TEXT="gcc-11 (Debian 11.3.0-8) 11.3.0"
CONFIG_CC_IS_GCC=y
CONFIG_GCC_VERSION=110300
CONFIG_CLANG_VERSION=0
CONFIG_AS_IS_GNU=y
CONFIG_AS_VERSION=23900
CONFIG_LD_IS_BFD=y
CONFIG_LD_VERSION=23900
CONFIG_LLD_VERSION=0
CONFIG_CC_CAN_LINK=y
CONFIG_CC_CAN_LINK_STATIC=y
CONFIG_CC_HAS_ASM_GOTO_OUTPUT=y
CONFIG_CC_HAS_ASM_INLINE=y
CONFIG_CC_HAS_NO_PROFILE_FN_ATTR=y
CONFIG_PAHOLE_VERSION=123
CONFIG_CONSTRUCTORS=y
CONFIG_IRQ_WORK=y
CONFIG_BUILDTIME_TABLE_SORT=y
CONFIG_THREAD_INFO_IN_TASK=y

#
# General setup
#
CONFIG_INIT_ENV_ARG_LIMIT=32
# CONFIG_COMPILE_TEST is not set
# CONFIG_WERROR is not set
CONFIG_LOCALVERSION=""
CONFIG_LOCALVERSION_AUTO=y
CONFIG_BUILD_SALT=""
CONFIG_HAVE_KERNEL_GZIP=y
CONFIG_HAVE_KERNEL_BZIP2=y
CONFIG_HAVE_KERNEL_LZMA=y
CONFIG_HAVE_KERNEL_XZ=y
CONFIG_HAVE_KERNEL_LZO=y
CONFIG_HAVE_KERNEL_LZ4=y
CONFIG_HAVE_KERNEL_ZSTD=y
CONFIG_KERNEL_GZIP=y
# CONFIG_KERNEL_BZIP2 is not set
# CONFIG_KERNEL_LZMA is not set
# CONFIG_KERNEL_XZ is not set
# CONFIG_KERNEL_LZO is not set
# CONFIG_KERNEL_LZ4 is not set
# CONFIG_KERNEL_ZSTD is not set
CONFIG_DEFAULT_INIT=""
CONFIG_DEFAULT_HOSTNAME="(none)"
CONFIG_SYSVIPC=y
CONFIG_SYSVIPC_SYSCTL=y
CONFIG_SYSVIPC_COMPAT=y
CONFIG_POSIX_MQUEUE=y
CONFIG_POSIX_MQUEUE_SYSCTL=y
CONFIG_WATCH_QUEUE=y
CONFIG_CROSS_MEMORY_ATTACH=y
# CONFIG_USELIB is not set
CONFIG_AUDIT=y
CONFIG_HAVE_ARCH_AUDITSYSCALL=y
CONFIG_AUDITSYSCALL=y

#
# IRQ subsystem
#
CONFIG_GENERIC_IRQ_PROBE=y
CONFIG_GENERIC_IRQ_SHOW=y
CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK=y
CONFIG_GENERIC_PENDING_IRQ=y
CONFIG_GENERIC_IRQ_MIGRATION=y
CONFIG_GENERIC_IRQ_INJECTION=y
CONFIG_HARDIRQS_SW_RESEND=y
CONFIG_IRQ_DOMAIN=y
CONFIG_IRQ_DOMAIN_HIERARCHY=y
CONFIG_GENERIC_MSI_IRQ=y
CONFIG_GENERIC_MSI_IRQ_DOMAIN=y
CONFIG_IRQ_MSI_IOMMU=y
CONFIG_GENERIC_IRQ_MATRIX_ALLOCATOR=y
CONFIG_GENERIC_IRQ_RESERVATION_MODE=y
CONFIG_IRQ_FORCED_THREADING=y
CONFIG_SPARSE_IRQ=y
# CONFIG_GENERIC_IRQ_DEBUGFS is not set
# end of IRQ subsystem

CONFIG_CLOCKSOURCE_WATCHDOG=y
CONFIG_ARCH_CLOCKSOURCE_INIT=y
CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE=y
CONFIG_GENERIC_TIME_VSYSCALL=y
CONFIG_GENERIC_CLOCKEVENTS=y
CONFIG_GENERIC_CLOCKEVENTS_BROADCAST=y
CONFIG_GENERIC_CLOCKEVENTS_MIN_ADJUST=y
CONFIG_GENERIC_CMOS_UPDATE=y
CONFIG_HAVE_POSIX_CPU_TIMERS_TASK_WORK=y
CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y
CONFIG_CONTEXT_TRACKING=y
CONFIG_CONTEXT_TRACKING_IDLE=y

#
# Timers subsystem
#
CONFIG_TICK_ONESHOT=y
CONFIG_NO_HZ_COMMON=y
# CONFIG_HZ_PERIODIC is not set
# CONFIG_NO_HZ_IDLE is not set
CONFIG_NO_HZ_FULL=y
CONFIG_CONTEXT_TRACKING_USER=y
# CONFIG_CONTEXT_TRACKING_USER_FORCE is not set
CONFIG_NO_HZ=y
CONFIG_HIGH_RES_TIMERS=y
CONFIG_CLOCKSOURCE_WATCHDOG_MAX_SKEW_US=100
# end of Timers subsystem

CONFIG_BPF=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=y

#
# BPF subsystem
#
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_JIT_DEFAULT_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
# CONFIG_BPF_PRELOAD is not set
# CONFIG_BPF_LSM is not set
# end of BPF subsystem

CONFIG_PREEMPT_VOLUNTARY_BUILD=y
# CONFIG_PREEMPT_NONE is not set
CONFIG_PREEMPT_VOLUNTARY=y
# CONFIG_PREEMPT is not set
CONFIG_PREEMPT_COUNT=y
# CONFIG_PREEMPT_DYNAMIC is not set
# CONFIG_SCHED_CORE is not set

#
# CPU/Task time and stats accounting
#
CONFIG_VIRT_CPU_ACCOUNTING=y
CONFIG_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_SCHED_AVG_IRQ=y
CONFIG_BSD_PROCESS_ACCT=y
CONFIG_BSD_PROCESS_ACCT_V3=y
CONFIG_TASKSTATS=y
CONFIG_TASK_DELAY_ACCT=y
CONFIG_TASK_XACCT=y
CONFIG_TASK_IO_ACCOUNTING=y
# CONFIG_PSI is not set
# end of CPU/Task time and stats accounting

CONFIG_CPU_ISOLATION=y

#
# RCU Subsystem
#
CONFIG_TREE_RCU=y
CONFIG_RCU_EXPERT=y
CONFIG_SRCU=y
CONFIG_TREE_SRCU=y
CONFIG_TASKS_RCU_GENERIC=y
CONFIG_FORCE_TASKS_RCU=y
CONFIG_TASKS_RCU=y
# CONFIG_FORCE_TASKS_RUDE_RCU is not set
CONFIG_TASKS_RUDE_RCU=y
CONFIG_FORCE_TASKS_TRACE_RCU=y
CONFIG_TASKS_TRACE_RCU=y
CONFIG_RCU_STALL_COMMON=y
CONFIG_RCU_NEED_SEGCBLIST=y
CONFIG_RCU_FANOUT=64
CONFIG_RCU_FANOUT_LEAF=16
CONFIG_RCU_NOCB_CPU=y
# CONFIG_RCU_NOCB_CPU_DEFAULT_ALL is not set
# CONFIG_TASKS_TRACE_RCU_READ_MB is not set
# end of RCU Subsystem

CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
# CONFIG_IKHEADERS is not set
CONFIG_LOG_BUF_SHIFT=20
CONFIG_LOG_CPU_MAX_BUF_SHIFT=12
CONFIG_PRINTK_SAFE_LOG_BUF_SHIFT=13
# CONFIG_PRINTK_INDEX is not set
CONFIG_HAVE_UNSTABLE_SCHED_CLOCK=y

#
# Scheduler features
#
# CONFIG_UCLAMP_TASK is not set
# end of Scheduler features

CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=y
CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH=y
CONFIG_CC_HAS_INT128=y
CONFIG_CC_IMPLICIT_FALLTHROUGH="-Wimplicit-fallthrough=5"
CONFIG_GCC12_NO_ARRAY_BOUNDS=y
CONFIG_ARCH_SUPPORTS_INT128=y
CONFIG_NUMA_BALANCING=y
CONFIG_NUMA_BALANCING_DEFAULT_ENABLED=y
CONFIG_CGROUPS=y
CONFIG_PAGE_COUNTER=y
# CONFIG_CGROUP_FAVOR_DYNMODS is not set
CONFIG_MEMCG=y
CONFIG_MEMCG_KMEM=y
CONFIG_BLK_CGROUP=y
CONFIG_CGROUP_WRITEBACK=y
CONFIG_CGROUP_SCHED=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_CFS_BANDWIDTH=y
CONFIG_RT_GROUP_SCHED=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_RDMA=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CPUSETS=y
CONFIG_PROC_PID_CPUSET=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_PERF=y
# CONFIG_CGROUP_BPF is not set
# CONFIG_CGROUP_MISC is not set
# CONFIG_CGROUP_DEBUG is not set
CONFIG_SOCK_CGROUP_DATA=y
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_TIME_NS=y
CONFIG_IPC_NS=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CHECKPOINT_RESTORE=y
CONFIG_SCHED_AUTOGROUP=y
# CONFIG_SYSFS_DEPRECATED is not set
CONFIG_RELAY=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_INITRAMFS_SOURCE=""
CONFIG_RD_GZIP=y
CONFIG_RD_BZIP2=y
CONFIG_RD_LZMA=y
CONFIG_RD_XZ=y
CONFIG_RD_LZO=y
CONFIG_RD_LZ4=y
CONFIG_RD_ZSTD=y
# CONFIG_BOOT_CONFIG is not set
CONFIG_INITRAMFS_PRESERVE_MTIME=y
CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y
# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
CONFIG_LD_ORPHAN_WARN=y
CONFIG_SYSCTL=y
CONFIG_HAVE_UID16=y
CONFIG_SYSCTL_EXCEPTION_TRACE=y
CONFIG_HAVE_PCSPKR_PLATFORM=y
CONFIG_EXPERT=y
CONFIG_UID16=y
CONFIG_MULTIUSER=y
CONFIG_SGETMASK_SYSCALL=y
CONFIG_SYSFS_SYSCALL=y
CONFIG_FHANDLE=y
CONFIG_POSIX_TIMERS=y
CONFIG_PRINTK=y
CONFIG_BUG=y
CONFIG_ELF_CORE=y
CONFIG_PCSPKR_PLATFORM=y
CONFIG_BASE_FULL=y
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_SHMEM=y
CONFIG_AIO=y
CONFIG_IO_URING=y
CONFIG_ADVISE_SYSCALLS=y
CONFIG_MEMBARRIER=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y
CONFIG_KALLSYMS_BASE_RELATIVE=y
CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE=y
CONFIG_KCMP=y
CONFIG_RSEQ=y
# CONFIG_DEBUG_RSEQ is not set
# CONFIG_EMBEDDED is not set
CONFIG_HAVE_PERF_EVENTS=y
CONFIG_GUEST_PERF_EVENTS=y
# CONFIG_PC104 is not set

#
# Kernel Performance Events And Counters
#
CONFIG_PERF_EVENTS=y
# CONFIG_DEBUG_PERF_USE_VMALLOC is not set
# end of Kernel Performance Events And Counters

CONFIG_SYSTEM_DATA_VERIFICATION=y
CONFIG_PROFILING=y
CONFIG_TRACEPOINTS=y
# end of General setup

CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_X86=y
CONFIG_INSTRUCTION_DECODER=y
CONFIG_OUTPUT_FORMAT="elf64-x86-64"
CONFIG_LOCKDEP_SUPPORT=y
CONFIG_STACKTRACE_SUPPORT=y
CONFIG_MMU=y
CONFIG_ARCH_MMAP_RND_BITS_MIN=28
CONFIG_ARCH_MMAP_RND_BITS_MAX=32
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=8
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX=16
CONFIG_GENERIC_ISA_DMA=y
CONFIG_GENERIC_CSUM=y
CONFIG_GENERIC_BUG=y
CONFIG_GENERIC_BUG_RELATIVE_POINTERS=y
CONFIG_ARCH_MAY_HAVE_PC_FDC=y
CONFIG_GENERIC_CALIBRATE_DELAY=y
CONFIG_ARCH_HAS_CPU_RELAX=y
CONFIG_ARCH_HIBERNATION_POSSIBLE=y
CONFIG_ARCH_NR_GPIO=1024
CONFIG_ARCH_SUSPEND_POSSIBLE=y
CONFIG_AUDIT_ARCH=y
CONFIG_KASAN_SHADOW_OFFSET=0xdffffc0000000000
CONFIG_HAVE_INTEL_TXT=y
CONFIG_X86_64_SMP=y
CONFIG_ARCH_SUPPORTS_UPROBES=y
CONFIG_FIX_EARLYCON_MEM=y
CONFIG_DYNAMIC_PHYSICAL_MASK=y
CONFIG_PGTABLE_LEVELS=5
CONFIG_CC_HAS_SANE_STACKPROTECTOR=y

#
# Processor type and features
#
CONFIG_SMP=y
CONFIG_X86_FEATURE_NAMES=y
CONFIG_X86_X2APIC=y
CONFIG_X86_MPPARSE=y
# CONFIG_GOLDFISH is not set
# CONFIG_X86_CPU_RESCTRL is not set
CONFIG_X86_EXTENDED_PLATFORM=y
# CONFIG_X86_NUMACHIP is not set
# CONFIG_X86_VSMP is not set
CONFIG_X86_UV=y
# CONFIG_X86_GOLDFISH is not set
# CONFIG_X86_INTEL_MID is not set
CONFIG_X86_INTEL_LPSS=y
# CONFIG_X86_AMD_PLATFORM_DEVICE is not set
CONFIG_IOSF_MBI=y
# CONFIG_IOSF_MBI_DEBUG is not set
CONFIG_X86_SUPPORTS_MEMORY_FAILURE=y
# CONFIG_SCHED_OMIT_FRAME_POINTER is not set
CONFIG_HYPERVISOR_GUEST=y
CONFIG_PARAVIRT=y
# CONFIG_PARAVIRT_DEBUG is not set
CONFIG_PARAVIRT_SPINLOCKS=y
CONFIG_X86_HV_CALLBACK_VECTOR=y
# CONFIG_XEN is not set
CONFIG_KVM_GUEST=y
CONFIG_ARCH_CPUIDLE_HALTPOLL=y
# CONFIG_PVH is not set
CONFIG_PARAVIRT_TIME_ACCOUNTING=y
CONFIG_PARAVIRT_CLOCK=y
# CONFIG_JAILHOUSE_GUEST is not set
# CONFIG_ACRN_GUEST is not set
CONFIG_INTEL_TDX_GUEST=y
# CONFIG_MK8 is not set
# CONFIG_MPSC is not set
# CONFIG_MCORE2 is not set
# CONFIG_MATOM is not set
CONFIG_GENERIC_CPU=y
CONFIG_X86_INTERNODE_CACHE_SHIFT=6
CONFIG_X86_L1_CACHE_SHIFT=6
CONFIG_X86_TSC=y
CONFIG_X86_CMPXCHG64=y
CONFIG_X86_CMOV=y
CONFIG_X86_MINIMUM_CPU_FAMILY=64
CONFIG_X86_DEBUGCTLMSR=y
CONFIG_IA32_FEAT_CTL=y
CONFIG_X86_VMX_FEATURE_NAMES=y
CONFIG_PROCESSOR_SELECT=y
CONFIG_CPU_SUP_INTEL=y
# CONFIG_CPU_SUP_AMD is not set
# CONFIG_CPU_SUP_HYGON is not set
# CONFIG_CPU_SUP_CENTAUR is not set
# CONFIG_CPU_SUP_ZHAOXIN is not set
CONFIG_HPET_TIMER=y
CONFIG_HPET_EMULATE_RTC=y
CONFIG_DMI=y
CONFIG_BOOT_VESA_SUPPORT=y
CONFIG_MAXSMP=y
CONFIG_NR_CPUS_RANGE_BEGIN=8192
CONFIG_NR_CPUS_RANGE_END=8192
CONFIG_NR_CPUS_DEFAULT=8192
CONFIG_NR_CPUS=8192
CONFIG_SCHED_CLUSTER=y
CONFIG_SCHED_SMT=y
CONFIG_SCHED_MC=y
CONFIG_SCHED_MC_PRIO=y
CONFIG_X86_LOCAL_APIC=y
CONFIG_X86_IO_APIC=y
CONFIG_X86_REROUTE_FOR_BROKEN_BOOT_IRQS=y
CONFIG_X86_MCE=y
CONFIG_X86_MCELOG_LEGACY=y
CONFIG_X86_MCE_INTEL=y
CONFIG_X86_MCE_THRESHOLD=y
CONFIG_X86_MCE_INJECT=m

#
# Performance monitoring
#
CONFIG_PERF_EVENTS_INTEL_UNCORE=m
CONFIG_PERF_EVENTS_INTEL_RAPL=m
CONFIG_PERF_EVENTS_INTEL_CSTATE=m
# end of Performance monitoring

CONFIG_X86_16BIT=y
CONFIG_X86_ESPFIX64=y
CONFIG_X86_VSYSCALL_EMULATION=y
CONFIG_X86_IOPL_IOPERM=y
CONFIG_MICROCODE=y
CONFIG_MICROCODE_INTEL=y
CONFIG_MICROCODE_LATE_LOADING=y
CONFIG_X86_MSR=y
CONFIG_X86_CPUID=y
CONFIG_X86_5LEVEL=y
CONFIG_X86_DIRECT_GBPAGES=y
# CONFIG_X86_CPA_STATISTICS is not set
CONFIG_X86_MEM_ENCRYPT=y
CONFIG_NUMA=y
# CONFIG_AMD_NUMA is not set
CONFIG_X86_64_ACPI_NUMA=y
CONFIG_NUMA_EMU=y
CONFIG_NODES_SHIFT=10
CONFIG_ARCH_SPARSEMEM_ENABLE=y
CONFIG_ARCH_SPARSEMEM_DEFAULT=y
# CONFIG_ARCH_MEMORY_PROBE is not set
CONFIG_ARCH_PROC_KCORE_TEXT=y
CONFIG_ILLEGAL_POINTER_VALUE=0xdead000000000000
CONFIG_X86_PMEM_LEGACY_DEVICE=y
CONFIG_X86_PMEM_LEGACY=m
CONFIG_X86_CHECK_BIOS_CORRUPTION=y
# CONFIG_X86_BOOTPARAM_MEMORY_CORRUPTION_CHECK is not set
CONFIG_MTRR=y
CONFIG_MTRR_SANITIZER=y
CONFIG_MTRR_SANITIZER_ENABLE_DEFAULT=1
CONFIG_MTRR_SANITIZER_SPARE_REG_NR_DEFAULT=1
CONFIG_X86_PAT=y
CONFIG_ARCH_USES_PG_UNCACHED=y
CONFIG_X86_UMIP=y
CONFIG_CC_HAS_IBT=y
# CONFIG_X86_KERNEL_IBT is not set
CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=y
# CONFIG_X86_INTEL_TSX_MODE_OFF is not set
# CONFIG_X86_INTEL_TSX_MODE_ON is not set
CONFIG_X86_INTEL_TSX_MODE_AUTO=y
# CONFIG_X86_SGX is not set
CONFIG_EFI=y
CONFIG_EFI_STUB=y
CONFIG_EFI_MIXED=y
# CONFIG_HZ_100 is not set
# CONFIG_HZ_250 is not set
# CONFIG_HZ_300 is not set
CONFIG_HZ_1000=y
CONFIG_HZ=1000
CONFIG_SCHED_HRTICK=y
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
CONFIG_ARCH_HAS_KEXEC_PURGATORY=y
# CONFIG_KEXEC_SIG is not set
CONFIG_CRASH_DUMP=y
CONFIG_KEXEC_JUMP=y
CONFIG_PHYSICAL_START=0x1000000
CONFIG_RELOCATABLE=y
# CONFIG_RANDOMIZE_BASE is not set
CONFIG_PHYSICAL_ALIGN=0x200000
CONFIG_DYNAMIC_MEMORY_LAYOUT=y
CONFIG_HOTPLUG_CPU=y
CONFIG_BOOTPARAM_HOTPLUG_CPU0=y
# CONFIG_DEBUG_HOTPLUG_CPU0 is not set
# CONFIG_COMPAT_VDSO is not set
CONFIG_LEGACY_VSYSCALL_XONLY=y
# CONFIG_LEGACY_VSYSCALL_NONE is not set
# CONFIG_CMDLINE_BOOL is not set
CONFIG_MODIFY_LDT_SYSCALL=y
# CONFIG_STRICT_SIGALTSTACK_SIZE is not set
CONFIG_HAVE_LIVEPATCH=y
CONFIG_LIVEPATCH=y
# end of Processor type and features

CONFIG_CC_HAS_SLS=y
CONFIG_CC_HAS_RETURN_THUNK=y
CONFIG_SPECULATION_MITIGATIONS=y
CONFIG_PAGE_TABLE_ISOLATION=y
# CONFIG_RETPOLINE is not set
CONFIG_CPU_IBRS_ENTRY=y
# CONFIG_SLS is not set
CONFIG_ARCH_HAS_ADD_PAGES=y
CONFIG_ARCH_MHP_MEMMAP_ON_MEMORY_ENABLE=y

#
# Power management and ACPI options
#
CONFIG_ARCH_HIBERNATION_HEADER=y
CONFIG_SUSPEND=y
CONFIG_SUSPEND_FREEZER=y
# CONFIG_SUSPEND_SKIP_SYNC is not set
CONFIG_HIBERNATE_CALLBACKS=y
CONFIG_HIBERNATION=y
CONFIG_HIBERNATION_SNAPSHOT_DEV=y
CONFIG_PM_STD_PARTITION=""
CONFIG_PM_SLEEP=y
CONFIG_PM_SLEEP_SMP=y
# CONFIG_PM_AUTOSLEEP is not set
# CONFIG_PM_USERSPACE_AUTOSLEEP is not set
# CONFIG_PM_WAKELOCKS is not set
CONFIG_PM=y
CONFIG_PM_DEBUG=y
# CONFIG_PM_ADVANCED_DEBUG is not set
# CONFIG_PM_TEST_SUSPEND is not set
CONFIG_PM_SLEEP_DEBUG=y
# CONFIG_DPM_WATCHDOG is not set
# CONFIG_PM_TRACE_RTC is not set
CONFIG_PM_CLK=y
# CONFIG_WQ_POWER_EFFICIENT_DEFAULT is not set
# CONFIG_ENERGY_MODEL is not set
CONFIG_ARCH_SUPPORTS_ACPI=y
CONFIG_ACPI=y
CONFIG_ACPI_LEGACY_TABLES_LOOKUP=y
CONFIG_ARCH_MIGHT_HAVE_ACPI_PDC=y
CONFIG_ACPI_SYSTEM_POWER_STATES_SUPPORT=y
# CONFIG_ACPI_DEBUGGER is not set
CONFIG_ACPI_SPCR_TABLE=y
# CONFIG_ACPI_FPDT is not set
CONFIG_ACPI_LPIT=y
CONFIG_ACPI_SLEEP=y
CONFIG_ACPI_REV_OVERRIDE_POSSIBLE=y
CONFIG_ACPI_EC_DEBUGFS=m
CONFIG_ACPI_AC=y
CONFIG_ACPI_BATTERY=y
CONFIG_ACPI_BUTTON=y
CONFIG_ACPI_VIDEO=m
CONFIG_ACPI_FAN=y
CONFIG_ACPI_TAD=m
CONFIG_ACPI_DOCK=y
CONFIG_ACPI_CPU_FREQ_PSS=y
CONFIG_ACPI_PROCESSOR_CSTATE=y
CONFIG_ACPI_PROCESSOR_IDLE=y
CONFIG_ACPI_CPPC_LIB=y
CONFIG_ACPI_PROCESSOR=y
CONFIG_ACPI_IPMI=m
CONFIG_ACPI_HOTPLUG_CPU=y
CONFIG_ACPI_PROCESSOR_AGGREGATOR=m
CONFIG_ACPI_THERMAL=y
CONFIG_ACPI_PLATFORM_PROFILE=m
CONFIG_ARCH_HAS_ACPI_TABLE_UPGRADE=y
CONFIG_ACPI_TABLE_UPGRADE=y
# CONFIG_ACPI_DEBUG is not set
CONFIG_ACPI_PCI_SLOT=y
CONFIG_ACPI_CONTAINER=y
CONFIG_ACPI_HOTPLUG_MEMORY=y
CONFIG_ACPI_HOTPLUG_IOAPIC=y
CONFIG_ACPI_SBS=m
CONFIG_ACPI_HED=y
# CONFIG_ACPI_CUSTOM_METHOD is not set
CONFIG_ACPI_BGRT=y
# CONFIG_ACPI_REDUCED_HARDWARE_ONLY is not set
CONFIG_ACPI_NFIT=m
# CONFIG_NFIT_SECURITY_DEBUG is not set
CONFIG_ACPI_NUMA=y
# CONFIG_ACPI_HMAT is not set
CONFIG_HAVE_ACPI_APEI=y
CONFIG_HAVE_ACPI_APEI_NMI=y
CONFIG_ACPI_APEI=y
CONFIG_ACPI_APEI_GHES=y
CONFIG_ACPI_APEI_PCIEAER=y
CONFIG_ACPI_APEI_MEMORY_FAILURE=y
CONFIG_ACPI_APEI_EINJ=m
# CONFIG_ACPI_APEI_ERST_DEBUG is not set
# CONFIG_ACPI_DPTF is not set
CONFIG_ACPI_WATCHDOG=y
CONFIG_ACPI_EXTLOG=m
CONFIG_ACPI_ADXL=y
# CONFIG_ACPI_CONFIGFS is not set
# CONFIG_ACPI_PFRUT is not set
CONFIG_ACPI_PCC=y
CONFIG_PMIC_OPREGION=y
CONFIG_ACPI_PRMT=y
CONFIG_X86_PM_TIMER=y

#
# CPU Frequency scaling
#
CONFIG_CPU_FREQ=y
CONFIG_CPU_FREQ_GOV_ATTR_SET=y
CONFIG_CPU_FREQ_GOV_COMMON=y
CONFIG_CPU_FREQ_STAT=y
CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE=y
# CONFIG_CPU_FREQ_DEFAULT_GOV_POWERSAVE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_USERSPACE is not set
# CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL is not set
CONFIG_CPU_FREQ_GOV_PERFORMANCE=y
CONFIG_CPU_FREQ_GOV_POWERSAVE=y
CONFIG_CPU_FREQ_GOV_USERSPACE=y
CONFIG_CPU_FREQ_GOV_ONDEMAND=y
CONFIG_CPU_FREQ_GOV_CONSERVATIVE=y
CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y

#
# CPU frequency scaling drivers
#
CONFIG_X86_INTEL_PSTATE=y
# CONFIG_X86_PCC_CPUFREQ is not set
# CONFIG_X86_AMD_PSTATE is not set
# CONFIG_X86_AMD_PSTATE_UT is not set
CONFIG_X86_ACPI_CPUFREQ=m
# CONFIG_X86_POWERNOW_K8 is not set
# CONFIG_X86_SPEEDSTEP_CENTRINO is not set
CONFIG_X86_P4_CLOCKMOD=m

#
# shared options
#
CONFIG_X86_SPEEDSTEP_LIB=m
# end of CPU Frequency scaling

#
# CPU Idle
#
CONFIG_CPU_IDLE=y
# CONFIG_CPU_IDLE_GOV_LADDER is not set
CONFIG_CPU_IDLE_GOV_MENU=y
# CONFIG_CPU_IDLE_GOV_TEO is not set
# CONFIG_CPU_IDLE_GOV_HALTPOLL is not set
CONFIG_HALTPOLL_CPUIDLE=y
# end of CPU Idle

CONFIG_INTEL_IDLE=y
# end of Power management and ACPI options

#
# Bus options (PCI etc.)
#
CONFIG_PCI_DIRECT=y
CONFIG_PCI_MMCONFIG=y
CONFIG_MMCONF_FAM10H=y
# CONFIG_PCI_CNB20LE_QUIRK is not set
# CONFIG_ISA_BUS is not set
CONFIG_ISA_DMA_API=y
# end of Bus options (PCI etc.)

#
# Binary Emulations
#
CONFIG_IA32_EMULATION=y
# CONFIG_X86_X32_ABI is not set
CONFIG_COMPAT_32=y
CONFIG_COMPAT=y
CONFIG_COMPAT_FOR_U64_ALIGNMENT=y
# end of Binary Emulations

CONFIG_HAVE_KVM=y
CONFIG_HAVE_KVM_PFNCACHE=y
CONFIG_HAVE_KVM_IRQCHIP=y
CONFIG_HAVE_KVM_IRQFD=y
CONFIG_HAVE_KVM_IRQ_ROUTING=y
CONFIG_HAVE_KVM_DIRTY_RING=y
CONFIG_HAVE_KVM_DIRTY_RING_TSO=y
CONFIG_HAVE_KVM_DIRTY_RING_ACQ_REL=y
CONFIG_HAVE_KVM_EVENTFD=y
CONFIG_KVM_MMIO=y
CONFIG_KVM_ASYNC_PF=y
CONFIG_HAVE_KVM_MSI=y
CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT=y
CONFIG_KVM_VFIO=y
CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT=y
CONFIG_KVM_COMPAT=y
CONFIG_HAVE_KVM_IRQ_BYPASS=y
CONFIG_HAVE_KVM_NO_POLL=y
CONFIG_KVM_XFER_TO_GUEST_WORK=y
CONFIG_HAVE_KVM_PM_NOTIFIER=y
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=m
# CONFIG_KVM_WERROR is not set
CONFIG_KVM_INTEL=m
# CONFIG_KVM_AMD is not set
# CONFIG_KVM_XEN is not set
CONFIG_AS_AVX512=y
CONFIG_AS_SHA1_NI=y
CONFIG_AS_SHA256_NI=y
CONFIG_AS_TPAUSE=y

#
# General architecture-dependent options
#
CONFIG_CRASH_CORE=y
CONFIG_KEXEC_CORE=y
CONFIG_HOTPLUG_SMT=y
CONFIG_GENERIC_ENTRY=y
CONFIG_KPROBES=y
CONFIG_JUMP_LABEL=y
# CONFIG_STATIC_KEYS_SELFTEST is not set
# CONFIG_STATIC_CALL_SELFTEST is not set
CONFIG_OPTPROBES=y
CONFIG_KPROBES_ON_FTRACE=y
CONFIG_UPROBES=y
CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS=y
CONFIG_ARCH_USE_BUILTIN_BSWAP=y
CONFIG_KRETPROBES=y
CONFIG_KRETPROBE_ON_RETHOOK=y
CONFIG_USER_RETURN_NOTIFIER=y
CONFIG_HAVE_IOREMAP_PROT=y
CONFIG_HAVE_KPROBES=y
CONFIG_HAVE_KRETPROBES=y
CONFIG_HAVE_OPTPROBES=y
CONFIG_HAVE_KPROBES_ON_FTRACE=y
CONFIG_ARCH_CORRECT_STACKTRACE_ON_KRETPROBE=y
CONFIG_HAVE_FUNCTION_ERROR_INJECTION=y
CONFIG_HAVE_NMI=y
CONFIG_TRACE_IRQFLAGS_SUPPORT=y
CONFIG_TRACE_IRQFLAGS_NMI_SUPPORT=y
CONFIG_HAVE_ARCH_TRACEHOOK=y
CONFIG_HAVE_DMA_CONTIGUOUS=y
CONFIG_GENERIC_SMP_IDLE_THREAD=y
CONFIG_ARCH_HAS_FORTIFY_SOURCE=y
CONFIG_ARCH_HAS_SET_MEMORY=y
CONFIG_ARCH_HAS_SET_DIRECT_MAP=y
CONFIG_HAVE_ARCH_THREAD_STRUCT_WHITELIST=y
CONFIG_ARCH_WANTS_DYNAMIC_TASK_STRUCT=y
CONFIG_ARCH_WANTS_NO_INSTR=y
CONFIG_HAVE_ASM_MODVERSIONS=y
CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=y
CONFIG_HAVE_RSEQ=y
CONFIG_HAVE_RUST=y
CONFIG_HAVE_FUNCTION_ARG_ACCESS_API=y
CONFIG_HAVE_HW_BREAKPOINT=y
CONFIG_HAVE_MIXED_BREAKPOINTS_REGS=y
CONFIG_HAVE_USER_RETURN_NOTIFIER=y
CONFIG_HAVE_PERF_EVENTS_NMI=y
CONFIG_HAVE_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HAVE_PERF_REGS=y
CONFIG_HAVE_PERF_USER_STACK_DUMP=y
CONFIG_HAVE_ARCH_JUMP_LABEL=y
CONFIG_HAVE_ARCH_JUMP_LABEL_RELATIVE=y
CONFIG_MMU_GATHER_TABLE_FREE=y
CONFIG_MMU_GATHER_RCU_TABLE_FREE=y
CONFIG_MMU_GATHER_MERGE_VMAS=y
CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG=y
CONFIG_HAVE_ALIGNED_STRUCT_PAGE=y
CONFIG_HAVE_CMPXCHG_LOCAL=y
CONFIG_HAVE_CMPXCHG_DOUBLE=y
CONFIG_ARCH_WANT_COMPAT_IPC_PARSE_VERSION=y
CONFIG_ARCH_WANT_OLD_COMPAT_IPC=y
CONFIG_HAVE_ARCH_SECCOMP=y
CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
# CONFIG_SECCOMP_CACHE_DEBUG is not set
CONFIG_HAVE_ARCH_STACKLEAK=y
CONFIG_HAVE_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
CONFIG_ARCH_SUPPORTS_LTO_CLANG=y
CONFIG_ARCH_SUPPORTS_LTO_CLANG_THIN=y
CONFIG_LTO_NONE=y
CONFIG_ARCH_SUPPORTS_CFI_CLANG=y
CONFIG_HAVE_ARCH_WITHIN_STACK_FRAMES=y
CONFIG_HAVE_CONTEXT_TRACKING_USER=y
CONFIG_HAVE_CONTEXT_TRACKING_USER_OFFSTACK=y
CONFIG_HAVE_VIRT_CPU_ACCOUNTING_GEN=y
CONFIG_HAVE_IRQ_TIME_ACCOUNTING=y
CONFIG_HAVE_MOVE_PUD=y
CONFIG_HAVE_MOVE_PMD=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE=y
CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD=y
CONFIG_HAVE_ARCH_HUGE_VMAP=y
CONFIG_HAVE_ARCH_HUGE_VMALLOC=y
CONFIG_ARCH_WANT_HUGE_PMD_SHARE=y
CONFIG_HAVE_ARCH_SOFT_DIRTY=y
CONFIG_HAVE_MOD_ARCH_SPECIFIC=y
CONFIG_MODULES_USE_ELF_RELA=y
CONFIG_HAVE_IRQ_EXIT_ON_IRQ_STACK=y
CONFIG_HAVE_SOFTIRQ_ON_OWN_STACK=y
CONFIG_SOFTIRQ_ON_OWN_STACK=y
CONFIG_ARCH_HAS_ELF_RANDOMIZE=y
CONFIG_HAVE_ARCH_MMAP_RND_BITS=y
CONFIG_HAVE_EXIT_THREAD=y
CONFIG_ARCH_MMAP_RND_BITS=28
CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=y
CONFIG_ARCH_MMAP_RND_COMPAT_BITS=8
CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES=y
CONFIG_PAGE_SIZE_LESS_THAN_64KB=y
CONFIG_PAGE_SIZE_LESS_THAN_256KB=y
CONFIG_HAVE_OBJTOOL=y
CONFIG_HAVE_JUMP_LABEL_HACK=y
CONFIG_HAVE_NOINSTR_HACK=y
CONFIG_HAVE_NOINSTR_VALIDATION=y
CONFIG_HAVE_UACCESS_VALIDATION=y
CONFIG_HAVE_STACK_VALIDATION=y
CONFIG_HAVE_RELIABLE_STACKTRACE=y
CONFIG_OLD_SIGSUSPEND3=y
CONFIG_COMPAT_OLD_SIGACTION=y
CONFIG_COMPAT_32BIT_TIME=y
CONFIG_HAVE_ARCH_VMAP_STACK=y
CONFIG_VMAP_STACK=y
CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET=y
CONFIG_RANDOMIZE_KSTACK_OFFSET=y
# CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT is not set
CONFIG_ARCH_HAS_STRICT_KERNEL_RWX=y
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_ARCH_HAS_STRICT_MODULE_RWX=y
CONFIG_STRICT_MODULE_RWX=y
CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y
CONFIG_ARCH_USE_MEMREMAP_PROT=y
# CONFIG_LOCK_EVENT_COUNTS is not set
CONFIG_ARCH_HAS_MEM_ENCRYPT=y
CONFIG_ARCH_HAS_CC_PLATFORM=y
CONFIG_HAVE_STATIC_CALL=y
CONFIG_HAVE_STATIC_CALL_INLINE=y
CONFIG_HAVE_PREEMPT_DYNAMIC=y
CONFIG_HAVE_PREEMPT_DYNAMIC_CALL=y
CONFIG_ARCH_WANT_LD_ORPHAN_WARN=y
CONFIG_ARCH_SUPPORTS_DEBUG_PAGEALLOC=y
CONFIG_ARCH_SUPPORTS_PAGE_TABLE_CHECK=y
CONFIG_ARCH_HAS_ELFCORE_COMPAT=y
CONFIG_ARCH_HAS_PARANOID_L1D_FLUSH=y
CONFIG_DYNAMIC_SIGFRAME=y
CONFIG_ARCH_HAS_NONLEAF_PMD_YOUNG=y

#
# GCOV-based kernel profiling
#
# CONFIG_GCOV_KERNEL is not set
CONFIG_ARCH_HAS_GCOV_PROFILE_ALL=y
# end of GCOV-based kernel profiling

CONFIG_HAVE_GCC_PLUGINS=y
CONFIG_GCC_PLUGINS=y
# CONFIG_GCC_PLUGIN_LATENT_ENTROPY is not set
# end of General architecture-dependent options

CONFIG_RT_MUTEXES=y
CONFIG_BASE_SMALL=0
CONFIG_MODULE_SIG_FORMAT=y
CONFIG_MODULES=y
CONFIG_MODULE_FORCE_LOAD=y
CONFIG_MODULE_UNLOAD=y
# CONFIG_MODULE_FORCE_UNLOAD is not set
# CONFIG_MODULE_UNLOAD_TAINT_TRACKING is not set
# CONFIG_MODVERSIONS is not set
# CONFIG_MODULE_SRCVERSION_ALL is not set
CONFIG_MODULE_SIG=y
# CONFIG_MODULE_SIG_FORCE is not set
CONFIG_MODULE_SIG_ALL=y
# CONFIG_MODULE_SIG_SHA1 is not set
# CONFIG_MODULE_SIG_SHA224 is not set
CONFIG_MODULE_SIG_SHA256=y
# CONFIG_MODULE_SIG_SHA384 is not set
# CONFIG_MODULE_SIG_SHA512 is not set
CONFIG_MODULE_SIG_HASH="sha256"
CONFIG_MODULE_COMPRESS_NONE=y
# CONFIG_MODULE_COMPRESS_GZIP is not set
# CONFIG_MODULE_COMPRESS_XZ is not set
# CONFIG_MODULE_COMPRESS_ZSTD is not set
# CONFIG_MODULE_ALLOW_MISSING_NAMESPACE_IMPORTS is not set
CONFIG_MODPROBE_PATH="/sbin/modprobe"
# CONFIG_TRIM_UNUSED_KSYMS is not set
CONFIG_MODULES_TREE_LOOKUP=y
CONFIG_BLOCK=y
CONFIG_BLOCK_LEGACY_AUTOLOAD=y
CONFIG_BLK_CGROUP_RWSTAT=y
CONFIG_BLK_DEV_BSG_COMMON=y
CONFIG_BLK_ICQ=y
CONFIG_BLK_DEV_BSGLIB=y
CONFIG_BLK_DEV_INTEGRITY=y
CONFIG_BLK_DEV_INTEGRITY_T10=m
CONFIG_BLK_DEV_ZONED=y
CONFIG_BLK_DEV_THROTTLING=y
# CONFIG_BLK_DEV_THROTTLING_LOW is not set
CONFIG_BLK_WBT=y
CONFIG_BLK_WBT_MQ=y
# CONFIG_BLK_CGROUP_IOLATENCY is not set
# CONFIG_BLK_CGROUP_IOCOST is not set
# CONFIG_BLK_CGROUP_IOPRIO is not set
CONFIG_BLK_DEBUG_FS=y
CONFIG_BLK_DEBUG_FS_ZONED=y
# CONFIG_BLK_SED_OPAL is not set
# CONFIG_BLK_INLINE_ENCRYPTION is not set

#
# Partition Types
#
# CONFIG_PARTITION_ADVANCED is not set
CONFIG_MSDOS_PARTITION=y
CONFIG_EFI_PARTITION=y
# end of Partition Types

CONFIG_BLOCK_COMPAT=y
CONFIG_BLK_MQ_PCI=y
CONFIG_BLK_MQ_VIRTIO=y
CONFIG_BLK_MQ_RDMA=y
CONFIG_BLK_PM=y
CONFIG_BLOCK_HOLDER_DEPRECATED=y
CONFIG_BLK_MQ_STACKING=y

#
# IO Schedulers
#
CONFIG_MQ_IOSCHED_DEADLINE=y
CONFIG_MQ_IOSCHED_KYBER=y
CONFIG_IOSCHED_BFQ=y
CONFIG_BFQ_GROUP_IOSCHED=y
# CONFIG_BFQ_CGROUP_DEBUG is not set
# end of IO Schedulers

CONFIG_PREEMPT_NOTIFIERS=y
CONFIG_PADATA=y
CONFIG_ASN1=y
CONFIG_INLINE_SPIN_UNLOCK_IRQ=y
CONFIG_INLINE_READ_UNLOCK=y
CONFIG_INLINE_READ_UNLOCK_IRQ=y
CONFIG_INLINE_WRITE_UNLOCK=y
CONFIG_INLINE_WRITE_UNLOCK_IRQ=y
CONFIG_ARCH_SUPPORTS_ATOMIC_RMW=y
CONFIG_MUTEX_SPIN_ON_OWNER=y
CONFIG_RWSEM_SPIN_ON_OWNER=y
CONFIG_LOCK_SPIN_ON_OWNER=y
CONFIG_ARCH_USE_QUEUED_SPINLOCKS=y
CONFIG_QUEUED_SPINLOCKS=y
CONFIG_ARCH_USE_QUEUED_RWLOCKS=y
CONFIG_QUEUED_RWLOCKS=y
CONFIG_ARCH_HAS_NON_OVERLAPPING_ADDRESS_SPACE=y
CONFIG_ARCH_HAS_SYNC_CORE_BEFORE_USERMODE=y
CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y
CONFIG_FREEZER=y

#
# Executable file formats
#
CONFIG_BINFMT_ELF=y
CONFIG_COMPAT_BINFMT_ELF=y
CONFIG_ELFCORE=y
CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS=y
CONFIG_BINFMT_SCRIPT=y
CONFIG_BINFMT_MISC=m
CONFIG_COREDUMP=y
# end of Executable file formats

#
# Memory Management options
#
CONFIG_ZPOOL=y
CONFIG_SWAP=y
CONFIG_ZSWAP=y
# CONFIG_ZSWAP_DEFAULT_ON is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_DEFLATE is not set
CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZO=y
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_842 is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZ4 is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_LZ4HC is not set
# CONFIG_ZSWAP_COMPRESSOR_DEFAULT_ZSTD is not set
CONFIG_ZSWAP_COMPRESSOR_DEFAULT="lzo"
CONFIG_ZSWAP_ZPOOL_DEFAULT_ZBUD=y
# CONFIG_ZSWAP_ZPOOL_DEFAULT_Z3FOLD is not set
# CONFIG_ZSWAP_ZPOOL_DEFAULT_ZSMALLOC is not set
CONFIG_ZSWAP_ZPOOL_DEFAULT="zbud"
CONFIG_ZBUD=y
# CONFIG_Z3FOLD is not set
CONFIG_ZSMALLOC=y
CONFIG_ZSMALLOC_STAT=y

#
# SLAB allocator options
#
# CONFIG_SLAB is not set
CONFIG_SLUB=y
# CONFIG_SLOB is not set
CONFIG_SLAB_MERGE_DEFAULT=y
CONFIG_SLAB_FREELIST_RANDOM=y
# CONFIG_SLAB_FREELIST_HARDENED is not set
# CONFIG_SLUB_STATS is not set
CONFIG_SLUB_CPU_PARTIAL=y
# end of SLAB allocator options

CONFIG_SHUFFLE_PAGE_ALLOCATOR=y
# CONFIG_COMPAT_BRK is not set
CONFIG_SPARSEMEM=y
CONFIG_SPARSEMEM_EXTREME=y
CONFIG_SPARSEMEM_VMEMMAP_ENABLE=y
CONFIG_SPARSEMEM_VMEMMAP=y
CONFIG_HAVE_FAST_GUP=y
CONFIG_NUMA_KEEP_MEMINFO=y
CONFIG_MEMORY_ISOLATION=y
CONFIG_EXCLUSIVE_SYSTEM_RAM=y
CONFIG_HAVE_BOOTMEM_INFO_NODE=y
CONFIG_ARCH_ENABLE_MEMORY_HOTPLUG=y
CONFIG_ARCH_ENABLE_MEMORY_HOTREMOVE=y
CONFIG_MEMORY_HOTPLUG=y
# CONFIG_MEMORY_HOTPLUG_DEFAULT_ONLINE is not set
CONFIG_MEMORY_HOTREMOVE=y
CONFIG_MHP_MEMMAP_ON_MEMORY=y
CONFIG_SPLIT_PTLOCK_CPUS=4
CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK=y
CONFIG_MEMORY_BALLOON=y
CONFIG_BALLOON_COMPACTION=y
CONFIG_COMPACTION=y
CONFIG_COMPACT_UNEVICTABLE_DEFAULT=1
CONFIG_PAGE_REPORTING=y
CONFIG_MIGRATION=y
CONFIG_DEVICE_MIGRATION=y
CONFIG_ARCH_ENABLE_HUGEPAGE_MIGRATION=y
CONFIG_ARCH_ENABLE_THP_MIGRATION=y
CONFIG_CONTIG_ALLOC=y
CONFIG_PHYS_ADDR_T_64BIT=y
CONFIG_MMU_NOTIFIER=y
CONFIG_KSM=y
CONFIG_DEFAULT_MMAP_MIN_ADDR=4096
CONFIG_ARCH_SUPPORTS_MEMORY_FAILURE=y
CONFIG_MEMORY_FAILURE=y
CONFIG_HWPOISON_INJECT=m
CONFIG_ARCH_WANT_GENERAL_HUGETLB=y
CONFIG_ARCH_WANTS_THP_SWAP=y
CONFIG_TRANSPARENT_HUGEPAGE=y
CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS=y
# CONFIG_TRANSPARENT_HUGEPAGE_MADVISE is not set
CONFIG_THP_SWAP=y
# CONFIG_READ_ONLY_THP_FOR_FS is not set
CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK=y
CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK=y
CONFIG_USE_PERCPU_NUMA_NODE_ID=y
CONFIG_HAVE_SETUP_PER_CPU_AREA=y
CONFIG_FRONTSWAP=y
CONFIG_CMA=y
# CONFIG_CMA_DEBUG is not set
# CONFIG_CMA_DEBUGFS is not set
# CONFIG_CMA_SYSFS is not set
CONFIG_CMA_AREAS=19
# CONFIG_MEM_SOFT_DIRTY is not set
CONFIG_GENERIC_EARLY_IOREMAP=y
CONFIG_DEFERRED_STRUCT_PAGE_INIT=y
CONFIG_PAGE_IDLE_FLAG=y
CONFIG_IDLE_PAGE_TRACKING=y
CONFIG_ARCH_HAS_CACHE_LINE_SIZE=y
CONFIG_ARCH_HAS_CURRENT_STACK_POINTER=y
CONFIG_ARCH_HAS_PTE_DEVMAP=y
CONFIG_ARCH_HAS_ZONE_DMA_SET=y
CONFIG_ZONE_DMA=y
CONFIG_ZONE_DMA32=y
CONFIG_ZONE_DEVICE=y
CONFIG_HMM_MIRROR=y
CONFIG_GET_FREE_REGION=y
CONFIG_DEVICE_PRIVATE=y
CONFIG_VMAP_PFN=y
CONFIG_ARCH_USES_HIGH_VMA_FLAGS=y
CONFIG_ARCH_HAS_PKEYS=y
CONFIG_VM_EVENT_COUNTERS=y
# CONFIG_PERCPU_STATS is not set
# CONFIG_GUP_TEST is not set
CONFIG_ARCH_HAS_PTE_SPECIAL=y
CONFIG_SECRETMEM=y
# CONFIG_ANON_VMA_NAME is not set
# CONFIG_USERFAULTFD is not set
# CONFIG_LRU_GEN is not set

#
# Data Access Monitoring
#
# CONFIG_DAMON is not set
# end of Data Access Monitoring
# end of Memory Management options

CONFIG_NET=y
CONFIG_COMPAT_NETLINK_MESSAGES=y
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_SKB_EXTENSIONS=y

#
# Networking options
#
CONFIG_PACKET=y
CONFIG_PACKET_DIAG=m
CONFIG_UNIX=y
CONFIG_UNIX_SCM=y
CONFIG_AF_UNIX_OOB=y
CONFIG_UNIX_DIAG=m
CONFIG_TLS=m
CONFIG_TLS_DEVICE=y
# CONFIG_TLS_TOE is not set
CONFIG_XFRM=y
CONFIG_XFRM_OFFLOAD=y
CONFIG_XFRM_ALGO=y
CONFIG_XFRM_USER=y
# CONFIG_XFRM_USER_COMPAT is not set
# CONFIG_XFRM_INTERFACE is not set
CONFIG_XFRM_SUB_POLICY=y
CONFIG_XFRM_MIGRATE=y
CONFIG_XFRM_STATISTICS=y
CONFIG_XFRM_AH=m
CONFIG_XFRM_ESP=m
CONFIG_XFRM_IPCOMP=m
CONFIG_NET_KEY=m
CONFIG_NET_KEY_MIGRATE=y
# CONFIG_SMC is not set
CONFIG_XDP_SOCKETS=y
# CONFIG_XDP_SOCKETS_DIAG is not set
CONFIG_INET=y
CONFIG_IP_MULTICAST=y
CONFIG_IP_ADVANCED_ROUTER=y
CONFIG_IP_FIB_TRIE_STATS=y
CONFIG_IP_MULTIPLE_TABLES=y
CONFIG_IP_ROUTE_MULTIPATH=y
CONFIG_IP_ROUTE_VERBOSE=y
CONFIG_IP_ROUTE_CLASSID=y
CONFIG_IP_PNP=y
CONFIG_IP_PNP_DHCP=y
# CONFIG_IP_PNP_BOOTP is not set
# CONFIG_IP_PNP_RARP is not set
CONFIG_NET_IPIP=m
CONFIG_NET_IPGRE_DEMUX=m
CONFIG_NET_IP_TUNNEL=m
CONFIG_NET_IPGRE=m
CONFIG_NET_IPGRE_BROADCAST=y
CONFIG_IP_MROUTE_COMMON=y
CONFIG_IP_MROUTE=y
CONFIG_IP_MROUTE_MULTIPLE_TABLES=y
CONFIG_IP_PIMSM_V1=y
CONFIG_IP_PIMSM_V2=y
CONFIG_SYN_COOKIES=y
CONFIG_NET_IPVTI=m
CONFIG_NET_UDP_TUNNEL=m
# CONFIG_NET_FOU is not set
# CONFIG_NET_FOU_IP_TUNNELS is not set
CONFIG_INET_AH=m
CONFIG_INET_ESP=m
CONFIG_INET_ESP_OFFLOAD=m
# CONFIG_INET_ESPINTCP is not set
CONFIG_INET_IPCOMP=m
CONFIG_INET_XFRM_TUNNEL=m
CONFIG_INET_TUNNEL=m
CONFIG_INET_DIAG=m
CONFIG_INET_TCP_DIAG=m
CONFIG_INET_UDP_DIAG=m
CONFIG_INET_RAW_DIAG=m
# CONFIG_INET_DIAG_DESTROY is not set
CONFIG_TCP_CONG_ADVANCED=y
CONFIG_TCP_CONG_BIC=m
CONFIG_TCP_CONG_CUBIC=y
CONFIG_TCP_CONG_WESTWOOD=m
CONFIG_TCP_CONG_HTCP=m
CONFIG_TCP_CONG_HSTCP=m
CONFIG_TCP_CONG_HYBLA=m
CONFIG_TCP_CONG_VEGAS=m
CONFIG_TCP_CONG_NV=m
CONFIG_TCP_CONG_SCALABLE=m
CONFIG_TCP_CONG_LP=m
CONFIG_TCP_CONG_VENO=m
CONFIG_TCP_CONG_YEAH=m
CONFIG_TCP_CONG_ILLINOIS=m
CONFIG_TCP_CONG_DCTCP=m
# CONFIG_TCP_CONG_CDG is not set
CONFIG_TCP_CONG_BBR=m
CONFIG_DEFAULT_CUBIC=y
# CONFIG_DEFAULT_RENO is not set
CONFIG_DEFAULT_TCP_CONG="cubic"
CONFIG_TCP_MD5SIG=y
CONFIG_IPV6=y
CONFIG_IPV6_ROUTER_PREF=y
CONFIG_IPV6_ROUTE_INFO=y
CONFIG_IPV6_OPTIMISTIC_DAD=y
CONFIG_INET6_AH=m
CONFIG_INET6_ESP=m
CONFIG_INET6_ESP_OFFLOAD=m
# CONFIG_INET6_ESPINTCP is not set
CONFIG_INET6_IPCOMP=m
CONFIG_IPV6_MIP6=m
# CONFIG_IPV6_ILA is not set
CONFIG_INET6_XFRM_TUNNEL=m
CONFIG_INET6_TUNNEL=m
CONFIG_IPV6_VTI=m
CONFIG_IPV6_SIT=m
CONFIG_IPV6_SIT_6RD=y
CONFIG_IPV6_NDISC_NODETYPE=y
CONFIG_IPV6_TUNNEL=m
CONFIG_IPV6_GRE=m
CONFIG_IPV6_MULTIPLE_TABLES=y
# CONFIG_IPV6_SUBTREES is not set
CONFIG_IPV6_MROUTE=y
CONFIG_IPV6_MROUTE_MULTIPLE_TABLES=y
CONFIG_IPV6_PIMSM_V2=y
# CONFIG_IPV6_SEG6_LWTUNNEL is not set
# CONFIG_IPV6_SEG6_HMAC is not set
# CONFIG_IPV6_RPL_LWTUNNEL is not set
# CONFIG_IPV6_IOAM6_LWTUNNEL is not set
CONFIG_NETLABEL=y
# CONFIG_MPTCP is not set
CONFIG_NETWORK_SECMARK=y
CONFIG_NET_PTP_CLASSIFY=y
CONFIG_NETWORK_PHY_TIMESTAMPING=y
CONFIG_NETFILTER=y
CONFIG_NETFILTER_ADVANCED=y
CONFIG_BRIDGE_NETFILTER=m

#
# Core Netfilter Configuration
#
CONFIG_NETFILTER_INGRESS=y
CONFIG_NETFILTER_EGRESS=y
CONFIG_NETFILTER_SKIP_EGRESS=y
CONFIG_NETFILTER_NETLINK=m
CONFIG_NETFILTER_FAMILY_BRIDGE=y
CONFIG_NETFILTER_FAMILY_ARP=y
# CONFIG_NETFILTER_NETLINK_HOOK is not set
# CONFIG_NETFILTER_NETLINK_ACCT is not set
CONFIG_NETFILTER_NETLINK_QUEUE=m
CONFIG_NETFILTER_NETLINK_LOG=m
CONFIG_NETFILTER_NETLINK_OSF=m
CONFIG_NF_CONNTRACK=m
CONFIG_NF_LOG_SYSLOG=m
CONFIG_NETFILTER_CONNCOUNT=m
CONFIG_NF_CONNTRACK_MARK=y
CONFIG_NF_CONNTRACK_SECMARK=y
CONFIG_NF_CONNTRACK_ZONES=y
CONFIG_NF_CONNTRACK_PROCFS=y
CONFIG_NF_CONNTRACK_EVENTS=y
CONFIG_NF_CONNTRACK_TIMEOUT=y
CONFIG_NF_CONNTRACK_TIMESTAMP=y
CONFIG_NF_CONNTRACK_LABELS=y
CONFIG_NF_CT_PROTO_DCCP=y
CONFIG_NF_CT_PROTO_GRE=y
CONFIG_NF_CT_PROTO_SCTP=y
CONFIG_NF_CT_PROTO_UDPLITE=y
CONFIG_NF_CONNTRACK_AMANDA=m
CONFIG_NF_CONNTRACK_FTP=m
CONFIG_NF_CONNTRACK_H323=m
CONFIG_NF_CONNTRACK_IRC=m
CONFIG_NF_CONNTRACK_BROADCAST=m
CONFIG_NF_CONNTRACK_NETBIOS_NS=m
CONFIG_NF_CONNTRACK_SNMP=m
CONFIG_NF_CONNTRACK_PPTP=m
CONFIG_NF_CONNTRACK_SANE=m
CONFIG_NF_CONNTRACK_SIP=m
CONFIG_NF_CONNTRACK_TFTP=m
CONFIG_NF_CT_NETLINK=m
CONFIG_NF_CT_NETLINK_TIMEOUT=m
CONFIG_NF_CT_NETLINK_HELPER=m
CONFIG_NETFILTER_NETLINK_GLUE_CT=y
CONFIG_NF_NAT=m
CONFIG_NF_NAT_AMANDA=m
CONFIG_NF_NAT_FTP=m
CONFIG_NF_NAT_IRC=m
CONFIG_NF_NAT_SIP=m
CONFIG_NF_NAT_TFTP=m
CONFIG_NF_NAT_REDIRECT=y
CONFIG_NF_NAT_MASQUERADE=y
CONFIG_NETFILTER_SYNPROXY=m
CONFIG_NF_TABLES=m
CONFIG_NF_TABLES_INET=y
CONFIG_NF_TABLES_NETDEV=y
CONFIG_NFT_NUMGEN=m
CONFIG_NFT_CT=m
CONFIG_NFT_CONNLIMIT=m
CONFIG_NFT_LOG=m
CONFIG_NFT_LIMIT=m
CONFIG_NFT_MASQ=m
CONFIG_NFT_REDIR=m
CONFIG_NFT_NAT=m
# CONFIG_NFT_TUNNEL is not set
CONFIG_NFT_OBJREF=m
CONFIG_NFT_QUEUE=m
CONFIG_NFT_QUOTA=m
CONFIG_NFT_REJECT=m
CONFIG_NFT_REJECT_INET=m
CONFIG_NFT_COMPAT=m
CONFIG_NFT_HASH=m
CONFIG_NFT_FIB=m
CONFIG_NFT_FIB_INET=m
# CONFIG_NFT_XFRM is not set
CONFIG_NFT_SOCKET=m
# CONFIG_NFT_OSF is not set
# CONFIG_NFT_TPROXY is not set
# CONFIG_NFT_SYNPROXY is not set
CONFIG_NF_DUP_NETDEV=m
CONFIG_NFT_DUP_NETDEV=m
CONFIG_NFT_FWD_NETDEV=m
CONFIG_NFT_FIB_NETDEV=m
# CONFIG_NFT_REJECT_NETDEV is not set
# CONFIG_NF_FLOW_TABLE is not set
CONFIG_NETFILTER_XTABLES=y
CONFIG_NETFILTER_XTABLES_COMPAT=y

#
# Xtables combined modules
#
CONFIG_NETFILTER_XT_MARK=m
CONFIG_NETFILTER_XT_CONNMARK=m
CONFIG_NETFILTER_XT_SET=m

#
# Xtables targets
#
CONFIG_NETFILTER_XT_TARGET_AUDIT=m
CONFIG_NETFILTER_XT_TARGET_CHECKSUM=m
CONFIG_NETFILTER_XT_TARGET_CLASSIFY=m
CONFIG_NETFILTER_XT_TARGET_CONNMARK=m
CONFIG_NETFILTER_XT_TARGET_CONNSECMARK=m
CONFIG_NETFILTER_XT_TARGET_CT=m
CONFIG_NETFILTER_XT_TARGET_DSCP=m
CONFIG_NETFILTER_XT_TARGET_HL=m
CONFIG_NETFILTER_XT_TARGET_HMARK=m
CONFIG_NETFILTER_XT_TARGET_IDLETIMER=m
# CONFIG_NETFILTER_XT_TARGET_LED is not set
CONFIG_NETFILTER_XT_TARGET_LOG=m
CONFIG_NETFILTER_XT_TARGET_MARK=m
CONFIG_NETFILTER_XT_NAT=m
CONFIG_NETFILTER_XT_TARGET_NETMAP=m
CONFIG_NETFILTER_XT_TARGET_NFLOG=m
CONFIG_NETFILTER_XT_TARGET_NFQUEUE=m
CONFIG_NETFILTER_XT_TARGET_NOTRACK=m
CONFIG_NETFILTER_XT_TARGET_RATEEST=m
CONFIG_NETFILTER_XT_TARGET_REDIRECT=m
CONFIG_NETFILTER_XT_TARGET_MASQUERADE=m
CONFIG_NETFILTER_XT_TARGET_TEE=m
CONFIG_NETFILTER_XT_TARGET_TPROXY=m
CONFIG_NETFILTER_XT_TARGET_TRACE=m
CONFIG_NETFILTER_XT_TARGET_SECMARK=m
CONFIG_NETFILTER_XT_TARGET_TCPMSS=m
CONFIG_NETFILTER_XT_TARGET_TCPOPTSTRIP=m

#
# Xtables matches
#
CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=m
CONFIG_NETFILTER_XT_MATCH_BPF=m
CONFIG_NETFILTER_XT_MATCH_CGROUP=m
CONFIG_NETFILTER_XT_MATCH_CLUSTER=m
CONFIG_NETFILTER_XT_MATCH_COMMENT=m
CONFIG_NETFILTER_XT_MATCH_CONNBYTES=m
CONFIG_NETFILTER_XT_MATCH_CONNLABEL=m
CONFIG_NETFILTER_XT_MATCH_CONNLIMIT=m
CONFIG_NETFILTER_XT_MATCH_CONNMARK=m
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=m
CONFIG_NETFILTER_XT_MATCH_CPU=m
CONFIG_NETFILTER_XT_MATCH_DCCP=m
CONFIG_NETFILTER_XT_MATCH_DEVGROUP=m
CONFIG_NETFILTER_XT_MATCH_DSCP=m
CONFIG_NETFILTER_XT_MATCH_ECN=m
CONFIG_NETFILTER_XT_MATCH_ESP=m
CONFIG_NETFILTER_XT_MATCH_HASHLIMIT=m
CONFIG_NETFILTER_XT_MATCH_HELPER=m
CONFIG_NETFILTER_XT_MATCH_HL=m
# CONFIG_NETFILTER_XT_MATCH_IPCOMP is not set
CONFIG_NETFILTER_XT_MATCH_IPRANGE=m
CONFIG_NETFILTER_XT_MATCH_IPVS=m
# CONFIG_NETFILTER_XT_MATCH_L2TP is not set
CONFIG_NETFILTER_XT_MATCH_LENGTH=m
CONFIG_NETFILTER_XT_MATCH_LIMIT=m
CONFIG_NETFILTER_XT_MATCH_MAC=m
CONFIG_NETFILTER_XT_MATCH_MARK=m
CONFIG_NETFILTER_XT_MATCH_MULTIPORT=m
# CONFIG_NETFILTER_XT_MATCH_NFACCT is not set
CONFIG_NETFILTER_XT_MATCH_OSF=m
CONFIG_NETFILTER_XT_MATCH_OWNER=m
CONFIG_NETFILTER_XT_MATCH_POLICY=m
CONFIG_NETFILTER_XT_MATCH_PHYSDEV=m
CONFIG_NETFILTER_XT_MATCH_PKTTYPE=m
CONFIG_NETFILTER_XT_MATCH_QUOTA=m
CONFIG_NETFILTER_XT_MATCH_RATEEST=m
CONFIG_NETFILTER_XT_MATCH_REALM=m
CONFIG_NETFILTER_XT_MATCH_RECENT=m
CONFIG_NETFILTER_XT_MATCH_SCTP=m
CONFIG_NETFILTER_XT_MATCH_SOCKET=m
CONFIG_NETFILTER_XT_MATCH_STATE=m
CONFIG_NETFILTER_XT_MATCH_STATISTIC=m
CONFIG_NETFILTER_XT_MATCH_STRING=m
CONFIG_NETFILTER_XT_MATCH_TCPMSS=m
# CONFIG_NETFILTER_XT_MATCH_TIME is not set
# CONFIG_NETFILTER_XT_MATCH_U32 is not set
# end of Core Netfilter Configuration

CONFIG_IP_SET=m
CONFIG_IP_SET_MAX=256
CONFIG_IP_SET_BITMAP_IP=m
CONFIG_IP_SET_BITMAP_IPMAC=m
CONFIG_IP_SET_BITMAP_PORT=m
CONFIG_IP_SET_HASH_IP=m
CONFIG_IP_SET_HASH_IPMARK=m
CONFIG_IP_SET_HASH_IPPORT=m
CONFIG_IP_SET_HASH_IPPORTIP=m
CONFIG_IP_SET_HASH_IPPORTNET=m
CONFIG_IP_SET_HASH_IPMAC=m
CONFIG_IP_SET_HASH_MAC=m
CONFIG_IP_SET_HASH_NETPORTNET=m
CONFIG_IP_SET_HASH_NET=m
CONFIG_IP_SET_HASH_NETNET=m
CONFIG_IP_SET_HASH_NETPORT=m
CONFIG_IP_SET_HASH_NETIFACE=m
CONFIG_IP_SET_LIST_SET=m
CONFIG_IP_VS=m
CONFIG_IP_VS_IPV6=y
# CONFIG_IP_VS_DEBUG is not set
CONFIG_IP_VS_TAB_BITS=12

#
# IPVS transport protocol load balancing support
#
CONFIG_IP_VS_PROTO_TCP=y
CONFIG_IP_VS_PROTO_UDP=y
CONFIG_IP_VS_PROTO_AH_ESP=y
CONFIG_IP_VS_PROTO_ESP=y
CONFIG_IP_VS_PROTO_AH=y
CONFIG_IP_VS_PROTO_SCTP=y

#
# IPVS scheduler
#
CONFIG_IP_VS_RR=m
CONFIG_IP_VS_WRR=m
CONFIG_IP_VS_LC=m
CONFIG_IP_VS_WLC=m
CONFIG_IP_VS_FO=m
CONFIG_IP_VS_OVF=m
CONFIG_IP_VS_LBLC=m
CONFIG_IP_VS_LBLCR=m
CONFIG_IP_VS_DH=m
CONFIG_IP_VS_SH=m
# CONFIG_IP_VS_MH is not set
CONFIG_IP_VS_SED=m
CONFIG_IP_VS_NQ=m
# CONFIG_IP_VS_TWOS is not set

#
# IPVS SH scheduler
#
CONFIG_IP_VS_SH_TAB_BITS=8

#
# IPVS MH scheduler
#
CONFIG_IP_VS_MH_TAB_INDEX=12

#
# IPVS application helper
#
CONFIG_IP_VS_FTP=m
CONFIG_IP_VS_NFCT=y
CONFIG_IP_VS_PE_SIP=m

#
# IP: Netfilter Configuration
#
CONFIG_NF_DEFRAG_IPV4=m
CONFIG_NF_SOCKET_IPV4=m
CONFIG_NF_TPROXY_IPV4=m
CONFIG_NF_TABLES_IPV4=y
CONFIG_NFT_REJECT_IPV4=m
CONFIG_NFT_DUP_IPV4=m
CONFIG_NFT_FIB_IPV4=m
CONFIG_NF_TABLES_ARP=y
CONFIG_NF_DUP_IPV4=m
CONFIG_NF_LOG_ARP=m
CONFIG_NF_LOG_IPV4=m
CONFIG_NF_REJECT_IPV4=m
CONFIG_NF_NAT_SNMP_BASIC=m
CONFIG_NF_NAT_PPTP=m
CONFIG_NF_NAT_H323=m
CONFIG_IP_NF_IPTABLES=m
CONFIG_IP_NF_MATCH_AH=m
CONFIG_IP_NF_MATCH_ECN=m
CONFIG_IP_NF_MATCH_RPFILTER=m
CONFIG_IP_NF_MATCH_TTL=m
CONFIG_IP_NF_FILTER=m
CONFIG_IP_NF_TARGET_REJECT=m
CONFIG_IP_NF_TARGET_SYNPROXY=m
CONFIG_IP_NF_NAT=m
CONFIG_IP_NF_TARGET_MASQUERADE=m
CONFIG_IP_NF_TARGET_NETMAP=m
CONFIG_IP_NF_TARGET_REDIRECT=m
CONFIG_IP_NF_MANGLE=m
# CONFIG_IP_NF_TARGET_CLUSTERIP is not set
CONFIG_IP_NF_TARGET_ECN=m
CONFIG_IP_NF_TARGET_TTL=m
CONFIG_IP_NF_RAW=m
CONFIG_IP_NF_SECURITY=m
CONFIG_IP_NF_ARPTABLES=m
CONFIG_IP_NF_ARPFILTER=m
CONFIG_IP_NF_ARP_MANGLE=m
# end of IP: Netfilter Configuration

#
# IPv6: Netfilter Configuration
#
CONFIG_NF_SOCKET_IPV6=m
CONFIG_NF_TPROXY_IPV6=m
CONFIG_NF_TABLES_IPV6=y
CONFIG_NFT_REJECT_IPV6=m
CONFIG_NFT_DUP_IPV6=m
CONFIG_NFT_FIB_IPV6=m
CONFIG_NF_DUP_IPV6=m
CONFIG_NF_REJECT_IPV6=m
CONFIG_NF_LOG_IPV6=m
CONFIG_IP6_NF_IPTABLES=m
CONFIG_IP6_NF_MATCH_AH=m
CONFIG_IP6_NF_MATCH_EUI64=m
CONFIG_IP6_NF_MATCH_FRAG=m
CONFIG_IP6_NF_MATCH_OPTS=m
CONFIG_IP6_NF_MATCH_HL=m
CONFIG_IP6_NF_MATCH_IPV6HEADER=m
CONFIG_IP6_NF_MATCH_MH=m
CONFIG_IP6_NF_MATCH_RPFILTER=m
CONFIG_IP6_NF_MATCH_RT=m
# CONFIG_IP6_NF_MATCH_SRH is not set
# CONFIG_IP6_NF_TARGET_HL is not set
CONFIG_IP6_NF_FILTER=m
CONFIG_IP6_NF_TARGET_REJECT=m
CONFIG_IP6_NF_TARGET_SYNPROXY=m
CONFIG_IP6_NF_MANGLE=m
CONFIG_IP6_NF_RAW=m
CONFIG_IP6_NF_SECURITY=m
CONFIG_IP6_NF_NAT=m
CONFIG_IP6_NF_TARGET_MASQUERADE=m
CONFIG_IP6_NF_TARGET_NPT=m
# end of IPv6: Netfilter Configuration

CONFIG_NF_DEFRAG_IPV6=m
CONFIG_NF_TABLES_BRIDGE=m
# CONFIG_NFT_BRIDGE_META is not set
CONFIG_NFT_BRIDGE_REJECT=m
# CONFIG_NF_CONNTRACK_BRIDGE is not set
CONFIG_BRIDGE_NF_EBTABLES=m
CONFIG_BRIDGE_EBT_BROUTE=m
CONFIG_BRIDGE_EBT_T_FILTER=m
CONFIG_BRIDGE_EBT_T_NAT=m
CONFIG_BRIDGE_EBT_802_3=m
CONFIG_BRIDGE_EBT_AMONG=m
CONFIG_BRIDGE_EBT_ARP=m
CONFIG_BRIDGE_EBT_IP=m
CONFIG_BRIDGE_EBT_IP6=m
CONFIG_BRIDGE_EBT_LIMIT=m
CONFIG_BRIDGE_EBT_MARK=m
CONFIG_BRIDGE_EBT_PKTTYPE=m
CONFIG_BRIDGE_EBT_STP=m
CONFIG_BRIDGE_EBT_VLAN=m
CONFIG_BRIDGE_EBT_ARPREPLY=m
CONFIG_BRIDGE_EBT_DNAT=m
CONFIG_BRIDGE_EBT_MARK_T=m
CONFIG_BRIDGE_EBT_REDIRECT=m
CONFIG_BRIDGE_EBT_SNAT=m
CONFIG_BRIDGE_EBT_LOG=m
CONFIG_BRIDGE_EBT_NFLOG=m
# CONFIG_BPFILTER is not set
# CONFIG_IP_DCCP is not set
CONFIG_IP_SCTP=m
# CONFIG_SCTP_DBG_OBJCNT is not set
# CONFIG_SCTP_DEFAULT_COOKIE_HMAC_MD5 is not set
CONFIG_SCTP_DEFAULT_COOKIE_HMAC_SHA1=y
# CONFIG_SCTP_DEFAULT_COOKIE_HMAC_NONE is not set
CONFIG_SCTP_COOKIE_HMAC_MD5=y
CONFIG_SCTP_COOKIE_HMAC_SHA1=y
CONFIG_INET_SCTP_DIAG=m
# CONFIG_RDS is not set
CONFIG_TIPC=m
# CONFIG_TIPC_MEDIA_IB is not set
CONFIG_TIPC_MEDIA_UDP=y
CONFIG_TIPC_CRYPTO=y
CONFIG_TIPC_DIAG=m
CONFIG_ATM=m
CONFIG_ATM_CLIP=m
# CONFIG_ATM_CLIP_NO_ICMP is not set
CONFIG_ATM_LANE=m
# CONFIG_ATM_MPOA is not set
CONFIG_ATM_BR2684=m
# CONFIG_ATM_BR2684_IPFILTER is not set
CONFIG_L2TP=m
CONFIG_L2TP_DEBUGFS=m
CONFIG_L2TP_V3=y
CONFIG_L2TP_IP=m
CONFIG_L2TP_ETH=m
CONFIG_STP=m
CONFIG_GARP=m
CONFIG_MRP=m
CONFIG_BRIDGE=m
CONFIG_BRIDGE_IGMP_SNOOPING=y
CONFIG_BRIDGE_VLAN_FILTERING=y
# CONFIG_BRIDGE_MRP is not set
# CONFIG_BRIDGE_CFM is not set
# CONFIG_NET_DSA is not set
CONFIG_VLAN_8021Q=m
CONFIG_VLAN_8021Q_GVRP=y
CONFIG_VLAN_8021Q_MVRP=y
CONFIG_LLC=m
# CONFIG_LLC2 is not set
# CONFIG_ATALK is not set
# CONFIG_X25 is not set
# CONFIG_LAPB is not set
# CONFIG_PHONET is not set
CONFIG_6LOWPAN=m
# CONFIG_6LOWPAN_DEBUGFS is not set
# CONFIG_6LOWPAN_NHC is not set
# CONFIG_IEEE802154 is not set
CONFIG_NET_SCHED=y

#
# Queueing/Scheduling
#
CONFIG_NET_SCH_CBQ=m
CONFIG_NET_SCH_HTB=m
CONFIG_NET_SCH_HFSC=m
CONFIG_NET_SCH_ATM=m
CONFIG_NET_SCH_PRIO=m
CONFIG_NET_SCH_MULTIQ=m
CONFIG_NET_SCH_RED=m
CONFIG_NET_SCH_SFB=m
CONFIG_NET_SCH_SFQ=m
CONFIG_NET_SCH_TEQL=m
CONFIG_NET_SCH_TBF=m
# CONFIG_NET_SCH_CBS is not set
# CONFIG_NET_SCH_ETF is not set
# CONFIG_NET_SCH_TAPRIO is not set
CONFIG_NET_SCH_GRED=m
CONFIG_NET_SCH_DSMARK=m
CONFIG_NET_SCH_NETEM=m
CONFIG_NET_SCH_DRR=m
CONFIG_NET_SCH_MQPRIO=m
# CONFIG_NET_SCH_SKBPRIO is not set
CONFIG_NET_SCH_CHOKE=m
CONFIG_NET_SCH_QFQ=m
CONFIG_NET_SCH_CODEL=m
CONFIG_NET_SCH_FQ_CODEL=y
# CONFIG_NET_SCH_CAKE is not set
CONFIG_NET_SCH_FQ=m
CONFIG_NET_SCH_HHF=m
CONFIG_NET_SCH_PIE=m
# CONFIG_NET_SCH_FQ_PIE is not set
CONFIG_NET_SCH_INGRESS=m
CONFIG_NET_SCH_PLUG=m
# CONFIG_NET_SCH_ETS is not set
CONFIG_NET_SCH_DEFAULT=y
# CONFIG_DEFAULT_FQ is not set
# CONFIG_DEFAULT_CODEL is not set
CONFIG_DEFAULT_FQ_CODEL=y
# CONFIG_DEFAULT_SFQ is not set
# CONFIG_DEFAULT_PFIFO_FAST is not set
CONFIG_DEFAULT_NET_SCH="fq_codel"

#
# Classification
#
CONFIG_NET_CLS=y
CONFIG_NET_CLS_BASIC=m
CONFIG_NET_CLS_TCINDEX=m
CONFIG_NET_CLS_ROUTE4=m
CONFIG_NET_CLS_FW=m
CONFIG_NET_CLS_U32=m
CONFIG_CLS_U32_PERF=y
CONFIG_CLS_U32_MARK=y
CONFIG_NET_CLS_RSVP=m
CONFIG_NET_CLS_RSVP6=m
CONFIG_NET_CLS_FLOW=m
CONFIG_NET_CLS_CGROUP=y
CONFIG_NET_CLS_BPF=m
CONFIG_NET_CLS_FLOWER=m
CONFIG_NET_CLS_MATCHALL=m
CONFIG_NET_EMATCH=y
CONFIG_NET_EMATCH_STACK=32
CONFIG_NET_EMATCH_CMP=m
CONFIG_NET_EMATCH_NBYTE=m
CONFIG_NET_EMATCH_U32=m
CONFIG_NET_EMATCH_META=m
CONFIG_NET_EMATCH_TEXT=m
# CONFIG_NET_EMATCH_CANID is not set
CONFIG_NET_EMATCH_IPSET=m
# CONFIG_NET_EMATCH_IPT is not set
CONFIG_NET_CLS_ACT=y
CONFIG_NET_ACT_POLICE=m
CONFIG_NET_ACT_GACT=m
CONFIG_GACT_PROB=y
CONFIG_NET_ACT_MIRRED=m
CONFIG_NET_ACT_SAMPLE=m
# CONFIG_NET_ACT_IPT is not set
CONFIG_NET_ACT_NAT=m
CONFIG_NET_ACT_PEDIT=m
CONFIG_NET_ACT_SIMP=m
CONFIG_NET_ACT_SKBEDIT=m
CONFIG_NET_ACT_CSUM=m
# CONFIG_NET_ACT_MPLS is not set
CONFIG_NET_ACT_VLAN=m
CONFIG_NET_ACT_BPF=m
# CONFIG_NET_ACT_CONNMARK is not set
# CONFIG_NET_ACT_CTINFO is not set
CONFIG_NET_ACT_SKBMOD=m
# CONFIG_NET_ACT_IFE is not set
CONFIG_NET_ACT_TUNNEL_KEY=m
# CONFIG_NET_ACT_GATE is not set
# CONFIG_NET_TC_SKB_EXT is not set
CONFIG_NET_SCH_FIFO=y
CONFIG_DCB=y
CONFIG_DNS_RESOLVER=m
# CONFIG_BATMAN_ADV is not set
CONFIG_OPENVSWITCH=m
CONFIG_OPENVSWITCH_GRE=m
CONFIG_VSOCKETS=m
CONFIG_VSOCKETS_DIAG=m
CONFIG_VSOCKETS_LOOPBACK=m
CONFIG_VMWARE_VMCI_VSOCKETS=m
CONFIG_VIRTIO_VSOCKETS=m
CONFIG_VIRTIO_VSOCKETS_COMMON=m
CONFIG_NETLINK_DIAG=m
CONFIG_MPLS=y
CONFIG_NET_MPLS_GSO=y
CONFIG_MPLS_ROUTING=m
CONFIG_MPLS_IPTUNNEL=m
CONFIG_NET_NSH=y
# CONFIG_HSR is not set
CONFIG_NET_SWITCHDEV=y
CONFIG_NET_L3_MASTER_DEV=y
# CONFIG_QRTR is not set
# CONFIG_NET_NCSI is not set
CONFIG_PCPU_DEV_REFCNT=y
CONFIG_RPS=y
CONFIG_RFS_ACCEL=y
CONFIG_SOCK_RX_QUEUE_MAPPING=y
CONFIG_XPS=y
CONFIG_CGROUP_NET_PRIO=y
CONFIG_CGROUP_NET_CLASSID=y
CONFIG_NET_RX_BUSY_POLL=y
CONFIG_BQL=y
CONFIG_NET_FLOW_LIMIT=y

#
# Network testing
#
CONFIG_NET_PKTGEN=m
CONFIG_NET_DROP_MONITOR=y
# end of Network testing
# end of Networking options

# CONFIG_HAMRADIO is not set
CONFIG_CAN=m
CONFIG_CAN_RAW=m
CONFIG_CAN_BCM=m
CONFIG_CAN_GW=m
# CONFIG_CAN_J1939 is not set
# CONFIG_CAN_ISOTP is not set
# CONFIG_BT is not set
# CONFIG_AF_RXRPC is not set
# CONFIG_AF_KCM is not set
CONFIG_STREAM_PARSER=y
# CONFIG_MCTP is not set
CONFIG_FIB_RULES=y
CONFIG_WIRELESS=y
CONFIG_WEXT_CORE=y
CONFIG_WEXT_PROC=y
CONFIG_CFG80211=m
# CONFIG_NL80211_TESTMODE is not set
# CONFIG_CFG80211_DEVELOPER_WARNINGS is not set
# CONFIG_CFG80211_CERTIFICATION_ONUS is not set
CONFIG_CFG80211_REQUIRE_SIGNED_REGDB=y
CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS=y
CONFIG_CFG80211_DEFAULT_PS=y
# CONFIG_CFG80211_DEBUGFS is not set
CONFIG_CFG80211_CRDA_SUPPORT=y
CONFIG_CFG80211_WEXT=y
CONFIG_MAC80211=m
CONFIG_MAC80211_HAS_RC=y
CONFIG_MAC80211_RC_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT_MINSTREL=y
CONFIG_MAC80211_RC_DEFAULT="minstrel_ht"
CONFIG_MAC80211_MESH=y
CONFIG_MAC80211_LEDS=y
CONFIG_MAC80211_DEBUGFS=y
# CONFIG_MAC80211_MESSAGE_TRACING is not set
# CONFIG_MAC80211_DEBUG_MENU is not set
CONFIG_MAC80211_STA_HASH_MAX_SIZE=0
CONFIG_RFKILL=m
CONFIG_RFKILL_LEDS=y
CONFIG_RFKILL_INPUT=y
# CONFIG_RFKILL_GPIO is not set
CONFIG_NET_9P=y
CONFIG_NET_9P_FD=y
CONFIG_NET_9P_VIRTIO=y
# CONFIG_NET_9P_RDMA is not set
# CONFIG_NET_9P_DEBUG is not set
# CONFIG_CAIF is not set
CONFIG_CEPH_LIB=m
# CONFIG_CEPH_LIB_PRETTYDEBUG is not set
CONFIG_CEPH_LIB_USE_DNS_RESOLVER=y
# CONFIG_NFC is not set
CONFIG_PSAMPLE=m
# CONFIG_NET_IFE is not set
CONFIG_LWTUNNEL=y
CONFIG_LWTUNNEL_BPF=y
CONFIG_DST_CACHE=y
CONFIG_GRO_CELLS=y
CONFIG_SOCK_VALIDATE_XMIT=y
CONFIG_NET_SELFTESTS=y
CONFIG_NET_SOCK_MSG=y
CONFIG_PAGE_POOL=y
# CONFIG_PAGE_POOL_STATS is not set
CONFIG_FAILOVER=m
CONFIG_ETHTOOL_NETLINK=y

#
# Device Drivers
#
CONFIG_HAVE_EISA=y
# CONFIG_EISA is not set
CONFIG_HAVE_PCI=y
CONFIG_PCI=y
CONFIG_PCI_DOMAINS=y
CONFIG_PCIEPORTBUS=y
CONFIG_HOTPLUG_PCI_PCIE=y
CONFIG_PCIEAER=y
CONFIG_PCIEAER_INJECT=m
CONFIG_PCIE_ECRC=y
CONFIG_PCIEASPM=y
CONFIG_PCIEASPM_DEFAULT=y
# CONFIG_PCIEASPM_POWERSAVE is not set
# CONFIG_PCIEASPM_POWER_SUPERSAVE is not set
# CONFIG_PCIEASPM_PERFORMANCE is not set
CONFIG_PCIE_PME=y
CONFIG_PCIE_DPC=y
# CONFIG_PCIE_PTM is not set
# CONFIG_PCIE_EDR is not set
CONFIG_PCI_MSI=y
CONFIG_PCI_MSI_IRQ_DOMAIN=y
CONFIG_PCI_QUIRKS=y
# CONFIG_PCI_DEBUG is not set
# CONFIG_PCI_REALLOC_ENABLE_AUTO is not set
CONFIG_PCI_STUB=y
CONFIG_PCI_PF_STUB=m
CONFIG_PCI_ATS=y
CONFIG_PCI_LOCKLESS_CONFIG=y
CONFIG_PCI_IOV=y
CONFIG_PCI_PRI=y
CONFIG_PCI_PASID=y
# CONFIG_PCI_P2PDMA is not set
CONFIG_PCI_LABEL=y
# CONFIG_PCIE_BUS_TUNE_OFF is not set
CONFIG_PCIE_BUS_DEFAULT=y
# CONFIG_PCIE_BUS_SAFE is not set
# CONFIG_PCIE_BUS_PERFORMANCE is not set
# CONFIG_PCIE_BUS_PEER2PEER is not set
CONFIG_VGA_ARB=y
CONFIG_VGA_ARB_MAX_GPUS=64
CONFIG_HOTPLUG_PCI=y
CONFIG_HOTPLUG_PCI_ACPI=y
CONFIG_HOTPLUG_PCI_ACPI_IBM=m
# CONFIG_HOTPLUG_PCI_CPCI is not set
CONFIG_HOTPLUG_PCI_SHPC=y

#
# PCI controller drivers
#
CONFIG_VMD=y

#
# DesignWare PCI Core Support
#
# CONFIG_PCIE_DW_PLAT_HOST is not set
# CONFIG_PCI_MESON is not set
# end of DesignWare PCI Core Support

#
# Mobiveil PCIe Core Support
#
# end of Mobiveil PCIe Core Support

#
# Cadence PCIe controllers support
#
# end of Cadence PCIe controllers support
# end of PCI controller drivers

#
# PCI Endpoint
#
# CONFIG_PCI_ENDPOINT is not set
# end of PCI Endpoint

#
# PCI switch controller drivers
#
# CONFIG_PCI_SW_SWITCHTEC is not set
# end of PCI switch controller drivers

# CONFIG_CXL_BUS is not set
# CONFIG_PCCARD is not set
# CONFIG_RAPIDIO is not set

#
# Generic Driver Options
#
CONFIG_AUXILIARY_BUS=y
# CONFIG_UEVENT_HELPER is not set
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
# CONFIG_DEVTMPFS_SAFE is not set
CONFIG_STANDALONE=y
CONFIG_PREVENT_FIRMWARE_BUILD=y

#
# Firmware loader
#
CONFIG_FW_LOADER=y
CONFIG_FW_LOADER_PAGED_BUF=y
CONFIG_FW_LOADER_SYSFS=y
CONFIG_EXTRA_FIRMWARE=""
CONFIG_FW_LOADER_USER_HELPER=y
# CONFIG_FW_LOADER_USER_HELPER_FALLBACK is not set
# CONFIG_FW_LOADER_COMPRESS is not set
CONFIG_FW_CACHE=y
# CONFIG_FW_UPLOAD is not set
# end of Firmware loader

CONFIG_ALLOW_DEV_COREDUMP=y
# CONFIG_DEBUG_DRIVER is not set
# CONFIG_DEBUG_DEVRES is not set
# CONFIG_DEBUG_TEST_DRIVER_REMOVE is not set
# CONFIG_TEST_ASYNC_DRIVER_PROBE is not set
CONFIG_GENERIC_CPU_AUTOPROBE=y
CONFIG_GENERIC_CPU_VULNERABILITIES=y
CONFIG_REGMAP=y
CONFIG_REGMAP_I2C=m
CONFIG_REGMAP_SPI=m
CONFIG_DMA_SHARED_BUFFER=y
# CONFIG_DMA_FENCE_TRACE is not set
# end of Generic Driver Options

#
# Bus devices
#
# CONFIG_MHI_BUS is not set
# CONFIG_MHI_BUS_EP is not set
# end of Bus devices

CONFIG_CONNECTOR=y
CONFIG_PROC_EVENTS=y

#
# Firmware Drivers
#

#
# ARM System Control and Management Interface Protocol
#
# end of ARM System Control and Management Interface Protocol

CONFIG_EDD=m
# CONFIG_EDD_OFF is not set
CONFIG_FIRMWARE_MEMMAP=y
CONFIG_DMIID=y
CONFIG_DMI_SYSFS=y
CONFIG_DMI_SCAN_MACHINE_NON_EFI_FALLBACK=y
# CONFIG_ISCSI_IBFT is not set
CONFIG_FW_CFG_SYSFS=y
# CONFIG_FW_CFG_SYSFS_CMDLINE is not set
CONFIG_SYSFB=y
# CONFIG_SYSFB_SIMPLEFB is not set
# CONFIG_GOOGLE_FIRMWARE is not set

#
# EFI (Extensible Firmware Interface) Support
#
CONFIG_EFI_ESRT=y
CONFIG_EFI_VARS_PSTORE=y
CONFIG_EFI_VARS_PSTORE_DEFAULT_DISABLE=y
CONFIG_EFI_RUNTIME_MAP=y
# CONFIG_EFI_FAKE_MEMMAP is not set
CONFIG_EFI_DXE_MEM_ATTRIBUTES=y
CONFIG_EFI_RUNTIME_WRAPPERS=y
CONFIG_EFI_GENERIC_STUB_INITRD_CMDLINE_LOADER=y
# CONFIG_EFI_BOOTLOADER_CONTROL is not set
# CONFIG_EFI_CAPSULE_LOADER is not set
# CONFIG_EFI_TEST is not set
# CONFIG_APPLE_PROPERTIES is not set
# CONFIG_RESET_ATTACK_MITIGATION is not set
# CONFIG_EFI_RCI2_TABLE is not set
# CONFIG_EFI_DISABLE_PCI_DMA is not set
CONFIG_EFI_EARLYCON=y
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS=y
# CONFIG_EFI_DISABLE_RUNTIME is not set
# CONFIG_EFI_COCO_SECRET is not set
# end of EFI (Extensible Firmware Interface) Support

CONFIG_UEFI_CPER=y
CONFIG_UEFI_CPER_X86=y

#
# Tegra firmware driver
#
# end of Tegra firmware driver
# end of Firmware Drivers

# CONFIG_GNSS is not set
# CONFIG_MTD is not set
# CONFIG_OF is not set
CONFIG_ARCH_MIGHT_HAVE_PC_PARPORT=y
CONFIG_PARPORT=m
CONFIG_PARPORT_PC=m
CONFIG_PARPORT_SERIAL=m
# CONFIG_PARPORT_PC_FIFO is not set
# CONFIG_PARPORT_PC_SUPERIO is not set
# CONFIG_PARPORT_AX88796 is not set
CONFIG_PARPORT_1284=y
CONFIG_PNP=y
# CONFIG_PNP_DEBUG_MESSAGES is not set

#
# Protocols
#
CONFIG_PNPACPI=y
CONFIG_BLK_DEV=y
CONFIG_BLK_DEV_NULL_BLK=m
CONFIG_BLK_DEV_NULL_BLK_FAULT_INJECTION=y
# CONFIG_BLK_DEV_FD is not set
CONFIG_CDROM=m
# CONFIG_PARIDE is not set
# CONFIG_BLK_DEV_PCIESSD_MTIP32XX is not set
CONFIG_ZRAM=m
CONFIG_ZRAM_DEF_COMP_LZORLE=y
# CONFIG_ZRAM_DEF_COMP_LZO is not set
CONFIG_ZRAM_DEF_COMP="lzo-rle"
CONFIG_ZRAM_WRITEBACK=y
# CONFIG_ZRAM_MEMORY_TRACKING is not set
CONFIG_BLK_DEV_LOOP=m
CONFIG_BLK_DEV_LOOP_MIN_COUNT=0
# CONFIG_BLK_DEV_DRBD is not set
CONFIG_BLK_DEV_NBD=m
CONFIG_BLK_DEV_RAM=m
CONFIG_BLK_DEV_RAM_COUNT=16
CONFIG_BLK_DEV_RAM_SIZE=16384
CONFIG_CDROM_PKTCDVD=m
CONFIG_CDROM_PKTCDVD_BUFFERS=8
# CONFIG_CDROM_PKTCDVD_WCACHE is not set
# CONFIG_ATA_OVER_ETH is not set
CONFIG_VIRTIO_BLK=m
CONFIG_BLK_DEV_RBD=m
# CONFIG_BLK_DEV_UBLK is not set

#
# NVME Support
#
CONFIG_NVME_CORE=m
CONFIG_BLK_DEV_NVME=m
CONFIG_NVME_MULTIPATH=y
# CONFIG_NVME_VERBOSE_ERRORS is not set
# CONFIG_NVME_HWMON is not set
CONFIG_NVME_FABRICS=m
# CONFIG_NVME_RDMA is not set
# CONFIG_NVME_FC is not set
# CONFIG_NVME_TCP is not set
# CONFIG_NVME_AUTH is not set
CONFIG_NVME_TARGET=m
# CONFIG_NVME_TARGET_PASSTHRU is not set
CONFIG_NVME_TARGET_LOOP=m
# CONFIG_NVME_TARGET_RDMA is not set
CONFIG_NVME_TARGET_FC=m
# CONFIG_NVME_TARGET_TCP is not set
# CONFIG_NVME_TARGET_AUTH is not set
# end of NVME Support

#
# Misc devices
#
CONFIG_SENSORS_LIS3LV02D=m
# CONFIG_AD525X_DPOT is not set
# CONFIG_DUMMY_IRQ is not set
# CONFIG_IBM_ASM is not set
# CONFIG_PHANTOM is not set
CONFIG_TIFM_CORE=m
CONFIG_TIFM_7XX1=m
# CONFIG_ICS932S401 is not set
CONFIG_ENCLOSURE_SERVICES=m
CONFIG_SGI_XP=m
CONFIG_HP_ILO=m
CONFIG_SGI_GRU=m
# CONFIG_SGI_GRU_DEBUG is not set
CONFIG_APDS9802ALS=m
CONFIG_ISL29003=m
CONFIG_ISL29020=m
CONFIG_SENSORS_TSL2550=m
CONFIG_SENSORS_BH1770=m
CONFIG_SENSORS_APDS990X=m
# CONFIG_HMC6352 is not set
# CONFIG_DS1682 is not set
CONFIG_VMWARE_BALLOON=m
# CONFIG_LATTICE_ECP3_CONFIG is not set
# CONFIG_SRAM is not set
# CONFIG_DW_XDATA_PCIE is not set
# CONFIG_PCI_ENDPOINT_TEST is not set
# CONFIG_XILINX_SDFEC is not set
CONFIG_MISC_RTSX=m
# CONFIG_C2PORT is not set

#
# EEPROM support
#
# CONFIG_EEPROM_AT24 is not set
# CONFIG_EEPROM_AT25 is not set
CONFIG_EEPROM_LEGACY=m
CONFIG_EEPROM_MAX6875=m
CONFIG_EEPROM_93CX6=m
# CONFIG_EEPROM_93XX46 is not set
# CONFIG_EEPROM_IDT_89HPESX is not set
# CONFIG_EEPROM_EE1004 is not set
# end of EEPROM support

CONFIG_CB710_CORE=m
# CONFIG_CB710_DEBUG is not set
CONFIG_CB710_DEBUG_ASSUMPTIONS=y

#
# Texas Instruments shared transport line discipline
#
# CONFIG_TI_ST is not set
# end of Texas Instruments shared transport line discipline

CONFIG_SENSORS_LIS3_I2C=m
CONFIG_ALTERA_STAPL=m
CONFIG_INTEL_MEI=m
CONFIG_INTEL_MEI_ME=m
# CONFIG_INTEL_MEI_TXE is not set
# CONFIG_INTEL_MEI_GSC is not set
# CONFIG_INTEL_MEI_HDCP is not set
# CONFIG_INTEL_MEI_PXP is not set
CONFIG_VMWARE_VMCI=m
# CONFIG_GENWQE is not set
# CONFIG_ECHO is not set
# CONFIG_BCM_VK is not set
# CONFIG_MISC_ALCOR_PCI is not set
CONFIG_MISC_RTSX_PCI=m
# CONFIG_MISC_RTSX_USB is not set
# CONFIG_HABANA_AI is not set
# CONFIG_UACCE is not set
CONFIG_PVPANIC=y
# CONFIG_PVPANIC_MMIO is not set
# CONFIG_PVPANIC_PCI is not set
# CONFIG_GP_PCI1XXXX is not set
# end of Misc devices

#
# SCSI device support
#
CONFIG_SCSI_MOD=y
CONFIG_RAID_ATTRS=m
CONFIG_SCSI_COMMON=y
CONFIG_SCSI=y
CONFIG_SCSI_DMA=y
CONFIG_SCSI_NETLINK=y
CONFIG_SCSI_PROC_FS=y

#
# SCSI support type (disk, tape, CD-ROM)
#
CONFIG_BLK_DEV_SD=m
CONFIG_CHR_DEV_ST=m
CONFIG_BLK_DEV_SR=m
CONFIG_CHR_DEV_SG=m
CONFIG_BLK_DEV_BSG=y
CONFIG_CHR_DEV_SCH=m
CONFIG_SCSI_ENCLOSURE=m
CONFIG_SCSI_CONSTANTS=y
CONFIG_SCSI_LOGGING=y
CONFIG_SCSI_SCAN_ASYNC=y

#
# SCSI Transports
#
CONFIG_SCSI_SPI_ATTRS=m
CONFIG_SCSI_FC_ATTRS=m
CONFIG_SCSI_ISCSI_ATTRS=m
CONFIG_SCSI_SAS_ATTRS=m
CONFIG_SCSI_SAS_LIBSAS=m
CONFIG_SCSI_SAS_ATA=y
CONFIG_SCSI_SAS_HOST_SMP=y
CONFIG_SCSI_SRP_ATTRS=m
# end of SCSI Transports

CONFIG_SCSI_LOWLEVEL=y
# CONFIG_ISCSI_TCP is not set
# CONFIG_ISCSI_BOOT_SYSFS is not set
# CONFIG_SCSI_CXGB3_ISCSI is not set
# CONFIG_SCSI_CXGB4_ISCSI is not set
# CONFIG_SCSI_BNX2_ISCSI is not set
# CONFIG_BE2ISCSI is not set
# CONFIG_BLK_DEV_3W_XXXX_RAID is not set
# CONFIG_SCSI_HPSA is not set
# CONFIG_SCSI_3W_9XXX is not set
# CONFIG_SCSI_3W_SAS is not set
# CONFIG_SCSI_ACARD is not set
# CONFIG_SCSI_AACRAID is not set
# CONFIG_SCSI_AIC7XXX is not set
# CONFIG_SCSI_AIC79XX is not set
# CONFIG_SCSI_AIC94XX is not set
# CONFIG_SCSI_MVSAS is not set
# CONFIG_SCSI_MVUMI is not set
# CONFIG_SCSI_ADVANSYS is not set
# CONFIG_SCSI_ARCMSR is not set
# CONFIG_SCSI_ESAS2R is not set
# CONFIG_MEGARAID_NEWGEN is not set
# CONFIG_MEGARAID_LEGACY is not set
# CONFIG_MEGARAID_SAS is not set
CONFIG_SCSI_MPT3SAS=m
CONFIG_SCSI_MPT2SAS_MAX_SGE=128
CONFIG_SCSI_MPT3SAS_MAX_SGE=128
# CONFIG_SCSI_MPT2SAS is not set
# CONFIG_SCSI_MPI3MR is not set
# CONFIG_SCSI_SMARTPQI is not set
# CONFIG_SCSI_HPTIOP is not set
# CONFIG_SCSI_BUSLOGIC is not set
# CONFIG_SCSI_MYRB is not set
# CONFIG_SCSI_MYRS is not set
# CONFIG_VMWARE_PVSCSI is not set
# CONFIG_LIBFC is not set
# CONFIG_SCSI_SNIC is not set
# CONFIG_SCSI_DMX3191D is not set
# CONFIG_SCSI_FDOMAIN_PCI is not set
CONFIG_SCSI_ISCI=m
# CONFIG_SCSI_IPS is not set
# CONFIG_SCSI_INITIO is not set
# CONFIG_SCSI_INIA100 is not set
# CONFIG_SCSI_PPA is not set
# CONFIG_SCSI_IMM is not set
# CONFIG_SCSI_STEX is not set
# CONFIG_SCSI_SYM53C8XX_2 is not set
# CONFIG_SCSI_IPR is not set
# CONFIG_SCSI_QLOGIC_1280 is not set
# CONFIG_SCSI_QLA_FC is not set
# CONFIG_SCSI_QLA_ISCSI is not set
# CONFIG_SCSI_LPFC is not set
# CONFIG_SCSI_EFCT is not set
# CONFIG_SCSI_DC395x is not set
# CONFIG_SCSI_AM53C974 is not set
# CONFIG_SCSI_WD719X is not set
CONFIG_SCSI_DEBUG=m
# CONFIG_SCSI_PMCRAID is not set
# CONFIG_SCSI_PM8001 is not set
# CONFIG_SCSI_BFA_FC is not set
# CONFIG_SCSI_VIRTIO is not set
# CONFIG_SCSI_CHELSIO_FCOE is not set
CONFIG_SCSI_DH=y
CONFIG_SCSI_DH_RDAC=y
CONFIG_SCSI_DH_HP_SW=y
CONFIG_SCSI_DH_EMC=y
CONFIG_SCSI_DH_ALUA=y
# end of SCSI device support

CONFIG_ATA=m
CONFIG_SATA_HOST=y
CONFIG_PATA_TIMINGS=y
CONFIG_ATA_VERBOSE_ERROR=y
CONFIG_ATA_FORCE=y
CONFIG_ATA_ACPI=y
# CONFIG_SATA_ZPODD is not set
CONFIG_SATA_PMP=y

#
# Controllers with non-SFF native interface
#
CONFIG_SATA_AHCI=m
CONFIG_SATA_MOBILE_LPM_POLICY=0
CONFIG_SATA_AHCI_PLATFORM=m
# CONFIG_AHCI_DWC is not set
# CONFIG_SATA_INIC162X is not set
# CONFIG_SATA_ACARD_AHCI is not set
# CONFIG_SATA_SIL24 is not set
CONFIG_ATA_SFF=y

#
# SFF controllers with custom DMA interface
#
# CONFIG_PDC_ADMA is not set
# CONFIG_SATA_QSTOR is not set
# CONFIG_SATA_SX4 is not set
CONFIG_ATA_BMDMA=y

#
# SATA SFF controllers with BMDMA
#
CONFIG_ATA_PIIX=m
# CONFIG_SATA_DWC is not set
# CONFIG_SATA_MV is not set
# CONFIG_SATA_NV is not set
# CONFIG_SATA_PROMISE is not set
# CONFIG_SATA_SIL is not set
# CONFIG_SATA_SIS is not set
# CONFIG_SATA_SVW is not set
# CONFIG_SATA_ULI is not set
# CONFIG_SATA_VIA is not set
# CONFIG_SATA_VITESSE is not set

#
# PATA SFF controllers with BMDMA
#
# CONFIG_PATA_ALI is not set
# CONFIG_PATA_AMD is not set
# CONFIG_PATA_ARTOP is not set
# CONFIG_PATA_ATIIXP is not set
# CONFIG_PATA_ATP867X is not set
# CONFIG_PATA_CMD64X is not set
# CONFIG_PATA_CYPRESS is not set
# CONFIG_PATA_EFAR is not set
# CONFIG_PATA_HPT366 is not set
# CONFIG_PATA_HPT37X is not set
# CONFIG_PATA_HPT3X2N is not set
# CONFIG_PATA_HPT3X3 is not set
# CONFIG_PATA_IT8213 is not set
# CONFIG_PATA_IT821X is not set
# CONFIG_PATA_JMICRON is not set
# CONFIG_PATA_MARVELL is not set
# CONFIG_PATA_NETCELL is not set
# CONFIG_PATA_NINJA32 is not set
# CONFIG_PATA_NS87415 is not set
# CONFIG_PATA_OLDPIIX is not set
# CONFIG_PATA_OPTIDMA is not set
# CONFIG_PATA_PDC2027X is not set
# CONFIG_PATA_PDC_OLD is not set
# CONFIG_PATA_RADISYS is not set
# CONFIG_PATA_RDC is not set
# CONFIG_PATA_SCH is not set
# CONFIG_PATA_SERVERWORKS is not set
# CONFIG_PATA_SIL680 is not set
# CONFIG_PATA_SIS is not set
# CONFIG_PATA_TOSHIBA is not set
# CONFIG_PATA_TRIFLEX is not set
# CONFIG_PATA_VIA is not set
# CONFIG_PATA_WINBOND is not set

#
# PIO-only SFF controllers
#
# CONFIG_PATA_CMD640_PCI is not set
# CONFIG_PATA_MPIIX is not set
# CONFIG_PATA_NS87410 is not set
# CONFIG_PATA_OPTI is not set
# CONFIG_PATA_RZ1000 is not set

#
# Generic fallback / legacy drivers
#
# CONFIG_PATA_ACPI is not set
CONFIG_ATA_GENERIC=m
# CONFIG_PATA_LEGACY is not set
CONFIG_MD=y
CONFIG_BLK_DEV_MD=y
CONFIG_MD_AUTODETECT=y
CONFIG_MD_LINEAR=m
CONFIG_MD_RAID0=m
CONFIG_MD_RAID1=m
CONFIG_MD_RAID10=m
CONFIG_MD_RAID456=m
CONFIG_MD_MULTIPATH=m
CONFIG_MD_FAULTY=m
CONFIG_MD_CLUSTER=m
# CONFIG_BCACHE is not set
CONFIG_BLK_DEV_DM_BUILTIN=y
CONFIG_BLK_DEV_DM=m
CONFIG_DM_DEBUG=y
CONFIG_DM_BUFIO=m
# CONFIG_DM_DEBUG_BLOCK_MANAGER_LOCKING is not set
CONFIG_DM_BIO_PRISON=m
CONFIG_DM_PERSISTENT_DATA=m
# CONFIG_DM_UNSTRIPED is not set
CONFIG_DM_CRYPT=m
CONFIG_DM_SNAPSHOT=m
CONFIG_DM_THIN_PROVISIONING=m
CONFIG_DM_CACHE=m
CONFIG_DM_CACHE_SMQ=m
CONFIG_DM_WRITECACHE=m
# CONFIG_DM_EBS is not set
CONFIG_DM_ERA=m
# CONFIG_DM_CLONE is not set
CONFIG_DM_MIRROR=m
CONFIG_DM_LOG_USERSPACE=m
CONFIG_DM_RAID=m
CONFIG_DM_ZERO=m
CONFIG_DM_MULTIPATH=m
CONFIG_DM_MULTIPATH_QL=m
CONFIG_DM_MULTIPATH_ST=m
# CONFIG_DM_MULTIPATH_HST is not set
# CONFIG_DM_MULTIPATH_IOA is not set
CONFIG_DM_DELAY=m
# CONFIG_DM_DUST is not set
CONFIG_DM_UEVENT=y
CONFIG_DM_FLAKEY=m
CONFIG_DM_VERITY=m
# CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG is not set
# CONFIG_DM_VERITY_FEC is not set
CONFIG_DM_SWITCH=m
CONFIG_DM_LOG_WRITES=m
CONFIG_DM_INTEGRITY=m
# CONFIG_DM_ZONED is not set
CONFIG_DM_AUDIT=y
CONFIG_TARGET_CORE=m
CONFIG_TCM_IBLOCK=m
CONFIG_TCM_FILEIO=m
CONFIG_TCM_PSCSI=m
CONFIG_TCM_USER2=m
CONFIG_LOOPBACK_TARGET=m
CONFIG_ISCSI_TARGET=m
# CONFIG_SBP_TARGET is not set
# CONFIG_FUSION is not set

#
# IEEE 1394 (FireWire) support
#
CONFIG_FIREWIRE=m
CONFIG_FIREWIRE_OHCI=m
CONFIG_FIREWIRE_SBP2=m
CONFIG_FIREWIRE_NET=m
# CONFIG_FIREWIRE_NOSY is not set
# end of IEEE 1394 (FireWire) support

CONFIG_MACINTOSH_DRIVERS=y
CONFIG_MAC_EMUMOUSEBTN=y
CONFIG_NETDEVICES=y
CONFIG_MII=y
CONFIG_NET_CORE=y
# CONFIG_BONDING is not set
CONFIG_DUMMY=m
# CONFIG_WIREGUARD is not set
# CONFIG_EQUALIZER is not set
# CONFIG_NET_FC is not set
# CONFIG_IFB is not set
# CONFIG_NET_TEAM is not set
# CONFIG_MACVLAN is not set
# CONFIG_IPVLAN is not set
# CONFIG_VXLAN is not set
# CONFIG_GENEVE is not set
# CONFIG_BAREUDP is not set
# CONFIG_GTP is not set
# CONFIG_AMT is not set
CONFIG_MACSEC=m
CONFIG_NETCONSOLE=m
CONFIG_NETCONSOLE_DYNAMIC=y
CONFIG_NETPOLL=y
CONFIG_NET_POLL_CONTROLLER=y
CONFIG_TUN=m
# CONFIG_TUN_VNET_CROSS_LE is not set
CONFIG_VETH=m
CONFIG_VIRTIO_NET=m
# CONFIG_NLMON is not set
# CONFIG_NET_VRF is not set
# CONFIG_VSOCKMON is not set
# CONFIG_ARCNET is not set
CONFIG_ATM_DRIVERS=y
# CONFIG_ATM_DUMMY is not set
# CONFIG_ATM_TCP is not set
# CONFIG_ATM_LANAI is not set
# CONFIG_ATM_ENI is not set
# CONFIG_ATM_NICSTAR is not set
# CONFIG_ATM_IDT77252 is not set
# CONFIG_ATM_IA is not set
# CONFIG_ATM_FORE200E is not set
# CONFIG_ATM_HE is not set
# CONFIG_ATM_SOLOS is not set
CONFIG_ETHERNET=y
CONFIG_MDIO=y
# CONFIG_NET_VENDOR_3COM is not set
CONFIG_NET_VENDOR_ADAPTEC=y
# CONFIG_ADAPTEC_STARFIRE is not set
CONFIG_NET_VENDOR_AGERE=y
# CONFIG_ET131X is not set
CONFIG_NET_VENDOR_ALACRITECH=y
# CONFIG_SLICOSS is not set
CONFIG_NET_VENDOR_ALTEON=y
# CONFIG_ACENIC is not set
# CONFIG_ALTERA_TSE is not set
CONFIG_NET_VENDOR_AMAZON=y
# CONFIG_ENA_ETHERNET is not set
# CONFIG_NET_VENDOR_AMD is not set
CONFIG_NET_VENDOR_AQUANTIA=y
# CONFIG_AQTION is not set
CONFIG_NET_VENDOR_ARC=y
CONFIG_NET_VENDOR_ASIX=y
# CONFIG_SPI_AX88796C is not set
CONFIG_NET_VENDOR_ATHEROS=y
# CONFIG_ATL2 is not set
# CONFIG_ATL1 is not set
# CONFIG_ATL1E is not set
# CONFIG_ATL1C is not set
# CONFIG_ALX is not set
# CONFIG_CX_ECAT is not set
CONFIG_NET_VENDOR_BROADCOM=y
# CONFIG_B44 is not set
# CONFIG_BCMGENET is not set
# CONFIG_BNX2 is not set
# CONFIG_CNIC is not set
# CONFIG_TIGON3 is not set
# CONFIG_BNX2X is not set
# CONFIG_SYSTEMPORT is not set
# CONFIG_BNXT is not set
CONFIG_NET_VENDOR_CADENCE=y
# CONFIG_MACB is not set
CONFIG_NET_VENDOR_CAVIUM=y
# CONFIG_THUNDER_NIC_PF is not set
# CONFIG_THUNDER_NIC_VF is not set
# CONFIG_THUNDER_NIC_BGX is not set
# CONFIG_THUNDER_NIC_RGX is not set
CONFIG_CAVIUM_PTP=y
# CONFIG_LIQUIDIO is not set
# CONFIG_LIQUIDIO_VF is not set
CONFIG_NET_VENDOR_CHELSIO=y
# CONFIG_CHELSIO_T1 is not set
# CONFIG_CHELSIO_T3 is not set
# CONFIG_CHELSIO_T4 is not set
# CONFIG_CHELSIO_T4VF is not set
CONFIG_NET_VENDOR_CISCO=y
# CONFIG_ENIC is not set
CONFIG_NET_VENDOR_CORTINA=y
CONFIG_NET_VENDOR_DAVICOM=y
# CONFIG_DM9051 is not set
# CONFIG_DNET is not set
CONFIG_NET_VENDOR_DEC=y
# CONFIG_NET_TULIP is not set
CONFIG_NET_VENDOR_DLINK=y
# CONFIG_DL2K is not set
# CONFIG_SUNDANCE is not set
CONFIG_NET_VENDOR_EMULEX=y
# CONFIG_BE2NET is not set
CONFIG_NET_VENDOR_ENGLEDER=y
# CONFIG_TSNEP is not set
CONFIG_NET_VENDOR_EZCHIP=y
CONFIG_NET_VENDOR_FUNGIBLE=y
# CONFIG_FUN_ETH is not set
CONFIG_NET_VENDOR_GOOGLE=y
# CONFIG_GVE is not set
CONFIG_NET_VENDOR_HUAWEI=y
# CONFIG_HINIC is not set
CONFIG_NET_VENDOR_I825XX=y
CONFIG_NET_VENDOR_INTEL=y
# CONFIG_E100 is not set
CONFIG_E1000=y
CONFIG_E1000E=y
CONFIG_E1000E_HWTS=y
CONFIG_IGB=y
CONFIG_IGB_HWMON=y
# CONFIG_IGBVF is not set
# CONFIG_IXGB is not set
CONFIG_IXGBE=y
CONFIG_IXGBE_HWMON=y
# CONFIG_IXGBE_DCB is not set
# CONFIG_IXGBE_IPSEC is not set
# CONFIG_IXGBEVF is not set
CONFIG_I40E=y
# CONFIG_I40E_DCB is not set
# CONFIG_I40EVF is not set
# CONFIG_ICE is not set
# CONFIG_FM10K is not set
CONFIG_IGC=y
CONFIG_NET_VENDOR_WANGXUN=y
# CONFIG_NGBE is not set
# CONFIG_TXGBE is not set
# CONFIG_JME is not set
CONFIG_NET_VENDOR_ADI=y
# CONFIG_ADIN1110 is not set
CONFIG_NET_VENDOR_LITEX=y
CONFIG_NET_VENDOR_MARVELL=y
# CONFIG_MVMDIO is not set
# CONFIG_SKGE is not set
# CONFIG_SKY2 is not set
# CONFIG_OCTEON_EP is not set
# CONFIG_PRESTERA is not set
CONFIG_NET_VENDOR_MELLANOX=y
# CONFIG_MLX4_EN is not set
# CONFIG_MLX5_CORE is not set
# CONFIG_MLXSW_CORE is not set
# CONFIG_MLXFW is not set
CONFIG_NET_VENDOR_MICREL=y
# CONFIG_KS8842 is not set
# CONFIG_KS8851 is not set
# CONFIG_KS8851_MLL is not set
# CONFIG_KSZ884X_PCI is not set
CONFIG_NET_VENDOR_MICROCHIP=y
# CONFIG_ENC28J60 is not set
# CONFIG_ENCX24J600 is not set
# CONFIG_LAN743X is not set
CONFIG_NET_VENDOR_MICROSEMI=y
CONFIG_NET_VENDOR_MICROSOFT=y
CONFIG_NET_VENDOR_MYRI=y
# CONFIG_MYRI10GE is not set
# CONFIG_FEALNX is not set
CONFIG_NET_VENDOR_NI=y
# CONFIG_NI_XGE_MANAGEMENT_ENET is not set
CONFIG_NET_VENDOR_NATSEMI=y
# CONFIG_NATSEMI is not set
# CONFIG_NS83820 is not set
CONFIG_NET_VENDOR_NETERION=y
# CONFIG_S2IO is not set
CONFIG_NET_VENDOR_NETRONOME=y
# CONFIG_NFP is not set
CONFIG_NET_VENDOR_8390=y
# CONFIG_NE2K_PCI is not set
CONFIG_NET_VENDOR_NVIDIA=y
# CONFIG_FORCEDETH is not set
CONFIG_NET_VENDOR_OKI=y
# CONFIG_ETHOC is not set
CONFIG_NET_VENDOR_PACKET_ENGINES=y
# CONFIG_HAMACHI is not set
# CONFIG_YELLOWFIN is not set
CONFIG_NET_VENDOR_PENSANDO=y
# CONFIG_IONIC is not set
CONFIG_NET_VENDOR_QLOGIC=y
# CONFIG_QLA3XXX is not set
# CONFIG_QLCNIC is not set
# CONFIG_NETXEN_NIC is not set
# CONFIG_QED is not set
CONFIG_NET_VENDOR_BROCADE=y
# CONFIG_BNA is not set
CONFIG_NET_VENDOR_QUALCOMM=y
# CONFIG_QCOM_EMAC is not set
# CONFIG_RMNET is not set
CONFIG_NET_VENDOR_RDC=y
# CONFIG_R6040 is not set
CONFIG_NET_VENDOR_REALTEK=y
# CONFIG_ATP is not set
# CONFIG_8139CP is not set
# CONFIG_8139TOO is not set
CONFIG_R8169=y
CONFIG_NET_VENDOR_RENESAS=y
CONFIG_NET_VENDOR_ROCKER=y
# CONFIG_ROCKER is not set
CONFIG_NET_VENDOR_SAMSUNG=y
# CONFIG_SXGBE_ETH is not set
CONFIG_NET_VENDOR_SEEQ=y
CONFIG_NET_VENDOR_SILAN=y
# CONFIG_SC92031 is not set
CONFIG_NET_VENDOR_SIS=y
# CONFIG_SIS900 is not set
# CONFIG_SIS190 is not set
CONFIG_NET_VENDOR_SOLARFLARE=y
# CONFIG_SFC is not set
# CONFIG_SFC_FALCON is not set
# CONFIG_SFC_SIENA is not set
CONFIG_NET_VENDOR_SMSC=y
# CONFIG_EPIC100 is not set
# CONFIG_SMSC911X is not set
# CONFIG_SMSC9420 is not set
CONFIG_NET_VENDOR_SOCIONEXT=y
CONFIG_NET_VENDOR_STMICRO=y
# CONFIG_STMMAC_ETH is not set
CONFIG_NET_VENDOR_SUN=y
# CONFIG_HAPPYMEAL is not set
# CONFIG_SUNGEM is not set
# CONFIG_CASSINI is not set
# CONFIG_NIU is not set
CONFIG_NET_VENDOR_SYNOPSYS=y
# CONFIG_DWC_XLGMAC is not set
CONFIG_NET_VENDOR_TEHUTI=y
# CONFIG_TEHUTI is not set
CONFIG_NET_VENDOR_TI=y
# CONFIG_TI_CPSW_PHY_SEL is not set
# CONFIG_TLAN is not set
CONFIG_NET_VENDOR_VERTEXCOM=y
# CONFIG_MSE102X is not set
CONFIG_NET_VENDOR_VIA=y
# CONFIG_VIA_RHINE is not set
# CONFIG_VIA_VELOCITY is not set
CONFIG_NET_VENDOR_WIZNET=y
# CONFIG_WIZNET_W5100 is not set
# CONFIG_WIZNET_W5300 is not set
CONFIG_NET_VENDOR_XILINX=y
# CONFIG_XILINX_EMACLITE is not set
# CONFIG_XILINX_AXI_EMAC is not set
# CONFIG_XILINX_LL_TEMAC is not set
# CONFIG_FDDI is not set
# CONFIG_HIPPI is not set
# CONFIG_NET_SB1000 is not set
CONFIG_PHYLINK=y
CONFIG_PHYLIB=y
CONFIG_SWPHY=y
# CONFIG_LED_TRIGGER_PHY is not set
CONFIG_FIXED_PHY=y
# CONFIG_SFP is not set

#
# MII PHY device drivers
#
# CONFIG_AMD_PHY is not set
# CONFIG_ADIN_PHY is not set
# CONFIG_ADIN1100_PHY is not set
# CONFIG_AQUANTIA_PHY is not set
CONFIG_AX88796B_PHY=y
# CONFIG_BROADCOM_PHY is not set
# CONFIG_BCM54140_PHY is not set
# CONFIG_BCM7XXX_PHY is not set
# CONFIG_BCM84881_PHY is not set
# CONFIG_BCM87XX_PHY is not set
# CONFIG_CICADA_PHY is not set
# CONFIG_CORTINA_PHY is not set
# CONFIG_DAVICOM_PHY is not set
# CONFIG_ICPLUS_PHY is not set
# CONFIG_LXT_PHY is not set
# CONFIG_INTEL_XWAY_PHY is not set
# CONFIG_LSI_ET1011C_PHY is not set
# CONFIG_MARVELL_PHY is not set
# CONFIG_MARVELL_10G_PHY is not set
# CONFIG_MARVELL_88X2222_PHY is not set
# CONFIG_MAXLINEAR_GPHY is not set
# CONFIG_MEDIATEK_GE_PHY is not set
# CONFIG_MICREL_PHY is not set
# CONFIG_MICROCHIP_PHY is not set
# CONFIG_MICROCHIP_T1_PHY is not set
# CONFIG_MICROSEMI_PHY is not set
# CONFIG_MOTORCOMM_PHY is not set
# CONFIG_NATIONAL_PHY is not set
# CONFIG_NXP_C45_TJA11XX_PHY is not set
# CONFIG_NXP_TJA11XX_PHY is not set
# CONFIG_QSEMI_PHY is not set
CONFIG_REALTEK_PHY=y
# CONFIG_RENESAS_PHY is not set
# CONFIG_ROCKCHIP_PHY is not set
# CONFIG_SMSC_PHY is not set
# CONFIG_STE10XP is not set
# CONFIG_TERANETICS_PHY is not set
# CONFIG_DP83822_PHY is not set
# CONFIG_DP83TC811_PHY is not set
# CONFIG_DP83848_PHY is not set
# CONFIG_DP83867_PHY is not set
# CONFIG_DP83869_PHY is not set
# CONFIG_DP83TD510_PHY is not set
# CONFIG_VITESSE_PHY is not set
# CONFIG_XILINX_GMII2RGMII is not set
# CONFIG_MICREL_KS8995MA is not set
# CONFIG_PSE_CONTROLLER is not set
CONFIG_CAN_DEV=m
CONFIG_CAN_VCAN=m
# CONFIG_CAN_VXCAN is not set
CONFIG_CAN_NETLINK=y
CONFIG_CAN_CALC_BITTIMING=y
# CONFIG_CAN_CAN327 is not set
# CONFIG_CAN_KVASER_PCIEFD is not set
CONFIG_CAN_SLCAN=m
CONFIG_CAN_C_CAN=m
CONFIG_CAN_C_CAN_PLATFORM=m
CONFIG_CAN_C_CAN_PCI=m
CONFIG_CAN_CC770=m
# CONFIG_CAN_CC770_ISA is not set
CONFIG_CAN_CC770_PLATFORM=m
# CONFIG_CAN_CTUCANFD_PCI is not set
# CONFIG_CAN_IFI_CANFD is not set
# CONFIG_CAN_M_CAN is not set
# CONFIG_CAN_PEAK_PCIEFD is not set
CONFIG_CAN_SJA1000=m
CONFIG_CAN_EMS_PCI=m
# CONFIG_CAN_F81601 is not set
CONFIG_CAN_KVASER_PCI=m
CONFIG_CAN_PEAK_PCI=m
CONFIG_CAN_PEAK_PCIEC=y
CONFIG_CAN_PLX_PCI=m
# CONFIG_CAN_SJA1000_ISA is not set
# CONFIG_CAN_SJA1000_PLATFORM is not set
CONFIG_CAN_SOFTING=m

#
# CAN SPI interfaces
#
# CONFIG_CAN_HI311X is not set
# CONFIG_CAN_MCP251X is not set
# CONFIG_CAN_MCP251XFD is not set
# end of CAN SPI interfaces

#
# CAN USB interfaces
#
# CONFIG_CAN_8DEV_USB is not set
# CONFIG_CAN_EMS_USB is not set
# CONFIG_CAN_ESD_USB is not set
# CONFIG_CAN_ETAS_ES58X is not set
# CONFIG_CAN_GS_USB is not set
# CONFIG_CAN_KVASER_USB is not set
# CONFIG_CAN_MCBA_USB is not set
# CONFIG_CAN_PEAK_USB is not set
# CONFIG_CAN_UCAN is not set
# end of CAN USB interfaces

# CONFIG_CAN_DEBUG_DEVICES is not set
CONFIG_MDIO_DEVICE=y
CONFIG_MDIO_BUS=y
CONFIG_FWNODE_MDIO=y
CONFIG_ACPI_MDIO=y
CONFIG_MDIO_DEVRES=y
# CONFIG_MDIO_BITBANG is not set
# CONFIG_MDIO_BCM_UNIMAC is not set
# CONFIG_MDIO_MVUSB is not set
# CONFIG_MDIO_THUNDER is not set

#
# MDIO Multiplexers
#

#
# PCS device drivers
#
# end of PCS device drivers

# CONFIG_PLIP is not set
# CONFIG_PPP is not set
# CONFIG_SLIP is not set
CONFIG_USB_NET_DRIVERS=y
# CONFIG_USB_CATC is not set
# CONFIG_USB_KAWETH is not set
# CONFIG_USB_PEGASUS is not set
# CONFIG_USB_RTL8150 is not set
CONFIG_USB_RTL8152=y
# CONFIG_USB_LAN78XX is not set
CONFIG_USB_USBNET=y
CONFIG_USB_NET_AX8817X=y
CONFIG_USB_NET_AX88179_178A=y
# CONFIG_USB_NET_CDCETHER is not set
# CONFIG_USB_NET_CDC_EEM is not set
# CONFIG_USB_NET_CDC_NCM is not set
# CONFIG_USB_NET_HUAWEI_CDC_NCM is not set
# CONFIG_USB_NET_CDC_MBIM is not set
# CONFIG_USB_NET_DM9601 is not set
# CONFIG_USB_NET_SR9700 is not set
# CONFIG_USB_NET_SR9800 is not set
# CONFIG_USB_NET_SMSC75XX is not set
# CONFIG_USB_NET_SMSC95XX is not set
# CONFIG_USB_NET_GL620A is not set
# CONFIG_USB_NET_NET1080 is not set
# CONFIG_USB_NET_PLUSB is not set
# CONFIG_USB_NET_MCS7830 is not set
# CONFIG_USB_NET_RNDIS_HOST is not set
# CONFIG_USB_NET_CDC_SUBSET is not set
# CONFIG_USB_NET_ZAURUS is not set
# CONFIG_USB_NET_CX82310_ETH is not set
# CONFIG_USB_NET_KALMIA is not set
# CONFIG_USB_NET_QMI_WWAN is not set
# CONFIG_USB_HSO is not set
# CONFIG_USB_NET_INT51X1 is not set
# CONFIG_USB_IPHETH is not set
# CONFIG_USB_SIERRA_NET is not set
# CONFIG_USB_NET_CH9200 is not set
# CONFIG_USB_NET_AQC111 is not set
CONFIG_WLAN=y
CONFIG_WLAN_VENDOR_ADMTEK=y
# CONFIG_ADM8211 is not set
CONFIG_WLAN_VENDOR_ATH=y
# CONFIG_ATH_DEBUG is not set
# CONFIG_ATH5K is not set
# CONFIG_ATH5K_PCI is not set
# CONFIG_ATH9K is not set
# CONFIG_ATH9K_HTC is not set
# CONFIG_CARL9170 is not set
# CONFIG_ATH6KL is not set
# CONFIG_AR5523 is not set
# CONFIG_WIL6210 is not set
# CONFIG_ATH10K is not set
# CONFIG_WCN36XX is not set
# CONFIG_ATH11K is not set
CONFIG_WLAN_VENDOR_ATMEL=y
# CONFIG_ATMEL is not set
# CONFIG_AT76C50X_USB is not set
CONFIG_WLAN_VENDOR_BROADCOM=y
# CONFIG_B43 is not set
# CONFIG_B43LEGACY is not set
# CONFIG_BRCMSMAC is not set
# CONFIG_BRCMFMAC is not set
CONFIG_WLAN_VENDOR_CISCO=y
# CONFIG_AIRO is not set
CONFIG_WLAN_VENDOR_INTEL=y
# CONFIG_IPW2100 is not set
# CONFIG_IPW2200 is not set
# CONFIG_IWL4965 is not set
# CONFIG_IWL3945 is not set
# CONFIG_IWLWIFI is not set
CONFIG_WLAN_VENDOR_INTERSIL=y
# CONFIG_HOSTAP is not set
# CONFIG_HERMES is not set
# CONFIG_P54_COMMON is not set
CONFIG_WLAN_VENDOR_MARVELL=y
# CONFIG_LIBERTAS is not set
# CONFIG_LIBERTAS_THINFIRM is not set
# CONFIG_MWIFIEX is not set
# CONFIG_MWL8K is not set
# CONFIG_WLAN_VENDOR_MEDIATEK is not set
CONFIG_WLAN_VENDOR_MICROCHIP=y
# CONFIG_WILC1000_SDIO is not set
# CONFIG_WILC1000_SPI is not set
CONFIG_WLAN_VENDOR_PURELIFI=y
# CONFIG_PLFXLC is not set
CONFIG_WLAN_VENDOR_RALINK=y
# CONFIG_RT2X00 is not set
CONFIG_WLAN_VENDOR_REALTEK=y
# CONFIG_RTL8180 is not set
# CONFIG_RTL8187 is not set
CONFIG_RTL_CARDS=m
# CONFIG_RTL8192CE is not set
# CONFIG_RTL8192SE is not set
# CONFIG_RTL8192DE is not set
# CONFIG_RTL8723AE is not set
# CONFIG_RTL8723BE is not set
# CONFIG_RTL8188EE is not set
# CONFIG_RTL8192EE is not set
# CONFIG_RTL8821AE is not set
# CONFIG_RTL8192CU is not set
# CONFIG_RTL8XXXU is not set
# CONFIG_RTW88 is not set
# CONFIG_RTW89 is not set
CONFIG_WLAN_VENDOR_RSI=y
# CONFIG_RSI_91X is not set
CONFIG_WLAN_VENDOR_SILABS=y
# CONFIG_WFX is not set
CONFIG_WLAN_VENDOR_ST=y
# CONFIG_CW1200 is not set
CONFIG_WLAN_VENDOR_TI=y
# CONFIG_WL1251 is not set
# CONFIG_WL12XX is not set
# CONFIG_WL18XX is not set
# CONFIG_WLCORE is not set
CONFIG_WLAN_VENDOR_ZYDAS=y
# CONFIG_USB_ZD1201 is not set
# CONFIG_ZD1211RW is not set
CONFIG_WLAN_VENDOR_QUANTENNA=y
# CONFIG_QTNFMAC_PCIE is not set
CONFIG_MAC80211_HWSIM=m
# CONFIG_USB_NET_RNDIS_WLAN is not set
# CONFIG_VIRT_WIFI is not set
# CONFIG_WAN is not set

#
# Wireless WAN
#
# CONFIG_WWAN is not set
# end of Wireless WAN

# CONFIG_VMXNET3 is not set
# CONFIG_FUJITSU_ES is not set
# CONFIG_NETDEVSIM is not set
CONFIG_NET_FAILOVER=m
# CONFIG_ISDN is not set

#
# Input device support
#
CONFIG_INPUT=y
CONFIG_INPUT_LEDS=y
CONFIG_INPUT_FF_MEMLESS=m
CONFIG_INPUT_SPARSEKMAP=m
# CONFIG_INPUT_MATRIXKMAP is not set
CONFIG_INPUT_VIVALDIFMAP=y

#
# Userland interfaces
#
CONFIG_INPUT_MOUSEDEV=y
# CONFIG_INPUT_MOUSEDEV_PSAUX is not set
CONFIG_INPUT_MOUSEDEV_SCREEN_X=1024
CONFIG_INPUT_MOUSEDEV_SCREEN_Y=768
CONFIG_INPUT_JOYDEV=m
CONFIG_INPUT_EVDEV=y
# CONFIG_INPUT_EVBUG is not set

#
# Input Device Drivers
#
CONFIG_INPUT_KEYBOARD=y
# CONFIG_KEYBOARD_ADP5588 is not set
# CONFIG_KEYBOARD_ADP5589 is not set
# CONFIG_KEYBOARD_APPLESPI is not set
CONFIG_KEYBOARD_ATKBD=y
# CONFIG_KEYBOARD_QT1050 is not set
# CONFIG_KEYBOARD_QT1070 is not set
# CONFIG_KEYBOARD_QT2160 is not set
# CONFIG_KEYBOARD_DLINK_DIR685 is not set
# CONFIG_KEYBOARD_LKKBD is not set
# CONFIG_KEYBOARD_GPIO is not set
# CONFIG_KEYBOARD_GPIO_POLLED is not set
# CONFIG_KEYBOARD_TCA6416 is not set
# CONFIG_KEYBOARD_TCA8418 is not set
# CONFIG_KEYBOARD_MATRIX is not set
# CONFIG_KEYBOARD_LM8323 is not set
# CONFIG_KEYBOARD_LM8333 is not set
# CONFIG_KEYBOARD_MAX7359 is not set
# CONFIG_KEYBOARD_MCS is not set
# CONFIG_KEYBOARD_MPR121 is not set
# CONFIG_KEYBOARD_NEWTON is not set
# CONFIG_KEYBOARD_OPENCORES is not set
# CONFIG_KEYBOARD_SAMSUNG is not set
# CONFIG_KEYBOARD_STOWAWAY is not set
# CONFIG_KEYBOARD_SUNKBD is not set
# CONFIG_KEYBOARD_TM2_TOUCHKEY is not set
# CONFIG_KEYBOARD_XTKBD is not set
# CONFIG_KEYBOARD_CYPRESS_SF is not set
CONFIG_INPUT_MOUSE=y
CONFIG_MOUSE_PS2=y
CONFIG_MOUSE_PS2_ALPS=y
CONFIG_MOUSE_PS2_BYD=y
CONFIG_MOUSE_PS2_LOGIPS2PP=y
CONFIG_MOUSE_PS2_SYNAPTICS=y
CONFIG_MOUSE_PS2_SYNAPTICS_SMBUS=y
CONFIG_MOUSE_PS2_CYPRESS=y
CONFIG_MOUSE_PS2_LIFEBOOK=y
CONFIG_MOUSE_PS2_TRACKPOINT=y
CONFIG_MOUSE_PS2_ELANTECH=y
CONFIG_MOUSE_PS2_ELANTECH_SMBUS=y
CONFIG_MOUSE_PS2_SENTELIC=y
# CONFIG_MOUSE_PS2_TOUCHKIT is not set
CONFIG_MOUSE_PS2_FOCALTECH=y
CONFIG_MOUSE_PS2_VMMOUSE=y
CONFIG_MOUSE_PS2_SMBUS=y
CONFIG_MOUSE_SERIAL=m
# CONFIG_MOUSE_APPLETOUCH is not set
# CONFIG_MOUSE_BCM5974 is not set
CONFIG_MOUSE_CYAPA=m
CONFIG_MOUSE_ELAN_I2C=m
CONFIG_MOUSE_ELAN_I2C_I2C=y
CONFIG_MOUSE_ELAN_I2C_SMBUS=y
CONFIG_MOUSE_VSXXXAA=m
# CONFIG_MOUSE_GPIO is not set
CONFIG_MOUSE_SYNAPTICS_I2C=m
# CONFIG_MOUSE_SYNAPTICS_USB is not set
# CONFIG_INPUT_JOYSTICK is not set
# CONFIG_INPUT_TABLET is not set
# CONFIG_INPUT_TOUCHSCREEN is not set
CONFIG_INPUT_MISC=y
# CONFIG_INPUT_AD714X is not set
# CONFIG_INPUT_BMA150 is not set
# CONFIG_INPUT_E3X0_BUTTON is not set
# CONFIG_INPUT_PCSPKR is not set
# CONFIG_INPUT_MMA8450 is not set
# CONFIG_INPUT_APANEL is not set
# CONFIG_INPUT_GPIO_BEEPER is not set
# CONFIG_INPUT_GPIO_DECODER is not set
# CONFIG_INPUT_GPIO_VIBRA is not set
# CONFIG_INPUT_ATLAS_BTNS is not set
# CONFIG_INPUT_ATI_REMOTE2 is not set
# CONFIG_INPUT_KEYSPAN_REMOTE is not set
# CONFIG_INPUT_KXTJ9 is not set
# CONFIG_INPUT_POWERMATE is not set
# CONFIG_INPUT_YEALINK is not set
# CONFIG_INPUT_CM109 is not set
CONFIG_INPUT_UINPUT=y
# CONFIG_INPUT_PCF8574 is not set
# CONFIG_INPUT_PWM_BEEPER is not set
# CONFIG_INPUT_PWM_VIBRA is not set
# CONFIG_INPUT_GPIO_ROTARY_ENCODER is not set
# CONFIG_INPUT_DA7280_HAPTICS is not set
# CONFIG_INPUT_ADXL34X is not set
# CONFIG_INPUT_IMS_PCU is not set
# CONFIG_INPUT_IQS269A is not set
# CONFIG_INPUT_IQS626A is not set
# CONFIG_INPUT_IQS7222 is not set
# CONFIG_INPUT_CMA3000 is not set
# CONFIG_INPUT_IDEAPAD_SLIDEBAR is not set
# CONFIG_INPUT_DRV260X_HAPTICS is not set
# CONFIG_INPUT_DRV2665_HAPTICS is not set
# CONFIG_INPUT_DRV2667_HAPTICS is not set
CONFIG_RMI4_CORE=m
CONFIG_RMI4_I2C=m
CONFIG_RMI4_SPI=m
CONFIG_RMI4_SMB=m
CONFIG_RMI4_F03=y
CONFIG_RMI4_F03_SERIO=m
CONFIG_RMI4_2D_SENSOR=y
CONFIG_RMI4_F11=y
CONFIG_RMI4_F12=y
CONFIG_RMI4_F30=y
CONFIG_RMI4_F34=y
# CONFIG_RMI4_F3A is not set
CONFIG_RMI4_F55=y

#
# Hardware I/O ports
#
CONFIG_SERIO=y
CONFIG_ARCH_MIGHT_HAVE_PC_SERIO=y
CONFIG_SERIO_I8042=y
CONFIG_SERIO_SERPORT=y
# CONFIG_SERIO_CT82C710 is not set
# CONFIG_SERIO_PARKBD is not set
# CONFIG_SERIO_PCIPS2 is not set
CONFIG_SERIO_LIBPS2=y
CONFIG_SERIO_RAW=m
CONFIG_SERIO_ALTERA_PS2=m
# CONFIG_SERIO_PS2MULT is not set
CONFIG_SERIO_ARC_PS2=m
# CONFIG_SERIO_GPIO_PS2 is not set
# CONFIG_USERIO is not set
# CONFIG_GAMEPORT is not set
# end of Hardware I/O ports
# end of Input device support

#
# Character devices
#
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_CONSOLE_TRANSLATIONS=y
CONFIG_VT_CONSOLE=y
CONFIG_VT_CONSOLE_SLEEP=y
CONFIG_HW_CONSOLE=y
CONFIG_VT_HW_CONSOLE_BINDING=y
CONFIG_UNIX98_PTYS=y
# CONFIG_LEGACY_PTYS is not set
CONFIG_LDISC_AUTOLOAD=y

#
# Serial drivers
#
CONFIG_SERIAL_EARLYCON=y
CONFIG_SERIAL_8250=y
# CONFIG_SERIAL_8250_DEPRECATED_OPTIONS is not set
CONFIG_SERIAL_8250_PNP=y
# CONFIG_SERIAL_8250_16550A_VARIANTS is not set
# CONFIG_SERIAL_8250_FINTEK is not set
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_8250_DMA=y
CONFIG_SERIAL_8250_PCI=y
CONFIG_SERIAL_8250_EXAR=y
CONFIG_SERIAL_8250_NR_UARTS=64
CONFIG_SERIAL_8250_RUNTIME_UARTS=4
CONFIG_SERIAL_8250_EXTENDED=y
CONFIG_SERIAL_8250_MANY_PORTS=y
CONFIG_SERIAL_8250_SHARE_IRQ=y
# CONFIG_SERIAL_8250_DETECT_IRQ is not set
CONFIG_SERIAL_8250_RSA=y
CONFIG_SERIAL_8250_DWLIB=y
CONFIG_SERIAL_8250_DW=y
# CONFIG_SERIAL_8250_RT288X is not set
CONFIG_SERIAL_8250_LPSS=y
CONFIG_SERIAL_8250_MID=y
CONFIG_SERIAL_8250_PERICOM=y

#
# Non-8250 serial port support
#
# CONFIG_SERIAL_MAX3100 is not set
# CONFIG_SERIAL_MAX310X is not set
# CONFIG_SERIAL_UARTLITE is not set
CONFIG_SERIAL_CORE=y
CONFIG_SERIAL_CORE_CONSOLE=y
CONFIG_SERIAL_JSM=m
# CONFIG_SERIAL_LANTIQ is not set
# CONFIG_SERIAL_SCCNXP is not set
# CONFIG_SERIAL_SC16IS7XX is not set
# CONFIG_SERIAL_ALTERA_JTAGUART is not set
# CONFIG_SERIAL_ALTERA_UART is not set
CONFIG_SERIAL_ARC=m
CONFIG_SERIAL_ARC_NR_PORTS=1
# CONFIG_SERIAL_RP2 is not set
# CONFIG_SERIAL_FSL_LPUART is not set
# CONFIG_SERIAL_FSL_LINFLEXUART is not set
# CONFIG_SERIAL_SPRD is not set
# end of Serial drivers

CONFIG_SERIAL_MCTRL_GPIO=y
CONFIG_SERIAL_NONSTANDARD=y
# CONFIG_MOXA_INTELLIO is not set
# CONFIG_MOXA_SMARTIO is not set
CONFIG_SYNCLINK_GT=m
CONFIG_N_HDLC=m
CONFIG_N_GSM=m
CONFIG_NOZOMI=m
# CONFIG_NULL_TTY is not set
CONFIG_HVC_DRIVER=y
# CONFIG_SERIAL_DEV_BUS is not set
# CONFIG_TTY_PRINTK is not set
CONFIG_PRINTER=m
# CONFIG_LP_CONSOLE is not set
CONFIG_PPDEV=m
CONFIG_VIRTIO_CONSOLE=m
CONFIG_IPMI_HANDLER=m
CONFIG_IPMI_DMI_DECODE=y
CONFIG_IPMI_PLAT_DATA=y
CONFIG_IPMI_PANIC_EVENT=y
CONFIG_IPMI_PANIC_STRING=y
CONFIG_IPMI_DEVICE_INTERFACE=m
CONFIG_IPMI_SI=m
CONFIG_IPMI_SSIF=m
CONFIG_IPMI_WATCHDOG=m
CONFIG_IPMI_POWEROFF=m
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_TIMERIOMEM=m
CONFIG_HW_RANDOM_INTEL=m
# CONFIG_HW_RANDOM_AMD is not set
# CONFIG_HW_RANDOM_BA431 is not set
CONFIG_HW_RANDOM_VIA=m
CONFIG_HW_RANDOM_VIRTIO=y
# CONFIG_HW_RANDOM_XIPHERA is not set
# CONFIG_APPLICOM is not set
# CONFIG_MWAVE is not set
CONFIG_DEVMEM=y
CONFIG_NVRAM=y
CONFIG_DEVPORT=y
CONFIG_HPET=y
CONFIG_HPET_MMAP=y
# CONFIG_HPET_MMAP_DEFAULT is not set
CONFIG_HANGCHECK_TIMER=m
CONFIG_UV_MMTIMER=m
CONFIG_TCG_TPM=y
CONFIG_HW_RANDOM_TPM=y
CONFIG_TCG_TIS_CORE=y
CONFIG_TCG_TIS=y
# CONFIG_TCG_TIS_SPI is not set
# CONFIG_TCG_TIS_I2C is not set
# CONFIG_TCG_TIS_I2C_CR50 is not set
CONFIG_TCG_TIS_I2C_ATMEL=m
CONFIG_TCG_TIS_I2C_INFINEON=m
CONFIG_TCG_TIS_I2C_NUVOTON=m
CONFIG_TCG_NSC=m
CONFIG_TCG_ATMEL=m
CONFIG_TCG_INFINEON=m
CONFIG_TCG_CRB=y
# CONFIG_TCG_VTPM_PROXY is not set
CONFIG_TCG_TIS_ST33ZP24=m
CONFIG_TCG_TIS_ST33ZP24_I2C=m
# CONFIG_TCG_TIS_ST33ZP24_SPI is not set
CONFIG_TELCLOCK=m
# CONFIG_XILLYBUS is not set
# CONFIG_XILLYUSB is not set
CONFIG_RANDOM_TRUST_CPU=y
CONFIG_RANDOM_TRUST_BOOTLOADER=y
# end of Character devices

#
# I2C support
#
CONFIG_I2C=y
CONFIG_ACPI_I2C_OPREGION=y
CONFIG_I2C_BOARDINFO=y
CONFIG_I2C_COMPAT=y
CONFIG_I2C_CHARDEV=m
CONFIG_I2C_MUX=m

#
# Multiplexer I2C Chip support
#
# CONFIG_I2C_MUX_GPIO is not set
# CONFIG_I2C_MUX_LTC4306 is not set
# CONFIG_I2C_MUX_PCA9541 is not set
# CONFIG_I2C_MUX_PCA954x is not set
# CONFIG_I2C_MUX_REG is not set
CONFIG_I2C_MUX_MLXCPLD=m
# end of Multiplexer I2C Chip support

CONFIG_I2C_HELPER_AUTO=y
CONFIG_I2C_SMBUS=m
CONFIG_I2C_ALGOBIT=y
CONFIG_I2C_ALGOPCA=m

#
# I2C Hardware Bus support
#

#
# PC SMBus host controller drivers
#
# CONFIG_I2C_ALI1535 is not set
# CONFIG_I2C_ALI1563 is not set
# CONFIG_I2C_ALI15X3 is not set
# CONFIG_I2C_AMD756 is not set
# CONFIG_I2C_AMD8111 is not set
# CONFIG_I2C_AMD_MP2 is not set
CONFIG_I2C_I801=m
CONFIG_I2C_ISCH=m
CONFIG_I2C_ISMT=m
CONFIG_I2C_PIIX4=m
CONFIG_I2C_NFORCE2=m
CONFIG_I2C_NFORCE2_S4985=m
# CONFIG_I2C_NVIDIA_GPU is not set
# CONFIG_I2C_SIS5595 is not set
# CONFIG_I2C_SIS630 is not set
CONFIG_I2C_SIS96X=m
CONFIG_I2C_VIA=m
CONFIG_I2C_VIAPRO=m

#
# ACPI drivers
#
CONFIG_I2C_SCMI=m

#
# I2C system bus drivers (mostly embedded / system-on-chip)
#
# CONFIG_I2C_CBUS_GPIO is not set
CONFIG_I2C_DESIGNWARE_CORE=m
# CONFIG_I2C_DESIGNWARE_SLAVE is not set
CONFIG_I2C_DESIGNWARE_PLATFORM=m
# CONFIG_I2C_DESIGNWARE_AMDPSP is not set
CONFIG_I2C_DESIGNWARE_BAYTRAIL=y
# CONFIG_I2C_DESIGNWARE_PCI is not set
# CONFIG_I2C_EMEV2 is not set
# CONFIG_I2C_GPIO is not set
# CONFIG_I2C_OCORES is not set
CONFIG_I2C_PCA_PLATFORM=m
CONFIG_I2C_SIMTEC=m
# CONFIG_I2C_XILINX is not set

#
# External I2C/SMBus adapter drivers
#
# CONFIG_I2C_DIOLAN_U2C is not set
# CONFIG_I2C_CP2615 is not set
CONFIG_I2C_PARPORT=m
# CONFIG_I2C_PCI1XXXX is not set
# CONFIG_I2C_ROBOTFUZZ_OSIF is not set
# CONFIG_I2C_TAOS_EVM is not set
# CONFIG_I2C_TINY_USB is not set

#
# Other I2C/SMBus bus drivers
#
CONFIG_I2C_MLXCPLD=m
# CONFIG_I2C_VIRTIO is not set
# end of I2C Hardware Bus support

CONFIG_I2C_STUB=m
# CONFIG_I2C_SLAVE is not set
# CONFIG_I2C_DEBUG_CORE is not set
# CONFIG_I2C_DEBUG_ALGO is not set
# CONFIG_I2C_DEBUG_BUS is not set
# end of I2C support

# CONFIG_I3C is not set
CONFIG_SPI=y
# CONFIG_SPI_DEBUG is not set
CONFIG_SPI_MASTER=y
# CONFIG_SPI_MEM is not set

#
# SPI Master Controller Drivers
#
# CONFIG_SPI_ALTERA is not set
# CONFIG_SPI_AXI_SPI_ENGINE is not set
# CONFIG_SPI_BITBANG is not set
# CONFIG_SPI_BUTTERFLY is not set
# CONFIG_SPI_CADENCE is not set
# CONFIG_SPI_DESIGNWARE is not set
# CONFIG_SPI_NXP_FLEXSPI is not set
# CONFIG_SPI_GPIO is not set
# CONFIG_SPI_LM70_LLP is not set
# CONFIG_SPI_MICROCHIP_CORE is not set
# CONFIG_SPI_MICROCHIP_CORE_QSPI is not set
# CONFIG_SPI_LANTIQ_SSC is not set
# CONFIG_SPI_OC_TINY is not set
# CONFIG_SPI_PXA2XX is not set
# CONFIG_SPI_ROCKCHIP is not set
# CONFIG_SPI_SC18IS602 is not set
# CONFIG_SPI_SIFIVE is not set
# CONFIG_SPI_MXIC is not set
# CONFIG_SPI_XCOMM is not set
# CONFIG_SPI_XILINX is not set
# CONFIG_SPI_ZYNQMP_GQSPI is not set
# CONFIG_SPI_AMD is not set

#
# SPI Multiplexer support
#
# CONFIG_SPI_MUX is not set

#
# SPI Protocol Masters
#
# CONFIG_SPI_SPIDEV is not set
# CONFIG_SPI_LOOPBACK_TEST is not set
# CONFIG_SPI_TLE62X0 is not set
# CONFIG_SPI_SLAVE is not set
CONFIG_SPI_DYNAMIC=y
# CONFIG_SPMI is not set
# CONFIG_HSI is not set
CONFIG_PPS=y
# CONFIG_PPS_DEBUG is not set

#
# PPS clients support
#
# CONFIG_PPS_CLIENT_KTIMER is not set
CONFIG_PPS_CLIENT_LDISC=m
CONFIG_PPS_CLIENT_PARPORT=m
CONFIG_PPS_CLIENT_GPIO=m

#
# PPS generators support
#

#
# PTP clock support
#
CONFIG_PTP_1588_CLOCK=y
CONFIG_PTP_1588_CLOCK_OPTIONAL=y
# CONFIG_DP83640_PHY is not set
# CONFIG_PTP_1588_CLOCK_INES is not set
CONFIG_PTP_1588_CLOCK_KVM=m
# CONFIG_PTP_1588_CLOCK_IDT82P33 is not set
# CONFIG_PTP_1588_CLOCK_IDTCM is not set
# CONFIG_PTP_1588_CLOCK_VMW is not set
# end of PTP clock support

CONFIG_PINCTRL=y
# CONFIG_DEBUG_PINCTRL is not set
# CONFIG_PINCTRL_AMD is not set
# CONFIG_PINCTRL_CY8C95X0 is not set
# CONFIG_PINCTRL_MCP23S08 is not set
# CONFIG_PINCTRL_SX150X is not set

#
# Intel pinctrl drivers
#
# CONFIG_PINCTRL_BAYTRAIL is not set
# CONFIG_PINCTRL_CHERRYVIEW is not set
# CONFIG_PINCTRL_LYNXPOINT is not set
# CONFIG_PINCTRL_ALDERLAKE is not set
# CONFIG_PINCTRL_BROXTON is not set
# CONFIG_PINCTRL_CANNONLAKE is not set
# CONFIG_PINCTRL_CEDARFORK is not set
# CONFIG_PINCTRL_DENVERTON is not set
# CONFIG_PINCTRL_ELKHARTLAKE is not set
# CONFIG_PINCTRL_EMMITSBURG is not set
# CONFIG_PINCTRL_GEMINILAKE is not set
# CONFIG_PINCTRL_ICELAKE is not set
# CONFIG_PINCTRL_JASPERLAKE is not set
# CONFIG_PINCTRL_LAKEFIELD is not set
# CONFIG_PINCTRL_LEWISBURG is not set
# CONFIG_PINCTRL_METEORLAKE is not set
# CONFIG_PINCTRL_SUNRISEPOINT is not set
# CONFIG_PINCTRL_TIGERLAKE is not set
# end of Intel pinctrl drivers

#
# Renesas pinctrl drivers
#
# end of Renesas pinctrl drivers

CONFIG_GPIOLIB=y
CONFIG_GPIOLIB_FASTPATH_LIMIT=512
CONFIG_GPIO_ACPI=y
# CONFIG_DEBUG_GPIO is not set
CONFIG_GPIO_SYSFS=y
CONFIG_GPIO_CDEV=y
CONFIG_GPIO_CDEV_V1=y

#
# Memory mapped GPIO drivers
#
# CONFIG_GPIO_AMDPT is not set
# CONFIG_GPIO_DWAPB is not set
# CONFIG_GPIO_EXAR is not set
# CONFIG_GPIO_GENERIC_PLATFORM is not set
CONFIG_GPIO_ICH=m
# CONFIG_GPIO_MB86S7X is not set
# CONFIG_GPIO_VX855 is not set
# CONFIG_GPIO_AMD_FCH is not set
# end of Memory mapped GPIO drivers

#
# Port-mapped I/O GPIO drivers
#
# CONFIG_GPIO_F7188X is not set
# CONFIG_GPIO_IT87 is not set
# CONFIG_GPIO_SCH is not set
# CONFIG_GPIO_SCH311X is not set
# CONFIG_GPIO_WINBOND is not set
# CONFIG_GPIO_WS16C48 is not set
# end of Port-mapped I/O GPIO drivers

#
# I2C GPIO expanders
#
# CONFIG_GPIO_MAX7300 is not set
# CONFIG_GPIO_MAX732X is not set
# CONFIG_GPIO_PCA953X is not set
# CONFIG_GPIO_PCA9570 is not set
# CONFIG_GPIO_PCF857X is not set
# CONFIG_GPIO_TPIC2810 is not set
# end of I2C GPIO expanders

#
# MFD GPIO expanders
#
# end of MFD GPIO expanders

#
# PCI GPIO expanders
#
# CONFIG_GPIO_AMD8111 is not set
# CONFIG_GPIO_BT8XX is not set
# CONFIG_GPIO_ML_IOH is not set
# CONFIG_GPIO_PCI_IDIO_16 is not set
# CONFIG_GPIO_PCIE_IDIO_24 is not set
# CONFIG_GPIO_RDC321X is not set
# end of PCI GPIO expanders

#
# SPI GPIO expanders
#
# CONFIG_GPIO_MAX3191X is not set
# CONFIG_GPIO_MAX7301 is not set
# CONFIG_GPIO_MC33880 is not set
# CONFIG_GPIO_PISOSR is not set
# CONFIG_GPIO_XRA1403 is not set
# end of SPI GPIO expanders

#
# USB GPIO expanders
#
# end of USB GPIO expanders

#
# Virtual GPIO drivers
#
# CONFIG_GPIO_AGGREGATOR is not set
# CONFIG_GPIO_MOCKUP is not set
# CONFIG_GPIO_VIRTIO is not set
# CONFIG_GPIO_SIM is not set
# end of Virtual GPIO drivers

# CONFIG_W1 is not set
CONFIG_POWER_RESET=y
# CONFIG_POWER_RESET_RESTART is not set
CONFIG_POWER_SUPPLY=y
# CONFIG_POWER_SUPPLY_DEBUG is not set
CONFIG_POWER_SUPPLY_HWMON=y
# CONFIG_PDA_POWER is not set
# CONFIG_IP5XXX_POWER is not set
# CONFIG_TEST_POWER is not set
# CONFIG_CHARGER_ADP5061 is not set
# CONFIG_BATTERY_CW2015 is not set
# CONFIG_BATTERY_DS2780 is not set
# CONFIG_BATTERY_DS2781 is not set
# CONFIG_BATTERY_DS2782 is not set
# CONFIG_BATTERY_SAMSUNG_SDI is not set
# CONFIG_BATTERY_SBS is not set
# CONFIG_CHARGER_SBS is not set
# CONFIG_MANAGER_SBS is not set
# CONFIG_BATTERY_BQ27XXX is not set
# CONFIG_BATTERY_MAX17040 is not set
# CONFIG_BATTERY_MAX17042 is not set
# CONFIG_CHARGER_MAX8903 is not set
# CONFIG_CHARGER_LP8727 is not set
# CONFIG_CHARGER_GPIO is not set
# CONFIG_CHARGER_LT3651 is not set
# CONFIG_CHARGER_LTC4162L is not set
# CONFIG_CHARGER_MAX77976 is not set
# CONFIG_CHARGER_BQ2415X is not set
# CONFIG_CHARGER_BQ24257 is not set
# CONFIG_CHARGER_BQ24735 is not set
# CONFIG_CHARGER_BQ2515X is not set
# CONFIG_CHARGER_BQ25890 is not set
# CONFIG_CHARGER_BQ25980 is not set
# CONFIG_CHARGER_BQ256XX is not set
# CONFIG_BATTERY_GAUGE_LTC2941 is not set
# CONFIG_BATTERY_GOLDFISH is not set
# CONFIG_BATTERY_RT5033 is not set
# CONFIG_CHARGER_RT9455 is not set
# CONFIG_CHARGER_BD99954 is not set
# CONFIG_BATTERY_UG3105 is not set
CONFIG_HWMON=y
CONFIG_HWMON_VID=m
# CONFIG_HWMON_DEBUG_CHIP is not set

#
# Native drivers
#
CONFIG_SENSORS_ABITUGURU=m
CONFIG_SENSORS_ABITUGURU3=m
# CONFIG_SENSORS_AD7314 is not set
CONFIG_SENSORS_AD7414=m
CONFIG_SENSORS_AD7418=m
CONFIG_SENSORS_ADM1025=m
CONFIG_SENSORS_ADM1026=m
CONFIG_SENSORS_ADM1029=m
CONFIG_SENSORS_ADM1031=m
# CONFIG_SENSORS_ADM1177 is not set
CONFIG_SENSORS_ADM9240=m
CONFIG_SENSORS_ADT7X10=m
# CONFIG_SENSORS_ADT7310 is not set
CONFIG_SENSORS_ADT7410=m
CONFIG_SENSORS_ADT7411=m
CONFIG_SENSORS_ADT7462=m
CONFIG_SENSORS_ADT7470=m
CONFIG_SENSORS_ADT7475=m
# CONFIG_SENSORS_AHT10 is not set
# CONFIG_SENSORS_AQUACOMPUTER_D5NEXT is not set
# CONFIG_SENSORS_AS370 is not set
CONFIG_SENSORS_ASC7621=m
# CONFIG_SENSORS_AXI_FAN_CONTROL is not set
CONFIG_SENSORS_K8TEMP=m
CONFIG_SENSORS_APPLESMC=m
CONFIG_SENSORS_ASB100=m
CONFIG_SENSORS_ATXP1=m
# CONFIG_SENSORS_CORSAIR_CPRO is not set
# CONFIG_SENSORS_CORSAIR_PSU is not set
# CONFIG_SENSORS_DRIVETEMP is not set
CONFIG_SENSORS_DS620=m
CONFIG_SENSORS_DS1621=m
# CONFIG_SENSORS_DELL_SMM is not set
CONFIG_SENSORS_I5K_AMB=m
CONFIG_SENSORS_F71805F=m
CONFIG_SENSORS_F71882FG=m
CONFIG_SENSORS_F75375S=m
CONFIG_SENSORS_FSCHMD=m
# CONFIG_SENSORS_FTSTEUTATES is not set
CONFIG_SENSORS_GL518SM=m
CONFIG_SENSORS_GL520SM=m
CONFIG_SENSORS_G760A=m
# CONFIG_SENSORS_G762 is not set
# CONFIG_SENSORS_HIH6130 is not set
CONFIG_SENSORS_IBMAEM=m
CONFIG_SENSORS_IBMPEX=m
CONFIG_SENSORS_I5500=m
CONFIG_SENSORS_CORETEMP=m
CONFIG_SENSORS_IT87=m
CONFIG_SENSORS_JC42=m
# CONFIG_SENSORS_POWR1220 is not set
CONFIG_SENSORS_LINEAGE=m
# CONFIG_SENSORS_LTC2945 is not set
# CONFIG_SENSORS_LTC2947_I2C is not set
# CONFIG_SENSORS_LTC2947_SPI is not set
# CONFIG_SENSORS_LTC2990 is not set
# CONFIG_SENSORS_LTC2992 is not set
CONFIG_SENSORS_LTC4151=m
CONFIG_SENSORS_LTC4215=m
# CONFIG_SENSORS_LTC4222 is not set
CONFIG_SENSORS_LTC4245=m
# CONFIG_SENSORS_LTC4260 is not set
CONFIG_SENSORS_LTC4261=m
# CONFIG_SENSORS_MAX1111 is not set
# CONFIG_SENSORS_MAX127 is not set
CONFIG_SENSORS_MAX16065=m
CONFIG_SENSORS_MAX1619=m
CONFIG_SENSORS_MAX1668=m
CONFIG_SENSORS_MAX197=m
# CONFIG_SENSORS_MAX31722 is not set
# CONFIG_SENSORS_MAX31730 is not set
# CONFIG_SENSORS_MAX31760 is not set
# CONFIG_SENSORS_MAX6620 is not set
# CONFIG_SENSORS_MAX6621 is not set
CONFIG_SENSORS_MAX6639=m
CONFIG_SENSORS_MAX6650=m
CONFIG_SENSORS_MAX6697=m
# CONFIG_SENSORS_MAX31790 is not set
CONFIG_SENSORS_MCP3021=m
# CONFIG_SENSORS_MLXREG_FAN is not set
# CONFIG_SENSORS_TC654 is not set
# CONFIG_SENSORS_TPS23861 is not set
# CONFIG_SENSORS_MR75203 is not set
# CONFIG_SENSORS_ADCXX is not set
CONFIG_SENSORS_LM63=m
# CONFIG_SENSORS_LM70 is not set
CONFIG_SENSORS_LM73=m
CONFIG_SENSORS_LM75=m
CONFIG_SENSORS_LM77=m
CONFIG_SENSORS_LM78=m
CONFIG_SENSORS_LM80=m
CONFIG_SENSORS_LM83=m
CONFIG_SENSORS_LM85=m
CONFIG_SENSORS_LM87=m
CONFIG_SENSORS_LM90=m
CONFIG_SENSORS_LM92=m
CONFIG_SENSORS_LM93=m
CONFIG_SENSORS_LM95234=m
CONFIG_SENSORS_LM95241=m
CONFIG_SENSORS_LM95245=m
CONFIG_SENSORS_PC87360=m
CONFIG_SENSORS_PC87427=m
# CONFIG_SENSORS_NCT6683 is not set
CONFIG_SENSORS_NCT6775_CORE=m
CONFIG_SENSORS_NCT6775=m
# CONFIG_SENSORS_NCT6775_I2C is not set
# CONFIG_SENSORS_NCT7802 is not set
# CONFIG_SENSORS_NCT7904 is not set
# CONFIG_SENSORS_NPCM7XX is not set
# CONFIG_SENSORS_NZXT_KRAKEN2 is not set
# CONFIG_SENSORS_NZXT_SMART2 is not set
CONFIG_SENSORS_PCF8591=m
CONFIG_PMBUS=m
CONFIG_SENSORS_PMBUS=m
# CONFIG_SENSORS_ADM1266 is not set
CONFIG_SENSORS_ADM1275=m
# CONFIG_SENSORS_BEL_PFE is not set
# CONFIG_SENSORS_BPA_RS600 is not set
# CONFIG_SENSORS_DELTA_AHE50DC_FAN is not set
# CONFIG_SENSORS_FSP_3Y is not set
# CONFIG_SENSORS_IBM_CFFPS is not set
# CONFIG_SENSORS_DPS920AB is not set
# CONFIG_SENSORS_INSPUR_IPSPS is not set
# CONFIG_SENSORS_IR35221 is not set
# CONFIG_SENSORS_IR36021 is not set
# CONFIG_SENSORS_IR38064 is not set
# CONFIG_SENSORS_IRPS5401 is not set
# CONFIG_SENSORS_ISL68137 is not set
CONFIG_SENSORS_LM25066=m
# CONFIG_SENSORS_LT7182S is not set
CONFIG_SENSORS_LTC2978=m
# CONFIG_SENSORS_LTC3815 is not set
# CONFIG_SENSORS_MAX15301 is not set
CONFIG_SENSORS_MAX16064=m
# CONFIG_SENSORS_MAX16601 is not set
# CONFIG_SENSORS_MAX20730 is not set
# CONFIG_SENSORS_MAX20751 is not set
# CONFIG_SENSORS_MAX31785 is not set
CONFIG_SENSORS_MAX34440=m
CONFIG_SENSORS_MAX8688=m
# CONFIG_SENSORS_MP2888 is not set
# CONFIG_SENSORS_MP2975 is not set
# CONFIG_SENSORS_MP5023 is not set
# CONFIG_SENSORS_PIM4328 is not set
# CONFIG_SENSORS_PLI1209BC is not set
# CONFIG_SENSORS_PM6764TR is not set
# CONFIG_SENSORS_PXE1610 is not set
# CONFIG_SENSORS_Q54SJ108A2 is not set
# CONFIG_SENSORS_STPDDC60 is not set
# CONFIG_SENSORS_TPS40422 is not set
# CONFIG_SENSORS_TPS53679 is not set
# CONFIG_SENSORS_TPS546D24 is not set
CONFIG_SENSORS_UCD9000=m
CONFIG_SENSORS_UCD9200=m
# CONFIG_SENSORS_XDPE152 is not set
# CONFIG_SENSORS_XDPE122 is not set
CONFIG_SENSORS_ZL6100=m
# CONFIG_SENSORS_SBTSI is not set
# CONFIG_SENSORS_SBRMI is not set
CONFIG_SENSORS_SHT15=m
CONFIG_SENSORS_SHT21=m
# CONFIG_SENSORS_SHT3x is not set
# CONFIG_SENSORS_SHT4x is not set
# CONFIG_SENSORS_SHTC1 is not set
CONFIG_SENSORS_SIS5595=m
CONFIG_SENSORS_DME1737=m
CONFIG_SENSORS_EMC1403=m
# CONFIG_SENSORS_EMC2103 is not set
# CONFIG_SENSORS_EMC2305 is not set
CONFIG_SENSORS_EMC6W201=m
CONFIG_SENSORS_SMSC47M1=m
CONFIG_SENSORS_SMSC47M192=m
CONFIG_SENSORS_SMSC47B397=m
CONFIG_SENSORS_SCH56XX_COMMON=m
CONFIG_SENSORS_SCH5627=m
CONFIG_SENSORS_SCH5636=m
# CONFIG_SENSORS_STTS751 is not set
# CONFIG_SENSORS_SMM665 is not set
# CONFIG_SENSORS_ADC128D818 is not set
CONFIG_SENSORS_ADS7828=m
# CONFIG_SENSORS_ADS7871 is not set
CONFIG_SENSORS_AMC6821=m
CONFIG_SENSORS_INA209=m
CONFIG_SENSORS_INA2XX=m
# CONFIG_SENSORS_INA238 is not set
# CONFIG_SENSORS_INA3221 is not set
# CONFIG_SENSORS_TC74 is not set
CONFIG_SENSORS_THMC50=m
CONFIG_SENSORS_TMP102=m
# CONFIG_SENSORS_TMP103 is not set
# CONFIG_SENSORS_TMP108 is not set
CONFIG_SENSORS_TMP401=m
CONFIG_SENSORS_TMP421=m
# CONFIG_SENSORS_TMP464 is not set
# CONFIG_SENSORS_TMP513 is not set
CONFIG_SENSORS_VIA_CPUTEMP=m
CONFIG_SENSORS_VIA686A=m
CONFIG_SENSORS_VT1211=m
CONFIG_SENSORS_VT8231=m
# CONFIG_SENSORS_W83773G is not set
CONFIG_SENSORS_W83781D=m
CONFIG_SENSORS_W83791D=m
CONFIG_SENSORS_W83792D=m
CONFIG_SENSORS_W83793=m
CONFIG_SENSORS_W83795=m
# CONFIG_SENSORS_W83795_FANCTRL is not set
CONFIG_SENSORS_W83L785TS=m
CONFIG_SENSORS_W83L786NG=m
CONFIG_SENSORS_W83627HF=m
CONFIG_SENSORS_W83627EHF=m
# CONFIG_SENSORS_XGENE is not set

#
# ACPI drivers
#
CONFIG_SENSORS_ACPI_POWER=m
CONFIG_SENSORS_ATK0110=m
# CONFIG_SENSORS_ASUS_WMI is not set
# CONFIG_SENSORS_ASUS_EC is not set
CONFIG_THERMAL=y
# CONFIG_THERMAL_NETLINK is not set
# CONFIG_THERMAL_STATISTICS is not set
CONFIG_THERMAL_EMERGENCY_POWEROFF_DELAY_MS=0
CONFIG_THERMAL_HWMON=y
CONFIG_THERMAL_WRITABLE_TRIPS=y
CONFIG_THERMAL_DEFAULT_GOV_STEP_WISE=y
# CONFIG_THERMAL_DEFAULT_GOV_FAIR_SHARE is not set
# CONFIG_THERMAL_DEFAULT_GOV_USER_SPACE is not set
CONFIG_THERMAL_GOV_FAIR_SHARE=y
CONFIG_THERMAL_GOV_STEP_WISE=y
CONFIG_THERMAL_GOV_BANG_BANG=y
CONFIG_THERMAL_GOV_USER_SPACE=y
# CONFIG_THERMAL_EMULATION is not set

#
# Intel thermal drivers
#
CONFIG_INTEL_POWERCLAMP=m
CONFIG_X86_THERMAL_VECTOR=y
CONFIG_X86_PKG_TEMP_THERMAL=m
# CONFIG_INTEL_SOC_DTS_THERMAL is not set

#
# ACPI INT340X thermal drivers
#
# CONFIG_INT340X_THERMAL is not set
# end of ACPI INT340X thermal drivers

CONFIG_INTEL_PCH_THERMAL=m
# CONFIG_INTEL_TCC_COOLING is not set
# CONFIG_INTEL_MENLOW is not set
# CONFIG_INTEL_HFI_THERMAL is not set
# end of Intel thermal drivers

CONFIG_WATCHDOG=y
CONFIG_WATCHDOG_CORE=y
# CONFIG_WATCHDOG_NOWAYOUT is not set
CONFIG_WATCHDOG_HANDLE_BOOT_ENABLED=y
CONFIG_WATCHDOG_OPEN_TIMEOUT=0
CONFIG_WATCHDOG_SYSFS=y
# CONFIG_WATCHDOG_HRTIMER_PRETIMEOUT is not set

#
# Watchdog Pretimeout Governors
#
# CONFIG_WATCHDOG_PRETIMEOUT_GOV is not set

#
# Watchdog Device Drivers
#
CONFIG_SOFT_WATCHDOG=m
CONFIG_WDAT_WDT=m
# CONFIG_XILINX_WATCHDOG is not set
# CONFIG_ZIIRAVE_WATCHDOG is not set
# CONFIG_MLX_WDT is not set
# CONFIG_CADENCE_WATCHDOG is not set
# CONFIG_DW_WATCHDOG is not set
# CONFIG_MAX63XX_WATCHDOG is not set
# CONFIG_ACQUIRE_WDT is not set
# CONFIG_ADVANTECH_WDT is not set
CONFIG_ALIM1535_WDT=m
CONFIG_ALIM7101_WDT=m
# CONFIG_EBC_C384_WDT is not set
# CONFIG_EXAR_WDT is not set
CONFIG_F71808E_WDT=m
# CONFIG_SP5100_TCO is not set
CONFIG_SBC_FITPC2_WATCHDOG=m
# CONFIG_EUROTECH_WDT is not set
CONFIG_IB700_WDT=m
CONFIG_IBMASR=m
# CONFIG_WAFER_WDT is not set
CONFIG_I6300ESB_WDT=y
CONFIG_IE6XX_WDT=m
CONFIG_ITCO_WDT=y
CONFIG_ITCO_VENDOR_SUPPORT=y
CONFIG_IT8712F_WDT=m
CONFIG_IT87_WDT=m
CONFIG_HP_WATCHDOG=m
CONFIG_HPWDT_NMI_DECODING=y
# CONFIG_SC1200_WDT is not set
# CONFIG_PC87413_WDT is not set
CONFIG_NV_TCO=m
# CONFIG_60XX_WDT is not set
# CONFIG_CPU5_WDT is not set
CONFIG_SMSC_SCH311X_WDT=m
# CONFIG_SMSC37B787_WDT is not set
# CONFIG_TQMX86_WDT is not set
CONFIG_VIA_WDT=m
CONFIG_W83627HF_WDT=m
CONFIG_W83877F_WDT=m
CONFIG_W83977F_WDT=m
CONFIG_MACHZ_WDT=m
# CONFIG_SBC_EPX_C3_WATCHDOG is not set
CONFIG_INTEL_MEI_WDT=m
# CONFIG_NI903X_WDT is not set
# CONFIG_NIC7018_WDT is not set
# CONFIG_MEN_A21_WDT is not set

#
# PCI-based Watchdog Cards
#
CONFIG_PCIPCWATCHDOG=m
CONFIG_WDTPCI=m

#
# USB-based Watchdog Cards
#
# CONFIG_USBPCWATCHDOG is not set
CONFIG_SSB_POSSIBLE=y
# CONFIG_SSB is not set
CONFIG_BCMA_POSSIBLE=y
CONFIG_BCMA=m
CONFIG_BCMA_HOST_PCI_POSSIBLE=y
CONFIG_BCMA_HOST_PCI=y
# CONFIG_BCMA_HOST_SOC is not set
CONFIG_BCMA_DRIVER_PCI=y
CONFIG_BCMA_DRIVER_GMAC_CMN=y
CONFIG_BCMA_DRIVER_GPIO=y
# CONFIG_BCMA_DEBUG is not set

#
# Multifunction device drivers
#
CONFIG_MFD_CORE=y
# CONFIG_MFD_AS3711 is not set
# CONFIG_PMIC_ADP5520 is not set
# CONFIG_MFD_AAT2870_CORE is not set
# CONFIG_MFD_BCM590XX is not set
# CONFIG_MFD_BD9571MWV is not set
# CONFIG_MFD_AXP20X_I2C is not set
# CONFIG_MFD_MADERA is not set
# CONFIG_PMIC_DA903X is not set
# CONFIG_MFD_DA9052_SPI is not set
# CONFIG_MFD_DA9052_I2C is not set
# CONFIG_MFD_DA9055 is not set
# CONFIG_MFD_DA9062 is not set
# CONFIG_MFD_DA9063 is not set
# CONFIG_MFD_DA9150 is not set
# CONFIG_MFD_DLN2 is not set
# CONFIG_MFD_MC13XXX_SPI is not set
# CONFIG_MFD_MC13XXX_I2C is not set
# CONFIG_MFD_MP2629 is not set
# CONFIG_HTC_PASIC3 is not set
# CONFIG_HTC_I2CPLD is not set
# CONFIG_MFD_INTEL_QUARK_I2C_GPIO is not set
CONFIG_LPC_ICH=m
CONFIG_LPC_SCH=m
CONFIG_MFD_INTEL_LPSS=y
CONFIG_MFD_INTEL_LPSS_ACPI=y
CONFIG_MFD_INTEL_LPSS_PCI=y
# CONFIG_MFD_INTEL_PMC_BXT is not set
# CONFIG_MFD_IQS62X is not set
# CONFIG_MFD_JANZ_CMODIO is not set
# CONFIG_MFD_KEMPLD is not set
# CONFIG_MFD_88PM800 is not set
# CONFIG_MFD_88PM805 is not set
# CONFIG_MFD_88PM860X is not set
# CONFIG_MFD_MAX14577 is not set
# CONFIG_MFD_MAX77693 is not set
# CONFIG_MFD_MAX77843 is not set
# CONFIG_MFD_MAX8907 is not set
# CONFIG_MFD_MAX8925 is not set
# CONFIG_MFD_MAX8997 is not set
# CONFIG_MFD_MAX8998 is not set
# CONFIG_MFD_MT6360 is not set
# CONFIG_MFD_MT6370 is not set
# CONFIG_MFD_MT6397 is not set
# CONFIG_MFD_MENF21BMC is not set
# CONFIG_MFD_OCELOT is not set
# CONFIG_EZX_PCAP is not set
# CONFIG_MFD_VIPERBOARD is not set
# CONFIG_MFD_RETU is not set
# CONFIG_MFD_PCF50633 is not set
# CONFIG_MFD_SY7636A is not set
# CONFIG_MFD_RDC321X is not set
# CONFIG_MFD_RT4831 is not set
# CONFIG_MFD_RT5033 is not set
# CONFIG_MFD_RT5120 is not set
# CONFIG_MFD_RC5T583 is not set
# CONFIG_MFD_SI476X_CORE is not set
CONFIG_MFD_SM501=m
CONFIG_MFD_SM501_GPIO=y
# CONFIG_MFD_SKY81452 is not set
# CONFIG_MFD_SYSCON is not set
# CONFIG_MFD_TI_AM335X_TSCADC is not set
# CONFIG_MFD_LP3943 is not set
# CONFIG_MFD_LP8788 is not set
# CONFIG_MFD_TI_LMU is not set
# CONFIG_MFD_PALMAS is not set
# CONFIG_TPS6105X is not set
# CONFIG_TPS65010 is not set
# CONFIG_TPS6507X is not set
# CONFIG_MFD_TPS65086 is not set
# CONFIG_MFD_TPS65090 is not set
# CONFIG_MFD_TI_LP873X is not set
# CONFIG_MFD_TPS6586X is not set
# CONFIG_MFD_TPS65910 is not set
# CONFIG_MFD_TPS65912_I2C is not set
# CONFIG_MFD_TPS65912_SPI is not set
# CONFIG_TWL4030_CORE is not set
# CONFIG_TWL6040_CORE is not set
# CONFIG_MFD_WL1273_CORE is not set
# CONFIG_MFD_LM3533 is not set
# CONFIG_MFD_TQMX86 is not set
CONFIG_MFD_VX855=m
# CONFIG_MFD_ARIZONA_I2C is not set
# CONFIG_MFD_ARIZONA_SPI is not set
# CONFIG_MFD_WM8400 is not set
# CONFIG_MFD_WM831X_I2C is not set
# CONFIG_MFD_WM831X_SPI is not set
# CONFIG_MFD_WM8350_I2C is not set
# CONFIG_MFD_WM8994 is not set
# CONFIG_MFD_ATC260X_I2C is not set
# CONFIG_MFD_INTEL_M10_BMC is not set
# end of Multifunction device drivers

# CONFIG_REGULATOR is not set
CONFIG_RC_CORE=m
CONFIG_LIRC=y
CONFIG_RC_MAP=m
CONFIG_RC_DECODERS=y
CONFIG_IR_IMON_DECODER=m
CONFIG_IR_JVC_DECODER=m
CONFIG_IR_MCE_KBD_DECODER=m
CONFIG_IR_NEC_DECODER=m
CONFIG_IR_RC5_DECODER=m
CONFIG_IR_RC6_DECODER=m
# CONFIG_IR_RCMM_DECODER is not set
CONFIG_IR_SANYO_DECODER=m
# CONFIG_IR_SHARP_DECODER is not set
CONFIG_IR_SONY_DECODER=m
# CONFIG_IR_XMP_DECODER is not set
CONFIG_RC_DEVICES=y
CONFIG_IR_ENE=m
CONFIG_IR_FINTEK=m
# CONFIG_IR_IGORPLUGUSB is not set
# CONFIG_IR_IGUANA is not set
# CONFIG_IR_IMON is not set
# CONFIG_IR_IMON_RAW is not set
CONFIG_IR_ITE_CIR=m
# CONFIG_IR_MCEUSB is not set
CONFIG_IR_NUVOTON=m
# CONFIG_IR_REDRAT3 is not set
CONFIG_IR_SERIAL=m
CONFIG_IR_SERIAL_TRANSMITTER=y
# CONFIG_IR_STREAMZAP is not set
# CONFIG_IR_TOY is not set
# CONFIG_IR_TTUSBIR is not set
CONFIG_IR_WINBOND_CIR=m
# CONFIG_RC_ATI_REMOTE is not set
# CONFIG_RC_LOOPBACK is not set
# CONFIG_RC_XBOX_DVD is not set

#
# CEC support
#
# CONFIG_MEDIA_CEC_SUPPORT is not set
# end of CEC support

CONFIG_MEDIA_SUPPORT=m
CONFIG_MEDIA_SUPPORT_FILTER=y
CONFIG_MEDIA_SUBDRV_AUTOSELECT=y

#
# Media device types
#
# CONFIG_MEDIA_CAMERA_SUPPORT is not set
# CONFIG_MEDIA_ANALOG_TV_SUPPORT is not set
# CONFIG_MEDIA_DIGITAL_TV_SUPPORT is not set
# CONFIG_MEDIA_RADIO_SUPPORT is not set
# CONFIG_MEDIA_SDR_SUPPORT is not set
# CONFIG_MEDIA_PLATFORM_SUPPORT is not set
# CONFIG_MEDIA_TEST_SUPPORT is not set
# end of Media device types

#
# Media drivers
#

#
# Drivers filtered as selected at 'Filter media drivers'
#

#
# Media drivers
#
# CONFIG_MEDIA_USB_SUPPORT is not set
# CONFIG_MEDIA_PCI_SUPPORT is not set
# end of Media drivers

#
# Media ancillary drivers
#
# end of Media ancillary drivers

#
# Graphics support
#
CONFIG_APERTURE_HELPERS=y
# CONFIG_AGP is not set
CONFIG_INTEL_GTT=m
CONFIG_VGA_SWITCHEROO=y
CONFIG_DRM=m
CONFIG_DRM_MIPI_DSI=y
CONFIG_DRM_USE_DYNAMIC_DEBUG=y
CONFIG_DRM_KMS_HELPER=m
# CONFIG_DRM_DEBUG_DP_MST_TOPOLOGY_REFS is not set
# CONFIG_DRM_DEBUG_MODESET_LOCK is not set
CONFIG_DRM_FBDEV_EMULATION=y
CONFIG_DRM_FBDEV_OVERALLOC=100
# CONFIG_DRM_FBDEV_LEAK_PHYS_SMEM is not set
CONFIG_DRM_LOAD_EDID_FIRMWARE=y
CONFIG_DRM_DISPLAY_HELPER=m
CONFIG_DRM_DISPLAY_DP_HELPER=y
CONFIG_DRM_DISPLAY_HDCP_HELPER=y
CONFIG_DRM_DISPLAY_HDMI_HELPER=y
CONFIG_DRM_DP_AUX_CHARDEV=y
# CONFIG_DRM_DP_CEC is not set
CONFIG_DRM_TTM=m
CONFIG_DRM_BUDDY=m
CONFIG_DRM_VRAM_HELPER=m
CONFIG_DRM_TTM_HELPER=m
CONFIG_DRM_GEM_SHMEM_HELPER=m

#
# I2C encoder or helper chips
#
CONFIG_DRM_I2C_CH7006=m
CONFIG_DRM_I2C_SIL164=m
# CONFIG_DRM_I2C_NXP_TDA998X is not set
# CONFIG_DRM_I2C_NXP_TDA9950 is not set
# end of I2C encoder or helper chips

#
# ARM devices
#
# end of ARM devices

# CONFIG_DRM_RADEON is not set
# CONFIG_DRM_AMDGPU is not set
# CONFIG_DRM_NOUVEAU is not set
CONFIG_DRM_I915=m
CONFIG_DRM_I915_FORCE_PROBE=""
CONFIG_DRM_I915_CAPTURE_ERROR=y
CONFIG_DRM_I915_COMPRESS_ERROR=y
CONFIG_DRM_I915_USERPTR=y
# CONFIG_DRM_I915_GVT_KVMGT is not set

#
# drm/i915 Debugging
#
# CONFIG_DRM_I915_WERROR is not set
# CONFIG_DRM_I915_DEBUG is not set
# CONFIG_DRM_I915_DEBUG_MMIO is not set
# CONFIG_DRM_I915_SW_FENCE_DEBUG_OBJECTS is not set
# CONFIG_DRM_I915_SW_FENCE_CHECK_DAG is not set
# CONFIG_DRM_I915_DEBUG_GUC is not set
# CONFIG_DRM_I915_SELFTEST is not set
# CONFIG_DRM_I915_LOW_LEVEL_TRACEPOINTS is not set
# CONFIG_DRM_I915_DEBUG_VBLANK_EVADE is not set
# CONFIG_DRM_I915_DEBUG_RUNTIME_PM is not set
# end of drm/i915 Debugging

#
# drm/i915 Profile Guided Optimisation
#
CONFIG_DRM_I915_REQUEST_TIMEOUT=20000
CONFIG_DRM_I915_FENCE_TIMEOUT=10000
CONFIG_DRM_I915_USERFAULT_AUTOSUSPEND=250
CONFIG_DRM_I915_HEARTBEAT_INTERVAL=2500
CONFIG_DRM_I915_PREEMPT_TIMEOUT=640
CONFIG_DRM_I915_MAX_REQUEST_BUSYWAIT=8000
CONFIG_DRM_I915_STOP_TIMEOUT=100
CONFIG_DRM_I915_TIMESLICE_DURATION=1
# end of drm/i915 Profile Guided Optimisation

# CONFIG_DRM_VGEM is not set
# CONFIG_DRM_VKMS is not set
# CONFIG_DRM_VMWGFX is not set
CONFIG_DRM_GMA500=m
# CONFIG_DRM_UDL is not set
CONFIG_DRM_AST=m
# CONFIG_DRM_MGAG200 is not set
CONFIG_DRM_QXL=m
CONFIG_DRM_VIRTIO_GPU=m
CONFIG_DRM_PANEL=y

#
# Display Panels
#
# CONFIG_DRM_PANEL_RASPBERRYPI_TOUCHSCREEN is not set
# CONFIG_DRM_PANEL_WIDECHIPS_WS2401 is not set
# end of Display Panels

CONFIG_DRM_BRIDGE=y
CONFIG_DRM_PANEL_BRIDGE=y

#
# Display Interface Bridges
#
# CONFIG_DRM_ANALOGIX_ANX78XX is not set
# end of Display Interface Bridges

# CONFIG_DRM_ETNAVIV is not set
CONFIG_DRM_BOCHS=m
CONFIG_DRM_CIRRUS_QEMU=m
# CONFIG_DRM_GM12U320 is not set
# CONFIG_DRM_PANEL_MIPI_DBI is not set
# CONFIG_DRM_SIMPLEDRM is not set
# CONFIG_TINYDRM_HX8357D is not set
# CONFIG_TINYDRM_ILI9163 is not set
# CONFIG_TINYDRM_ILI9225 is not set
# CONFIG_TINYDRM_ILI9341 is not set
# CONFIG_TINYDRM_ILI9486 is not set
# CONFIG_TINYDRM_MI0283QT is not set
# CONFIG_TINYDRM_REPAPER is not set
# CONFIG_TINYDRM_ST7586 is not set
# CONFIG_TINYDRM_ST7735R is not set
# CONFIG_DRM_VBOXVIDEO is not set
# CONFIG_DRM_GUD is not set
# CONFIG_DRM_SSD130X is not set
# CONFIG_DRM_LEGACY is not set
CONFIG_DRM_PANEL_ORIENTATION_QUIRKS=y
CONFIG_DRM_NOMODESET=y
CONFIG_DRM_PRIVACY_SCREEN=y

#
# Frame buffer Devices
#
CONFIG_FB_CMDLINE=y
CONFIG_FB_NOTIFY=y
CONFIG_FB=y
# CONFIG_FIRMWARE_EDID is not set
CONFIG_FB_CFB_FILLRECT=y
CONFIG_FB_CFB_COPYAREA=y
CONFIG_FB_CFB_IMAGEBLIT=y
CONFIG_FB_SYS_FILLRECT=m
CONFIG_FB_SYS_COPYAREA=m
CONFIG_FB_SYS_IMAGEBLIT=m
# CONFIG_FB_FOREIGN_ENDIAN is not set
CONFIG_FB_SYS_FOPS=m
CONFIG_FB_DEFERRED_IO=y
# CONFIG_FB_MODE_HELPERS is not set
CONFIG_FB_TILEBLITTING=y

#
# Frame buffer hardware drivers
#
# CONFIG_FB_CIRRUS is not set
# CONFIG_FB_PM2 is not set
# CONFIG_FB_CYBER2000 is not set
# CONFIG_FB_ARC is not set
# CONFIG_FB_ASILIANT is not set
# CONFIG_FB_IMSTT is not set
# CONFIG_FB_VGA16 is not set
# CONFIG_FB_UVESA is not set
CONFIG_FB_VESA=y
CONFIG_FB_EFI=y
# CONFIG_FB_N411 is not set
# CONFIG_FB_HGA is not set
# CONFIG_FB_OPENCORES is not set
# CONFIG_FB_S1D13XXX is not set
# CONFIG_FB_NVIDIA is not set
# CONFIG_FB_RIVA is not set
# CONFIG_FB_I740 is not set
# CONFIG_FB_LE80578 is not set
# CONFIG_FB_MATROX is not set
# CONFIG_FB_RADEON is not set
# CONFIG_FB_ATY128 is not set
# CONFIG_FB_ATY is not set
# CONFIG_FB_S3 is not set
# CONFIG_FB_SAVAGE is not set
# CONFIG_FB_SIS is not set
# CONFIG_FB_VIA is not set
# CONFIG_FB_NEOMAGIC is not set
# CONFIG_FB_KYRO is not set
# CONFIG_FB_3DFX is not set
# CONFIG_FB_VOODOO1 is not set
# CONFIG_FB_VT8623 is not set
# CONFIG_FB_TRIDENT is not set
# CONFIG_FB_ARK is not set
# CONFIG_FB_PM3 is not set
# CONFIG_FB_CARMINE is not set
# CONFIG_FB_SM501 is not set
# CONFIG_FB_SMSCUFX is not set
# CONFIG_FB_UDL is not set
# CONFIG_FB_IBM_GXT4500 is not set
# CONFIG_FB_VIRTUAL is not set
# CONFIG_FB_METRONOME is not set
# CONFIG_FB_MB862XX is not set
# CONFIG_FB_SIMPLE is not set
# CONFIG_FB_SSD1307 is not set
# CONFIG_FB_SM712 is not set
# end of Frame buffer Devices

#
# Backlight & LCD device support
#
CONFIG_LCD_CLASS_DEVICE=m
# CONFIG_LCD_L4F00242T03 is not set
# CONFIG_LCD_LMS283GF05 is not set
# CONFIG_LCD_LTV350QV is not set
# CONFIG_LCD_ILI922X is not set
# CONFIG_LCD_ILI9320 is not set
# CONFIG_LCD_TDO24M is not set
# CONFIG_LCD_VGG2432A4 is not set
CONFIG_LCD_PLATFORM=m
# CONFIG_LCD_AMS369FG06 is not set
# CONFIG_LCD_LMS501KF03 is not set
# CONFIG_LCD_HX8357 is not set
# CONFIG_LCD_OTM3225A is not set
CONFIG_BACKLIGHT_CLASS_DEVICE=y
# CONFIG_BACKLIGHT_KTD253 is not set
# CONFIG_BACKLIGHT_PWM is not set
CONFIG_BACKLIGHT_APPLE=m
# CONFIG_BACKLIGHT_QCOM_WLED is not set
# CONFIG_BACKLIGHT_SAHARA is not set
# CONFIG_BACKLIGHT_ADP8860 is not set
# CONFIG_BACKLIGHT_ADP8870 is not set
# CONFIG_BACKLIGHT_LM3630A is not set
# CONFIG_BACKLIGHT_LM3639 is not set
CONFIG_BACKLIGHT_LP855X=m
# CONFIG_BACKLIGHT_GPIO is not set
# CONFIG_BACKLIGHT_LV5207LP is not set
# CONFIG_BACKLIGHT_BD6107 is not set
# CONFIG_BACKLIGHT_ARCXCNN is not set
# end of Backlight & LCD device support

CONFIG_HDMI=y

#
# Console display driver support
#
CONFIG_VGA_CONSOLE=y
CONFIG_DUMMY_CONSOLE=y
CONFIG_DUMMY_CONSOLE_COLUMNS=80
CONFIG_DUMMY_CONSOLE_ROWS=25
CONFIG_FRAMEBUFFER_CONSOLE=y
# CONFIG_FRAMEBUFFER_CONSOLE_LEGACY_ACCELERATION is not set
CONFIG_FRAMEBUFFER_CONSOLE_DETECT_PRIMARY=y
CONFIG_FRAMEBUFFER_CONSOLE_ROTATION=y
# CONFIG_FRAMEBUFFER_CONSOLE_DEFERRED_TAKEOVER is not set
# end of Console display driver support

CONFIG_LOGO=y
# CONFIG_LOGO_LINUX_MONO is not set
# CONFIG_LOGO_LINUX_VGA16 is not set
CONFIG_LOGO_LINUX_CLUT224=y
# end of Graphics support

# CONFIG_SOUND is not set

#
# HID support
#
CONFIG_HID=y
CONFIG_HID_BATTERY_STRENGTH=y
CONFIG_HIDRAW=y
CONFIG_UHID=m
CONFIG_HID_GENERIC=y

#
# Special HID drivers
#
CONFIG_HID_A4TECH=m
# CONFIG_HID_ACCUTOUCH is not set
CONFIG_HID_ACRUX=m
# CONFIG_HID_ACRUX_FF is not set
CONFIG_HID_APPLE=m
# CONFIG_HID_APPLEIR is not set
CONFIG_HID_ASUS=m
CONFIG_HID_AUREAL=m
CONFIG_HID_BELKIN=m
# CONFIG_HID_BETOP_FF is not set
# CONFIG_HID_BIGBEN_FF is not set
CONFIG_HID_CHERRY=m
# CONFIG_HID_CHICONY is not set
# CONFIG_HID_CORSAIR is not set
# CONFIG_HID_COUGAR is not set
# CONFIG_HID_MACALLY is not set
CONFIG_HID_CMEDIA=m
# CONFIG_HID_CP2112 is not set
# CONFIG_HID_CREATIVE_SB0540 is not set
CONFIG_HID_CYPRESS=m
CONFIG_HID_DRAGONRISE=m
# CONFIG_DRAGONRISE_FF is not set
# CONFIG_HID_EMS_FF is not set
# CONFIG_HID_ELAN is not set
CONFIG_HID_ELECOM=m
# CONFIG_HID_ELO is not set
CONFIG_HID_EZKEY=m
# CONFIG_HID_FT260 is not set
CONFIG_HID_GEMBIRD=m
CONFIG_HID_GFRM=m
# CONFIG_HID_GLORIOUS is not set
# CONFIG_HID_HOLTEK is not set
# CONFIG_HID_VIVALDI is not set
# CONFIG_HID_GT683R is not set
CONFIG_HID_KEYTOUCH=m
CONFIG_HID_KYE=m
# CONFIG_HID_UCLOGIC is not set
CONFIG_HID_WALTOP=m
# CONFIG_HID_VIEWSONIC is not set
# CONFIG_HID_VRC2 is not set
# CONFIG_HID_XIAOMI is not set
CONFIG_HID_GYRATION=m
CONFIG_HID_ICADE=m
CONFIG_HID_ITE=m
CONFIG_HID_JABRA=m
CONFIG_HID_TWINHAN=m
CONFIG_HID_KENSINGTON=m
CONFIG_HID_LCPOWER=m
CONFIG_HID_LED=m
CONFIG_HID_LENOVO=m
# CONFIG_HID_LETSKETCH is not set
CONFIG_HID_LOGITECH=m
CONFIG_HID_LOGITECH_DJ=m
CONFIG_HID_LOGITECH_HIDPP=m
# CONFIG_LOGITECH_FF is not set
# CONFIG_LOGIRUMBLEPAD2_FF is not set
# CONFIG_LOGIG940_FF is not set
# CONFIG_LOGIWHEELS_FF is not set
CONFIG_HID_MAGICMOUSE=y
# CONFIG_HID_MALTRON is not set
# CONFIG_HID_MAYFLASH is not set
# CONFIG_HID_MEGAWORLD_FF is not set
# CONFIG_HID_REDRAGON is not set
CONFIG_HID_MICROSOFT=m
CONFIG_HID_MONTEREY=m
CONFIG_HID_MULTITOUCH=m
# CONFIG_HID_NINTENDO is not set
CONFIG_HID_NTI=m
# CONFIG_HID_NTRIG is not set
CONFIG_HID_ORTEK=m
CONFIG_HID_PANTHERLORD=m
# CONFIG_PANTHERLORD_FF is not set
# CONFIG_HID_PENMOUNT is not set
CONFIG_HID_PETALYNX=m
CONFIG_HID_PICOLCD=m
CONFIG_HID_PICOLCD_FB=y
CONFIG_HID_PICOLCD_BACKLIGHT=y
CONFIG_HID_PICOLCD_LCD=y
CONFIG_HID_PICOLCD_LEDS=y
CONFIG_HID_PICOLCD_CIR=y
CONFIG_HID_PLANTRONICS=m
# CONFIG_HID_PXRC is not set
# CONFIG_HID_RAZER is not set
CONFIG_HID_PRIMAX=m
# CONFIG_HID_RETRODE is not set
# CONFIG_HID_ROCCAT is not set
CONFIG_HID_SAITEK=m
CONFIG_HID_SAMSUNG=m
# CONFIG_HID_SEMITEK is not set
# CONFIG_HID_SIGMAMICRO is not set
# CONFIG_HID_SONY is not set
CONFIG_HID_SPEEDLINK=m
# CONFIG_HID_STEAM is not set
CONFIG_HID_STEELSERIES=m
CONFIG_HID_SUNPLUS=m
CONFIG_HID_RMI=m
CONFIG_HID_GREENASIA=m
# CONFIG_GREENASIA_FF is not set
CONFIG_HID_SMARTJOYPLUS=m
# CONFIG_SMARTJOYPLUS_FF is not set
CONFIG_HID_TIVO=m
CONFIG_HID_TOPSEED=m
# CONFIG_HID_TOPRE is not set
CONFIG_HID_THINGM=m
CONFIG_HID_THRUSTMASTER=m
# CONFIG_THRUSTMASTER_FF is not set
# CONFIG_HID_UDRAW_PS3 is not set
# CONFIG_HID_U2FZERO is not set
# CONFIG_HID_WACOM is not set
CONFIG_HID_WIIMOTE=m
CONFIG_HID_XINMO=m
CONFIG_HID_ZEROPLUS=m
# CONFIG_ZEROPLUS_FF is not set
CONFIG_HID_ZYDACRON=m
CONFIG_HID_SENSOR_HUB=y
CONFIG_HID_SENSOR_CUSTOM_SENSOR=m
CONFIG_HID_ALPS=m
# CONFIG_HID_MCP2221 is not set
# end of Special HID drivers

#
# USB HID support
#
CONFIG_USB_HID=y
# CONFIG_HID_PID is not set
# CONFIG_USB_HIDDEV is not set
# end of USB HID support

#
# I2C HID support
#
# CONFIG_I2C_HID_ACPI is not set
# end of I2C HID support

#
# Intel ISH HID support
#
CONFIG_INTEL_ISH_HID=m
# CONFIG_INTEL_ISH_FIRMWARE_DOWNLOADER is not set
# end of Intel ISH HID support

#
# AMD SFH HID Support
#
# CONFIG_AMD_SFH_HID is not set
# end of AMD SFH HID Support
# end of HID support

CONFIG_USB_OHCI_LITTLE_ENDIAN=y
CONFIG_USB_SUPPORT=y
CONFIG_USB_COMMON=y
# CONFIG_USB_LED_TRIG is not set
# CONFIG_USB_ULPI_BUS is not set
# CONFIG_USB_CONN_GPIO is not set
CONFIG_USB_ARCH_HAS_HCD=y
CONFIG_USB=y
CONFIG_USB_PCI=y
CONFIG_USB_ANNOUNCE_NEW_DEVICES=y

#
# Miscellaneous USB options
#
CONFIG_USB_DEFAULT_PERSIST=y
# CONFIG_USB_FEW_INIT_RETRIES is not set
# CONFIG_USB_DYNAMIC_MINORS is not set
# CONFIG_USB_OTG is not set
# CONFIG_USB_OTG_PRODUCTLIST is not set
# CONFIG_USB_OTG_DISABLE_EXTERNAL_HUB is not set
CONFIG_USB_LEDS_TRIGGER_USBPORT=y
CONFIG_USB_AUTOSUSPEND_DELAY=2
CONFIG_USB_MON=y

#
# USB Host Controller Drivers
#
# CONFIG_USB_C67X00_HCD is not set
CONFIG_USB_XHCI_HCD=y
# CONFIG_USB_XHCI_DBGCAP is not set
CONFIG_USB_XHCI_PCI=y
# CONFIG_USB_XHCI_PCI_RENESAS is not set
# CONFIG_USB_XHCI_PLATFORM is not set
CONFIG_USB_EHCI_HCD=y
CONFIG_USB_EHCI_ROOT_HUB_TT=y
CONFIG_USB_EHCI_TT_NEWSCHED=y
CONFIG_USB_EHCI_PCI=y
# CONFIG_USB_EHCI_FSL is not set
# CONFIG_USB_EHCI_HCD_PLATFORM is not set
# CONFIG_USB_OXU210HP_HCD is not set
# CONFIG_USB_ISP116X_HCD is not set
# CONFIG_USB_FOTG210_HCD is not set
# CONFIG_USB_MAX3421_HCD is not set
CONFIG_USB_OHCI_HCD=y
CONFIG_USB_OHCI_HCD_PCI=y
# CONFIG_USB_OHCI_HCD_PLATFORM is not set
CONFIG_USB_UHCI_HCD=y
# CONFIG_USB_SL811_HCD is not set
# CONFIG_USB_R8A66597_HCD is not set
# CONFIG_USB_HCD_BCMA is not set
# CONFIG_USB_HCD_TEST_MODE is not set

#
# USB Device Class drivers
#
# CONFIG_USB_ACM is not set
# CONFIG_USB_PRINTER is not set
# CONFIG_USB_WDM is not set
# CONFIG_USB_TMC is not set

#
# NOTE: USB_STORAGE depends on SCSI but BLK_DEV_SD may
#

#
# also be needed; see USB_STORAGE Help for more info
#
CONFIG_USB_STORAGE=m
# CONFIG_USB_STORAGE_DEBUG is not set
# CONFIG_USB_STORAGE_REALTEK is not set
# CONFIG_USB_STORAGE_DATAFAB is not set
# CONFIG_USB_STORAGE_FREECOM is not set
# CONFIG_USB_STORAGE_ISD200 is not set
# CONFIG_USB_STORAGE_USBAT is not set
# CONFIG_USB_STORAGE_SDDR09 is not set
# CONFIG_USB_STORAGE_SDDR55 is not set
# CONFIG_USB_STORAGE_JUMPSHOT is not set
# CONFIG_USB_STORAGE_ALAUDA is not set
# CONFIG_USB_STORAGE_ONETOUCH is not set
# CONFIG_USB_STORAGE_KARMA is not set
# CONFIG_USB_STORAGE_CYPRESS_ATACB is not set
# CONFIG_USB_STORAGE_ENE_UB6250 is not set
# CONFIG_USB_UAS is not set

#
# USB Imaging devices
#
# CONFIG_USB_MDC800 is not set
# CONFIG_USB_MICROTEK is not set
# CONFIG_USBIP_CORE is not set
# CONFIG_USB_CDNS_SUPPORT is not set
# CONFIG_USB_MUSB_HDRC is not set
# CONFIG_USB_DWC3 is not set
# CONFIG_USB_DWC2 is not set
# CONFIG_USB_CHIPIDEA is not set
# CONFIG_USB_ISP1760 is not set

#
# USB port drivers
#
# CONFIG_USB_USS720 is not set
CONFIG_USB_SERIAL=m
CONFIG_USB_SERIAL_GENERIC=y
# CONFIG_USB_SERIAL_SIMPLE is not set
# CONFIG_USB_SERIAL_AIRCABLE is not set
# CONFIG_USB_SERIAL_ARK3116 is not set
# CONFIG_USB_SERIAL_BELKIN is not set
# CONFIG_USB_SERIAL_CH341 is not set
# CONFIG_USB_SERIAL_WHITEHEAT is not set
# CONFIG_USB_SERIAL_DIGI_ACCELEPORT is not set
# CONFIG_USB_SERIAL_CP210X is not set
# CONFIG_USB_SERIAL_CYPRESS_M8 is not set
# CONFIG_USB_SERIAL_EMPEG is not set
# CONFIG_USB_SERIAL_FTDI_SIO is not set
# CONFIG_USB_SERIAL_VISOR is not set
# CONFIG_USB_SERIAL_IPAQ is not set
# CONFIG_USB_SERIAL_IR is not set
# CONFIG_USB_SERIAL_EDGEPORT is not set
# CONFIG_USB_SERIAL_EDGEPORT_TI is not set
# CONFIG_USB_SERIAL_F81232 is not set
# CONFIG_USB_SERIAL_F8153X is not set
# CONFIG_USB_SERIAL_GARMIN is not set
# CONFIG_USB_SERIAL_IPW is not set
# CONFIG_USB_SERIAL_IUU is not set
# CONFIG_USB_SERIAL_KEYSPAN_PDA is not set
# CONFIG_USB_SERIAL_KEYSPAN is not set
# CONFIG_USB_SERIAL_KLSI is not set
# CONFIG_USB_SERIAL_KOBIL_SCT is not set
# CONFIG_USB_SERIAL_MCT_U232 is not set
# CONFIG_USB_SERIAL_METRO is not set
# CONFIG_USB_SERIAL_MOS7720 is not set
# CONFIG_USB_SERIAL_MOS7840 is not set
# CONFIG_USB_SERIAL_MXUPORT is not set
# CONFIG_USB_SERIAL_NAVMAN is not set
# CONFIG_USB_SERIAL_PL2303 is not set
# CONFIG_USB_SERIAL_OTI6858 is not set
# CONFIG_USB_SERIAL_QCAUX is not set
# CONFIG_USB_SERIAL_QUALCOMM is not set
# CONFIG_USB_SERIAL_SPCP8X5 is not set
# CONFIG_USB_SERIAL_SAFE is not set
# CONFIG_USB_SERIAL_SIERRAWIRELESS is not set
# CONFIG_USB_SERIAL_SYMBOL is not set
# CONFIG_USB_SERIAL_TI is not set
# CONFIG_USB_SERIAL_CYBERJACK is not set
# CONFIG_USB_SERIAL_OPTION is not set
# CONFIG_USB_SERIAL_OMNINET is not set
# CONFIG_USB_SERIAL_OPTICON is not set
# CONFIG_USB_SERIAL_XSENS_MT is not set
# CONFIG_USB_SERIAL_WISHBONE is not set
# CONFIG_USB_SERIAL_SSU100 is not set
# CONFIG_USB_SERIAL_QT2 is not set
# CONFIG_USB_SERIAL_UPD78F0730 is not set
# CONFIG_USB_SERIAL_XR is not set
CONFIG_USB_SERIAL_DEBUG=m

#
# USB Miscellaneous drivers
#
# CONFIG_USB_EMI62 is not set
# CONFIG_USB_EMI26 is not set
# CONFIG_USB_ADUTUX is not set
# CONFIG_USB_SEVSEG is not set
# CONFIG_USB_LEGOTOWER is not set
# CONFIG_USB_LCD is not set
# CONFIG_USB_CYPRESS_CY7C63 is not set
# CONFIG_USB_CYTHERM is not set
# CONFIG_USB_IDMOUSE is not set
# CONFIG_USB_FTDI_ELAN is not set
# CONFIG_USB_APPLEDISPLAY is not set
# CONFIG_APPLE_MFI_FASTCHARGE is not set
# CONFIG_USB_SISUSBVGA is not set
# CONFIG_USB_LD is not set
# CONFIG_USB_TRANCEVIBRATOR is not set
# CONFIG_USB_IOWARRIOR is not set
# CONFIG_USB_TEST is not set
# CONFIG_USB_EHSET_TEST_FIXTURE is not set
# CONFIG_USB_ISIGHTFW is not set
# CONFIG_USB_YUREX is not set
# CONFIG_USB_EZUSB_FX2 is not set
# CONFIG_USB_HUB_USB251XB is not set
# CONFIG_USB_HSIC_USB3503 is not set
# CONFIG_USB_HSIC_USB4604 is not set
# CONFIG_USB_LINK_LAYER_TEST is not set
# CONFIG_USB_CHAOSKEY is not set
# CONFIG_USB_ATM is not set

#
# USB Physical Layer drivers
#
# CONFIG_NOP_USB_XCEIV is not set
# CONFIG_USB_GPIO_VBUS is not set
# CONFIG_USB_ISP1301 is not set
# end of USB Physical Layer drivers

# CONFIG_USB_GADGET is not set
CONFIG_TYPEC=y
# CONFIG_TYPEC_TCPM is not set
CONFIG_TYPEC_UCSI=y
# CONFIG_UCSI_CCG is not set
CONFIG_UCSI_ACPI=y
# CONFIG_UCSI_STM32G0 is not set
# CONFIG_TYPEC_TPS6598X is not set
# CONFIG_TYPEC_RT1719 is not set
# CONFIG_TYPEC_STUSB160X is not set
# CONFIG_TYPEC_WUSB3801 is not set

#
# USB Type-C Multiplexer/DeMultiplexer Switch support
#
# CONFIG_TYPEC_MUX_FSA4480 is not set
# CONFIG_TYPEC_MUX_PI3USB30532 is not set
# end of USB Type-C Multiplexer/DeMultiplexer Switch support

#
# USB Type-C Alternate Mode drivers
#
# CONFIG_TYPEC_DP_ALTMODE is not set
# end of USB Type-C Alternate Mode drivers

# CONFIG_USB_ROLE_SWITCH is not set
CONFIG_MMC=m
CONFIG_MMC_BLOCK=m
CONFIG_MMC_BLOCK_MINORS=8
CONFIG_SDIO_UART=m
# CONFIG_MMC_TEST is not set

#
# MMC/SD/SDIO Host Controller Drivers
#
# CONFIG_MMC_DEBUG is not set
CONFIG_MMC_SDHCI=m
CONFIG_MMC_SDHCI_IO_ACCESSORS=y
CONFIG_MMC_SDHCI_PCI=m
CONFIG_MMC_RICOH_MMC=y
CONFIG_MMC_SDHCI_ACPI=m
CONFIG_MMC_SDHCI_PLTFM=m
# CONFIG_MMC_SDHCI_F_SDH30 is not set
# CONFIG_MMC_WBSD is not set
# CONFIG_MMC_TIFM_SD is not set
# CONFIG_MMC_SPI is not set
# CONFIG_MMC_CB710 is not set
# CONFIG_MMC_VIA_SDMMC is not set
# CONFIG_MMC_VUB300 is not set
# CONFIG_MMC_USHC is not set
# CONFIG_MMC_USDHI6ROL0 is not set
# CONFIG_MMC_REALTEK_PCI is not set
CONFIG_MMC_CQHCI=m
# CONFIG_MMC_HSQ is not set
# CONFIG_MMC_TOSHIBA_PCI is not set
# CONFIG_MMC_MTK is not set
# CONFIG_MMC_SDHCI_XENON is not set
# CONFIG_SCSI_UFSHCD is not set
# CONFIG_MEMSTICK is not set
CONFIG_NEW_LEDS=y
CONFIG_LEDS_CLASS=y
# CONFIG_LEDS_CLASS_FLASH is not set
# CONFIG_LEDS_CLASS_MULTICOLOR is not set
# CONFIG_LEDS_BRIGHTNESS_HW_CHANGED is not set

#
# LED drivers
#
# CONFIG_LEDS_APU is not set
CONFIG_LEDS_LM3530=m
# CONFIG_LEDS_LM3532 is not set
# CONFIG_LEDS_LM3642 is not set
# CONFIG_LEDS_PCA9532 is not set
# CONFIG_LEDS_GPIO is not set
CONFIG_LEDS_LP3944=m
# CONFIG_LEDS_LP3952 is not set
# CONFIG_LEDS_LP50XX is not set
# CONFIG_LEDS_PCA955X is not set
# CONFIG_LEDS_PCA963X is not set
# CONFIG_LEDS_DAC124S085 is not set
# CONFIG_LEDS_PWM is not set
# CONFIG_LEDS_BD2802 is not set
CONFIG_LEDS_INTEL_SS4200=m
CONFIG_LEDS_LT3593=m
# CONFIG_LEDS_TCA6507 is not set
# CONFIG_LEDS_TLC591XX is not set
# CONFIG_LEDS_LM355x is not set
# CONFIG_LEDS_IS31FL319X is not set

#
# LED driver for blink(1) USB RGB LED is under Special HID drivers (HID_THINGM)
#
CONFIG_LEDS_BLINKM=m
CONFIG_LEDS_MLXCPLD=m
# CONFIG_LEDS_MLXREG is not set
# CONFIG_LEDS_USER is not set
# CONFIG_LEDS_NIC78BX is not set
# CONFIG_LEDS_TI_LMU_COMMON is not set

#
# Flash and Torch LED drivers
#

#
# RGB LED drivers
#

#
# LED Triggers
#
CONFIG_LEDS_TRIGGERS=y
CONFIG_LEDS_TRIGGER_TIMER=m
CONFIG_LEDS_TRIGGER_ONESHOT=m
# CONFIG_LEDS_TRIGGER_DISK is not set
CONFIG_LEDS_TRIGGER_HEARTBEAT=m
CONFIG_LEDS_TRIGGER_BACKLIGHT=m
# CONFIG_LEDS_TRIGGER_CPU is not set
# CONFIG_LEDS_TRIGGER_ACTIVITY is not set
CONFIG_LEDS_TRIGGER_GPIO=m
CONFIG_LEDS_TRIGGER_DEFAULT_ON=m

#
# iptables trigger is under Netfilter config (LED target)
#
CONFIG_LEDS_TRIGGER_TRANSIENT=m
CONFIG_LEDS_TRIGGER_CAMERA=m
# CONFIG_LEDS_TRIGGER_PANIC is not set
# CONFIG_LEDS_TRIGGER_NETDEV is not set
# CONFIG_LEDS_TRIGGER_PATTERN is not set
CONFIG_LEDS_TRIGGER_AUDIO=m
# CONFIG_LEDS_TRIGGER_TTY is not set

#
# Simple LED drivers
#
# CONFIG_ACCESSIBILITY is not set
CONFIG_INFINIBAND=m
CONFIG_INFINIBAND_USER_MAD=m
CONFIG_INFINIBAND_USER_ACCESS=m
CONFIG_INFINIBAND_USER_MEM=y
CONFIG_INFINIBAND_ON_DEMAND_PAGING=y
CONFIG_INFINIBAND_ADDR_TRANS=y
CONFIG_INFINIBAND_ADDR_TRANS_CONFIGFS=y
CONFIG_INFINIBAND_VIRT_DMA=y
# CONFIG_INFINIBAND_EFA is not set
# CONFIG_INFINIBAND_ERDMA is not set
# CONFIG_MLX4_INFINIBAND is not set
# CONFIG_INFINIBAND_MTHCA is not set
# CONFIG_INFINIBAND_OCRDMA is not set
# CONFIG_INFINIBAND_USNIC is not set
# CONFIG_INFINIBAND_RDMAVT is not set
CONFIG_RDMA_RXE=m
CONFIG_RDMA_SIW=m
CONFIG_INFINIBAND_IPOIB=m
# CONFIG_INFINIBAND_IPOIB_CM is not set
CONFIG_INFINIBAND_IPOIB_DEBUG=y
# CONFIG_INFINIBAND_IPOIB_DEBUG_DATA is not set
CONFIG_INFINIBAND_SRP=m
CONFIG_INFINIBAND_SRPT=m
# CONFIG_INFINIBAND_ISER is not set
# CONFIG_INFINIBAND_ISERT is not set
# CONFIG_INFINIBAND_RTRS_CLIENT is not set
# CONFIG_INFINIBAND_RTRS_SERVER is not set
# CONFIG_INFINIBAND_OPA_VNIC is not set
CONFIG_EDAC_ATOMIC_SCRUB=y
CONFIG_EDAC_SUPPORT=y
CONFIG_EDAC=y
CONFIG_EDAC_LEGACY_SYSFS=y
# CONFIG_EDAC_DEBUG is not set
CONFIG_EDAC_GHES=y
CONFIG_EDAC_E752X=m
CONFIG_EDAC_I82975X=m
CONFIG_EDAC_I3000=m
CONFIG_EDAC_I3200=m
CONFIG_EDAC_IE31200=m
CONFIG_EDAC_X38=m
CONFIG_EDAC_I5400=m
CONFIG_EDAC_I7CORE=m
CONFIG_EDAC_I5000=m
CONFIG_EDAC_I5100=m
CONFIG_EDAC_I7300=m
CONFIG_EDAC_SBRIDGE=m
CONFIG_EDAC_SKX=m
# CONFIG_EDAC_I10NM is not set
CONFIG_EDAC_PND2=m
# CONFIG_EDAC_IGEN6 is not set
CONFIG_RTC_LIB=y
CONFIG_RTC_MC146818_LIB=y
CONFIG_RTC_CLASS=y
CONFIG_RTC_HCTOSYS=y
CONFIG_RTC_HCTOSYS_DEVICE="rtc0"
# CONFIG_RTC_SYSTOHC is not set
# CONFIG_RTC_DEBUG is not set
CONFIG_RTC_NVMEM=y

#
# RTC interfaces
#
CONFIG_RTC_INTF_SYSFS=y
CONFIG_RTC_INTF_PROC=y
CONFIG_RTC_INTF_DEV=y
# CONFIG_RTC_INTF_DEV_UIE_EMUL is not set
# CONFIG_RTC_DRV_TEST is not set

#
# I2C RTC drivers
#
# CONFIG_RTC_DRV_ABB5ZES3 is not set
# CONFIG_RTC_DRV_ABEOZ9 is not set
# CONFIG_RTC_DRV_ABX80X is not set
CONFIG_RTC_DRV_DS1307=m
# CONFIG_RTC_DRV_DS1307_CENTURY is not set
CONFIG_RTC_DRV_DS1374=m
# CONFIG_RTC_DRV_DS1374_WDT is not set
CONFIG_RTC_DRV_DS1672=m
CONFIG_RTC_DRV_MAX6900=m
CONFIG_RTC_DRV_RS5C372=m
CONFIG_RTC_DRV_ISL1208=m
CONFIG_RTC_DRV_ISL12022=m
CONFIG_RTC_DRV_X1205=m
CONFIG_RTC_DRV_PCF8523=m
# CONFIG_RTC_DRV_PCF85063 is not set
# CONFIG_RTC_DRV_PCF85363 is not set
CONFIG_RTC_DRV_PCF8563=m
CONFIG_RTC_DRV_PCF8583=m
CONFIG_RTC_DRV_M41T80=m
CONFIG_RTC_DRV_M41T80_WDT=y
CONFIG_RTC_DRV_BQ32K=m
# CONFIG_RTC_DRV_S35390A is not set
CONFIG_RTC_DRV_FM3130=m
# CONFIG_RTC_DRV_RX8010 is not set
CONFIG_RTC_DRV_RX8581=m
CONFIG_RTC_DRV_RX8025=m
CONFIG_RTC_DRV_EM3027=m
# CONFIG_RTC_DRV_RV3028 is not set
# CONFIG_RTC_DRV_RV3032 is not set
# CONFIG_RTC_DRV_RV8803 is not set
# CONFIG_RTC_DRV_SD3078 is not set

#
# SPI RTC drivers
#
# CONFIG_RTC_DRV_M41T93 is not set
# CONFIG_RTC_DRV_M41T94 is not set
# CONFIG_RTC_DRV_DS1302 is not set
# CONFIG_RTC_DRV_DS1305 is not set
# CONFIG_RTC_DRV_DS1343 is not set
# CONFIG_RTC_DRV_DS1347 is not set
# CONFIG_RTC_DRV_DS1390 is not set
# CONFIG_RTC_DRV_MAX6916 is not set
# CONFIG_RTC_DRV_R9701 is not set
CONFIG_RTC_DRV_RX4581=m
# CONFIG_RTC_DRV_RS5C348 is not set
# CONFIG_RTC_DRV_MAX6902 is not set
# CONFIG_RTC_DRV_PCF2123 is not set
# CONFIG_RTC_DRV_MCP795 is not set
CONFIG_RTC_I2C_AND_SPI=y

#
# SPI and I2C RTC drivers
#
CONFIG_RTC_DRV_DS3232=m
CONFIG_RTC_DRV_DS3232_HWMON=y
# CONFIG_RTC_DRV_PCF2127 is not set
CONFIG_RTC_DRV_RV3029C2=m
# CONFIG_RTC_DRV_RV3029_HWMON is not set
# CONFIG_RTC_DRV_RX6110 is not set

#
# Platform RTC drivers
#
CONFIG_RTC_DRV_CMOS=y
CONFIG_RTC_DRV_DS1286=m
CONFIG_RTC_DRV_DS1511=m
CONFIG_RTC_DRV_DS1553=m
# CONFIG_RTC_DRV_DS1685_FAMILY is not set
CONFIG_RTC_DRV_DS1742=m
CONFIG_RTC_DRV_DS2404=m
CONFIG_RTC_DRV_STK17TA8=m
# CONFIG_RTC_DRV_M48T86 is not set
CONFIG_RTC_DRV_M48T35=m
CONFIG_RTC_DRV_M48T59=m
CONFIG_RTC_DRV_MSM6242=m
CONFIG_RTC_DRV_BQ4802=m
CONFIG_RTC_DRV_RP5C01=m
CONFIG_RTC_DRV_V3020=m

#
# on-CPU RTC drivers
#
# CONFIG_RTC_DRV_FTRTC010 is not set

#
# HID Sensor RTC drivers
#
# CONFIG_RTC_DRV_GOLDFISH is not set
CONFIG_DMADEVICES=y
# CONFIG_DMADEVICES_DEBUG is not set

#
# DMA Devices
#
CONFIG_DMA_ENGINE=y
CONFIG_DMA_VIRTUAL_CHANNELS=y
CONFIG_DMA_ACPI=y
# CONFIG_ALTERA_MSGDMA is not set
CONFIG_INTEL_IDMA64=m
# CONFIG_INTEL_IDXD is not set
# CONFIG_INTEL_IDXD_COMPAT is not set
CONFIG_INTEL_IOATDMA=m
# CONFIG_PLX_DMA is not set
# CONFIG_AMD_PTDMA is not set
# CONFIG_QCOM_HIDMA_MGMT is not set
# CONFIG_QCOM_HIDMA is not set
CONFIG_DW_DMAC_CORE=y
CONFIG_DW_DMAC=m
CONFIG_DW_DMAC_PCI=y
# CONFIG_DW_EDMA is not set
# CONFIG_DW_EDMA_PCIE is not set
CONFIG_HSU_DMA=y
# CONFIG_SF_PDMA is not set
# CONFIG_INTEL_LDMA is not set

#
# DMA Clients
#
CONFIG_ASYNC_TX_DMA=y
CONFIG_DMATEST=m
CONFIG_DMA_ENGINE_RAID=y

#
# DMABUF options
#
CONFIG_SYNC_FILE=y
# CONFIG_SW_SYNC is not set
# CONFIG_UDMABUF is not set
# CONFIG_DMABUF_MOVE_NOTIFY is not set
# CONFIG_DMABUF_DEBUG is not set
# CONFIG_DMABUF_SELFTESTS is not set
# CONFIG_DMABUF_HEAPS is not set
# CONFIG_DMABUF_SYSFS_STATS is not set
# end of DMABUF options

CONFIG_DCA=m
# CONFIG_AUXDISPLAY is not set
# CONFIG_PANEL is not set
CONFIG_UIO=m
CONFIG_UIO_CIF=m
CONFIG_UIO_PDRV_GENIRQ=m
# CONFIG_UIO_DMEM_GENIRQ is not set
CONFIG_UIO_AEC=m
CONFIG_UIO_SERCOS3=m
CONFIG_UIO_PCI_GENERIC=m
# CONFIG_UIO_NETX is not set
# CONFIG_UIO_PRUSS is not set
# CONFIG_UIO_MF624 is not set
CONFIG_VFIO=m
CONFIG_VFIO_IOMMU_TYPE1=m
CONFIG_VFIO_VIRQFD=m
CONFIG_VFIO_NOIOMMU=y
CONFIG_VFIO_PCI_CORE=m
CONFIG_VFIO_PCI_MMAP=y
CONFIG_VFIO_PCI_INTX=y
CONFIG_VFIO_PCI=m
# CONFIG_VFIO_PCI_VGA is not set
# CONFIG_VFIO_PCI_IGD is not set
CONFIG_VFIO_MDEV=m
CONFIG_IRQ_BYPASS_MANAGER=m
# CONFIG_VIRT_DRIVERS is not set
CONFIG_VIRTIO_ANCHOR=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI_LIB=y
CONFIG_VIRTIO_PCI_LIB_LEGACY=y
CONFIG_VIRTIO_MENU=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_LEGACY=y
# CONFIG_VIRTIO_PMEM is not set
CONFIG_VIRTIO_BALLOON=m
# CONFIG_VIRTIO_MEM is not set
CONFIG_VIRTIO_INPUT=m
# CONFIG_VIRTIO_MMIO is not set
CONFIG_VIRTIO_DMA_SHARED_BUFFER=m
# CONFIG_VDPA is not set
CONFIG_VHOST_IOTLB=m
CONFIG_VHOST=m
CONFIG_VHOST_MENU=y
CONFIG_VHOST_NET=m
# CONFIG_VHOST_SCSI is not set
CONFIG_VHOST_VSOCK=m
# CONFIG_VHOST_CROSS_ENDIAN_LEGACY is not set

#
# Microsoft Hyper-V guest support
#
# CONFIG_HYPERV is not set
# end of Microsoft Hyper-V guest support

# CONFIG_GREYBUS is not set
# CONFIG_COMEDI is not set
# CONFIG_STAGING is not set
# CONFIG_CHROME_PLATFORMS is not set
CONFIG_MELLANOX_PLATFORM=y
CONFIG_MLXREG_HOTPLUG=m
# CONFIG_MLXREG_IO is not set
# CONFIG_MLXREG_LC is not set
# CONFIG_NVSW_SN2201 is not set
CONFIG_SURFACE_PLATFORMS=y
# CONFIG_SURFACE3_WMI is not set
# CONFIG_SURFACE_3_POWER_OPREGION is not set
# CONFIG_SURFACE_GPE is not set
# CONFIG_SURFACE_HOTPLUG is not set
# CONFIG_SURFACE_PRO3_BUTTON is not set
CONFIG_X86_PLATFORM_DEVICES=y
CONFIG_ACPI_WMI=m
CONFIG_WMI_BMOF=m
# CONFIG_HUAWEI_WMI is not set
# CONFIG_UV_SYSFS is not set
CONFIG_MXM_WMI=m
# CONFIG_PEAQ_WMI is not set
# CONFIG_NVIDIA_WMI_EC_BACKLIGHT is not set
# CONFIG_XIAOMI_WMI is not set
# CONFIG_GIGABYTE_WMI is not set
# CONFIG_YOGABOOK_WMI is not set
CONFIG_ACERHDF=m
# CONFIG_ACER_WIRELESS is not set
CONFIG_ACER_WMI=m
# CONFIG_AMD_PMF is not set
# CONFIG_AMD_PMC is not set
# CONFIG_ADV_SWBUTTON is not set
CONFIG_APPLE_GMUX=m
CONFIG_ASUS_LAPTOP=m
# CONFIG_ASUS_WIRELESS is not set
CONFIG_ASUS_WMI=m
CONFIG_ASUS_NB_WMI=m
# CONFIG_ASUS_TF103C_DOCK is not set
# CONFIG_MERAKI_MX100 is not set
CONFIG_EEEPC_LAPTOP=m
CONFIG_EEEPC_WMI=m
# CONFIG_X86_PLATFORM_DRIVERS_DELL is not set
CONFIG_AMILO_RFKILL=m
CONFIG_FUJITSU_LAPTOP=m
CONFIG_FUJITSU_TABLET=m
# CONFIG_GPD_POCKET_FAN is not set
CONFIG_HP_ACCEL=m
# CONFIG_WIRELESS_HOTKEY is not set
CONFIG_HP_WMI=m
# CONFIG_IBM_RTL is not set
CONFIG_IDEAPAD_LAPTOP=m
CONFIG_SENSORS_HDAPS=m
CONFIG_THINKPAD_ACPI=m
# CONFIG_THINKPAD_ACPI_DEBUGFACILITIES is not set
# CONFIG_THINKPAD_ACPI_DEBUG is not set
# CONFIG_THINKPAD_ACPI_UNSAFE_LEDS is not set
CONFIG_THINKPAD_ACPI_VIDEO=y
CONFIG_THINKPAD_ACPI_HOTKEY_POLL=y
# CONFIG_THINKPAD_LMI is not set
# CONFIG_INTEL_ATOMISP2_PM is not set
# CONFIG_INTEL_SAR_INT1092 is not set
CONFIG_INTEL_PMC_CORE=m

#
# Intel Speed Select Technology interface support
#
# CONFIG_INTEL_SPEED_SELECT_INTERFACE is not set
# end of Intel Speed Select Technology interface support

CONFIG_INTEL_WMI=y
# CONFIG_INTEL_WMI_SBL_FW_UPDATE is not set
CONFIG_INTEL_WMI_THUNDERBOLT=m

#
# Intel Uncore Frequency Control
#
# CONFIG_INTEL_UNCORE_FREQ_CONTROL is not set
# end of Intel Uncore Frequency Control

CONFIG_INTEL_HID_EVENT=m
CONFIG_INTEL_VBTN=m
# CONFIG_INTEL_INT0002_VGPIO is not set
CONFIG_INTEL_OAKTRAIL=m
# CONFIG_INTEL_ISHTP_ECLITE is not set
# CONFIG_INTEL_PUNIT_IPC is not set
CONFIG_INTEL_RST=m
# CONFIG_INTEL_SMARTCONNECT is not set
CONFIG_INTEL_TURBO_MAX_3=y
# CONFIG_INTEL_VSEC is not set
CONFIG_MSI_LAPTOP=m
CONFIG_MSI_WMI=m
# CONFIG_PCENGINES_APU2 is not set
# CONFIG_BARCO_P50_GPIO is not set
CONFIG_SAMSUNG_LAPTOP=m
CONFIG_SAMSUNG_Q10=m
CONFIG_TOSHIBA_BT_RFKILL=m
# CONFIG_TOSHIBA_HAPS is not set
# CONFIG_TOSHIBA_WMI is not set
CONFIG_ACPI_CMPC=m
CONFIG_COMPAL_LAPTOP=m
# CONFIG_LG_LAPTOP is not set
CONFIG_PANASONIC_LAPTOP=m
CONFIG_SONY_LAPTOP=m
CONFIG_SONYPI_COMPAT=y
# CONFIG_SYSTEM76_ACPI is not set
CONFIG_TOPSTAR_LAPTOP=m
# CONFIG_SERIAL_MULTI_INSTANTIATE is not set
CONFIG_MLX_PLATFORM=m
CONFIG_INTEL_IPS=m
# CONFIG_INTEL_SCU_PCI is not set
# CONFIG_INTEL_SCU_PLATFORM is not set
# CONFIG_SIEMENS_SIMATIC_IPC is not set
# CONFIG_WINMATE_FM07_KEYS is not set
CONFIG_P2SB=y
CONFIG_HAVE_CLK=y
CONFIG_HAVE_CLK_PREPARE=y
CONFIG_COMMON_CLK=y
# CONFIG_LMK04832 is not set
# CONFIG_COMMON_CLK_MAX9485 is not set
# CONFIG_COMMON_CLK_SI5341 is not set
# CONFIG_COMMON_CLK_SI5351 is not set
# CONFIG_COMMON_CLK_SI544 is not set
# CONFIG_COMMON_CLK_CDCE706 is not set
# CONFIG_COMMON_CLK_CS2000_CP is not set
# CONFIG_COMMON_CLK_PWM is not set
# CONFIG_XILINX_VCU is not set
CONFIG_HWSPINLOCK=y

#
# Clock Source drivers
#
CONFIG_CLKEVT_I8253=y
CONFIG_I8253_LOCK=y
CONFIG_CLKBLD_I8253=y
# end of Clock Source drivers

CONFIG_MAILBOX=y
CONFIG_PCC=y
# CONFIG_ALTERA_MBOX is not set
CONFIG_IOMMU_IOVA=y
CONFIG_IOASID=y
CONFIG_IOMMU_API=y
CONFIG_IOMMU_SUPPORT=y

#
# Generic IOMMU Pagetable Support
#
# end of Generic IOMMU Pagetable Support

# CONFIG_IOMMU_DEBUGFS is not set
# CONFIG_IOMMU_DEFAULT_DMA_STRICT is not set
CONFIG_IOMMU_DEFAULT_DMA_LAZY=y
# CONFIG_IOMMU_DEFAULT_PASSTHROUGH is not set
CONFIG_IOMMU_DMA=y
CONFIG_IOMMU_SVA=y
# CONFIG_AMD_IOMMU is not set
CONFIG_DMAR_TABLE=y
CONFIG_INTEL_IOMMU=y
CONFIG_INTEL_IOMMU_SVM=y
# CONFIG_INTEL_IOMMU_DEFAULT_ON is not set
CONFIG_INTEL_IOMMU_FLOPPY_WA=y
CONFIG_INTEL_IOMMU_SCALABLE_MODE_DEFAULT_ON=y
CONFIG_IRQ_REMAP=y
# CONFIG_VIRTIO_IOMMU is not set

#
# Remoteproc drivers
#
# CONFIG_REMOTEPROC is not set
# end of Remoteproc drivers

#
# Rpmsg drivers
#
# CONFIG_RPMSG_QCOM_GLINK_RPM is not set
# CONFIG_RPMSG_VIRTIO is not set
# end of Rpmsg drivers

# CONFIG_SOUNDWIRE is not set

#
# SOC (System On Chip) specific Drivers
#

#
# Amlogic SoC drivers
#
# end of Amlogic SoC drivers

#
# Broadcom SoC drivers
#
# end of Broadcom SoC drivers

#
# NXP/Freescale QorIQ SoC drivers
#
# end of NXP/Freescale QorIQ SoC drivers

#
# fujitsu SoC drivers
#
# end of fujitsu SoC drivers

#
# i.MX SoC drivers
#
# end of i.MX SoC drivers

#
# Enable LiteX SoC Builder specific drivers
#
# end of Enable LiteX SoC Builder specific drivers

#
# Qualcomm SoC drivers
#
# end of Qualcomm SoC drivers

# CONFIG_SOC_TI is not set

#
# Xilinx SoC drivers
#
# end of Xilinx SoC drivers
# end of SOC (System On Chip) specific Drivers

# CONFIG_PM_DEVFREQ is not set
# CONFIG_EXTCON is not set
# CONFIG_MEMORY is not set
# CONFIG_IIO is not set
CONFIG_NTB=m
# CONFIG_NTB_MSI is not set
# CONFIG_NTB_AMD is not set
# CONFIG_NTB_IDT is not set
# CONFIG_NTB_INTEL is not set
# CONFIG_NTB_EPF is not set
# CONFIG_NTB_SWITCHTEC is not set
# CONFIG_NTB_PINGPONG is not set
# CONFIG_NTB_TOOL is not set
# CONFIG_NTB_PERF is not set
# CONFIG_NTB_TRANSPORT is not set
CONFIG_PWM=y
CONFIG_PWM_SYSFS=y
# CONFIG_PWM_DEBUG is not set
# CONFIG_PWM_CLK is not set
# CONFIG_PWM_DWC is not set
CONFIG_PWM_LPSS=m
CONFIG_PWM_LPSS_PCI=m
CONFIG_PWM_LPSS_PLATFORM=m
# CONFIG_PWM_PCA9685 is not set

#
# IRQ chip support
#
# end of IRQ chip support

# CONFIG_IPACK_BUS is not set
# CONFIG_RESET_CONTROLLER is not set

#
# PHY Subsystem
#
# CONFIG_GENERIC_PHY is not set
# CONFIG_USB_LGM_PHY is not set
# CONFIG_PHY_CAN_TRANSCEIVER is not set

#
# PHY drivers for Broadcom platforms
#
# CONFIG_BCM_KONA_USB2_PHY is not set
# end of PHY drivers for Broadcom platforms

# CONFIG_PHY_PXA_28NM_HSIC is not set
# CONFIG_PHY_PXA_28NM_USB2 is not set
# CONFIG_PHY_INTEL_LGM_EMMC is not set
# end of PHY Subsystem

CONFIG_POWERCAP=y
CONFIG_INTEL_RAPL_CORE=m
CONFIG_INTEL_RAPL=m
# CONFIG_IDLE_INJECT is not set
# CONFIG_MCB is not set

#
# Performance monitor support
#
# end of Performance monitor support

CONFIG_RAS=y
# CONFIG_RAS_CEC is not set
# CONFIG_USB4 is not set

#
# Android
#
# CONFIG_ANDROID_BINDER_IPC is not set
# end of Android

CONFIG_LIBNVDIMM=m
CONFIG_BLK_DEV_PMEM=m
CONFIG_ND_CLAIM=y
CONFIG_ND_BTT=m
CONFIG_BTT=y
CONFIG_ND_PFN=m
CONFIG_NVDIMM_PFN=y
CONFIG_NVDIMM_DAX=y
CONFIG_NVDIMM_KEYS=y
CONFIG_DAX=y
CONFIG_DEV_DAX=m
CONFIG_DEV_DAX_PMEM=m
CONFIG_DEV_DAX_KMEM=m
CONFIG_NVMEM=y
CONFIG_NVMEM_SYSFS=y
# CONFIG_NVMEM_RMEM is not set

#
# HW tracing support
#
CONFIG_STM=m
# CONFIG_STM_PROTO_BASIC is not set
# CONFIG_STM_PROTO_SYS_T is not set
CONFIG_STM_DUMMY=m
CONFIG_STM_SOURCE_CONSOLE=m
CONFIG_STM_SOURCE_HEARTBEAT=m
CONFIG_STM_SOURCE_FTRACE=m
CONFIG_INTEL_TH=m
CONFIG_INTEL_TH_PCI=m
CONFIG_INTEL_TH_ACPI=m
CONFIG_INTEL_TH_GTH=m
CONFIG_INTEL_TH_STH=m
CONFIG_INTEL_TH_MSU=m
CONFIG_INTEL_TH_PTI=m
# CONFIG_INTEL_TH_DEBUG is not set
# end of HW tracing support

# CONFIG_FPGA is not set
# CONFIG_SIOX is not set
# CONFIG_SLIMBUS is not set
# CONFIG_INTERCONNECT is not set
# CONFIG_COUNTER is not set
# CONFIG_MOST is not set
# CONFIG_PECI is not set
# CONFIG_HTE is not set
# end of Device Drivers

#
# File systems
#
CONFIG_DCACHE_WORD_ACCESS=y
# CONFIG_VALIDATE_FS_PARSER is not set
CONFIG_FS_IOMAP=y
CONFIG_EXT2_FS=m
CONFIG_EXT2_FS_XATTR=y
CONFIG_EXT2_FS_POSIX_ACL=y
CONFIG_EXT2_FS_SECURITY=y
# CONFIG_EXT3_FS is not set
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
# CONFIG_EXT4_DEBUG is not set
CONFIG_JBD2=y
# CONFIG_JBD2_DEBUG is not set
CONFIG_FS_MBCACHE=y
# CONFIG_REISERFS_FS is not set
# CONFIG_JFS_FS is not set
CONFIG_XFS_FS=m
CONFIG_XFS_SUPPORT_V4=y
CONFIG_XFS_QUOTA=y
CONFIG_XFS_POSIX_ACL=y
CONFIG_XFS_RT=y
CONFIG_XFS_ONLINE_SCRUB=y
CONFIG_XFS_ONLINE_REPAIR=y
CONFIG_XFS_DEBUG=y
CONFIG_XFS_ASSERT_FATAL=y
CONFIG_GFS2_FS=m
CONFIG_GFS2_FS_LOCKING_DLM=y
CONFIG_OCFS2_FS=m
CONFIG_OCFS2_FS_O2CB=m
CONFIG_OCFS2_FS_USERSPACE_CLUSTER=m
CONFIG_OCFS2_FS_STATS=y
CONFIG_OCFS2_DEBUG_MASKLOG=y
# CONFIG_OCFS2_DEBUG_FS is not set
CONFIG_BTRFS_FS=m
CONFIG_BTRFS_FS_POSIX_ACL=y
# CONFIG_BTRFS_FS_CHECK_INTEGRITY is not set
# CONFIG_BTRFS_FS_RUN_SANITY_TESTS is not set
# CONFIG_BTRFS_DEBUG is not set
# CONFIG_BTRFS_ASSERT is not set
# CONFIG_BTRFS_FS_REF_VERIFY is not set
# CONFIG_NILFS2_FS is not set
CONFIG_F2FS_FS=m
CONFIG_F2FS_STAT_FS=y
CONFIG_F2FS_FS_XATTR=y
CONFIG_F2FS_FS_POSIX_ACL=y
CONFIG_F2FS_FS_SECURITY=y
# CONFIG_F2FS_CHECK_FS is not set
# CONFIG_F2FS_FAULT_INJECTION is not set
# CONFIG_F2FS_FS_COMPRESSION is not set
CONFIG_F2FS_IOSTAT=y
# CONFIG_F2FS_UNFAIR_RWSEM is not set
# CONFIG_ZONEFS_FS is not set
CONFIG_FS_DAX=y
CONFIG_FS_DAX_PMD=y
CONFIG_FS_POSIX_ACL=y
CONFIG_EXPORTFS=y
CONFIG_EXPORTFS_BLOCK_OPS=y
CONFIG_FILE_LOCKING=y
CONFIG_FS_ENCRYPTION=y
CONFIG_FS_ENCRYPTION_ALGS=y
# CONFIG_FS_VERITY is not set
CONFIG_FSNOTIFY=y
CONFIG_DNOTIFY=y
CONFIG_INOTIFY_USER=y
CONFIG_FANOTIFY=y
CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y
CONFIG_QUOTA=y
CONFIG_QUOTA_NETLINK_INTERFACE=y
CONFIG_PRINT_QUOTA_WARNING=y
# CONFIG_QUOTA_DEBUG is not set
CONFIG_QUOTA_TREE=y
# CONFIG_QFMT_V1 is not set
CONFIG_QFMT_V2=y
CONFIG_QUOTACTL=y
CONFIG_AUTOFS4_FS=y
CONFIG_AUTOFS_FS=y
CONFIG_FUSE_FS=m
CONFIG_CUSE=m
# CONFIG_VIRTIO_FS is not set
CONFIG_OVERLAY_FS=m
# CONFIG_OVERLAY_FS_REDIRECT_DIR is not set
# CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW is not set
# CONFIG_OVERLAY_FS_INDEX is not set
# CONFIG_OVERLAY_FS_XINO_AUTO is not set
# CONFIG_OVERLAY_FS_METACOPY is not set

#
# Caches
#
CONFIG_NETFS_SUPPORT=y
CONFIG_NETFS_STATS=y
CONFIG_FSCACHE=m
CONFIG_FSCACHE_STATS=y
# CONFIG_FSCACHE_DEBUG is not set
CONFIG_CACHEFILES=m
# CONFIG_CACHEFILES_DEBUG is not set
# CONFIG_CACHEFILES_ERROR_INJECTION is not set
# CONFIG_CACHEFILES_ONDEMAND is not set
# end of Caches

#
# CD-ROM/DVD Filesystems
#
CONFIG_ISO9660_FS=m
CONFIG_JOLIET=y
CONFIG_ZISOFS=y
CONFIG_UDF_FS=m
# end of CD-ROM/DVD Filesystems

#
# DOS/FAT/EXFAT/NT Filesystems
#
CONFIG_FAT_FS=m
CONFIG_MSDOS_FS=m
CONFIG_VFAT_FS=m
CONFIG_FAT_DEFAULT_CODEPAGE=437
CONFIG_FAT_DEFAULT_IOCHARSET="ascii"
# CONFIG_FAT_DEFAULT_UTF8 is not set
# CONFIG_EXFAT_FS is not set
# CONFIG_NTFS_FS is not set
# CONFIG_NTFS3_FS is not set
# end of DOS/FAT/EXFAT/NT Filesystems

#
# Pseudo filesystems
#
CONFIG_PROC_FS=y
CONFIG_PROC_KCORE=y
CONFIG_PROC_VMCORE=y
CONFIG_PROC_VMCORE_DEVICE_DUMP=y
CONFIG_PROC_SYSCTL=y
CONFIG_PROC_PAGE_MONITOR=y
CONFIG_PROC_CHILDREN=y
CONFIG_PROC_PID_ARCH_STATUS=y
CONFIG_KERNFS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_TMPFS_XATTR=y
# CONFIG_TMPFS_INODE64 is not set
CONFIG_HUGETLBFS=y
CONFIG_HUGETLB_PAGE=y
CONFIG_ARCH_WANT_HUGETLB_PAGE_OPTIMIZE_VMEMMAP=y
CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP=y
# CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP_DEFAULT_ON is not set
CONFIG_MEMFD_CREATE=y
CONFIG_ARCH_HAS_GIGANTIC_PAGE=y
CONFIG_CONFIGFS_FS=y
CONFIG_EFIVAR_FS=y
# end of Pseudo filesystems

CONFIG_MISC_FILESYSTEMS=y
# CONFIG_ORANGEFS_FS is not set
# CONFIG_ADFS_FS is not set
# CONFIG_AFFS_FS is not set
# CONFIG_ECRYPT_FS is not set
# CONFIG_HFS_FS is not set
# CONFIG_HFSPLUS_FS is not set
# CONFIG_BEFS_FS is not set
# CONFIG_BFS_FS is not set
# CONFIG_EFS_FS is not set
CONFIG_CRAMFS=m
CONFIG_CRAMFS_BLOCKDEV=y
CONFIG_SQUASHFS=m
# CONFIG_SQUASHFS_FILE_CACHE is not set
CONFIG_SQUASHFS_FILE_DIRECT=y
# CONFIG_SQUASHFS_DECOMP_SINGLE is not set
# CONFIG_SQUASHFS_DECOMP_MULTI is not set
CONFIG_SQUASHFS_DECOMP_MULTI_PERCPU=y
CONFIG_SQUASHFS_XATTR=y
CONFIG_SQUASHFS_ZLIB=y
# CONFIG_SQUASHFS_LZ4 is not set
CONFIG_SQUASHFS_LZO=y
CONFIG_SQUASHFS_XZ=y
# CONFIG_SQUASHFS_ZSTD is not set
# CONFIG_SQUASHFS_4K_DEVBLK_SIZE is not set
# CONFIG_SQUASHFS_EMBEDDED is not set
CONFIG_SQUASHFS_FRAGMENT_CACHE_SIZE=3
# CONFIG_VXFS_FS is not set
CONFIG_MINIX_FS=m
# CONFIG_OMFS_FS is not set
# CONFIG_HPFS_FS is not set
# CONFIG_QNX4FS_FS is not set
# CONFIG_QNX6FS_FS is not set
# CONFIG_ROMFS_FS is not set
CONFIG_PSTORE=y
CONFIG_PSTORE_DEFAULT_KMSG_BYTES=10240
CONFIG_PSTORE_DEFLATE_COMPRESS=y
# CONFIG_PSTORE_LZO_COMPRESS is not set
# CONFIG_PSTORE_LZ4_COMPRESS is not set
# CONFIG_PSTORE_LZ4HC_COMPRESS is not set
# CONFIG_PSTORE_842_COMPRESS is not set
# CONFIG_PSTORE_ZSTD_COMPRESS is not set
CONFIG_PSTORE_COMPRESS=y
CONFIG_PSTORE_DEFLATE_COMPRESS_DEFAULT=y
CONFIG_PSTORE_COMPRESS_DEFAULT="deflate"
# CONFIG_PSTORE_CONSOLE is not set
# CONFIG_PSTORE_PMSG is not set
# CONFIG_PSTORE_FTRACE is not set
CONFIG_PSTORE_RAM=m
# CONFIG_PSTORE_BLK is not set
# CONFIG_SYSV_FS is not set
# CONFIG_UFS_FS is not set
# CONFIG_EROFS_FS is not set
CONFIG_NETWORK_FILESYSTEMS=y
CONFIG_NFS_FS=y
# CONFIG_NFS_V2 is not set
CONFIG_NFS_V3=y
CONFIG_NFS_V3_ACL=y
CONFIG_NFS_V4=m
# CONFIG_NFS_SWAP is not set
CONFIG_NFS_V4_1=y
CONFIG_NFS_V4_2=y
CONFIG_PNFS_FILE_LAYOUT=m
CONFIG_PNFS_BLOCK=m
CONFIG_PNFS_FLEXFILE_LAYOUT=m
CONFIG_NFS_V4_1_IMPLEMENTATION_ID_DOMAIN="kernel.org"
# CONFIG_NFS_V4_1_MIGRATION is not set
CONFIG_NFS_V4_SECURITY_LABEL=y
CONFIG_ROOT_NFS=y
# CONFIG_NFS_USE_LEGACY_DNS is not set
CONFIG_NFS_USE_KERNEL_DNS=y
CONFIG_NFS_DEBUG=y
CONFIG_NFS_DISABLE_UDP_SUPPORT=y
# CONFIG_NFS_V4_2_READ_PLUS is not set
CONFIG_NFSD=m
CONFIG_NFSD_V2_ACL=y
CONFIG_NFSD_V3_ACL=y
CONFIG_NFSD_V4=y
CONFIG_NFSD_PNFS=y
# CONFIG_NFSD_BLOCKLAYOUT is not set
CONFIG_NFSD_SCSILAYOUT=y
# CONFIG_NFSD_FLEXFILELAYOUT is not set
# CONFIG_NFSD_V4_2_INTER_SSC is not set
CONFIG_NFSD_V4_SECURITY_LABEL=y
CONFIG_GRACE_PERIOD=y
CONFIG_LOCKD=y
CONFIG_LOCKD_V4=y
CONFIG_NFS_ACL_SUPPORT=y
CONFIG_NFS_COMMON=y
CONFIG_NFS_V4_2_SSC_HELPER=y
CONFIG_SUNRPC=y
CONFIG_SUNRPC_GSS=m
CONFIG_SUNRPC_BACKCHANNEL=y
CONFIG_RPCSEC_GSS_KRB5=m
# CONFIG_SUNRPC_DISABLE_INSECURE_ENCTYPES is not set
CONFIG_SUNRPC_DEBUG=y
CONFIG_SUNRPC_XPRT_RDMA=m
CONFIG_CEPH_FS=m
# CONFIG_CEPH_FSCACHE is not set
CONFIG_CEPH_FS_POSIX_ACL=y
# CONFIG_CEPH_FS_SECURITY_LABEL is not set
CONFIG_CIFS=m
CONFIG_CIFS_STATS2=y
CONFIG_CIFS_ALLOW_INSECURE_LEGACY=y
CONFIG_CIFS_UPCALL=y
CONFIG_CIFS_XATTR=y
CONFIG_CIFS_POSIX=y
CONFIG_CIFS_DEBUG=y
# CONFIG_CIFS_DEBUG2 is not set
# CONFIG_CIFS_DEBUG_DUMP_KEYS is not set
CONFIG_CIFS_DFS_UPCALL=y
# CONFIG_CIFS_SWN_UPCALL is not set
# CONFIG_CIFS_SMB_DIRECT is not set
# CONFIG_CIFS_FSCACHE is not set
# CONFIG_SMB_SERVER is not set
CONFIG_SMBFS_COMMON=m
# CONFIG_CODA_FS is not set
# CONFIG_AFS_FS is not set
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y
# CONFIG_9P_FS_SECURITY is not set
CONFIG_NLS=y
CONFIG_NLS_DEFAULT="utf8"
CONFIG_NLS_CODEPAGE_437=y
CONFIG_NLS_CODEPAGE_737=m
CONFIG_NLS_CODEPAGE_775=m
CONFIG_NLS_CODEPAGE_850=m
CONFIG_NLS_CODEPAGE_852=m
CONFIG_NLS_CODEPAGE_855=m
CONFIG_NLS_CODEPAGE_857=m
CONFIG_NLS_CODEPAGE_860=m
CONFIG_NLS_CODEPAGE_861=m
CONFIG_NLS_CODEPAGE_862=m
CONFIG_NLS_CODEPAGE_863=m
CONFIG_NLS_CODEPAGE_864=m
CONFIG_NLS_CODEPAGE_865=m
CONFIG_NLS_CODEPAGE_866=m
CONFIG_NLS_CODEPAGE_869=m
CONFIG_NLS_CODEPAGE_936=m
CONFIG_NLS_CODEPAGE_950=m
CONFIG_NLS_CODEPAGE_932=m
CONFIG_NLS_CODEPAGE_949=m
CONFIG_NLS_CODEPAGE_874=m
CONFIG_NLS_ISO8859_8=m
CONFIG_NLS_CODEPAGE_1250=m
CONFIG_NLS_CODEPAGE_1251=m
CONFIG_NLS_ASCII=y
CONFIG_NLS_ISO8859_1=m
CONFIG_NLS_ISO8859_2=m
CONFIG_NLS_ISO8859_3=m
CONFIG_NLS_ISO8859_4=m
CONFIG_NLS_ISO8859_5=m
CONFIG_NLS_ISO8859_6=m
CONFIG_NLS_ISO8859_7=m
CONFIG_NLS_ISO8859_9=m
CONFIG_NLS_ISO8859_13=m
CONFIG_NLS_ISO8859_14=m
CONFIG_NLS_ISO8859_15=m
CONFIG_NLS_KOI8_R=m
CONFIG_NLS_KOI8_U=m
CONFIG_NLS_MAC_ROMAN=m
CONFIG_NLS_MAC_CELTIC=m
CONFIG_NLS_MAC_CENTEURO=m
CONFIG_NLS_MAC_CROATIAN=m
CONFIG_NLS_MAC_CYRILLIC=m
CONFIG_NLS_MAC_GAELIC=m
CONFIG_NLS_MAC_GREEK=m
CONFIG_NLS_MAC_ICELAND=m
CONFIG_NLS_MAC_INUIT=m
CONFIG_NLS_MAC_ROMANIAN=m
CONFIG_NLS_MAC_TURKISH=m
CONFIG_NLS_UTF8=m
CONFIG_DLM=m
# CONFIG_DLM_DEPRECATED_API is not set
CONFIG_DLM_DEBUG=y
# CONFIG_UNICODE is not set
CONFIG_IO_WQ=y
# end of File systems

#
# Security options
#
CONFIG_KEYS=y
# CONFIG_KEYS_REQUEST_CACHE is not set
CONFIG_PERSISTENT_KEYRINGS=y
CONFIG_TRUSTED_KEYS=y
CONFIG_TRUSTED_KEYS_TPM=y
CONFIG_ENCRYPTED_KEYS=y
# CONFIG_USER_DECRYPTED_DATA is not set
# CONFIG_KEY_DH_OPERATIONS is not set
# CONFIG_KEY_NOTIFICATIONS is not set
# CONFIG_SECURITY_DMESG_RESTRICT is not set
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
# CONFIG_SECURITY_INFINIBAND is not set
CONFIG_SECURITY_NETWORK_XFRM=y
# CONFIG_SECURITY_PATH is not set
CONFIG_INTEL_TXT=y
CONFIG_HAVE_HARDENED_USERCOPY_ALLOCATOR=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_FORTIFY_SOURCE=y
# CONFIG_STATIC_USERMODEHELPER is not set
# CONFIG_SECURITY_SELINUX is not set
# CONFIG_SECURITY_SMACK is not set
# CONFIG_SECURITY_TOMOYO is not set
# CONFIG_SECURITY_APPARMOR is not set
# CONFIG_SECURITY_LOADPIN is not set
CONFIG_SECURITY_YAMA=y
# CONFIG_SECURITY_SAFESETID is not set
# CONFIG_SECURITY_LOCKDOWN_LSM is not set
# CONFIG_SECURITY_LANDLOCK is not set
CONFIG_INTEGRITY=y
CONFIG_INTEGRITY_SIGNATURE=y
CONFIG_INTEGRITY_ASYMMETRIC_KEYS=y
CONFIG_INTEGRITY_TRUSTED_KEYRING=y
# CONFIG_INTEGRITY_PLATFORM_KEYRING is not set
CONFIG_INTEGRITY_AUDIT=y
# CONFIG_IMA is not set
# CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT is not set
# CONFIG_EVM is not set
CONFIG_DEFAULT_SECURITY_DAC=y
CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,bpf"

#
# Kernel hardening options
#

#
# Memory initialization
#
CONFIG_INIT_STACK_NONE=y
# CONFIG_GCC_PLUGIN_STRUCTLEAK_USER is not set
# CONFIG_GCC_PLUGIN_STACKLEAK is not set
# CONFIG_INIT_ON_ALLOC_DEFAULT_ON is not set
# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set
CONFIG_CC_HAS_ZERO_CALL_USED_REGS=y
# CONFIG_ZERO_CALL_USED_REGS is not set
# end of Memory initialization

CONFIG_RANDSTRUCT_NONE=y
# CONFIG_RANDSTRUCT_FULL is not set
# CONFIG_RANDSTRUCT_PERFORMANCE is not set
# end of Kernel hardening options
# end of Security options

CONFIG_XOR_BLOCKS=m
CONFIG_ASYNC_CORE=m
CONFIG_ASYNC_MEMCPY=m
CONFIG_ASYNC_XOR=m
CONFIG_ASYNC_PQ=m
CONFIG_ASYNC_RAID6_RECOV=m
CONFIG_CRYPTO=y

#
# Crypto core or helper
#
CONFIG_CRYPTO_ALGAPI=y
CONFIG_CRYPTO_ALGAPI2=y
CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_AEAD2=y
CONFIG_CRYPTO_SKCIPHER=y
CONFIG_CRYPTO_SKCIPHER2=y
CONFIG_CRYPTO_HASH=y
CONFIG_CRYPTO_HASH2=y
CONFIG_CRYPTO_RNG=y
CONFIG_CRYPTO_RNG2=y
CONFIG_CRYPTO_RNG_DEFAULT=y
CONFIG_CRYPTO_AKCIPHER2=y
CONFIG_CRYPTO_AKCIPHER=y
CONFIG_CRYPTO_KPP2=y
CONFIG_CRYPTO_KPP=m
CONFIG_CRYPTO_ACOMP2=y
CONFIG_CRYPTO_MANAGER=y
CONFIG_CRYPTO_MANAGER2=y
CONFIG_CRYPTO_USER=m
CONFIG_CRYPTO_MANAGER_DISABLE_TESTS=y
CONFIG_CRYPTO_GF128MUL=y
CONFIG_CRYPTO_NULL=y
CONFIG_CRYPTO_NULL2=y
CONFIG_CRYPTO_PCRYPT=m
CONFIG_CRYPTO_CRYPTD=y
CONFIG_CRYPTO_AUTHENC=m
# CONFIG_CRYPTO_TEST is not set
CONFIG_CRYPTO_SIMD=y
# end of Crypto core or helper

#
# Public-key cryptography
#
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_DH=m
# CONFIG_CRYPTO_DH_RFC7919_GROUPS is not set
CONFIG_CRYPTO_ECC=m
CONFIG_CRYPTO_ECDH=m
# CONFIG_CRYPTO_ECDSA is not set
# CONFIG_CRYPTO_ECRDSA is not set
# CONFIG_CRYPTO_SM2 is not set
# CONFIG_CRYPTO_CURVE25519 is not set
# end of Public-key cryptography

#
# Block ciphers
#
CONFIG_CRYPTO_AES=y
# CONFIG_CRYPTO_AES_TI is not set
CONFIG_CRYPTO_ANUBIS=m
# CONFIG_CRYPTO_ARIA is not set
CONFIG_CRYPTO_BLOWFISH=m
CONFIG_CRYPTO_BLOWFISH_COMMON=m
CONFIG_CRYPTO_CAMELLIA=m
CONFIG_CRYPTO_CAST_COMMON=m
CONFIG_CRYPTO_CAST5=m
CONFIG_CRYPTO_CAST6=m
CONFIG_CRYPTO_DES=m
CONFIG_CRYPTO_FCRYPT=m
CONFIG_CRYPTO_KHAZAD=m
CONFIG_CRYPTO_SEED=m
CONFIG_CRYPTO_SERPENT=m
# CONFIG_CRYPTO_SM4_GENERIC is not set
CONFIG_CRYPTO_TEA=m
CONFIG_CRYPTO_TWOFISH=m
CONFIG_CRYPTO_TWOFISH_COMMON=m
# end of Block ciphers

#
# Length-preserving ciphers and modes
#
# CONFIG_CRYPTO_ADIANTUM is not set
CONFIG_CRYPTO_ARC4=m
CONFIG_CRYPTO_CHACHA20=m
CONFIG_CRYPTO_CBC=y
CONFIG_CRYPTO_CFB=y
CONFIG_CRYPTO_CTR=y
CONFIG_CRYPTO_CTS=m
CONFIG_CRYPTO_ECB=y
# CONFIG_CRYPTO_HCTR2 is not set
# CONFIG_CRYPTO_KEYWRAP is not set
CONFIG_CRYPTO_LRW=m
# CONFIG_CRYPTO_OFB is not set
CONFIG_CRYPTO_PCBC=m
CONFIG_CRYPTO_XTS=m
# end of Length-preserving ciphers and modes

#
# AEAD (authenticated encryption with associated data) ciphers
#
# CONFIG_CRYPTO_AEGIS128 is not set
# CONFIG_CRYPTO_CHACHA20POLY1305 is not set
CONFIG_CRYPTO_CCM=m
CONFIG_CRYPTO_GCM=y
CONFIG_CRYPTO_SEQIV=y
CONFIG_CRYPTO_ECHAINIV=m
CONFIG_CRYPTO_ESSIV=m
# end of AEAD (authenticated encryption with associated data) ciphers

#
# Hashes, digests, and MACs
#
CONFIG_CRYPTO_BLAKE2B=m
CONFIG_CRYPTO_CMAC=m
CONFIG_CRYPTO_GHASH=y
CONFIG_CRYPTO_HMAC=y
CONFIG_CRYPTO_MD4=m
CONFIG_CRYPTO_MD5=y
CONFIG_CRYPTO_MICHAEL_MIC=m
# CONFIG_CRYPTO_POLY1305 is not set
CONFIG_CRYPTO_RMD160=m
CONFIG_CRYPTO_SHA1=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_SHA3=m
# CONFIG_CRYPTO_SM3_GENERIC is not set
# CONFIG_CRYPTO_STREEBOG is not set
CONFIG_CRYPTO_VMAC=m
CONFIG_CRYPTO_WP512=m
CONFIG_CRYPTO_XCBC=m
CONFIG_CRYPTO_XXHASH=m
# end of Hashes, digests, and MACs

#
# CRCs (cyclic redundancy checks)
#
CONFIG_CRYPTO_CRC32C=y
CONFIG_CRYPTO_CRC32=m
CONFIG_CRYPTO_CRCT10DIF=y
CONFIG_CRYPTO_CRC64_ROCKSOFT=m
# end of CRCs (cyclic redundancy checks)

#
# Compression
#
CONFIG_CRYPTO_DEFLATE=y
CONFIG_CRYPTO_LZO=y
# CONFIG_CRYPTO_842 is not set
# CONFIG_CRYPTO_LZ4 is not set
# CONFIG_CRYPTO_LZ4HC is not set
# CONFIG_CRYPTO_ZSTD is not set
# end of Compression

#
# Random number generation
#
CONFIG_CRYPTO_ANSI_CPRNG=m
CONFIG_CRYPTO_DRBG_MENU=y
CONFIG_CRYPTO_DRBG_HMAC=y
CONFIG_CRYPTO_DRBG_HASH=y
CONFIG_CRYPTO_DRBG_CTR=y
CONFIG_CRYPTO_DRBG=y
CONFIG_CRYPTO_JITTERENTROPY=y
# end of Random number generation

#
# Userspace interface
#
CONFIG_CRYPTO_USER_API=y
CONFIG_CRYPTO_USER_API_HASH=y
CONFIG_CRYPTO_USER_API_SKCIPHER=y
CONFIG_CRYPTO_USER_API_RNG=y
# CONFIG_CRYPTO_USER_API_RNG_CAVP is not set
CONFIG_CRYPTO_USER_API_AEAD=y
CONFIG_CRYPTO_USER_API_ENABLE_OBSOLETE=y
# CONFIG_CRYPTO_STATS is not set
# end of Userspace interface

CONFIG_CRYPTO_HASH_INFO=y

#
# Accelerated Cryptographic Algorithms for CPU (x86)
#
# CONFIG_CRYPTO_CURVE25519_X86 is not set
CONFIG_CRYPTO_AES_NI_INTEL=y
CONFIG_CRYPTO_BLOWFISH_X86_64=m
CONFIG_CRYPTO_CAMELLIA_X86_64=m
CONFIG_CRYPTO_CAMELLIA_AESNI_AVX_X86_64=m
CONFIG_CRYPTO_CAMELLIA_AESNI_AVX2_X86_64=m
CONFIG_CRYPTO_CAST5_AVX_X86_64=m
CONFIG_CRYPTO_CAST6_AVX_X86_64=m
# CONFIG_CRYPTO_DES3_EDE_X86_64 is not set
CONFIG_CRYPTO_SERPENT_SSE2_X86_64=m
CONFIG_CRYPTO_SERPENT_AVX_X86_64=m
CONFIG_CRYPTO_SERPENT_AVX2_X86_64=m
# CONFIG_CRYPTO_SM4_AESNI_AVX_X86_64 is not set
# CONFIG_CRYPTO_SM4_AESNI_AVX2_X86_64 is not set
CONFIG_CRYPTO_TWOFISH_X86_64=m
CONFIG_CRYPTO_TWOFISH_X86_64_3WAY=m
CONFIG_CRYPTO_TWOFISH_AVX_X86_64=m
# CONFIG_CRYPTO_ARIA_AESNI_AVX_X86_64 is not set
CONFIG_CRYPTO_CHACHA20_X86_64=m
# CONFIG_CRYPTO_AEGIS128_AESNI_SSE2 is not set
# CONFIG_CRYPTO_NHPOLY1305_SSE2 is not set
# CONFIG_CRYPTO_NHPOLY1305_AVX2 is not set
# CONFIG_CRYPTO_BLAKE2S_X86 is not set
# CONFIG_CRYPTO_POLYVAL_CLMUL_NI is not set
# CONFIG_CRYPTO_POLY1305_X86_64 is not set
CONFIG_CRYPTO_SHA1_SSSE3=y
CONFIG_CRYPTO_SHA256_SSSE3=y
CONFIG_CRYPTO_SHA512_SSSE3=m
# CONFIG_CRYPTO_SM3_AVX_X86_64 is not set
CONFIG_CRYPTO_GHASH_CLMUL_NI_INTEL=m
CONFIG_CRYPTO_CRC32C_INTEL=m
CONFIG_CRYPTO_CRC32_PCLMUL=m
CONFIG_CRYPTO_CRCT10DIF_PCLMUL=m
# end of Accelerated Cryptographic Algorithms for CPU (x86)

CONFIG_CRYPTO_HW=y
CONFIG_CRYPTO_DEV_PADLOCK=m
CONFIG_CRYPTO_DEV_PADLOCK_AES=m
CONFIG_CRYPTO_DEV_PADLOCK_SHA=m
# CONFIG_CRYPTO_DEV_ATMEL_ECC is not set
# CONFIG_CRYPTO_DEV_ATMEL_SHA204A is not set
CONFIG_CRYPTO_DEV_CCP=y
CONFIG_CRYPTO_DEV_QAT=m
CONFIG_CRYPTO_DEV_QAT_DH895xCC=m
CONFIG_CRYPTO_DEV_QAT_C3XXX=m
CONFIG_CRYPTO_DEV_QAT_C62X=m
# CONFIG_CRYPTO_DEV_QAT_4XXX is not set
CONFIG_CRYPTO_DEV_QAT_DH895xCCVF=m
CONFIG_CRYPTO_DEV_QAT_C3XXXVF=m
CONFIG_CRYPTO_DEV_QAT_C62XVF=m
CONFIG_CRYPTO_DEV_NITROX=m
CONFIG_CRYPTO_DEV_NITROX_CNN55XX=m
# CONFIG_CRYPTO_DEV_VIRTIO is not set
# CONFIG_CRYPTO_DEV_SAFEXCEL is not set
# CONFIG_CRYPTO_DEV_AMLOGIC_GXL is not set
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
# CONFIG_PKCS8_PRIVATE_KEY_PARSER is not set
CONFIG_PKCS7_MESSAGE_PARSER=y
# CONFIG_PKCS7_TEST_KEY is not set
CONFIG_SIGNED_PE_FILE_VERIFICATION=y
# CONFIG_FIPS_SIGNATURE_SELFTEST is not set

#
# Certificates for signature checking
#
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_MODULE_SIG_KEY_TYPE_RSA=y
# CONFIG_MODULE_SIG_KEY_TYPE_ECDSA is not set
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS=""
# CONFIG_SYSTEM_EXTRA_CERTIFICATE is not set
# CONFIG_SECONDARY_TRUSTED_KEYRING is not set
CONFIG_SYSTEM_BLACKLIST_KEYRING=y
CONFIG_SYSTEM_BLACKLIST_HASH_LIST=""
# CONFIG_SYSTEM_REVOCATION_LIST is not set
# CONFIG_SYSTEM_BLACKLIST_AUTH_UPDATE is not set
# end of Certificates for signature checking

CONFIG_BINARY_PRINTF=y

#
# Library routines
#
CONFIG_RAID6_PQ=m
CONFIG_RAID6_PQ_BENCHMARK=y
# CONFIG_PACKING is not set
CONFIG_BITREVERSE=y
CONFIG_GENERIC_STRNCPY_FROM_USER=y
CONFIG_GENERIC_STRNLEN_USER=y
CONFIG_GENERIC_NET_UTILS=y
CONFIG_CORDIC=m
# CONFIG_PRIME_NUMBERS is not set
CONFIG_RATIONAL=y
CONFIG_GENERIC_PCI_IOMAP=y
CONFIG_GENERIC_IOMAP=y
CONFIG_ARCH_USE_CMPXCHG_LOCKREF=y
CONFIG_ARCH_HAS_FAST_MULTIPLIER=y
CONFIG_ARCH_USE_SYM_ANNOTATIONS=y

#
# Crypto library routines
#
CONFIG_CRYPTO_LIB_UTILS=y
CONFIG_CRYPTO_LIB_AES=y
CONFIG_CRYPTO_LIB_ARC4=m
CONFIG_CRYPTO_LIB_BLAKE2S_GENERIC=y
CONFIG_CRYPTO_ARCH_HAVE_LIB_CHACHA=m
CONFIG_CRYPTO_LIB_CHACHA_GENERIC=m
# CONFIG_CRYPTO_LIB_CHACHA is not set
# CONFIG_CRYPTO_LIB_CURVE25519 is not set
CONFIG_CRYPTO_LIB_DES=m
CONFIG_CRYPTO_LIB_POLY1305_RSIZE=11
# CONFIG_CRYPTO_LIB_POLY1305 is not set
# CONFIG_CRYPTO_LIB_CHACHA20POLY1305 is not set
CONFIG_CRYPTO_LIB_SHA1=y
CONFIG_CRYPTO_LIB_SHA256=y
# end of Crypto library routines

CONFIG_CRC_CCITT=y
CONFIG_CRC16=y
CONFIG_CRC_T10DIF=y
CONFIG_CRC64_ROCKSOFT=m
CONFIG_CRC_ITU_T=m
CONFIG_CRC32=y
# CONFIG_CRC32_SELFTEST is not set
CONFIG_CRC32_SLICEBY8=y
# CONFIG_CRC32_SLICEBY4 is not set
# CONFIG_CRC32_SARWATE is not set
# CONFIG_CRC32_BIT is not set
CONFIG_CRC64=m
# CONFIG_CRC4 is not set
CONFIG_CRC7=m
CONFIG_LIBCRC32C=m
CONFIG_CRC8=m
CONFIG_XXHASH=y
# CONFIG_RANDOM32_SELFTEST is not set
CONFIG_ZLIB_INFLATE=y
CONFIG_ZLIB_DEFLATE=y
CONFIG_LZO_COMPRESS=y
CONFIG_LZO_DECOMPRESS=y
CONFIG_LZ4_DECOMPRESS=y
CONFIG_ZSTD_COMMON=y
CONFIG_ZSTD_COMPRESS=m
CONFIG_ZSTD_DECOMPRESS=y
CONFIG_XZ_DEC=y
CONFIG_XZ_DEC_X86=y
CONFIG_XZ_DEC_POWERPC=y
CONFIG_XZ_DEC_IA64=y
CONFIG_XZ_DEC_ARM=y
CONFIG_XZ_DEC_ARMTHUMB=y
CONFIG_XZ_DEC_SPARC=y
# CONFIG_XZ_DEC_MICROLZMA is not set
CONFIG_XZ_DEC_BCJ=y
# CONFIG_XZ_DEC_TEST is not set
CONFIG_DECOMPRESS_GZIP=y
CONFIG_DECOMPRESS_BZIP2=y
CONFIG_DECOMPRESS_LZMA=y
CONFIG_DECOMPRESS_XZ=y
CONFIG_DECOMPRESS_LZO=y
CONFIG_DECOMPRESS_LZ4=y
CONFIG_DECOMPRESS_ZSTD=y
CONFIG_GENERIC_ALLOCATOR=y
CONFIG_REED_SOLOMON=m
CONFIG_REED_SOLOMON_ENC8=y
CONFIG_REED_SOLOMON_DEC8=y
CONFIG_TEXTSEARCH=y
CONFIG_TEXTSEARCH_KMP=m
CONFIG_TEXTSEARCH_BM=m
CONFIG_TEXTSEARCH_FSM=m
CONFIG_INTERVAL_TREE=y
CONFIG_XARRAY_MULTI=y
CONFIG_ASSOCIATIVE_ARRAY=y
CONFIG_HAS_IOMEM=y
CONFIG_HAS_IOPORT_MAP=y
CONFIG_HAS_DMA=y
CONFIG_DMA_OPS=y
CONFIG_NEED_SG_DMA_LENGTH=y
CONFIG_NEED_DMA_MAP_STATE=y
CONFIG_ARCH_DMA_ADDR_T_64BIT=y
CONFIG_ARCH_HAS_FORCE_DMA_UNENCRYPTED=y
CONFIG_SWIOTLB=y
CONFIG_DMA_CMA=y
# CONFIG_DMA_PERNUMA_CMA is not set

#
# Default contiguous memory area size:
#
CONFIG_CMA_SIZE_MBYTES=0
CONFIG_CMA_SIZE_SEL_MBYTES=y
# CONFIG_CMA_SIZE_SEL_PERCENTAGE is not set
# CONFIG_CMA_SIZE_SEL_MIN is not set
# CONFIG_CMA_SIZE_SEL_MAX is not set
CONFIG_CMA_ALIGNMENT=8
# CONFIG_DMA_API_DEBUG is not set
# CONFIG_DMA_MAP_BENCHMARK is not set
CONFIG_SGL_ALLOC=y
CONFIG_CHECK_SIGNATURE=y
CONFIG_CPUMASK_OFFSTACK=y
# CONFIG_FORCE_NR_CPUS is not set
CONFIG_CPU_RMAP=y
CONFIG_DQL=y
CONFIG_GLOB=y
# CONFIG_GLOB_SELFTEST is not set
CONFIG_NLATTR=y
CONFIG_CLZ_TAB=y
CONFIG_IRQ_POLL=y
CONFIG_MPILIB=y
CONFIG_SIGNATURE=y
CONFIG_DIMLIB=y
CONFIG_OID_REGISTRY=y
CONFIG_UCS2_STRING=y
CONFIG_HAVE_GENERIC_VDSO=y
CONFIG_GENERIC_GETTIMEOFDAY=y
CONFIG_GENERIC_VDSO_TIME_NS=y
CONFIG_FONT_SUPPORT=y
# CONFIG_FONTS is not set
CONFIG_FONT_8x8=y
CONFIG_FONT_8x16=y
CONFIG_SG_POOL=y
CONFIG_ARCH_HAS_PMEM_API=y
CONFIG_MEMREGION=y
CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE=y
CONFIG_ARCH_HAS_COPY_MC=y
CONFIG_ARCH_STACKWALK=y
CONFIG_STACKDEPOT=y
CONFIG_STACKDEPOT_ALWAYS_INIT=y
CONFIG_SBITMAP=y
# end of Library routines

CONFIG_ASN1_ENCODER=y

#
# Kernel hacking
#

#
# printk and dmesg options
#
CONFIG_PRINTK_TIME=y
CONFIG_PRINTK_CALLER=y
# CONFIG_STACKTRACE_BUILD_ID is not set
CONFIG_CONSOLE_LOGLEVEL_DEFAULT=7
CONFIG_CONSOLE_LOGLEVEL_QUIET=4
CONFIG_MESSAGE_LOGLEVEL_DEFAULT=4
CONFIG_BOOT_PRINTK_DELAY=y
CONFIG_DYNAMIC_DEBUG=y
CONFIG_DYNAMIC_DEBUG_CORE=y
CONFIG_SYMBOLIC_ERRNAME=y
CONFIG_DEBUG_BUGVERBOSE=y
# end of printk and dmesg options

CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_MISC=y

#
# Compile-time checks and compiler options
#
CONFIG_DEBUG_INFO=y
CONFIG_AS_HAS_NON_CONST_LEB128=y
# CONFIG_DEBUG_INFO_NONE is not set
# CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT is not set
CONFIG_DEBUG_INFO_DWARF4=y
# CONFIG_DEBUG_INFO_DWARF5 is not set
# CONFIG_DEBUG_INFO_REDUCED is not set
# CONFIG_DEBUG_INFO_COMPRESSED is not set
# CONFIG_DEBUG_INFO_SPLIT is not set
CONFIG_DEBUG_INFO_BTF=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
# CONFIG_MODULE_ALLOW_BTF_MISMATCH is not set
# CONFIG_GDB_SCRIPTS is not set
CONFIG_FRAME_WARN=8192
CONFIG_STRIP_ASM_SYMS=y
# CONFIG_READABLE_ASM is not set
# CONFIG_HEADERS_INSTALL is not set
CONFIG_DEBUG_SECTION_MISMATCH=y
CONFIG_SECTION_MISMATCH_WARN_ONLY=y
# CONFIG_DEBUG_FORCE_FUNCTION_ALIGN_64B is not set
CONFIG_OBJTOOL=y
# CONFIG_VMLINUX_MAP is not set
# CONFIG_DEBUG_FORCE_WEAK_PER_CPU is not set
# end of Compile-time checks and compiler options

#
# Generic Kernel Debugging Instruments
#
CONFIG_MAGIC_SYSRQ=y
CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x1
CONFIG_MAGIC_SYSRQ_SERIAL=y
CONFIG_MAGIC_SYSRQ_SERIAL_SEQUENCE=""
CONFIG_DEBUG_FS=y
CONFIG_DEBUG_FS_ALLOW_ALL=y
# CONFIG_DEBUG_FS_DISALLOW_MOUNT is not set
# CONFIG_DEBUG_FS_ALLOW_NONE is not set
CONFIG_HAVE_ARCH_KGDB=y
# CONFIG_KGDB is not set
CONFIG_ARCH_HAS_UBSAN_SANITIZE_ALL=y
CONFIG_UBSAN=y
# CONFIG_UBSAN_TRAP is not set
CONFIG_CC_HAS_UBSAN_BOUNDS=y
CONFIG_UBSAN_BOUNDS=y
CONFIG_UBSAN_ONLY_BOUNDS=y
CONFIG_UBSAN_SHIFT=y
# CONFIG_UBSAN_DIV_ZERO is not set
# CONFIG_UBSAN_BOOL is not set
# CONFIG_UBSAN_ENUM is not set
# CONFIG_UBSAN_ALIGNMENT is not set
CONFIG_UBSAN_SANITIZE_ALL=y
# CONFIG_TEST_UBSAN is not set
CONFIG_HAVE_ARCH_KCSAN=y
CONFIG_HAVE_KCSAN_COMPILER=y
# end of Generic Kernel Debugging Instruments

#
# Networking Debugging
#
# CONFIG_NET_DEV_REFCNT_TRACKER is not set
# CONFIG_NET_NS_REFCNT_TRACKER is not set
# CONFIG_DEBUG_NET is not set
# end of Networking Debugging

#
# Memory Debugging
#
CONFIG_PAGE_EXTENSION=y
# CONFIG_DEBUG_PAGEALLOC is not set
CONFIG_SLUB_DEBUG=y
# CONFIG_SLUB_DEBUG_ON is not set
CONFIG_PAGE_OWNER=y
# CONFIG_PAGE_TABLE_CHECK is not set
# CONFIG_PAGE_POISONING is not set
# CONFIG_DEBUG_PAGE_REF is not set
# CONFIG_DEBUG_RODATA_TEST is not set
CONFIG_ARCH_HAS_DEBUG_WX=y
# CONFIG_DEBUG_WX is not set
CONFIG_GENERIC_PTDUMP=y
# CONFIG_PTDUMP_DEBUGFS is not set
# CONFIG_DEBUG_OBJECTS is not set
# CONFIG_SHRINKER_DEBUG is not set
CONFIG_HAVE_DEBUG_KMEMLEAK=y
# CONFIG_DEBUG_KMEMLEAK is not set
# CONFIG_DEBUG_STACK_USAGE is not set
# CONFIG_SCHED_STACK_END_CHECK is not set
CONFIG_ARCH_HAS_DEBUG_VM_PGTABLE=y
# CONFIG_DEBUG_VM is not set
# CONFIG_DEBUG_VM_PGTABLE is not set
CONFIG_ARCH_HAS_DEBUG_VIRTUAL=y
# CONFIG_DEBUG_VIRTUAL is not set
CONFIG_DEBUG_MEMORY_INIT=y
# CONFIG_DEBUG_PER_CPU_MAPS is not set
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_CC_HAS_WORKING_NOSANITIZE_ADDRESS=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
# CONFIG_KASAN_OUTLINE is not set
CONFIG_KASAN_INLINE=y
CONFIG_KASAN_STACK=y
CONFIG_KASAN_VMALLOC=y
# CONFIG_KASAN_MODULE_TEST is not set
CONFIG_HAVE_ARCH_KFENCE=y
# CONFIG_KFENCE is not set
CONFIG_HAVE_ARCH_KMSAN=y
# end of Memory Debugging

CONFIG_DEBUG_SHIRQ=y

#
# Debug Oops, Lockups and Hangs
#
CONFIG_PANIC_ON_OOPS=y
CONFIG_PANIC_ON_OOPS_VALUE=1
CONFIG_PANIC_TIMEOUT=0
CONFIG_LOCKUP_DETECTOR=y
CONFIG_SOFTLOCKUP_DETECTOR=y
# CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC is not set
CONFIG_HARDLOCKUP_DETECTOR_PERF=y
CONFIG_HARDLOCKUP_CHECK_TIMESTAMP=y
CONFIG_HARDLOCKUP_DETECTOR=y
CONFIG_BOOTPARAM_HARDLOCKUP_PANIC=y
CONFIG_DETECT_HUNG_TASK=y
CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=480
# CONFIG_BOOTPARAM_HUNG_TASK_PANIC is not set
CONFIG_WQ_WATCHDOG=y
# CONFIG_TEST_LOCKUP is not set
# end of Debug Oops, Lockups and Hangs

#
# Scheduler Debugging
#
CONFIG_SCHED_DEBUG=y
CONFIG_SCHED_INFO=y
CONFIG_SCHEDSTATS=y
# end of Scheduler Debugging

# CONFIG_DEBUG_TIMEKEEPING is not set

#
# Lock Debugging (spinlocks, mutexes, etc...)
#
CONFIG_LOCK_DEBUGGING_SUPPORT=y
# CONFIG_PROVE_LOCKING is not set
# CONFIG_LOCK_STAT is not set
# CONFIG_DEBUG_RT_MUTEXES is not set
# CONFIG_DEBUG_SPINLOCK is not set
# CONFIG_DEBUG_MUTEXES is not set
# CONFIG_DEBUG_WW_MUTEX_SLOWPATH is not set
# CONFIG_DEBUG_RWSEMS is not set
# CONFIG_DEBUG_LOCK_ALLOC is not set
CONFIG_DEBUG_ATOMIC_SLEEP=y
# CONFIG_DEBUG_LOCKING_API_SELFTESTS is not set
# CONFIG_LOCK_TORTURE_TEST is not set
# CONFIG_WW_MUTEX_SELFTEST is not set
# CONFIG_SCF_TORTURE_TEST is not set
# CONFIG_CSD_LOCK_WAIT_DEBUG is not set
# end of Lock Debugging (spinlocks, mutexes, etc...)

# CONFIG_DEBUG_IRQFLAGS is not set
CONFIG_STACKTRACE=y
# CONFIG_WARN_ALL_UNSEEDED_RANDOM is not set
# CONFIG_DEBUG_KOBJECT is not set

#
# Debug kernel data structures
#
CONFIG_DEBUG_LIST=y
# CONFIG_DEBUG_PLIST is not set
# CONFIG_DEBUG_SG is not set
# CONFIG_DEBUG_NOTIFIERS is not set
CONFIG_BUG_ON_DATA_CORRUPTION=y
# CONFIG_DEBUG_MAPLE_TREE is not set
# end of Debug kernel data structures

# CONFIG_DEBUG_CREDENTIALS is not set

#
# RCU Debugging
#
CONFIG_TORTURE_TEST=m
# CONFIG_RCU_SCALE_TEST is not set
# CONFIG_RCU_TORTURE_TEST is not set
CONFIG_RCU_REF_SCALE_TEST=m
CONFIG_RCU_CPU_STALL_TIMEOUT=60
CONFIG_RCU_EXP_CPU_STALL_TIMEOUT=0
# CONFIG_RCU_TRACE is not set
# CONFIG_RCU_EQS_DEBUG is not set
# end of RCU Debugging

# CONFIG_DEBUG_WQ_FORCE_RR_CPU is not set
# CONFIG_CPU_HOTPLUG_STATE_CONTROL is not set
CONFIG_LATENCYTOP=y
CONFIG_USER_STACKTRACE_SUPPORT=y
CONFIG_NOP_TRACER=y
CONFIG_HAVE_RETHOOK=y
CONFIG_RETHOOK=y
CONFIG_HAVE_FUNCTION_TRACER=y
CONFIG_HAVE_FUNCTION_GRAPH_TRACER=y
CONFIG_HAVE_DYNAMIC_FTRACE=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS=y
CONFIG_HAVE_DYNAMIC_FTRACE_NO_PATCHABLE=y
CONFIG_HAVE_FTRACE_MCOUNT_RECORD=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_HAVE_FENTRY=y
CONFIG_HAVE_OBJTOOL_MCOUNT=y
CONFIG_HAVE_C_RECORDMCOUNT=y
CONFIG_HAVE_BUILDTIME_MCOUNT_SORT=y
CONFIG_BUILDTIME_MCOUNT_SORT=y
CONFIG_TRACER_MAX_TRACE=y
CONFIG_TRACE_CLOCK=y
CONFIG_RING_BUFFER=y
CONFIG_EVENT_TRACING=y
CONFIG_CONTEXT_SWITCH_TRACER=y
CONFIG_TRACING=y
CONFIG_GENERIC_TRACER=y
CONFIG_TRACING_SUPPORT=y
CONFIG_FTRACE=y
# CONFIG_BOOTTIME_TRACING is not set
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_DYNAMIC_FTRACE_WITH_ARGS=y
# CONFIG_FPROBE is not set
CONFIG_FUNCTION_PROFILER=y
CONFIG_STACK_TRACER=y
# CONFIG_IRQSOFF_TRACER is not set
CONFIG_SCHED_TRACER=y
CONFIG_HWLAT_TRACER=y
# CONFIG_OSNOISE_TRACER is not set
# CONFIG_TIMERLAT_TRACER is not set
# CONFIG_MMIOTRACE is not set
CONFIG_FTRACE_SYSCALLS=y
CONFIG_TRACER_SNAPSHOT=y
# CONFIG_TRACER_SNAPSHOT_PER_CPU_SWAP is not set
CONFIG_BRANCH_PROFILE_NONE=y
# CONFIG_PROFILE_ANNOTATED_BRANCHES is not set
# CONFIG_BLK_DEV_IO_TRACE is not set
CONFIG_KPROBE_EVENTS=y
# CONFIG_KPROBE_EVENTS_ON_NOTRACE is not set
CONFIG_UPROBE_EVENTS=y
CONFIG_BPF_EVENTS=y
CONFIG_DYNAMIC_EVENTS=y
CONFIG_PROBE_EVENTS=y
CONFIG_BPF_KPROBE_OVERRIDE=y
CONFIG_FTRACE_MCOUNT_RECORD=y
CONFIG_FTRACE_MCOUNT_USE_CC=y
CONFIG_TRACING_MAP=y
CONFIG_SYNTH_EVENTS=y
CONFIG_HIST_TRIGGERS=y
# CONFIG_TRACE_EVENT_INJECT is not set
# CONFIG_TRACEPOINT_BENCHMARK is not set
CONFIG_RING_BUFFER_BENCHMARK=m
# CONFIG_TRACE_EVAL_MAP_FILE is not set
# CONFIG_FTRACE_RECORD_RECURSION is not set
# CONFIG_FTRACE_STARTUP_TEST is not set
# CONFIG_FTRACE_SORT_STARTUP_TEST is not set
# CONFIG_RING_BUFFER_STARTUP_TEST is not set
# CONFIG_RING_BUFFER_VALIDATE_TIME_DELTAS is not set
# CONFIG_PREEMPTIRQ_DELAY_TEST is not set
# CONFIG_SYNTH_EVENT_GEN_TEST is not set
# CONFIG_KPROBE_EVENT_GEN_TEST is not set
# CONFIG_HIST_TRIGGERS_DEBUG is not set
# CONFIG_RV is not set
CONFIG_PROVIDE_OHCI1394_DMA_INIT=y
# CONFIG_SAMPLES is not set
CONFIG_HAVE_SAMPLE_FTRACE_DIRECT=y
CONFIG_HAVE_SAMPLE_FTRACE_DIRECT_MULTI=y
CONFIG_ARCH_HAS_DEVMEM_IS_ALLOWED=y
CONFIG_STRICT_DEVMEM=y
# CONFIG_IO_STRICT_DEVMEM is not set

#
# x86 Debugging
#
CONFIG_EARLY_PRINTK_USB=y
CONFIG_X86_VERBOSE_BOOTUP=y
CONFIG_EARLY_PRINTK=y
CONFIG_EARLY_PRINTK_DBGP=y
CONFIG_EARLY_PRINTK_USB_XDBC=y
# CONFIG_EFI_PGT_DUMP is not set
# CONFIG_DEBUG_TLBFLUSH is not set
CONFIG_HAVE_MMIOTRACE_SUPPORT=y
# CONFIG_X86_DECODER_SELFTEST is not set
CONFIG_IO_DELAY_0X80=y
# CONFIG_IO_DELAY_0XED is not set
# CONFIG_IO_DELAY_UDELAY is not set
# CONFIG_IO_DELAY_NONE is not set
CONFIG_DEBUG_BOOT_PARAMS=y
# CONFIG_CPA_DEBUG is not set
# CONFIG_DEBUG_ENTRY is not set
# CONFIG_DEBUG_NMI_SELFTEST is not set
# CONFIG_X86_DEBUG_FPU is not set
# CONFIG_PUNIT_ATOM_DEBUG is not set
CONFIG_UNWINDER_ORC=y
# CONFIG_UNWINDER_FRAME_POINTER is not set
# end of x86 Debugging

#
# Kernel Testing and Coverage
#
# CONFIG_KUNIT is not set
# CONFIG_NOTIFIER_ERROR_INJECTION is not set
CONFIG_FUNCTION_ERROR_INJECTION=y
CONFIG_FAULT_INJECTION=y
# CONFIG_FAILSLAB is not set
# CONFIG_FAIL_PAGE_ALLOC is not set
# CONFIG_FAULT_INJECTION_USERCOPY is not set
CONFIG_FAIL_MAKE_REQUEST=y
# CONFIG_FAIL_IO_TIMEOUT is not set
# CONFIG_FAIL_FUTEX is not set
CONFIG_FAULT_INJECTION_DEBUG_FS=y
# CONFIG_FAIL_FUNCTION is not set
# CONFIG_FAIL_MMC_REQUEST is not set
# CONFIG_FAIL_SUNRPC is not set
CONFIG_ARCH_HAS_KCOV=y
CONFIG_CC_HAS_SANCOV_TRACE_PC=y
# CONFIG_KCOV is not set
CONFIG_RUNTIME_TESTING_MENU=y
# CONFIG_LKDTM is not set
# CONFIG_TEST_MIN_HEAP is not set
# CONFIG_TEST_DIV64 is not set
# CONFIG_BACKTRACE_SELF_TEST is not set
# CONFIG_TEST_REF_TRACKER is not set
# CONFIG_RBTREE_TEST is not set
# CONFIG_REED_SOLOMON_TEST is not set
# CONFIG_INTERVAL_TREE_TEST is not set
# CONFIG_PERCPU_TEST is not set
# CONFIG_ATOMIC64_SELFTEST is not set
# CONFIG_ASYNC_RAID6_TEST is not set
# CONFIG_TEST_HEXDUMP is not set
# CONFIG_STRING_SELFTEST is not set
# CONFIG_TEST_STRING_HELPERS is not set
# CONFIG_TEST_STRSCPY is not set
# CONFIG_TEST_KSTRTOX is not set
# CONFIG_TEST_PRINTF is not set
# CONFIG_TEST_SCANF is not set
# CONFIG_TEST_BITMAP is not set
# CONFIG_TEST_UUID is not set
# CONFIG_TEST_XARRAY is not set
# CONFIG_TEST_RHASHTABLE is not set
# CONFIG_TEST_SIPHASH is not set
# CONFIG_TEST_IDA is not set
# CONFIG_TEST_LKM is not set
# CONFIG_TEST_BITOPS is not set
# CONFIG_TEST_VMALLOC is not set
# CONFIG_TEST_USER_COPY is not set
CONFIG_TEST_BPF=m
# CONFIG_TEST_BLACKHOLE_DEV is not set
# CONFIG_FIND_BIT_BENCHMARK is not set
# CONFIG_TEST_FIRMWARE is not set
# CONFIG_TEST_SYSCTL is not set
# CONFIG_TEST_UDELAY is not set
# CONFIG_TEST_STATIC_KEYS is not set
# CONFIG_TEST_DYNAMIC_DEBUG is not set
# CONFIG_TEST_KMOD is not set
# CONFIG_TEST_MEMCAT_P is not set
# CONFIG_TEST_LIVEPATCH is not set
# CONFIG_TEST_MEMINIT is not set
# CONFIG_TEST_HMM is not set
# CONFIG_TEST_FREE_PAGES is not set
# CONFIG_TEST_FPU is not set
# CONFIG_TEST_CLOCKSOURCE_WATCHDOG is not set
CONFIG_ARCH_USE_MEMTEST=y
# CONFIG_MEMTEST is not set
# end of Kernel Testing and Coverage

#
# Rust hacking
#
# end of Rust hacking
# end of Kernel hacking

--b8seNkh+w+eqQ5nt
Content-Type: text/plain; charset="us-ascii"
Content-Disposition: attachment; filename="job-script"

#!/bin/sh

export_top_env()
{
	export suite='otc_ddt'
	export testcase='otc_ddt'
	export category='functional'
	export platform='spr'
	export kernel_cmdline='initcall_debug text log_buf_len=4M no_console_suspend ignore_loglevel'
	export do_not_reboot_for_same_kernel=1
	export job_origin='ddt-spr.yaml'
	export queue_cmdline_keys='branch
commit
kbuild_queue_analysis'
	export queue='validate'
	export testbox='lkp-icl-2sp4'
	export tbox_group='lkp-icl-2sp4'
	export submit_id='636e93244cd782445415239a'
	export job_file='/lkp/jobs/scheduled/lkp-icl-2sp4/otc_ddt-spr-spr-test-set-debian-11.1-x86_64-20220510.cgz-9fd429c28073fa40f5465cd6e4769a0af80bf398-20221112-148564-1yutfuf-4.yaml'
	export id='5603ad1a317f4e09ac10b73a8f2717fed66d75bd'
	export queuer_version='/zday/lkp'
	export model='Ice Lake'
	export nr_node=2
	export nr_cpu=128
	export memory='128G'
	export nr_ssd_partitions=3
	export nr_hdd_partitions=6
	export hdd_partitions='/dev/disk/by-id/ata-WDC_WD20SPZX-08UA7_WD-WXE2EA0ECVAS-part*'
	export ssd_partitions='/dev/disk/by-id/ata-INTEL_SSDSC2BA800G3_BTTV34510181800JGN-part*'
	export rootfs_partition='/dev/disk/by-id/ata-INTEL_SSDSC2BB240G4_CVWL422602EB240NGN-part1'
	export kernel_cmdline_hw='acpi_rsdp=0x69ffd014'
	export brand='Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz'
	export initrds='linux_perf'
	export commit='9fd429c28073fa40f5465cd6e4769a0af80bf398'
	export ucode='0xd000363'
	export bisect_dmesg=true
	export kconfig='x86_64-rhel-8.3-func'
	export enqueue_time='2022-11-12 02:23:32 +0800'
	export _id='636e933c4cd782445415239d'
	export _rt='/result/otc_ddt/spr-spr-test-set/lkp-icl-2sp4/debian-11.1-x86_64-20220510.cgz/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398'
	export user='lkp'
	export compiler='gcc-11'
	export LKP_SERVER='internal-lkp-server'
	export head_commit='4d2cc661176f64933ca294dae7d48e8cd650a0fe'
	export base_commit='80e78fcce86de0288793a0ef0f6acf37656ee4cf'
	export branch='tip/x86/mm'
	export rootfs='debian-11.1-x86_64-20220510.cgz'
	export result_root='/result/otc_ddt/spr-spr-test-set/lkp-icl-2sp4/debian-11.1-x86_64-20220510.cgz/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/1'
	export scheduler_version='/lkp/lkp/.src-20221111-153930'
	export arch='x86_64'
	export max_uptime=2100
	export initrd='/osimage/debian/debian-11.1-x86_64-20220510.cgz'
	export bootloader_append='root=/dev/ram0
RESULT_ROOT=/result/otc_ddt/spr-spr-test-set/lkp-icl-2sp4/debian-11.1-x86_64-20220510.cgz/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/1
BOOT_IMAGE=/pkg/linux/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/vmlinuz-6.1.0-rc2-00001-g9fd429c28073
branch=tip/x86/mm
job=/lkp/jobs/scheduled/lkp-icl-2sp4/otc_ddt-spr-spr-test-set-debian-11.1-x86_64-20220510.cgz-9fd429c28073fa40f5465cd6e4769a0af80bf398-20221112-148564-1yutfuf-4.yaml
user=lkp
ARCH=x86_64
kconfig=x86_64-rhel-8.3-func
commit=9fd429c28073fa40f5465cd6e4769a0af80bf398
initcall_debug text log_buf_len=4M no_console_suspend ignore_loglevel
initcall_debug
acpi_rsdp=0x69ffd014
max_uptime=2100
LKP_SERVER=internal-lkp-server
nokaslr
selinux=0
debug
apic=debug
sysrq_always_enabled
rcupdate.rcu_cpu_stall_timeout=100
net.ifnames=0
printk.devkmsg=on
panic=-1
softlockup_panic=1
nmi_watchdog=panic
oops=panic
load_ramdisk=2
prompt_ramdisk=0
drbd.minor_count=8
systemd.log_level=err
ignore_loglevel
console=tty0
earlyprintk=ttyS0,115200
console=ttyS0,115200
vga=normal
rw'
	export modules_initrd='/pkg/linux/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/modules.cgz'
	export linux_perf_initrd='/pkg/linux/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/linux-perf.cgz'
	export bm_initrd='/osimage/deps/debian-11.1-x86_64-20220510.cgz/run-ipconfig_20220515.cgz,/osimage/deps/debian-11.1-x86_64-20220510.cgz/lkp_20220513.cgz,/osimage/deps/debian-11.1-x86_64-20220510.cgz/rsync-rootfs_20220515.cgz,/osimage/deps/debian-11.1-x86_64-20220510.cgz/otc_ddt_20220718.cgz,/osimage/pkg/debian-11.1-x86_64-20220510.cgz/otc_ddt-x86_64-2022WW31-1_20220913.cgz,/osimage/deps/debian-11.1-x86_64-20220510.cgz/hw_20220526.cgz'
	export ucode_initrd='/osimage/ucode/intel-ucode-20220804.cgz'
	export lkp_initrd='/osimage/user/lkp/lkp-x86_64.cgz'
	export site='inn'
	export LKP_CGI_PORT=80
	export LKP_CIFS_PORT=139
	export last_kernel='6.1.0-rc4'
	export repeat_to=6
	export stop_repeat_if_found='dmesg.RIP:get_desc'
	export kbuild_queue_analysis=1
	export schedule_notify_address=
	export kernel='/pkg/linux/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/vmlinuz-6.1.0-rc2-00001-g9fd429c28073'
	export dequeue_time='2022-11-12 02:28:34 +0800'
	export job_initrd='/lkp/jobs/scheduled/lkp-icl-2sp4/otc_ddt-spr-spr-test-set-debian-11.1-x86_64-20220510.cgz-9fd429c28073fa40f5465cd6e4769a0af80bf398-20221112-148564-1yutfuf-4.cgz'

	[ -n "$LKP_SRC" ] ||
	export LKP_SRC=/lkp/${user:-lkp}/src
}

run_job()
{
	echo $$ > $TMP/run-job.pid

	. $LKP_SRC/lib/http.sh
	. $LKP_SRC/lib/job.sh
	. $LKP_SRC/lib/env.sh

	export_top_env

	run_monitor $LKP_SRC/monitors/wrapper kmsg
	run_monitor $LKP_SRC/monitors/wrapper heartbeat
	run_monitor $LKP_SRC/monitors/wrapper meminfo
	run_monitor $LKP_SRC/monitors/wrapper oom-killer
	run_monitor $LKP_SRC/monitors/plain/watchdog

	run_test test='spr-test-set' $LKP_SRC/tests/wrapper otc_ddt
}

extract_stats()
{
	export stats_part_begin=
	export stats_part_end=

	env test='spr-test-set' $LKP_SRC/stats/wrapper otc_ddt
	$LKP_SRC/stats/wrapper kmsg
	$LKP_SRC/stats/wrapper meminfo

	$LKP_SRC/stats/wrapper time otc_ddt.time
	$LKP_SRC/stats/wrapper dmesg
	$LKP_SRC/stats/wrapper kmsg
	$LKP_SRC/stats/wrapper last_state
	$LKP_SRC/stats/wrapper stderr
	$LKP_SRC/stats/wrapper time
}

"$@"

--b8seNkh+w+eqQ5nt
Content-Type: application/x-xz
Content-Disposition: attachment; filename="dmesg.xz"
Content-Transfer-Encoding: base64

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

--b8seNkh+w+eqQ5nt
Content-Type: text/plain; charset="us-ascii"
Content-Disposition: attachment; filename="job.yaml"

---

#! jobs/ddt-spr.yaml
suite: otc_ddt
testcase: otc_ddt
category: functional
platform: spr
kernel_cmdline: initcall_debug text log_buf_len=4M no_console_suspend ignore_loglevel
do_not_reboot_for_same_kernel: 1
otc_ddt:
  test: spr-test-set
job_origin: ddt-spr.yaml

#! queue options
queue_cmdline_keys:
- branch
- commit
queue: bisect
testbox: lkp-icl-2sp4
tbox_group: lkp-icl-2sp4
submit_id: 636e84f84cd782401076b4a8
job_file: "/lkp/jobs/scheduled/lkp-icl-2sp4/otc_ddt-spr-spr-test-set-debian-11.1-x86_64-20220510.cgz-9fd429c28073fa40f5465cd6e4769a0af80bf398-20221112-147472-1s1bbfo-0.yaml"
id: b2bdb9a8b2ec133227109f4a04351342bc404c6d
queuer_version: "/zday/lkp"

#! hosts/lkp-icl-2sp4
model: Ice Lake
nr_node: 2
nr_cpu: 128
memory: 128G
nr_ssd_partitions: 3
nr_hdd_partitions: 6
hdd_partitions: "/dev/disk/by-id/ata-WDC_WD20SPZX-08UA7_WD-WXE2EA0ECVAS-part*"
ssd_partitions: "/dev/disk/by-id/ata-INTEL_SSDSC2BA800G3_BTTV34510181800JGN-part*"
rootfs_partition: "/dev/disk/by-id/ata-INTEL_SSDSC2BB240G4_CVWL422602EB240NGN-part1"
kernel_cmdline_hw: acpi_rsdp=0x69ffd014
brand: Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz

#! include/category/functional
kmsg:
heartbeat:
meminfo:

#! include/otc_ddt
initrds:
- linux_perf

#! include/queue/cyclic
commit: 9fd429c28073fa40f5465cd6e4769a0af80bf398

#! include/testbox/lkp-icl-2sp4
ucode: '0xd000363'
bisect_dmesg: true
kconfig: x86_64-rhel-8.3-func
enqueue_time: 2022-11-12 01:23:05.435260421 +08:00
_id: 636e84f84cd782401076b4a8
_rt: "/result/otc_ddt/spr-spr-test-set/lkp-icl-2sp4/debian-11.1-x86_64-20220510.cgz/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398"

#! schedule options
user: lkp
compiler: gcc-11
LKP_SERVER: internal-lkp-server
head_commit: 4d2cc661176f64933ca294dae7d48e8cd650a0fe
base_commit: 80e78fcce86de0288793a0ef0f6acf37656ee4cf
branch: linux-next/master
rootfs: debian-11.1-x86_64-20220510.cgz
result_root: "/result/otc_ddt/spr-spr-test-set/lkp-icl-2sp4/debian-11.1-x86_64-20220510.cgz/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/0"
scheduler_version: "/lkp/lkp/.src-20221111-153930"
arch: x86_64
max_uptime: 2100
initrd: "/osimage/debian/debian-11.1-x86_64-20220510.cgz"
bootloader_append:
- root=/dev/ram0
- RESULT_ROOT=/result/otc_ddt/spr-spr-test-set/lkp-icl-2sp4/debian-11.1-x86_64-20220510.cgz/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/0
- BOOT_IMAGE=/pkg/linux/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/vmlinuz-6.1.0-rc2-00001-g9fd429c28073
- branch=linux-next/master
- job=/lkp/jobs/scheduled/lkp-icl-2sp4/otc_ddt-spr-spr-test-set-debian-11.1-x86_64-20220510.cgz-9fd429c28073fa40f5465cd6e4769a0af80bf398-20221112-147472-1s1bbfo-0.yaml
- user=lkp
- ARCH=x86_64
- kconfig=x86_64-rhel-8.3-func
- commit=9fd429c28073fa40f5465cd6e4769a0af80bf398
- initcall_debug text log_buf_len=4M no_console_suspend ignore_loglevel
- initcall_debug
- acpi_rsdp=0x69ffd014
- max_uptime=2100
- LKP_SERVER=internal-lkp-server
- nokaslr
- selinux=0
- debug
- apic=debug
- sysrq_always_enabled
- rcupdate.rcu_cpu_stall_timeout=100
- net.ifnames=0
- printk.devkmsg=on
- panic=-1
- softlockup_panic=1
- nmi_watchdog=panic
- oops=panic
- load_ramdisk=2
- prompt_ramdisk=0
- drbd.minor_count=8
- systemd.log_level=err
- ignore_loglevel
- console=tty0
- earlyprintk=ttyS0,115200
- console=ttyS0,115200
- vga=normal
- rw
modules_initrd: "/pkg/linux/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/modules.cgz"
linux_perf_initrd: "/pkg/linux/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/linux-perf.cgz"
bm_initrd: "/osimage/deps/debian-11.1-x86_64-20220510.cgz/run-ipconfig_20220515.cgz,/osimage/deps/debian-11.1-x86_64-20220510.cgz/lkp_20220513.cgz,/osimage/deps/debian-11.1-x86_64-20220510.cgz/rsync-rootfs_20220515.cgz,/osimage/deps/debian-11.1-x86_64-20220510.cgz/otc_ddt_20220718.cgz,/osimage/pkg/debian-11.1-x86_64-20220510.cgz/otc_ddt-x86_64-2022WW31-1_20220913.cgz,/osimage/deps/debian-11.1-x86_64-20220510.cgz/hw_20220526.cgz"
ucode_initrd: "/osimage/ucode/intel-ucode-20220804.cgz"
lkp_initrd: "/osimage/user/lkp/lkp-x86_64.cgz"
site: inn

#! /cephfs/db/releases/20220913141905/lkp-src/include/site/inn
LKP_CGI_PORT: 80
LKP_CIFS_PORT: 139
oom-killer:
watchdog:

#! runtime status
last_kernel: 6.1.0-rc3-intel-next-01603-ge6c37d4a3760

#! /cephfs/db/releases/20220916204556/lkp-src/include/site/inn

#! /cephfs/db/releases/20221018123244/lkp-src/include/site/inn
stop_repeat_if_found: otc_ddt.CPU_XS_FUNC_SL_TESTCTL_WRITABLE.fail
kbuild_queue_analysis: 1

#! /cephfs/db/releases/20221020110634/lkp-src/include/site/inn

#! /cephfs/db/releases/20221109190458/lkp-src/include/site/inn
schedule_notify_address:

#! user overrides
kernel: "/pkg/linux/x86_64-rhel-8.3-func/gcc-11/9fd429c28073fa40f5465cd6e4769a0af80bf398/vmlinuz-6.1.0-rc2-00001-g9fd429c28073"
dequeue_time: 2022-11-12 02:10:07.156012769 +08:00

#! /cephfs/db/releases/20221111220745/lkp-src/include/site/inn
job_state: running

--b8seNkh+w+eqQ5nt--
