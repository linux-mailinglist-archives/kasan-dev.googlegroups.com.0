Return-Path: <kasan-dev+bncBDN7L7O25EIBBTUQ52NQMGQEJVC42RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2586E63255D
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 15:16:47 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id r17-20020ac25a51000000b004b01305202dsf4375354lfn.5
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Nov 2022 06:16:47 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/J/N6iWX1++FsZMkZA/lXoJK6OkzXf49fPou6atFULs=;
        b=PHfnfPxR456P4UmIkSNGVNCbCZAuWKs8KxlaQY2gkMG6QB9EQwT2obvbQBR8FRNGwi
         hj/azcIn3sSgvS2TKqytmMxqyl4nXGJ0OT9wzjvQm3Me7T56YcZBuZPEt+WjlABFU0T3
         Euk0+S8sAiTsu+MomOOWTwLODncLvx6Omf/5OzXnh15L3N49tmtopDdkDHoApqjcumey
         o6HRzwpWj/lfKFTrE8gwE1usqwSYeX85ZeX7th0PHnPH9SPXgzTlt3UVUI7t6me2YSaA
         jrAZlCfADGMCNcSOTXyGwsqbdifdqTQzdWdVYZjO2tf1HHo9pnFxOC+qz3CooC2yzGMS
         ooag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/J/N6iWX1++FsZMkZA/lXoJK6OkzXf49fPou6atFULs=;
        b=yELAIleSYAlCLl7n8r9flvfoAVylhwCSfvW7MSsMYN4YWBDf6hcMZR+cSryGAF+Bso
         4luRiuOh8gTCbUS6I52fKwoQOv+1X+AY6/vyHFKuD4SkqihrzMYCiXB07WfqtdY82Nir
         9wmh4vzRFJ1lE04qqkaiwT65sLW81gk/rTb/QPUePu7m6I2SOY6vFgB8zdGumAMvKvWT
         +N5dysS4VU5KAjMDatnLn4Rylj5PMU2jzCVmYijOex4zYFp2EyKVhzoJOTcvyzy5KiWF
         LUhvFWW6l694s6fN56wVdi960E8vJYiFUgp5GQEf9eQUbHArc298YDCu8re8tyfB4DJx
         jAJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5ploAoehREmf9YYYLY3bn7HQZ2Vd2OiKkTCgUuNrS/fzS0Y8Ig61
	lfahPzFzgohrq29hTV+YqoM=
X-Google-Smtp-Source: AA0mqf5nMiZNdfB+fF9mJdRK4P8xV6hw7bL/Jog7erQtVLwGA0BTA44JTfwhfjVIXTSjyYURy3/NqQ==
X-Received: by 2002:a2e:a372:0:b0:26d:e73c:e018 with SMTP id i18-20020a2ea372000000b0026de73ce018mr6424960ljn.391.1669040206448;
        Mon, 21 Nov 2022 06:16:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4a2:3951:eac8 with SMTP id
 s15-20020a056512214f00b004a23951eac8ls146781lfr.0.-pod-prod-gmail; Mon, 21
 Nov 2022 06:16:45 -0800 (PST)
X-Received: by 2002:ac2:5dea:0:b0:4b2:2cff:8446 with SMTP id z10-20020ac25dea000000b004b22cff8446mr6113867lfq.572.1669040205206;
        Mon, 21 Nov 2022 06:16:45 -0800 (PST)
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id x2-20020a0565123f8200b004b01b303713si383494lfa.8.2022.11.21.06.16.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Nov 2022 06:16:45 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-IronPort-AV: E=McAfee;i="6500,9779,10538"; a="399853145"
X-IronPort-AV: E=Sophos;i="5.96,181,1665471600"; 
   d="scan'208";a="399853145"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2022 06:16:42 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10538"; a="709820865"
X-IronPort-AV: E=Sophos;i="5.96,181,1665471600"; 
   d="scan'208";a="709820865"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by fmsmga004.fm.intel.com with ESMTP; 21 Nov 2022 06:16:41 -0800
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Mon, 21 Nov 2022 06:16:41 -0800
Received: from fmsmsx602.amr.corp.intel.com (10.18.126.82) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Mon, 21 Nov 2022 06:16:40 -0800
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx602.amr.corp.intel.com (10.18.126.82) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Mon, 21 Nov 2022 06:16:40 -0800
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.102)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Mon, 21 Nov 2022 06:16:40 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=NEJj3EwcQh0p2RZuBG3aTMjxz4lseU9LSSbZVDk2z3sY/5GDd6cml4wbY+hJqgZig/maXJyBue9um+vhWLvvqFWbZm66UfejHAXbdv30VMuQzo+9KO7PfixdqIUU7M0WQbpE7inwwHs/GmdxsOnQrPeB7sfLl7kfAFtQO/P9NDkAa8Jg4WVZuJdImuIe71mqGlV5XvXOpJBprAXQAoDZJoyLKs3I2LTwh6ow1R8dJh2dutHFhOYBgzfK/uSfbX6mEpr9c7ePgAeCyCvKzFj93FJIr9tb+/04znsR4Xskt9oc1vCbc6GcmnfbbUjRdUJoj5/yff3gz3KIfsCx7H08yA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gh7oL0EP/uvmJ+8ZepPUGEc1qzIPkCUs2CEzc2tsJ+U=;
 b=knV6oc1nzQStXlbEk7RFDvfa0Rj0jJCjfrHEvIn2p4JXZvRUJV9ayBMBGHKXG/ENokR6JVTghXp7nz+qN5gZWqw/sh3ZLOkyWKbmM9hFWNhhaBwvMOfmSk7Pj95XnF3YtW9JDnl0C0OKXHf2YG3Acj/BLPfhGHzslEoFAlfZIN/ejYHCXmFUFGNo7kkdM5PI3iI2WZJu2mD+oJtedhSRvCo82jbOnO54NPvtdR03uJRjogn1SwznPeVzEEaUT3oNVSnIQ0XDc2pvTuuwnFGJGD5EcnZH6BjYIALrbsSRtWB3QcyLPeUNnJ+/+fxxr/KLVcamjt5MhrilTzHkkDslIw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by IA1PR11MB6172.namprd11.prod.outlook.com (2603:10b6:208:3e8::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5834.15; Mon, 21 Nov
 2022 14:16:39 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::1564:b428:df98:96eb%5]) with mapi id 15.20.5834.015; Mon, 21 Nov 2022
 14:16:38 +0000
Date: Mon, 21 Nov 2022 22:13:27 +0800
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>
CC: "linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>
Subject: Re: [PATCH -next 2/2] mm/kasan: simplify is_kmalloc check
Message-ID: <Y3uHhxWeKGyRrkYT@feng-clx>
References: <20221121135024.1655240-1-feng.tang@intel.com>
 <20221121135024.1655240-2-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221121135024.1655240-2-feng.tang@intel.com>
X-ClientProxiedBy: SG2PR02CA0008.apcprd02.prod.outlook.com
 (2603:1096:3:17::20) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|IA1PR11MB6172:EE_
X-MS-Office365-Filtering-Correlation-Id: bff33406-c341-4add-eed0-08dacbcb0147
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: bXksltyZZEic4OyqVba07EVOT/SHmcN9GsZcW1c3e9dOiabrwZZEHGPq6uKVUsUtjG80qHQ1NI/w/yn9tpwcA+65sV+SY1iyBF4ZFPDbdtuXaOVoyMQV278flOMtcWr5THZPDEN28z3tdCJ8tbTCErIBfmqcnMY+IFfDDCXsT9yQFFly0SQiGnnfJfKEDKJBmGD6id4M1MCEz/DKvl7X+LsPEDuFYxqJLNa3L28JOE6wLNO+Tszj7+2us4P0OQraPMkZKcebqFlbi5jNQSYa1ViIEh8FhdMJ+np4KsgpEARvFSKW5oKU9xmMgJQkJO3loruKxEWfJGbwxRqinZV6X7s9K3mRJRB2VEhMvjGFSWpTDDxF71DA3lH7q5e+VGPX6fM3lPAyZzuJf3ku7f4F9qP5KPrj+dIbQEcADctm/Qe2h5Qp3RtOOKvovHf7JOQ8uMJpnHIs1Mxze4gzw83gRBIvRYNWNo7XIVlb3GB1GtHdcgUXoRPwSL6u62rtD06ozO7+xJ9G3C/Y7tlJUzCRs8qTQuxunyWiDbAAkpdoG3le6uT/n+ZzV3s1VAcXpQsebx8MDvCut5K+wqKSxm2Jhpwfoafdpa3WqsaN6UC5zHAtZeytBISvxCr/7aCE+s5RFgGZb1YJWeAnMxqJNTE6DSNN9PquaKlfqkvyqtNLedYOJPhz3KWtW65hB+uGBtFh
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(346002)(396003)(366004)(376002)(39860400002)(136003)(451199015)(2906002)(186003)(38100700002)(921005)(26005)(478600001)(6512007)(66946007)(66556008)(6666004)(6506007)(5660300002)(316002)(4326008)(8676002)(9686003)(66476007)(8936002)(7416002)(6486002)(44832011)(83380400001)(33716001)(82960400001)(86362001)(41300700001)(54906003)(110136005);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uMUM31xchWUbGMi/QN5xM5kkJ0Nzx4gmZ0b9B7WHFEbTbcTXCzla8HtCrLxd?=
 =?us-ascii?Q?7WOSW15Ikdg48M+1mwOylBXuT9fItWgZiDcHY6g7Z4P/r0L2Z9uwRvrQjMMG?=
 =?us-ascii?Q?4UpOE1LjioTmEOnM7hQRMTcPe82u233sPLVzpNtKoHNmzmpYrns3XzMRYCZd?=
 =?us-ascii?Q?QFxuaZCGE3mj93KNnOV8VtCyermvW0qVhKTo6wOKPM9wJrfudH+Xcy/Pilq0?=
 =?us-ascii?Q?fSSgHEPIyNdOUttzNuKDespbJrM6KZ/U/mQYBEMP+3knIDISSjs0rBfveTlo?=
 =?us-ascii?Q?Bme+qQMno7tT0xlkZgYbwSdiO2dWd5Je9ECdP1chv+9lMWZUBOu+sGnPhMTx?=
 =?us-ascii?Q?1FUQ+CWPvCrIQqktGk/QstzxMp11JrU3KX8BEJi6vSvOkoK+kWbEcLIadS02?=
 =?us-ascii?Q?CsXKPiR9y7ae8uCNUpMPXLDfjhEOsHZS+6dNjosEhE0ZV7538y8N/vB34hTt?=
 =?us-ascii?Q?0Otyo0+Sk+GNOy/FYDkYCrBIiFZigJ0CQL4g96EXkbW5I/dcrPKesesy91x1?=
 =?us-ascii?Q?S6CLTML9hFwEW5ATUKopl9R+gO3kc8Z4ctworRtqX/Wxik+ga3HUGhiKSGkt?=
 =?us-ascii?Q?g93ZPSGngk9+799EIZaqlgLtHQfcZNrrHhYahaGK5k1GLHTSE6ykJLCHtNN9?=
 =?us-ascii?Q?eLcGdSbbjlJLvUCcMA5kQHveIn1zvgDlkM0sccXgj4tR4xLgKhPBkA22L6NW?=
 =?us-ascii?Q?Dmismg/ntsjVvfbgyXhyzm2o957XuZ7fbGzIOBUhMw3SgrOP7zI6odrTdEB/?=
 =?us-ascii?Q?EE0vsCKDSNIaoDtm5ihV049Ms2HLRqn6/cPcv4JayWssJS4aNCS9YcBvEK+w?=
 =?us-ascii?Q?Yo2QXZDoFEuO/RuzBxGHCrba/IVUfqf/9fmn18BXXJoN8cZXi7D75QZDxosj?=
 =?us-ascii?Q?48wISn61xJLWMzyqiyM0wVPqcQDiql6nO662vTalMCDPzTv6ONDXOMP/S6ye?=
 =?us-ascii?Q?I6GW9VWtmA3QesGCfPMS+G3H0B1V72EYYOhJ9yzjsxq3syD083aBp7TU28sR?=
 =?us-ascii?Q?kyhR+dMR5LwOcWY22BfFCL6AObTXsVGnCLFC9tjH/lg2sfIS0PUkFgHsiq7k?=
 =?us-ascii?Q?wkg7i3lGZpsO+TrRitaJPGqfGP/divgo4M9Jqm/23ZHBGqXJjLW/CPZunIPC?=
 =?us-ascii?Q?G5gXfO9+rat0pgf3MjfCfAZYyMn+L2Y4ranSo/dq1FJPeSsf7mjjkOPyJkpA?=
 =?us-ascii?Q?vO6n3GmAPhdQ7/nlQHbEj83TSq9GRBI4fKT7R9zSKhW/tjc72CyKBLCg2Jri?=
 =?us-ascii?Q?3cwVOLUfeT3LbKekh6D26fN5E1wT0u5JadHgZKp2DkmsIt62grIwlJSGyy5q?=
 =?us-ascii?Q?OzLaGZzmckHSfUj9W+tflY5uH84lL6OEyU92pvQ2HPMG7BVmQ5676LfvIs2d?=
 =?us-ascii?Q?hOLU40l/VFJwpHyv8DYn/ApzvebmxpYeY2uHYIADomRQaKh+gRT9tSYcN//T?=
 =?us-ascii?Q?2MqOokihlDThLgmT1Sqnmq8RrcPUmLMTGDFBNZaQCQ1prFGz+afpfyc3Y2kC?=
 =?us-ascii?Q?J2t0KeDEJGMniOGEForq5mHIcRO/pNjq9SXFudjxwxj6/Mo7Z5LIkemn2md5?=
 =?us-ascii?Q?sX6zDx832Z4XMEG1uD7AzHLCwXV5KUnoSN3Ab15o?=
X-MS-Exchange-CrossTenant-Network-Message-Id: bff33406-c341-4add-eed0-08dacbcb0147
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Nov 2022 14:16:38.8043
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: m1pwfVVD3YvbJGmilBdfiENd61UHVAJPjOBxPTNCoB4/USCzTDHDLrx1hjXpTVRGjSO46NEqtLJXjR0mmESaGg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR11MB6172
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ltRcBSGN;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.43 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Mon, Nov 21, 2022 at 09:50:24PM +0800, Tang, Feng wrote:
> Use new is_kmalloc_cache() to simplify the code of checking whether
> a kmem_cache is a kmalloc cache.
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  include/linux/kasan.h | 9 ---------
>  mm/kasan/common.c     | 9 ++-------
>  mm/slab_common.c      | 1 -
>  3 files changed, 2 insertions(+), 17 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dff604912687..fc46f5d6f404 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -102,7 +102,6 @@ struct kasan_cache {
>  	int alloc_meta_offset;
>  	int free_meta_offset;
>  #endif
> -	bool is_kmalloc;
>  };
>  
>  void __kasan_unpoison_range(const void *addr, size_t size);
> @@ -129,13 +128,6 @@ static __always_inline bool kasan_unpoison_pages(struct page *page,
>  	return false;
>  }
>  
> -void __kasan_cache_create_kmalloc(struct kmem_cache *cache);
> -static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
> -{
> -	if (kasan_enabled())
> -		__kasan_cache_create_kmalloc(cache);
> -}
> -
>  void __kasan_poison_slab(struct slab *slab);
>  static __always_inline void kasan_poison_slab(struct slab *slab)
>  {
> @@ -252,7 +244,6 @@ static inline void kasan_poison_pages(struct page *page, unsigned int order,
>  				      bool init) {}
>  static inline bool kasan_unpoison_pages(struct page *page, unsigned int order,
>  					bool init) { return false; }
> -static inline void kasan_cache_create_kmalloc(struct kmem_cache *cache) {}
>  static inline void kasan_poison_slab(struct slab *slab) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
>  					void *object) {}
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 1f30080a7a4c..f7e0e5067e7a 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -122,11 +122,6 @@ void __kasan_poison_pages(struct page *page, unsigned int order, bool init)
>  			     KASAN_PAGE_FREE, init);
>  }
>  
> -void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
> -{
> -	cache->kasan_info.is_kmalloc = true;
> -}
> -
>  void __kasan_poison_slab(struct slab *slab)
>  {
>  	struct page *page = slab_page(slab);
> @@ -326,7 +321,7 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
>  	kasan_unpoison(tagged_object, cache->object_size, init);
>  
>  	/* Save alloc info (if possible) for non-kmalloc() allocations. */
> -	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
> +	if (kasan_stack_collection_enabled() && is_kmalloc_cache(cache))

Sorry, it should be: 

 -	if (kasan_stack_collection_enabled() && !cache->kasan_info.is_kmalloc)
 +	if (kasan_stack_collection_enabled() && !is_kmalloc_cache(cache))

Thanks,
Feng

>  		kasan_save_alloc_info(cache, tagged_object, flags);
>  
>  	return tagged_object;
> @@ -372,7 +367,7 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
>  	 * Save alloc info (if possible) for kmalloc() allocations.
>  	 * This also rewrites the alloc info when called from kasan_krealloc().
>  	 */
> -	if (kasan_stack_collection_enabled() && cache->kasan_info.is_kmalloc)
> +	if (kasan_stack_collection_enabled() && is_kmalloc_cache(cache))
>  		kasan_save_alloc_info(cache, (void *)object, flags);
>  
>  	/* Keep the tag that was set by kasan_slab_alloc(). */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 8276022f0da4..a5480d67f391 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -663,7 +663,6 @@ struct kmem_cache *__init create_kmalloc_cache(const char *name,
>  
>  	create_boot_cache(s, name, size, flags | SLAB_KMALLOC, useroffset,
>  								usersize);
> -	kasan_cache_create_kmalloc(s);
>  	list_add(&s->list, &slab_caches);
>  	s->refcount = 1;
>  	return s;
> -- 
> 2.34.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y3uHhxWeKGyRrkYT%40feng-clx.
