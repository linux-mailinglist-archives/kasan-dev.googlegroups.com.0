Return-Path: <kasan-dev+bncBDN7L7O25EIBBKXJ7SNAMGQE7VLOVEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6113D612F0B
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Oct 2022 03:36:27 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id i5-20020a0565123e0500b004a26e99bcd5sf2829927lfv.1
        for <lists+kasan-dev@lfdr.de>; Sun, 30 Oct 2022 19:36:27 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CRz3aTOOEq56Av7GrRZpYX6sStfPG7t9blwylf1mtPE=;
        b=IV3Et2UtiJ0od7BLpIm7IrxUsGGnbFlMygEUw+bjDuoRkzbe/h1rgmqzTTraofL0oY
         cUSVGRJL+hgaGvpzRVofYoidKxBPOg9fRbNnhTvY/rUCim/MNmpP72/0d6VXyw89qNk1
         6f/LHmM0FlVFgvGgB1lQ736/YmlDo1Ib5XrLNyq4hDdSoZkglYPHbb7q5jwCO90RP5f+
         Tyou7Di98ci7Pj1N7sM73DwoEBYtVr2Gbe0S01yY6UyDZ7RZN7IXDuV9bX/YswguPj2D
         vLpchIcMsMddaGtQKWFr1dkIJeoLYuwJaKeE+6jJ/nhJx4kwImP3K+nkfRvWWHcqABw5
         HDFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CRz3aTOOEq56Av7GrRZpYX6sStfPG7t9blwylf1mtPE=;
        b=KiOJmSJolyPO7DpReoQf9DznUp9uJtGT0u0DfbWU87yedj5+qV7xnMPhn2+hXWF28d
         hS2HNwGWkp+aNdVqAWqLI1kLrgTSlzMaOYIxajBb9e74L+E/HMFk9HbM3gj2GDAYVrIg
         eNSJCDyyw6yanLYU532ih+7JcwhruEAia3t2fUA28R52XgwaTlro50ci3xA6e1832ZTf
         lLAraGJXHN2LPpwDcJbhF1EnX2N/ABFb1cGu17eCpek1I6otLAWLPb/rrLeDJdj8vFSV
         lnzkep/TTxCkvBhIEgI/KkoCb2nWzTyNvqPxbTIiDS3Ffbt6SWsbUPUuVwQKcYUJzPsB
         ++lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0PHfMzqtsiOUyvWZlzDzxhcPwN+3sTisu1ufG20NRc4iswe7Xj
	wYCmOKajAHsSU4z3Y7C4f68=
X-Google-Smtp-Source: AMsMyM59Hhd4SaXBiRY3BTBlWG7V8UcR2PjPSKU+Ns3DeMZUgs6NhHnHr1KBY6dI2Y2JyioPbrAmTg==
X-Received: by 2002:a05:6512:110f:b0:4a2:697f:c39a with SMTP id l15-20020a056512110f00b004a2697fc39amr4150496lfg.685.1667183786707;
        Sun, 30 Oct 2022 19:36:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58f3:0:b0:49a:b814:856d with SMTP id v19-20020ac258f3000000b0049ab814856dls4895464lfo.1.-pod-prod-gmail;
 Sun, 30 Oct 2022 19:36:25 -0700 (PDT)
X-Received: by 2002:a05:6512:308d:b0:4a2:5958:3443 with SMTP id z13-20020a056512308d00b004a259583443mr4435140lfd.208.1667183785478;
        Sun, 30 Oct 2022 19:36:25 -0700 (PDT)
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id u16-20020a05651c131000b0026fcb9f003csi185436lja.6.2022.10.30.19.36.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 30 Oct 2022 19:36:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-IronPort-AV: E=McAfee;i="6500,9779,10516"; a="288518443"
X-IronPort-AV: E=Sophos;i="5.95,227,1661842800"; 
   d="scan'208";a="288518443"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 30 Oct 2022 19:36:22 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10516"; a="758686127"
X-IronPort-AV: E=Sophos;i="5.95,227,1661842800"; 
   d="scan'208";a="758686127"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by orsmga004.jf.intel.com with ESMTP; 30 Oct 2022 19:36:22 -0700
Received: from fmsmsx601.amr.corp.intel.com (10.18.126.81) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Sun, 30 Oct 2022 19:36:21 -0700
Received: from fmsedg602.ED.cps.intel.com (10.1.192.136) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Sun, 30 Oct 2022 19:36:21 -0700
Received: from NAM10-DM6-obe.outbound.protection.outlook.com (104.47.58.102)
 by edgegateway.intel.com (192.55.55.71) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Sun, 30 Oct 2022 19:36:21 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=jhYJ50gsm/ktnVXV1U2hLP15avKsgJhKAO88X+gK9UbS7JLP4Ei16EZWdNm+wW1OIZJ+hBxtGrwlXPeErKbbi88kTZdpxpOJGPrEMKxBl7Y5rPvXWO63kDgzhBY7sM9bHdFWuiw2EDrUnT6Y4OwX4PNq9X1FCS9F0TYSboflRMnXwfpjNjc7n5aB4rjdR4YHG1oF/YUbEVBda8KCXFz7lf7Ly3zwSjOr1+8NR8AuAEc4U614yVpRQlwRPU2onoVE7WcHZSqvCqFwVVlD34SK6eHa1T7qbjKskLavvAE9kVVuUqIfQQNCe7ULpbV3uutPqqdsvNX2zsEoMCDFmrAD0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+CyAb5wwz1hHCLaxWh+DSaUNxM06UkO6ScqSQUc6Mdc=;
 b=NuV3AcIXjtvHpvZ3XtAHM9QfaCrr4jww1I+iqtJsObbvlZAl7J/FKDZsg+xklixKYThfUtqN/zE7wCDCx+a9WVaNEh+NesdNrjuEJ/L+d0KzFWuV8BTLOc1CJGmp4W7k7+X6bban3OjYeH6Sa32sv6cE48A9PG0UP6f0RF/nTZ9dfHFDMoi7ycAfYNBe/WsDOGqBHFk5+uHRQhH6eaIhORWKHlXSflICW9Yn5yl8Kf2vSotJWYUoctrNGLys74E/sIm+YcbLKXY4MxGQEXnB9wOnVnxRR3bTx4ZEtOXToeGDn8jHwVVwxoidMcKbSoiuB06FWhHuT4MucLX9Ly6R+w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by CH0PR11MB5361.namprd11.prod.outlook.com (2603:10b6:610:b8::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5769.19; Mon, 31 Oct
 2022 02:36:17 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::3f8d:1406:50e2:7bcc]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::3f8d:1406:50e2:7bcc%3]) with mapi id 15.20.5723.033; Mon, 31 Oct 2022
 02:36:17 +0000
Date: Mon, 31 Oct 2022 10:36:07 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>, John Thomson
	<lists@johnthomson.fastmail.com.au>
CC: John Thomson <lists@johnthomson.fastmail.com.au>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>, Andrey Konovalov <andreyknvl@gmail.com>,
	"Hansen, Dave" <dave.hansen@intel.com>, "linux-mm@kvack.org"
	<linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, Robin Murphy <robin.murphy@arm.com>, John Garry
	<john.garry@huawei.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Message-ID: <Y180l6zUnNjdCoaE@feng-clx>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz>
X-ClientProxiedBy: SI2PR02CA0011.apcprd02.prod.outlook.com
 (2603:1096:4:194::20) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|CH0PR11MB5361:EE_
X-MS-Office365-Filtering-Correlation-Id: 2cd44b72-b8fc-41ae-e23b-08dabae8afc7
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: f62svTTxj0peZg65S5TjqLUX2gPIVv5K3fstMhHJV9F7f8sDYiG18Kp+S/w6tamTJJM7J/Lu4t3tKHkQgOpvibT6UCuPu9VVmgMFsujxyn3h24m3diJr3sivcZjHGDPuEjqCKARECZqUB+7BsepfiD2XO+08vMbBg1jlaN4S3j2jfYtfae1z7eHD6L6/a01iFb7gtfqIvtikyl6xegeB8b/s+yt60TdQB1n2WW9NccP7sk8PxCFMCo64oQeT24h0AQE7wsOYpHH1TKqxBZfzFzHHanXmjc1U5o0Brd7R60zVbHkQ/aJt1WGtJTZJWAqvdl8tGsy+fD7IDxHZUDThbXPcX/B8VCRMRxqi0tv+noyQmB60ivBv7Bh/VK1Z2hjVCr9m5ri1H6/UjtMuZdfY1xkyfa8/aoEBMrE4evM7qVJmByr3LAaANefpuYRZUZsEAArAYrFr+raAu5wABTyuj76V0pqOfYtgr+NjAeFPysVDT8bYdgrUKpzpGcKEoTJsz2jvZ3GnKfhG0v88mCmjofz/qvnAWAS1/sbfm0MP8EzjKYj7KjFA4cCO0MDEKTbrPXL/hvwYOkW//AhtCSWZ/rAVK3+WUmKcI3CX36/QhskaHlQj6r/QAC5LvkAow3vRoEhu1jefqHZFuIpo89O7/1t6QiHGeo58uXyhe1v1QyWtyCUjPP9gu0PnvavgH/fiWy5qskodHACZ69QXsGGLXQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(346002)(376002)(396003)(136003)(366004)(39860400002)(451199015)(33716001)(6486002)(82960400001)(53546011)(8936002)(9686003)(6512007)(26005)(54906003)(110136005)(5660300002)(66556008)(66476007)(8676002)(316002)(6506007)(7416002)(6666004)(38100700002)(478600001)(86362001)(83380400001)(186003)(66946007)(44832011)(41300700001)(4326008)(2906002)(66574015);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ZYzN1Exo9Klcn2+uCoXvDp1krh0Hu5jVZf5erW+CLpoJz+WoIDD3RzLAnl3Y?=
 =?us-ascii?Q?cAgIyl0BqiRA/C7cETieqzYm9F/bcmSRmZbc8r4SwPFpxTQYiezhvDGiCP22?=
 =?us-ascii?Q?zyoeAranHZM7zbnN0LjusMBRXv157xoNSH3JRlDpC/1KTPFnknbVhEwYTtBp?=
 =?us-ascii?Q?ZO74zDKWVXu/px9LDlsPEcYsDCML30tFiSnEDBw6IdlZcFP5zXG392j2BPgT?=
 =?us-ascii?Q?Ma9m6Zu/7sEpQU1rcldu9FYuF/igWX6tfESD4uZO8a6kOLFSXofiqnwegEqy?=
 =?us-ascii?Q?AgQ/0NeCbeFx1zDa4azKCOUyLXasTiEAtMi1mRQKonuOSmJ+Rd7JFKzbOrG/?=
 =?us-ascii?Q?8+vK/lUIBbJRzg0cdTjnR2BbVOxVEKbU7yVbxLCQaLomsia4ZkXSTn6tIqth?=
 =?us-ascii?Q?sVfFEf9Mcx59sQwBJBVqWMP9bkmwsd6o2dwbwO1LACG4J19hj/Ehk178lc6D?=
 =?us-ascii?Q?JCJy+1/ncoQTjW5q6jHLNPTaY+M6viERikajT8FMwSxYi31/jxIb6DEHmq9c?=
 =?us-ascii?Q?C3kXrmMKaYJ8wOWeBLNVeAHNIhWBxw+04HSl2GbbJpx1q7+9fH/7OMCZhf/9?=
 =?us-ascii?Q?Zx3qkU2toQpHfpKqkYfIaqP7bJOLQFCanH420ocV6NAU8LVDqXMPygK9Wypk?=
 =?us-ascii?Q?LZo9QiuUQhcpa0PIBjQ2mvv93lobOzwYK5vVg4yIJrIjomrtm7KRhVPbkPEN?=
 =?us-ascii?Q?9KlPFqV/APVCJDhvgoGkVCBu1WesIVYZQ1nMjZSrHFLpgh5isDJumPKpN4va?=
 =?us-ascii?Q?QjITn4VDYeunY1U3GD6aTTLaQzm4clRDxZ++RwMk1TTVNnKB4+a1NO4lUm1p?=
 =?us-ascii?Q?OJBgmEQmer0vWf22D29276DNkjyYTwgWdgMFDz/WM2ZeQaKeeVyiIfruErDj?=
 =?us-ascii?Q?zsJeczRDled7r5ovoAmt3wo16+ldL4/OWEAg07LCMwalx7SL1w2uNTd4rX+W?=
 =?us-ascii?Q?mr8sfLujdEn4hQ+Y9sQrxzlt+YO/Vns/UBk7AXrZ8Cpk2qaI5V/JSUQ4Ejd9?=
 =?us-ascii?Q?izS2CBN4NichpawaSL2OQORmwsY60sT60mgCdF49dVRbhQGn5jYgiY0GGUK3?=
 =?us-ascii?Q?xhJwI90LflQNoMF5J4QQbuPlOAI0f26+cIcKNHgL0F/rOJ+N+RpHXJXYgsHU?=
 =?us-ascii?Q?cJ6L6YFfVA6b8ldIfvmcX6Qr+gcrCuzDjhgxNdeommAnGI1+kOsDwQvAEzUM?=
 =?us-ascii?Q?AdsKeNx2j5v9Bt5njM/P37PS2ddMwVpoe/M5B1Y0qbV0T/VQLdVznrhYHpGr?=
 =?us-ascii?Q?ALNzO9xy3o5dytw2G31Z40wkHxB5AJkxWJxvUBF8OZcMywhvZV2Xh+a9IzOl?=
 =?us-ascii?Q?sY+AY0C1wT//dDPa9s+ULZrWpecBZzYWZZP6wYjH1QQkPk/agMFqbmpzWi+e?=
 =?us-ascii?Q?DdQFXv+PSZSXG7YokOUrUPQ+D0l7emXBAK8RHG4HgJRQY07btp/NaJZcvves?=
 =?us-ascii?Q?AqJyc9O+wMj18Y9PliaMiLTilyw79FHGkulsvD10isn+0qWtO5VqAJeqhqJO?=
 =?us-ascii?Q?gEX+JP5M1lUX/KxVkNfEwAWlZSHHPGlGjS96D7P0GXM7yWGgLpq+CHeH3hpS?=
 =?us-ascii?Q?savPpNAwUzG5eQqITaPROK88/lnz7XjTKfL7xtUN?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 2cd44b72-b8fc-41ae-e23b-08dabae8afc7
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 31 Oct 2022 02:36:17.2512
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: hj49g/3G1R53mWKRRBpJM6+cdAZ9QMX1Jw/m7piLCzAdRt65RScAmsYHf+rznWNHw+3rogUFNzOYh1+KFUsiIw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR11MB5361
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=SWCAV909;       arc=fail
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

Hi John,

Thanks for the bisecting and reporting!

On Mon, Oct 31, 2022 at 05:30:24AM +0800, Vlastimil Babka wrote:
> On 10/30/22 20:23, John Thomson wrote:
> > On Tue, 13 Sep 2022, at 06:54, Feng Tang wrote:
> >> kmalloc's API family is critical for mm, with one nature that it will
> >> round up the request size to a fixed one (mostly power of 2). Say
> >> when user requests memory for '2^n + 1' bytes, actually 2^(n+1) bytes
> >> could be allocated, so in worst case, there is around 50% memory
> >> space waste.
> > 
> > 
> > I have a ralink mt7621 router running Openwrt, using the mips ZBOOT kernel, and appear to have bisected
> > a very-nearly-clean kernel v6.1rc-2 boot issue to this commit.
> > I have 3 commits atop 6.1-rc2: fix a ZBOOT compile error, use the Openwrt LZMA options,
> > and enable DEBUG_ZBOOT for my platform. I am compiling my kernel within the Openwrt build system.
> > No guarantees this is not due to something I am doing wrong, but any insight would be greatly appreciated.
> > 
> > 
> > On UART, No indication of the (once extracted) kernel booting:
> > 
> > transfer started ......................................... transfer ok, time=2.01s
> > setting up elf image... OK
> > jumping to kernel code
> > zimage at:     80BA4100 810D4720
> > Uncompressing Linux at load address 80001000
> > Copy device tree to address  80B96EE0
> > Now, booting the kernel...
> 
> It's weird that the commit would cause no output so early, SLUB code is 
> run only later.
 
I noticed your cmdline has console setting, could you enable the
earlyprintk in cmdline like "earlyprintk=ttyS0,115200" etc to see
if there is more message printed out.

Also I want to confirm this is a boot failure and not only a boot
message missing.

> > Nothing follows
> > 
> > 6edf2576a6cc  ("mm/slub: enable debugging memory wasting of kmalloc") reverted, normal boot:
> > transfer started ......................................... transfer ok, time=2.01s
> > setting up elf image... OK
> > jumping to kernel code
> > zimage at:     80BA4100 810D47A4
> > Uncompressing Linux at load address 80001000
> > Copy device tree to address  80B96EE0
> > Now, booting the kernel...
> > 
> > [    0.000000] Linux version 6.1.0-rc2 (john@john) (mipsel-openwrt-linux-musl-gcc (OpenWrt GCC 11.3.0 r19724+16-1521d5f453) 11.3.0, GNU ld (GNU Binutils) 2.37) #0 SMP Fri Oct 28 03:48:10 2022
> > [    0.000000] SoC Type: MediaTek MT7621 ver:1 eco:3
> > [    0.000000] printk: bootconsole [early0] enabled
> > [    0.000000] CPU0 revision is: 0001992f (MIPS 1004Kc)
> > [    0.000000] MIPS: machine is MikroTik RouterBOARD 760iGS
> > [    0.000000] Initrd not found or empty - disabling initrd
> > [    0.000000] VPE topology {2,2} total 4
> > [    0.000000] Primary instruction cache 32kB, VIPT, 4-way, linesize 32 bytes.
> > [    0.000000] Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
> > [    0.000000] MIPS secondary cache 256kB, 8-way, linesize 32 bytes.
> > [    0.000000] Zone ranges:
> > [    0.000000]   Normal   [mem 0x0000000000000000-0x000000000fffffff]
> > [    0.000000]   HighMem  empty
> > [    0.000000] Movable zone start for each node
> > [    0.000000] Early memory node ranges
> > [    0.000000]   node   0: [mem 0x0000000000000000-0x000000000fffffff]
> > [    0.000000] Initmem setup node 0 [mem 0x0000000000000000-0x000000000fffffff]
> > [    0.000000] percpu: Embedded 11 pages/cpu s16064 r8192 d20800 u45056
> > [    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 64960
> > [    0.000000] Kernel command line: console=ttyS0,115200 rootfstype=squashfs,jffs2
> > [    0.000000] Dentry cache hash table entries: 32768 (order: 5, 131072 bytes, linear)
> > [    0.000000] Inode-cache hash table entries: 16384 (order: 4, 65536 bytes, linear)
> > [    0.000000] Writing ErrCtl register=00019146
> > [    0.000000] Readback ErrCtl register=00019146
> > [    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
> > [    0.000000] Memory: 246220K/262144K available (7455K kernel code, 628K rwdata, 1308K rodata, 3524K init, 245K bss, 15924K reserved, 0K cma-reserved, 0K highmem)
> > [    0.000000] SLUB: HWalign=32, Order=0-3, MinObjects=0, CPUs=4, Nodes=1
> > [    0.000000] rcu: Hierarchical RCU implementation.
> > 
> > 
> > boot continues as expected
> > 
> > 
> > possibly relevant config options:
> > grep -E '(SLUB|SLAB)' .config
> > # SLAB allocator options
> > # CONFIG_SLAB is not set
> > CONFIG_SLUB=y
> > CONFIG_SLAB_MERGE_DEFAULT=y
> > # CONFIG_SLAB_FREELIST_RANDOM is not set
> > # CONFIG_SLAB_FREELIST_HARDENED is not set
> > # CONFIG_SLUB_STATS is not set
> > CONFIG_SLUB_CPU_PARTIAL=y
> > # end of SLAB allocator options
> > # CONFIG_SLUB_DEBUG is not set
> 
> Also not having CONFIG_SLUB_DEBUG enabled means most of the code the 
> patch/commit touches is not even active.
> Could this be some miscompile or code layout change exposing some 
> different bug, hmm.
> Is it any different if you do enable CONFIG_SLUB_DEBUG ?
> Or change to CONFIG_SLAB? (that would be really weird if not)

I haven't found any clue from the code either, and I compiled
kernel with the config above and tested booting on an Alder-lake
desktop and a QEMU, which boot fine.

Could you provide the full kernel config and demsg (in compressed
format if you think it's too big), so we can check more?

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y180l6zUnNjdCoaE%40feng-clx.
