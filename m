Return-Path: <kasan-dev+bncBDN7L7O25EIBBU5Y42MAMGQEQL6GZDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 71AF15B15CE
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 09:40:04 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id o22-20020a2e90d6000000b0026b8a746a9dsf429072ljg.6
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 00:40:04 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=felapj3dAN9SOBD8sLAoeaVSQagpQq4aXmm8afKzkVM=;
        b=SYX7ZCvpWaga1ufMm/HUdOLgsKcB+a+2KpK5P8xlJ9XvdpZYgvHqU4+35XlhpQ8Y8S
         UqfArLKUEjWIlQcgTj8NPwUe843gMcLRzgCkDqJ+MZpxq/TleG93A2oWVRCcDWmr4vm/
         OIMC6+jUynlVrFEJ8As/3gA0KQZLKpmP+I4j9bvHFpr4gLtSL7cjbH4VAk8vYjxVNmRO
         /xwrsKPXE1y4baeO+TPZEkFr2oVlq47s2Km2nQg0kHSI7uvGItwYis2jGbs8AOooUloK
         roDAKoryb2ezJ7XMfOUJnYPpxv4KY5pUjtjw/0rSM37m10b2rNN5Me49nuEC29zy9ttI
         s4dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=felapj3dAN9SOBD8sLAoeaVSQagpQq4aXmm8afKzkVM=;
        b=iZTp/aHsnOsEfBAr/FzYHPHw34mGgqxz/Z1l26FeggyOGYMIQF2YXqCx1j2RPkYeLW
         qHcXXy5cogioqfNk2mpnh1hc+sMNND8e0+1yYOur+Pju0PvqqL5kRQcQLs6cJL4aShXO
         aH3e2TFKsy5YxFFURu/k7cQoNyRxYtAKbEs7hfANUrGBnarE2xMNCB3bNUuSXwHqwO+P
         MikbGrncjVwN+B8kWg3d7kLjMyQ8KEN3j5119QjUqq5zQ0pm6EdDVKw/KR7FpmWuYmmv
         EUY5W5QFHxdPL46uXACv9op2GkKu2Z9TzwBzbkfgsQR7GD4yTLzzWTX1Y3VbUL8/+O1I
         UMxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo06Pm1a+YUtlOukFX30EIhwL8c/9WSORuvD+IGz23s5hpykv/dT
	qKH+jmpXdnplE+TWU2vPu+Q=
X-Google-Smtp-Source: AA6agR4I1Weo4KC1CJaqxh6Sqztm4rZLOwYBQ4dd4j8+Ubuz8Vvx8zeikLGtd3gI5Xcm94ZTUVXCTQ==
X-Received: by 2002:a05:6512:754:b0:494:b3db:1b61 with SMTP id c20-20020a056512075400b00494b3db1b61mr2621992lfs.556.1662622803778;
        Thu, 08 Sep 2022 00:40:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:210e:b0:48b:2227:7787 with SMTP id
 q14-20020a056512210e00b0048b22277787ls677042lfr.3.-pod-prod-gmail; Thu, 08
 Sep 2022 00:40:02 -0700 (PDT)
X-Received: by 2002:a19:ad03:0:b0:492:d9e0:ef42 with SMTP id t3-20020a19ad03000000b00492d9e0ef42mr2328143lfc.327.1662622802755;
        Thu, 08 Sep 2022 00:40:02 -0700 (PDT)
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id z17-20020a05651c11d100b0026adb8f2e68si65827ljo.5.2022.09.08.00.40.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Sep 2022 00:40:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6500,9779,10463"; a="297098373"
X-IronPort-AV: E=Sophos;i="5.93,299,1654585200"; 
   d="scan'208";a="297098373"
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2022 00:39:22 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,299,1654585200"; 
   d="scan'208";a="740579675"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orsmga004.jf.intel.com with ESMTP; 08 Sep 2022 00:39:22 -0700
Received: from orsmsx607.amr.corp.intel.com (10.22.229.20) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Thu, 8 Sep 2022 00:39:21 -0700
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 orsmsx607.amr.corp.intel.com (10.22.229.20) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Thu, 8 Sep 2022 00:39:21 -0700
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (104.47.56.49) by
 edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Thu, 8 Sep 2022 00:39:21 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=VTKNy+l5QjnKW5Is3e58YsyY7dsKO75qupu2+dAtZgtfcbKCvvyPlJkvAZ/5p6uUrEJPrK9CwAIqCw/S/LW3ujPnq0seMP8gEL1kPcBSLHvVhlhxaAf8dtv7rmDYvg1vSf+eFxXSi1ShLVzoJFLCQkIIVMMeY/eNf09EuEvqX5/3XohJkwbWkXr7oOfrWQG6QUJu2qjox2J0nM7w/FCJHwIUtAtqvwb+zhSUr9yYHDPRQEoZQ/7/5DfRYf7qROYxLN2WFgyGFBBDxjfuxtx/bAJbLbMdDpzIqa/EudJzH7Ipy5iqgPQ3zSPL0igfiXul4F9G4V29tZe3qHOa0sHrGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HrKU3z79hQUKlS0FTmf5Co9tZwaYE8vTfPGCWHhAAhk=;
 b=Abs68qsQwVh5/98HaHtZP7hnW9eMOK9qnCNjeOkVsh+t2hVPPPr3y6GOiLbKjNvzH2bMoxga1fQNFA7EQE5jknb+/zvbs89ydTYztp9PDTVnEzUZOZkM6Tyz6VlqZ7FJSVzRVxg5dZTBElAq8Emo3wDRAoOxWV1CUU9Vk4lpnIvZB0PAfqnbCzpCPqobEW3U+N5UAcl16+FeJAuBBR3hhhdG3IKUH+bWi3FRR+xmhiX3WKUAVcUV3Yvb8fNfSB4FL804J8UjTX0h1MCF/4FzRn6e8J7NVQSAC6wv7MyU0VzN66/w7ki9wuBouUtWH3lneTYN+HzUMAWLvojeXkqT9w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by MW4PR11MB6863.namprd11.prod.outlook.com (2603:10b6:303:222::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5588.18; Thu, 8 Sep
 2022 07:39:12 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::4c8f:1e3c:5288:d77e%7]) with mapi id 15.20.5588.015; Thu, 8 Sep 2022
 07:39:12 +0000
Date: Thu, 8 Sep 2022 15:38:37 +0800
From: Feng Tang <feng.tang@intel.com>
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, "Dmitry
 Vyukov" <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, "Hansen,
 Dave" <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v5 2/4] mm/slub: only zero the requested size of buffer
 for kzalloc
Message-ID: <Yxmb/W4wmJnwA0Qt@feng-clx>
References: <20220907071023.3838692-1-feng.tang@intel.com>
 <20220907071023.3838692-3-feng.tang@intel.com>
 <YxixXhscutM0nw66@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxixXhscutM0nw66@hyeyoo>
X-ClientProxiedBy: SG2PR02CA0126.apcprd02.prod.outlook.com
 (2603:1096:4:188::11) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 3538e9a4-07ed-4fb0-056e-08da916d3945
X-MS-TrafficTypeDiagnostic: MW4PR11MB6863:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: Tqb3x8dzPV5WFzjc0IMQgdmsoct5A6ooP5Pg2nn9IXT1BhTi88/lkXpI8+1G+ltm2ZtDXyov2TqOpFYY6PpVv+3iBAvgG2bwDV58vbvrXm/qwETsvE8dRIt/+2rAV6HJx3aE1LDPkqfxzPFQIc2HqROIriB/P82rdlM6gMBSDE2Q3+jyVcvw5TQPOlB/M/CjjKlVayhN7EwzBmGXoUMY2jSNjLunLZD/qt/Ta93sTWR7ixShX0hJXFDQ/vmbZAakjxgKcKIRNpVoRNK1t+yhjKiu8qrVbKMgb+i12XyTrYEjxJJ0bybhwlLZckQWqwUFJzatdePju2WKhgZdxe2Lx/cQFjhdM/04jEeHKZHjdE0yzFhAWMy8wYwkTi5YRA478qwWVerQalu62cd69Une4KZ6Sv1qiaYNpPVNZL4Wnp9sdT2FTuZFPIBQEW92tiAeI19Ak+B/T7okbqVQPsDEs4xzsfvCSpsLKtkT30FXFhTFyHn5rFPWzcUspH64TNYv/+/Op2HRgspYRjx9qlskgLHumhPHOUpETmfZE9HoJS8axbm/m/yey8FPsA8BMGIuvXbTsS5Qb8j6eUbpALBsMlNebdQ5XL3Sd6J2BO8XanKY3SaL7zzN/SvyulHOS2JPgmbwwGK2F+w2EfMJ0K3x1DRx4Sxd1vjxd6oCrmVZE0K2hEj/VrKxgICEfEUrwSgu0/Ru+B8VLgPjZXX8eKwRUg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(346002)(366004)(396003)(39860400002)(136003)(376002)(41300700001)(478600001)(6666004)(26005)(7416002)(6506007)(44832011)(33716001)(9686003)(6512007)(8936002)(2906002)(82960400001)(5660300002)(38100700002)(186003)(66556008)(54906003)(6916009)(316002)(86362001)(66946007)(83380400001)(66476007)(8676002)(4326008)(6486002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?I8Sq/pwGYWcE8jz0mDzvo2MVcwz/C17M/6FzFaUuv5pI+8NEk4r2PCvLkpNv?=
 =?us-ascii?Q?gwLrhBRAxsAbfvGzdegSITvM6T+MluhUwo8M6ERP5skWPk4vRPNS3OIs8sey?=
 =?us-ascii?Q?/8JliCY6toC0v+7R6sFGopzyJscbkqBkms/VEfueXzf95dCWeF9CUG/iXOWs?=
 =?us-ascii?Q?rJCjSNymkbAg8AzaZb2V5/d2VJWEC1rn0gpr2+toOLqKfAwgtIVyqkzQ9AOs?=
 =?us-ascii?Q?URmFMKmgTPOBWKFroLKAJJh4FAg4tTVM2aCEQNSRs8HL5yna2kFnOKR7zfL8?=
 =?us-ascii?Q?90YUIe2bcmX7WY6S5pbmQ8jqY3UMyS6U32AcaOe+i1/tFIe5R7rUkU8qbYFj?=
 =?us-ascii?Q?4Z9DkbtbHW8O/jvoi0rlwkbhtHOztS62YWIXttJz34l4INWIu9FvSDlanc9T?=
 =?us-ascii?Q?9egCt14qtmS9UQ+5sB/ZxAPMGUHmmbMQnnHCgAQz2UVnYXr9X0l3bp6PRC/A?=
 =?us-ascii?Q?iyIqdcLE3gmcbKecoJ4885u91CxekAM2SmBKz8/KEjZNTkGxJ5zrNwn11YCm?=
 =?us-ascii?Q?TIpedQaYlD783uKc3Lwefu1y0PZ6vBKF0EyE/yQdu3wsaRC7BUcT2bB+tA98?=
 =?us-ascii?Q?YwA5bwK5oMra7F+z/Dq+r0nq3JSyxjikNiVfDUHWcNusfXYAPY2XyWxFx2EB?=
 =?us-ascii?Q?Hgiz84IpYodQAKEngs6/4YYSi8FnWsdjVqQl4w53TNJa5/LJJxeP9BctBXK8?=
 =?us-ascii?Q?AUhVzUm1HEgshdjtVw3wxfV6p9lnrO20NjZkt/k4/wA0NYYOYbJcLU/yd8t2?=
 =?us-ascii?Q?HU5wyKwmCdkoyeNC8YmJrVRJJyWrzsQvHvF6QrjLvJSjLfdB0CY5TEQ5R4fT?=
 =?us-ascii?Q?WkVq0D6D+rYBMUqz/f378UcyYCOF4rH24QztdFAI/XzK/PsGx5WYIcORzcWM?=
 =?us-ascii?Q?ZgUwU9rqXjqOg+6dGz+Mb5E7jInTT5+60+IOxr9H5lXqp4rRaSFhNN0OlrtL?=
 =?us-ascii?Q?cLGTh+MZ57w3LP/VyUnv4ubcGtIGYVUY/ePo2CYVi8bX7XvMIWEkycegR9iM?=
 =?us-ascii?Q?HAtcLy9Hnsxs5bHioN6rHexIpbkyx5pEcmpYbBomweGamNtZ8yE7oNkuZgoe?=
 =?us-ascii?Q?QXrOIcICPWHP4QIvG3uYdjWFlmKkVfydqmxaQBxj5MxUs68PGAqPB5lnzuT8?=
 =?us-ascii?Q?2COoBTsB6hmdQYnSg1PpFx8Z4pQrvAUKi8R9cXNkOVjhr3L1z9pRpdKlDD3g?=
 =?us-ascii?Q?xMrF9V2ZrfgFrQe6Mi71IS4wCrZroOYRCqHcN0yz0kYwuSra5ZtLk6YmQzYd?=
 =?us-ascii?Q?6uFyEjA7+S7vPoxc+tUeyf2Uc6QsNrega6p7Uomq5zo8p65pdnxH1LuYxDxj?=
 =?us-ascii?Q?XruRmZhqlsIpB8vLQOhmoIw4CxrhXXEeut4PtS/OW9ELN+UFtWO1M33j2jS6?=
 =?us-ascii?Q?Y3ayaSlXoeikWwyYXdSt0g41lyt6eICz+z03EjcCUPQlAJTu1QsT2t0jtuY/?=
 =?us-ascii?Q?YO4InW80leo2hVYR5q33OjyaUHW0elu6eS6J2b9oX6Wr37sxb4lTU7H2zudT?=
 =?us-ascii?Q?qq2Z+AyuHqJ48Y5KDxl0LCbCsX1i3ejFP/u5925iHX7ZuLvFMvjo0u3xMx72?=
 =?us-ascii?Q?3co4z4AjZyOk9/PSTmKsHusG6cazBUwdCVS1EhLS?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 3538e9a4-07ed-4fb0-056e-08da916d3945
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2022 07:39:12.5727
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 3Br2P7REQv8q5/k28guH0OiAA8HxU3VpajMsKkACUTKDOcx3Jn5Mf9iFuMqAjOFWCczaDZXd4XmOJE5aYplqhg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW4PR11MB6863
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=M8hJwGfu;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.115 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Wed, Sep 07, 2022 at 10:57:34PM +0800, Hyeonggon Yoo wrote:
> On Wed, Sep 07, 2022 at 03:10:21PM +0800, Feng Tang wrote:
> > kzalloc/kmalloc will round up the request size to a fixed size
> > (mostly power of 2), so the allocated memory could be more than
> > requested. Currently kzalloc family APIs will zero all the
> > allocated memory.
> > 
> > To detect out-of-bound usage of the extra allocated memory, only
> > zero the requested part, so that sanity check could be added to
> > the extra space later.
> > 
> > For kzalloc users who will call ksize() later and utilize this
> > extra space, please be aware that the space is not zeroed any
> > more.
> 
> Can this break existing users?
> or should we initialize extra bytes to zero when someone called ksize()?

Good point!

As kmalloc caches' size are not strictly power of 2, the logical
usage for users is to call ksize() first to know the actual size.

I did a grep of both "xxzalloc" + "ksize" with cmd 

#git-grep " ksize(" | cut -f 1 -d':' | xargs grep zalloc | cut -f 1 -d':' | sort  -u

and got:

	arch/x86/kernel/cpu/microcode/amd.c
	drivers/base/devres.c
	drivers/net/ethernet/intel/igb/igb_main.c
	drivers/net/wireless/intel/iwlwifi/mvm/scan.c
	fs/btrfs/send.c
	include/linux/slab.h
	lib/test_kasan.c
	mm/mempool.c
	mm/nommu.c
	mm/slab_common.c
	security/tomoyo/memory.c

I roughly went through these files, and haven't found obvious breakage
regarding with data zeroing (I could miss something)

Also these patches has been in a tree monitored by 0Day, and some basic
sanity tests should have been run with 0Day's help, no problem with
this patch so far (one KASAN related problem was found though, see
patch 3/4).

And in worst case there is problem, we can fix it quickly.


> If it is not going to break something - I think we can add a comment of this.
> something like "... kzalloc() will initialize to zero only for @size bytes ..."
 
Agree, this is necessary. 

> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > ---
> >  mm/slab.c | 6 +++---
> >  mm/slab.h | 9 +++++++--
> >  mm/slub.c | 6 +++---
> >  3 files changed, 13 insertions(+), 8 deletions(-)
> > 
> > diff --git a/mm/slab.c b/mm/slab.c
> > index a5486ff8362a..73ecaa7066e1 100644
> > --- a/mm/slab.c
> > +++ b/mm/slab.c
> > @@ -3253,7 +3253,7 @@ slab_alloc_node(struct kmem_cache *cachep, struct list_lru *lru, gfp_t flags,
> >  	init = slab_want_init_on_alloc(flags, cachep);
> >  
> >  out:
> > -	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
> > +	slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init, 0);
> >  	return objp;
> >  }
> >  
> > @@ -3506,13 +3506,13 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
> >  	 * Done outside of the IRQ disabled section.
> >  	 */
> >  	slab_post_alloc_hook(s, objcg, flags, size, p,
> > -				slab_want_init_on_alloc(flags, s));
> > +				slab_want_init_on_alloc(flags, s), 0);
> >  	/* FIXME: Trace call missing. Christoph would like a bulk variant */
> >  	return size;
> >  error:
> >  	local_irq_enable();
> >  	cache_alloc_debugcheck_after_bulk(s, flags, i, p, _RET_IP_);
> > -	slab_post_alloc_hook(s, objcg, flags, i, p, false);
> > +	slab_post_alloc_hook(s, objcg, flags, i, p, false, 0);
> >  	kmem_cache_free_bulk(s, i, p);
> >  	return 0;
> >  }
> > diff --git a/mm/slab.h b/mm/slab.h
> > index d0ef9dd44b71..20f9e2a9814f 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -730,12 +730,17 @@ static inline struct kmem_cache *slab_pre_alloc_hook(struct kmem_cache *s,
> >  
> >  static inline void slab_post_alloc_hook(struct kmem_cache *s,
> >  					struct obj_cgroup *objcg, gfp_t flags,
> > -					size_t size, void **p, bool init)
> > +					size_t size, void **p, bool init,
> > +					unsigned int orig_size)
> >  {
> >  	size_t i;
> >  
> >  	flags &= gfp_allowed_mask;
> >  
> > +	/* If original request size(kmalloc) is not set, use object_size */
> > +	if (!orig_size)
> > +		orig_size = s->object_size;
> 
> I think it is more readable to pass s->object_size than zero

OK, will change. 

Thanks,
Feng


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxmb/W4wmJnwA0Qt%40feng-clx.
