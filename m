Return-Path: <kasan-dev+bncBD2KV7O4UQOBBDN73OTQMGQEMB4XEGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D9F6F7920E7
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Sep 2023 09:58:06 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-501bf3722dfsf320980e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Sep 2023 00:58:06 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693900686; x=1694505486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LX3DskvT7lG7c5ORl0HoVVEWcRa9WwmxEiQc6FHepUA=;
        b=og9Xsbdh5IevLM5yhIebIQInnk7PH1gGXMmVwOHlxnZEXGQTxnHeI8UzE0phaoZEcH
         5WmXRspqgN3looiyv0s0MQtY4I2LvBhqZq5BfYO9jc9dpIDEQtci29z4jCyN/s4gjISN
         xNkx0MAUtQwGzVAkgzjyq1vvGrep8SJWsBQzX/BanfISKK/u/INtnFkI2nQ/9IksHz6W
         4e7cnnnsiGh///C/QCNNoB0R3YJ7rXTSbsW1pvNeppzVL7pKwMNXCyeBUeGKDbOnw4CP
         upqVgN6JJg2uv8RdC3WcKwWlEbJ0h1Zh2U+n1OLwVRSS8+cSTZIrpjgdunD8VcY8Kpm6
         7NEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693900686; x=1694505486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LX3DskvT7lG7c5ORl0HoVVEWcRa9WwmxEiQc6FHepUA=;
        b=MvyTOvv1Gk+MKVuSZPAQ2m+Q5fRXMYYSGpyEx10TUwiFw/W53iTrhB1ejFKC5slap1
         bznhFgnLdbC7G7SeIsnBWfJUsR1e4PiJSga5awnh3qDbLfmYnr+aDLl998dd4kDtCabu
         qfauJIES2pA5VDDQDgYiWh7O5EzYTnKIQNbx45mY5bkC8Vp1vssLsp8Z2JH94W8AMBJb
         aFQi8QmHHzFzm1eA7Zy/gPwaA2ijcXmjD+/nEBPeHz+t96Vj1lEXM9CpoxlFQKgBF8ov
         4MxRKvl7tQ5/gMlWb1+14XMJ+xAKwFGBZjmGdE5ER9w0/MJnLobBdTwdrYft+Qc481WX
         4GnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwtljYZ+Jl4/CEC/fY5AWZf6KjvN4lPdvPsWwwM65//0Sa/aToa
	hqsj6OreLJZNOZ3h5vkX0ck=
X-Google-Smtp-Source: AGHT+IE2zA1M9y4hPEEiiEnTadnOdpCqy6EyVJGhzTME8RS2MV85yMNGM/hzaRJ7ycvVkYcOLxndZw==
X-Received: by 2002:a05:6512:1314:b0:4f8:7897:55e6 with SMTP id x20-20020a056512131400b004f8789755e6mr10729781lfu.45.1693900685698;
        Tue, 05 Sep 2023 00:58:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3122:b0:500:a007:12fa with SMTP id
 p2-20020a056512312200b00500a00712fals533539lfd.1.-pod-prod-05-eu; Tue, 05 Sep
 2023 00:58:03 -0700 (PDT)
X-Received: by 2002:a05:6512:3d1b:b0:501:bf30:714c with SMTP id d27-20020a0565123d1b00b00501bf30714cmr620280lfv.24.1693900683518;
        Tue, 05 Sep 2023 00:58:03 -0700 (PDT)
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id h9-20020a05600016c900b0031ad54d83besi306829wrf.5.2023.09.05.00.58.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 05 Sep 2023 00:58:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of oliver.sang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6600,9927,10823"; a="366958094"
X-IronPort-AV: E=Sophos;i="6.02,228,1688454000"; 
   d="scan'208";a="366958094"
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Sep 2023 00:58:00 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10823"; a="1071879859"
X-IronPort-AV: E=Sophos;i="6.02,228,1688454000"; 
   d="scan'208";a="1071879859"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by fmsmga005.fm.intel.com with ESMTP/TLS/AES256-GCM-SHA384; 05 Sep 2023 00:57:59 -0700
Received: from orsmsx611.amr.corp.intel.com (10.22.229.24) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.27; Tue, 5 Sep 2023 00:57:59 -0700
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX611.amr.corp.intel.com (10.22.229.24) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.27; Tue, 5 Sep 2023 00:57:58 -0700
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 orsmsx610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.27 via Frontend Transport; Tue, 5 Sep 2023 00:57:58 -0700
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (104.47.56.47) by
 edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.27; Tue, 5 Sep 2023 00:57:58 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=K0o6S/FwS9ixmN4RY9sSkVWSTuGUOTnulqDBWENgkPCPTAvAVclYR9GndH2K8aGksE2tWygtfRJ52UAV3vYWK5p8YEBE4d65hZaWTg8FP9sirCauCxKB4w5LLfHzIQBTI4v57tcmaTiHNWXPMYsvk2iPaEk1AFEUlgDwmogiYg+PIBH8gsJleDJZ6+0XvbAJZDhTeEvylnHUTxlixxMle3MYBuOU21lX2KTtPCXF8Qo+JCh5Hlp6ID0xqAncLl+3RKzEDTLhmp5YtVe/5vEUGYxOpCa8m57ayhcKvG4kSecmBUAhqOea5iPdcBIwlbZCCcf4SLpR6Ohj/5Rk4lMtew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=tJYMJqSYugZwDXQakyyIDJ8pck2KyHNwhyvYNCRQXBM=;
 b=RskyuXhiIyLvCU6Gyq6gtXsrbrFdyH40A7aTQYcfhlj8VHC/dRCpdteZXJcK1vsqbX9oONCGKRwAGS5rsSVKcy5FabW9JBtr0wmRjT4d1glcBibqVPPq3EQ0dC/6K+nsdUe24EcnP3EVKaVD3nFL7wn62RqdomV/UTPV7FvxTgDGoiTVbVZdlF34QfMaE2pojxvJ+vBtq96XyAdLG8clWHC3F8STEPfI/X+FenmpMZJDc51qZaNWJnxzu0BP82LkNbTbRjPf99nn+6LJ3q6DA9SOI3qFAaHbVeTIHNroRT8ED5/4UhF9OF+1uXajozpoVJzR+ny+VYeNl8T5Z7g7sQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from PH8PR11MB6779.namprd11.prod.outlook.com (2603:10b6:510:1ca::17)
 by MN0PR11MB6136.namprd11.prod.outlook.com (2603:10b6:208:3c8::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6745.32; Tue, 5 Sep
 2023 07:57:56 +0000
Received: from PH8PR11MB6779.namprd11.prod.outlook.com
 ([fe80::73c6:1231:e700:924]) by PH8PR11MB6779.namprd11.prod.outlook.com
 ([fe80::73c6:1231:e700:924%4]) with mapi id 15.20.6745.030; Tue, 5 Sep 2023
 07:57:56 +0000
Date: Tue, 5 Sep 2023 15:57:44 +0800
From: kernel test robot <oliver.sang@intel.com>
To: Jann Horn <jannh@google.com>
CC: <oe-lkp@lists.linux.dev>, <lkp@intel.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, "Christoph
 Lameter" <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka
	<vbabka@suse.cz>, Alexander Potapenko <glider@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
	<vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Roman
 Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	<linux-kernel@vger.kernel.org>, <linux-hardening@vger.kernel.org>,
	<kernel-hardening@lists.openwall.com>, <oliver.sang@intel.com>
Subject: Re: [PATCH] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Message-ID: <202309051537.999262cc-oliver.sang@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230825211426.3798691-1-jannh@google.com>
X-ClientProxiedBy: SI2PR02CA0041.apcprd02.prod.outlook.com
 (2603:1096:4:196::20) To PH8PR11MB6779.namprd11.prod.outlook.com
 (2603:10b6:510:1ca::17)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH8PR11MB6779:EE_|MN0PR11MB6136:EE_
X-MS-Office365-Filtering-Correlation-Id: a65b4d0a-5241-4eda-c170-08dbade5d0bc
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: mcEWoeOKh4l3QGWOOqznovw/4Lf9/YUEuf5InJywvuT4KL+llR42Wgm/qxhm2GePe/yQTOwghMBtDsFlwWGz2WyWf8gaSpLGBMOXQCv3ZN/eFzT1XuH4+K7XTQjJ4RoVTyGqx6mz48Z2WRtn46etXprpSfD8j698lQN2axT+s1Lw/MKYS/v8Q19o+xrjQjB+jv0iOBQPsezqiHtoroKinPgJTYit7CdTIUlzqtDXDf0jz+fCA4Cf+a0dElEEYfOIWrCEVIRHkliIkRLJtHYGh2RDgcTdxO6QxvLML/odEyI1NVRsGt702cFOr6+b/vwp2+ggdox0pSfl5EwL7HZmQwm+OtkyDnNJdaKkCdHlhACjgGK0Y22RrEcBnYFnZsFDKespidXrddAH0L5vAPdeFjOooqt21RkUq3B/c0F82uj12wZJnwnMkRRxPBkhL5QDFG7ISScK+FNHHoLV+p1muaAz48Wvpe5K1A98xUBdQ+EnDJ8vfXHlF9NWPsKuHsuJ39SAYLyG0R0/5Zjm48XKpqfafdP6Ql0ubWqVtSDrnP9yjHt0isIpdxKbfQG11eLT9JlPwULDqIqe+xZiAwGGHg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH8PR11MB6779.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(396003)(376002)(346002)(39860400002)(366004)(136003)(1800799009)(186009)(451199024)(478600001)(966005)(6666004)(66556008)(66946007)(26005)(107886003)(2616005)(66476007)(1076003)(54906003)(6506007)(6486002)(6512007)(316002)(2906002)(8676002)(4326008)(8936002)(6916009)(7416002)(5660300002)(86362001)(36756003)(38100700002)(41300700001)(82960400001)(83380400001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?HAhwcZGVjeDJnnQWwMXPC9IFcNSj9H6bpOMgQH3qPg68TKKCdgJzHWELAfDQ?=
 =?us-ascii?Q?p/S+8vgSyS/OYYG7bV4sjCrhtkjoU1XrbaNW+H8FbbupDvbYXtTUy3HNHLn2?=
 =?us-ascii?Q?wHpaoIJ+TlFBsYxmMEkkE6cXGAeH5jl/j+FjTIT5UlTgeKELSLNO25WKoUSy?=
 =?us-ascii?Q?n7x+ngHhbGXLxH+ET9nMOeEM0J0H+vL2USyVGUcpuZbGfk7OINrf0kpOkxM/?=
 =?us-ascii?Q?gQtIARuha15kuaSUshplIEaCP3d4eHUrMSYUJpdJ/XEY14K5UVuE65xnZ+u9?=
 =?us-ascii?Q?CxB7SSK7bIQfsphF8RthJOB6djUKaLVfTUn7Agftpj5SWpYaEJCoNQqrwaLe?=
 =?us-ascii?Q?knjyZ+BmTzpulFBQcxdZO0q2GjFNsOx6e4N+zuLcNGd2lcyLFq/zgIbEUOPl?=
 =?us-ascii?Q?nykvqQW9VkXpPVjKB7lBEF9/p0R6qNyJult9y4KPctC1rNVN1oU3BQyVPcEM?=
 =?us-ascii?Q?0Y7Ep0/UKcM0z5pyYTv1zVeG7x5HZ1Xzzl/7FNgPA/tEiEbkG5yiFoa98EjX?=
 =?us-ascii?Q?UoDy8iPInFZE8ihSZsyfUM50cJivF9FQWE0ga4+75gxaDDeNEaE8y871mfoU?=
 =?us-ascii?Q?8pEgXeYsGD9kPd9NyEg0fEBBAcr4WQt+p38guNg7ECXV5bVzCkLoCwJh35ma?=
 =?us-ascii?Q?b1OcraQ8WekeT/tLHHGeEYREWSZpko+wNMJIbJR5g0yhlQbFd64jpiJWmmsh?=
 =?us-ascii?Q?ktPhMyEHBVPBCiDJuSnSjuZw2+kcTLVFpAFySiKsz+TfS+PZPuL/za+RyIyW?=
 =?us-ascii?Q?czjw1T36XdagjRlkFTmh+ssooaUg/O8ADFT+cZZ/bgH5zW7aGch6bzTmYG7v?=
 =?us-ascii?Q?d99m6VIPKZlrWnhvdNWwJBKhEzObkIQGrR60xn/MvbXhpx6bFDWAus/zc1CC?=
 =?us-ascii?Q?6VrRpvjnCV8C9ioDG/zlMyY0ecpwf0u316JDaYooiP7RQQkOjScjgNH8/323?=
 =?us-ascii?Q?FKCW29NLwhqmV4AU88NqOLGBRcuMjTajhoEx1AkseyTivNsv7mlNQhULabhU?=
 =?us-ascii?Q?kH/8dx+vZxTQEtUXhDQ8R5YaqXLlOfdE3HyLo4pC96fj1ojjaRoSnDHdjqwY?=
 =?us-ascii?Q?9cufC2n/z20wfeCK2mUL6ucqwABui1IiqxCB69TlKsbefEuGrBnWs2EsCHL2?=
 =?us-ascii?Q?YMleXrakqqFRLXmX1JXLWR8FEDGsV/2o1O4buUuQ77edRIPYrH6Dp7620j01?=
 =?us-ascii?Q?zjEIocI3utRGYj+YbslLmI7OfPrSf9DosdlXVk7L+/TI9oBSYYS0bRWn/mV6?=
 =?us-ascii?Q?dSEtKBhjVuZaMRjMIUk6eI42M2Juc0kKhAMMPJDhoI/GvdJWjRSNIk5lgAb3?=
 =?us-ascii?Q?7QsMqH2FLuQ85dNXPAN2V57/zO8woQI8OuyWZucvr8Lqsu2JjhFcFUd62Oep?=
 =?us-ascii?Q?rKfSQMVaO2f4qpilOI+lyvIwqT+NHsuc/RbQkYLD2UjqKPPzxP/yugHMXHyN?=
 =?us-ascii?Q?lCPzu4fq6Yzt93LJ97O1c9/P8VpPURmBJiXvEiZsOziXu1YTufSC047ePamR?=
 =?us-ascii?Q?nwvw5bzMxpKDPuTR+NXfmqpB4mbwFi3E58y1CpOcNOh4Jlu3Plhj0uRFl4hW?=
 =?us-ascii?Q?lTe+QVL4z6NWW2D6WfufdKkGy4+GT0+2QN6Kai/bOi0QYqFgiEqTu1CYjxZF?=
 =?us-ascii?Q?dg=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: a65b4d0a-5241-4eda-c170-08dbade5d0bc
X-MS-Exchange-CrossTenant-AuthSource: PH8PR11MB6779.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 05 Sep 2023 07:57:56.6412
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: H4cToWRK2yIAgpswRG6iV9J+lAkTGUxWRn7rQX6XS+EgAR1bEy6czr9aJitidFLgifatMeJYrXl/ZU/SVFAQLg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN0PR11MB6136
X-OriginatorOrg: intel.com
X-Original-Sender: oliver.sang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=e7YR3Os8;       arc=fail
 (signature failed);       spf=pass (google.com: domain of oliver.sang@intel.com
 designates 134.134.136.20 as permitted sender) smtp.mailfrom=oliver.sang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Content-Transfer-Encoding: quoted-printable
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



Hello,

kernel test robot noticed "BUG_bio-#(Tainted:G_S):Objects_remaining_in_bio-=
#on__kmem_cache_shutdown()" on:

commit: d0dc03872a9d13afc16b9f12e69cb0dc60437198 ("[PATCH] slub: Introduce =
CONFIG_SLUB_RCU_DEBUG")
url: https://github.com/intel-lab-lkp/linux/commits/Jann-Horn/slub-Introduc=
e-CONFIG_SLUB_RCU_DEBUG/20230826-051804
patch link: https://lore.kernel.org/all/20230825211426.3798691-1-jannh@goog=
le.com/
patch subject: [PATCH] slub: Introduce CONFIG_SLUB_RCU_DEBUG

in testcase: mdadm-selftests
version: mdadm-selftests-x86_64-5f41845-1_20220826
with following parameters:

	disk: 1HDD
	test_prefix: 01replace



compiler: gcc-12
test machine: 8 threads 1 sockets Intel(R) Core(TM) i7-4790T CPU @ 2.70GHz =
(Haswell) with 16G memory

(please refer to attached dmesg/kmsg for entire log/backtrace)



If you fix the issue in a separate patch/commit (i.e. not just a new versio=
n of
the same patch/commit), kindly add following tags
| Reported-by: kernel test robot <oliver.sang@intel.com>
| Closes: https://lore.kernel.org/oe-lkp/202309051537.999262cc-oliver.sang@=
intel.com


kern  :info  : [  120.278340] md: recovery of RAID array md0
kern  :info  : [  124.955979] md: md0: recovery done.
kern  :info  : [  125.769059] md: recovery of RAID array md0
kern  :info  : [  127.326184] md: md0: recovery done.
kern  :err   : [  133.408242] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
kern  :err   : [  133.417160] BUG bio-144 (Tainted: G S                ): O=
bjects remaining in bio-144 on __kmem_cache_shutdown()
kern  :err   : [  133.427951] ---------------------------------------------=
--------------------------------

kern  :err   : [  133.439000] Slab 0x00000000419abc96 objects=3D32 used=3D2=
 fp=3D0x000000008e0d14fb flags=3D0x17ffffc0010200(slab|head|node=3D0|zone=
=3D2|lastcpupid=3D0x1fffff)
kern  :warn  : [  133.452568] CPU: 3 PID: 1314 Comm: mdadm Tainted: G S    =
             6.5.0-rc7-00105-gd0dc03872a9d #1
kern  :warn  : [  133.462585] Hardware name: Gigabyte Technology Co., Ltd. =
Z97X-UD5H/Z97X-UD5H, BIOS F9 04/21/2015
kern  :warn  : [  133.472076] Call Trace:
kern  :warn  : [  133.475236]  <TASK>
kern :warn : [  133.478051] dump_stack_lvl (kbuild/src/consumer/lib/dump_st=
ack.c:107 (discriminator 1))=20
kern :warn : [  133.482427] slab_err (kbuild/src/consumer/mm/slub.c:1016)=
=20
kern :warn : [  133.486370] ? _raw_spin_lock_irqsave (kbuild/src/consumer/a=
rch/x86/include/asm/atomic.h:115 kbuild/src/consumer/include/linux/atomic/a=
tomic-arch-fallback.h:2155 kbuild/src/consumer/include/linux/atomic/atomic-=
instrumented.h:1296 kbuild/src/consumer/include/asm-generic/qspinlock.h:111=
 kbuild/src/consumer/include/linux/spinlock.h:187 kbuild/src/consumer/inclu=
de/linux/spinlock_api_smp.h:111 kbuild/src/consumer/kernel/locking/spinlock=
.c:162)=20
kern :warn : [  133.491615] __kmem_cache_shutdown (kbuild/src/consumer/incl=
ude/linux/spinlock.h:351 kbuild/src/consumer/mm/slub.c:4625 kbuild/src/cons=
umer/mm/slub.c:4656 kbuild/src/consumer/mm/slub.c:4688)=20


The kernel config and materials to reproduce are available at:
https://download.01.org/0day-ci/archive/20230905/202309051537.999262cc-oliv=
er.sang@intel.com



--=20
0-DAY CI Kernel Test Service
https://github.com/intel/lkp-tests/wiki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202309051537.999262cc-oliver.sang%40intel.com.
