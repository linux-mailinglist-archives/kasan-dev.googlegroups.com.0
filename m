Return-Path: <kasan-dev+bncBDN7L7O25EIBBGXWYCMQMGQEBAZT5KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B8225E92BB
	for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 13:27:23 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id c28-20020ac2531c000000b0049f54cc790dsf1431291lfh.14
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 04:27:23 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=/OLTb66hXwa3NQDAWRzi5lOID/vFOsIaWNvVBry7R/M=;
        b=WW/PNYthDcglRERQd8F2/Y/tx3YbDNsIrEW1vGZvCeo6ePQvXlKad31ejbSpsxL5Ck
         +0B9n4Bo8EO0EHExCRr1VxUBgDquupMz/QQstH/7rBqKWELHx7Mrk/8NYTjBgWfHuvPV
         0sYD6aJZXENryrF7GBmtP7UWUl5904q/E1cP/OHCiDI/0zlFGDSY6LK7rk2BTnHda7iW
         lgnpH72Ztra1MGicgLbH8NxiK+aAzG6ADaRdKvZqDovAinsTTN7ZvjStwHNMyLLmDLON
         bZu9XT0X27ugkGxKLsBX7v5LFFQlNm4D0p2YqhkRL+c30s1z7knQFXImnVFB+5fF+9aM
         QMpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=/OLTb66hXwa3NQDAWRzi5lOID/vFOsIaWNvVBry7R/M=;
        b=xJQNQc8E93PvY+xEVNc2xIpMQkXqUdtmLbMmfLnwIaWBG9SOJ6xLHQQDIQo8FUmmoY
         gs+RYRht5MFpqhxZ/IxFEjfKBOvwiX1FywFIWRLLMCVn3tvHq5Wx8QW0NpnczkX6au02
         en/vESz+gd/KWk2Vlp+yh2ubaBWXVHbA7pvVKtigP49bZkReM1k5/CAsk1Ht0tdt30Il
         N/6yKy9p6xydOXXtKazcNC1Pbk+Twn1ZaTzYyw6Y/T/GRxQz8SR0nt4BZ+R/xXSNySmm
         ivYDF7Mhpyb5YHs/d9sMVwTQeg48Rpf1g9sPe//XJ1zUeY/+8vlBZ9smhB3vBMhctVbn
         YSNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2H207Cy/2YiUicz49Iw/z5+p7mPEHInILUk+3WNlESqEuT4Je4
	9MOM6+TBVl7DFRxPRtXHIR0=
X-Google-Smtp-Source: AMsMyM5BjjCa4U2aGkUAXjUkiKntMxfKiHL44b8zZ9PvOVRs2D1VDrubB6VzAs303rQitwl7irkF1Q==
X-Received: by 2002:a05:6512:1504:b0:4a0:5045:e09a with SMTP id bq4-20020a056512150400b004a05045e09amr5154972lfb.139.1664105242609;
        Sun, 25 Sep 2022 04:27:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8297:0:b0:26b:ff81:b7cb with SMTP id y23-20020a2e8297000000b0026bff81b7cbls2521804ljg.6.-pod-prod-gmail;
 Sun, 25 Sep 2022 04:27:21 -0700 (PDT)
X-Received: by 2002:a2e:95cd:0:b0:26c:3bb0:289f with SMTP id y13-20020a2e95cd000000b0026c3bb0289fmr5799968ljh.449.1664105241285;
        Sun, 25 Sep 2022 04:27:21 -0700 (PDT)
Received: from mga14.intel.com (mga14.intel.com. [192.55.52.115])
        by gmr-mx.google.com with ESMTPS id p4-20020a2eb984000000b0026bf7cf2a41si529467ljp.2.2022.09.25.04.27.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 25 Sep 2022 04:27:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.115 as permitted sender) client-ip=192.55.52.115;
X-IronPort-AV: E=McAfee;i="6500,9779,10480"; a="300836044"
X-IronPort-AV: E=Sophos;i="5.93,344,1654585200"; 
   d="scan'208";a="300836044"
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by fmsmga103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Sep 2022 04:27:17 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,344,1654585200"; 
   d="scan'208";a="598405268"
Received: from orsmsx603.amr.corp.intel.com ([10.22.229.16])
  by orsmga006.jf.intel.com with ESMTP; 25 Sep 2022 04:27:17 -0700
Received: from orsmsx607.amr.corp.intel.com (10.22.229.20) by
 ORSMSX603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Sun, 25 Sep 2022 04:27:17 -0700
Received: from ORSEDG602.ED.cps.intel.com (10.7.248.7) by
 orsmsx607.amr.corp.intel.com (10.22.229.20) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Sun, 25 Sep 2022 04:27:17 -0700
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.102)
 by edgegateway.intel.com (134.134.137.103) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Sun, 25 Sep 2022 04:27:16 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=AfK+Xl8i7JgDd9XEXnL/J7ViV5lQVzOclsyA2L7aNjk3TA4rRA4jLJhz6z4IvjzSUo6tpz/N4zd974213GjwGrOa9T7Jto46Zz+f5Z1SbNKAzUJK/8HcJ1IAvqDTAiw9L5uCvc6LnEMqpa/l2GOcFKEujNbsizx9wIlG2g+j7Sic/1ij7e20Ekgg6F6qjv0rTlNyw+isdUolhCRUNexDczq9tf7grgcIISEQkX3hPbhJF9IyVCyQLrXi4ASoGSzVOfPTQ7m1+RTUL/96WigmnsvmJdqc+atmv+I+FHi+docvv0oUR+i7F2zrrczJWtZyYUN1ufbGNcsVKcaJHFHZBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=jo/yo8xfJUdZ629TGuiZiHSPNFMUZG5zw3gYMriieOA=;
 b=miXQMaIBhgzW9+lsVijjp1rr4HTVASaHtFcyZihTikCdCeOgRcRv4L5cZ59NhsvGzM79njfxc7MM/8VhZJ/BbBvkez9k4nFlbIf4k5idUojjoLxDWcGMrQyOIWuT3ljlvdYwj7RikYgTbe8AyaZVJ46akH2aSa6P/l6yzP3v2SSg57qduNANjZhiH1Ybi6KHq+QQE4Rgo0FxmvP2CMEcJG8yuanmR1HqMt7XmR9+5ZbhL2HAl7L54WTBzayq4zmOPEmo3v+fQY/xkvGmLCDpEH25Z9W4QJ9662wQOHLlVswo/mjUgXk/GG0PSb7hLQq+kqIIZJukdthhARL5XyDXmw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by PH8PR11MB7144.namprd11.prod.outlook.com (2603:10b6:510:22c::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5654.24; Sun, 25 Sep
 2022 11:27:13 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::ccec:43dc:464f:4100]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::ccec:43dc:464f:4100%7]) with mapi id 15.20.5654.024; Sun, 25 Sep 2022
 11:27:13 +0000
Date: Sun, 25 Sep 2022 19:26:41 +0800
From: Feng Tang <feng.tang@intel.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka
	<vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jonathan Corbet <corbet@lwn.net>, "Hansen, Dave" <dave.hansen@intel.com>,
	Linux Memory Management List <linux-mm@kvack.org>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	"Sang, Oliver" <oliver.sang@intel.com>
Subject: Re: [PATCH v6 3/4] mm: kasan: Add free_meta size info in struct
 kasan_cache
Message-ID: <YzA68cSh5Uuh5pjZ@feng-clx>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-4-feng.tang@intel.com>
 <CA+fCnZdFi471MxQG9RduQcBZWR10GCqxyNkuaDXzX6y4zCaYAQ@mail.gmail.com>
 <Yyr9ZZnVPgr4GHYQ@feng-clx>
 <CA+fCnZdUF3YiNpy10=xOJmPVbftaJr76wB5E58v0W_946Uketw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdUF3YiNpy10=xOJmPVbftaJr76wB5E58v0W_946Uketw@mail.gmail.com>
X-ClientProxiedBy: SG2PR03CA0115.apcprd03.prod.outlook.com
 (2603:1096:4:91::19) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|PH8PR11MB7144:EE_
X-MS-Office365-Filtering-Correlation-Id: 5ad801b9-2f77-4585-3c2d-08da9ee8e4bc
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 7tFIU2F7eqsrrRAA6pnuhV9bWUK8olH5s0FQ5tMtHInnos+LJ4uHJAgkE2DisQSqGlsYf6GluYipd3y2sbRceiWgSivVeVZb3mVCHGVL4JIUOqwoK8+bX1+M93w15RtaXwznUKr7Dgg20HdkAF4jzYu5ooGTl+nnuOwVCnRfNL7rHeaaXKJWBx3QtDMLEycF8YhLG/rYHYcLSHhb30aghCAFOHYy3rzgTUqKmY76pr4LiAEcfcytlKtWL6W3eiP2EXuvUTIyOWjtDtIuAm12jo+wrfQr/sq58p26MqqHqZYV1o7Q8ZCW5u2Kp2kC+koaEzGoTLWuyZc9EWCWqVCj2dVTbJ1USp54A/AYqVlUU8NukRN8q/FN4/Y6gKAaB/bcjtSGfvU63uMrvy6vpUnAeZWXRfZmXS3JMNPa6GXJoNPGz2brxRIO9grXKgkSXETHjx89Of2q6M1xexrt5YlsqAqVYvMeKsCJ0caCDMyPVpvw5OcQ2JwrLQ2bNLahWzIbGBr1sf0fvB7PRa7cCBDyz470a4kTHR02rZUGWWBrdhvPh7so4Ni2gvaGEEZxiXXl/8C52EbBK1Ph1ecSgarhzd68iOdyQuBoyJlprmm8xJabORYtgrNuU1zS80YLktJvy4O9+jmcnRVL2EcY9ML+FSKL0ypCd8/oNgoVCbAkLJfTv6C2j/KVPh17QhowQ7367pbrNWf09cS1/AT4Z/vSZb4wSRwEdOUe4fBWgQGXpLw=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(136003)(39860400002)(346002)(376002)(396003)(366004)(451199015)(82960400001)(38100700002)(83380400001)(186003)(53546011)(107886003)(6486002)(478600001)(966005)(86362001)(26005)(9686003)(6666004)(6506007)(6512007)(8676002)(4326008)(8936002)(41300700001)(66556008)(66476007)(7416002)(5660300002)(44832011)(66946007)(2906002)(6916009)(54906003)(316002)(33716001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?0M2Hf7pl7fOdo2yuu8MVpOE1Z0MGfRf/vZ7+P2V0Ko0EmLljMMV9RLfFPM6Z?=
 =?us-ascii?Q?UPFJSPi1IfVzOeSCmD32PCuit+rxBIw+snIDoNiLXPvLIYc2Z7zq1qLNzxwK?=
 =?us-ascii?Q?Z03FQqXdp76MdmRViAf8XXDr/pmVVHOHouG3Ni9nQzQTYKo13wiJH1tMddRk?=
 =?us-ascii?Q?enioQ6/jOLNb2J8C4Y6ANqfuw2Q4W4EdLDHsp8bP8pgWsKxDNBhwdjWbI1o7?=
 =?us-ascii?Q?MVcbPkeEIY+NaQZLoPbYadsMw6odINxpn7fe5eievP5zYDtgbhkiHLveMgMW?=
 =?us-ascii?Q?uNgI2wuVUemkA+34bTkfOyccBxcCsus5XNN6seIJSDjyLhVjJK05WUTuYQjQ?=
 =?us-ascii?Q?cSX6JAsPTY2q7TlGmhUdj2YGBfquu5056LKEm43gETOZDMnKR7yoG2R13hk/?=
 =?us-ascii?Q?RyoWAWH0C+jMt2UYdr09bQGpqv2Z8ofxousD4c3Hu+w3cyA8FxeRrmgQ/ZXZ?=
 =?us-ascii?Q?JJ1vXgmYTuQ29GZtDtHA4KRrlkzYfnsjL3+/GsALjksmbYyYIcy9NVrAdqvB?=
 =?us-ascii?Q?SQBPJy0UJXu2IWw87W3gPAWLZ30cYWQTIZaa+YZKPSUrPZi1zthkQOg4mrTS?=
 =?us-ascii?Q?pJfBKU1cblRMIKFeJdai33GODMS6VTx9rJRP/2HlUTdvDSdg96fcYmLxnQGz?=
 =?us-ascii?Q?Ww7jH4WOY/oWUkPbZWGYw86ea09npmLg1okK2g8XL5mNzObv4pXOT0RyBSJ8?=
 =?us-ascii?Q?N7Ed0+X+Dtkf3LNYleFuUO1KqD2/DD9IR13znx6yHKURTJ1ub+ebugRs7+VL?=
 =?us-ascii?Q?fkKS3C0QU9aDidJT4zqT6z80isqqNqXe33pzf1r1NKaOIb9cNctiX+m93NXD?=
 =?us-ascii?Q?6yP9cO4BpN3EpoWC+vsZBw75xlonInLLxmGTE5RPJaTOtkTkS47p6xUOGwWa?=
 =?us-ascii?Q?h4bSr6rTAkHVsJ/mag6cS/iCCZ2C260zp3kibE6IH5RGNw1OiWdT14A9wB5b?=
 =?us-ascii?Q?5L5xyGlMqecL+/mofU5B1jZJ+JDEAACtoVp3iP/l0YooXmVkvFh/LDZJga4U?=
 =?us-ascii?Q?43r3eWsMTdcV057j54bwEJfsXmKFpRR7ShzjfGpHvyXynugf+6TKV8Hv3b15?=
 =?us-ascii?Q?YXTzQcCL/4RNVxXw8XR+CLYpAg/BorbaDznTVvWn8dcJb+sqLTCshiCU8ayE?=
 =?us-ascii?Q?vTu+MU5SqMjZk2HXyJ6purM3WY77tiHDZKtGhEWSCWkZU0hPao/msTx96ZyH?=
 =?us-ascii?Q?qhc46tt12ENtucvfvUp9g+w5SS72HmPMnpf/vYQbdbWABGRZ7o1Vsl3/mcTw?=
 =?us-ascii?Q?6cg246TbLzBKbdZgNdHsa/yL1DKIi7E2IS3tPyYuQxTDSL6RfWNx6od7IqBs?=
 =?us-ascii?Q?YOImeJY4VXv252mKCRqJ0OgoH5kltTjG7WZ9pVy19S8bAsYmnX3z0NZ2DSXV?=
 =?us-ascii?Q?jYUYKHNa9rSxzjN3xJ8k241/orDTO2kktX0pqyeV0gaHWy4lRpopC/rbGuc+?=
 =?us-ascii?Q?fZCM3PDRGZuWs9w+nPJf0ouHJXn7JovDFzhAgf7VfpOVlvNglpkat5DcAIuf?=
 =?us-ascii?Q?QugHuCsT5l/JZmgB92NJkCBoh9HRI+YezqhE7EoLNHUlPueb+QD/VYMG67U2?=
 =?us-ascii?Q?otoOIQmbUAxRCdqMyE11p+QJwVfbeamZIf2muNWS?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 5ad801b9-2f77-4585-3c2d-08da9ee8e4bc
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 Sep 2022 11:27:13.5051
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CLIKRH95o8fgA39v9Ppsx2Ga0kFCPUrJdBZpHpzr59BB1KFh3kJVfS16m4bCP3cSZp/W7jNhS3y7fD8rOk6+nA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH8PR11MB7144
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=URlqm9fH;       arc=fail
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

On Sun, Sep 25, 2022 at 02:05:04AM +0800, Andrey Konovalov wrote:
> On Wed, Sep 21, 2022 at 2:03 PM Feng Tang <feng.tang@intel.com> wrote:
> >
> > Agree, it's better not touch the internal fields in slub code.
> >
> > How about the following patch, it merge the 2 functions with one flag
> > indicating in meta data or object. (I'm fine with 2 separate functions)
> 
> The overall approach sounds good. See some comments below.
> 
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index b092277bf48d..0ad05a34e708 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -150,11 +150,12 @@ static __always_inline void kasan_cache_create_kmalloc(struct kmem_cache *cache)
> >                 __kasan_cache_create_kmalloc(cache);
> >  }
> >
> > -size_t __kasan_metadata_size(struct kmem_cache *cache);
> > -static __always_inline size_t kasan_metadata_size(struct kmem_cache *cache)
> > +size_t __kasan_meta_size(struct kmem_cache *cache, bool in_slab_object);
> > +static __always_inline size_t kasan_meta_size(struct kmem_cache *cache,
> > +                                                       bool in_slab_object)
> 
> I would keep the name as kasan_metadata_size as it's more clear to
> external users but rename in_slab_object to in_object to make the
> declaration shorter.

Make sense to me, will do.

[...]

> > +       if (in_slab_object)
> > +               return (cache->kasan_info.alloc_meta_offset == 0 ?
> > +                       sizeof(struct kasan_alloc_meta) : 0) +
> > +                       (cache->kasan_info.free_meta_offset ?
> > +                       sizeof(struct kasan_free_meta) : 0);
> > +       else
> > +               return (cache->kasan_info.alloc_meta_offset == 0 ?
> > +                       sizeof(struct kasan_alloc_meta) : 0) +
> > +                       (cache->kasan_info.free_meta_offset ?
> > +                       sizeof(struct kasan_free_meta) : 0);
> 
> Something weird here: both if and else cases are the same.
 
Yes, will fix it. 

> The change also needs to be rebased onto [1].
> 
> Thanks!
> 
> [1] https://lore.kernel.org/linux-mm/c7b316d30d90e5947eb8280f4dc78856a49298cf.1662411799.git.andreyknvl@google.com/

I noticed this has been merged to -mm tree's 'mm-everything' branch,
so following is the patch againt that. Thanks! 

One thing I'm not very sure is, to check 'in-object' kasan's meta
size, I didn't check 'alloc_meta_offset', as from the code reading
the alloc_meta is never put inside slab object data area.


Thanks,
Feng

---8<---

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d811b3d7d2a1..96c9d56e5510 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -302,7 +302,7 @@ static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
 #ifdef CONFIG_KASAN_GENERIC
 
-size_t kasan_metadata_size(struct kmem_cache *cache);
+size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
 slab_flags_t kasan_never_merge(void);
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			slab_flags_t *flags);
@@ -315,7 +315,8 @@ void kasan_record_aux_stack_noalloc(void *ptr);
 #else /* CONFIG_KASAN_GENERIC */
 
 /* Tag-based KASAN modes do not use per-object metadata. */
-static inline size_t kasan_metadata_size(struct kmem_cache *cache)
+static inline size_t kasan_metadata_size(struct kmem_cache *cache,
+						bool in_object)
 {
 	return 0;
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d8b5590f9484..5a806f9b9466 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -450,15 +450,22 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 }
 
-size_t kasan_metadata_size(struct kmem_cache *cache)
+size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 {
+	struct kasan_cache *info = &cache->kasan_info ;
+
 	if (!kasan_requires_meta())
 		return 0;
-	return (cache->kasan_info.alloc_meta_offset ?
-		sizeof(struct kasan_alloc_meta) : 0) +
-		((cache->kasan_info.free_meta_offset &&
-		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
-		 sizeof(struct kasan_free_meta) : 0);
+
+	if (in_object)
+		return (info->free_meta_offset ?
+			0 : sizeof(struct kasan_free_meta));
+	else
+		return (info->alloc_meta_offset ?
+			sizeof(struct kasan_alloc_meta) : 0) +
+			((info->free_meta_offset &&
+			info->free_meta_offset != KASAN_NO_FREE_META) ?
+			sizeof(struct kasan_free_meta) : 0);
 }
 
 static void __kasan_record_aux_stack(void *addr, bool can_alloc)
diff --git a/mm/slub.c b/mm/slub.c
index ce8310e131b3..a75c21a0da8b 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -887,7 +887,7 @@ static void print_trailer(struct kmem_cache *s, struct slab *slab, u8 *p)
 	if (s->flags & SLAB_STORE_USER)
 		off += 2 * sizeof(struct track);
 
-	off += kasan_metadata_size(s);
+	off += kasan_metadata_size(s, false);
 
 	if (off != size_from_object(s))
 		/* Beginning of the filler is the free pointer */
@@ -1042,7 +1042,7 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 		/* We also have user information there */
 		off += 2 * sizeof(struct track);
 
-	off += kasan_metadata_size(s);
+	off += kasan_metadata_size(s, false);
 
 	if (size_from_object(s) == off)
 		return 1;








-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzA68cSh5Uuh5pjZ%40feng-clx.
