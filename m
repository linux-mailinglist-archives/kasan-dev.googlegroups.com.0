Return-Path: <kasan-dev+bncBDN7L7O25EIBBUG5WGNQMGQEOFBVTKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D735623A56
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Nov 2022 04:24:01 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id a26-20020ac25e7a000000b004b21ed7d4e4sf91786lfr.15
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 19:24:01 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mXF6Hy1zwHR6EQIecCrADDyJUBLE7+HhZd04wAlZiKY=;
        b=easJIeRFYTlM7dCI5/HlZHTnnF6kW1nfKnpU3MLnyUELubeRyJX9ZEDB1UjMqSe3cr
         Z1CdDaU+wyW6gPMb/juMb1U64ZvMrg4x+BwYNMyf0pPeXK0+XplXT5DsPu3FzCCdlEZr
         dusRZDwuyo0bjfT/B0rJxT81wHC8JbHOt5wDZNHrBv8IcQEQTtyJKNO714Pzbj7O1yV6
         YxVJ0oWPvQ/ZrpoQcdiYnZFsXaBTizNIADOb9O821U4LaZLG4ntU4FHddiJX/WBdxsVI
         kzpkDL2SP1+7Iu48Lz3m+VBS9FRua64WvkWWIGgmwV6osrWh37+lNcf014DdtnXEv/ap
         e2pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mXF6Hy1zwHR6EQIecCrADDyJUBLE7+HhZd04wAlZiKY=;
        b=nceP9juZhUckKjNVNpNN/2efnVJjvbAjV4YqnfbG6IYEfHDCqcgVogQ3/JmirW1WpG
         CW5egtyilp8GzYW1s3fZK3T4R0KWLYQSeR98Sva8QtFW7ZVnkXc6+OoLVUXbPd6fX172
         V3JupprxqqYcEmaJ24Oo8eHInsQSSws52RT0C+0aHUknFFQddYin7n+6qGr9RezoioHV
         Debn/1Cl5dadk0J4SWrI3runGXwm1VhVQJpT3vBbc8qLNYkmwLkCceRFwWLf423Q3C3H
         EGsgqKQnQ+So034cZGX7bZREjQSdU48nPeXk6xDRBEQlX2R2mwieU/S9JvKjfGPrBZuF
         nsBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0GTbdTqZyOynoMHmn1El5HS9y3IesbfLXcdYrZroD+grdbPkDA
	+qWdSUrZWlGKrhZJ6/mXG08=
X-Google-Smtp-Source: AMsMyM67I785xqcA4I3fS6v3vt76gW7xUvcAmI9dk6S8/bxe7LdWYOlNpmyRienWiEd3XwNrXBoD7g==
X-Received: by 2002:a05:651c:2321:b0:277:b9f:cdbd with SMTP id bi33-20020a05651c232100b002770b9fcdbdmr8738937ljb.0.1668050640628;
        Wed, 09 Nov 2022 19:24:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:36c7:b0:4a2:3951:eac8 with SMTP id
 e7-20020a05651236c700b004a23951eac8ls566854lfs.0.-pod-prod-gmail; Wed, 09 Nov
 2022 19:23:59 -0800 (PST)
X-Received: by 2002:a05:6512:31c9:b0:4a2:5349:7103 with SMTP id j9-20020a05651231c900b004a253497103mr21091597lfe.497.1668050639421;
        Wed, 09 Nov 2022 19:23:59 -0800 (PST)
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id v7-20020a05651203a700b0048b12871da5si603751lfp.4.2022.11.09.19.23.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Nov 2022 19:23:59 -0800 (PST)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6500,9779,10526"; a="309911948"
X-IronPort-AV: E=Sophos;i="5.96,152,1665471600"; 
   d="scan'208";a="309911948"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Nov 2022 19:23:56 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10526"; a="700626285"
X-IronPort-AV: E=Sophos;i="5.96,152,1665471600"; 
   d="scan'208";a="700626285"
Received: from fmsmsx601.amr.corp.intel.com ([10.18.126.81])
  by fmsmga008.fm.intel.com with ESMTP; 09 Nov 2022 19:23:56 -0800
Received: from fmsmsx611.amr.corp.intel.com (10.18.126.91) by
 fmsmsx601.amr.corp.intel.com (10.18.126.81) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 9 Nov 2022 19:23:56 -0800
Received: from fmsmsx610.amr.corp.intel.com (10.18.126.90) by
 fmsmsx611.amr.corp.intel.com (10.18.126.91) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Wed, 9 Nov 2022 19:23:55 -0800
Received: from FMSEDG603.ED.cps.intel.com (10.1.192.133) by
 fmsmsx610.amr.corp.intel.com (10.18.126.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31 via Frontend Transport; Wed, 9 Nov 2022 19:23:55 -0800
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (104.47.57.170)
 by edgegateway.intel.com (192.55.55.68) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.31; Wed, 9 Nov 2022 19:23:55 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=lnTf52WJwaklW6tpxri9x0To5+/okgsXupXpHU2CRPv1pWiKCKL/iBlkvkMg96uZ44jveKjzbUX3SBLisJ2UeGodK5tgz5ztWNvhD9RbFsNoJ7II5KKLAfy3OAAXzTLVfLw7u5i0pZuYu8kgfo9/ahEgZ3KcitXF8yl+BmZ52RWC67EKqaxja1XW2CnBqqTDpj+qsmNN5/EAIqpXvVQEtucJHngnRzT7tn1SUd3YjtuDH+PM7o93hROwzXkZvJSLDQMInRs1Q5eeQBmyQ3kmQdzAENFQxk/qjuyELJ4Y2lFEtw4BosN3pdaPcWMlUPRBcEiZbduY8aoyBO8LelAMpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZuvYc2w5ltTzqoYSTNMnmpRuwAqsMkxP9unPprt3kVE=;
 b=UCH2ivqcR6f3cH9dMc3Fo9/04bEJeHr6gLC7N/SPLsPjRN8445kA/qBVALrcPICNDy/ch7IRhHD+zJ7MtG+EYggq6Q9hwa/LadtgCYlX2mDYWJcACmaoCsFt+dvvd1EA8/eXV4YAJbS5oqxoz6Rp0BNHKSgGxyUlsDpv2DeIKl3MTVUhp2eV2/10eA2BuDzUgPgmfvXxXrlIiDQCd3Yb/aAfo/7e9n6+3/pjKVmaBBvN33LNPoB/GxknsGk8BMo5G+ku83B4RNVGDcrWE9KFtQzevHAav/rFvpkWafk5cCNqsJ2onN0nG8dzEHtdBN5ZRAZIgp9TScN1TcHBX3MgLw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by DS0PR11MB6422.namprd11.prod.outlook.com (2603:10b6:8:c6::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5813.12; Thu, 10 Nov
 2022 03:23:50 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::c00f:264f:c005:3a5b%3]) with mapi id 15.20.5791.027; Thu, 10 Nov 2022
 03:23:50 +0000
Date: Thu, 10 Nov 2022 11:20:34 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter
	<cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes
	<rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin
	<roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, "Kees
 Cook" <keescook@chromium.org>, Dave Hansen <dave.hansen@intel.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH v7 1/3] mm/slub: only zero requested size of buffer for
 kzalloc when debug enabled
Message-ID: <Y2xuAiZD9IEMwkSh@feng-clx>
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <20221021032405.1825078-2-feng.tang@intel.com>
 <09074855-f0ee-8e4f-a190-4fad583953c3@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <09074855-f0ee-8e4f-a190-4fad583953c3@suse.cz>
X-ClientProxiedBy: SI2PR02CA0012.apcprd02.prod.outlook.com
 (2603:1096:4:194::7) To MN0PR11MB6304.namprd11.prod.outlook.com
 (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MN0PR11MB6304:EE_|DS0PR11MB6422:EE_
X-MS-Office365-Filtering-Correlation-Id: 83915a94-2f93-4fe3-0719-08dac2cafc39
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: arw2kZ16+UaG4X6m6ek1j5mBXN7VtCtilNPpWSLXcQuu5r9qoWCLvgL0Mojj8fWIa7qL7dUzvZQJTznSWA18mMo0mktbHjCJb6KQ+KllIeVydUkzfnFSSCSl4SbomfqLY2pKmaTAbHATs8IceCUmq9kuBbYdYV3nT8dmXGADlNba8QjXCwE3kdDvDhBijUi/BVWMKKpnhxO+Aws3D6LYxciPmDECHIrJw5koq2OPIzvfFO9aDGicNTOr3jaf3ALDcc9zMfEbL+OfUff44lm7f8MHgbXqrkQ4tpV63KWpuU99GrsJGkPE13KIiiOq7GqXjJmKBPfem0fonU3x9DwjD+23ml4ON3J03m7CooODXybwSBE3+j5FLrJjLK764Sm5XAMviz07Gc1yb/LE2UJ0Sm48lCimApOpqiNiImGoaldgj5aIkrEWRLQjPwdci6t1QqQiMJwbELNTq/ak+qhIxKxjxG6DeLJoeh9Ic1Yqm6BI3Rp8zL4ZnsJKPhVOP55osplep3JcEIfm7TqhAoO6yjMC+krd+yG6UyfN88DFbS3/jVA3hxo8AizOjtYACJpY3u5LdEvGsQEfvXtE935/kuTFXnv3PYO82uvuOzYkYMgM4HeoVUFRBMoe/ZxdSgiTEQX8Jk494CU+nyh+CmJFgnV4nu6mpPGqwm6bf4+AGPPCADNPS22sRwL1y0Ewo+71u95MfU0rLEXUrCkdsWD6r1/QrKIrGPb28DLb/54VtWoUDjS1fileCE3j6puP1YnKv/+LMkqSyl7QyJ+4qYSanQ==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(7916004)(366004)(376002)(346002)(39860400002)(396003)(136003)(451199015)(6486002)(966005)(478600001)(6666004)(6916009)(54906003)(316002)(6506007)(33716001)(26005)(66556008)(66476007)(66946007)(8676002)(9686003)(6512007)(53546011)(38100700002)(4326008)(5660300002)(8936002)(41300700001)(44832011)(186003)(2906002)(7416002)(83380400001)(82960400001)(86362001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?maANtvEF0g0Q2/6humrQ5+Llk1Ds6I49QXyZWPi2rdcpP9FrTDcaDV6U3S8k?=
 =?us-ascii?Q?otMGKF1lsbcEaVWYiUU7uN6qxEtW79MeVuBCRecdw46TVsdJclSkAfV8HgU0?=
 =?us-ascii?Q?PjmJqA8AAk2hFGosPB0bEXvr0e6IT1kaDlHFGkB8RzzaydHVoS2mB0cSQVTf?=
 =?us-ascii?Q?PdT39PZH9Lyin6vnGRtW8Rp2FfqNxVtow+2o2dwnd2+aLGD/LLmMjTukjm23?=
 =?us-ascii?Q?ZvdJ5lkpT+JUlv9gtpPOryhljxRmQvuq3pupMtSnhExWLaEOU+aczaHyzFJe?=
 =?us-ascii?Q?bH8+uX1NXpJGvPFcQ2LEcn55M4A1I4jykf5ak4UBWlY7tjWvhJblHGVeIiWX?=
 =?us-ascii?Q?IfWyfaCtyHJJZxTzqsNUv71wggnAkvK7/PYU6ERbt9sX/YiocqodoW4lYj3b?=
 =?us-ascii?Q?gL/6oHt9N3E8oyKcQ/RVJATKxfKsQ4uItdpk2ozsb5uPkGR4kFdaV12z3254?=
 =?us-ascii?Q?sovgDId24f7E8PJ8aWSMMuLzGanvz91GYPdworX/rqlrmZKG4sGefH31V6ba?=
 =?us-ascii?Q?WYfm5UDOJcZCVmbDQQ/IjDG3o3YCYN1555bDGop8i2njxJ1htoARkVAntQed?=
 =?us-ascii?Q?ekgYqK56ZQaBHLaCizMgZwqZphL704L2rCJfUyFemrGtTG2iQ7JjqqAEKYGG?=
 =?us-ascii?Q?V5toh3V4N5CqffdVG+61QaBiAWZSGGEj3q6WYQEeSLOVgU14BOSAdDsnAZpW?=
 =?us-ascii?Q?5Jfnda94nNlvWfzx5vG+w5K4zRNPiqsU5z7yma30oDaN/hEHnb0TFsqCLZXm?=
 =?us-ascii?Q?j617lgtAzZtSypCbO/a6AnVWoRIgJDYnqVSa1/Dp/UyuTjqLBwsG6wj8KCd0?=
 =?us-ascii?Q?DE3iap9Nfr1UL/W1d4WKBJEYhiMLr2emEYSbRFnIpmMhPDRhItQih78Nj22m?=
 =?us-ascii?Q?kh0kDtBr6QAWySy2zGyl9rsZ5vkgcoiw/fa4P1IEOLQgnz/h52FtdBfFXXxN?=
 =?us-ascii?Q?07NjoUn6NbC7Gba3zekb5fC45G4rlAZy3RaztW3u3QaGCAb6aIU1FeXn74aO?=
 =?us-ascii?Q?jwZ2J1ly56oBrjUnBvOPyCqaX61X3jw7QVJDdhGfQIodAI62xCV0N60nZXGq?=
 =?us-ascii?Q?WvDm11PJx4wraBJdi8i0JpzSK4p9gdPUVPM/mmv07F7HAtiALSSHbaHrlYA0?=
 =?us-ascii?Q?1wh4tGIjpsDdXJydjzNL0eIyBwlVb8e5m7FAKPHVOxC7ZsuUeb+huAlbOgdM?=
 =?us-ascii?Q?C41pkeTDezlBF8YTQumivZZUtBsiMBq7RPzGyWY/ttGosGhshemPUA+o08KF?=
 =?us-ascii?Q?DFBFR9b6HYUMbOhU0UUWW2qZpWOmfxLYe0qZYX7RmzU8KxN47hdFD3BxwENO?=
 =?us-ascii?Q?Dr9fwBZpkdP9YoWyWajuZ1MK0ukBaNOCzla6Q0KDb6dbkm9QV0ITPxmPEFX+?=
 =?us-ascii?Q?jFjoK1VOwuySDxfCdWfbsCNZiZdzFEZnkh0MzElPHMdc2EX85WS+J1Fa1cuf?=
 =?us-ascii?Q?3VZLwPEOyA9OX05KTo2zMerttWMXX2oIoFNg1DbUtIEOy/KRBzAZX+SEsxcs?=
 =?us-ascii?Q?ooOr0WcF5pN6G5ddCLKBvrI5nDDy3Ui6uGitgO28I5/N72KjmACoSs/pgcYd?=
 =?us-ascii?Q?FUBICZX3zgCbbQfQ6fCv15NMJvrLwk22iYStL9Q1?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 83915a94-2f93-4fe3-0719-08dac2cafc39
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Nov 2022 03:23:49.9155
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: TKA3oNUu7YvPf6lI98E45eGFCAvFeZsisTYSbeLZ3K8NpJAE/nhcrrM2PdpvKqdOt25Zi9dourYXB94ofRT4tg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR11MB6422
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BPJHl3MJ;       arc=fail
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

On Wed, Nov 09, 2022 at 03:28:19PM +0100, Vlastimil Babka wrote:
> On 10/21/22 05:24, Feng Tang wrote:
> > kzalloc/kmalloc will round up the request size to a fixed size
> > (mostly power of 2), so the allocated memory could be more than
> > requested. Currently kzalloc family APIs will zero all the
> > allocated memory.
> > 
> > To detect out-of-bound usage of the extra allocated memory, only
> > zero the requested part, so that redzone sanity check could be
> > added to the extra space later.
> > 
> > For kzalloc users who will call ksize() later and utilize this
> > extra space, please be aware that the space is not zeroed any
> > more when debug is enabled. (Thanks to Kees Cook's effort to
> > sanitize all ksize() user cases [1], this won't be a big issue).
> > 
> > [1]. https://lore.kernel.org/all/20220922031013.2150682-1-keescook@chromium.org/#r
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> > ---
[...]
> >  static inline void slab_post_alloc_hook(struct kmem_cache *s,
> >  					struct obj_cgroup *objcg, gfp_t flags,
> > -					size_t size, void **p, bool init)
> > +					size_t size, void **p, bool init,
> > +					unsigned int orig_size)
> >  {
> > +	unsigned int zero_size = s->object_size;
> >  	size_t i;
> >  
> >  	flags &= gfp_allowed_mask;
> >  
> > +	/*
> > +	 * For kmalloc object, the allocated memory size(object_size) is likely
> > +	 * larger than the requested size(orig_size). If redzone check is
> > +	 * enabled for the extra space, don't zero it, as it will be redzoned
> > +	 * soon. The redzone operation for this extra space could be seen as a
> > +	 * replacement of current poisoning under certain debug option, and
> > +	 * won't break other sanity checks.
> > +	 */
> > +	if (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
> 
> Shouldn't we check SLAB_RED_ZONE instead? Otherwise a debugging could be
> specified so that SLAB_RED_ZONE is set but SLAB_STORE_USER?

Thanks for the catch!

I will add check for SLAB_RED_ZONE. The SLAB_STORE_USER is for
checking whether 'orig_size' field exists. In earlier discussion,
we make 'orig_size' depend on STORE_USER, https://lore.kernel.org/lkml/1b0fa66c-f855-1c00-e024-b2b823b18678@suse.cz/ 

> > +	    (s->flags & SLAB_KMALLOC))
> > +		zero_size = orig_size;
> > +
> >  	/*
> >  	 * As memory initialization might be integrated into KASAN,
> >  	 * kasan_slab_alloc and initialization memset must be
> > @@ -736,7 +750,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
> >  	for (i = 0; i < size; i++) {
> >  		p[i] = kasan_slab_alloc(s, p[i], flags, init);
> >  		if (p[i] && init && !kasan_has_integrated_init())
> > -			memset(p[i], 0, s->object_size);
> > +			memset(p[i], 0, zero_size);
> >  		kmemleak_alloc_recursive(p[i], s->object_size, 1,
> >  					 s->flags, flags);
> >  		kmsan_slab_alloc(s, p[i], flags);
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 12354fb8d6e4..17292c2d3eee 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -3395,7 +3395,11 @@ static __always_inline void *slab_alloc_node(struct kmem_cache *s, struct list_l
> >  	init = slab_want_init_on_alloc(gfpflags, s);
> >  
> >  out:
> > -	slab_post_alloc_hook(s, objcg, gfpflags, 1, &object, init);
> > +	/*
> > +	 * When init equals 'true', like for kzalloc() family, only
> > +	 * @orig_size bytes will be zeroed instead of s->object_size
> 
> s/will be/might be/ because it depends on the debugging?

Yes, will change.

Thanks,
Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2xuAiZD9IEMwkSh%40feng-clx.
