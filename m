Return-Path: <kasan-dev+bncBDN7L7O25EIBBUUUUOLQMGQENCGOHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id E244358774D
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 08:55:14 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id v5-20020adfa1c5000000b002205c89c80asf1648951wrv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Aug 2022 23:55:14 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references
         :content-disposition:in-reply-to:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pcbwp64xzDgtC3h9TYyKWzzM9+fn3+k/zwcdWz4AJgY=;
        b=RWrxtQ6bTFgTi4MeUpptWi6NNpHSZqn8rxm4PTZuxJxq/aDxm1TJvVS0JICVp6WFxm
         iHI/p1QjzTO+ljRjJHboo8QY1lzN91SMk3Z3bTNCoQAVXwPNeGWte2grTd/zPGS3DCeB
         Ylxv7e98c0ZsxTgWkomMtycXIeGM3Ekh4qQFteluu84I1Q0Xun9nXFKXYWGh/U9oW/14
         6zCG+Kcs9bJeg6oz2pJVX8zG1qti/5/K9WYO3tHI+ciqe4nkw8LenKTQ2SiU9ptO8ynH
         W8QVKn46CvtGlV0hWptVpq6Yon/jnYP4YtjVRpGfS5P+gFN0Ig/bKfS8KP0P18gwBfgM
         9l1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:content-disposition:in-reply-to:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pcbwp64xzDgtC3h9TYyKWzzM9+fn3+k/zwcdWz4AJgY=;
        b=oe2TJm/vbPDOB4QE4GnbaUQk/v0gZWznolO084nSsgJbKY+y6hb6wuK7dnYxpAN4o5
         ytFC8drdsrxfGFXxE3aJEIe98FNxFlG+6L0gLtlP/D9Pu5DBhKoO3DPvUhQe6z0qaWQN
         Urwizv7PccDlPEhOc8KzKMhVVGe7EG6/gngbGyJHSfDq6asuq6/lEzOAIiEqrv95d73D
         QBpKTYIT4YNDD1JPM2agCdXoDwJve6D+11VjwfB11/CUuSPRbHe7INqRuWWyCDBnAcQ4
         BZldRpgVmrBZenpu1eHe0aZywLLTKMMrrbQRYWKNsiqEJesGA7L79DvmUyivlqyViROc
         lDew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2GDJEDgp9gic6jFGcHytZPu5uaYyUklTcLD+U+GHd/ZEBJRRcA
	4znnbB7ub6No6ruyTqP6y+0=
X-Google-Smtp-Source: AA6agR6yMuMGqQVrkLeSONBtRWqNX9JV7m1NZsdgYZb7v/spt6m6mHdxVq4yEh/lybTHy4/pgQKqFA==
X-Received: by 2002:a5d:4e52:0:b0:21f:15aa:1174 with SMTP id r18-20020a5d4e52000000b0021f15aa1174mr10427779wrt.106.1659423314504;
        Mon, 01 Aug 2022 23:55:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:668c:0:b0:21f:15aa:1c69 with SMTP id l12-20020a5d668c000000b0021f15aa1c69ls13767971wru.0.-pod-prod-gmail;
 Mon, 01 Aug 2022 23:55:13 -0700 (PDT)
X-Received: by 2002:adf:fe81:0:b0:21b:88ea:6981 with SMTP id l1-20020adffe81000000b0021b88ea6981mr12816836wrr.616.1659423313569;
        Mon, 01 Aug 2022 23:55:13 -0700 (PDT)
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id ay30-20020a5d6f1e000000b00220626c58c7si204995wrb.3.2022.08.01.23.55.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Aug 2022 23:55:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6400,9594,10426"; a="269718700"
X-IronPort-AV: E=Sophos;i="5.93,210,1654585200"; 
   d="scan'208";a="269718700"
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 01 Aug 2022 23:55:11 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,210,1654585200"; 
   d="scan'208";a="929855964"
Received: from orsmsx605.amr.corp.intel.com ([10.22.229.18])
  by fmsmga005.fm.intel.com with ESMTP; 01 Aug 2022 23:55:10 -0700
Received: from orsmsx609.amr.corp.intel.com (10.22.229.22) by
 ORSMSX605.amr.corp.intel.com (10.22.229.18) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28; Mon, 1 Aug 2022 23:55:09 -0700
Received: from orsmsx603.amr.corp.intel.com (10.22.229.16) by
 ORSMSX609.amr.corp.intel.com (10.22.229.22) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28; Mon, 1 Aug 2022 23:55:09 -0700
Received: from orsedg603.ED.cps.intel.com (10.7.248.4) by
 orsmsx603.amr.corp.intel.com (10.22.229.16) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.28 via Frontend Transport; Mon, 1 Aug 2022 23:55:09 -0700
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (104.47.55.176)
 by edgegateway.intel.com (134.134.137.100) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2375.28; Mon, 1 Aug 2022 23:54:45 -0700
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=AS3s29Z+BRk3tA3cCvvvhKyGI/lv1tcsPfX6zYGosBDVPvD2TNc8O/NVvm6YlItnowJ+s40Uf6D1nEzmxr7PVxsYkFQaTeHhIqBO/Iq+vDAmw4b4JDJU7OT807vRlfN4foTqHbODlzRD4CgztXkv7ERP/v6KQJxSO+Ge1tQ96XDZ1TTitIQ4J+evQHdrLkzopw4D5acooo1QDpdTaL7wHe6PHVShIWGyD5lzKcQXTjzpJ24LHFytNOPSdOnqx6yntbpn0Q4fRIUQvwP0dYbzBkUPeBzyiLBqqOT+4TLpMybyKa3JmEcBMqwvrRjNiw3qEoiKZ1YW9EaCMfHBIKezww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Lp+fR1Q9AGVrg5Loy6/FM9swxDoSpXdE99b/WnnY4jg=;
 b=IDYxt9JkJSA2LmYOk8tsj1MLQrilxTQHDzl87+HiyaB8O9ne+CgZ4I26tXJAO29K4CoJWoCztkUJUuRqILiEEqSqLWXP0YQOrRXLZ4Mrsz5ltN17D4cq6rUx2PYcPocVxn7bwwcrJGQ386pE8igcnLHL9Wp77qcLIAnZtgTYnAzJA2BWrTSCTe2OWxwUM9WvhbpX66VauFNCHgdiSuR/9RkbIujhZfUjcVaRth/tg4S3O1ddp4Yq0iJNm5IoWHZT7RLFESofFC9kHMTkVKDuhKonpsuJQMC5Oyqri6+KxB4Z+cS5OIg68b4kDrBd3VezRBJwDfYLCXFtIKes06FrwA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
 by DM6PR11MB3322.namprd11.prod.outlook.com (2603:10b6:5:55::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5482.14; Tue, 2 Aug
 2022 06:54:38 +0000
Received: from MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::8525:4565:6b49:dc55]) by MN0PR11MB6304.namprd11.prod.outlook.com
 ([fe80::8525:4565:6b49:dc55%6]) with mapi id 15.20.5458.024; Tue, 2 Aug 2022
 06:54:38 +0000
Date: Tue, 2 Aug 2022 14:54:03 +0800
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: "Sang, Oliver" <oliver.sang@intel.com>, lkp <lkp@intel.com>, LKML
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"lkp@lists.01.org" <lkp@lists.01.org>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>,
	Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, "Alexander
 Potapenko" <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [mm/slub] 3616799128:
 BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
Message-ID: <YujKCxu2lJJFm73P@feng-skl>
References: <20220727071042.8796-4-feng.tang@intel.com>
 <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl>
 <Yudw5ge/lJ26Hksk@feng-skl>
 <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
X-ClientProxiedBy: SG2PR06CA0203.apcprd06.prod.outlook.com (2603:1096:4:1::35)
 To MN0PR11MB6304.namprd11.prod.outlook.com (2603:10b6:208:3c0::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 724fb791-6c3c-44d8-b876-08da7453ddf9
X-MS-TrafficTypeDiagnostic: DM6PR11MB3322:EE_
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: xh8rj2YAYNr9NvaXSzpy5+ztTxxvOM20BtUETQFY/93r0mqdTbIRAlLV2p+0v0UFcx4arzBfq0OfRjHPICnGZb5e9hvDVhE2OXX2+gS98X88GpHK+LFyJuQFomlyN4qosl7gHN1AldOqYMXeZAvbBNB6sBx+v0nUL+IHsSlToN1B/BrA/a8wjEQ54hkWlgJdM0dM/ue+KBfEz6gc3YfagiKCF8E6vsr7QaH7VxdEbT3Sm5XdksW6nmqvkEINgQ5wKsP6gp85qG73wWpW++8TFQWB15qWweIg2yoHvMhbzzGPPklHaDLUdPqar9F6AGkA1Z5xduhONv1oSORlOZ//GlYoVCjT5UXls/jfZjKPH/Eu6cSlmGTtNBlj5L8RfxBABEM1TifX0Z5yW59f+9Ku78jdhLhufem08+HZrXt2pcYN+OFprAyqTE1h3PmCztDRD+7oFKEVMdBZ3sAJ1LgK0shhZCIqCo65mDexSw507UzhEyLYG9RZSGspu+AiKeMa+XWjF/vnChkzL6Guk73+ue/a0m+ZrClx2pYq47vKt8ySNyBJAb5lPcEONDWm1IiICSyiksIlHZrjx7hg4P3aVkESuf0mJG/L5SZyXTla60DeONSFzamSxvXEnWlaZNUeB5MT92D4Qkg65OvjfPiRkb68/fnXEntMZnSkBHAz59uFhcFgGlsNoCTuBeNlrZcXPNQbZY6ftSUUvyolpC61DU1nqxQwVmXbPSZygkJSt98BW7oxHY76M+UgEQN+iNg8
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MN0PR11MB6304.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(7916004)(346002)(136003)(396003)(39860400002)(376002)(366004)(7416002)(38100700002)(44832011)(82960400001)(54906003)(6916009)(26005)(9686003)(6512007)(53546011)(6506007)(186003)(316002)(83380400001)(2906002)(33716001)(6666004)(5660300002)(6486002)(478600001)(8676002)(4326008)(86362001)(8936002)(41300700001)(66946007)(66556008)(66476007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?8ZIj1cC8u63K82b2FuGSoANQUQMxjq/2LV/aEhsCn+VpYIl25WoEp26ax+TG?=
 =?us-ascii?Q?hOtuflwwmAqqbGUbTtQa6UcSDhrI5WPf7r8xNqIFiInW26e1AR+uM60vrQS0?=
 =?us-ascii?Q?hK5YPhK+los920YeFa2esIBnK5I2VRwd+BSp3sXeM7fcb3s/9HknLRbqn0oZ?=
 =?us-ascii?Q?m1ZSUoV0a42vc1kodvB+nXA2MJv5vE0Yc4zT3AZa/QpqZS6jcYU3Zs+HXZHW?=
 =?us-ascii?Q?ku2+Bb4EecOHVzHcRlo5JdDcuTh8+OMudvLK3ruf+ItS4GLEc1i996BkT6Dp?=
 =?us-ascii?Q?lWwMi4xSh52G8W2G1e6lX1upC23oKVwx8X9HOc6MpyYKoUoRXh2AN1lRKSfI?=
 =?us-ascii?Q?8VEH5xHHgb66Y9FDokT/2D29ocbPR3Fohikx5xNPjBR8XPQ/R+TtmoVg7rH1?=
 =?us-ascii?Q?UjAcFCc9H7vdklXdEL3bAUvcUDgF14xy3ZEqUi+/kvu/xcJLkm/ITN07RATU?=
 =?us-ascii?Q?nQD2FEwKso+0KgLpx+OGZm2ax4btNEU6HvFtvIVoAuHFXFwL1kL5cZ7f2YZg?=
 =?us-ascii?Q?tbcIYeVYPJjk41klyUAE1mPsEe/KVeUaUfp0bf9TJJsli6F/oZE8ud4JYfDp?=
 =?us-ascii?Q?RmZL+QqxPYWhUrU3jGqST8B9o6TY8gClk/GGE0BqC9Q3qvuEnAk4AsmkNmmP?=
 =?us-ascii?Q?Dmr6M3Vaoxa4n/SaEhHWI29w2LowtnmREKwZvPWR2upIIENA8RTDjcG8uwNc?=
 =?us-ascii?Q?jsHCHaITw4XmSjf3SQ9uLTo44ysbOfRvcJy+2kByHAuI7rGqd8y3jGb9JWgx?=
 =?us-ascii?Q?NAxKNnabpHAdneB3vxFVi1E1+SP2gT39UF8L94G0d9jbGRtHe4IvwrbzNS8H?=
 =?us-ascii?Q?gB9bQcnZMjVHz+aN+wCsgv2kRdurB+gpROoBOBWSJVPaHY3wzK3+YJnUz1z0?=
 =?us-ascii?Q?N1bbuE9C4VbkxppXnMQ4QKnagaP8uKf2TXlyAyuUNhpU2CT7DmabkvV9/X6l?=
 =?us-ascii?Q?LbttETSN0Cb3zu+eXxg+frc+f4agRfzQ9oMGkYChWyCWMu3IoItxjP2cdqt2?=
 =?us-ascii?Q?YiGGhkR8ILfUN9+No4gqHzLcVOwaJcCMo+sYvbJHE0w0qv971upA8uvSVMoI?=
 =?us-ascii?Q?wg/4Nx3Esh5OAkP/rrNnTjNcDZaARraLmNol9vNw2wGvedYfuhEwGf9HxLOP?=
 =?us-ascii?Q?U3Z2tDyDhbsGpruZ6aW3ju+NGpQ74Pr8OzViwf17NMo/SlfcsOcXN+8D/7bb?=
 =?us-ascii?Q?q+VOizqHXAoLxj9aNPuF/lcK+QqZnsDi5o2lY3QXNA00CZ4k3on7biQ7pBQE?=
 =?us-ascii?Q?99Qp72P8POQ7YZrBMN4O5PeAtSMHdSqy2Um6nF+6v2T3/WKNf3At7RT/RxDa?=
 =?us-ascii?Q?/bWvtc1tKdwoHT4mXhYTUhV9mvtSuLfWICBYIMjhi4hsHvGU7tCZdKiiw4xD?=
 =?us-ascii?Q?7qlNDj/ldWnjNAipUubRPEINLHPdZZ958D2dl0nQRfD4sVM9BmFy0DexIb5q?=
 =?us-ascii?Q?P0YCtEgf06Ubm3vitvwhrr/pTW0Td6ttlsl9n067drwyZTNqAaIE4ODexKeo?=
 =?us-ascii?Q?Wu0+JNm3eyPv/OiuciYNciAQ9DYDoFu+CUJu9mwg33hT+508VxYiJLfGEk9x?=
 =?us-ascii?Q?qRY8f3GHgDmt4FZ32qqhPwd1pnGYSjOjDYwkPfZU?=
X-MS-Exchange-CrossTenant-Network-Message-Id: 724fb791-6c3c-44d8-b876-08da7453ddf9
X-MS-Exchange-CrossTenant-AuthSource: MN0PR11MB6304.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 02 Aug 2022 06:54:38.4240
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /4WQL0JM29k7MSj3YETR2EnHPZaxwWnpuvBfH8FoT82aAQx/nw3FrM7MguE9DNxtKEwwZ9dod8GiKtfXbdt7wQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR11MB3322
X-OriginatorOrg: intel.com
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=cmum8iHq;       arc=fail
 (signature failed);       spf=pass (google.com: domain of feng.tang@intel.com
 designates 192.55.52.151 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
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

On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
> On 8/1/22 08:21, Feng Tang wrote:
[snip]
> > Cc kansan  mail list.
> > 
> > This is really related with KASAN debug, that in free path, some
> > kmalloc redzone ([orig_size+1, object_size]) area is written by
> > kasan to save free meta info.
> > 
> > The callstack is:
> > 
> >   kfree
> >     slab_free
> >       slab_free_freelist_hook
> >           slab_free_hook
> >             __kasan_slab_free
> >               ____kasan_slab_free
> >                 kasan_set_free_info
> >                   kasan_set_track    
> > 
> > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> > tracks: alloc_track and free_track, for x86_64 test platform, most
> > of the slabs will reserve space for alloc_track, and reuse the
> > 'object' area for free_track.  The kasan free_track is 16 bytes
> > large, that it will occupy the whole 'kmalloc-16's object area,
> > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> > error is triggered.
> > 
> > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> > conflict with kmalloc-redzone which stay in the latter part of
> > kmalloc area.
> > 
> > So the solution I can think of is:
> > * skip the kmalloc-redzone for kmalloc-16 only, or
> > * skip kmalloc-redzone if kasan is enabled, or
> > * let kasan reserve the free meta (16 bytes) outside of object
> >   just like for alloc meta
> 
> Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> enabled, we bump the stored orig_size from <16 to 16? Similar to what
> __ksize() does.

How about the following patch:

---
diff --git a/mm/slub.c b/mm/slub.c
index added2653bb0..33bbac2afaef 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
 	if (!slub_debug_orig_size(s))
 		return;
 
+#ifdef CONFIG_KASAN
+	/*
+	 * When kasan is enabled, it could save its free meta data in the
+	 * start part of object area, so skip the kmalloc redzone check
+	 * for small kmalloc slabs to avoid the data conflict.
+	 */
+	if (s->object_size <= 32)
+		orig_size = s->object_size;
+#endif
+
 	p += get_info_end(s);
 	p += sizeof(struct track) * 2;

I extend the size to 32 for potential's kasan meta data size increase.
This is tested locally, if people are OK with it, I can ask for 0Day's
help to verify this.

Thanks,
Feng

> 
> > I don't have way to test kasan's SW/HW tag configuration, which
> > is only enabled on arm64 now. And I don't know if there will
> > also be some conflict.
> > 
> > Thanks,
> > Feng
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YujKCxu2lJJFm73P%40feng-skl.
