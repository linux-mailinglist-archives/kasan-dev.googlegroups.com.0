Return-Path: <kasan-dev+bncBDZYPUPHYEJBB7EU3WOQMGQE5NATRGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id F146665F66E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 23:09:00 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id p34-20020a05600c1da200b003d990064285sf1601699wms.8
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jan 2023 14:09:00 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MzzjnhLCZTWPf/uVALOTESp6qIR+nZL+r5t7/tpubtc=;
        b=k+jXdWV7/uwmhrupCib/Gz9uNUcGmJg99gLNqI+fws/KOFxLQ8mxQmQPExMveHCAbd
         5Y08ZLjb8F0T1ZRzL0bxOh4DrKYRTBF15UP1xa3Mq4s4fkYZ5jLGBCvDU3M4zYlOikOT
         x6RZE9IW0HvUaTqdyzin/7OJAAxBN+K+NmvnZf84eAB0/jBQFRS4rZWlCaVkuA+0JAzV
         ZJ89v+xjx4MBdo9iHKaNh4ppaF5EsxD+gsZmaDDZoFL+QYDaZGcsMNKuRQzVCoY3D72W
         EXERqAaCy+7CjSmtXxKgmeaCwAx6ofPGY7yUTi15ujXCF2xkAcLMVnLGZBNuObQz4VbA
         75Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MzzjnhLCZTWPf/uVALOTESp6qIR+nZL+r5t7/tpubtc=;
        b=xIHDjPRoCkkuMNwOxAOJy6F763KubHhlEsRa4XtbqunO1qTAQDAjdV4tWkbE234R7R
         oguZNGJILq5S7UCulJoUkfUi4x2BDultq+l+twvIIJOj3ktE9OY9TyGFeV69s5iS8uEW
         BWBNMe/DeLxUmSMbsv+46c66Q7akw4eprZiYdpfWhmbrFmxxWA7GxISk+pL/ZOCYtfz3
         7+eIRU/2eQ/b2owdNvG+S1ukm6/Sv62Hg4SGS8rbuVZ9l75tBhFv0BMxDnzdO+sRlDQB
         4t6xkvbU26f6Bo1qdOxVZ3JVJGVwY6nhyFpqftZc+WwB8gjeXMKRmXnC8UgUf19v/c3X
         Q8wg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kogdU8PJV6cg6zrxnqYD7x7+WS0gexlObODw0gVTO/E0sWJh2Fl
	6zawZebteM14vm/Ev4JSf4k=
X-Google-Smtp-Source: AMrXdXuVqAFz2LMHhvMMparQqTU6ABoee9LYWDwizkmWOjKgwUK74X1hdVooy4g2pSfj/mw3K3Qp0w==
X-Received: by 2002:a05:600c:354f:b0:3d0:5160:c81b with SMTP id i15-20020a05600c354f00b003d05160c81bmr3163663wmq.110.1672956540519;
        Thu, 05 Jan 2023 14:09:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d07:b0:3cf:9be3:73dd with SMTP id
 l7-20020a05600c1d0700b003cf9be373ddls203941wms.3.-pod-canary-gmail; Thu, 05
 Jan 2023 14:08:59 -0800 (PST)
X-Received: by 2002:a7b:ce06:0:b0:3cf:a483:3100 with SMTP id m6-20020a7bce06000000b003cfa4833100mr37345016wmc.3.1672956539262;
        Thu, 05 Jan 2023 14:08:59 -0800 (PST)
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id ay6-20020a05600c1e0600b003d9c716fa3csi260520wmb.1.2023.01.05.14.08.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Jan 2023 14:08:59 -0800 (PST)
Received-SPF: pass (google.com: domain of dan.j.williams@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6500,9779,10581"; a="349551516"
X-IronPort-AV: E=Sophos;i="5.96,303,1665471600"; 
   d="scan'208";a="349551516"
Received: from orsmga008.jf.intel.com ([10.7.209.65])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 05 Jan 2023 14:08:57 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10581"; a="686267675"
X-IronPort-AV: E=Sophos;i="5.96,303,1665471600"; 
   d="scan'208";a="686267675"
Received: from orsmsx602.amr.corp.intel.com ([10.22.229.15])
  by orsmga008.jf.intel.com with ESMTP; 05 Jan 2023 14:08:56 -0800
Received: from orsmsx610.amr.corp.intel.com (10.22.229.23) by
 ORSMSX602.amr.corp.intel.com (10.22.229.15) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.16; Thu, 5 Jan 2023 14:08:56 -0800
Received: from ORSEDG601.ED.cps.intel.com (10.7.248.6) by
 orsmsx610.amr.corp.intel.com (10.22.229.23) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.16 via Frontend Transport; Thu, 5 Jan 2023 14:08:56 -0800
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (104.47.70.101)
 by edgegateway.intel.com (134.134.137.102) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.16; Thu, 5 Jan 2023 14:08:56 -0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=nCuZyI6hDer4lEVJFARAqyB/wR6YUoAeaoWmwfgCT1ySR3zPmcAyNjPuT3yronhLpG9meux+09Pa8u3R7Lnl21XZhUYZ2vjW8N++Ctgc4ZwdyVJfZT41FOB3cbN2gNQcoJKtsn+UpK7eco7mZccTeh4WTuhJmod5rYa4yk0oVwG0d9LnVpU0my8EXS+1r1xykWSZW6KXhwVEqT77O9GuihjUknHy7avTr/0jRoflA4aK35LI65FgVxrCDJjI1S7uCM2NF4Ht0WRrCVVA+4zcmmJkV8rds76HjamtJcvN/hthTj1zvZoggCetEyXa3PF0SzpoDm6tf+BE/3JZvd95aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lFJNOQWy3H+caJ4ySpd5z++SrjQJp0tOnsb77LxfyDA=;
 b=L7SUbjI4jAHFRn1suBzPYO9tlAH41zUwS+wgtsfBE6P64zuEIQYFrDgGtaT/E2J0qdJvGh42X8pcRMFLASi6wyPQHFH/GXOQwOYgC0CUcaZpWqVZU9hoJSwLTh2gGclcWaS8D6UGK4mtz0s0aonhIe4IU9NJNbIVapxqGI3DFbpgQbxHD4xqbky8KXWtvz6vstnaXm7SH/RBt603uP1KemNzBX7zB9lLG/VUTj/WefAUehDGGMCtyNKMJeOaCNwAL13yaXEo0XZj9kFqYG+llIvj8It4p8ySqSchbyeAcfgT35e42ej3K9QBuu94RpOlet4u5s2qqUqdagmYKr8S2Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=intel.com; dmarc=pass action=none header.from=intel.com;
 dkim=pass header.d=intel.com; arc=none
Received: from MWHPR1101MB2126.namprd11.prod.outlook.com
 (2603:10b6:301:50::20) by SJ0PR11MB5149.namprd11.prod.outlook.com
 (2603:10b6:a03:2d1::17) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5944.19; Thu, 5 Jan
 2023 22:08:51 +0000
Received: from MWHPR1101MB2126.namprd11.prod.outlook.com
 ([fe80::8dee:cc20:8c44:42dd]) by MWHPR1101MB2126.namprd11.prod.outlook.com
 ([fe80::8dee:cc20:8c44:42dd%5]) with mapi id 15.20.5944.019; Thu, 5 Jan 2023
 22:08:51 +0000
Date: Thu, 5 Jan 2023 14:08:46 -0800
From: Dan Williams <dan.j.williams@intel.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dan Williams <dan.j.williams@intel.com>
CC: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
	<ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov
	<andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann
	<arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, Christoph Hellwig
	<hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes
	<rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet
	<edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich
	<iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe
	<axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook
	<keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
	<willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
	<penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
	<pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner
	<tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum
	<vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux Memory Management List
	<linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, LKML
	<linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
Message-ID: <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
References: <20220701142310.2188015-1-glider@google.com>
 <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
X-ClientProxiedBy: BYAPR07CA0030.namprd07.prod.outlook.com
 (2603:10b6:a02:bc::43) To MWHPR1101MB2126.namprd11.prod.outlook.com
 (2603:10b6:301:50::20)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: MWHPR1101MB2126:EE_|SJ0PR11MB5149:EE_
X-MS-Office365-Filtering-Correlation-Id: a7915380-f8f5-4297-18d4-08daef696d07
X-LD-Processed: 46c98d88-e344-4ed4-8496-4ed7712e255d,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: lK0Y8fCE+ahoZJWqDtnxEH2NXK+6/4kZjotkc/lHgG48Q8zFja0HZ0uAJlKwabOJJ9WbHxNpbSlY0p2qxsY6PBcTIiArRGfYfhQYP4xpfKrLKXSZDYrGF1I8y8FjvblyJBJuKf/YdHZreJItlCupb6wJhfqgdd6b66+TMcKujWZ+DwnjiT10JcAlqhp3dW4aVH8urmv1RjRv0tKkfet1VRAiQWOr7bdVuyLbXowq3MEEAm+wu8OXr88xC7oA08OsVkKTyKfhe8SP9nSsLWqkD09csbwpMiguD0tkPd/1CApXfnhlMMYzm19yUyusA1tVCE+tzWl5PLWaJ61pBp5CH6XmyxGp/vYDVsl8AOX60+Ru9LKaV1z9rdGykKZCN8e3zxGY9xzPCW0qyZ+DIsxMWNvLchBpwKQB7GMvrYChE+0PvKQwDmqlrkJWhaVhg8hbP2xsM4NVPJ3Jds4/z4Pp1JCC4q68+36f8vBmRrVMOyUdUTQFp6dysoOeaJgfwR9Y/ZmwyFFSsq3pjDSSxrs4InTmAl9FA6AQ63qRRoCQF6txbfNLrK76/glPSXhmQLqfcjeL0KWb8rH/G05QTncLq4sU7SMCXrnvk/QJ1/rXj+OHRcp87WvHG2ufTVXPqPkV8MVxCh18HRmqp6al289K4g==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MWHPR1101MB2126.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230022)(346002)(136003)(376002)(366004)(39860400002)(396003)(451199015)(41300700001)(316002)(54906003)(8676002)(4326008)(66476007)(66556008)(66946007)(86362001)(82960400001)(8936002)(7416002)(110136005)(38100700002)(83380400001)(5660300002)(7406005)(2906002)(53546011)(6486002)(478600001)(6666004)(6512007)(9686003)(186003)(26005)(6506007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?rbPk80CbsS4ovs3FoDhlD+TZfoeT5k5zVBbkr5w/8fP8yT+UBSgZjVJkrDRx?=
 =?us-ascii?Q?vdSSBDFNUhj5XywfffZGoKjUVuwwGzP6UojP5B6B+jVli1XjCWQ0uHCBPWPS?=
 =?us-ascii?Q?MllDIkkSTxtwQmjXHNRCKRLqnq5+CCBqqt0S1iYV2xCc/fHagOR3cL6tYfPu?=
 =?us-ascii?Q?eB2qxrj/jLOIaPf9eitr9Nwr+ECyoAsr/di41GJTTA1H93DfGtAr4xgxYr1v?=
 =?us-ascii?Q?4vAKETL0Yl+yks+xCQkZlrJvI8oKvB6Y4G8SYi1P0eAeRPqRTlYzYPEjifLo?=
 =?us-ascii?Q?kgnQc0tnNCLNr7Ua09KXihiIfvyPoICUF/X48mKi2CyGNkBYxg8e1mA3osvf?=
 =?us-ascii?Q?khKs5aq2CgstLubhUxnVbesYcmbbBlJ1evtoJRCbD3dpT0GgsdqZq93iWYnV?=
 =?us-ascii?Q?aiFj/unFNv+uwyK5BoHQfKefUJZn4aprvukSFZdmz0Jbry8wbPItevOiGtIe?=
 =?us-ascii?Q?9afJ60beT4uwdYj/Bu1kVb+NbtXlW7CwKU5y9dqp9cyIw0WRuJauyOF+olj2?=
 =?us-ascii?Q?cvGncuYGaQ1P7Ovq7SSjAE/TgvdJBoBjQOyxFhQocum46rcyA78PQB+XwCZ8?=
 =?us-ascii?Q?mVW1Y3lhdxrUPGUl90VqsqC4c8OnPRk45tAHuDVgq6JN6p5GIJEb4TvMhWst?=
 =?us-ascii?Q?i/xPtc5oREmDDKQ3BPMZnmZ/p6IHP9i3rguvFU7yGDBQHHpHvkrFcHmFaPrm?=
 =?us-ascii?Q?BX0YK3AdtLgw9kImrGWeg6G6bsNlXCrzg0jqWX8Z/mI0fPrHJ1rQT1m++7nf?=
 =?us-ascii?Q?Xri6XNbeZdjE8YChhihqXicAupUVuT4Oyj0WI8q67NR4a9ttgoLNY1i1nY6F?=
 =?us-ascii?Q?hJhfG2cz+lT8yKZJNJkBjwAUYrPywHAe7iVOIvdKseinbw9ni8YYUipMxmUV?=
 =?us-ascii?Q?UCkbFeYqGUin6SnRuzznbzZTX/AzQxyDDqZdOFaL6zOzhKcu8zH4NPQ1CEIe?=
 =?us-ascii?Q?efI3eLsJOv6hSjdqGDT8vq9eB30w5+/oNKHepJpRjTbCue+OiP0bsbX+idt/?=
 =?us-ascii?Q?uPkaEKFv8i7eeEz2E+sU01O2bRAXdWWKuHKxuJ3LQ0zcypBcpmsMMo4g6MGR?=
 =?us-ascii?Q?SARnT99W3i8f0kN75YY+5eaZ5kSR97eNt5ibk00CEOQrTtMxkrMcGso1lgkS?=
 =?us-ascii?Q?gHGAYPM/8rVxj29Xs6AplYMJOg2PQuLOl/qwgBBE1ND6aHpbJtHRqyVRIZ+W?=
 =?us-ascii?Q?nfNjjIDeZAExawT6Lot9NYGP+CnbEbqFoIP6hLGifyDkrBbOpYSv0axDhvoj?=
 =?us-ascii?Q?O8oSu6cNCVHhDmUXhyHf3+scNRExBTF2A1/yQWqRNPz/tmUADpZxhv/GFenE?=
 =?us-ascii?Q?Umin7ugL7XMY9/q/o65XU+DfLc/o0y+6qtJ0z2MKjaCQ+Hw0swBZEmp9fOcO?=
 =?us-ascii?Q?MWRo+8gaT/5EOd2Xc6cXAu7Z1h7/RHtODJW9qSeIez9CebEgplLbZO1VMN4j?=
 =?us-ascii?Q?jFfN101DNvw7BJziVJLCyznJkZbHhSjEpsYv2VTWFvAyt8GraYyhI/hlBNJH?=
 =?us-ascii?Q?VdUtDO9vFuz9J0zW8Ak++EqZBE35so4XQhP/m6C37vbVnl2GqZKpzWu4Jmp+?=
 =?us-ascii?Q?zlyAoGhkQv3xa7/oHWpvwyGslbMEtqj5zvZmBL+cEhCkYU8uEhdyUWZ6p2MW?=
 =?us-ascii?Q?7g=3D=3D?=
X-MS-Exchange-CrossTenant-Network-Message-Id: a7915380-f8f5-4297-18d4-08daef696d07
X-MS-Exchange-CrossTenant-AuthSource: MWHPR1101MB2126.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 05 Jan 2023 22:08:50.8944
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 46c98d88-e344-4ed4-8496-4ed7712e255d
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: BYocwcEYz+Beg/+hR1rvA4bbZurFzNJ9DZ4zc0saB+wLOFFzN3DZUw1+9u1agxfezC9cwdUom8WHFAGRpR5E74dWAz4H7hRNTvumxTsrrnM=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR11MB5149
X-OriginatorOrg: intel.com
X-Original-Sender: dan.j.williams@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="kEolK/cm";       arc=fail
 (signature failed);       spf=pass (google.com: domain of dan.j.williams@intel.com
 designates 192.55.52.88 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
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

Alexander Potapenko wrote:
> (+ Dan Williams)
> (resending with patch context included)
> 
> On Mon, Jul 11, 2022 at 6:27 PM Marco Elver <elver@google.com> wrote:
> >
> > On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
> > >
> > > KMSAN adds extra metadata fields to struct page, so it does not fit into
> > > 64 bytes anymore.
> >
> > Does this somehow cause extra space being used in all kernel configs?
> > If not, it would be good to note this in the commit message.
> >
> I actually couldn't verify this on QEMU, because the driver never got loaded.
> Looks like this increases the amount of memory used by the nvdimm
> driver in all kernel configs that enable it (including those that
> don't use KMSAN), but I am not sure how much is that.
> 
> Dan, do you know how bad increasing MAX_STRUCT_PAGE_SIZE can be?

Apologies I missed this several months ago. The answer is that this
causes everyone creating PMEM namespaces on v6.1+ to lose double the
capacity of their namespace even when not using KMSAN which is too
wasteful to tolerate. So, I think "6e9f05dc66f9 libnvdimm/pfn_dev:
increase MAX_STRUCT_PAGE_SIZE" needs to be reverted and replaced with
something like:

diff --git a/drivers/nvdimm/Kconfig b/drivers/nvdimm/Kconfig
index 79d93126453d..5693869b720b 100644
--- a/drivers/nvdimm/Kconfig
+++ b/drivers/nvdimm/Kconfig
@@ -63,6 +63,7 @@ config NVDIMM_PFN
        bool "PFN: Map persistent (device) memory"
        default LIBNVDIMM
        depends on ZONE_DEVICE
+       depends on !KMSAN
        select ND_CLAIM
        help
          Map persistent memory, i.e. advertise it to the memory


...otherwise, what was the rationale for increasing this value? Were you
actually trying to use KMSAN for DAX pages?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/63b74a6e6a909_c81f0294a5%40dwillia2-xfh.jf.intel.com.notmuch.
