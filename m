Return-Path: <kasan-dev+bncBCN77QHK3UIBBRGK2LCAMGQEMWL6EXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B73CB1D891
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 15:08:23 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-32129c65bf8sf1201533a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 06:08:23 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754572101; cv=pass;
        d=google.com; s=arc-20240605;
        b=NDgHmiXqo1NWCjpyM2MrsmI31053JnjBisqUC1R8DKjfB3VCdO+ANQM7KO4CWE2UD9
         crCprZsy324+UGuFUcTK7XvKM0QrLtgm2DyX3qpWDNvEC3qKzQpyw6JOMFl2jatKqv/A
         Vb4ZoZedwo4dGUlHJUcH/SrNM7xdv0Psf4eC4ObVKzDOoEkPeTzLL896mn6UQDvZ1OUd
         2rWVNq/u09+e4YMbmgWLBIJwNyNa0JZDL1JYCpgiHrDmQYXKSiRnGapwt3ugmVgIqNS3
         RKD8socTNmJ/U+5Jf/Jk+olksXGYY3ZdNRGUUUkx1RvhYxJz3VTnzN9WxCMDjdDUH6QT
         t8qA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=GyaursgnGt8Y7Avu1WNz7KQNWImBZYVEa+P9dlUhPOs=;
        fh=UDwy1LkyBxxGZRVJSzRAvuDvpTElFOhrdMeBwxTOYU8=;
        b=aHUbbkCzvKMLd6JRnJC0mEnVer+F0V64kF9XSKXLKGxzmnl6izPP00Wcz/nzzBRtPG
         XdBA/OmAQh5sYtSc9pNCZHZDxHz7GE/c3OVRUOUTxhawB2qHk/BDXe5Hp6rg6dVtUxxM
         wfknwPsEpLhRwuPz8h7EphL4gS8UcZ7GO3EHx6Rhk7Fcxkdkzmh7TY3ZIkCU+h3dKx0R
         N3cm97YwRL4TVbLNyr+5gtJ+Oa1XCcAPTPrLg3zpiYKaeb5GsxbX/ewR4ra5anC2hovA
         r8T9hdAt++VLK+p2RLGMhBwtvVc6YnNS7RnLUq8H2T1GTjq+yOs/342duhgFn5tf257g
         fYng==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="M/m2K/JO";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::629 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754572101; x=1755176901; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=GyaursgnGt8Y7Avu1WNz7KQNWImBZYVEa+P9dlUhPOs=;
        b=EyRENFLjo4CqXeTRS2mQ1olrq9dwSjohEcG0HrjBOkXEZZz5S/ij7z9mrpJ887zTQD
         ehS2AHW2dv1VHfcbN5Qa16L73XmuWty2EhLL1P5IlJQkUSzls7R9fxjZ4eK27rOA5QhP
         CE4+L5cZDwhtAsYnTGIuZ5NPB4IIfRDmW6j/4Sgj0W+VwA6+E3OkVBVzr+ApmoXcZL86
         QJ8V0z+RNKSvLVgSnv6cdnu5PugqMum4d5aEODUvo8pd8Jb5qClssqYdEMQxyNIjANEa
         nYWZF/P9B6S9bon4p8aoH4gj9GbDjLBipKoebAtFo6gw2Vioat4HEcOVTpQdfxW774f4
         54iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754572101; x=1755176901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GyaursgnGt8Y7Avu1WNz7KQNWImBZYVEa+P9dlUhPOs=;
        b=sqNZsQNp1Pd9qLtq04jR+TU9CZMXEUvNb0lpGvnNPKKjGEZCFW/OkZL4ZQcrL2Cfxi
         yucvSR3S9f1l/X42fHE1lX7qm4pokzd32bBKOID+0lRZSNTE5pkVCkEF0dY119d0XL5q
         s2ycXoNMG7EanxtraKIfCLxosVnOorrMfYZ6b6ukUW9GUFgVEziZSh3EGWVy4Bmuxh3r
         XDTZzsh1Kv59doux2+YJ2rvNwmNLI5wgp0MoGtaCDLwAjjUB3cYlOJMn9BKSXdN7m1NY
         yfGzVAlyeErXU/MfPfoFJOb+IedUUMcM2rZVYVC0m9NPBTegpdYCGow5UmpWfX8iWRQT
         958A==
X-Forwarded-Encrypted: i=3; AJvYcCV+IlXjp70oTFPQ29gHvkJQBy4wSjU+OmpFmDBk5Ja1UMuKc9VQhTMw7HuMNJp86dhklHh79A==@lfdr.de
X-Gm-Message-State: AOJu0YwlGvKhtYXL1sN7Uwdbznj/N/DWj/YHU2jBRgyTWPha9lJUVDJ0
	pN41jK0c7f349tQK593u7IfoljYByl75/AYHNuLT71TaN9IePyCHj7e1
X-Google-Smtp-Source: AGHT+IHCooPQmVfn8tHnrmsXasarybw1f07XT3CYUoIPPZE/j2eFCfKeoMuxr1+AjPfBv2TZvj/0QQ==
X-Received: by 2002:a17:90b:1850:b0:321:27d5:eaf1 with SMTP id 98e67ed59e1d1-32166cc8bc2mr8912654a91.25.1754572101119;
        Thu, 07 Aug 2025 06:08:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd61x2hKWRQ88z4QaabQHiG3Kib8LiMpDT6XQbr4KmEoQ==
Received: by 2002:a17:90b:1909:b0:321:6ddc:3398 with SMTP id
 98e67ed59e1d1-3217507b7cels869060a91.2.-pod-prod-05-us; Thu, 07 Aug 2025
 06:08:19 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW7r5qSM/av6CJw/iJi/Nvmvu3g7kAtdrhIiwEWy3xhc5KzLAEc9d8Jr0LGftKGwxSE+xtAslyaAEY=@googlegroups.com
X-Received: by 2002:a17:90b:1812:b0:318:f0cb:5a50 with SMTP id 98e67ed59e1d1-32166cc88e8mr8259176a91.26.1754572099447;
        Thu, 07 Aug 2025 06:08:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754572099; cv=pass;
        d=google.com; s=arc-20240605;
        b=F0OrC7pKzQZBCldMk10wER5i1a9eg2phIr6pkSMiNTOt9tv+5vPrg/s2RFjxfQPKfT
         +eWlgOu79nM8+0oGkFwAizqv2yuJPrmqoIGgby/XQZXhz9Gxe7X6iBul2n8ku3UviygS
         dkNQUwGLDXUlc2aObOZpG83UFIvEk36kcAGF9rWMlYcI/8OuNrjcP2dsgOcP7zNVLiXW
         m1qBoBBpIrD5YMfv9eRzEgezbAU56P9tRGSuVkcD4mM920ajM66TNcQPzcRsp3qwW5yV
         m34jN0XY1UeDN23wjVbIPySC9l+NlwNdkf1xMcAc/uDtH2YJGbEJI41ywwAYvN2sIqcg
         aHew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HcNahN9GoGL0AP88sLUVxLsV+OiezgDlSya5Beqdmb4=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=imnIkm1HMfjhemLhUKXzANMShGhb2ual4gBhtZCN3p+8wOTek/KcSqPYJjesQtudmf
         4SaNyCxUVqEX7oq9WWRl3i8/2jfq5EIsk1kmJLRCrWSbVZj3rvNFd1lD/puIh7B3JA+R
         hLkhHnDab1YJW6EVuKL3Vzx6H3MC9HYaolG5u9HC5drL0eqkdEREMHEtdbWvH6cc/tVv
         quXeeaHsrBW1dwSn4mhsLvlm39A0aoMeM076UkNB0E4iVXFQjIsAtLfHvUgYhzaYcNjF
         LCrxGzw+rmXiwpYrkib9wP86AMu7HDCq2Ood+r+kWjHGjQYSKdII5tj60b9H4/JZ88X2
         GEQw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="M/m2K/JO";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::629 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (mail-dm6nam12on20629.outbound.protection.outlook.com. [2a01:111:f403:2417::629])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3207ec5d581si915619a91.2.2025.08.07.06.08.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 06:08:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::629 as permitted sender) client-ip=2a01:111:f403:2417::629;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=tQ1+zt8SxkWpi6XQvKb/4txJLmNhj/lKE1tbbt1yHm5Mc5mfMh1id0s7n9GI5o++auSo5fgwsbyFF8RGHy/AhtAQmxzQ50KAfwY+Lk+ne7i9/mPM6kIjAisy9OVGCuJDn89lx40GkRUvA92ncv0c2r7XBOY1KlrUvG81hcJl/JCd1EKx5Qz3kZ488T0o9nNYANzl74kNcFUIhK1EKWagmcQFDl7gCFYfa/YppIhvPXVVWPvY0tosrnQ06eTFBoFUEu1y4rfvyEjIg0ev32yYzL/OxMyWvHTDYb6Vc3xTRZh/5pybM9kmC5wf/gCuvZ7fNOa3OtGQIP1Q8Pvuvl0srQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=HcNahN9GoGL0AP88sLUVxLsV+OiezgDlSya5Beqdmb4=;
 b=kzDGV6ClUN6JhAsCb/Tg2C17AqRbsb3oWrHgWl17B9xc8vaSbqHGdsTIoTLBp8xnm7fuotA5anPz87YJfP9LyCJ4aXVEJHepCizOuK5BZjEA6OSQ/wJlCsuslw8jZAGYQ+OVW7nHymzqFALhtmHmdtBC1jSarxIPH4iwu6ViqOWNDcXBuuGW3KqEEcm67zRTLCtxpgU50wz0Xa3B+SNZIKomGv06gR3y1AtY4jwGFe7EDNtR2A0Cu1gQr0YYJQf9F4b331gjSHFe+aMKXkuj3/CMchqVpsMKgeSg3af87PgeGXihKo06Xheu+myXJZautZ77luPaUmCww9ZssjNJug==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by DM4PR12MB8558.namprd12.prod.outlook.com (2603:10b6:8:187::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.16; Thu, 7 Aug
 2025 13:08:13 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.017; Thu, 7 Aug 2025
 13:08:13 +0000
Date: Thu, 7 Aug 2025 10:08:11 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leonro@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v1 09/16] dma-mapping: handle MMIO flow in
 dma_map|unmap_page
Message-ID: <20250807130811.GI184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <152745932ce4200e4baaedcc59ef45c230e47896.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <152745932ce4200e4baaedcc59ef45c230e47896.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: YT3PR01CA0108.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:85::25) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|DM4PR12MB8558:EE_
X-MS-Office365-Filtering-Correlation-Id: 08950cc1-2de1-4780-484f-08ddd5b376d7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|366016|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Nq/4a2aPxe/mtkoI+QV41hdJKUg3cdlvSoOR/muTmjH0jenhZt1pRK5w3IzH?=
 =?us-ascii?Q?p/QFHExc/MgAgAc9aZQDcNnoHwi28teNBmt1OWbiyYcoTOc5Cb2wtWDPulgK?=
 =?us-ascii?Q?lRbbS7eEZagenmxQTEc+UUnF8s1mRoMLRy32fpksYmbw5v8mYjrbqJAKM1u7?=
 =?us-ascii?Q?KOTKhGVh777MbtRutO4zJRcrF1kRDXeKNnthTkAOSt/dKpif4LMWsvTKEha4?=
 =?us-ascii?Q?Q1VF2VW8cL2wutuXlsjVj8hGa8LVjTreJD7E3Z1xkfakk9+ka0SyNAseQpcG?=
 =?us-ascii?Q?gsLbMjQCzBddVDXCW1kuNJvSGpoI7lnQiSfA7pZ8ADRalwfE+Wd03wgQR3C2?=
 =?us-ascii?Q?kLpHy3kjaXHOmiEXvOv++7pxX5zMW7IRAtLjqcjoQHoev6H3/qXbKik5wHXc?=
 =?us-ascii?Q?RRyt/ae8W9ZVP6FekBsEETq2wOTaO9MlqpMCLFsWmX8vKQVuI+iYUOTaTd04?=
 =?us-ascii?Q?HUBwHFwWjIpnrD3cFb3qcNkg4yi+bm8/GC/Et6ucLgPJXJbUKe2YkwKSZqSs?=
 =?us-ascii?Q?CDXXbkHaVZwJbeU0WnrPRZbrfPcUDbVI5eA10870B0FyKaIHyMRI0x7/zCCP?=
 =?us-ascii?Q?AQ3jJ9Op0mto7K0skfRbtGmvyreJY3Nh4Leuq440dmD3GbRTxpMmUJeTrSFB?=
 =?us-ascii?Q?sFdvVDqzXfYUTFxKXAmkp+H3L5XiaIg5fTDbsHh3T31qSBy+4Ggfd0FDv0wB?=
 =?us-ascii?Q?QGRI2WkOXf2Kln/xZiyDkCqR6+CtYgA9c23F0/9VpyPCk5ZIYjUdKhKWc/l6?=
 =?us-ascii?Q?TM16Zonii3uyIvOX+gBnQbtIVf8om4ZEYnCLTSajZ5xI3/rcs+rp549OwAaH?=
 =?us-ascii?Q?v4pwvGo9mvAy3l8n82aOYSmGg7xY25BQIvsalU3qzA9AWBQgz7SMLMNJpPSD?=
 =?us-ascii?Q?g8W0JjY7HjdwX5em71q4xpApzR95Q6pUwlfnbKpMtaz1BMNHNYXpfaiQmK4T?=
 =?us-ascii?Q?U30RbT4w7xqdhd7GCtAugnvLNCa0ZYjBubYnmojSsQNfh8blXE5jjBIyEvyl?=
 =?us-ascii?Q?N1ML8UBAaT/6M4w8S9RWSQ1HXCw3gyVhmA5qVYz6kRnwYAuH4jttPqqU21ts?=
 =?us-ascii?Q?mc6+jLwdCTRLxaqX0cAjTWTnOURE0pG7WC78sDc2oRS+nazzJoxhLoQR3j8R?=
 =?us-ascii?Q?ovpm0N+kaQoi6TiloWW4BZ8JiuhTZ9orE5xiKzRfsva9gFbF67IV1C1iLGHE?=
 =?us-ascii?Q?3Izs9IQYnVOP0aFr/uYb9NX1NcfuEY5HPyY1iQw5B6mk5As1LaYlHuIYnodk?=
 =?us-ascii?Q?mF32bjbDXsSDkQIxF/0LhDcdp9IuwTqAbTgUeSi9SOrVI3x8sat/XVh1s/GM?=
 =?us-ascii?Q?bmQc+MvkzYeqQSqXEvWk/4BPL43BorkZoPfZfxAAlzy9x+MlHnog1mzE/DD5?=
 =?us-ascii?Q?bl0OWTpu948qX9qOmmcDYGR17MxIM/C5TBPx+yLLOQF062Nxw7t4KN9UiIOI?=
 =?us-ascii?Q?P1tH+x/69d0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(366016)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Rj4qcstFxUNxsRt471nCdJj82wmdEq5/Kx7zvkQBLfZLQRl+ga88yJlYaCsf?=
 =?us-ascii?Q?CbdR5MQ2vuVy3EpcYdVVFFFuGDV6c/18dGgVy+aIQX4Xz3Taj0QWItN6MfAp?=
 =?us-ascii?Q?fdK3eG9vIwBOxPgwq3r8hbXL8FUymx7Ury4B1K21cfVGfAHu0/T8/7mSvooq?=
 =?us-ascii?Q?jJIMjROfGb2SglfRzuidjznIqdf3HNmIvDb9Vf0G8LS1A52miIu11TW9wBUe?=
 =?us-ascii?Q?1BGs6bBOxq8N9mz/FIwxof2vawn/poPbtXLbRIpUYk8UgzUBrBv1v4c1JtYn?=
 =?us-ascii?Q?otlxohDx2mxKpVCgHnOqkg5xVBuF0zgfBgBf0AlwsLRpwd4Q8G3xdiwPTnR4?=
 =?us-ascii?Q?Sspl65u0J6IPBVkwiQgyZatvFlT3rrhAQ+tuJO2UQ0mG239MR9IeOUJg9kSE?=
 =?us-ascii?Q?gW82aHqUFkerfU8AD3AFAWXH+Jfs6lzIna8/opyIEIDZIE73ZPXwj4CB5c8P?=
 =?us-ascii?Q?ioeE2zfcTc3PdvivMeeXMulub5u5IHBdiy2g5fVp/PRSrplWN1lgGq5TaOoW?=
 =?us-ascii?Q?EmfRJ957EM/oJ/1LU6bjRlXSt5CGu7B55SDYzKgMVCUNqIxc1mmDGOAArrwe?=
 =?us-ascii?Q?UihpLdOIVq2JzAecSr1X2GDfb3wYgiwSAORwRdpg4e4LyyimuAnso83lo+b1?=
 =?us-ascii?Q?ta0eoJPuf3AAa0xtEh+F1Rk89sYQF5ye5EZ9yOBx3VC1VC1NiMA5E2rIr7P4?=
 =?us-ascii?Q?uoSqNodY+GPN5iARUia8nXINxqfJBJNu3xlleOAE/SRO0smabmoLTY1a1FO1?=
 =?us-ascii?Q?piaXqyKi7ywfW73iD0HP7uZx2/0i/hfqglw01epL/KqZYbC60xX7iT5hW49Z?=
 =?us-ascii?Q?9cfUqCcxOAmwSFJR0PO/GKRiqarvC+1sD6fP7GS4kcFZ8jPtpItFsF9aWYX7?=
 =?us-ascii?Q?0FQVBSuV5d7s2mCE5WH8vNkQagG4ongmjy9XtQwwxlu/RH+LpeVH0NxyluGu?=
 =?us-ascii?Q?CULKE00Q+0mZc984ezCco3ZtV14RqVSsiCyR+XWoGXeCFv8hg9rD0s5tQGGd?=
 =?us-ascii?Q?YbKb24R9elV2YHlqk4oYH0kER3H2kQqdSdVXkIN7LeuWGVVN2E0boCQAWVrW?=
 =?us-ascii?Q?V3Vn6ZdR+qj3JARf/nEiTsP17PDBHDFKU6+Mfs0psjZXvdgFKHAl0TQqnLDZ?=
 =?us-ascii?Q?hWedoX7mADffbzxiSX2BhY2PCTciTJbseJX7GwyG6+FcZP+B3w3iakMH/pPZ?=
 =?us-ascii?Q?KcCtjslOcZ5QaDx6+zFxoEVghkCAbFOVxC7jA715eh+7ppgYr6nlG50Qimnc?=
 =?us-ascii?Q?Ge89r+xdDkrN+ZcjOqiXojuASnecl3FGDce7S6+ovPgNRbvtjNei5tn2J6Zt?=
 =?us-ascii?Q?CUVkOheZnHigLiuTQ/sJQ0//HdwQ9VAAgv+dMPZjKsNgbkF7N1cC5CZXI0uc?=
 =?us-ascii?Q?K9ct3Peu/gXnCYvZMLdFnl5mP/9x3jzXxseDC2Xq0GURAfeZAaZxCTjReqh5?=
 =?us-ascii?Q?CZ4WSzmbS5FGb4DPjk7IkC2gHvwHSDkiFBy0bOmm4ars19OIebfBS8MDl3C9?=
 =?us-ascii?Q?aoQdrCQAc1YMTs90T867gbeVLXS3snMjDLJlzsIbMvkkksphpbdW5Jz4pryX?=
 =?us-ascii?Q?Ma1w0FcmuWectGjgXy4=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 08950cc1-2de1-4780-484f-08ddd5b376d7
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2025 13:08:12.8802
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: vOq4jHUsSKGMaJyXZYTLbMWHzFOPikNkJkIkpgwbuFDcTt8ZteeQkm001BjRjw4P
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR12MB8558
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="M/m2K/JO";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2417::629 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Jason Gunthorpe <jgg@nvidia.com>
Reply-To: Jason Gunthorpe <jgg@nvidia.com>
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

On Mon, Aug 04, 2025 at 03:42:43PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Extend base DMA page API to handle MMIO flow.

I would mention here this follows the long ago agreement that we don't
need to enable P2P in the legacy dma_ops area. Simply failing when
getting an ATTR_MMIO is OK.

> --- a/kernel/dma/mapping.c
> +++ b/kernel/dma/mapping.c
> @@ -158,6 +158,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
>  {
>  	const struct dma_map_ops *ops = get_dma_ops(dev);
>  	phys_addr_t phys = page_to_phys(page) + offset;
> +	bool is_mmio = attrs & DMA_ATTR_MMIO;
>  	dma_addr_t addr;
>  
>  	BUG_ON(!valid_dma_direction(dir));
> @@ -166,12 +167,23 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
>  		return DMA_MAPPING_ERROR;
>  
>  	if (dma_map_direct(dev, ops) ||
> -	    arch_dma_map_phys_direct(dev, phys + size))
> +	    (!is_mmio && arch_dma_map_phys_direct(dev, phys + size)))
>  		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);

I don't know this area, maybe explain a bit in the commit message how
you see ATTR_MMIO interacts with arch_dma_map_phys_direct ?

>  	else if (use_dma_iommu(dev))
>  		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
> -	else
> +	else if (is_mmio) {
> +		if (!ops->map_resource)
> +			return DMA_MAPPING_ERROR;
> +
> +		addr = ops->map_resource(dev, phys, size, dir, attrs);
> +	} else {
> +		/*
> +		 * All platforms which implement .map_page() don't support
> +		 * non-struct page backed addresses.
> +		 */
>  		addr = ops->map_page(dev, page, offset, size, dir, attrs);

Comment could be clearer maybe just:

 The dma_ops API contract for ops->map_page() requires kmappable memory, while
 ops->map_resource() does not.

But this approach looks good to me, it prevents non-kmappable phys
from going down to the legacy dma_ops map_page where it cannot work.

From here you could do what Marek and Christoph asked to flush the
struct page out of the ops->map_page() and replace it with
kmap_local_phys().

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807130811.GI184255%40nvidia.com.
