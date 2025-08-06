Return-Path: <kasan-dev+bncBCN77QHK3UIBBXN4Z3CAMGQEZVEQEXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 495F6B1CBE6
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 20:26:40 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-b42249503c4sf1028298a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 11:26:40 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754504798; cv=pass;
        d=google.com; s=arc-20240605;
        b=UbzU43N/5PqUk3b+cb8NwbgGhL1oxqNnqqPN3VbEiFlgfnIy6vHWFgEAbKZsg8qpNI
         Wov7MYqYjPemZ6lX67X4bssXj/1qXx8MXMGBaxjxCjcgvw7BhyOdNCkVXp3ek3+EjtxX
         gddUSUPwR3S8ujM+bNneaXw7dyIEbTEtBoSSGPpoPV/xduWtzKelVqC12Rj5jk5yJAOC
         02/zjevgqqsGSIHuVEmwDA95Le/QztO1EbtJn5kWix9D67a/72LIVjHTNc+QYd1xXwvj
         WKZgR7jhYMm5ihrVxBYk5df7sBMRvKI15poYv0J4VRZdLKgYqdyvgYkc5cIIA+V+zPhe
         obKw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=waTT1YlIUgMIw5+rm+f3PcqucuAwcUJCYeXo2+6K6VE=;
        fh=gCHpPk4ByTjklapRtOjVnE4vZS45i1R8nTyyxtbeQ3M=;
        b=An4jM3GWstx3xOF3dAF8yY4J8XD6PtfocHvx+yx3bR/hxX+EG1Dh3q5AXlIsIFpM7P
         w571a+Zdj9zful/mLxH2P1r7TACHP1Ynd40hF4I7ehtPgwCmINsuAjJe7c/7P7o8nPJh
         9m1/pu/WBsjDjWd4/GVZ696xcyIp443vmfPUTnyGpZMap+C8DxgszGI7Kfnc3xxRBTNt
         stjVqpvnD0w4SnPDOTDX4IDalhjxDwJphsDt3a8V9thTgLTfXx60+2S1SrYIQhr5lolT
         TsLHDnua2mz/wpoNdXEO+Aex903zE9Tq3hu0UnmvCVW4m3TvPKd8PcCsVvQzRmU3ZkFD
         SMEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=l3tRof7+;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2414::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754504798; x=1755109598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=waTT1YlIUgMIw5+rm+f3PcqucuAwcUJCYeXo2+6K6VE=;
        b=T3EFOuKGhWPbbDI9DrKCrifCrtMIHm12ouzrwnYSZjeGBfqFcOd+bI5I9hzhRTISw2
         hZu/cT/Owgyiu/mybYnU2a5DRztgWktZutcIv1RTwgjFX8abbwuTz1b7rw66FIF5PzOp
         jNpN0AI3m3zEaWL+YRWaZvsYNy1yO4ypyPw6+IfX6/CFa/3bDxUve59zAQUtx0ix1wXy
         A0xT8vSBbHug+ChzzDmPgqq1GBjvO1TI2jpG+76qkYkCE2cIjAXSxeGWKpcB1zEnKuG3
         Eb/e+E1/sJzrgf0OdhuL432DbNb6EFQpHskyZq77XQPj5kz/DjrYauLc2fot4u3S3jO7
         oV8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754504798; x=1755109598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=waTT1YlIUgMIw5+rm+f3PcqucuAwcUJCYeXo2+6K6VE=;
        b=aIevTiEwyLy8g/imtgrNv2+b9+dmVJOG/yUFOMLmoiX3WfSoEIUSY4gr3/NIjc1YhJ
         2rKe/f80V1ZerfXPotKdlANWp0HToobqTh6CIvfiwLxQubzdfa7SHab94sCMUog3KFsY
         HR9pH71GZ5bDk9e2yqZ2nDOA5Y0IDHLadgahQ2v9VIOnuNl+DMh9rsYnc4s+XBlG+wu7
         eDVULePJlLF6RnCjWJZqpTIzxeSY15kweQgnEjBvgwvvF1z99hAfTnx+7wgNh3bTEgIV
         IJ4z5aVXPlyMa7hqm/r5yO+ndvD/m0N22cw8KxXkoonh6sdgBpkoGaNiV6DKMKN6b76R
         KZtQ==
X-Forwarded-Encrypted: i=3; AJvYcCUelpxj85r2BDKJTEtr0Y/m0xh5gT8CRmjlOYFjSGBIexpqmCbfpiRkltM1KGg2KlDocc5y2Q==@lfdr.de
X-Gm-Message-State: AOJu0YyqLS05TuDdunSHPQnswpMiEdyoT1fppKWuVctljlt93UL9635n
	mkq6CCoJHm6EuJTk1ajc2piPdbZ4+fsTCkoJNXT7LRUsRHKARWuAGykU
X-Google-Smtp-Source: AGHT+IECMqXTItBXcB3SnTQZS1MUt5IZ+zxMGDnvXQ4Bw8w1tEcr/TBavuqpT1Ek8TggO7/H6U3+rA==
X-Received: by 2002:a17:902:f68f:b0:23f:75d1:3691 with SMTP id d9443c01a7336-242b06b35b9mr7941875ad.15.1754504798062;
        Wed, 06 Aug 2025 11:26:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfe2P50RvkZimCAhuJ0N6uxxjjnMgYkxU+9+Th9b7pxSw==
Received: by 2002:a17:903:2283:b0:23e:2147:4c78 with SMTP id
 d9443c01a7336-242afcc5f33ls1299175ad.2.-pod-prod-00-us; Wed, 06 Aug 2025
 11:26:37 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXeCyorBfedephc8rGxJ33YzYGPUhOcIQms9XwYT9WYHja+oSZ76r+op03g3ZfO/1llODKPTxHdfio=@googlegroups.com
X-Received: by 2002:a17:902:e84c:b0:23f:ed0f:8dd4 with SMTP id d9443c01a7336-242b07940a6mr6809405ad.23.1754504796770;
        Wed, 06 Aug 2025 11:26:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754504796; cv=pass;
        d=google.com; s=arc-20240605;
        b=jHogVUJCJlxxabyKXOfxRskZh1scy1NKVHe6D+E4ZBs2wHDgHDoAKHF4eCjjdMyaiZ
         s/+IJe463vWge8Ht5FbOmlHyZA9dIuI2N3/kMEP+4B02lszxpcPi25p0v++3AQbUYgrF
         Y+5ne/u6ec1mtzliZe+kU2JI8sfueEh/SPwwjaXd2CWtTUosRbFj7KQH2TsZDoxyKr/F
         jBLmDTUFKUfIc5hvackqMUWUV5oTJdv3bd93D3CxTP5F2m/vnEtdk2BLMwbyxnILiRIh
         JqlgVz6x2qql56W3x+dNPf6Y/IEUspG+IXcFR7FzGcobqeO5djABC3FOKd0gBeipZCkP
         rFjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pKJXQxXxfUIo4tLv3CJl6XJN+6GoOozWS8CT0poTaRA=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=CaYPEy/DtpvSOk5BmsX1PnxbD6881329XB1r9OCZIn6W2T7DgcCLlUHDPXTERZy12H
         F9ExvqeO9BRLw++FNaMz+kgB5h2Pz8Ev2gjooWUd8Yf6VziOgM8EYiyMTQ0W4yTIm1ri
         lNTEQ4gULnGCLeDpJfWYhgBlWn+haUku3FLp3Ff8JROyGbnH/72dJquK9z2UnXRG27KY
         fo4tmduEI8ZqAhobeHdd8whjsqezIV8ck/J8yQBmQbGawoU6TTtYUrSjdV/dd7K/o/ms
         l51V5lE0lz1pjB5RysGpI+YvVqzvuUuXFc1JOzQdxLHY7zmE9bvBuJb4tgFHbo/aF04U
         Rnnw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=l3tRof7+;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2414::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-BN8-obe.outbound.protection.outlook.com (mail-bn8nam11on20611.outbound.protection.outlook.com. [2a01:111:f403:2414::611])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1f93e96si6790615ad.3.2025.08.06.11.26.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Aug 2025 11:26:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2414::611 as permitted sender) client-ip=2a01:111:f403:2414::611;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=T3oX4xKZrDwVMMnEgEiD8rNlrQo70s1Wnjel/mq8ahJBGHInkP2D2zAj401xXMBM9gTx3zrm4+MFSPALjx4xydi6NDqsElJJZ4hsfq4HJAGExDixeglhtFSmdPv6ppokj2Yj7/4NHvG+0QYs0pBx8jYs+otNzi0RaLmHXSh6ckgMN03hZSldHILwWL2ScGsbejCU20CB2pRelYWerEJfnx+aX3He0qBThOVi/OhmIrgRWfQt1Wh7OqXPCLVuajCd8kBOqYx9pH9/dGtnPeWU2p7+QS4VV30o0td4n4tmNpQn24RzQadcg18HdchJtkjrg+XLUscWfyHwfkckhc0tWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=pKJXQxXxfUIo4tLv3CJl6XJN+6GoOozWS8CT0poTaRA=;
 b=kiakdUudtbZi8emOq//VMD+aVo2GbqN7rv7GNnYKhQuloGMtgJNifUOyImW+84NupjZ1s1ZExbhmttSOZIz3prHNixdOYoTVNi/qN8rHYMdyRPFRg5LIpFnlZ/RXVcjW37F0xpg7qC3hhAZ4aFjOteU/dY31t19Pq/qVkgHlqimNC6aOvAaTldshJFrU/olOebipxFGAg0TWD8UYJw4Rh+Z82k922ZEyQJj4bSMTIZmn81Poek2xicFKuoqcRZ8efXfbxm+SGXyw3DXqrvWsusgqOcpEfySmpK2uUwvxmJhamDYAwBMyrntHiWB8CPdwvMLB+3n03jeGtcQ74R4nvw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by SJ0PR12MB6782.namprd12.prod.outlook.com (2603:10b6:a03:44d::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.21; Wed, 6 Aug
 2025 18:26:32 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.013; Wed, 6 Aug 2025
 18:26:32 +0000
Date: Wed, 6 Aug 2025 15:26:30 -0300
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
Subject: Re: [PATCH v1 03/16] dma-debug: refactor to use physical addresses
 for page mapping
Message-ID: <20250806182630.GC184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <9ba84c387ce67389cd80f374408eebb58326c448.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9ba84c387ce67389cd80f374408eebb58326c448.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0394.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:108::23) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|SJ0PR12MB6782:EE_
X-MS-Office365-Filtering-Correlation-Id: 632cafff-faa6-4b97-1b4a-08ddd516c47c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?owwpIJ/gX3NA4KCET+gimZq+FN0PuqQRzxipxevMPQb7n0i1WlzUqdFghi1S?=
 =?us-ascii?Q?19j+fumHYhWIjYAt58XbP5kKw0Ag6bpTz7rqSWX14k0J+w1uxD5SQzffX0oA?=
 =?us-ascii?Q?88/klCZU/brpMZz4Vo3dKsm+3sV6mHWTq+J1Fj2mmktQqG5y4NIJlQF1PMxj?=
 =?us-ascii?Q?Q4zAjL53yS0gcNHI/5KV7YERbSqdUPJUN/NaBsj+xfNDtKio8GXergY8uEEi?=
 =?us-ascii?Q?LEblKeO4/6Bwwml9K5BYoHIYHgdTGMgp10h0zhbZROA03uktm/FXzLapriuO?=
 =?us-ascii?Q?h8/KRarclJLPK0LnzRQQdchLSIeRhTGdMClq1ot8GQ30HUoFALDK/gYL2fzD?=
 =?us-ascii?Q?A0GeqOL5tEr+h21tfGfbu1Im0B7hjYPFTtd9AbRbeGdP43+JGj6dSxRdzNgD?=
 =?us-ascii?Q?Rs5abEENCmVlIWe+2wIU4DSMbJ9cocIyDrIui+iaETu2mR2uAKyu5xQxVHaZ?=
 =?us-ascii?Q?b34HTnzaGR5E6t0czMbcLiiUn3SxBp1RBFMvdYhYf96mY5m6juW54xR+jw3d?=
 =?us-ascii?Q?J1vTY0No7me8p4MCd3boUH+H55j1DJr1ynbKGjq0y5YGroUKcxdx/3vd3XPl?=
 =?us-ascii?Q?oSO+GWhSn+pBsg3tWgxlrEPC/GL7RAmuBQqxMBBrSNIixJUMb078qi6oZT8/?=
 =?us-ascii?Q?jv6iUD/p9tINXqWW3VePWXw+ilS7kVXlltY9ErXIUNUD3bMTxDW7ytPsmzZN?=
 =?us-ascii?Q?qR3DmMXglGcVshD2/QHfNrkWxaYWH1r2Hth+ZscjJjixAGNnqvVbr9OTeV1n?=
 =?us-ascii?Q?tjxQBFAr6QU3Z2wFMd17o7JNmc9H8Vu9Jt3JuKW+wyyBaTegwtsNs8jU6uIP?=
 =?us-ascii?Q?GpQRfIz0vj6rSmsBXPq091G3jMrNIVKu3tAqGi0otfXtNiR7uyQqQAm2J0M2?=
 =?us-ascii?Q?tX507FnQ2r1nHy6GhZT0+hy3WwS+8WDJXI2V/Xd3pyAs3wasL7pS7fUFPEJ+?=
 =?us-ascii?Q?A1cBy3LKeusKiCZVG1GHgP0k2MVqsrnRhdJ3yzjW4lbLFEZ3Iml6FKZi9AiL?=
 =?us-ascii?Q?ShausgFGQY6fuIJbjRxbcdb7V9Jiu5QdEfZVzvka/u0kXzIsche5PpSMHtMZ?=
 =?us-ascii?Q?ovKUcupTVZiqr5NX+oe1k546tROh8/2lY9PKafLR2YlLzCNLbPeLCWbmu63r?=
 =?us-ascii?Q?ebFwAfhAZfCoj0FHsvpowjD9e4aAPVMt42Mjui0CqRb8E+nI3bH1Ra063tef?=
 =?us-ascii?Q?fYqHKEc5+swy6EanZNW8yQfkS/+U8Jsn77sSaAWvQb83NqQnvbGWk3V202X4?=
 =?us-ascii?Q?Z/RVwduZChHGBt4zAOLato0o0xULnyiNcwej62TIruVz6j+7iZvAttLuWO88?=
 =?us-ascii?Q?ZvDokQKXbpNKsSBfd1tuMiEQEuQLkFH0JGV7YTRYVKG8bv2iH1Kubv+ype39?=
 =?us-ascii?Q?djF3iDL4dv4Yc8vRxDpa9OjtODHldc/4rM0OzlAbAMrP0kXfW9ypYmSStf15?=
 =?us-ascii?Q?9nk4T6yL2AI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?t39ZrHsSyipF2FxxWvOCrpOiCdTa9RlbbmJcEiSd7/usPKmN1w32/HQ1aYbo?=
 =?us-ascii?Q?j/5Y5e0l+3NLEdR7e93EiSxB0oqskwO2H7It/NFd3PGm2rCH+ioMm7swn09o?=
 =?us-ascii?Q?lLJYuIAo+jk/LNlbBhif7rAbXEKXl3rXU3a1TF7ITt6zAA3u/5D7+6w8whkT?=
 =?us-ascii?Q?CVZbVRXFIFZ7iAkoBRqBNNMVTNGcvq//axasMan5txxNMZctNZKYRTonj5Zn?=
 =?us-ascii?Q?Kxor43X2FR83/bVhHWzhDVYgC5h4894y7CuYyfzKJ1wh7s//ZDgL2e4j4PhM?=
 =?us-ascii?Q?cMGJdRCaUXgsocsf9JS1+aL8Zo7DfzJ6J0pqt9Bgt0lb4xEcbAIB4tAkPLpq?=
 =?us-ascii?Q?zF2mvzStnV4S7ILBLVDNaMmfLFlYkOsTKUmHOmbjnl9lgS+8y72yI25f+zm7?=
 =?us-ascii?Q?VB6avAtH6rXq2f6IlN8CFOd2ShdIVMae+GcZ9IGH0/XrtRR+4TbFoPo7zri3?=
 =?us-ascii?Q?Lc9pzRkDJ833W62CQv6mOhQiko4WpHS2ExgKfqMI2gHQdfNKm0n/JKG6irkH?=
 =?us-ascii?Q?cDwamegxjR+CmPKIr9BNCNyW+6ostD0jXjRQ5haDMaAXG0y1hSHLuI09Okmy?=
 =?us-ascii?Q?srUa0Bel5tIt9YHwdqIMpqtx4gC2y+GgnFT6DbwvXxlmhcvNNu10QceqbXpb?=
 =?us-ascii?Q?md2BsLbubZbJYOvTHvqqpfjzYCQV1+O2cC7Zrg3URLW43Db/oWeiQpg0hbB2?=
 =?us-ascii?Q?zrw1a0qQ4aNYuX24Nb1U0TgBtOvz0txjIxMjpgKc4k4X60ZN2Ekeuy2Dl+/T?=
 =?us-ascii?Q?XTbc0+goCnOo9b/HxrK03gG5mt+WI4ErGszYXmNhQ1w+baEihkbqc1VZZPsX?=
 =?us-ascii?Q?yMZIVy350zZir+594B8HugXTTsLyvokgnUaVYhU+jrQRLEIbjVQCnsHLFKkP?=
 =?us-ascii?Q?F2hBYjGg50K3TpUniBP/5U3j6Au5BRtp6FsqHNvUVqOvUvQQXg/8h1cU2N8D?=
 =?us-ascii?Q?jCqAIyWJOirRho6xjjYF5ivS1MnJuEBYW/LshV423PWK1/kqIgiW3Vr64amF?=
 =?us-ascii?Q?+ntWBU8+VodOuYF/C8+uc3mSRjg+yYv9qnvDYyjspvEhb7PqErKztqzAn5xP?=
 =?us-ascii?Q?f0ay60/QIlHT6KKdynA/akQFVMESmJisswXCL0IVhWKwTKzocWh3Va5yq+ew?=
 =?us-ascii?Q?7AqeJVg3xG7+L/hCVPqXLh2M/Z+jpqFrqW+NkrzJZTr6lXXrOuCihasacQ3H?=
 =?us-ascii?Q?Yisd38CjiZTcD5D9yKaSEgaPNHIk9Z12+MPqa6pLiIJMMJuVQ2mR8iK/D2IV?=
 =?us-ascii?Q?F8ao5THBiVMbReo83xNy7mqfO4OoofdDQ7258uW/2/scAV8mHZu75y8uAY6Y?=
 =?us-ascii?Q?W/dzqqF9TZ3svBcvHCLDUann8lFvwTu8tb9r+8xE54jp9BppaKQkO4gawrUe?=
 =?us-ascii?Q?Mf1QCEmFJNxs8vTx2+il3bYtwyrAaCFkICKFjjCIYj22ca1P7/gBXhIb35gs?=
 =?us-ascii?Q?EH6jU23VieGh3yAXEHv8OJ2rXwfzatF23k+gR+qTlzXeUwHb0eXFNe/2Rpjr?=
 =?us-ascii?Q?m4zoOR8wSjHBOIwyIfs4ATrvfFrZgGQYOTAONPHxiKLdbDQ3pDQHf2E/hr1m?=
 =?us-ascii?Q?6Zn0o1VaFz0u1AIxWW8=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 632cafff-faa6-4b97-1b4a-08ddd516c47c
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Aug 2025 18:26:32.4888
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: GQMRHuo2jl8akCW9nlaZJvuQAC3fHS2K5cV5C0IU02DKbHti6Tp+SLWOuo4/pZrj
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR12MB6782
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=l3tRof7+;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2414::611 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Aug 04, 2025 at 03:42:37PM +0300, Leon Romanovsky wrote:
> +void debug_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
> +		int direction, dma_addr_t dma_addr, unsigned long attrs)
>  {
>  	struct dma_debug_entry *entry;

Should this patch should also absorb debug_dma_map_resource() into
here as well and we can have the caller of dma_dma_map_resource() call
debug_dma_map_page with ATTR_MMIO?

If not, this looks OK

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250806182630.GC184255%40nvidia.com.
