Return-Path: <kasan-dev+bncBCN77QHK3UIBBEVB4PCAMGQE3FQIZ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F9E9B1FB36
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 19:02:12 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-88174f2d224sf367109139f.0
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 10:02:12 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754845330; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z7k0UMM1ViHUPELa4AWi2Efgk8BJumAamu+86HuHr/6t0F6sOK7Ph8C9MEfJd9qcRI
         Vy3+LUJeuFm7B0ZdN7XB4JEzqbBZ5mz1eAFS7/X5lvvoPm43oLHjOYxpqoFiJb2y7PHG
         As6d71qFwVL/3M2vfvBQGXMOC7ePLDZE4u8/7fSVPK0nEScOKGBpPHxn87PyUNbCdrmj
         pTIu8mfU5g6xWz9UCxkZ7XCDQyxV5KjJU2qoOEkQlp2eiEwfEFgZv8zYXQvEIGXydwS9
         WTuf/XNYIUmvm9dSDQICTZ2Zc3vN6GG+/+f33eXELCSkNoY+H2fJvslh3Q3uIrtnR/QN
         jmWQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Bd0DwhTE+GoTwWekMZIJ284fd5shZJ1QDQe09Z87ZBA=;
        fh=wpgtRKdxMGs0tSWMkZeqGsB9rxwr5mTyvv7DZj/ncW0=;
        b=GAE5WES88111AAtZu7xA5X9cTxC3lv3gOQQp+Mb6/HL548TiBDcaSOf8MJEXOFJnO2
         igk5JZeLLpeVJHkp4Z2W2jM8JgMss/XFukNNxtycZA8K7tXLNZX2X9zCjlXRxSgNo08A
         jvJddS0puyEI+EwEPXZ7kidpXyVZD5q5omB00O/I6qq2O5Wp+wOGNmYYvEpSp2mX9IfD
         XeylCs4mvKahnZmgi9mXCyZeLkny444Yq2/EOkUxjvkq2J41NTjVSW15SrKkse5EjcPe
         j3j/XS/ms/xWaZ1V1ta7d1kk37G3mmM6NfSkyfRHuXtRG5qTI9E2FbXrD3XDnPPOhlpv
         FBTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=esaqSj8b;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::631 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754845330; x=1755450130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Bd0DwhTE+GoTwWekMZIJ284fd5shZJ1QDQe09Z87ZBA=;
        b=qsZXpnZFXfry0ssSi2nJxnWCFVI/5zON4c6c4Xk7ilEkr17qC814DlrcWq84sgHyaW
         u8SL5inFFqv137OvzV0wpuTUPI52nsM4cPLg2yJpNtU/CGErSnerRU7D7gJK2I8ocSTL
         i7hWFg0xG3epxcF9kDHZzFx6KLMMoKSavgct5wBzIEpsSWOuwEUGg+pvCvVhj8YbLYOH
         Uh6xPb8uEkSzDtj9mo84fgIKS/UTyxQkY2iFyypU4WM0NkfEWr7VkrzxajnjLH/937Zb
         w3A5MlC2ky+PmgQDuW3NyJK2rQRg1cVGwLK7h8zP1LuC7kQlgq2rY4ItsK4LrxAWsrkW
         BD1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754845330; x=1755450130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Bd0DwhTE+GoTwWekMZIJ284fd5shZJ1QDQe09Z87ZBA=;
        b=OXwCFmEznSF+IamQfNxjtZ/SXmB3IXx7PRGiOarkHYYjueQ63Q/lBdtNRISxiR3v7X
         P7iXv4nrtsDwNDDWVbzMR/eK2nzn6O36muAaYFIwAND/Y+IjM8zfabT6Dv4MJkXBj1d6
         Him9BztPC6VoGsoejt39AEgLjIv9vvpUc/Y5/zwsHcgSFQtTMESS86f5UE8H1WPqXnJq
         eD/v1y65oiX32EuJ/pBIbsIUmrKZOUMjDTQCh1Kqr6US/mo7I0SIuH5S3z/1DVOs0ZCI
         8yb1VU14Za2aA8HgMIZqHPjfedQQ3R8ZpMoLSACWKasupicbg9+7OA56xGQgZY1i72sz
         yfcA==
X-Forwarded-Encrypted: i=3; AJvYcCWm8b4wT6SWp1SSrlNBELnjJ7ddAcMkUmoQnAuIAJvlAX9OrZfrukuoGlvEWL8xpfcYFmWt4g==@lfdr.de
X-Gm-Message-State: AOJu0YzQFyJPIsD65p0ncpa4lDbjcQ6TTIpQD4zdLyNL9clIvS2XhEIx
	oBphbAYy/2kx3NY8tKWNkcYRwzGuiVl2ikvE4EDfDzgTrqDuGPKq96qV
X-Google-Smtp-Source: AGHT+IEazsIX8VMUZYxiiJdokUELtneNx/gmb8PLSdQyFxIN6xPafeUB4tywrm3IsaHelA60O3Z5tA==
X-Received: by 2002:a05:6e02:4714:b0:3e5:4631:5487 with SMTP id e9e14a558f8ab-3e546315863mr49346125ab.13.1754845330576;
        Sun, 10 Aug 2025 10:02:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdO4BK4szLHrcza6vPl59U0WQZ9JDg+G+TdxX9eL19UYw==
Received: by 2002:a05:6e02:1a24:b0:3e5:11e4:37a2 with SMTP id
 e9e14a558f8ab-3e524941cd5ls28048005ab.0.-pod-prod-04-us; Sun, 10 Aug 2025
 10:02:09 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUoViGsncG3D2PgaEFQx0z1onS6dT/i3k/0wu53PhcGBiieVEDIlhKLYG4wj2pezJqBg3Qn4cq6LfI=@googlegroups.com
X-Received: by 2002:a05:6e02:3e90:b0:3e5:4d71:1038 with SMTP id e9e14a558f8ab-3e54d71121dmr26339205ab.19.1754845329658;
        Sun, 10 Aug 2025 10:02:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754845329; cv=pass;
        d=google.com; s=arc-20240605;
        b=deGI5nFTo9fAWqcQxUaK9frXBnY+ovhOxb0bTVuD03S84ZSzbr3Ze5P8nVZRzkCBE+
         kFAa4UivL6+sVnGhTzbYrw8S0PD1eZsaFuuQOeiq1ZouRx2ojbhxZXAr6ujBsZRaxEUu
         ltOTiLB+V3f7OL3uYJwTRjl1bxeXISAOQj2EYxyR3lHY0lcp3Q9kgI2CCaaAslWHbYsH
         EurxTcd+P65SkxkEWxoZQBpZJiYzTenAwUQ/90zmoKyZL/HcTh7SB5+WSPypwxuJ3pmS
         VQ3DLHO0K3khOLhxBR9wdpOSYXABT1GLZQd7zhnX+gLynzlzIFXYg+fCq4gt6tFnHKJU
         hBcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Twvo1MGwqVkIFIxri1sLWRAUlkj0wwBSKggdGXA8Hqc=;
        fh=ySMt3IROdmHxK+l2LYTgsPH75UK3ZhsVkipd4saoEJs=;
        b=ZUbnzrR2BgDbERAacxpaf7TINC4o83KJNisBeoACOcUJVlt70DNGx/2UdWwitCVyrk
         NnLEt+md0Cifl7lh1fBfF6oCyMrGNW7qnMPuA/06f44HnJj8XklIfEtlWjc2t8grfXHn
         Rn+7pgLeYuvk0cKoCiXe0n43lpofTCKwb6jbWSVExZa71kQtAk2k8a4X8mpdmr9dgDsX
         6cOdnRJMBkrmlTjsh54EKKgM1cFykecxE+pfQ6g3hXg6iQXUZDS8AX4qD+v9G13dttWE
         547n6HSMT4lzA9RYN90w8SxydodSa3Y9kysSuptNHMH0I0wOtWbWYXckdPalw39b8FPu
         g2nQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=esaqSj8b;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::631 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (mail-bn8nam12on20631.outbound.protection.outlook.com. [2a01:111:f403:2418::631])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae9b6f24dsi303875173.4.2025.08.10.10.02.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Aug 2025 10:02:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2418::631 as permitted sender) client-ip=2a01:111:f403:2418::631;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=DMRLHMDJvs4Dw51AHB0C/toHvAnkUMx83nUrbZgwAmrohiQwvqiWrVeNpY4s6GPJEJdqWljBHaE7NqrWh/ZiHoITJP1fZjOXRaqJL/qBSVpMBk1Ac48svWQn/z9II72HeGeGTHn19uu9JD0iQLRXZArYc2aJ6GVmBLLDX2057tDIGCxubfcqHCF1AltFf5a3vefDk/dMnMhXAr3ho9EJIWAQ01IR2iBbKDs+03VLE+Mrp/6ZMbG7cKBhEJbQaal7oaK7YlKTv4hIp7pwJa652rG2FiMhCTFOEzNKIPMERNCRIudLFS4ENN+maWygCgJJEY6Tli29Rs6AI1roFOaTZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Twvo1MGwqVkIFIxri1sLWRAUlkj0wwBSKggdGXA8Hqc=;
 b=FmwCDkrxqMDJZd9SiWxxD2PaihTYKmDPTPsBjrspsEubvJ/X7HGk01fJ1pNu6PMmxK8A2uOudtiDP07B2EQiras7H+qkbq9K1eSnIXi8q/hKz6YyhFwriY2G2K6mT5C8ArjZYDmASDZJFuujhWe5Sk8FuTFy/+DxafILE3Ydwz5aYRC4hr5k0N2vImv34UtId3GmFbWs0Lsy2ZxjKWTVR0v/D2kfIc4jHMCjKVGkoorT+XSuVBszau6gM21h4BDnEvJkfo4OPUapTEuUPV+zn5PnLzADrH+5vdDULeABEfmyPGzjiTPhwwe578rfvHd9RrgI1zNYVM7Pz59CKEn7/w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by PH7PR12MB5596.namprd12.prod.outlook.com (2603:10b6:510:136::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.20; Sun, 10 Aug
 2025 17:02:04 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.018; Sun, 10 Aug 2025
 17:02:03 +0000
Date: Sun, 10 Aug 2025 14:02:02 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Demi Marie Obenour <demiobenour@gmail.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leon@kernel.org>,
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
Subject: Re: [PATCH v1 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250810170202.GQ184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <CGME20250807141938eucas1p2319a0526b25db120b3c9aeb49f69cce1@eucas1p2.samsung.com>
 <20250807141929.GN184255@nvidia.com>
 <a154e058-c0e6-4208-9f52-57cec22eaf7d@samsung.com>
 <20250809133454.GP184255@nvidia.com>
 <6cbaa3a3-694e-4951-abb3-b88e6c9d6638@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6cbaa3a3-694e-4951-abb3-b88e6c9d6638@gmail.com>
X-ClientProxiedBy: YT4PR01CA0163.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:ac::16) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|PH7PR12MB5596:EE_
X-MS-Office365-Filtering-Correlation-Id: fec849dc-1ee6-4528-8aba-08ddd82fa0dd
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?tQ7R8t1K+FbIOGnc0aJmvxih0vp1cw9yA1yhHKE6+q0uUN5Qdl+Rlhg9ZSCb?=
 =?us-ascii?Q?Qo2keWV9B6ntQxdesYFS4a/Sfse6j7UKnxNTGuCMChZSZDnbTNLbvJrRsZdE?=
 =?us-ascii?Q?hepTFH1q7vgcNIvrmS5hlHUSAnNHxmSX42I/UI8xSHtaZo+PEr+Z/alXGQIK?=
 =?us-ascii?Q?QuGj9uZxAdbSs0wtYKEL8Yc7ZCNUuj/bAmql5VrKwAfR5Z6kD1C4jVBZC162?=
 =?us-ascii?Q?PFqQMQE3Alc9ZXx7EAm2SmE7sIErmtjpPYkAPmPHa8aA1hcP2uePrahBqS6y?=
 =?us-ascii?Q?V6Cnrfc7Whlac65SqD5Nwe5cACms/vP8r5cHO0PKaDpcgaiHxlIULjkHh/ez?=
 =?us-ascii?Q?GFrD/fJmov5ZoJFRPOk7lNOTe0wL1ObyiVHIgFPyjkZO3Kvf1tac5C6BxrhB?=
 =?us-ascii?Q?j7w8meCgGYUxzYRvxLMb9it2QXTjZA+TRZ5kIIDNUTdiUfaqMFedwJOn62TM?=
 =?us-ascii?Q?kmj4HXwtUTJtxqQGL4z267xtb4o4WN3+gIHxSbBVidGjzig8xJzS/sklhLGC?=
 =?us-ascii?Q?D44SK7WyFpZv/SHDscq94Sw8zJ7QpuejWHEJSvdmiqB4Tc3/pHD/coPi75iH?=
 =?us-ascii?Q?0UvyLysJ6zsIEQZAiEjLkg82dbGJIeerPLaLxgl44Ip90d5j5ktjouMjqVE7?=
 =?us-ascii?Q?uvwO2/KfzlOJLif3Xp+iwsmJVFM+NNBuqT3XXMcBH3Lv13ZR3qpMebnJdNFC?=
 =?us-ascii?Q?maBW8Hzj7QKbl92n9tAwxsvc50X0at/AHo6cdE/8Skv+R/4+mpJh6nSCCauk?=
 =?us-ascii?Q?8TA0wPUNrpCnNFzzarYuV+ZKwdnA9y57zSWbvN9pf1jB3DXGVmR6OhBcIMdI?=
 =?us-ascii?Q?GHNodaeA/Ct7PSfiNUkeycvt8c/ODVcvWSnbf7HQltjWV1dInOD7c5M3trC0?=
 =?us-ascii?Q?V5K3ntgj/vQ0NzKRU01lALB5Sxj2NVPOxf1wp4aZcdqFnaGw7/l5RROVrDud?=
 =?us-ascii?Q?oQhgIEpV1kL7VF2ZPLveObCaPoABBtQl5JWYw51OdW3nNmCmZmNZ7YFRYulk?=
 =?us-ascii?Q?7QZF4LpzOJ5Fx0TDefciNhrtzaFt1CpCdPzpLZhxIkSuBerYa20Z7wZdo9/3?=
 =?us-ascii?Q?3caSGtHtn7AAFhohOV9toc7r81df1eoLgXfS6V67zTj25uTZxYWjRDDTX7Cr?=
 =?us-ascii?Q?FDwjuv4VjrJJysz/rjY94XyqwVcEZO4XffIjYCUsRwiNEESpVtc6he1qzVLJ?=
 =?us-ascii?Q?cuslVADC1KFhHrDzIVb+VFGcv2wm8YZ3BTDRIfebpeiN98rCZv9IUTld7CIX?=
 =?us-ascii?Q?jTFyYVxYjZQtyQzaSEXG2Uc6452KRKVyQeLkdVRADeWN1n8aAOvNVp4HAu9Q?=
 =?us-ascii?Q?x+PQcSgUSknsyDgjJZ//mdhB8tlc6LnCatIi3+hfxcR6v8NGlp9d/laqnv2d?=
 =?us-ascii?Q?1k3SMuRg5Dd6s7yyYdlfoyfU3iNc/Amrj+GVkacOr/7w/EmtHSCq7azvCzwY?=
 =?us-ascii?Q?zo926LRBsL0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?s4vtM7QfcEK3pnSfpgdvdzEG1xxhmc0TDHTkbowPQHBiG7Js+F0EgSX3gR6e?=
 =?us-ascii?Q?LXKcn+Fk2D6v6uf0owIyEpBDKzCXNNkKlfOplXJD7I78uN251+l/4KRZbDV4?=
 =?us-ascii?Q?VC3ekjb0ET/hs/ETa04VhoVGGTuOBs9EB0viANhV7QCclMJ2RP70oTo/ySnD?=
 =?us-ascii?Q?UyzL16K+lCHpLy6KnA7WOk7myWGn2w872BSqBT6lbQWwAdUuFhCW/mIZxXkD?=
 =?us-ascii?Q?aHAi7LPZ2GHY30eZbSWG2YyTgBXolbuQBDyWlrGxra0dpOBsRY5aIwXPph3u?=
 =?us-ascii?Q?M3hcDrp7XBjkPyeaueEs2BUFfvmfZnQEg847Wlqbe2QWDM3RPoC1PGHnzKpt?=
 =?us-ascii?Q?/E3B7B6fE4vShteFtFySv/mR5e78pydy6dlyc0rvOClY/K9Atr0QXJxws9Uh?=
 =?us-ascii?Q?RBNxaEzBKZOGcfDPUqlZiPVB+a4WkR9tVQASiO072FkxLemZdiFGxoTZ5/XL?=
 =?us-ascii?Q?3ep6s5SDm69wRPq/KpfGd4SyPxzwTSTJ65667r5peGCUmSdSrJegZOogwFCA?=
 =?us-ascii?Q?bL3ey7+p5VpMa3+oGQd8wruIQlR8PX5Tmpd46QfVzhxfv5YTrXhunKbFzhZO?=
 =?us-ascii?Q?+ORlxaSx8DuOkCSQ6JOlK+rpd5Zr/aT6bq2XO0A+xk+dr6h6mHTPIsUb0Ba7?=
 =?us-ascii?Q?hASmrGZBJ+Yz9y9sekurvDHP+3+WT4gF6OYe80bzPjvXJxwrOcXAW0eVhlBl?=
 =?us-ascii?Q?MIk7XstZuj8qPWjqzcYzkde4AbmRw6pnLCIX6lTKViKmk29dxQlN3DS0Nic4?=
 =?us-ascii?Q?yBH9mRFgEtzGe+VbJQS4sCFtjNpg5Jo7Xok56YYIYIF3gg2tWCYlDBLIwtPS?=
 =?us-ascii?Q?BjddUK9zHiYo5OwYs6ukon6HM/ubFasl3RJc9wpQ631Ar6fmei/9GxDhcaMS?=
 =?us-ascii?Q?nZtXb+MQxbVt+DweGbOu8cClr2OjauWTWlEHhbfj7mAMGbv8R+EdbFfPlU1h?=
 =?us-ascii?Q?SysghU6TUunBigsYnjs1XQ3/FwkJm32lyxevA2jmvSkLGZF9wvTGkQF13Maa?=
 =?us-ascii?Q?HouAIwU8PPnf5xKke5aogbMEfyEOowGRxDKN9iR8nE/Rs4nIWlBMZwNuvPtu?=
 =?us-ascii?Q?2ZPbElPvkuHRmtyBswzUf0JZ3FeR2CKnn4lpl3mLD4EoSCeuevnmWr/LYQHK?=
 =?us-ascii?Q?nyg1SQTFKr7oxPt8sv/hm6l4x9UpgtrXocfyg4tpklBDinzsMkBd3ViazkLO?=
 =?us-ascii?Q?XuZmQy9EfznyFUStLHpG7lr6V32jIzjQHbkQDvy6qBEcvdrOHfHjW6/AXic6?=
 =?us-ascii?Q?cm6U3Vw2RHqiVeBduCcYFcdJ6H2i85FM2/k0SQpnIxDnY6Zcrsgas9pPWmJ3?=
 =?us-ascii?Q?4FmsWwSQbIbgx4Z+G+hR4eeF9FESAofr1cX0+Dm7xknDbs8e0u3eB+gcsZoO?=
 =?us-ascii?Q?0f6Pv/QeJvaf2BMhwTKL/TdhKKJ/Z09hIa9AM8dSY1WQJAMxmjNxK4mC/JAs?=
 =?us-ascii?Q?vu26/xOtRQPcN3L7DWyUgCf50rVmAOjmZZJ8ZARKMHj3KkM5NlKwjqO6DV77?=
 =?us-ascii?Q?9vdc1etf8ZozpPf3kvFM/NMKI/SpLZ6W16sJFD+ysAcbQNC/6sUsgSFmvEW9?=
 =?us-ascii?Q?sPp/rkUVFUz3DGY6d4Q=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fec849dc-1ee6-4528-8aba-08ddd82fa0dd
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Aug 2025 17:02:03.3537
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ATcPNo+pa28eZCR8JftR0i9jgCDxmwcDt/C1JwNANqcLcmzpVdD0nFciBdhhfL3Z
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR12MB5596
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=esaqSj8b;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2418::631 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Sat, Aug 09, 2025 at 12:53:09PM -0400, Demi Marie Obenour wrote:
> > With a long term goal that struct page only exists for legacy code,
> > and is maybe entirely compiled out of modern server kernels.
> 
> Why just server kernels?  I suspect client systems actually run
> newer kernels than servers do.

I would guess this is because of the people who are interested in this
work. Frankly there isn't much benifit for small memory client
systems. Modern servers have > 1TB of memory and struct page really
hurts here.

The flip side of this is the work is enormous and I think there is a
general idea that the smaller set of server related drivers and
subsystems will get ready well before the wider universe of stuff a
client or android might use.

It is not that more can't happen it just ultimately depends on
interest and time.

Many modern servers use quite new kernels if you ignore the enterprise
distros :\

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250810170202.GQ184255%40nvidia.com.
