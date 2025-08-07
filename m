Return-Path: <kasan-dev+bncBCN77QHK3UIBBMGN2LCAMGQEGIJMC3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 71135B1D8AF
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 15:14:26 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-24011c9da24sf9112875ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 06:14:26 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754572465; cv=pass;
        d=google.com; s=arc-20240605;
        b=Om4FyYbC54g3wbvT77rVvi+sXlsQU6b0X3w4W1Ws9bh+EVy0MMtROk90AdRUqQpBdY
         mYngW2oEE3rvOMdCfmlyYHLDXliicLxaAjp0a2yD8UUqjtTNKQDU/wv09AF67IPrI1sj
         7TA1oBm2fqVegl/GukjToL7shbBHGEbq25AcBhDsaz/jkRaLr+cGchmcKA4hzVWETXTc
         1JEQiBqEv9SCH3DtQLc4alVtYmW4N+hKQU4XkLZTAiRr5vw6do3E+2EetrLBtZr5Nxrj
         eHwQUcdWPdZoQc1LbWt9EOCDRSoKqARIh2vnJf9fQQKOAmbw9lwTTR+gAK1m2fohbSK2
         5K8Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Wy5Ao6hEjBNVOIjgeG4GqIHjR+ij2B5kWH8zC9icpnI=;
        fh=M0E252s6oNx6mPELw8P763bThQkwaea7bVef8f9kHww=;
        b=eD01z7nvdfF3KdLWUTvuT1plYC+Y/SxmkLveo8WfYnlfhtP6osZVhR32VijWSVjmhH
         jbxWJwgl6sVOEEesQ6hvOlCrxwREWk2E6KVvSHKGw2aOp+hhjCkNdOVRycAfhyPWQ86I
         irIEoruGyYSQj6k4nDIdxtYD/Sv6XzAOQhSvuGoitk7DDY5cefFhAMuXZgdIpt+AIdrm
         4MduHsG0pglA8L2Q3Kr1/f0Go0lOsl84xmcAM5LnC16uka0Xuc1QtC0ml/6ArsJletWS
         RY1nL6+TMQZPOT5I9mLpkNbFVv7askyh6c8llpTHAQISQUCqGGj3PMCgTDjY7idL+RrQ
         T55A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=FY4nlR+s;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::62c as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754572465; x=1755177265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Wy5Ao6hEjBNVOIjgeG4GqIHjR+ij2B5kWH8zC9icpnI=;
        b=Do/tt3d+/AXlGbtH4haZ6myZvRWgI+Pi0kCTU3bBMSaJAnjVmAmeWv/5hd+VcMUGJJ
         5uyHuz65koCV/2S2EfRNrfZQsHvZDfCA8haBVzlEVDQJwvBodq07VAiKrqQj00L5UhHq
         7Zhnz/c6wbhRe93e/IZrcqvyAVDIJOSYRYVJqN4z3s7FsCxMvzu3UJzbA8ZHuKHWYr6m
         4irMGWNK++3EtcsX3D/xH29h2o1i57cRPqgttAP0oogEX8UzrUqDM4RP8jy4RkHPThpz
         Q1sxldFsFmIgpEmkYQ1/6wCbqt1WTJr65ygnsYFht5rm1+PSZPR8fIXgD//oi0NM1V8U
         Yf1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754572465; x=1755177265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Wy5Ao6hEjBNVOIjgeG4GqIHjR+ij2B5kWH8zC9icpnI=;
        b=CDfPdQF7M52Q3p6RJ/DQWa6HK9v97/g+KA/6zHUFZ3VxumzckU/1FLIeDLmXom0syf
         qX+x7EqY2vYDFWewCfpykBQvNx1KXeIzRTwlJwARYujHhi2DevTUzRTJXWVHE7LLZNdl
         oDLvQA+7/uiCpWsA+lUhQXdDN+5xolxJJ3f/LVlBNoF7Eipek8mccF9sv00avcmsduGa
         vmAKYT7joWvowa3kskaLanp1VPN0Zb+GPxZdd7cADvFW6yTn4ZIqMhfIRxPJDuHxlFtY
         nTAsYpOJFqtCSTeRtIanLd/XrBcIFihrYGddgzg99B33vErasxTs3VWG+vGYM+HnAHz+
         KzBg==
X-Forwarded-Encrypted: i=3; AJvYcCXVHPAJXIrCaeWxjEPLBfzegk0aX6KRUjNvgZKX36cs7fyb/iEZp87D30cyULfA+w7L/zoiew==@lfdr.de
X-Gm-Message-State: AOJu0YzbHPB2xV4W1z6Pe7kQJDWPc1L6TA8Rkz/2NtKMNFml3uFOPe/Q
	utbaybT6ohkH0eCyf729Tv3Vk1cZ4e/zoleh3Cf5voffksXeTyJPKEym
X-Google-Smtp-Source: AGHT+IE8+WO2xVSRPzg3hksIzdHLEKtlSDoLcC8KRcuOCCg7qRLaUE29WP/txLnguqAaZetQM5m+hQ==
X-Received: by 2002:a17:903:28f:b0:234:325:500b with SMTP id d9443c01a7336-242b075c43amr56796185ad.22.1754572464794;
        Thu, 07 Aug 2025 06:14:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZduK1/n8ifYRHniRSZA6c2NEftjeZYpKpcq/6WWW+vSRg==
Received: by 2002:a17:903:3c6f:b0:240:3cf2:c3d9 with SMTP id
 d9443c01a7336-242afcb962cls5703505ad.1.-pod-prod-00-us; Thu, 07 Aug 2025
 06:14:23 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWHJJmhRXAAqHwS2s9NtImsj0tOtwDh35ETyjlwNp0oBiTB7suzHzpoKN4qxyfrDdzcz3G0E5a/+/M=@googlegroups.com
X-Received: by 2002:a17:902:e751:b0:240:417d:8166 with SMTP id d9443c01a7336-242b06e7164mr50935085ad.19.1754572463438;
        Thu, 07 Aug 2025 06:14:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754572463; cv=pass;
        d=google.com; s=arc-20240605;
        b=bq/ef0C7Mvt8ZhjH8zThP8Q8deAGwC+WGV79vJy7/St2ESWF9NCk+Cq78sSuLtDnVC
         R0Lc9jmkRAD8hsKn9D5DDo96vN25XATCTdcBBsmVhuP3MZLyIUyJNGYn23xVjb5tulQf
         sM0yLq4WHB+33a3x+iOWNnwD7GXzbaTQb3si4I4ch+kl0dJl9LE/Q/BQRDHSUT1EzNd0
         IEt1cQl9Qq9sOLefp4bxWZNtT+AvHQpHVxRqRpkeh8MxRf/zal8sF5XByQw7uPb/9X36
         nxw+Au3iyM+ugnSxYH8Bc8SxFGw2UYqR07xu1hlq64q+98UTpRw3BYp+TlDhulz8Ztva
         aYzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=El+thOM+nhiCDBrRZrRPm7X53YNuufqNBvCOI8akTxY=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=d2itCwHqKPw/XWGLXZeKpxJseXziFFQQgRwMl9lEK8luDzKcg28UqIBYUhVvBiFt/+
         +bJNK0JB6rJgIjfOqtxhWoaZlZN0kEpGzFZBYlO9CIjQFfLMZ7cSjDDzLUOSOxo5B03N
         dTgXCb/u+zHUGu5ZvfbznIImdQuqwY6FfhecCKUYwujj8t7T89rPdGjF95oJlsxAtJmr
         GtkPetduF06AkCiB5udlLBUkP5cCs+CaxVQyBYzRfdMfYBZ8vpkvAzNoGIAdl65V6aPZ
         saiiqVSpdw8bCVQjBzBsqtXP/H84Uha0h5CmD2W9ZsyHbm/nzCCJARHqGYOeDA1JuMZk
         /M9A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=FY4nlR+s;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::62c as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on2062c.outbound.protection.outlook.com. [2a01:111:f403:2009::62c])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241cec02f6csi677625ad.2.2025.08.07.06.14.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 06:14:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::62c as permitted sender) client-ip=2a01:111:f403:2009::62c;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=vBn1JdBGA9x4xZIh1Qb9LferC/kfi8XJFZfqbibzERq7ivOz94Pqpmj8hALck63PYHMaNDP9L9YrNX8ObqtwtGunWhbQbTgpLrGB6/X9ElhBJaDgn1abG4YpCI+EU5ptES0IWBZD4eqKTZRRX6CGeneHwhcai9Fci3WhBQuIr7pPCFNLfzate68J43+y9MO3c5uLpaBkU0Oin8ngYrkx1QPliu0NDEoluMFyMhGsdt1A2dMWEGLp983mLtY1N0mqmHwDhTsHHDsMpsIEBn/N1z81ITYGqNvu+kzGN88sE4kVREINHIb8zgZakf83P6s42eOpACkbdUNyY3p/H9d0gA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=El+thOM+nhiCDBrRZrRPm7X53YNuufqNBvCOI8akTxY=;
 b=KA9FpaUt08qX2CppQq8pBakpUps1iarFcu0wmxsKbKq1UGZAmIuhfFai4EPbMLG9gwCcljlU4yGxuS3j9ZKLTVvHFNccMjLLKaG8Xc2409IrN3gMgZxjGmSTkyecxKEMw/caN0COZyGxqaTvMQAON2oNev8OgIuo36jLIGgZOi9wNRkahl2UE+s6RESu2vzK5Xxs7Je4/pgR5gsskjP0TSyyewdJ6+dC6gE0V4pAJB1dmVFkuHc0Z9nadC5a9OXgyWSQVug9oKGc57edWruLaxTdGQsgnD2xSrenTLYmo6+i2oXIDrn7nMyw3t2CCaM6E+qUitFeVKAPfkJJZPOXOw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by SJ2PR12MB7848.namprd12.prod.outlook.com (2603:10b6:a03:4ca::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.15; Thu, 7 Aug
 2025 13:14:19 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.017; Thu, 7 Aug 2025
 13:14:19 +0000
Date: Thu, 7 Aug 2025 10:14:18 -0300
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
Subject: Re: [PATCH v1 13/16] mm/hmm: properly take MMIO path
Message-ID: <20250807131418.GJ184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <79cf36301cc05d6dd1c88e9c3812ac5c3f57e32b.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <79cf36301cc05d6dd1c88e9c3812ac5c3f57e32b.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: YT3PR01CA0030.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:86::18) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|SJ2PR12MB7848:EE_
X-MS-Office365-Filtering-Correlation-Id: a23f7666-f381-44ed-7261-08ddd5b45152
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Yx6kIC87cr6QGSDO2/ocsFrHfxDyWPJob8ClpG/b1iCCx7jQl9SbfJdYwGmA?=
 =?us-ascii?Q?0SCnTP5cEZ+3uAVFbD78BsFna0duU7C0od9AcX5Dw8Mzrz+nbkwFg/hdTaHt?=
 =?us-ascii?Q?gv2QpU2TCx0BrBLg4ywaxeRFc4u5BKvtUAXQ67WyVcg0OqaJlrQYfjbUe9Z3?=
 =?us-ascii?Q?CqAbguL+FG4tumyFaizqRh4k+dp2hCN9HXtGKrxEWkA5W3mydAEWUtGfTiH/?=
 =?us-ascii?Q?yFyGlLM3CUYv0UANPgz8OLGYtCb/v0dj0gkGIYwqZG+lWYwusuturuNdWh7+?=
 =?us-ascii?Q?GVjp/Bgo2X3M5DMMnUMa9Ep7r7l5GssZTr/5bbS8Y1v+cKsUrLa7BPvkk1ZP?=
 =?us-ascii?Q?s70SpOqcSGdkND8E942R5iRoXPupjZ3kkVPf+DYptPKaqjd5fbq9Z+6gTuXV?=
 =?us-ascii?Q?a3y8riXtmpbtg28ZYqedgMM+CfTcEuf4cU280lroq1gFO3YEk0gazAmuuGBx?=
 =?us-ascii?Q?R6+0vZP5txw7pvYcOtgZKl1JFHdEc6fTKbude7jN/aJjR//mVPt01KfIM2fs?=
 =?us-ascii?Q?08kPqK0J/g3uGNao1I/+Fnuu+FOXB2jz7qwrIGSkDh7rw1PB6mnz8sB1rpz8?=
 =?us-ascii?Q?Jn27l2c1oQALl352iCNwsf0c6ITtO6moNQe533xtAhdO0FFEsfKEVIOknrRC?=
 =?us-ascii?Q?DWp2BJCXq6NTEFjdqMBC0XQ5kCyJk1S0a8DXyVt6G9ce+mRxNqW8GfjZXrfQ?=
 =?us-ascii?Q?Mmmo+Jl+pvKHt9DipPEWPQeBHFgzP5lMcc8WDaeQvLRV2ag3LKM2wFvbjKoO?=
 =?us-ascii?Q?tsR8cITmN8/qPhDOrc3kjiw5h3MTe9v9jt5yiPv1iQc3NMUlOsc6xNkZKlo5?=
 =?us-ascii?Q?mb0zVO8Alu64x/hQnn3jI+IRDejbHOp/lSM3EimbbBwEuYcHpussF4L8onAA?=
 =?us-ascii?Q?2aL0esT331BhR8he7KtMygbYUbRU3fQppAKtbivq5MwrNN+sPdtjY5r2Jmm+?=
 =?us-ascii?Q?mXTPBVAbzctgZlFjhuNWr4ywRaPhc+qdz057kgKpQcfPeO8hzfmslfYjiQyH?=
 =?us-ascii?Q?WJdBQ+BnKG2lf58O0d08gaplR1D0rbUnLpQ13+jStDLHFl+BR/dtxQ1Mo2hF?=
 =?us-ascii?Q?FIW9fKzat4N7O1IgCwfshwUU2SsJzohB4z5GcWgESxNrhD9iO/zb8/fPPCJx?=
 =?us-ascii?Q?ofJFTmayXtZt6G5/Wq9qUYF1iXoIDFkMLkJQp2txvODyOLoK8gbf2zUi1b/Z?=
 =?us-ascii?Q?seAoFm/rc/BwrTiZRJoCEV9Z9olZ/6sEDTDynIGyQnzfZqdOV5cWEWGrx9Oq?=
 =?us-ascii?Q?KDo+hdwdZ8gUL2N2BozkcLAq+12z9JijoLk3kCmmkjiRgDIaPndijasGwCuy?=
 =?us-ascii?Q?vetI4XxhmWoShno5QwSD24G85Kp7wA4KwhKDacRBp5HBY+5qsDfWYlwLq54C?=
 =?us-ascii?Q?hwRnM2A48KDse6KJxxem1NUwmWDBdjBbH/G5U5bEX5SL6PwpnGTjy6NEtvFr?=
 =?us-ascii?Q?wZLYwWVsRiA=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?GuZggLyOM7OO92e5S7fOJyVVd1bi7L4yafMEFEoOjse8ZKlxA1U3xm6kb291?=
 =?us-ascii?Q?Fj+QvjYgFaJiEiHxz5PqGjBzSZyXfw8Gjo33jyJMkZCwVmN0oF8qzg/kWFRH?=
 =?us-ascii?Q?gz611O6P7nTz22JW/wGyCc4xb/huGIMzl2GxhhGQxoJseBpF9zTTW7WKa/hg?=
 =?us-ascii?Q?96RAlndKeft0qoeyV64IK0vKmAEgKE7P4FV53P82XuczrJQQ8eTRpXz4kHwE?=
 =?us-ascii?Q?zugrV0R5VcFO+4fQT2J8AFhQPRfx0/oHI59iuFu+CybYJfFgLe05oVISv/5z?=
 =?us-ascii?Q?74C/mjVWkPueRZsZIPympDwkezhDUinEz3vqUqiggYVth9f90CbJkHizkLQB?=
 =?us-ascii?Q?D1vQhwNCzvUA4Ro7Ke72OslLV0q0U9Bbd6n5jj4kfvhwlsXfc/7oJBWqmzRn?=
 =?us-ascii?Q?t4gib6TNBZTNjGXdk4ONqP11TZXn6lr5hX6MTdTKJNmhJGEoZEQVFT/4e8Ko?=
 =?us-ascii?Q?sQvfbNamaMosU0aQrvUKrtUT/fyBQXJ+1shPUdRuJau11/VW7SwXv469h6vP?=
 =?us-ascii?Q?sVP7HGe5m/6t9TiaSNPdbyPNjpBfiCyfqdVEs9IxULDQ9LgLCPeXLzXf9W4w?=
 =?us-ascii?Q?2qyPMxhaFptcLSikYv7DGdoxO0CYlCTu9nsjh7zg7iGE3mw2LJnY7i58YVul?=
 =?us-ascii?Q?p2uLUsm8/8i4cuw6IUDE+DsWF1H2w+BE3rUZ7sNDlus0JkAs8252gQ8XWn6O?=
 =?us-ascii?Q?sC5RD9aM9WHFQX6c/sGHiLkAZj68TjQsO//jT90tqz21eYHdJTbfWBhZ4aqO?=
 =?us-ascii?Q?U21fyMUfaIM3lElqIgSEuaH/vO5AH9lwLLjCP03Te+j44kFq5d/HqFct5Ma9?=
 =?us-ascii?Q?78beNahziuj+Y2QHuLZKiUwl+SUYIeUEJQcmL1in7UrD5QRMVYKayZ8LGFKM?=
 =?us-ascii?Q?x52Twm9SDMpnOZSWhmNPIPoLEomznG8BUEh3zBZNqFZpFmjJ+RHYj5CYOAXt?=
 =?us-ascii?Q?u+eHw2MSAHczRemjOUlW+orG41QG/hJOistp8cNZgH3dL51L8WIZJPgI7U8i?=
 =?us-ascii?Q?/xBRu9Xrg9FNYZ7UTObMqQwFNu/z8SVkBAItFtESetAg2twGmOiiCXC21CUM?=
 =?us-ascii?Q?LlEMSJkGdenL40iXOQO1gcxqnnkDQ/togw57I64AcBIUbcwUdekwE+cjb1bn?=
 =?us-ascii?Q?uUgiwo/Cg3vq6go3nQfYav2gtskkL6QgrgQeni0cZpPw0g6KVIGRMKohBywz?=
 =?us-ascii?Q?xZfGb27F+pTKeerTEMXeGaeEKywXmOseZYA0Avrtso12WDZS0/Pq23eFHDko?=
 =?us-ascii?Q?D+ShdTL9LuRZH0/Q036D5ymT6YSGnNLmr57e3O2ObempFdRETN/iHb+eByUJ?=
 =?us-ascii?Q?kgCKRYpnDnqlGCtg3s+P2/AMRrtScL4IE7P0xfCUesPrAC1GWIl0snuSZOl+?=
 =?us-ascii?Q?lcbn5RpD41vxbKtjUCR7qXezT1h38mkBHEFa+0an4/ybVHzhh+AaCZW9TYyQ?=
 =?us-ascii?Q?NJEvG2UWsBKfjnnmZIZUawI/79M/asPB821CK+zuhJC80V9BYs/Ctxopy123?=
 =?us-ascii?Q?bXBFCOfdSfDPTtVNYGbmXrXS72FHDUg49E4abuhNnFKOZdW+2Qvo71nq0iz+?=
 =?us-ascii?Q?T9+TW6anY1irc05J9FU=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a23f7666-f381-44ed-7261-08ddd5b45152
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2025 13:14:19.4548
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +hIdqSIgATwRq7OJckpehDxKPFDImSL8By+RE0tqZl/FgfZFXraRXFcwjhcsQya2
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR12MB7848
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=FY4nlR+s;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2009::62c as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Aug 04, 2025 at 03:42:47PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> In case peer-to-peer transaction traverses through host bridge,
> the IOMMU needs to have IOMMU_MMIO flag, together with skip of
> CPU sync.
> 
> The latter was handled by provided DMA_ATTR_SKIP_CPU_SYNC flag,
> but IOMMU flag was missed, due to assumption that such memory
> can be treated as regular one.
> 
> Reuse newly introduced DMA attribute to properly take MMIO path.
> 
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>  mm/hmm.c | 15 ++++++++-------
>  1 file changed, 8 insertions(+), 7 deletions(-)
> 
> diff --git a/mm/hmm.c b/mm/hmm.c
> index 015ab243f0813..6556c0e074ba8 100644
> --- a/mm/hmm.c
> +++ b/mm/hmm.c
> @@ -746,7 +746,7 @@ dma_addr_t hmm_dma_map_pfn(struct device *dev, struct hmm_dma_map *map,
>  	case PCI_P2PDMA_MAP_NONE:
>  		break;
>  	case PCI_P2PDMA_MAP_THRU_HOST_BRIDGE:
> -		attrs |= DMA_ATTR_SKIP_CPU_SYNC;
> +		attrs |= DMA_ATTR_MMIO;
>  		pfns[idx] |= HMM_PFN_P2PDMA;
>  		break;

Yeah, this is a lot cleaner

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807131418.GJ184255%40nvidia.com.
