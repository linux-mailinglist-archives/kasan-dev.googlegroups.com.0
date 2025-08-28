Return-Path: <kasan-dev+bncBCN77QHK3UIBBGOLYHCQMGQEBJZ6WPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id EBFAEB3A11F
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 16:20:10 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-70deaa19e05sf28865476d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 07:20:10 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756390810; cv=pass;
        d=google.com; s=arc-20240605;
        b=J2Z36ZiHqxO7na18+nLq7DerVeLRdxobX2nSNz2YCEEZhk5tbAIvf+4dkQsPoHsUkc
         xVSrF4eoJ2t5hDQcmHBEewGNva2ZUK9UyYRp8qAgSJLOkJjJvK0vu4sEOpRfKBMiJtEG
         hzt6rmhMl1jef9Vi5lpeOGE5aq3ro8cNdKcMbzOIfhCJd35n277ecRuXBUmsFFM6ULAW
         7FgJVHP4vqnEYaGkSSQpamY1hRi5esvoWb5LahdVJ93KvG5CQmK3xlPHAom+2dHHhwmm
         rGxDpYNPnkBxVu5EdpwGxqIkQc5Kev6iZLP4ZWmcC9wrbOtE5gdk01ZwUdr3AcOxDP3Z
         lNXA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=y8+qGSKPA5Ctc31Z8vcup21Kfhdrg+MdxFP9e7Kqif4=;
        fh=afUc6aH94EiLPOAoZgyhoZJHiOGyTyvann1hFXcYlf8=;
        b=MBFnneSq8xAuCgzh3I795LTt8WMs5aJL3FVFlHfjg84rcKsDXvj1RVRenRponlYr+b
         4KVJ5VRiRRCh1zMyp5z9oA+aGTNOZPU3bbupTvDytBHcl7Ha/IpH3waHVPmAMqILOW+R
         6P1c5bZERidWHnK5C3N/KcFzvbVJQF7Gx31sSb/3iyBa2hRgsn7NhFpDxtl0ZBboQmMG
         4pMLzWyNimQW5wm4yvM4gQoeBOyypH7SycMD6UPeW8IJpW+a9JRS4DipRpEUI+zvfUfQ
         u7UuDDz/kN7PcSVuWBqaB3QIi5DJBSEnL/vdg6pOEdA4jO1qpxP3Tl2NbLgKzPXfNAZJ
         DxIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=SHVyRQqx;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::612 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756390809; x=1756995609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=y8+qGSKPA5Ctc31Z8vcup21Kfhdrg+MdxFP9e7Kqif4=;
        b=fN/Q0Eo4Ipdh0WSaG9aDFTpMZbXhs/eR1qqNARnduWd/crN6gDF+X/fOhbysd5e8R9
         sSZPJ93tJVlJkec/8Zx1ppenEsgaVvBUnh6H4Pmw2b9t3gwg+JF7Xy3GFGrf8FMLUgMZ
         O+qf9BqgQp6WNDFxwCfPr7TaPEKdrQ3EKY8U+P1eZJQ84XFRXMpVuPkHD5KkTdoqXzcN
         9QaAKwzrqcr7kSeHR73Zp7ZdlYMxem7eJddMXBfkXfl8jKoKM7b9nZtYJOh/i7tFV6j0
         WEsT1Li0iv+RTVl/+ZzEe+Zz+rYxFRbX3icGeTvXk/yll1NWcRsaD4UmaJfxXSL66YoL
         IStg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756390810; x=1756995610;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y8+qGSKPA5Ctc31Z8vcup21Kfhdrg+MdxFP9e7Kqif4=;
        b=LnF4mSm5Ly2Up4zUXJhm+zDSvLBnokpD90/C9e40FJquqBKi9B62XPZ30SemnrjHTy
         FD7ze+whuB7t7rtR0HjNUQpPo+9L4bF8g/uAQqHVu2bpGuRTEToe9phnzKoideDfCOwO
         GfU8cIF+0zeqqbL03PUqW/s3gDKPi9IPrp9G8CYgN/vgbeUqYwI8x33LuWLlzd7x+BnF
         IL0RI9XU9tuVRmF2p73gndjehIZLw8Fzh3bRluFHGQVHb6vd32N2sEP9IIgHWpv+tIMw
         ur2hW4iOtVYj9dfC1HbK7Ir0mKLYPCn9MX/aY1y5kC1AWRCDh/7Tsgeajt7HnJkJz0GT
         CSkQ==
X-Forwarded-Encrypted: i=3; AJvYcCVcIvkwjC/rlktyjAnChqDy98MYT7ht81W7TOM1Ygg77/W07WXyh7tFm7f9XvKWQea7eqga6g==@lfdr.de
X-Gm-Message-State: AOJu0YzaHda5bolfCBi0C7rbo/7M3DUsfwQ3VUxDwC6plDog/QhT2xfw
	BaVilZ7yShpYgRyXUDNvCkSy1MzG4HWYLrc+L9kmEzNWsdsO0mCHY1cG
X-Google-Smtp-Source: AGHT+IEpVugnEukV69PeSOD0qRzYIc0Q9iaYtKZ0CX2hRwvkDuS7AxsFLFdrdnl/CtiZXil+cZpsiw==
X-Received: by 2002:a05:6214:4012:b0:70d:b315:beb5 with SMTP id 6a1803df08f44-70db315c00fmr213604516d6.14.1756390809417;
        Thu, 28 Aug 2025 07:20:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe5fPX1cC5JCbmpRT9MWLBFsSEjLkR7/sHBOYLlbF3x4w==
Received: by 2002:a05:6214:5086:b0:70d:ac70:48d7 with SMTP id
 6a1803df08f44-70df04c3d06ls13300776d6.1.-pod-prod-06-us; Thu, 28 Aug 2025
 07:20:07 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVi3yOVOrC2PpfgTtccIkkEPsYF78/bFVP9oDS1QOM23ZnK6THHNNz/qp2cyBQJJN766bFOBCykYvU=@googlegroups.com
X-Received: by 2002:a05:620a:4405:b0:7f3:62f3:32c7 with SMTP id af79cd13be357-7f362f34433mr1529244185a.49.1756390807534;
        Thu, 28 Aug 2025 07:20:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756390807; cv=pass;
        d=google.com; s=arc-20240605;
        b=OSmcVPDZ75WHsao23V+z50dedX5nwTSwaEH8Xqgw4UkQr03Zn1wY/C4cgZu5zVre64
         C3HBdhrp+uiv6cd/anji7SPFjKi3HvCahj8EaRCqG63HWf38xHoe54zPITtlSBUFXqIS
         AGx0Mh6Cx+sWgdh/CjYXMl93bwmfumMCgHtstY4fu4ewKiGJ245FOZmYx9RAFJPGbeSh
         q3NAfKY/ODNadkGdhEUrc+PriyK7UvFaqFL+BQopmQhpt1ItdLc5uSd4KHB/CUuY0fJR
         VDAgaFXJn/KzfIvqhG5Li7xPBfDpsbQ1fk+G+fFeHBMT5/eXO+DrW9q3d7A4TPbpJfmD
         JK2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kQVNpin3YPzO6syYTrDj2tSQysPubw+YKna9LrX2ZNY=;
        fh=OFOYP2Agp9I0RZrYQ73zsZUwZnZT4G+DzGcY88GSVSE=;
        b=lKiNqSFnLRhR5gj6xy61BJ06KKA8hm0114AgNMP1J8nKOPbkq5hvn5Kuj/+AWyzzpt
         n5fhMFJhh/7ixTj1zizW36Wvug9UmLkjhqYAKEBBi1vtjtoHcMRMjUbs9IQgZBnzYCZw
         vR8GTKjfImR8Su6yzCZQCcwKYMsFgECoAYTcf1ouJU06k3xXWeRo1IYcTLIMrZxeBxg5
         NZmB9vUAfgVR4ry+t4DhUhuhN7TK9LHTIONhjOc42szUcN/Z5SYTAx4GJ9MjcCs6VEQg
         2z5eF0e+Ktj5TLFbXW5uq9LXS6SSK8fFQRnVE4jEMh0UMFLpEUXhxzCnRx8PTmrNUnpv
         Cokw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=SHVyRQqx;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::612 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (mail-dm6nam12on20612.outbound.protection.outlook.com. [2a01:111:f403:2417::612])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7eeb4416f99si46847385a.3.2025.08.28.07.20.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 07:20:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::612 as permitted sender) client-ip=2a01:111:f403:2417::612;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=jXFlyb8zuu/paS1ZawJ1ZJ1MoYZI9MLnsy1iQRbHVJqVh0OMUxaG8sKXQ9gUCvAmgpV1v8+TxTBEvGBqt41EVUhZjJsJ8xQQf4+cQiifYq6e688dR1E4l+DbzpHWHGlXiFI6tQR39Fc3jFsrQZ0KQU0LXMUS8snCsy5VYFMbglCunUMqSDxqGG7B9qwHJtVHKzu/6qah8xlWSq1+dkTDwCpXovBkSPvriF9V+FcfL6oZyLZfJtx7AyfIu4mvXo+IZgyWbdaOd0nI/bbQiiM6e7X0p5Jx9sBWiUoQFwQt7jhbHb8Cuc4I6WhJxJ+Q++yK05JNtdpvxZ3HFsTR+d+T6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=kQVNpin3YPzO6syYTrDj2tSQysPubw+YKna9LrX2ZNY=;
 b=vqBL+8iwISAvFAQi32rutRIDaee8G4QXtxMQDjSV/DujYuKdVZjsiXFWkC/PUu74TXfCI8Rb7+6HXdyzo2KHR1HAwpznQ3qfgclNfOeZhrGkDnohJDxP2thouVnCLHhNd+K2rR/jix9XQE0sTVT4IcZXMNFUJJpAMXZ2PZsmAu4q6am5QzEG9sB8EOtKTxg/KzXO81htlhie6Uez48NGNf6/+dnvyrZknwh5ZuQPwn9Sk4xqdnvmWmKuq79H0f//30GCIg46/bNgouKf92uSSxCtvCTu/4gPKSpTKFTuodCXYQryGE42epJCswqNeumNoF74pBLYZLqdQWDrv55afQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CH1PPF4C9628624.namprd12.prod.outlook.com (2603:10b6:61f:fc00::60d) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 14:20:00 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 14:20:00 +0000
Date: Thu, 28 Aug 2025 11:19:58 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Alexey Kardashevskiy <aik@amd.com>
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
Subject: Re: [PATCH v4 07/16] dma-mapping: convert dma_direct_*map_page to be
 phys_addr_t based
Message-ID: <20250828141958.GF9469@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <3faa9c978e243a904ffe01496148c4563dc9274e.1755624249.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3faa9c978e243a904ffe01496148c4563dc9274e.1755624249.git.leon@kernel.org>
X-ClientProxiedBy: YT1PR01CA0055.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:2e::24) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CH1PPF4C9628624:EE_
X-MS-Office365-Filtering-Correlation-Id: ee25c9d4-a894-4ec6-2322-08dde63df8ba
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|1800799024|366016|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?9ABT6QTC3/4LJlsORe9ECLURm5FPgYglzP4U8WaOSREO8cESJY67mpBgPEgf?=
 =?us-ascii?Q?MkjBrlOeWvd+Wx5sAHlUUxAypsE3sfz8tRKkX9INneWs2ZUhCuiL+xViVKT/?=
 =?us-ascii?Q?rfMpRQymx+irdvSIp4qZHv0it0sFIEnAypUowzkTqVzqCSgFEN9wpsDQUbug?=
 =?us-ascii?Q?qCBBjuZxvzOKP1cE3SXz7NfTZkR7c2f/KeWbfYAVmhwF+JdwiEsfdIKiKGfu?=
 =?us-ascii?Q?KFOGSgoJegWT/eiZ0MFRxjbwCG+FwEkg81Ukc1BsCPF+8jXdZtJVeXhv7+VW?=
 =?us-ascii?Q?h698g2uohrUxw5kkLDmqSBPVhg8ilvnXIutPYKjCAt1bMWYT3SVpW+eR99yn?=
 =?us-ascii?Q?V2hYNiLmkVaSAtGxDbv2FjU7DY4TWALSxOsgPymNrMjpcwvEPmg9iRhe/Kak?=
 =?us-ascii?Q?emtDF8WNI0h8UDSBKFdP2kmXFiGT9OpfHXOUDXYc0EyyoNYemlSR/WNEP8fw?=
 =?us-ascii?Q?iIxBcNn90ffR5b7+rVNjGlKo0XU81sqQRBi8X8mYq2jkXCEO/peYXNNRemHT?=
 =?us-ascii?Q?42p6fIV0eogpg/mvjNqfDzp3ArXrvuenVv/BvlLC0kDzmZAIOPwN3QdIOuyi?=
 =?us-ascii?Q?W5TJnKzgtNhmJnfCWp3jVysjCXd9dWeG7RuRghEbc2RH3Uy7bXU9SMn8dmf9?=
 =?us-ascii?Q?gpARsIUsJQqV2u91jnjSMUrFMRwiOwFxNW/y14lTJM8Zm18iTTRBjdBArogn?=
 =?us-ascii?Q?l32UDaIh3XzO+DR3xPn3Mja3Jzx3n01d+9vrDjvg/iV+yhn+FTJR9fY3oHV6?=
 =?us-ascii?Q?DMkOurjB5PukWMJDHBEc7Wi/WC2myrLMwYL9/39GprTbNLrTUexGld9LH1qM?=
 =?us-ascii?Q?rwGb7NwkfSSKgaz8lA0b45FLXa2uJCydXEhmG+J9Khp9uo0cnJ6Q+DBykbAO?=
 =?us-ascii?Q?W+/IAB/HpcrmMyzu3DIe1rXsJEZWw68SSNF1TDZgDOTQJovBXejmtt4GBExT?=
 =?us-ascii?Q?arBrV3XY04TZtmkEMb/4I8MSuMhMRiOd8CpHcvT/+tYP1p2QFOBQ1gIgGsPW?=
 =?us-ascii?Q?P3ICz7+xrw2/1SWkrb+ev8szOepdpDazVU32e+meayOMKWf575XW3D3a0gxq?=
 =?us-ascii?Q?Qfm5CLQQ0CT0QRq/f8LXBnRon+W9NZws9+kPQjiW4Y4ZZFuQVA1NXi9RXK2i?=
 =?us-ascii?Q?7d109Wx8+biBFpwcU3HOHUEZ0TsZ/y610sjQ45jorO+034WU0/zvgFG06Jxf?=
 =?us-ascii?Q?V2d72ZQL2rkiFbwKS0iOquz664r6LYn8VYdwO3xjMZ19nsn4SoO/cQQ7u1g6?=
 =?us-ascii?Q?kdNWoNUZZHdwDj1fesG0YxnkIrkDOakzRSpKryPitAhtawRRPfI+hNpj9aWh?=
 =?us-ascii?Q?ZS5rVojaCrIdUpbyZMPEv6trU4xPtIfIjmPI+hbXqgQadAMblXKCk6rKTX5S?=
 =?us-ascii?Q?a1ybeGPwK4NZcscvfiQySo2DML0nC9zFVon4MrwW6ODFN3spzuJrWfsrMo/u?=
 =?us-ascii?Q?4dmb68jk8Mk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(1800799024)(366016)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?0GKUUMy2Zjj7bShx559KxLONxcEVScGItWUxoqpIFyh6XEjUtYEUSckAJ+VS?=
 =?us-ascii?Q?kRzeLOB37iyFXOukUG7mg8GSDXvLhCpRyfX2Oh2Fb45BNBhk2yEjnScpepNz?=
 =?us-ascii?Q?860jrVAdoO7ibpqBpfTD7zWlzqL9z/qjFMO22UMNfFrKPDrgiAnj//751W0f?=
 =?us-ascii?Q?WgWHubeAyDqwC5yntQuyj6PL5b2TYt2qobichzmcR75vrk+NM/omSaTnnokd?=
 =?us-ascii?Q?Hpd1UapkTBcfXsLjl7nMedjcjweiDkFLayWNjFiWrakgqmPVW7dziEmj43Wk?=
 =?us-ascii?Q?7ArwEpDKMyEo29afjiHg1veE1ewj9ao/+zS/WtDRHR1jDAwjoReLgRQDv+F0?=
 =?us-ascii?Q?03Z6s0dGmQsGMrJf/HltN2mTRCQ6IwYE0bHRLWqs9WMzd3WYTc5uuEBjZP53?=
 =?us-ascii?Q?0Enqlh+gVu673+0LDZ68ct+H3O6Unvf5NGCys5nRPF5LdDs/ahP6EB99/Sv3?=
 =?us-ascii?Q?UFTwKOm1WhdIHaBjc1VXOw2aJRSVENv8PLKhMa//9GsecikRKp1NDpBOxs5R?=
 =?us-ascii?Q?VPYBNKjffDK4iBHlfTrKx8n+pHYtwF/RsOlJTwF7Mpnktir+QiyPsxOBdldw?=
 =?us-ascii?Q?vUqPHod1VFyNkRyEFzZ9eTFEE7l5VqNTzRnWvivcB3TE9LxmDNQEjYDF7nFM?=
 =?us-ascii?Q?GP9LZ5v0U2yHhLn1RIXToR0xKkZ0BFh5+Y9ybZHAnURd4i104GJKlScvbreR?=
 =?us-ascii?Q?Q9BMdB37xbvftod+QfrHsm0p9YOsqOyVEDjNYTvAWUyFia2Ey7evm4ywkYTx?=
 =?us-ascii?Q?h+sIu07+uvh7racJKS/Z/xCUkTsr4GbLeZUv1lS4aPyxO96g0VfYbHgVQzcD?=
 =?us-ascii?Q?k5c0Vl3y01qhuqDwv+Nsth7/Rzh+5Hqakc84qx1CzTkWbf7bqkXsOWx/2Hsh?=
 =?us-ascii?Q?NN6DB6HizNh+TeKEGIgD42nteot86FM/EEGHVHo7x/qcGaj/but4TVQk/K1v?=
 =?us-ascii?Q?vRMaWoZ5Tmk15q3Tp3aP1129Cnt+dMu5WSWbuAEwJnbnczgt4XViE/ZqKX5V?=
 =?us-ascii?Q?nAApv4rOScsaCsker2ICS1EVqZ3/ze2jwu35ywe5GC/sKyuryKQx7p/CPCZW?=
 =?us-ascii?Q?1FkX4ls0qo86wW9mXmendEiz8R5CBLzpFzYmyhMM0O4v5MSi+lhX1rjl576J?=
 =?us-ascii?Q?UDlXc1RprnpiHUBQpT/3CTXFW0R4q/D1rdUPqFnFegBGw8wLZl1G9kZrzPjV?=
 =?us-ascii?Q?kyIwSDxl+GlmU8WG9ODPPzMraHCdju/SEdV5nGXP+idSzYNyGyCRO16YHz+c?=
 =?us-ascii?Q?sgsQzLW+SQbh3kOfIDKy7AnP8apjMad3QeUKs5Vbxiws6DJVnk+kC1U9aI6W?=
 =?us-ascii?Q?bv+N+M2QWywysxu5/R5s9QqPWKcCLYpk9UwU6vOhXOGTx/8ehEeRZMTzpc95?=
 =?us-ascii?Q?gXE9x0w7K4qqhLJQQoZNDRAdSzebrIqL+phygzWYqpV7kOpxvx9KOWMs5uNs?=
 =?us-ascii?Q?XS1HhwwV9Kh2B/aqy05LWXl9uY8kXMVVN6K12dkxOz15Hc7B5X6BfCCDydhP?=
 =?us-ascii?Q?fQxez10fHoATxU0Sj/6J8X7LHHevla7d3+DBz+Oze7OmFlVBqnJJsa2/UxPp?=
 =?us-ascii?Q?uT3klxfrEJzyDMyljFs=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ee25c9d4-a894-4ec6-2322-08dde63df8ba
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 14:19:59.9859
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: MleWSaT+fPMApu6hDDjuoGGeeHk6jrZi5TxdTZ3vJyLRcRpsAXuDhi0ZC+bhq47a
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH1PPF4C9628624
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=SHVyRQqx;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2417::612 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Aug 19, 2025 at 08:36:51PM +0300, Leon Romanovsky wrote:
> +static inline dma_addr_t dma_direct_map_phys(struct device *dev,
> +		phys_addr_t phys, size_t size, enum dma_data_direction dir,
> +		unsigned long attrs)
>  {
> -	phys_addr_t phys = page_to_phys(page) + offset;
> -	dma_addr_t dma_addr = phys_to_dma(dev, phys);
> +	dma_addr_t dma_addr;
> +	bool capable;
>  
>  	if (is_swiotlb_force_bounce(dev)) {
> -		if (is_pci_p2pdma_page(page))
> -			return DMA_MAPPING_ERROR;
> +		if (attrs & DMA_ATTR_MMIO)
> +			goto err_overflow;
> +
>  		return swiotlb_map(dev, phys, size, dir, attrs);
>  	}
>  
> -	if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
> -	    dma_kmalloc_needs_bounce(dev, size, dir)) {
> -		if (is_pci_p2pdma_page(page))
> -			return DMA_MAPPING_ERROR;
> -		if (is_swiotlb_active(dev))
> +	if (attrs & DMA_ATTR_MMIO)
> +		dma_addr = phys;
> +	else
> +		dma_addr = phys_to_dma(dev, phys);

I've been trying to unpuzzle this CC related mess for a while and
still am unsure what is right here... But judging from the comments I
think this should always call phys_to_dma(). Though I understand the
existing map_resource path didn't call it so it would also be fine to
leave it like this..

Alexey do you know?

The only time this seems to do anything is on AMD and I have no idea
what AMD has done to their CC memory map with the iommu..

On ARM at least I would expect the DMA API to be dealing only with
canonical IPA, ie if the memory is encrpyted it is in the protect IPA
region, if it is decrypted then it is in the unprotected IPA region.

I think some of this 'dma encrypted' 'dma unencrypted' stuff is a bit
confused, at least on ARM, as I would expect the caller to have a
correct phys_addr_t with the correct IPA aliases already. Passing in
an ambiguous struct page for DMA mapping and then magically fixing it
seems really weird to me. I would expect that a correct phys_addr_t
should just translate 1:1 to a dma_addr_t or an iopte. Suzuki is that
the right idea for ARM?

To that end this series seems like a big improvment for CCA as the
caller can now specify either the protected or unprotected IPA
directly instead of an ambiguous struct page.

One of the things we are going to need for bounce buffering devices
like RDMA is to be able to allocate unencrypted folios, mmap them to
userspace, come back and then dma map them as unencrypted into a
MR.

So it looks to me like this series will be important for this use case
as well.

It looks OK though:

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828141958.GF9469%40nvidia.com.
