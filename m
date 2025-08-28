Return-Path: <kasan-dev+bncBCN77QHK3UIBBLOUYPCQMGQEHDS57EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C4FBB3AE84
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 01:45:51 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-71fea0dac4fsf20481227b3.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 16:45:51 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756424750; cv=pass;
        d=google.com; s=arc-20240605;
        b=bn1ItMqagGIkMpMSUuHsy+urKklw6fisMWse3Ecq53rlCfH7+k5lBgxTgf8Pc7wdvo
         fvBGHSPjdZ8lT02BqTW4EvuT3AwET/CqIJ8WZ1aunYct+QMWkamrhg6bWq/ckN4lJ5np
         ZSFBqL2CXF4jRBrPrDi1G5MzK1dYpeBoQNlc/z+ZkUh3dAfZFfEkk1Ltc+96pNq1J5RP
         t6HXy3zbE3VTbZc0KQU1NSTmNojzqqbZF9GS/bG0pP15asgWi5ncVLb+Fz3AVxBo+mJS
         Mk79im/RSwzQFlo3dmLottMmN6tUhPuZUrpfSmW+JGRnJGLvcax09Op6UDrz4QLAdIGw
         u1lQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=SOvmDv8jg/DLUQp2mGxUkgv7q1pEwaQc0nJF55hOmho=;
        fh=OPfDQJpYWxAjUoDhwXFKCvX5y5vdGrRY6WzHi72zx3U=;
        b=O40d8Wb/dynCv/TJM1QdFZyixTMRLB9wfmKJhU5bWtqBEE99fpn1RRlj3+P3xh2MJM
         K91v/DgTFL5ESbdPUZ1OCBeakBXg01ulm7a2F2Xg8lpGsKQRKNW/nXERsTJJvp4jxAGA
         EX66kEZqkNpOmiA249fW2wdvsxs5PXOw+sbQ8pFH4OJOOC/XzgVwZeaQXvyCK8k8EGiK
         vBjwRq2lZvz6cwXOI9VjzaXNXNOCAiW/TI7DmIldBkKg+aFE3rgnZSuUKnpFSGkAl0Gb
         0Ib+LaW/1kOi+csH9XcoGARHtTw+8b0LW+YH96hdHSKtILkXwwF6HOeNij47P3oF5Nue
         XaWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=VxRX8y7v;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::60f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756424750; x=1757029550; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=SOvmDv8jg/DLUQp2mGxUkgv7q1pEwaQc0nJF55hOmho=;
        b=JQ6VAtekiMFRPGY+N7Jxr9pH8kIyyzZV6kLH0t6QB3xLiGTNzNBa+SM6/40GoLCBXz
         NL9eLBG/QdUp6L+BmJ6a7W/g0+mRf4EfFdJ7rcc6y16SHIkzMKwRd4B6sV823JZkh7e7
         Ywqn0BmfmndoOHpG9VITQydn9pq+Bz8k/F9p4kOFE/jiscFJhOmHD9nj3hUi42abRN6T
         +gK37bOtKmYuNv5W7TZD/2t0ggeBqXPz+5vNAoddSbCHECIYGFO+13E5NeUI6UI6cl7/
         MZjwg40YzHNzs27wIN0X9jug/0/xhdq9AUp3NrRya8eRBeBQevh526moujbHkDTegLhk
         sRxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756424750; x=1757029550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SOvmDv8jg/DLUQp2mGxUkgv7q1pEwaQc0nJF55hOmho=;
        b=W0nx/TFNhCMCVcA6D3kx0jH8OeqQpxZtufZ9aeHds7ZYrkaHZTBRWYA7eSYlqLVguw
         2LsBK974XsP3ohce5KDKR/+3n3FNso/9UsMgPAuNQImTJloEPUapO9G4pd3m1PtEeeXB
         8R98eWZ47upas8Zllcj/nE05MXzUIg13ysV0Z9XeD8HbK4THwwjMSej3tjqd+1ya7pLv
         yIq0RkaPjOX5PRQYWHdKukPDeQ9FrbYdNOsl9f+CSjG3DdLowHXGPM9AW/XnnZRPgmnp
         d2Suj1uXFRdPZ21Os3D2lUsbamvtUS9HgfUT9kFL+2ICjrb70Wem/5kXqnEbjbOgoKDk
         UBoA==
X-Forwarded-Encrypted: i=3; AJvYcCUt7JnLrlYwhEV9UdT/T53pPC6NRL2ATl3W65FGBLZ4VjgEkNG86EOAj65TsYGRlMkGu2npuw==@lfdr.de
X-Gm-Message-State: AOJu0YzxW+u3Hk9qpCbNO8dFkPBwGitKSm1B132GLXLET+BrgHUJA0A0
	lpfTGV+Suuwhq/S0prcvS21l7pYh7Vw6jT1b+l7nu5SsjQ+6aZOuM6a4
X-Google-Smtp-Source: AGHT+IHajh9COoyVRN/LFhsA2jFhVl6IBQOHhBHUEaErDAZqR+q9+OPeuJi4+ic3R0ayNEVqh1wIAg==
X-Received: by 2002:a05:6902:2d08:b0:e8f:db21:9544 with SMTP id 3f1490d57ef6-e951c23996amr30872576276.20.1756424749925;
        Thu, 28 Aug 2025 16:45:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe+PoFivDjL6XUzlav+Av626cqxNkxtIaZSVLnttc3wLQ==
Received: by 2002:a05:6902:a06:b0:e93:3a67:babd with SMTP id
 3f1490d57ef6-e9700f4e59bls1232956276.2.-pod-prod-07-us; Thu, 28 Aug 2025
 16:45:49 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV3fG0f4Gvlo/x6oAwNrp5z12SJcgXQLmC0x1q+LBNpYXTcwcyI1xvCiNEUjIzgTpQ3QTSgjhadMBQ=@googlegroups.com
X-Received: by 2002:a05:6902:2b07:b0:e95:5f4:c88b with SMTP id 3f1490d57ef6-e951c2a54c6mr30498946276.27.1756424749036;
        Thu, 28 Aug 2025 16:45:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756424749; cv=pass;
        d=google.com; s=arc-20240605;
        b=HQ4f4oYu7yLMxLhJTMyaXJ1JcZWYc+mx8F0UWw+i4bZv84Tf+TTUOwDGk3ZCi/fuay
         4qp+xgQmRk8nQijdaN8Y366ZybOFxDHkfYURuc9wave1Ur+5j3+ThquKLl5SHfx7fDmB
         4+H/qpKRMyzkvLwOI5LOCgIYknks0plYJPRo6PL65ORg/UIVsAyijJ8p0z4VsIZizFOW
         J53WipO12XKmT1VbdNdFUXTtYZdBKeChiEENPgqRWm4kKPF1Ba37He/MTbJTC3y+K8GX
         VxQ2XGgIGbrvUeJFznP7vUzO3hPwzH6VBpfr8WrfK/Jd2dDBp6SSDEJFPQWy5D6t0YpA
         yYLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1JzfVyfbWEkwcvRy5E87In4bJJ84qEkwC/j9O+RskB0=;
        fh=KNrcxmkEXOCGvlInKu/iFbEeiPtFjj53/K2rpPyAzag=;
        b=htOjmXFEIITDYwLcu9KHXwSynWF4gArqEo+sB46hl8R/oLZ1794OB5eJh4TKZATbkF
         bvF1tyiEEWDQtjgxtTA12RNeEHAdK+9csFdTwaeKCEXnpqjeq5JiuZItiR76N9yaR4Ur
         2gsxSM/07vH/4LMuI9AgQQD9n8E0YjQBcJASE1QESPAIT32acrZtR1FgtbOeHCh7VYpH
         eNYwDgYA4YsqMFTO3TQtfAsfZqNG0RfLhzFvsiwvLAFnAXwqyp/ch9YOJkON23dTVWaZ
         nje+Gi3LK2cStS9Zh7nAk9BF+nSjtuDbPlhNxbq/mrG4NS8Tm+ZbC0dCwPnczie2Chwg
         9WrA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=VxRX8y7v;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::60f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (mail-dm6nam12on2060f.outbound.protection.outlook.com. [2a01:111:f403:2417::60f])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e9847d3aac7si27799276.1.2025.08.28.16.45.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 16:45:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2417::60f as permitted sender) client-ip=2a01:111:f403:2417::60f;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BC0j4lwL4dAZkVK7ch7LF2nEtfdyfLuAA9ArPob3ntYclDYP9WUWF4lzLgBjVEWhKD5fzKCHCvGY5+ndBoRrUZwm7waYZhpSqAahKYwgQ4pjljsudSoVim6I1hb9ly7jMQqHnr44z2LJClAFi82An2v/KrYyR5ZeA70EU+uCXT/rleKxZWx+PAzM297baujTy8UZVntNmF6p7b2TJOYuME78pNxz1HsfZpzErVOVNYl6GiqZ5yRWCRCzttx+jBI51JngDmXcWelvtfVyFMvxw+62K7k2qBxCZ8Fc4e37K8Q+jGpjWdeifbVUhI00fggE7wEQP4jyhOoXizMoJ8tVEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1JzfVyfbWEkwcvRy5E87In4bJJ84qEkwC/j9O+RskB0=;
 b=OuXuVM34IS1TM0+6lpGfRyQyiWbMArhtJHiPyAgIiz4AlR2A9iMHh2iJjDR5UK+PYaynzoJXM12KvSYb+IA2KB2fmTlbiAUz1r2mUfUeZHRKqxSwV0LmV2GkOPmgSzQ5MYzn1hZJFRWDqoYgBFtMNGuMPDBJVb8P/9jqwjbguKt+hkYnD+ht+QDLJRox2+wePM3TpqbrBPHyqOTkdOJZycEjFRPmJuUNApFbfzhw1d53g2o7cqRI0vZ+VJTqLbGS1YEEO/x5afwsJ/CT40bHaWRqBIKvugAMF2pDdPIOcs4D6WdXb0OSJy8SlnmEMFsA7TmpWwIyN/tzZN7HLbt84g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by SA1PR12MB6776.namprd12.prod.outlook.com (2603:10b6:806:25b::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 23:45:44 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 23:45:44 +0000
Date: Thu, 28 Aug 2025 20:45:42 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Keith Busch <kbusch@kernel.org>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
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
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <20250828234542.GK7333@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
 <aLBzeMNT3WOrjprC@kbusch-mbp>
 <20250828165427.GB10073@unreal>
 <aLCOqIaoaKUEOdeh@kbusch-mbp>
 <20250828184115.GE7333@nvidia.com>
 <aLCpqI-VQ7KeB6DL@kbusch-mbp>
 <20250828191820.GH7333@nvidia.com>
 <aLDCC4rXcIKF8sRg@kbusch-mbp>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aLDCC4rXcIKF8sRg@kbusch-mbp>
X-ClientProxiedBy: PH7PR13CA0003.namprd13.prod.outlook.com
 (2603:10b6:510:174::14) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|SA1PR12MB6776:EE_
X-MS-Office365-Filtering-Correlation-Id: 753e419c-5ee5-49ef-69cc-08dde68d017e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|366016|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?BRmB+3sKM17VmapuvDAanENDABDoL5Vpjr28rLgku94+uoeQ47+jUimtSCp1?=
 =?us-ascii?Q?u0ol1dYjEgBvhO+ruK3iz1KEP/hZe25IXKS3DBr3YL9i7oeUIybZm61bc1EK?=
 =?us-ascii?Q?ySVKFefar6hxK0//rT6Je0GyXftJ2+WIKk+gQVSVNjs+Bkungz+C7gvV7FE9?=
 =?us-ascii?Q?JWTCKInSOrbbaQQHrNsl6Z5VBvqOljwWpgr3qXQvyL+Pg+MscLmm6SArQcxY?=
 =?us-ascii?Q?DhRw9/ZD8E7yHpahJ58uR5uiRAi4+XlAVS2evL/9AMATYhX1mkLmURS/z3jc?=
 =?us-ascii?Q?1V8fE7B86lb2Ht8o66gydqV81PLbS1K7px3v2ku7KKgIc9spCDxux52V1e9X?=
 =?us-ascii?Q?2498Hip1BaWsm1qRiLue87NQN9Z8AJishXg/2l29DTeQIEgx8BvWPqqlHtMI?=
 =?us-ascii?Q?LZrzHSOQwD82enU0XZ4QvLY+EpJrrsG0aR8cPF6lU48eUz2Bwk19vFp5xmob?=
 =?us-ascii?Q?FBLQcOaGyTp3p1DF5P/fDKAKIx3KFyk25UzYulT6OPKOJ8/nAaUAfoELdNwt?=
 =?us-ascii?Q?gJJsBFxQ7TZfd+e5TwigthbjSdVMfwZu4ntQ3hbIPzZ3X8i+//nTBmsBv2P/?=
 =?us-ascii?Q?9JHw7gf5BC5M7B79SHTbr3VxCjAxyblS+ecONyQ7+pV0UZdx4ZkJaEYtITXK?=
 =?us-ascii?Q?/Ud/XTouTFMXZ5sLYqFF7qM81eEraAf2qP9fHpukUza4yBXVwCBf3mZem0Vf?=
 =?us-ascii?Q?OJRavtRWTGaJ+pLqvA6Ou8HUKqW+yoROq9n9FY6r9a2ShUiGDeBHELGNMS9I?=
 =?us-ascii?Q?dL7jH7kqZnUOoBBf3mGbE+UqUXxdaXpDchRzCfuEK4FnZ7zr4gN9ep/+4aJM?=
 =?us-ascii?Q?sw6wi+XaEogKqqzViWPfuAemHi05HSfMS4MdRfkPchzCEfzJFlwSv+GLxzlD?=
 =?us-ascii?Q?HCWlPg4s9cg/K3ly9v7KncbEKuyZo2TZaLSvdiK6wXEvmt5LLMxwqXZIWgFn?=
 =?us-ascii?Q?xWdsfLj+2G7UfQCHxukuX2UQYJuI1WLdvSDOw0AGKcw+99YC77IRY+OL92/D?=
 =?us-ascii?Q?21dNzr7nLqsmiYEFtY1EJio4JyFTMe3ec10oPKTUrkcsGkjr1/ks+6KSCtvn?=
 =?us-ascii?Q?HA0+NJPHPPjzq4wQhCZDNTDtkDziamYMNAFgr0N+PteMCcAxrxhNkG5ZyPDo?=
 =?us-ascii?Q?Ua1raoxaJ5NswslbugvyjHR0iXjibH3cEoK59tkDZ1f/uLlg+VQy3QNMGn7n?=
 =?us-ascii?Q?HCK6PdEXVn7LemiRnfbB5fcOxtdaUEPFW5lJjVHBVf8vHD2B4Bo1bM3mIXwL?=
 =?us-ascii?Q?I9Jn/tVJuGDOr+/G4UBoCVpEef7zxZjVhIs5r53tho0Sm441MIodgr3hTnDX?=
 =?us-ascii?Q?65dDh/vJRvQ25+EgjhJh4yNobd1W8xoCF1IhGxQbiNrO49hN+w8dOg6USblN?=
 =?us-ascii?Q?ZdfJit9b8mGe+lxErrCIkoNOdCD3aQ01k1hLoZQAmRwv/zUPd+uDvm7rBHth?=
 =?us-ascii?Q?Cvvs6vcbnBU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(366016)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Guohg76/pkR5ZgCdXgoXw1W3mQ00oIzJR+SdpQh5sfjJMXbMJ6diFn7nFxpV?=
 =?us-ascii?Q?idifmlCDn6s8kevNE8Sf4gg9m8QK3+NtR2NSUeO9qNsfGDtGDFWFwjrJ5I5k?=
 =?us-ascii?Q?Ox4PeX8sLOraVXU+a9YyVUbixgamtzWXtFVqTFjAYxe7tJjQRhfS2cBo+fi5?=
 =?us-ascii?Q?kVVvQnY8kZ3FnBMRjUQZFrfMSc7Mi3mxfiW8w7B7GKRGTOIBn3rkqXeyvfl9?=
 =?us-ascii?Q?D1Q7+0cmtHVDvXMJiug98HJ17TCVxynsb1SEjZxEdfB/d5l5f17QzUwpPnVN?=
 =?us-ascii?Q?Gplf3AcoLO1AIGH+gwg6UqRp0s6sMkSKs0xwRZigys9wH5XBl9W2216ei6tY?=
 =?us-ascii?Q?vvR5O4PxY3fkdAsxQQKZfY3GGooMAF5guVzbOllo+zUmGHGYzSN6di40Xba+?=
 =?us-ascii?Q?ngFmkM1zsb8jSY87arByWlr7nB8uWwkhGYuLFNV0c8xY/D6x46jEvCrDrLzN?=
 =?us-ascii?Q?QdaBljNNtZJQpa7uhXrdwcbQHLktyV87FIGiljAjlhL2tDE8GgdWmjQ9I07Q?=
 =?us-ascii?Q?cpe0ZtsvokBQR0zYqw6t8PkI1eqMRH+E8s7b2oIPX61W4gxJPmeMgjkokkN4?=
 =?us-ascii?Q?BePhnvjrhX+JARM1FdSryWeoCtJ3m77i7OSY+ZS+AyHeOn2IUYgxh0ArUlvq?=
 =?us-ascii?Q?BvNDMGcSBFWJu4hdNZztzTi+5uLEGmsdU2p+6i9UE/XqPfDiTD88psrco+fb?=
 =?us-ascii?Q?fY/xzqHaiCEj1rxu6vxJXwfiTL+iTcSA52Gl7mFQGOMgADdAjDbHTUSLIaQw?=
 =?us-ascii?Q?cAixtwK5ed5SN/lVyfz4rS2BpfHcflIlkrhPN1NLFiXEJogyMcgIUlslIWfc?=
 =?us-ascii?Q?N4SxOFYJprB/AeCcdUG9CkiCGanv1lbz4sFatvqfIBj/Cz07Fs7w5EHoVrsl?=
 =?us-ascii?Q?BkitYeS6X6zNKItXzPlD0uehnMerAtpbspMmXMkfgDTxVQqDMRprgWSEZTs4?=
 =?us-ascii?Q?3ceZRuolwKKM2lcKQL+tawp818fSy1l2N5KTgPhJGK3DAjHmnUPP+DExWgQ8?=
 =?us-ascii?Q?62AcQmC0vE3imo5f6Axz3FQHoBp3zbuYc7CfhCuDOe+6hSguUTMHfZfnZyII?=
 =?us-ascii?Q?7fnKE8QhQ6zMbXSZMUPCXIEWZRaSfB/x954fCwGQFhgCqxiCxkE4w5HzBMOh?=
 =?us-ascii?Q?dLeCGlEaAsHoOcFROZCGOdisGP9Zlit0/k6rVQ+J9tO3D6iXu8tp/2c3Wk/L?=
 =?us-ascii?Q?euhoY/rX47hr8ctR5Cp1zPCIL7Hk1EtfflIpOZwE4I88A1Tpiw/JVGWBpoK/?=
 =?us-ascii?Q?wQGvzOztsizk77wdlm2KI4QYnPVWD3gZHYmFEVNhuf/cdumvV6iho52kDZbC?=
 =?us-ascii?Q?urbjXb+V0k3ksRa5Yl6SkXgRGvaBvJVo8pShoQITY792C177/Qu1Kzp8TIGs?=
 =?us-ascii?Q?jaby0wxn228VgUWgqaGu01nkxL96Q5xrnXO7hbCRmfyOPPyasuMfwZLX4EHU?=
 =?us-ascii?Q?e9ljeB3zqOhiHYAVmIosgGuhi1Wif+QzpP/frMqCpXzb0vpi6c19NhWE3vG0?=
 =?us-ascii?Q?wdimmMQp2Hr+zsdLF43kjsQZlHnbRGTNKGJW5xxYHTTjqo4bwYiXSm+YG9UX?=
 =?us-ascii?Q?+1fyZ2DaYg9/ErkWntpBMRbOiJM/hdBX7nHaA03A?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 753e419c-5ee5-49ef-69cc-08dde68d017e
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 23:45:44.7681
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: stKDrPdUYg+cKM6Zaii6EJX1iDXReQlwcCRvIIs2DW0PSsQcsndv+JR8Lnf1GfOk
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA1PR12MB6776
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=VxRX8y7v;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2417::60f as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Thu, Aug 28, 2025 at 02:54:35PM -0600, Keith Busch wrote:

> In truth though, I hadn't tried p2p metadata before today, and it looks
> like bio_integrity_map_user() is missing the P2P extraction flags to
> make that work. Just added this patch below, now I can set p2p or host
> memory independently for data and integrity payloads:

I think it is a bit more than that, you have to make sure all the meta
data is the same, either all p2p or all cpu and then record this
somehow so the DMA mapping knows what kind it is.

Once that is all done then the above should still be OK, the dma unmap
of the data can follow Leon's new flag and the dma unmap of the
integrity can follow however integrity kept track (in the
bio_integrity_payload perhaps?) ??

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828234542.GK7333%40nvidia.com.
