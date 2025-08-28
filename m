Return-Path: <kasan-dev+bncBCN77QHK3UIBBLNHYHCQMGQENP5ZECY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 54A4AB39E08
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 15:03:44 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3278f873865sf209650a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 06:03:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756386223; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZhnD1WjAod9AK0TGtwotRDsLFi+IyPX7bsceqV6vlUZLXZI1vIi+6hFq34BVMJH65U
         +xRL4HGSusWVLhNNu+c6yNU8mhqiv1h35BVGI4/YkVyiaRMwBmeEf1oI6HnN2MXqupmU
         za6hhD9CLZEUTBDBwPIyonm9BTpXqigwKf7UsAvJWsY0igQpn/sJeAhX7edhQcO48Egt
         TcqJE4QZ5jG3CnD+Mh+sQnJicnpW0XNUxwFXxdnFor210HELZuIQ2hSd7HGng6Uymjl1
         35IeFDa0xxFJIFQKU+1CBO3plETj/F832h0ieawHNUkBHWuKbiuHldEHXnlyBmp9zPBd
         KWkA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=7Rq0k06fBlWyhgoO9wP1mec4cjhDg2DJObQamMmdgVM=;
        fh=n1m7LtfuSmPGwFCyISybkfnAbEZFwc1aNdQ5WKAQNoY=;
        b=g52Jmv5qaIdckWzONipk/YC7RF9DHYa6NRKeNZCYYBtDDcx274HtU46zSq/z5CaTCn
         y+abP5k/QEtScYIOzMad9HVMeBEj/fVD33U3mlzRPFBzN84KVMeOQH1UC/id2IOdpR1K
         wU14ob7n3AmqVXNNsTxBMAangsyC5b+JCK6qYiN7bgifMCZsY3Lgh29ozy4njNR8OAgP
         sxCXS7HPB9LBH2HPhBXtHRR8gr3abF413deyeh2n4WObnxJhPHiRiUn+FcCi/qxjIuHu
         55QsGZZI6bwc7YeUpUfrsmLUPvC4CGam6JwmABypHdJhgC+4cz+sbgbNPfjcscBxtUZg
         AaPg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=fMOHKVpY;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::602 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756386223; x=1756991023; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=7Rq0k06fBlWyhgoO9wP1mec4cjhDg2DJObQamMmdgVM=;
        b=iviLBCQDyjaHHdTion88gmyqAFtiDBp+TZOGmBqVrxKdNqboVRKoSvu39YvZ1Nf6hM
         wvyW4HjIiwfbyOs2tqNpyQ1/DIINwSw/3ns6FF1QkPBoXD5rYk0WmAVZTQa2sSSKTV+Y
         Ee7yAr8CYMq6Q0/L8Pfo6G2eQ89TzzwZW9u9h9s+78cjoEPTw9PLgGjzjns8XQz5c0hV
         ko/VIiQZVpILTHtjeox4kzsY8qniYdb4HfU9Qt4EvDfTGJFeIfMdtY6Z7vwcm2D4mxdV
         r3lnyhn0qXe5p1cLbnBYB4YXPSiQ9Cltsl2iWPoO8TWF8tkJ73sXhSh63bBn8TcxoHpb
         M7sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756386223; x=1756991023;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7Rq0k06fBlWyhgoO9wP1mec4cjhDg2DJObQamMmdgVM=;
        b=fyGWnEDP8JJUX9mlitspiJ4hs+sDtcNRDKxl/0P203Z9NcCpm8WEcBd/wb03F9khx9
         h3pD2/anEGOzMp3/bWYloylcvAVDGjBTnI38PX/zlj1krD8OmUCLCtM6panGC52LYbnt
         rAo5qjntCcKHqJbgDms3nJ8FPCrqqxdRkazKfAC/OQN7RhN/DIiApTk2hA4fBQlz3xdM
         ptR8eIH64BccQRLypQEnKi0rTl+y0dtvzQD/PKOnnDQrzdNsLy0GvHgPGcM+8CQDaXWY
         7AuJMQ9ts4qDApNQOWK0yzoaDYQyseIj9rk5pFiy4i44VwKHMXz4dk34us5G3+kQmp8b
         a19Q==
X-Forwarded-Encrypted: i=3; AJvYcCXkmpg5tJUYGrqe6d8xqDdiGHdXgnZMYHYs8w7u+LaY01bXPbAuThrwlb7kWr9csjhC77UI8w==@lfdr.de
X-Gm-Message-State: AOJu0YwtqZQEIOrYygBL9Twt2DsAr0bAwDRRfJOvmlv5PWMz+pXa3aS1
	7Tjoihplp5VEeUWktgG6yh55GLLIt8hPcunD0Xp56+3GVONMBkwi2NMC
X-Google-Smtp-Source: AGHT+IGPk4b/f1fx2VG08Qo5Lb3/33wDcfXE4eUhWwJII9YxB8XcCigKa+SjGuqfFR5jiWhA3dd78Q==
X-Received: by 2002:a17:90b:1a8e:b0:327:c784:7c37 with SMTP id 98e67ed59e1d1-327c7847ecbmr531354a91.0.1756386222082;
        Thu, 28 Aug 2025 06:03:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcy7Q6s0xbUnDMJJMZ49oqt5MBVE3tOhVcsAnmsOs5fAw==
Received: by 2002:a17:90a:6c89:b0:327:6f3a:16ba with SMTP id
 98e67ed59e1d1-327aac842fals614604a91.2.-pod-prod-04-us; Thu, 28 Aug 2025
 06:03:40 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVSwHullMCIILgTq7iR3aIRxe/2vdLmaZ/dZq64+p0sYSrvpPDaWwpZDWSJ1U9Kse1J3yEhZHLYwXM=@googlegroups.com
X-Received: by 2002:a17:90b:1d92:b0:323:7bb1:1048 with SMTP id 98e67ed59e1d1-32515ec1404mr25732448a91.2.1756386218404;
        Thu, 28 Aug 2025 06:03:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756386218; cv=pass;
        d=google.com; s=arc-20240605;
        b=feYvh72sEcXXLS5XRPcDJCnj8OyUGi/molu49bKTbZtkbWw7vtilA1I/iR2IK3gp09
         ardcWrJj7AR6P3dAs0CEDeaymyr3Npbz/Q0YI0aeGwGlAuVL84pp6JnEombis3tEJNFJ
         jaz2DPp3XLxjT8Oq76H3XhFdB2sb6NKgyRKZac9P2jQddZLzaHEgSWPJtDwpP+uArQkd
         RlJyCnlE2W0oryVTe7kxHvmruC07r3gI1YJau5gdRwUWjsx7ZyxF0r+CmCaYD32bH1pz
         TdimkTSrRfQ1EFR0+nuzTgm+tEQWb4O3VOqW5fssyF0R6xE0vN4YZ7584Lzob80YzaPu
         rWIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lb1aBSrT7FmXIFNg2GsFQ9EVeTQg1mhe6sX7cdRiThE=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=Dt4MmXyCD80e6NPmtCl0/anQttN9gNrP/r1W4bWGcJDBIuzx2hyeOsVGIcvYo6gsvE
         vy/I4lXRWDqSIJWfvPIOR3zPrKHiBkpQrlfXwDaJdaPP5MOTe1uy/u4NKe9lmeJgxyjF
         dLG47cTkEqtTpl3L7S6lZGnJkxvUPZK5vvP6ASGPRACAjBcT2z4nq/l0+Y9xJCWCj+qs
         ihVWdiTaKFIMHGmWTNLeOnjvY4D6qCwqLhxt81Oh0x6mS/aZ44L35CUNuIS5WhL50mFb
         H/zsm+r9KdP+N19YSLBkDuOf8SS4X0hddtSk6iRMg5Gg7/NrmW4nO8JmwN21uuiqYJH8
         m2Tg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=fMOHKVpY;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::602 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on20602.outbound.protection.outlook.com. [2a01:111:f403:2415::602])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f538490si154927a91.1.2025.08.28.06.03.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 06:03:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::602 as permitted sender) client-ip=2a01:111:f403:2415::602;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RK2boCbuG8+THudRPPBnz2BVqcPYNNmsZyx6ar7cyi1lJcWMGtn/ODmZOffdT7qr3h/4lPrOQHsyY0CzZyoXlH3KOo8fq3J/HKXq/eqAPshsEvv8YSYqfMsroBxHgj34lnK0rmecBfSBeQz5+oCEtxl/1Nn22bBVz1yHfe44eZVE5G9Ojmrf2vMxAyujQbF3+V68y9Q+yG9nQJPhEt+KuMx2MNwNHStPV0a56gCrM0dCvTyf6B7qlLqlvQGTcF0wxRVMFUd+09dOJ8bvoSNPLhXE28LxX7xbHWbbK5imu4qfBVrlX0MMEuby46JVtyi1JCRp/F//MobtUQ+GdES3+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lb1aBSrT7FmXIFNg2GsFQ9EVeTQg1mhe6sX7cdRiThE=;
 b=QNE/q3aD/UhQyoArlwBvT6pR78ENgDH6SthcNwV2RzXCPOlWNTfJcH3icSZ4l0uhf6Fyb+axnIji94LsLZkCJhlsF53MITYJ8SYoPZY011pKsGidejJBAQ0tbmuGbFIz4dccEIw+0fZDlg3Yxc+oQoCDIWESr/CyrE2c4DcC938qFUmzyPCRGKI7Uwk3ivluL4NxAgtFCcSBYwxQS/r33nvygfw2jJrpV1U73jzZQ8nXk4em9We9fxr6L5U5UY3QCewrgOHTnOxd6B5lJhcXMtfXit0+pRdHr2wfBSw/pctbtVtPldJawM/erewW4h+9CtsOVnzzahYOWIFNOo7hvw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CY1PR12MB9583.namprd12.prod.outlook.com (2603:10b6:930:fe::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 13:03:31 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 13:03:31 +0000
Date: Thu, 28 Aug 2025 10:03:29 -0300
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
Subject: Re: [PATCH v4 01/16] dma-mapping: introduce new DMA attribute to
 indicate MMIO memory
Message-ID: <20250828130329.GA9469@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <08e044a00a872932e106f7e27449a8eab2690dbc.1755624249.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <08e044a00a872932e106f7e27449a8eab2690dbc.1755624249.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0331.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10a::27) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CY1PR12MB9583:EE_
X-MS-Office365-Filtering-Correlation-Id: 2e8ce38d-1495-4e9c-fbd5-08dde633497c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?js25oaDOXC1PcXJuXby3MQJZ3I26MTRuNb2Mzk6+4y5rkgGrDvohXSlf/qIm?=
 =?us-ascii?Q?BoL/lRuUSmmk6jDV4j9TNDCZVuU+mk9bgVAHZ3LPGwfZ3JluaHL4Njb/BxTX?=
 =?us-ascii?Q?5Cw9YeJSXbEjnuCzrd9NW2mbFh0etMT4jm/SfC/4K4X5J3jOUg//9oRaOLIU?=
 =?us-ascii?Q?+A6sDEgKzo5AbemFCiD56LnQc/ViOBLF4Lbugl70oHH2Qf2N1Armg4SLLxMH?=
 =?us-ascii?Q?lOnumEAoTZZkBv9S79uAObcb1Db8Eeyr+MiL/xNHuxs7xxVKjZCLMSJvvIbK?=
 =?us-ascii?Q?Gq3tEoSfg5wVXzDGYdVRICaGPvRC5DkyrRokbcKMJz9RLG6BQI+Py69KHOM9?=
 =?us-ascii?Q?kUb8lRnRKtv20kXjar1fS5jPwxIxJdqwnDEvqph1YC3G3nlXhX13PsorJ89V?=
 =?us-ascii?Q?LF4U9f6A510WkPbyjMqe9Z5X5gloGfieT5ojgSRR5aidoskVFEPhSg05EfeW?=
 =?us-ascii?Q?St4cblaAlN/p/UZn9RLg5E4n2RjOitB9j5DOPqfgo/v9oSO8v5snnUxdfpYy?=
 =?us-ascii?Q?tOAVVGha6SaMNGhdSQTaoyIRsG+70sUscfdsLQzwWOXznwzQDMZSHt2jbYY+?=
 =?us-ascii?Q?0GRIIw8+iliUtb9Opvh572fs714cbkIlX/MwkZ3HrpERdGzgyIgI6Kwue1yt?=
 =?us-ascii?Q?P5x2GL+6Ck41N/fCcJkIt/BlZJFQj+NBBgTeDyENWfl0H7yOZ1+UlBkBsvYN?=
 =?us-ascii?Q?A93YXE2aoIb/oEQ3tn70Wtj2oCOkuUyN1ClVwy2MhB2OI12cRU3WCF9XImtH?=
 =?us-ascii?Q?ZGQ2wAgmsf6MLHhLrmbcbDm7G8aOR0OKPyCs+7oLdpapYokRbTFB6kp5XQm6?=
 =?us-ascii?Q?PGSeS0/RdtYTXI0u9w0HTmUGyWXe+nP7YjJvft6vWvmorxNA1JQf4zrBdisM?=
 =?us-ascii?Q?mhHZnlb9uKPCzP4++8fl/BWkUPrxNCrlA7Y48ad1QrCxpNP4hBbKhbPIaENQ?=
 =?us-ascii?Q?sFOBi17yp3lndZrOr8mR34QqIfShd8+qw8ynE9/A/S0j91f4laQXx0uugGiy?=
 =?us-ascii?Q?YUaEupYaD07R14df//37cpWUPUT2YcNEu43MQp3FttrYinCkfXL+QEmpxvXx?=
 =?us-ascii?Q?pbkeA4qcaGgg3Q8vWl94dSmA+vedIspxIM+C9kOBGA6vju3Uh/uCz9VsHTcw?=
 =?us-ascii?Q?hgg96ayEx8J3Vg+qqO2qN3/mtuMU0tw5ZbG//3lXqwyDJ9AfnEba4wj0rGz/?=
 =?us-ascii?Q?HL8ZOJ/L1EKxYSDyKDUq+aZnQsBzsfKuYb3UH8jlN/cTXcJa7l2fvMPlaDnC?=
 =?us-ascii?Q?YRLi5e09+b2ERDgeihK0w2U8HRnze+77o97+MPX9DPr/Ka+qZYSsrUYot4QB?=
 =?us-ascii?Q?Uv1IjWIFxYm62bJMpF0gdD2rckJ6RVhfz/A4QXBAWTAvPrQmYe1+t6Qm2G6Z?=
 =?us-ascii?Q?D71WfPVmpCfQH+S92jhbuixwQiPV6Z0PTEOvCgIGjIzLPFdzQFwGNM3JbQpk?=
 =?us-ascii?Q?CzpsWKvkBKU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?1ckjCiMh3aH7YHuAcYKILzSmiSeqWlaX0cjU6lr4SyHlEcJpmEAmCeyOV40z?=
 =?us-ascii?Q?9e1fR89T7j6Xp4z815rEDhXVCgZIIo5/9Sb04mNpuRfGYPRBY9zvqpgOkh35?=
 =?us-ascii?Q?/IOPcsnkEdYIiouJI/wlLh7BnCc/nEB/fa3oJleLj3SXEa/1YouLRDZ/ieHd?=
 =?us-ascii?Q?Fhgn69Lu1zSjAD4cDL8F4xerway++pdKYp7fMh6cIZ+VlW6jycFV1P5MXmgS?=
 =?us-ascii?Q?mGoV98JXp74/ppnciUAThGSQzIxV/501z03pCA1eCrV3j/v+1Br3yDy4QJxW?=
 =?us-ascii?Q?frMzh866Wke8P8HGgSkgaXpOEwgWy3NKvZOWom5IlZaQ7STgDF21n3deg2Bn?=
 =?us-ascii?Q?smMK5qJYmUv/jkHZMtLRoXgBwR9hcu6+SvkgrewPkzyqBlRl6GTkMCr3k5VU?=
 =?us-ascii?Q?Giq4WnZqwKFeLOQps32EJCGUMPry83QrPBaNQL6gWIPmnMvFyZSyAVDm33RB?=
 =?us-ascii?Q?Nsr45KQ1aoLyewrNb+mw5B+uzTtLwjFV+N2mOUGeVFIHf75PqWqyy4eoQWco?=
 =?us-ascii?Q?wsPshiiaB2TYJsV+YT+NrgZovS94Jcb5smuzQLTnPPYLsbEfZgq8vP23JNE5?=
 =?us-ascii?Q?0oIZWVjvcbOUXUQ2nxNg9O6CsRDFOnW6vwXQ8hIeYJ0z7OlEC4uo+6X9hqsK?=
 =?us-ascii?Q?y4Gl1D9IPDsnjZEc5PABOo7nWuuY9OkIfi+DzpgT6SH8PGC8O9gsn12QD9iD?=
 =?us-ascii?Q?VHCXBZ/dky8PMllRareAMm9eiICY+eX+htBuOVv6YHLr+eHCDo5EzEJso+ZA?=
 =?us-ascii?Q?DvjhpqVdbeaZwt7TnBuqzgfG4taKsF9UKdhPYrjQQNQ/d/iHvMNy0gtC9jDv?=
 =?us-ascii?Q?A8wYHhwRWc07lOdovRO6IA4mL9B02+icHfZr1/KGehCEHBqrBFbeO6zOVurf?=
 =?us-ascii?Q?ISrwNfw+VWQFC2e2Jxr7QeagvEtwLbOPYlUsVvv5ouP/fmLkb9L+vQsiADaQ?=
 =?us-ascii?Q?0KFF0SxzmH8inER9VlRkWQj0uNmQsVFoU7A7VEop+6CPD+kMmtDkfsXixQKw?=
 =?us-ascii?Q?2IiT0TOhGwzqVh1hNf2+uFaw4c9EhIXWPBB8fpLj+KDyJZCRxevz6pgajGiD?=
 =?us-ascii?Q?6e7tp4RsiOIP/Xavv4sXZ1KwcKti2bFyaaRW9q3aE5/5bOj7YvQSlvTJyFcy?=
 =?us-ascii?Q?kpYDF/yTAwhXZyFXDbgZ9IjCIjLtGugtDk4bAJjQ/gr1GrnLqqhzXPE57QWJ?=
 =?us-ascii?Q?tvusWzcZabNSlAxrYhLQt9cEh/6g/IXqiyuBEp/8uUB53JY5tovj1FwY7dBa?=
 =?us-ascii?Q?POWqTvzzR9OjJNSNOYA1vFMFL0NX1qP4KFiAOxEPvZl/bNot7SBXmSsUqQRb?=
 =?us-ascii?Q?i2roYAb0OOObJ5qpVpyF/VUBMiTm/Ffg65Y6dDlp3oYLtb98fMfrqLNlir5o?=
 =?us-ascii?Q?69dWufR7H944Ebi7jgYNTTnrOi+apHLvwcBfiNyXb6pO8LPkL+toURxOapMC?=
 =?us-ascii?Q?txtSAZPvR0gYWoN6ASv0OhUDjZNkxjBzocQbB3nXsjABL9de5niWUn4J1UsY?=
 =?us-ascii?Q?1AM2M6EZA2k2+hd/hd6eZSjh1JlTWb6QuWfgRP1wqdgQbsfEPseK/hCvJ0i4?=
 =?us-ascii?Q?kzEeLZAg6e2kdvXAlIY=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2e8ce38d-1495-4e9c-fbd5-08dde633497c
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 13:03:31.1146
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: RspixjdFPbAilZf2tLBPnkO+nFqvF4XSCsFdPZ/SEHIuDVu4IvPjaklp3X5pg66+
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY1PR12MB9583
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=fMOHKVpY;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::602 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Aug 19, 2025 at 08:36:45PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> This patch introduces the DMA_ATTR_MMIO attribute to mark DMA buffers
> that reside in memory-mapped I/O (MMIO) regions, such as device BARs
> exposed through the host bridge, which are accessible for peer-to-peer
> (P2P) DMA.
> 
> This attribute is especially useful for exporting device memory to other
> devices for DMA without CPU involvement, and avoids unnecessary or
> potentially detrimental CPU cache maintenance calls.
> 
> DMA_ATTR_MMIO is supposed to provide dma_map_resource() functionality
> without need to call to special function and perform branching by
> the callers.

'branching when processing generic containers like bio_vec by the callers'

Many of the existing dma_map_resource() users already know the thing
is MMIO and don't have branching..

> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>  Documentation/core-api/dma-attributes.rst | 18 ++++++++++++++++++
>  include/linux/dma-mapping.h               | 20 ++++++++++++++++++++
>  include/trace/events/dma.h                |  3 ++-
>  rust/kernel/dma.rs                        |  3 +++
>  4 files changed, 43 insertions(+), 1 deletion(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828130329.GA9469%40nvidia.com.
