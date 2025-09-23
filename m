Return-Path: <kasan-dev+bncBCN77QHK3UIBBWVIZPDAMGQE7EQQEMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E4CDB96F24
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:09:47 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-7341cfed3ffsf92725927b3.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:09:47 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758647386; cv=pass;
        d=google.com; s=arc-20240605;
        b=IvQQ6SERoViKIFBo5OaWiSRrfSmlrf/ZoBt0KqKQAsVGGsplknRYqd2ucIfibARmkB
         32nhUO2hfU6sp/JFSPkQLtD/ree+YmcVmhKHKkYra08Lh9qE8tAq1J9ZHnNuohHRNWyT
         pHU4QHAHhFSAzytm0nk3+CIpFXICQxf4JeNzzJOscCf8Z/D3QuGdxWRgAosXP5IMuulG
         Frd6W0Lo/9tYzFWPJGNtC4xfIOXHsB/ArvEdSzH91VzuZQulybOkiIdT+2dGTFcdOqun
         M6sCOIaR1CcZmVuDXZkJmI92BvKrcXHdxYfKJJaE1ZAeCEikm+carrKCKLLwmGl8L92H
         oryQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Fz6rBAyWMonj7uzMLxoxvyQlaix02FGzBpegpIiBuUI=;
        fh=aMDYK20MlOBupZTx/UzH03qMSdGTU1Fo5JDaHyPcaX4=;
        b=KkDGeEOfZekOI+VjW+mTCmYpJGAyIlFlZMqJk+taAuFGskSZYKkYgp5GNSscT4B8Bg
         FNPHNl6dLX+lVZgJ//LNdatUTah+EpZpMMXmMRw24tm4erAQ9xINBufesX3TVtDaivAY
         /y82Fs6+nXEUnt4x1AvVgksNg5zfs79MoczPLML4HWcuz3AFd8iqEhIYBk1TuJTbkykv
         eRmMCKVEAy6dXCAmdbSe8WkZ0KBUCpdOWhb7QqLlYSSB7yXADDyLhpZHk+/MzT+G9Emi
         KC/5YjNwzbQtBwqbYRO4KLKa1Dkg22qQb/vsFyNn/HijWLurRHtLZBFvfeuETkG3Jb4j
         5+Fw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Clve4RHO;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758647386; x=1759252186; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Fz6rBAyWMonj7uzMLxoxvyQlaix02FGzBpegpIiBuUI=;
        b=ALsPG5/PiL/E0q9Nf+3s2uxZeZoIbwhHUXMV1KzgsYNPqI45tFeuYF8QmlfoU3U3g1
         nYEDqmrByquQ4gZ1EsfUZqJQz1qaWsDIXtO6V+eUCa/jtca/hSbBdQYIOv6JGbz7ubTZ
         b7/owjOiHeOEgFpCPITwh5iyMUGa3G6TwQsksisGZYsDeOTiORTPIUONTFECuOdzlaUI
         ZwCeR8cfPco44SEILsBlTDIUernTTjrsHTNTNuY/uELt3U8ikHUOJbmYUYzCc1/ChcCS
         Kd3Auu3+jVLMy9xlyNImR5CUayo0cgn+EZXxexb6L62RTRxqJOHSE4DwMWlcn30CNbHJ
         1eSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758647386; x=1759252186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fz6rBAyWMonj7uzMLxoxvyQlaix02FGzBpegpIiBuUI=;
        b=gRrz2vRPLaCQ6X+Bz3KoeDEIDTx4DGe9I9SdekP+DglL8TMixgsrLXtbLtOhVCda/c
         WQFzoWbZkHTwsU7bL4rgrz3m67AL0ij4enn/a4fHNBvGvX5U2YpbFOVUp/f0653/GZVc
         LwQbeBxzEjTVyGnhG/DKos03CA3vWYumak8v8iuL6nat19VwuW5FGlMNPsB4Jrc1hAKF
         REGlqVReyZNygr++OsKKs1F9n7YqcQf6Zr6BsZ5DITfUT3iiyxqyo0Tgk12OOmmdFOdQ
         9x7xiC3uL7w5Zbo0dNYqSHnwkWatYJtyN3zanB7LyV1axufcfT6BIcNsvdAqWwxXfy0p
         cu2A==
X-Forwarded-Encrypted: i=3; AJvYcCUhKB9CXz5t+A3+8DSfAlOscUUn7UlmKeCDIuzj4quYAuMkXj1jInr9Bv8plIjLDPBcDyupdw==@lfdr.de
X-Gm-Message-State: AOJu0YwCof2YRb2EaUbzw6FPeeXJ+QzFpB+MGSzNLjAEDqftQwShiiVM
	LQMXEsrlWJca+YNXFynQGYWz+iNyiGmsbSyyhBxlzWtLiBDcEAxS267i
X-Google-Smtp-Source: AGHT+IHtSPtMJ63GsIOi3UorgJfUj30M/ytsftL0uG50qg3+0W0yfjbgqVaUKhSUbAi6lUIr8jmZ/Q==
X-Received: by 2002:a53:c611:0:b0:633:961a:bd46 with SMTP id 956f58d0204a3-6360463d1b7mr2239950d50.25.1758647386279;
        Tue, 23 Sep 2025 10:09:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4aZkts/Pr6lVuc9xUmPjjWgwabbrup6IaSnLP53CiYHw==
Received: by 2002:a25:d60f:0:b0:e96:f5a8:6a70 with SMTP id 3f1490d57ef6-ea5d11bc337ls4249393276.2.-pod-prod-01-us;
 Tue, 23 Sep 2025 10:09:45 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV07lroCc4c/p3XyrgOA3L9QVY/3lXU/qbQ7idDjPQXKO76bOmlb7L26YkfZb4M1VZoOUDY/FoatM4=@googlegroups.com
X-Received: by 2002:a05:6902:33ca:b0:e97:598:fa39 with SMTP id 3f1490d57ef6-eb32e72e6eamr2581095276.16.1758647385243;
        Tue, 23 Sep 2025 10:09:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758647385; cv=pass;
        d=google.com; s=arc-20240605;
        b=JUa+cg7jgPLrl7J5GyS19TQimKJ+bnwBx+QF5Mv9jvKw3w+XSLw6uc9JNlT87AvxWi
         LBBdk1vvQOqy5K+UYs5xY+an/pJ8GRtAymAk6EITII87zG6HtOfDBydPgcBD/NNGc2Yl
         4hkPGUhfXkAxP/utY6lbJ/6v73wGRd6YxtHEcJZKSXs0v2FA4MbF3+n812xRcOP8JHZj
         A56dPG/o+KwTUo9YS4F9vqs65OLG0Kx3n4CdmBT1OG9nD+Pvlf68iAfXvsBdy8xcxPCi
         PPETKYqw7gWaWYfQ5vx4Xz4tcw7xh6czdiWM/17skVmLUhfUspxuHyr0Q3sf7UbfRWGR
         SKSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zfBJt5ORyJeWyTmriSi9rxIRbYwbq9D6z6afL/pAXS8=;
        fh=rDAxN/Iy2nxK9hcQ8li78U2u7XWjrcYsRqVBWjO8IzE=;
        b=iEJl68ZBu1dQERY3vKQsCETObwBekesdyfGGhev5kBDseuWFnfN/KBldUdPs/gljq+
         H9mJfYa4mC/lb5dzv58jWR+ML7btZgAnzkAPrsXRJTG4CVojYXD/RwROVoHalDdPydpY
         EdypHelia7Kmp/0l53DmUjE9kPLCB6THJGQfmxg/IZWuHtivAmns+2U23/LD55081cli
         O4de0GYy9fivgJ69ZXRdpbkt5PBt1Eg7Q85c2CVI0GgkX2uCeEq04W1r2qIqDscss73N
         Q6oxnGzn3+CLYXRdE08bhWxbCoG4XiY8c1p61qURbLSZhUozwktDLcgu+WPB5np+gMHa
         Cn8A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=Clve4RHO;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CY7PR03CU001.outbound.protection.outlook.com (mail-westcentralusazlp170100005.outbound.protection.outlook.com. [2a01:111:f403:c112::5])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-ea5ce7250b6si721295276.1.2025.09.23.10.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Sep 2025 10:09:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::5 as permitted sender) client-ip=2a01:111:f403:c112::5;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=oWXggwVgG5+rl5z3SotJHQW1m4VjyXkt4rjniHHR2g+2Y3BHmjdoAqeVdP8k6mFe4IPb7kV+kge+ua1wSDvFL/quwLj4xhgtg8qlTIIUhCND6ACY1ARSrSYQ1pBHaSOpuwWRUe4OCI33oN+aektYyfNGfWTTlHi5lIwPl+an8UXKbN+hNUXK9Al/EyVpsysGtHD3vdUrEgNt1EMA7AVtqQwfJvPDoxL69kJrBOAbNaM3P//k0fFCX16uKv5cS6gw5sNS6VeWBk1hZgy5h50/yWGLyF4jP1+0rbw5DoPWdZbzD2HEXux/VkFJmyXHmptrQF3nI2FE+1vg30x+4Ui66g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=zfBJt5ORyJeWyTmriSi9rxIRbYwbq9D6z6afL/pAXS8=;
 b=c4pMUCw0BfP/FSxTb+iJvOpFnhv2VZ5tk4N0rFUs3VE5JxKA+/LCYfsgEscOPhkcBmn8mnqWcvQBR8ozQh3kBNvhm/k8t/iXX0N3X3MAB7NL+3A7G+2SRwEnBiw9tNhNJ++RJMXlSFhasUB3UKspQrLRpqDBn809urbmvdRpCe8BQtw+rAQ3B6qSQMHUcXgjB97FDu8Z8M/QGUR/kkKu8BrcsyDg+z1FjySil2bvtHYp5VbPFYh3DrMT5KLkFnOVJE3g2Z9jrRPkrKYpnxDMu5ap+AsWNINW9UHaB4ftMQ/b789+skrb0bomTQOX2Z14ErVFPJGj3bG6xxi2XV3jKQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CY8PR12MB7097.namprd12.prod.outlook.com (2603:10b6:930:51::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.14; Tue, 23 Sep
 2025 17:09:39 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9137.018; Tue, 23 Sep 2025
 17:09:39 +0000
Date: Tue, 23 Sep 2025 14:09:36 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Keith Busch <kbusch@kernel.org>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>, iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>, kasan-dev@googlegroups.com,
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
Subject: Re: [PATCH v6 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250923170936.GA2614310@nvidia.com>
References: <CGME20250909132821eucas1p1051ce9e0270ddbf520e105c913fa8db6@eucas1p1.samsung.com>
 <cover.1757423202.git.leonro@nvidia.com>
 <0db9bce5-40df-4cf5-85ab-f032c67d5c71@samsung.com>
 <20250912090327.GU341237@unreal>
 <aM1_9cS_LGl4GFC5@kbusch-mbp>
 <20250920155352.GH10800@unreal>
 <aM9LH6WSeOPGeleY@kbusch-mbp>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aM9LH6WSeOPGeleY@kbusch-mbp>
X-ClientProxiedBy: BL0PR0102CA0062.prod.exchangelabs.com
 (2603:10b6:208:25::39) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CY8PR12MB7097:EE_
X-MS-Office365-Filtering-Correlation-Id: bc204952-1979-427d-43f4-08ddfac3faa1
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?SJmAD6P8WrWWuHZOaif2sELSogZjML3CSOMNpyLWiBOtInZlQ+z3+HEwPek+?=
 =?us-ascii?Q?xMrD+nXnpvB6+wyNA1MiGP7PUnMUXGOAo3Uji+JoeKTFjjpa2Wi8Tbdyy306?=
 =?us-ascii?Q?lwMaY9apU4XbSh6ZMNDCYILAWKLg9xO1o0WaQX8X0t8PvWqGVI05dXYUfaJS?=
 =?us-ascii?Q?dP23xF90g3yxrMg3E0ZweazGKCUtcpUk0BvZseMZ9Mn3ZEYPDC6SUqNTPyT5?=
 =?us-ascii?Q?h9T0/JdzXqp5RVHFb0bCnTeE1SrhMbi0i6Rwq9D+7fSAiRtjgDGvD08j6Dh4?=
 =?us-ascii?Q?9zDSElycQTqtC+SxuEXwPTeBP5j6mXPlytrpc/8I54CGMdxY0OT/iG0EKH+k?=
 =?us-ascii?Q?fKXK1lmN2YB3l8NfwJKB3i6Bz1OJ+8wsnPpvf5DTWI6QOizZNh1dlKcg9Ons?=
 =?us-ascii?Q?TwWJMjyGVaKnEc2KUnRHPRc9MXBxGdU2tpcoHFFMsv9ME5toHcHyY+5fBPyE?=
 =?us-ascii?Q?3Lb1wA0tfhFmNLq9dByW3S/Z+OHToqipzWlBOL6llXnYqFA+YekgTSmj5THl?=
 =?us-ascii?Q?IUevUbBBCkjpZQxFLPv0NEJI2jBOhEfviO8nRNoLyQPmgl2v4GXdiHmnd5B0?=
 =?us-ascii?Q?qgOqPkxSpeWRVpwdlX+vRBOY8V8aTOnh+PZoebudEvEnynv7uqK6MA0Pr1F4?=
 =?us-ascii?Q?+TlSLo1HaMFQ+fiKgoBluBBPW4Er7lSbish+pOk2mGuC9aJf+Flh7VdsNF6A?=
 =?us-ascii?Q?UBkhE3SDC/eCbRcZtuyp5GvG8SnptVS3yn2DsSwwLQpvFtNh5A2kh4ZNKih5?=
 =?us-ascii?Q?QE5ni5X10wtQk9Lj7T3AchwuQtLJwd4rBA7qvGl2P71YUZWb2LPuBW0/72Ko?=
 =?us-ascii?Q?HO0ZQDsdrG8umM0sZrIhMKAFizButughBB28ZD1cnb+YnbeglqerRHRo9O8o?=
 =?us-ascii?Q?1tTH5/UldaE30aM/XBB3HqZ6cRzzPdXjNJQwa2kWysbdYBzArHi4lJOq6uT+?=
 =?us-ascii?Q?mZxfrv0YS27avYVToN6qcOyuSpCKxEBWrDJacnMkhhw+w06PXPIWOVgcLgod?=
 =?us-ascii?Q?pRGBSZmi4gYf6GWVOypTrxrQ0KtcbuO8KCcCkSjevTbrbQp5gUbkFJW/lEoY?=
 =?us-ascii?Q?zELONf86F3MT5VsZE9116D1a+e6lzmJCL9whVQqkV5sdp1irFJ+ropB9qI/k?=
 =?us-ascii?Q?gGCmG061yMAzLvZxz6tc7q3/3RWpV+zHLlQxPe1v04t0wauH76R68fyv9HNn?=
 =?us-ascii?Q?zn9NF6ZRGRZ5r/qNo2Uw/19OKlKFBpbeXLMMvKu5NQTSsADFKP7IT7jD76xH?=
 =?us-ascii?Q?mn/fba6qnsgXbTXfsL0KdhGksYcRoJxVvi8p2TUhJ41p79ubs5tNZJcXm0IY?=
 =?us-ascii?Q?Nd/QX/TgbDELc27Fsek28z6L76ISG+5VrCn+LPiDjw7PEuA4X6IpJ76tIYcL?=
 =?us-ascii?Q?6ccVwWP77+YQSyB29uu+HetpBBRd/bjPUMECjnJO/TWb3cSYEl3+bHX392Dy?=
 =?us-ascii?Q?2VgYRkJLZZo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?9brSa+bdlvi/6eftqG0wEDppljbQgJEznYpb1kQH86dDICWbUMxtWiwK0/X7?=
 =?us-ascii?Q?4rEWjqAc1kRsokCGBoz/oQbnANRsFgz673fviV3zWc3btFSRfD9I/XSh4cqp?=
 =?us-ascii?Q?Q+Q+8h58Gm0cfSghyhxjy0uUK1l4e4fzZLwD04xX2uZPZxg3rHzASRTDh+us?=
 =?us-ascii?Q?qgCFEDJR1PuMoPABTM36UOjJ6ub0/RXqf1Q10EItpXz66f9Eqppjjk/LCCMf?=
 =?us-ascii?Q?49LiQkJ7Jeo39RkV8AIR7CtfJoLZrdV3MdmykRQ57YzURLJzvykAbUMGKRFx?=
 =?us-ascii?Q?OQFm3ar9RMXa+/T8WxRzXgwMvRW/YW7wivCv74tpewW3AhCRCEu+wj3SOSB+?=
 =?us-ascii?Q?4RlQ9MjNbsW7Jl9giTy6DXl4x6Fu9qIX6oRShn8Uilv+pRN/ry8KE3UcA+Wn?=
 =?us-ascii?Q?ULvpHSCX1TyG+D3TBfE5QuTqlCG3isyhf2JNFtZpdroPhK0r/PANzfcv3BWG?=
 =?us-ascii?Q?5+EH4FUjAbQPDabCUvlrG6EzUYfox05xMC6bLMoreyRPS7Ojy2mp1v2pIg7j?=
 =?us-ascii?Q?7c1YIEg/truGG6QwtrwM4sI/9Vf+vz4UxPJNkExIvW4XDBa07XUdpPIfdPwD?=
 =?us-ascii?Q?wx9RpRN+d13xiSLdQIFkuqZII6bHusCMmTb9E4narF0h5L/oEgpOqxsBcHBg?=
 =?us-ascii?Q?ewdVKMLIBuo4fNrUkHkFKGzyKxveEUg9bW8w2PUI6njWI+DQIkg5J+YF38uK?=
 =?us-ascii?Q?Ew1CW/yzGdWCvjC7hpcT8Ks7ALN72NOBDVhNCOMPtfuQ00fdyYU/ImkkcDCa?=
 =?us-ascii?Q?OgXhBxMQtCnHPN/94sn7nXKb42TanX5SvZSuubFyUn9YK/MPNCkdbSd2cvPd?=
 =?us-ascii?Q?O+eiBurynvlcVjvyQvC6tIMszTe9kXiIDrHL6h2TvytWCOgZyCSBQYmy8HjZ?=
 =?us-ascii?Q?AJE8h0BeCiD4GxdgQU0B9kVCJ7SRRuaVeWcG/byzaTRliSgzwspmNszSU7vI?=
 =?us-ascii?Q?w1zJZCrHgFDVq5KyG3ask7NK2W0l6gI+hQBLGORGHW4LJCSId4OVNZlD53px?=
 =?us-ascii?Q?qw+5w0iybqAX5cb/BcIO3BvJd+6Dvl9TTQXENrWmNE4hrPzOz3r/cCf6XjLK?=
 =?us-ascii?Q?MOa7ZLp/kRBF0xUqB0hEEAt7uVdrDwUHTBraQMBLZdDZS6Yh5Wmnam1J2ZZu?=
 =?us-ascii?Q?gL5lGS0Sa8F7GW+ZQWERfs/8h3BinfAAwALQr+XognophwGG/PoHnulu55wn?=
 =?us-ascii?Q?N6N61LxtGOTnozw9ccWDX9sp7X/5ZZUgMTNqDe5HPkkzf8E+TRIWQaSqsUMZ?=
 =?us-ascii?Q?h7hVC2StbNxHjI6L/97Q4lxxwCOl59nYpHes7gqUxhZIKkFj1NJ/QML71bGJ?=
 =?us-ascii?Q?SRBra1y1gGCD6HM4rDZdFiWixSvuP/Zl8olGEJUgiYR0LZo7l2+3qJ0DENnC?=
 =?us-ascii?Q?5qugSmfjHJFJVySpdCgDiGx7H/u147UlCRCnLlNsX1sBgdSO5fMLmg1bj1M1?=
 =?us-ascii?Q?8KkyHbCIbZvB+TBvJjr+HZZoL9DomFAIc8tlOZAIx2zdP7zX2hvfN/h9EOpe?=
 =?us-ascii?Q?dRp/8lGy1sAFgNZzIblQrUHChTBvYY7FFJUihHYLu0AQAC7CntY0Dde2YTGz?=
 =?us-ascii?Q?SOVUD2AqRajEjF69PyqwB/dZIVBwUeZ/PoDq/A15?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bc204952-1979-427d-43f4-08ddfac3faa1
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 23 Sep 2025 17:09:39.1137
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ceigpDcxetN7qTmDdR6xf/u6VfAhbxjc3VgXcalLxLEkjfvE0x+7MsjxHGl5BBWd
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR12MB7097
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=Clve4RHO;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c112::5 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Sat, Sep 20, 2025 at 06:47:27PM -0600, Keith Busch wrote:
> On Sat, Sep 20, 2025 at 06:53:52PM +0300, Leon Romanovsky wrote:
> > On Fri, Sep 19, 2025 at 10:08:21AM -0600, Keith Busch wrote:
> > > On Fri, Sep 12, 2025 at 12:03:27PM +0300, Leon Romanovsky wrote:
> > > > On Fri, Sep 12, 2025 at 12:25:38AM +0200, Marek Szyprowski wrote:
> > > > > >
> > > > > > This series does the core code and modern flows. A followup series
> > > > > > will give the same treatment to the legacy dma_ops implementation.
> > > > > 
> > > > > Applied patches 1-13 into dma-mapping-for-next branch. Let's check if it 
> > > > > works fine in linux-next.
> > > > 
> > > > Thanks a lot.
> > > 
> > > Just fyi, when dma debug is enabled, we're seeing this new warning
> > > below. I have not had a chance to look into it yet, so I'm just
> > > reporting the observation.
> > 
> > Did you apply all patches or only Marek's branch?
> > I don't get this warning when I run my NVMe tests on current dmabuf-vfio branch.
> 
> This was the snapshot of linux-next from the 20250918 tag. It doesn't
> have the full patchset applied.
> 
> One other thing to note, this was runing on arm64 platform using smmu
> configured with 64k pages. If your iommu granule is 4k instead, we
> wouldn't use the blk_dma_map_direct path.

I spent some time looking to see if I could guess what this is and
came up empty. It seems most likely we are leaking a dma mapping
tracking somehow? The DMA API side is pretty simple here though..

Not sure the 64k/4k itself is a cause, but triggering the non-iova
flow is probably the issue.

Can you check the output of this debugfs:

/*
 * Dump mappings entries on user space via debugfs
 */
static int dump_show(struct seq_file *seq, void *v)

? If the system is idle and it has lots of entries that is probably
confirmation of the theory.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923170936.GA2614310%40nvidia.com.
