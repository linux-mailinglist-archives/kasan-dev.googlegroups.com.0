Return-Path: <kasan-dev+bncBCN77QHK3UIBBYVF67CAMGQEIYAB6CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3754FB2651C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 14:13:42 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-32326e6c74esf948285a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 05:13:42 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755173602; cv=pass;
        d=google.com; s=arc-20240605;
        b=JJkhEOXOl3gnxkgFENbuXIeAH/1oDBV85skFju0nV2xX9hEjrmlsogKKcbTKohJXZn
         pmkV6olwzk0KkKk9tck0qP2V1TCpfSfLa+fdJcb3CXfEhKrk0+F19JsTL+OmaTd5E6ja
         qCh2kIJ/ZiHE6469wW0rGA6OGvj437dxqegRa3XwDhRDWuDew9hRXPJQnPvOM4fPFgfb
         HoOFI8LzvDePtT5e8ACRhJ23GjK/0P6XbJSqiOgjsafqoatS84RlDxIjYZA1qFxzEC44
         s2RQQjg+Y69rHZmtXwnJXgwpXpklQq1SZ1qes6oLwyqji+wjzHQcViRWWqHDaoZDPjfB
         t8mw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=uWigO7eiZS+cHcu1sw5/utayQmxfP74+SqAXTwujv6c=;
        fh=+vybM3MOBuoJ/NBmMLfF+g9Tf4U9Y5LOmVs//gpsXvA=;
        b=k1UrP35pj60AUAM0yarIz+OZKT3NzFmy50Vidh9EGjLeOh1fmY2ZjP0Oe5nmDA32yJ
         yvEHhyiEU38cbC9gtTH6EYV9U81fEzzDFcw+j0ksOKgxurVu5NvdlJE35h7N/J6UOJhu
         UQYZfSIsis7gPFZ4COEIEkPpR3n3NVrL1vGhAgO1ezKCpHM/ybcKQrZ+LUK1bxljVXMf
         gpJFQjx1flHiczeuJu35qoE0tFsyANrs5kz1xyhovNcDTSQ6z/D8sqKu/txNxfdlZnqb
         SwyniDlSlnVxafJwu42b/5y4lUSgLJklOdJgK7fvdFF8MFcvZC/o0amtCYGK9MGgAkSA
         FL8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=aalz1iI3;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755173602; x=1755778402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=uWigO7eiZS+cHcu1sw5/utayQmxfP74+SqAXTwujv6c=;
        b=GJtfaK58rauqw4p2YAH7aJhL/5UODycgcFGlLCPbWGIp8FcK+4pRa7US8otpicaGRA
         glCbIYZuUY9j9HlDp2xk0LRwBQw5lQr9wU51ca48X97+D2SxKCncbFUedDDGuR6ZVShH
         en38kf2+Msj2eZYe03W76B7g28eosZPjfiSb0zNEkUisjUaJ9s/PfTRLTd+IOB0iqGBn
         rAcMj+KIm6+ojec4ACx8X0vBXIuZyW0DE1qhLnTECPF9V4jxWiC5Mrv6WpNryt7IJsCK
         KFX4uOMhZcnxM3gTVy6ctGAvuVww2wqaxYsIVZbeCEp96c2lkBnYnhx5cZUlKtNNzYpZ
         2Fng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755173602; x=1755778402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uWigO7eiZS+cHcu1sw5/utayQmxfP74+SqAXTwujv6c=;
        b=XdPLWVti6UBN24Mg7mp13IsjqJdxvd4nP/z+e8D+SC5tm5kaDZq/IcIRT2tMfp3vCp
         AAFXZH65XQ8zC0x4m/2biDt72F6YoTramcNnsButVsK78LhF4K57+wh0ahC8l7FjkDdJ
         svCtB3RY2ok1akRqmn8FbGQ7vqnryYtEdLPng+6lJFbs/2pVGZfVB2zqJ9me5Lq9DnOQ
         o97sU7LxybrG39H16sNU17jKXDUD+15l3hA7T5j3J9DPydALi+sa5tByB/9smWCg7vwz
         liAcaXnqpQQl88D8f+/1hJGplWXdFiPxbDFvLVbuARBLO/ngxkuiCUqDIOt0Dh2lEPC8
         u0YQ==
X-Forwarded-Encrypted: i=3; AJvYcCUl7+YhamzvtTBYyYqcWmUZPCa3y+QKdFKnblS65HbP1KlBVHaJF7uuSzGvtBabkpElyTaXtw==@lfdr.de
X-Gm-Message-State: AOJu0YwGCuTqg29RDNrblMsVEPK6mZUjGrqAyQCNn0yCZl+fbnxdwt4z
	+RbKeCSZCoDRvScs2+h+ah/fT/Q5UCVBo8Ko6akkLYFo1fd4yk+ZWdQS
X-Google-Smtp-Source: AGHT+IGzXHJztcm55qLWf83KKEIeSLCvf6tAcxXOv8HDciyKn8Mh/zdRWBbwbcSQoiobavs4bXbv7Q==
X-Received: by 2002:a17:90b:3d46:b0:312:959:dc4f with SMTP id 98e67ed59e1d1-323279996a5mr3948324a91.5.1755173602338;
        Thu, 14 Aug 2025 05:13:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe/iZ3QNNzeT6sQAFSZpcW9YSW4NqOGvWaRfBujB+pFRQ==
Received: by 2002:a17:90b:4b51:b0:30e:8102:9f57 with SMTP id
 98e67ed59e1d1-32326dff6fbls1142459a91.2.-pod-prod-04-us; Thu, 14 Aug 2025
 05:13:21 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWJJY2PCEerZz1SS5VivI7P/z9XuF+70gBIkpVlhEj6LsT6WSYrmEJg1taJTcMtHAIz8hJZ66Be/xM=@googlegroups.com
X-Received: by 2002:a17:902:ef0f:b0:243:ead:f694 with SMTP id d9443c01a7336-244584e456amr47483245ad.17.1755173600991;
        Thu, 14 Aug 2025 05:13:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755173600; cv=pass;
        d=google.com; s=arc-20240605;
        b=LNQD3T7fYCwKuHO9yViX+CCgEV9o9CEmVwTxfIZqBFc0zaUSExrDyAZKxxog6KJkuR
         REnARrRQKrO94kIqeLWy/Jh8u3P2smwQASRBtQtcN6nhG/dAZBpdluw9Qgs6jfFU5Vwn
         RgWCnw6zEJcPexuVbTIw+QWCdt3WvCyFyCJIWl7imWz/pTt8xtJn7zqKa08a3qKK+U7K
         7A7bBSHvEjz3+myDs17B+YPrSJWFU+4uUIzwNn+SXb0qUe22Poww6YXIYqScZT0Fo5ZR
         NGvRZHdC1TBJEBhVp2fihjLqQ/zL+wmSiJjyu3EDs8TrP5bL4sjBFuiZkTiQkskazICO
         Tc2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=FlwP94jh94JMwUUIxviGkpnalg6FRzIqI7Hx8eS43Sc=;
        fh=7UGQiPUstHBdMrT+/gotlrsKf2dFOYLPDzCPmdRVN7g=;
        b=dyr4I+6QNqEIhtC+oLoyh47LRfaPQqKEVgaw9jU3UJVxuLprsSHS61m76k/4Xrz5sK
         1EEzlZ4PYI7AMu+pecr9maARrZut1/SFzz6NSo61VvgXz2bBjpvM8bpCB6TIUpQ15K3Z
         ss6CIDf4UrGEBzcWjfPigutmGfHo7pygAAVMn2dfWa828SwR1NrA08ImdLEfnfSFuSxg
         2ZQ9FK2sTMxGUtgbWg7ooSr8RaHO5Ug9JR6ElDBtjYJFaF3JsWnA6DMS5BcWZWCvDkfT
         sJ47bVQOaLxXf7Yi/ruhOVpsSfFZ4ynHiAF22uyUQLPLlqTGdD0U5ZDTBlyx8l7SqK8U
         t3Rg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=aalz1iI3;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on20620.outbound.protection.outlook.com. [2a01:111:f403:2415::620])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241d1fb2627si16131585ad.5.2025.08.14.05.13.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 05:13:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::620 as permitted sender) client-ip=2a01:111:f403:2415::620;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MAKEtyQy7PB+A1PDOHUokV1jcIj9UfR7JconjD+A5MEjcxtLJBHt7s1JSxpYDJeFKoc5sWJx4wW1shd8ql7I3qTJZcwz3MctE3NEmzWRsFPG2VFGU/MQiHZt9mUOme+EpBzAUiW7zaIwY7YDkZFaExex9NoCDX/m0nLiwm9zNYLNU+BODSee0P9uELiE5PwlEQD/soOAHFhzYATz9xTjESL8svTEPoeC5DuOPX9bYqvMZYb+OoAzG2VHKWVdhyXsEgDV8Z0Qqufg32ZOxkdb/2HBXee0yJDeGv8czLQhiGocnSgLjZMoNm5lsrsvq1x6bKm0ie3aRRgobp4BmlVDUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=FlwP94jh94JMwUUIxviGkpnalg6FRzIqI7Hx8eS43Sc=;
 b=Oehq8j6FUcLM94fx6qjmCt32BwKlHbdp/R9Cjr714mCkxOFOAYezhgWw1Q2FVMVZ+JJ+HscSy5OhEI9vRAX2dtazgHx9KZFCmNPWygY8/961iJnx72iSUzP9z2AsCmsP0EX45wdQQRSDK8GBHO8J0HPRZSQvFJDxcY1xhR4+lPA5RcU8lu4gZHELDVT83ywGL7TzCV6dQnstmMO8/YPO3zYwfbdRtxahESmvjE7aOVFxrBgBa9NEPVPGcxpWyn3kALOf0OHCjLn10VDCdiinbzoWPhbmUTis1/9qljuRUIvOr8AD6e38KHG0cNPjTmI0kkz68wZyAXg5ueZiOs/CAQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by DS2PR12MB9637.namprd12.prod.outlook.com (2603:10b6:8:27b::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.15; Thu, 14 Aug
 2025 12:13:18 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9031.012; Thu, 14 Aug 2025
 12:13:18 +0000
Date: Thu, 14 Aug 2025 09:13:16 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
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
Subject: Re: [PATCH v1 08/16] kmsan: convert kmsan_handle_dma to use physical
 addresses
Message-ID: <20250814121316.GC699432@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
 <20250807122115.GH184255@nvidia.com>
 <20250813150718.GB310013@unreal>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250813150718.GB310013@unreal>
X-ClientProxiedBy: YT4PR01CA0328.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10a::18) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|DS2PR12MB9637:EE_
X-MS-Office365-Filtering-Correlation-Id: 279f1ed8-ca25-4aa5-3a88-08dddb2bf3e9
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Zfap5jlwHnvm4haUSb1I1u4N0AYZZ2KLHtDBCoIrE4Gi2C9ESB1fzLeClr8g?=
 =?us-ascii?Q?Po0B5nsl30HuAPa7u5AiQbwsghkebjwNH8mOhHR0bD4z54R42Dzx8MEcayL2?=
 =?us-ascii?Q?Ny0Fuzk+NA/QVp+GCNfuQM6yO7dmKlD+x509Tbm/U92QcimKEgduCBtoUCh2?=
 =?us-ascii?Q?qx58uTeOTNBo1wPcG9lhUnBpqF0xpkNheC8VuAQIqjEMwNqpiySBlhGr4flj?=
 =?us-ascii?Q?7XIZQ46DaGxrfWz4CMgv7DAIOeAGrvvX9NZzZXVPpPRrnGs7Db14yMfMqZE7?=
 =?us-ascii?Q?T69Rx6ny10FmsbRYBGO2aaa8IvokaM7v1Zjske36whStXuywywpEB9Czq+7s?=
 =?us-ascii?Q?FttnsFxOcFYbuDA6WZFYhl2g/vclMnkQ63sDFB+2WLXWT9rOheuT/GI4x271?=
 =?us-ascii?Q?z0eSBD/9lZoIxBeMLj7pfSmrU3fsm+O0E08mNAfLpKMJv+3gSTjUTiFQyhTk?=
 =?us-ascii?Q?W+oiLlIQclE3NlxPNspv4F88wcuqhdRLm4tcRjRM9pFT56tKMMI3HV832X5s?=
 =?us-ascii?Q?Y62rNuRSEpZwLr8Fpxg/JuT3vt6fo5tvy7LDuFIpkNwEq+JfgXJCgNjq514n?=
 =?us-ascii?Q?pScnXQjJaLr9jV8lGDySR3Jh/yKwl+mTeHqQForkE52YdyLpIGFGz/VX7kFL?=
 =?us-ascii?Q?V21qqQX9+VeHR0basX4y5i84UeUgTC+LxOSHB6WLHRwXEUQub0N9a0uJLRjG?=
 =?us-ascii?Q?cti3fA1ySfhsSXuDRJrIfRATiiOzVtpc16n8espmFLRtnFKL5vGG7zIhzaQu?=
 =?us-ascii?Q?CzhIvbDMD8AzsmdSPeg0orsDr7NfL1q2jwdBsVZfn37vV4F7AywW7+Mx8Rjx?=
 =?us-ascii?Q?BQjFlFeq9TPp4qQR2XorfJ75ZzhAHpLZqmHawCuyfZlLwWX75Kj70SYl/u2p?=
 =?us-ascii?Q?0ldem62ZgcWwo3zLIkmQ7KhHxBOYkKRse1co2TrSvO9FH6p4jnpnedZXLUz0?=
 =?us-ascii?Q?IUaA/2CEX9/vZ3g+BqTpPANqKOqvsmsRHbmUcuNJXZ5+Scu4GhZzukho+YTX?=
 =?us-ascii?Q?5vpxynA+1/KbrrgWTrcibewjEbWqlg+gMbREVojMfishVHlo7REm6+aMHO7C?=
 =?us-ascii?Q?CorP5S+BwtK0kiI3YAAjNaTnLfH4WF0utrdFEgG2fsbKZsRuXvcGU+o/adTe?=
 =?us-ascii?Q?eIh+75cMgL2EJG5TroOvL7+AM+biLp2JqQBhKXXfQcKXOGkVc6137VU+U39X?=
 =?us-ascii?Q?xAy6IYzi0mWr2A4PPoRvC4+VGkbh26GP+0aXTknZGjlPythxxj2yNxy575R0?=
 =?us-ascii?Q?GIss8Cu2ZR7TZpJCDh6yfzFzT30Q+U3KAS+JjVc05wfkZ6dg7aPNON/nCTyt?=
 =?us-ascii?Q?QkEvvW8E9SMgrr7irEyuWMtIaP0HkP4vYKVS26P/evOAtCxllRL/Eo2b5fZr?=
 =?us-ascii?Q?7Vw3Uo23TQWiw4aCeHMHakcJEPlF98oVO1bTl2Lf9oMooLCfjnxs7ZfMgIfG?=
 =?us-ascii?Q?A7Bq3mIdDFo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?BJ6T8GYc9fCjO8k3crpC+I79EjWVbBmkej3GbVh6YO6TbL0OqbQrSUJOiqtz?=
 =?us-ascii?Q?kuwDzaSS2iAjqPqT6/xMXY1GxeKEE+SGRLExKwcm7U2RpRXbwjVkB1JjOP0g?=
 =?us-ascii?Q?mwWo5OeALd6PWDJWzSiQKXtSY8zE/OcNfUUnT4g7Tsc5BXPMNDe4J06Quxmx?=
 =?us-ascii?Q?CvSmEhksCQk7d6KmXts2cfzzQh402x6dxkETCWcjMUl2Mrh21HAPUUDD5YRp?=
 =?us-ascii?Q?qNdcITj0HPgy5o95cYNcKbb0P8IBjnYyqDK02UpSFYw4igQkazOFIjwWzPs/?=
 =?us-ascii?Q?bC0/w4Pfp0gUELgmtawEEWFFsqoA5bK5bQifg6TZjJ6gYklEA5/LiBxw3aEn?=
 =?us-ascii?Q?zsgbeJ7LBzkZbMvg+/PaPupYNbEX2F922ePnw/s5eK7nmSXcm3dEtPXwieNj?=
 =?us-ascii?Q?fDMufX0aQbP9pnCwDJAKC+lBu2f/7FKhL/4LdxvxXBD+sUbRB0kEGN4RORsV?=
 =?us-ascii?Q?ChFyMl1znz+uZFWGpIQCwueEKFNKgLpy57H1INxbwVNw+jeWPSQiLvgVF9Uk?=
 =?us-ascii?Q?wh0O35bGr5HSDXXniiEIalB4SJv6pSr50admQOytjtJkpE+aWjs0MLfCNtio?=
 =?us-ascii?Q?KzTfHpWNpfXUCby2U9ZHN3D8JO1ztQwuR3X0+F0wwVp/d3QR1HX98mzKC98F?=
 =?us-ascii?Q?5JXpLim3n1FxPtlLM0/OQik1kqw9VUwDv2K+cbYBSvCgR96AKS3Wmbg3kTMJ?=
 =?us-ascii?Q?vEEhBJG1++MWhrj9P0SKJy0tNoxyHxzeVqSfTjdJ1l/bpbRZ5LhUY3p5PiK4?=
 =?us-ascii?Q?SjDwyBPHNr90u102+omowP7/nR2roCWOMqZta8pQfMqlluHQXPYn5TEeUlwk?=
 =?us-ascii?Q?ob00tBMKS5K5RIAgrR6ZeSyjSYBx/fLM+dnXhWHHrTKufif2JK5igttmCB+W?=
 =?us-ascii?Q?bkjOTEFA1LYnVPRomGTsP0VWx5nte49f1bHfctZc/4BYtFxYt+xFdce1IxKJ?=
 =?us-ascii?Q?gnIzFmcFLaFBkTQI7TcKoFh2WeFu3/xccHO/AJkgHN/rmjboLrjYHTDhGCYe?=
 =?us-ascii?Q?JpmxzpBSj9u8iR8/W/qEN7+McztTUM7DWt4dG3PErl/RDeEJM2guMS+CNz3Y?=
 =?us-ascii?Q?9iOxztCm/JEDfnkOUgO3bd7kJDZ5Lg2uXLgx2+OAXxrHUr5E4ragJJ8pa+Qp?=
 =?us-ascii?Q?lij2fAU2z35Dr0CjLYjHpWEx01aBPHc2CM1XxRU1jWNsEX1eIqsnb34FbQLZ?=
 =?us-ascii?Q?AF1O0CDtpRMJ16FJ6/p4hCc+pBu1ibtufywPbc70bnWZnUbbtRIQYoh9H7Xl?=
 =?us-ascii?Q?em5I9GSdD4yP15MVzBpq2pJqpyIhPQSOQqzEx4oBy9S3A8CH9sV9n6a1qpbf?=
 =?us-ascii?Q?4EdeE/SjxzChdO+TtmJl4Be1ROtrLqIDaCzAmRFignpIe2N718tntI5gOcRh?=
 =?us-ascii?Q?HCAoFuKgut4tVLRD602YB7SHOvNR/mDVkd57XbT8IvAbsIooDrHuxUWHJbvF?=
 =?us-ascii?Q?WjQgfLKyVzl7BKQK34JZjT/sVLU3z8ZjICf1bMhDCNoHPKktQeBXlQScoyVm?=
 =?us-ascii?Q?8aJ3stlS4kxTOc4c9otFns4k1a4ow5ogbGKdMO7CEY05BtmN3UAGMqjMGDhR?=
 =?us-ascii?Q?bKpaIm2Lv4LRdtFqghA=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 279f1ed8-ca25-4aa5-3a88-08dddb2bf3e9
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 14 Aug 2025 12:13:18.0697
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: YIeclwU55ZGGwEG0nH+auFyY17BxFLO5LtNAZAlU2ZH6n+eMbun0/BrHAtl/v+8d
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS2PR12MB9637
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=aalz1iI3;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Aug 13, 2025 at 06:07:18PM +0300, Leon Romanovsky wrote:
> > >  /* Helper function to handle DMA data transfers. */
> > > -void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
> > > +void kmsan_handle_dma(phys_addr_t phys, size_t size,
> > >  		      enum dma_data_direction dir)
> > >  {
> > >  	u64 page_offset, to_go, addr;
> > > +	struct page *page;
> > > +	void *kaddr;
> > >  
> > > -	if (PageHighMem(page))
> > > +	if (!pfn_valid(PHYS_PFN(phys)))
> > >  		return;
> > 
> > Not needed, the caller must pass in a phys that is kmap
> > compatible. Maybe just leave a comment. FWIW today this is also not
> > checking for P2P or DEVICE non-kmap struct pages either, so it should
> > be fine without checks.
> 
> It is not true as we will call to kmsan_handle_dma() unconditionally in
> dma_map_phys(). The reason to it is that kmsan_handle_dma() is guarded
> with debug kconfig options and cost of pfn_valid() can be accommodated
> in that case. It gives more clean DMA code.

Then check attrs here, not pfn_valid.

> So let's keep this patch as is.

Still need to fix the remarks you clipped, do not check PageHighMem
just call kmap_local_pfn(). All thie PageHighMem stuff is new to this
patch and should not be here, it is the wrong way to use highmem.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250814121316.GC699432%40nvidia.com.
