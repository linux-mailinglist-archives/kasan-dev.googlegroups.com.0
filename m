Return-Path: <kasan-dev+bncBCN77QHK3UIBBS5Z3DCQMGQECCV4BJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id C0AFAB3F0F5
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 00:23:09 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id 5614622812f47-435de7c0722sf5336060b6e.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 15:23:09 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756765388; cv=pass;
        d=google.com; s=arc-20240605;
        b=TDOWltEQdRzupzMMsKrEDeKvv2WEOM0pjdZGRZalHbwvArw0K9LuS7U0we0HEpJzsq
         f+qcBXMcaW2h4BN4TuR0ReN/ksRMXUgfN55AnzqRCwAHJ5JS/j9sHtVFbYxyY0GylAT0
         7XoBPUviJIb09MF7aIkCoJpkYG5mG4ALF2XMN13saKzBq7uKwylY34Yey1dSjhOJC6Q3
         pKU/rIY//byclRczUHDsfHLBliJPYGEKj7uM3qBgegSgoeSySxuT21u792bplXnAJgAF
         x+0slp7Ct5XI8DAX3XHGGNYaF5wjp+r0fqRNPoSt03Xm7h8HmbPLtRUqjVNlZbP7Wk4G
         +CMg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KW25V+qflyynzAJeSslmfhmFQ8c63jMKe8tNtcJo0qA=;
        fh=PwWF1iszrAMpJcOG/BSLomaVh2H/9hX1mRHuBAeIYN0=;
        b=IC34P72poAjymK08swhgibxq46gc1hzHHBiMnr891O+DFa4+MkqwXsTWxlGeHtTPwy
         WHh5wujp4JJc6vGRk5qt/z8/HxEnYKDbkAJcSOkfx8+NbfNVVhHwG7Fylk4IEOXRovU4
         NOBcpZ4zmBheOQxixPh3fYZnlCrOLTAhKKsOF2F8oCJvrdoteup1L84itHq2ThwdANFb
         MQoJCZ591YJFQ9DshGGQ0f1Q7AxzxX2qXjoDGdYCvRyoYhPmnbtGY/HWAm+h4N4s3ATr
         xxMWWu7yPPxn45MxnIrbfBNGVYMTfrNHMhhkYNjdIyeNIBsKAc8s/DtMaUiK9VVUrLwi
         8WWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=iv80n33E;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756765388; x=1757370188; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=KW25V+qflyynzAJeSslmfhmFQ8c63jMKe8tNtcJo0qA=;
        b=Mf9mcr4i17QlBeWDkNSCBcfEueP46I9zyV+kVExJAZdoGDCzLhbN7iEhb4hRMzri5P
         ULgYGn5Jv0HZouO7e6cjqGP2/6p7XysgMC2f4qMgb5NEnKuz5VC4SDkjulMUoC4Wr2J3
         kNmeriDDGFDBVfg4ZmIi/7ZwclOoEa7ItKO8FBIIHI1GMP5oi85TrXaTMCDiRH5nOckg
         UfOeELlG9juBnOwCRxCiD+tOmFxmJyANFmx3tJgyoplIRV+8553bw2Z0S1Wg4uX7mRPT
         up2kbZOUCXDAZdN+pXKfBIi/wYyhtBnbBaB/YgWyaudlf82icPauBBBvx9GTvXz81lCT
         ylNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756765388; x=1757370188;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=KW25V+qflyynzAJeSslmfhmFQ8c63jMKe8tNtcJo0qA=;
        b=DoNU/DKQBS+Mh9DhBdGD9jX8UN/6I9rQOBzenBu4vRdpOgtOTkZd1LGJWGQ+Hx0km9
         vxBDdE5pUzA/L6gYSksLXRH0C6brw0skrvu4IPDNuq2gIYkdUsLY3uQfjfHacpknpcA4
         AhPW6+Chs/O72ses3OsW2ZorZKd8JTm7nFkRx/CO5QKIsUn0HjBcS6dJiLyGp3qvnmyN
         tgovAQBRVyBZrSjB3s27Sq/MiNiYFjdKuYRIKdbbRrZtFLMcJ8RBa3GHSB+dMXJoT0gv
         WMiPoW9YOVT46Rkiixu77Vm4zSg9jc2CWjXhC2eEifsRj8cjxBAHBu+15Rl4CNOR8JIs
         yVkw==
X-Forwarded-Encrypted: i=3; AJvYcCXDtx+Sp4yEKNmq6wBEOSoJ0XbS+IyftPkrtdIL/UlazHqz6DTpUS1FMweFoycvd7BPO0hqUA==@lfdr.de
X-Gm-Message-State: AOJu0Yye/yDou3KzbcPcyVNgllF8wHd9PoAY+Qg24xL28f0MCv+uis6i
	EsOvN/nGUISwHod/J1gW0/18SxGg8Wlcg4+uuUEREFYxmJPc2vMVSC7L
X-Google-Smtp-Source: AGHT+IHyk4jqAHS3kk/ZkW/ciEls12cui4rA5mVcbd0rJXUZaTQAeIuP0zui79vYVPdXS72BJOYTNA==
X-Received: by 2002:a05:6808:80c9:b0:437:7577:d459 with SMTP id 5614622812f47-437f7dcdce5mr5626636b6e.45.1756765387834;
        Mon, 01 Sep 2025 15:23:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd101F+uGoARAbeMcXyffMytPOJnoZ91gNb5lslZGSgsw==
Received: by 2002:a05:6870:4597:b0:30b:d6e4:3de6 with SMTP id
 586e51a60fabf-3159636dca5ls2138087fac.2.-pod-prod-01-us; Mon, 01 Sep 2025
 15:23:07 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXWBwcITraE/M6OrD3xokMEAHyqSpZiiIiWK3ECrg2hv3ze3nvHQD6j2zdw3hypiZi4tm8FQYXb5V0=@googlegroups.com
X-Received: by 2002:a05:6870:9610:b0:315:b42a:1788 with SMTP id 586e51a60fabf-3196347005dmr3970148fac.49.1756765386955;
        Mon, 01 Sep 2025 15:23:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756765386; cv=pass;
        d=google.com; s=arc-20240605;
        b=QvIS80pQRTmiioSxaS5LhKMihz5G2BVOEAQVy2GDQY4c0iVavdrpeY22Y7c5Rknk5D
         /QTwqmKgrbi302apB6EGGUAMGVWb0frvUV2VGnCi0mF4UPvmkO90WxJoHODy/pKrhtU2
         mDxpDk0Ou/V9A6/qw53bntoiHYhsnxK1EAj5lIabDz+NO9hAsODeDGyQ7cos+uRDEr/M
         isY/wD3IY40TMuVBG+LqJ5KH1VLySasnlirnedN6jLrG2ue5y6HRC1B4Hp5ibNL/ktUD
         26Zd/0JEcBvm8aVfWqFZLrE4VPtEG+TsX42RW9YuPFc/azHaeUBCbrnezJ1GGou3MhJh
         hLUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9PcD09FKAh1vF3qniFuOOvXvPYB3eKU4OoIktmAdxRs=;
        fh=V2v2wOTK7B95biDmlomC5DJQVb68W8dDVMwTi5I+Rf4=;
        b=dVaOAFt41CAjCnGaXjSnXdkhZVZ63ZhuNcqriKL97+ggqSZkBJuGz6xOUPRtaFa8N6
         PzkkZ3EoUbHfdCceFw4tUaLxlMQAGvv+TVImidYmpmm7k8/cYy/u2H7tugjhde70kEiM
         SWNIKNud1IHcm8QY+ItyOfvDpEeXIXCCw55d1EbC2LL2R1LlvwWStKAc5LnDovKNQvzF
         OysaUzHUijP/4lhP3p9VN8rOq1jPdM4gUltkoAyi957QPAw7eUmapeQ53XE1STSyrEN+
         nYaJFH9qBqvg79GdGGgWXHdmeno5fK+8MWOWyrRHsjnKmwid23faUDXF6bnD0a5+1HR2
         Dd/g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=iv80n33E;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on20620.outbound.protection.outlook.com. [2a01:111:f403:2415::620])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-319b6023651si6003fac.4.2025.09.01.15.23.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 15:23:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::620 as permitted sender) client-ip=2a01:111:f403:2415::620;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=bS1daFUznnVp//4wMYjsC7mQ61wfIUfOOaXIhB/KaP2C0FWv8GZ+AgFHdNow9W+6LXe4icajYJ2+WxXsc3zUbDKHO5qLBwEuMw+Q9bPQuu+vMYEQBHOuug5k1pMM+CHRmqItzRdnFmk0yd9gP1Dz8dtvUDuBXv37ceqZgk4JkGoauVNdC7DCt21lV4fbSKhkV5UqbzVrfG15J2hRPgi77evgwJcR5AbM88DSP+44Jl9DoMtdqDfb7NmsFMEjmsqpPAOnDztFEHEvqFK124YgXyGcVctt2NDvsBD9+LotYwcs40TPnAp0q4vlNtCGwMuLIVI1Kmi6+1vjV6I4h+6LPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9PcD09FKAh1vF3qniFuOOvXvPYB3eKU4OoIktmAdxRs=;
 b=WD2g5hBKoBkYOk72WapCvsuBh+eJvISk6j/e7JOqGTjIMxvJ6yAKX/KGI8zX0b5x+4+D7HcK3ab0wk3SSgkNNQppdXjtXvwPBNcDl/9NZoiOPLVlA8jNZj4FT0aSixw2m2UOrq1lugxBIVYkegHX2pu9CTI0Plgmcu0xrdJl/XdmmG2pvxFen7O4klgiyYAPTFe38ZrLdRzIPoHJi1rLN5fMWUI5o1tfon6zz69GRkz9LZxZUWlRiWWC9ogwpn6NCnXrDMvwgcJSwnxSofKEcQ8vMyV9E7xVIeOfnxtX5z0kY9O2R0Z8GRkFx68JvIa68t9nPT2dARPCjIyNbT6RZA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by IA1PR12MB7495.namprd12.prod.outlook.com (2603:10b6:208:419::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.27; Mon, 1 Sep
 2025 22:23:03 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.026; Mon, 1 Sep 2025
 22:23:03 +0000
Date: Mon, 1 Sep 2025 19:23:02 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leon@kernel.org>,
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
Subject: Re: [PATCH v4 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250901222302.GA186519@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <CGME20250828115738eucas1p24f3c17326b318c95a5569a2c9651ff92@eucas1p2.samsung.com>
 <20250828115729.GA10073@unreal>
 <26bd901a-0812-492d-9736-4a7bb2e6d6b4@samsung.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <26bd901a-0812-492d-9736-4a7bb2e6d6b4@samsung.com>
X-ClientProxiedBy: YT2PR01CA0016.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:38::21) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|IA1PR12MB7495:EE_
X-MS-Office365-Filtering-Correlation-Id: 2712e776-387d-4145-20bb-08dde9a61dfa
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?V0E1b1lMQkNvUlZFcUJCUEU4NWNRZTNUNnMwT3J1MjJOc0N0MTRoUWdhTkd1?=
 =?utf-8?B?VW9GZ1FISlp2ekpIeGRia1RkR1F5VThDUituWGpVWVVHOWlNZzB3bExoZVNn?=
 =?utf-8?B?SDJGRmcwYmlDTVcyQ1NkQ2lvd0lwVWIwcDlYYURNVFFBdHZMUHBvMURRR1Ir?=
 =?utf-8?B?OGc3UG42ZTRlMktlN1BCVUR4NHNCRDA2T2V2dUJBN1liUlRjTGxIT0hZMkhN?=
 =?utf-8?B?YmJaV0dTZ3VYS292S1VMb2hJSWNhYzRmWDJOZnFxaktvTWplVGRDUjQ0RlJ3?=
 =?utf-8?B?U2VVY0pxaHlmallkNkd2ZElUd2l3L0FDelhSeHQyTlNTd2hwS2xvMDF0RFlI?=
 =?utf-8?B?R2xVTTJ1NUxZTWgvSnNvTGp0Y0ovQ21LcTkvaFV5UmpTUzlTUDhEV0pibXhU?=
 =?utf-8?B?ejlXZkN3Z3NtRDR2bUx6dUVVL3BtM0ZyN3BDbGMrVHJpaS9BM0p6T2Uyclpw?=
 =?utf-8?B?eE1ESmxUNkFWSHkwZkFLdDhDaHloMUwvMFM0ZmtNaWtIaGhZRDdIZEZVcVYw?=
 =?utf-8?B?TC85ckZTa1M1bWtVQ3F1azFyeDFWb3lyL2crMEtVcVcrZjczTGRxdU1pY3lH?=
 =?utf-8?B?bXhlT2Rla2VpdDdIQUV4b21uQ3FGTnA0dU9ZU0lmSVo2TEJPcG1LaDVBTG1o?=
 =?utf-8?B?cW9INzArVVJlZUNUUXY0QytHN1J4M3VWRUpRZHlMYTFyZTA1RHdWVlo4dktW?=
 =?utf-8?B?dHNPdnl4dHovK0EyOHBneUN4aC9WdWhyamZodytPNTBzcHg2bU9nOCtpN2JG?=
 =?utf-8?B?TTB2NkRnT1FKWWo0bkNDdXZBY2dMVzVocHBXTnp6TXRGdDk5UlJSNWZsSWUw?=
 =?utf-8?B?YmRBRjc4RTNKdXdkTzc2MmtyaWt1VEphMTR2c3Q3UzBJOEhUYzBGQXdvYlpL?=
 =?utf-8?B?OW9VbDQ5dDJERTZRMW9Ib0R2bnduMFVSMVBBZ083YzBSSzNxM1hyU1RDTmVX?=
 =?utf-8?B?UHJEMnNsdC8vSmJDWUwvaW1ScXBGQUpnMGJCb1lIWVJSNW43Qm9rVTVCTVRD?=
 =?utf-8?B?aTIyMUUyUm9KelBESWc2UUJ4YWNEc2Z5ODBsRjVOKzM0SEQrMVF3QXV4SnQ5?=
 =?utf-8?B?T0t0dC94bGxHaUo4eml1UFY5bmtWQjNpdEZXZ1BsNE1nZmFyTlQwU1p4enZC?=
 =?utf-8?B?amFHa2pLM2c5Tk9wUk5ObUFFRnN3SjhIVUFEclhzN20wdG1tbmxYYjE1NnNU?=
 =?utf-8?B?dFM3dUhIWVZEN3E4ODFxS1lRUjVHSG1VNG9qMm5hRFRsOEYxb2F1MkxKdmdP?=
 =?utf-8?B?ajFQTU1VUVNrL2Rrb21mTkg2bXdSZThLUHJOSEhKSHh2SWlwM0t4RVl5ZXpo?=
 =?utf-8?B?bW1DNk9KOHNBMkcrWkwvM1JUZ1FPU2d5c0JHZmNvL1hrc1NsalRHUlExZTho?=
 =?utf-8?B?RFdDSDM0NXo5cW1kTlk4RDVGaWc3YUhTZTdMWHRJbXJ3Y3FwRjNkQUkxRW1i?=
 =?utf-8?B?VVRBUm4rQ3QydHNxMlRFaU9KM0h4N3VCMVE3dWlVay94V0o4ZzQrVDdoaU9C?=
 =?utf-8?B?d0hLZ0JWWDE2UXY3THY3T05hMFVkNjFvMG9GL3M4UytyaThINkRXTXhNVlhV?=
 =?utf-8?B?WTQyMnNqZk1TT1loRXdYSWV3ZjhsMURMRllTQVZvZFZ6MHhicyt3S3NTVm9y?=
 =?utf-8?B?NkkvVEttZU1nSUtmMDNhcE5UTjYxTXpGYVVuby9HQkY1MXQxVDdDdi9ZMzh6?=
 =?utf-8?B?dWtsc2dGTkJiWWNnVGVlbGw1V1VHb25CWmcvQmFjTTJvN3lHdlFsc1J0cFp4?=
 =?utf-8?B?b1BOMmFtWjhYVTZ6NjdleTlFVEFvSUNiYnc5MDNBUURpQk1VcFoyV01tSW41?=
 =?utf-8?B?WVg4N0kvUmxnVFhuZkZJZE1NRnVpQWowVW03bWRIZ1dSQ2FuTXdwVXEzMkRZ?=
 =?utf-8?B?V1IxblJ1L3A2N0Z4N2t3VGVaT1JNR0IzbHZVdlBtUk5qVFpSZnZGY1NsdXBN?=
 =?utf-8?Q?9gT21r84I2k=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?RkpjdmdHb1RMcitLaVM5OG5FZUZkYlU1WndDVjBnR1RrdEwxT3Jvdk8rVklj?=
 =?utf-8?B?d3NEVm1qSzBERU1wdVptRFhTUGZRTG43SDVvSHRCL25yMnZaSUMvVE1sUDJE?=
 =?utf-8?B?aldBMXRhTnNYN0c3NUVxK1M4dGFNNjQ2VFBnMmV0MnJzSCt0YTJGWlhLM0Fy?=
 =?utf-8?B?WjBjVVFiMDFmL2JLby8yWk9KYkk2REh1TFVQVGtxSUtFbytRY0xhMWt0VWxG?=
 =?utf-8?B?VW5GcEozb25ZaHUxWGQ5N3RTa3g4L1ZQeUQ2SVY2T2VmdHFnV29pa2lNc0h6?=
 =?utf-8?B?YVgwZTlyRDgyNmlxY3g4V2FyaVNsKzUzTzRlL0R2TFUyUzljZWx2SmY0VEpw?=
 =?utf-8?B?WFUxeTBrczh5MytEUUtVbU5XT0pOZ2U5T3NMR0xxUW5BNTd2MjNEVEZKVTJ1?=
 =?utf-8?B?Z1BHckFwWlJxZUVKckNsSUxFdGlScEtxM2ZBMkRHcHFtaGtkeGc0TEFRbEdt?=
 =?utf-8?B?ZnlXd1BzdEdZYUZxVFJXRmlFVks5MDlnNUYyVk0raHJ4NUpWbnozNG14RW1B?=
 =?utf-8?B?YzVIVEdERkUreVZaZlhUMTlDbDdBVzRRb3NCM0hiZGg0cXhuVGkzNm1oc1VU?=
 =?utf-8?B?TG4vSXZON2F5ZGUzUk1KMFM3SlRtQ0hyQkJlSmFFM0lnRGlnaVZEbC9EL2V2?=
 =?utf-8?B?VlhYdDZWL082a3pidkNQeEpGZEUwc2NWTStKQlByZnNLV2p0bGpmR2VVM2ho?=
 =?utf-8?B?ZFU1V3NrbGNaWlgyRFUvYTlKaUV3Kys0Qk91N1AxemVMemVhOURUYTRkQmln?=
 =?utf-8?B?MnNCSSsydW9KWFhQS0d1eVdEUTlITGVTVzNFZXlyd3BxeTRrZkg4Sk03bEw2?=
 =?utf-8?B?TWU3TE5mRVNDRU9VMmQ3V09yNlN6cWFrMjNOTjN5bXIwTVQ0RWJKU0tXdUFH?=
 =?utf-8?B?b0t3MkJoYkc5ZlR2c3R6YjRaU2RWVFBYdnFnQ1kraU9tc0ZXNlExa2xMeVZU?=
 =?utf-8?B?RFEwQWJtbGZGRHR0NXlSYXZhV0E0THk3WGRERUU4a3gzYjlTMnJlUWZ6eDM4?=
 =?utf-8?B?d0M3Ti9NNy83S1lCWGFqT0luTkF2VzF0ZUo5OW1sWUwzRXVpZzd4cnJhNmx6?=
 =?utf-8?B?K0dnLzhOZVdqMTBjVjgrL3pUTlByL3Z4WitmbkRSaEFwZGp1VVdJUDhsQWY5?=
 =?utf-8?B?akZpMlh2aDVYSUhwVXNpZWVjTnJqVXZ4T0prNDdQL2JSN200dlZ6NlBocnow?=
 =?utf-8?B?clorWUFjejM3WnpURWFkU1k2dDlSZUZ3RHJCZm1ZU2s0VmxKVDVvVlNNc2Ro?=
 =?utf-8?B?NW10T3ZYdi9LRXQ0dVdBRmVURHdaRlMzaUJzRm1SLzdzU1NVZ0QrcGU3UEVT?=
 =?utf-8?B?ZklXY1l3cFE3M09uT2w4bjkzcHpMcXZHT3k3bjhTcmpuT3dnQ2RMRmdDMmRQ?=
 =?utf-8?B?UzBDMXpoVlpwb3RVVVNqY2FUbkttYmplV01RRlQ5K1Ruc3p3QmFmSytaWnJM?=
 =?utf-8?B?RGJiVWQ3eWp5RTVFYXhmQWUrYzJlbmVjbzA2d1NCKzN1eS9LYlBLbWtnNEd0?=
 =?utf-8?B?RVdQMHVFdWZwTnVFcnFMQkpneXhocmw3d0ZMalo2dHMwQmhnY0VwNjI5Mkta?=
 =?utf-8?B?ZUNDQmhtZlg5eUpyVFhPM2s1NFZhbGVkbU9DZ1lxL1RCbGR6Q201WmsyMXE4?=
 =?utf-8?B?T2laZ1Bqb1NDNmNjU1dFVXZQb0xQOXd5Q1VwbWZQeXJhSkxmamRJa0MvTDQ0?=
 =?utf-8?B?bU00WXVZWlNYOTd5SlJBWUNydkpNVVhIUkVabkI3OHI1VWV1QlowOC9TdVZY?=
 =?utf-8?B?cm0vNlViOVp1V2Nxc2czaWZjbW1VVDBURVlCbHc5L3JtN2gycDNGNkNUNis2?=
 =?utf-8?B?ZkdyWnN6UU9rNzJ5bFFLZFJreTZkanlIUkRibk1MMEk2L0VXcFhLcGp3TW1T?=
 =?utf-8?B?dnlQUE9RRmFheVRaUitFbTZQaG1oenBLSXg4WFFiZXFJbHV5d3RMYUN5azZI?=
 =?utf-8?B?ZmlmMHR4YytsKzlaeUJ1dXpjdG9EYkJka2tMd0pMOXk1RGRIS2JJaStRdEk0?=
 =?utf-8?B?a0NkRTlmcVY4RloxUUI3Q21LU01Md2MxUzhqTUZ6TjdiVisrWUR3aFpKMjZQ?=
 =?utf-8?B?Y3lDWVlqZC9iUzB3dmtEWjJOK0NldjA5SWxxejlxZnNUTUZBZW56OVBOVW1r?=
 =?utf-8?Q?mYgQ=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2712e776-387d-4145-20bb-08dde9a61dfa
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Sep 2025 22:23:03.5273
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: w4znFzS8ZQTnhjINhC0mXrOLe3RICQMXCayvRTPzL4tTrPL8qJPNdtjBo+rtk6D0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR12MB7495
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=iv80n33E;       arc=pass
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

On Mon, Sep 01, 2025 at 11:47:59PM +0200, Marek Szyprowski wrote:
> I would like to=C2=A0give those patches a try in linux-next, but in meant=
ime=20
> I tested it on my test farm and found a regression in dma_map_resource()=
=20
> handling. Namely the dma_map_resource() is no longer possible with size=
=20
> not aligned to kmalloc()'ed buffer, as dma_direct_map_phys() calls=20
> dma_kmalloc_needs_bounce(),

Hmm, it's this bit:

	capable =3D dma_capable(dev, dma_addr, size, !(attrs & DMA_ATTR_MMIO));
	if (unlikely(!capable) || dma_kmalloc_needs_bounce(dev, size, dir)) {
		if (is_swiotlb_active(dev) && !(attrs & DMA_ATTR_MMIO))
			return swiotlb_map(dev, phys, size, dir, attrs);

		goto err_overflow;
	}

We shouldn't be checking dma_kmalloc_needs_bounce() on mmio as there
is no cache flushing so the "dma safe alignment" for non-coherent DMA
does not apply.

Like you say looks good to me, and more of the surrouding code can be
pulled in too, no sense in repeating the boolean logic:

	if (attrs & DMA_ATTR_MMIO) {
		dma_addr =3D phys;
		if (unlikely(!dma_capable(dev, dma_addr, size, false)))
			goto err_overflow;
	} else {
		dma_addr =3D phys_to_dma(dev, phys);
		if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
		    dma_kmalloc_needs_bounce(dev, size, dir)) {
			if (is_swiotlb_active(dev))
				return swiotlb_map(dev, phys, size, dir, attrs);

			goto err_overflow;
		}
		if (!dev_is_dma_coherent(dev) &&
		    !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
			arch_sync_dma_for_device(phys, size, dir);
	}

Jason

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250901222302.GA186519%40nvidia.com.
