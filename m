Return-Path: <kasan-dev+bncBCN77QHK3UIBBCFUVLDAMGQEJMJOARY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id E7149B7D5F9
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:26:21 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-25d7c72e163sf106269335ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:26:21 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758111979; cv=pass;
        d=google.com; s=arc-20240605;
        b=VTv/seU+oQABLKaGjynK26vCqQUifO425UpgJy07IH6aoa6kGDRQaIsG5cp1+2UPn6
         X5axPtWtY4xQZVbY0X44BXj3fZsi8rPi3X3QyooQZc0ixu4eT6Av58fxC5vmb2OZM7ew
         EGGw4Ika6HBPcYm1/JkWMDUFuC248wiXjID3zYflgtN5Itydhyga1YFgajLRtSFxH7nx
         5pYoY6r5NEmXYeo9hYEW4TF6gYITg8j8FltUx7XI0rAKPgz7NXdP24C6UF4BUD8tpR6A
         6o6GTx+mzBh2boZ10/oY9VO14ADZ+0CwpZnJ0TIwdTzCno1MuMu3Xy8bI006f+apIPqf
         71eQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=3DEQj6lzyhmdwmLY2G6gqL0aDKtCQJL3esbzXdyxhYs=;
        fh=XgHgEDyweJoU8WP8keMZ6hToPUrEH7lq7//qMhXGoV0=;
        b=kn0pL4liuCWaR5HYEW27WTuTnxTNqa2zLINDTyx1/wKBf7+WqlF9lJXSde5Tj2XCqc
         bAlmq7gqmiGlLGouaFxIh59HQmq+/i7eRXX8MbPb9PgEJWiSeMsdJkxncr8IRfhIY1IN
         VFHMawCqk0S7xUVQ7sYZX76vkSpUtKATVxT5xHh4bratlfHBV3z/HNVWokvw/MXhLMVD
         vSPH2/lBUxFnLWdGHbuenfzc/K9rMjpM2+Osct/B/Ds8mdOTcUx+NLGcvfKvtxaaZ8r0
         SmDYXTXCjW7TV+jo0V+wMNEL3y+SArdmfcB89XteefAFJDCwnZgnMRQnuWrh6kaAoX+g
         BkYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=iev9tvad;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c001::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758111979; x=1758716779; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3DEQj6lzyhmdwmLY2G6gqL0aDKtCQJL3esbzXdyxhYs=;
        b=RPeRfKbG7Tz8ZVD3D6SMwDCtcmIuNQUw65B6b7G/V6HxchQS11z7LUIxMOgfDP6sX7
         QmwOfTAcweSnrwXeVeQ6tsXeSlmhDvWS241RFEIhQgrcyzU+VeVDLe89zGi96eXVqCWC
         2IESXNPPIOluEGMq+JQjjTq9CfwJlSKtTUjvV0YdNlNJL6iGsnKAFfd763CxaI0AgLko
         ailc8AN0LYIbRAfVG4P5T55ZK0TVHR37GszZOlf0BUe44PIUBQKl8Wn+9bA9q234EZia
         CZ1FDkwq68Ry9UwmjBpZjAC84382iz2YtbhoSWLLxrMMnU+Xc9y0zHEmFkP05VhQbPFJ
         CL3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758111979; x=1758716779;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3DEQj6lzyhmdwmLY2G6gqL0aDKtCQJL3esbzXdyxhYs=;
        b=UDjY1/1Xz7jik+HczL4SWSw8md4sCpoNOB3EXTN1PkEkv6Bt8GeSlvBEc9WJxohwlw
         x4k5pvo2EYIB3fKKkCOujZP5BHm21gUMSNeOWBPTO44VSPaC0M/jeCGuUMfnR7wv1Jp2
         +1C3BigzvlJuobLYJ7isSOiKwpyAo/hChG3Yl3YAN1gNlgp2s3JBqDsp9WR7Q0yUa9XI
         RZOqjebmfFx9gnSgeZxaQ9VCW/9EUijYFnObKB4ofqa0bUuGCI+ZrVngSHFCgm8KclT5
         s/U9gtiOZTiMrZk2s18+yjE4aw77aBl9o1ni1C4aP5nMNp7osoZyEZE4goQYK3xCz/ss
         DuMw==
X-Forwarded-Encrypted: i=3; AJvYcCVvOvs4bV+KszNhWQ/xeu+JOIxbSdrxg47NddPDhm96jfGtdR4gNJOMjP3LIcuzQi8uzIC6WA==@lfdr.de
X-Gm-Message-State: AOJu0Yws/o1UL9LNHjw4iGjSm7VWajgOYb3cb5PPmlOfFx3IEPBTJfqj
	RD51cEzZUbgx4JJqnRjHB/2Hq0eTl1DIJSTQ/8EnUYh7XWKmpsBIY4qP
X-Google-Smtp-Source: AGHT+IHiF1AUNMTG8d1o+loNcFzZ81BDzg1fBAM25Y+AEHHB7nRKXWrRvHm8yThoDaqpDf8N8tHmnw==
X-Received: by 2002:a05:6214:e4e:b0:766:30e3:eb9e with SMTP id 6a1803df08f44-78eceb34393mr13657856d6.37.1758108168312;
        Wed, 17 Sep 2025 04:22:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd56/Ld60E7c2E7jFLxA9bhixvE9hBindc+NnOrihSAo0g==
Received: by 2002:a05:6214:5991:b0:783:6e2:3e57 with SMTP id
 6a1803df08f44-78306e24a40ls39434316d6.0.-pod-prod-08-us; Wed, 17 Sep 2025
 04:22:47 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXYa2hB8jHpioZQFXiqT3pOPORl5B7JX5kBeaJAPQXj+jaoKhW58pDVbilORwrdwcTNNxt6gloC8LE=@googlegroups.com
X-Received: by 2002:a05:620a:298c:b0:80b:985d:e95b with SMTP id af79cd13be357-8310903757bmr152445285a.24.1758108167278;
        Wed, 17 Sep 2025 04:22:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758108167; cv=pass;
        d=google.com; s=arc-20240605;
        b=DVvKdDDD93LTxEPZTF/IC5XXcPH5narLAh222uQf5ylyOmaamq794rkTkin/jM5B0B
         m5Coh4N6WqXwmO/FfRqMaLNyoeOOVbRoDSwBLlPBn1ZeOgTisz/59LgHmB8ZMwXRG3a0
         ZRyqTLzoocUcgQ8m+KxT7CXVy0BimudGBW2tDP/TOwPuAWaWHHvyRcZ3Q0z7BGjecd0y
         N1YVPVO2V57S4Zb2sHe2a6DEImji55hJsaBI5hcPqhj9DEvaTc/B3JRpa9yatJoyts6/
         PqtErSd/p9++JdIZDv5BHfT7kTmHCetL0NQ/mSvCcpbVRQs45JjLWLFnZt0l3EXnvq96
         kCDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZnpEPkLNx4tgAzdAqaQIJKgDVY+FGHX085UqVc9ZsUg=;
        fh=fMZOJI4GJQ22hzKQ0cYag4GrmL2sjsiUKWn6kSy1F0Y=;
        b=TZeHiL06BeykJLSTa88s8LhebcHEGfKSH0goXtE/LCo+afPsfvtmMiUemerCoReyx4
         IjZRIjCtzwXFd74LAi1kIVJv7XdkOnVDJUYgJTX3Db00M5qSAY5G5c98QoYdb/IAeMe2
         RRCbNk+3TcFsEbkAE8bx/kiGJX5oqO4GU+giAa/2wbyhKE73mmR8txO4Vdw56AoDvExx
         AQTAK4JEVhLvcnNTGsUchYK6KiIDQygIpqebqJVKNbcx8W1UoPNOMgJ+duAPujsPU6yc
         YMuiCK9TyweCmZv2uoNHu8cLs4Cobnv/dD7VKHSP5mk6UXsEUHrmZbWEL9ngIMHyZeog
         GzWg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=iev9tvad;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c001::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SJ2PR03CU001.outbound.protection.outlook.com (mail-westusazlp170120002.outbound.protection.outlook.com. [2a01:111:f403:c001::2])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763b1f6ee87si1524656d6.1.2025.09.17.04.22.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 04:22:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c001::2 as permitted sender) client-ip=2a01:111:f403:c001::2;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=JbJDojgMGGYC5RisI3b6lHk/PIln2SSiEmhovtd/aEC1i7GQ3lyfYCwSUeQkmSvsw78OEgTUUbKl04VY7P1C7SvKRHKAAkX42hBEwkNv3ANGLd9p7QPhy1wuAT55yRIP6UmP/QhJWTLfibCdewprLwCtxaWIoWfiaCJE71Cl3bFmZ7mqX32vH3Nz2CX+unsv2SydqluWoJLR0Wlewb+W2X8TRgbpW9zB5yerkWNH5mpEJzkLW44d9rUuCurEfHbvwXBdQ9b6Zb5MT/jLfoTWkyG4qcDrmq1rRh2D0wGfl/9YdRoAuOoLdbKve25N48FG8P/YDTFndSKaDuc5p4v8bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZnpEPkLNx4tgAzdAqaQIJKgDVY+FGHX085UqVc9ZsUg=;
 b=tWtyAQxn/I0RfAZMAkNU4WflhSnikujni9suVBEZa7Or/m3zBW6PL+G3jOrK3DHIXx3XAY16VQRielJG+DrUUcrX5v8Z14hAjMvNApR/8tnp8OPnCPI0YQVbygPihuKwFPFwXhpf15T5MIpm+lD0viI82h7G8dCezUVnlSMZPHEMypc+EUE/c9WyC5CHBKAXo/3b6KMHoVPcGQc5aK/WwSc1DuvBfrXQHejYklAR5FKMVk4k4bVAZCs0+uTEaJIMZVKytqutzl+ScjPlSKccgOrNSM4YWrp2H2M2P2AN1TP4cYCJpQBBbVQlmiSFwvQPFlBT/pMX/hb0jicAOjSIag==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CY5PR12MB6228.namprd12.prod.outlook.com (2603:10b6:930:20::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Wed, 17 Sep
 2025 11:22:44 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 11:22:43 +0000
Date: Wed, 17 Sep 2025 08:22:42 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leonro@nvidia.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, kernel test robot <lkp@intel.com>,
	linux-mm@kvack.org
Subject: Re: [PATCH] kmsan: fix missed kmsan_handle_dma() signature conversion
Message-ID: <20250917112242.GZ1086830@nvidia.com>
References: <4b2d7d0175b30177733bbbd42bf979d77eb73c29.1758090947.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4b2d7d0175b30177733bbbd42bf979d77eb73c29.1758090947.git.leon@kernel.org>
X-ClientProxiedBy: MN2PR01CA0053.prod.exchangelabs.com (2603:10b6:208:23f::22)
 To PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CY5PR12MB6228:EE_
X-MS-Office365-Filtering-Correlation-Id: 66db3745-88aa-4dd4-afa4-08ddf5dc8568
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?+KfuxH9UrAj4aU3KMGaubcZIrKofJMLEZJSi5PFiFyRs3oh1AmVvfqhslbUd?=
 =?us-ascii?Q?n71kpskHIwSx4i8j8cWKSQ5iauwOiWAJJfzCDukjv36W5vvX6c3XwB5QyHEf?=
 =?us-ascii?Q?K9Z813XGWB252to9X0XiozzVoSnAmVkkccK/vI1XCLOld/JPdIuanwAN9Bt3?=
 =?us-ascii?Q?XLhoD0XupQKhJVOJKHCMZcbIDWAYEVr3WSqNmA+AxrZCu+ETc4he7W+H4PNE?=
 =?us-ascii?Q?Bg+G+Ek+M9jS/52sOiPf7yBKb30TOr07Be88Kb3aN+PfNHzCislf39lGWSnB?=
 =?us-ascii?Q?4QJY2UN/cbI+HOWAta912mxKdRHaGlwDNcTrqDxcnlNSo8FR1+egzYJc5Nac?=
 =?us-ascii?Q?Ybu8pVIracjT4wUycN7dW3//4okIz96ESS+0SGVWprjQc3/A8/NzxXUJR23p?=
 =?us-ascii?Q?3sRLk1SsHI1AUIegl4/9yChsrhRXmknvVseTxKPWB1V5h01zUnM7bdeNr6al?=
 =?us-ascii?Q?TOKdywT6Ln+SlTS+zOsrZ8x8bEI+L6wRS3pjwo3aEtVXZXkIdrrYMPw5auUU?=
 =?us-ascii?Q?RjBYU9R+tHcv5A+PCvbhLlSFOb9Rl60A7YYqRIGkpYvq5CIfEDor/xFQJ9Ay?=
 =?us-ascii?Q?X15NPUyWXCQ1X4Ip2u5shKv/84sIw8T/QqD8PUjoMW0hZAvJKbt2KV9ceJrc?=
 =?us-ascii?Q?cN+G/bWxFxSWumrN5epaRLgbUelLFf9iBzU142EAvx4uFRWKOC7Ff0gN4Gu0?=
 =?us-ascii?Q?Lyzi826KUyL3lHC/kHqJ9AdsBOdghXbJ+lCip/gmDldI4zoVoHORGcJbPA9v?=
 =?us-ascii?Q?shRRRy1NRd7bi2m+UTs+rbYeHrBfAQSSTVabws5swPY2vd8m7jBUbrZ4uUy1?=
 =?us-ascii?Q?oa4Kh59/4c9w5G5Eh+1B1Xrf++EQs3CMkQSh1ZLfpeQL0SHMtN9VYiIb+KD/?=
 =?us-ascii?Q?jQXR1kDmjsda79TGSGvRpf4bmU4B61OS9wlsaQFfm8DOrUBNpUGeNEFxwsOJ?=
 =?us-ascii?Q?yodlafIhb+WbBX5dR6eySmfE0sGI+C2C9StmaInAL2mB4UEfyFJtIAVjRArP?=
 =?us-ascii?Q?MkfEKHhnHUtmAuy8gY4yV+zL2QjaGjHgm3XNUg/VrxuTGxh/Kucgyh7TKv9a?=
 =?us-ascii?Q?3fo657FQksWpeh8e+o3zhWRllSIiQ8BYfgC83ZYu0a5n2eLN0BbpemAih5Ua?=
 =?us-ascii?Q?Fpbh6PKZ//4uQ8BB1l9JR6GyKVE7Gojw7zPbZzdjS/1631m9qPC+EtaSQOIZ?=
 =?us-ascii?Q?A42BDkzBglNZT9UtAbAfajSvnx2pPEHfgGMRbnb66KKk/JAGM15f2fmaqx4/?=
 =?us-ascii?Q?TjLCRrhZmqtmHw+fteGErYBkQUEPkHCfGOJbhQOrxr/FdwvWvGZ0q+2rDaZe?=
 =?us-ascii?Q?ruaIN2NVVF2BUznUNTn9B+QJ3k42ABg3JgrC5q7I4TnTP5Fc1YRK/tNBp70G?=
 =?us-ascii?Q?ppdqNKK2ZrBiCXohHIRJEO7KwmqgrPcAhfqrJGEMkoRCbLUPBChOggkNKFkx?=
 =?us-ascii?Q?kx/fKVcFB04=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?i/0hpM5yErP1oqcrBoSGIKYf3MAF6rYoKCp41CW/f9a+1EUtGI1/j8uPOZ4P?=
 =?us-ascii?Q?L2TQpIf9n4m2pBuUqs43i9IZMNMoIzrYxaQwBHsfYl4lT1cdN767qOaJc/KU?=
 =?us-ascii?Q?SHR1E0AGc6B9LTSse/nldqL2PgMFIKRCAGq/BvZgy/YiGt65JzqfAkq1UOZ2?=
 =?us-ascii?Q?LN0Zn83clo7r3qpRkiQy5IKzQoxR4raz7fOAA5lEJIy9+xtKueapAlsfzPka?=
 =?us-ascii?Q?0EBa4ihl73XnvbIg8gD+utKheKU1+XKwHhFEUm/DqP9UApjx7TEuEDiXhX70?=
 =?us-ascii?Q?SLnj/SBU1k5e3er+Lli4eQ3CRzCyDa+LHCF/x//7LJ+lxu3+EktL4e8SuxQH?=
 =?us-ascii?Q?QrClpRCtofc/DirvJshKPGBqNIuOAakWRnl/eA68tew7MespJNt9VB63ZED6?=
 =?us-ascii?Q?JJxvJbg3mwVTIXUpEZeRc8sRoC4RA8AvpaBNjTkPEgfQR0KttmRWluE4rLwB?=
 =?us-ascii?Q?OETbiwZ1L6n7QQxtXmn2DOmzNv5f/xFXwgXIdId40UP3KcOEouT0qa+Cf09T?=
 =?us-ascii?Q?810e6Stj6q/NwG8158OqtLr0DMygz3u7n8pE76IyNWWkPKaHRphKcQQjPQHe?=
 =?us-ascii?Q?6uyN4WTPB4aoLKCWYg0IAMhYkHZxh4kXX5uKHQip/l+xhxzvQNsvDql6R5BJ?=
 =?us-ascii?Q?qGOJb/nN/SMXE16IIU+WAfS6fWb0uCPFoVrzYpKcXH1BeH/U8L8pGRuMFPPm?=
 =?us-ascii?Q?vXp588UlPCvMp/IVVTQ+lz+7G5+QhHnLJAIVaNtr5RGIO8DGzvbu4YjU/LXR?=
 =?us-ascii?Q?Nf2DHioHlJ3+aqjzkvWheUqdvDp9aMr4ciiIQD0eu+CxpZsJwJ7JympBHHMF?=
 =?us-ascii?Q?zdazwZN37/jh0bBSoTsY9L55naTroZLF9V7wCWmcIqcZXlRW0tYe2rheEsYD?=
 =?us-ascii?Q?Q7QGGdm9CF+sIsOzzhU2ANikaMa8RyKSUbl66L3asWK6n7+jTi0vA1r8WW4u?=
 =?us-ascii?Q?AnyBVDGKBA7nvgIaXTc9+h7hvmd+C6XIYkHQpY9380kqG1UBq0RYxRN9Jply?=
 =?us-ascii?Q?NcirxGo0vcBziKGOkoaVed+uT43q6jaHBy3X+yXfdQvBbWLbnD6Vlb1Gr9m1?=
 =?us-ascii?Q?LvSLOMiGy0B13OHGWVDbxSURqPp4/IeLATuQW6y5Z1DXwliWmHnxlMruBfQU?=
 =?us-ascii?Q?JGv0+znTwG0YGU9fCo8bH/5R/ItTVfCwfPAaFLCQwWDHr4LFhQFvjuQ8KRVL?=
 =?us-ascii?Q?vGSOA5HFLW14CQxBJ31tO+GU+lB2qke2nVVs9U0zS2Yppjpedmj4QpjNXt48?=
 =?us-ascii?Q?88MiS+JXULUgInkj2wtPZ3IbdSaf5wQ6ntx/Z1JUXfH40kVbK1kzouIfXFAd?=
 =?us-ascii?Q?M/8NxX5+J6FVzlyp3qCYpI+dtPF+BCK9Cs2l+MKbyw0ZhW9lwoVwXInJJqhO?=
 =?us-ascii?Q?7c6jr9cCvVtg1IiNRdSh1ACPprnGFcsQ3K1vAMcBHYjKY3jxRJzWYT5y3pTq?=
 =?us-ascii?Q?0jz2oehYsOmPwO0WEQ62rdTMaRhRHFldgwcPbdjRqnoRU2kKx7/4wmoEvO85?=
 =?us-ascii?Q?ZJmq2E3TBCuiEB/a58Wi/D4HC1jfp3ifknuQI58TAWNAYwKKB5PobTMKRtGj?=
 =?us-ascii?Q?H3AO/b4hmD9tSpaoaW+qlGN4x8uWeWqsMTAuK2Es?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 66db3745-88aa-4dd4-afa4-08ddf5dc8568
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 11:22:43.7992
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: W2mmrn5QRrKwgXN02tbVjs7BcaqjluNoegNp0VnAi19MnWBv9AM/RWjDd3DeBCBH
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR12MB6228
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=iev9tvad;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c001::2 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Sep 17, 2025 at 09:37:36AM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> kmsan_handle_dma_sg() has call to kmsan_handle_dma() function which was
> missed during conversion to physical addresses. Update that caller too
> and fix the following compilation error:
> 
> mm/kmsan/hooks.c:372:6: error: too many arguments to function call, expected 3, have 4
>   371 |                 kmsan_handle_dma(sg_page(item), item->offset, item->length,
>       |                 ~~~~~~~~~~~~~~~~
>   372 |                                  dir);
>       |                                  ^~~
> mm/kmsan/hooks.c:362:19: note: 'kmsan_handle_dma' declared here
>   362 | EXPORT_SYMBOL_GPL(kmsan_handle_dma);
> 
> Fixes: 6eb1e769b2c1 ("kmsan: convert kmsan_handle_dma to use physical addresses")
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202509170638.AMGNCMEE-lkp@intel.com/
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>  mm/kmsan/hooks.c | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250917112242.GZ1086830%40nvidia.com.
