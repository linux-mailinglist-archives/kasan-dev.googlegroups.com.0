Return-Path: <kasan-dev+bncBCN77QHK3UIBB35Q2LCAMGQE5DE6FZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 68FF7B1D765
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 14:13:37 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2403e4c82dbsf7911245ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 05:13:37 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754568816; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fuxw02At0X77ji4Babs9/NJUaJL1bycecxyUJBNurPpIzaN3Nx48h8KGhu3AbiM3zy
         YfNkgBexiOSQ5vJYwgKVrIn6xeWkbEBQJ7b2felfdr7XTjZsa/g5DFCSdVw/1Q8wSZ/R
         gR/0mNoAgTj5LjnIUhZVCkgG3Ku94TumanbLrnnc/2rtgpexBW0qlf+WcHv613sHoXG5
         z3jR1XA3ogXh8nlGMriyGUX4oE5NFXQ6v0iRJR0qUKrBAzXg+TSyyD9WbHQPcvg+rSQh
         QnLLZAtPXzNiCUID9ROpEQCqNN9PEnUGzpH/TrFvrgi5z4/TmyCdzMjILviV4DF3/Eqz
         pCEQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=oND36OnjslxNw45pD5YnHnQqi90gcs7Hc54t1fQP0X4=;
        fh=pcswZedLtB4aCTMluijIbz/0JV3i5SNG0nuHa0J+U94=;
        b=LVhItrUkfv+5Wo9fgNFxIp4hgXuuxH6wl6IK0Hhatf11dO+T5ggGeW+09UFIsHpApn
         mT0sDXqiAmui5AxAIbWumcxk7duGb925IvyFObHhml+MDb/TA9PJ1CyPTawWgcIv6CHk
         88Ru6VB2YG8mCW9dqFWV9ghpZjZWXqGw2ZwaK15/m8TLWkEGXhpa8bk+xtZjbuAFh91w
         /se5bGh9ts1j290MpsxHl/i2c8c2wz3TB42WA/jf7vajCJpLHavdCU8n5hMCcvAnnExc
         9yepa5U3bI1vAT7EbJnYeM2ulmI+0qKrhGgLDLTN//t/4bxXE7cxuGAVNbZM+QMu/Qlx
         Uh9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=YZbvDWhX;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2405::61a as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754568816; x=1755173616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=oND36OnjslxNw45pD5YnHnQqi90gcs7Hc54t1fQP0X4=;
        b=ibGdYJClvB9fnZYNPBiyJq/omSKdrPBK2q8UcE7ncS33Q/0Os2VyOFKrapM6/ZZMPF
         bjI+0e3TgHZm0vI/7InIR+pBsTs/YwNpE/rI6Xjs2yRNDCz1xgkZ/yda9GieC7SDDTF6
         KbBVvzIbIcPtOvjJcNK7l3zL37y3OwUjizkg5BnkndkPWCncQ3SevCajn+l1BpKF+jpD
         UULzjtMgcFNMNW4+4pDaVa2H3jMzPhKeeBU+UJgv8lR8LmrmsPob2fHyt+fN7hAIJM48
         HPOd142d+Vaq+/FVI8IDBf4julHiP3j1h0nyg9IYks+SBm/2ApoLlVxfhMpjHfniNLUp
         4Flg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754568816; x=1755173616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oND36OnjslxNw45pD5YnHnQqi90gcs7Hc54t1fQP0X4=;
        b=NYjPmVLyTJ6vzN5rUwmrMmJ36u51QHcw6kXmjc78b/CCjt47VvEiEZnhup9Ug5/foz
         A/v4twQPl5TJcHRfsM6Yj7Lc2ee/5tC+e7NV5+aKOcIfaZIpppVtFRu9Q7h0gjIrKwFl
         dYV8CvBa+SRnY+URaZW17/U0drNpAHf0mUD5K19VhgzKYG7Eq5wLvCcNA0WHA03LlSZc
         h4sUCSSjfGA/WHN8cUAIxEprcuS9gXicgXJeMN2vYQpqy6+msIHWYV/ISF4bBvuyRZ2w
         eY7GF1+tOOmW65fY8cQnl9CTOaej4G/3UUSDonURAotZwvm4zY+KCa9E5rHWWAI8EAP/
         O33w==
X-Forwarded-Encrypted: i=3; AJvYcCUKQNOpfpo4PfJlquOR3wge0Z7FZp2o91ZnqMMlF9H7CrKqf+XWi9dPYRwDsWcJ5+kK9xfy6Q==@lfdr.de
X-Gm-Message-State: AOJu0YyoRsF9U+k0o4QHpT05Q+A0FEuU5LnoKY4TmZfwmsDcZuHfu9eb
	r57bh5UGatWwdH6HJ/t+uq1p0iII8oCO8Ds0WAzMdQBjq4XRy48H15YO
X-Google-Smtp-Source: AGHT+IHZXP14+6mG22yOXj+t/ztG7prUjzX/pK3Hp39Dt4LCfGzyQ7pj3Htuhu0ulOz2NsD3wNpDrA==
X-Received: by 2002:a17:903:3c6f:b0:234:f4da:7eeb with SMTP id d9443c01a7336-242a0a765d2mr98784715ad.7.1754568815379;
        Thu, 07 Aug 2025 05:13:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCozQqdMw2eO5hQ2b7efTmQ+auSdIePEkenIRiIXyqoA==
Received: by 2002:a17:90a:642:b0:31e:f73d:d1a4 with SMTP id
 98e67ed59e1d1-32175090b84ls985044a91.1.-pod-prod-09-us; Thu, 07 Aug 2025
 05:13:33 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVirKnCkfcgRt+AorETqCObqLGds0Cn6rVrCLsQ43Kt1YsViNOeHFI4I2Fp3Jn0fIRadq3XFm7UM0Q=@googlegroups.com
X-Received: by 2002:a17:90b:4a91:b0:312:1c83:58e7 with SMTP id 98e67ed59e1d1-32166df9821mr8053209a91.1.1754568813082;
        Thu, 07 Aug 2025 05:13:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754568813; cv=pass;
        d=google.com; s=arc-20240605;
        b=ENFqEXuaw2tkxiwVhnNKZHL8rpVCHqB/j/Mm5Jx+GmhDLoHNacgLmMiwZ5LeW728WK
         MI9EEOJVjMOwrO7nKcjrXofF5NbP6nulG1x+4L9m5Goh+PO/EZpyOZzd26PxkRGIkbqY
         rgFxeRYf60QeH4t7r3b+qBhVArcISWRwetXgdSZJCiIkifzNCg9Wf0cePfY2RS0KTQHs
         HPZ/FTglK7J3tuDUT1xJY6DVuXgcspCpJO9v0u5vFW3HMGSS05INy3VsgRlDYqJyOak+
         Z84GQqYRMudDVtwQa4X64f3HXHC/ZhFgqjSjkF1B13yuae05siIJBBz9ovzu6C3utDmU
         nAxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jnd91fTvUuf7SAXkMx8PwNrI+Ba1V4Exo/CmbUm1lhI=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=Fl/iJdaRq31RQw1RA/G8Uz/35yoVIJXmP9vDp+KVJAOxJmYsdTevZnzaNMZGj9gYNp
         t8w+90TkVY+l7dy5hupNOLPi8grv1FT/6bF5PKUngGkKAgf0MNePVV5ALsqiSZnnmeU3
         nm3NW0lRTZT2x4+i7g9EKapRj17c4JQBsK2TUQy9gMXhdgLauIbMamZe2zT6JuqqCKPR
         k4wL38t1zondIuTaFvjyJeVMwVurpjy8OFKDfP/+3+Ki1IqLj0gZF7Fvg4JuXABDw2pU
         pqT5oKH5JaaIjZFEUoJ4do/XVaFfD0QmGEnqWaw6UkbQY0Tz00WwnUE70QaOQZtLmazh
         KALg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=YZbvDWhX;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2405::61a as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (mail-dm3nam02on2061a.outbound.protection.outlook.com. [2a01:111:f403:2405::61a])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-31f63c0cd73si956038a91.0.2025.08.07.05.13.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Aug 2025 05:13:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2405::61a as permitted sender) client-ip=2a01:111:f403:2405::61a;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=uxP7Pf0ykg70ESQ1qsMAV46ciw3fMetV5ptq9znpdyVeKuYe0CQx684fgoNYUFgJzPJn3+4lFMQwUMWJvnCER9DzlnAjzb7VOcXipnWlrp5Rw4Grsy1HtLACWH7J3Ed33vP8gXCUoLzgPGe3gtIlOAC4O9FyyR/easgliZtJvaFKrNxs0m6aavuCs6iAlt+gGerYf/zavPmSkkgZFgCQ44WhhSIATvspnXnSyxfWAQHaNOTZ/HVPTzz4GEdkjnqvf3kCRPTfrhReWfvFs/DVv4N8LeoSaEhRlihVFXR5bJsdoCD3YcCry8KRM0MFz2+8xSTiZh8WgrQMoUuWsJghuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=jnd91fTvUuf7SAXkMx8PwNrI+Ba1V4Exo/CmbUm1lhI=;
 b=DmkWUqr9j/Xt1cx/er4RxEftmeONbyeBlY6MYlI9tO6ARDn5qDSq+BE9Rn6KcWTUtkkb06gl26cXmkAlhgowChbxbNfVNKTy6XpUC+DUrHUQ+0ALoktpQmGEx9h5Jh/MukgoYpDzNR/5nD0yI9VF60sAHH9yWSOkMUkrJtsgmEW0AGhr4D7rU5U5OiAfYq7p2Pxf94PFeDtWgTKLn6MvCrf0TyKJwv1xON/D9VEEvWA2ZXuhJbeOnUXdnd63ZCwbhDaxa9qWeUGDfLQYoiGD9vb0uZnbPYHLCim+AOmlGJkL5fz5bLkUcnXmDXqyf6XULntQ+lPLJG0oRnpY7ip/fQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by BN7PPFD3499E3E3.namprd12.prod.outlook.com (2603:10b6:40f:fc02::6e3) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8943.28; Thu, 7 Aug
 2025 12:13:29 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.017; Thu, 7 Aug 2025
 12:13:28 +0000
Date: Thu, 7 Aug 2025 09:13:27 -0300
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
Subject: Re: [PATCH v1 07/16] dma-mapping: convert dma_direct_*map_page to be
 phys_addr_t based
Message-ID: <20250807121327.GG184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <882499bb37bf4af3dece27d9f791a8982ca4c6a7.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <882499bb37bf4af3dece27d9f791a8982ca4c6a7.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0094.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:ff::8) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|BN7PPFD3499E3E3:EE_
X-MS-Office365-Filtering-Correlation-Id: b942e929-cfed-4d71-c440-08ddd5abd12a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?axQI8w3VTYtQ5YUSriFu37Q7Ie+PYZ1H4KfTCwRvIpV2kxnY4WC0YXxwLc1M?=
 =?us-ascii?Q?cbMTZRNxCHmOYBy5eTk52kQcR31cLIJacQ+oXZItONC2qt8u2Zu8XIJNpKYr?=
 =?us-ascii?Q?gu0kM7eFZBqOmCJQMScmVxYvkdyFq79o4+asu8uQDBXWpOhKtiTBQ4/5tisb?=
 =?us-ascii?Q?TO1gXmomGnQiCfyhlPKtWUjJWhQFhbqJDXXQEb3XWHf/uds0D1iTj/UUfTfT?=
 =?us-ascii?Q?if/OFKTceOGBXABPR2sFkNv//ZgV2MuYpq373lJwhLmT7LvdSvITw7Dk2TGy?=
 =?us-ascii?Q?zrT16KfExdJ2dogIykgnTAacqFY1GdiloP2yb0mh474ah2q2SWdgy7WGw56y?=
 =?us-ascii?Q?2hDMDaoXNB3+7EJdT+gGGfxan1J9eE3SSZpEo0EAs6iyCvoI3QrsvESzekkS?=
 =?us-ascii?Q?Aq7Ug3SwekNtJvi+h6bEL0HyQL+JO/O8bldy5RAm1U/dSFLxkdFjeooWdhYe?=
 =?us-ascii?Q?bsYjfJ85QBDGi2fzHQKsyoc+8L/rjQmO4svE02zb+8+LABJUkebPFUebZH0I?=
 =?us-ascii?Q?RaDVIVl/B14xPSGwhWIYPkTEYyivT81KwaS91QGcBD25zmAdikz33Xft6bZG?=
 =?us-ascii?Q?lPh0lyooYx8G3l473Bil1oyinXnaB4sWZuy1DuAfZc7o826PRCYqdq4zxy4+?=
 =?us-ascii?Q?kakjsFfEC8Q0qAslgBVUSC6LoRUCk4p3B1HdvZwO0gfQDCkRDJ6lDNgik6cv?=
 =?us-ascii?Q?XDTb3ChTUb/fRynp/7buwxi1ugxtNgbvZGGNnWrl1GWsbsVqsO3F8cTZ4JQt?=
 =?us-ascii?Q?LQu1jS1XNfr+rUCIIuFUrC+qBrsiGSKD1t6zrfaZoQPSEc8PhdmMm4p+nRZH?=
 =?us-ascii?Q?H1094+/bDuXMoCLANgKLaSAIMQF4CdpfEz5LCMQQ68jx8nHrihoK9p4X5P6N?=
 =?us-ascii?Q?jYpsBOBpHVl5lnq75bAXGnoxZ+uw10nHH6iZe7u4kX6ZlfssoZpvdBeyOLnz?=
 =?us-ascii?Q?LtjWmFRu+Jwk/g7XO5D5WQpheth6vm2ElRzni/9d5HHtp5/ZvhjMHcRN6mHO?=
 =?us-ascii?Q?XZBM3ZKiRWuguOnnNngbUY+rO25Z9arZGX/fxnWQ0lIDiw1GOnI7cb5+6ize?=
 =?us-ascii?Q?ZgPXdY/RjlkuwK6Lt6Aox/weShKvRTQB0gf4y/pOw05Ap8GqILFVIk2/dJtH?=
 =?us-ascii?Q?Y8w/rhmP3vMiGMj9PY7cp7p7qb7AZwv8Y2iUTT35R0oTZqCWjpSaTMKH9Nkp?=
 =?us-ascii?Q?bm42bCC9tIArDMLClNbzTHTMKgXi6ZAsJ9/EfCNcg/zNrt0Nul9w6IPKXUyb?=
 =?us-ascii?Q?tM4cmLojMMemwoIaszqe3F0CSUcrb0IzTggrtqUXEAhejPywCBf/Fh+xQYZt?=
 =?us-ascii?Q?E7BC9VeEIfL0ULEsFpq4P1uOG3YGqtIBIlelb5DP6eG6iWO8gPgwPANOHhAb?=
 =?us-ascii?Q?MWaRKqhUyPwrvIdGvNHer0wFh1IBVHE3vsFURjhpYB//6MHcm1cqYt2l9dgN?=
 =?us-ascii?Q?uM/ptoUdCi8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?sR6OLO7WGVDrwfr9yuQJ+2KW/03YjBHbOxYbGMYOMCZYOWwxQoNDiL2pKIBU?=
 =?us-ascii?Q?hdkr7lEhol4n7NuO50U7v2uTIhbvOWPEQDMioCAWwI5WQ+BE/3msfWyjn31f?=
 =?us-ascii?Q?x3BGFqLNyI27rcfQLAUyUJHgLOFy0VsbZNJvK91B/cFod3Qf9hYYmBV5YKIt?=
 =?us-ascii?Q?rtVCIS0Ssf3y2Mt+NT5/um6iIc7xBaLkA9NCGFuWfqdHRLjD1VNKw4VXR89R?=
 =?us-ascii?Q?xUOuHBnZotMvkW+kxl9yx7S5XFzhtHlJUdnn2SGKzg5VtU7MsLR3dmI0I9qi?=
 =?us-ascii?Q?qeyHePnBc1XYOGm9LIS716SdiU4ZxVX3i0CmQRym1jcMjuKbyhmH5lUi+FHh?=
 =?us-ascii?Q?uhcbgVzRk7Yg1oR/UqFmRv5fhMBqtAEQq6oJ/tjnZHZFTaRRSDsBfE6fN6NE?=
 =?us-ascii?Q?JKctD2IVBqmaZaHCZRmRzgY1bCzFAueOU6do0G3DAp0/enFSV38HI2OZwZF0?=
 =?us-ascii?Q?SOMIQDdX2Efk8Fwlq3FWMITrXSexSeNHuIi5BnLIXSciAOvKAl3vOP/E3j8Q?=
 =?us-ascii?Q?wYTJJ8sGYGHkhpJ3gv8U6ac64gsoWuWdxKlcf2SiBpHebo3B4IAAzNDVWdIv?=
 =?us-ascii?Q?m9fnfBAtoOQGLt82yRP692KRPCQ+LkLMKn9Njq0KJWwTH8dBJ97Y8czAFS0M?=
 =?us-ascii?Q?d1ciS4Ip6i3DlQs542nVxucomToNBgLMN+JXvkOXTrJirQ+nCgoX3ykqu88b?=
 =?us-ascii?Q?RLcE/JY4nR3HrwLzy5YeXeM47gnfdbZwTpvyitRb2GfXGxn2Hk9uS7EnE4RN?=
 =?us-ascii?Q?x2MbostRNOUsHQVsnUtiSKT9/bpO+lScdGXvK+8hYcE3wypOuw3J4Q+FbMxP?=
 =?us-ascii?Q?bxeB+Ulqhl+1nXeAOfJaksQCBo1N9XCSbg/Tnq3nEXm2O+Tb2neq/mKopK+F?=
 =?us-ascii?Q?oKl+oXuS0TcMkLo/SMlBkaWMsClLVblgaVuhVGUIeQ07K+p7HSHOLTw+Rq03?=
 =?us-ascii?Q?NI1xJUEg9MBat+O3XeFBTbsf/WCudMezEwerfinT/opXWjlz7IchRHWWmm8S?=
 =?us-ascii?Q?bf/No0jewWT9JekdbUbxOp1MwITG05L/7/4XB7uSinax4/JiPV6DFvIFfFio?=
 =?us-ascii?Q?J6UR/vOAto95/JmCKTKcJ75TwpY+W0sPkMqL6S1uXILQWYkNhTbfw5ZN0JsS?=
 =?us-ascii?Q?rPepZ9+uT0ggzsogxf8f88ruPBm6yxFrr9/BZQRlLR/i+lKSnmm1bhlDQJ77?=
 =?us-ascii?Q?hsP3bc3vIpXfuixt+PZTiZYIU+cPc4E6h+mwwY+hjCEwKw8pf5W7Hk/rkJQV?=
 =?us-ascii?Q?FF8V0Ynr39av9YDx+D6kS59laa1QOn4cc80bgCG0lnCGNf0fo4BHjy9EOOab?=
 =?us-ascii?Q?1xtwoH1thASYwHssKN6HWrkfUXlzgk8Zz8LFFvntBeE2dH0lgaXNOMV5j2Se?=
 =?us-ascii?Q?ZbE5hA7pfDc0PavMHn29DccR3V/EeR10JgW2CQyK9o5L2ZP+0BTd0j5Ap1aj?=
 =?us-ascii?Q?VxFJSMoyvW6BiFVDB41ontdUjBXvFTPLQyKwQ0mUYVZDQ0IrJ++4PecmR3QV?=
 =?us-ascii?Q?AOjinVp4kbGo9305fabp1UsvUHAZHAVfK1uzEXRGyTKhD+3Hc7TYU1wS+QSw?=
 =?us-ascii?Q?DPs8HyXYZOpmOcM60GA=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b942e929-cfed-4d71-c440-08ddd5abd12a
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2025 12:13:28.4489
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: KROhXLqGII19t1me5Y8/lT8ezU6d/PVXc3lHTLvPLyrmNmHxaDMV+xvImfEg9mk1
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN7PPFD3499E3E3
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=YZbvDWhX;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2405::61a as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Aug 04, 2025 at 03:42:41PM +0300, Leon Romanovsky wrote:
> --- a/kernel/dma/direct.h
> +++ b/kernel/dma/direct.h
> @@ -80,42 +80,54 @@ static inline void dma_direct_sync_single_for_cpu(struct device *dev,
>  		arch_dma_mark_clean(paddr, size);
>  }
>  
> -static inline dma_addr_t dma_direct_map_page(struct device *dev,
> -		struct page *page, unsigned long offset, size_t size,
> -		enum dma_data_direction dir, unsigned long attrs)
> +static inline dma_addr_t dma_direct_map_phys(struct device *dev,
> +		phys_addr_t phys, size_t size, enum dma_data_direction dir,
> +		unsigned long attrs)
>  {
> -	phys_addr_t phys = page_to_phys(page) + offset;
> -	dma_addr_t dma_addr = phys_to_dma(dev, phys);
> +	bool is_mmio = attrs & DMA_ATTR_MMIO;
> +	dma_addr_t dma_addr;
> +	bool capable;
> +
> +	dma_addr = (is_mmio) ? phys : phys_to_dma(dev, phys);
> +	capable = dma_capable(dev, dma_addr, size, is_mmio);
> +	if (is_mmio) {
> +	       if (unlikely(!capable))
> +		       goto err_overflow;
> +	       return dma_addr;

Similar remark here, shouldn't we be checking swiotlb things for
ATTR_MMIO and failing if swiotlb is needed?

> -	if (is_swiotlb_force_bounce(dev)) {
> -		if (is_pci_p2pdma_page(page))
> -			return DMA_MAPPING_ERROR;

This

> -	if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
> -	    dma_kmalloc_needs_bounce(dev, size, dir)) {
> -		if (is_pci_p2pdma_page(page))
> -			return DMA_MAPPING_ERROR;

And this

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807121327.GG184255%40nvidia.com.
