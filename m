Return-Path: <kasan-dev+bncBCN77QHK3UIBBKFVZ3CAMGQEAJL6QQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E23D9B1CBB6
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 20:10:49 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id 5614622812f47-4357e99627esf233262b6e.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 11:10:49 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754503848; cv=pass;
        d=google.com; s=arc-20240605;
        b=NuR1g9ukU1m8K+oRcHh+k6L3Pj2OQd5jGvEozImXRkjTw/Xyao0kV350KbbKaCWEx1
         EtK436c9vV92tNYiMqzdBUWO1q9OOXQq3IFwb6elNgg9QUxVS74ge7n/7S3EQdL0jiHT
         HEfNNdTMXaTpiuiygTDSgwwK0rTohqd/PCfTcKwwp570ekOiUvqqKn22lzlGsgrI0o2H
         z4E5qE4FI+50+7I5JxlI3IRteuhgQF5ZG13XCvySc930lLGvNjlrjx3BjfPsSpdafhvf
         2GMuDn6wGVcSrI1MGau3RDKAhriQn3ihYT2Zvi7tAjVjqSaTS5UHweXoEEZZwcvg50hF
         jTlA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=fLTJYpC344HWGKm0De0miU/2usfL4wG3uQsA8eBgl0M=;
        fh=suHmftWzWFX1iRsQzbdT8Pm8Tl84QJmxEozX3BDHhLc=;
        b=Y52SFCj++1923bOVNN2Eb99rCKUX9gB7WjHzdk8fulGxVwEdyZqbmKCgG3wSAdA4AJ
         0N/v89NRzm2KzbTnUwaYgC2E8MZyuT6lay0qMsq87ZjYEIZUrARrRcOeui0f9nIziDZI
         kb1+LZ7UeMQ8aBFRApugZ5FZOoT/IkGkqwosjofN2N0QidbIqeLkHdBSQ7dcuVB1gYG/
         JEK1IqZ65mE6owoszJPZMstBLXY22DXH65ex5X5LP2cw4wyUberLvwsocmo8otjT0NFg
         MwzGMHr52z4RG4UWw9p86Dz0QdUO9VzVzlbK3Qz9t4kw4H8Qt1k4GQGSefYr3lk95WuD
         V6YA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=HPdzjbYj;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2407::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754503848; x=1755108648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=fLTJYpC344HWGKm0De0miU/2usfL4wG3uQsA8eBgl0M=;
        b=rZfmJlgYQJ5PhVI06uwEek1f81nrCrdSa1itdAa7Wznd8BBS1kb0Wlwp/B904xraSK
         W8bCfQRmypQLF1y6j4A7ahi5UCJPY+x1j2eGSQV04KrkPj1DYFt89F4THYv9KRjv9nJ+
         sMal/fTdRWJxYxpHeTk0S9fl4lLHs+4DE9LHIEM5UMnrQgQbhoBhspZZTG1Skm5+t29i
         lvY+yf7Lex8CKTX8SJkPj5M1s5bTi1Xnv/Gi/VEHYo/SjGsqGWzD3/lAVjqp6cmjGLwb
         TJmitnwhRgtqMuPf4X3SybQkzb/14YTkglMn9l0Y0EbK0pMcwxyYxzvNMFIAgBmjogcO
         nt+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754503848; x=1755108648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fLTJYpC344HWGKm0De0miU/2usfL4wG3uQsA8eBgl0M=;
        b=jEJOX4ogRCRaphU90Gz0s3XdJO4EzNe9iSUPODHqEu5+cdDOL8HbM7q2XAR7pd3c5f
         3U0cEGvbmZEdxvf3yIY4zK4FRS205BsBhNmgYEi09C9bShXOj21gx0aX9gzEh82Xlkhn
         hLXDM0tVXHOn4dl3vkHmMclun8eU/hTqHgbS/tOVK/cSlU6efC/7ZHfM+HURoIoQRvUp
         3Wx4pSL9eb3W612nr4OU5jJOWe7zRoNOXV2Qjw0I12qucVrjvBJWe7G3EiogRHbHVgTR
         uzz2W0R4DUSX0zNr6rHs/ARxt20s7/d1BQL8OvfMCZMJv5lgu30y+2bPHkumS8s+4cEj
         0Yyw==
X-Forwarded-Encrypted: i=3; AJvYcCW4ZHzMHafETjMMQcZXXspK0OsLJ8L/C3w+89FtZddsog0uNGKloBKqigBE+9GM23798n6+cg==@lfdr.de
X-Gm-Message-State: AOJu0Yz6K7Wsl8US+O38QWFtARAy1QY8ADS+nM0tMHRi+WiLyMT+s1DH
	2tUHa+hLDqDS6QlEDiUQJeeR88wVGf8B/vYunZp0aUhPKM/31/hhn6vS
X-Google-Smtp-Source: AGHT+IEmlcuZkiBaggyAZx4e87kexsAGySiU+3xc3pV6wTpnKS1mFctBkV7BglSGOtg6tGyu0h9tBg==
X-Received: by 2002:a05:6808:190b:b0:435:6f95:e850 with SMTP id 5614622812f47-4357c5e7e85mr2044990b6e.31.1754503848423;
        Wed, 06 Aug 2025 11:10:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdYoG+TGKLPGhwFZojy7LTQZYbEw+0lft5cXnA4gfEAPA==
Received: by 2002:a05:687c:2054:b0:30b:8494:7c57 with SMTP id
 586e51a60fabf-30bfe81dffbls95060fac.2.-pod-prod-09-us; Wed, 06 Aug 2025
 11:10:47 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUfdOOoEYDAlndLX3JRQeY0H13RHD+2PatmAMVb/rWGX5pg4R/chTB4zdAsAXcNdCj8FeuSGZkDalI=@googlegroups.com
X-Received: by 2002:a05:6870:1f0d:b0:30b:6fa2:694e with SMTP id 586e51a60fabf-30be5e777c7mr2492768fac.9.1754503846961;
        Wed, 06 Aug 2025 11:10:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754503846; cv=pass;
        d=google.com; s=arc-20240605;
        b=QKa0qYHsg7rti3VXNQA/8iernfc0yGYhZd0bhz5eOf1n9pZuuxOyOZ424YimAFeeuI
         CxZa74mY6oFTjQ22Ha+ntkTH/Cq/8d0WWcT6qquJs5buYm2TEjzXr8Q9CVDUMKHAwK/4
         d2bvQWkek2zdfLG66a5/ub5QWzvn7zttgIU3YeyQ95f31RRCqDTT3V8aBWRZJ2sYa61o
         hAtvBr8COhaoGnE+pVnDS3MClviYqPIhxCuHkAYCxb4XsuENSo2eaOJ//sajLLBCgzCG
         6R3TZ44kZAdIlOemBNyQVjYhmjLYxnaR4WKYyjwWEi4A2aHUkxinO3QL4uPepdmTjm+2
         hyMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BhmvRULt71lzNlfdmUfFLRjqdndltyCAJJ0V75nB3/U=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=MHMg1QTDmzK3czPhiPlJPYhxPHVpiMrz3Ugok9R2xfYRm42cwJdUQaMqcE4eVGmKmX
         89AdfcghIaRinfuMkCpVYjPEdrkanibn7gf6A55bW6KwEnbZrTjhrXL0YJrGg0/xYeJ8
         d8AHloHTh1TD30BjAY/rEC2WqZDnxUoZkDxK+ybKFP8/hzIjDgmgvP+Ju8eqovxI9rgE
         gRH//QkUzmTZWSPrE9L7Stt6/dMtj2fbg7soQZr3UKOEOp/GLA1lD2qjYMfr6F0gP8tV
         SyH7GaJelvq6+HbThI08okAAWriX6wwCrSJehaJIlTBEp6i32CVR54YEEEvZmE4kfkLQ
         2dmA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=HPdzjbYj;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2407::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM02-BN1-obe.outbound.protection.outlook.com (mail-bn1nam02on20620.outbound.protection.outlook.com. [2a01:111:f403:2407::620])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-307a6bcecc2si683029fac.2.2025.08.06.11.10.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Aug 2025 11:10:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2407::620 as permitted sender) client-ip=2a01:111:f403:2407::620;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=F/xGIwO8l037lIet6XDnEcFADS1S4j1v+xJwq0xbosit3tvuqIY0absR1Ze6wMZ/TKCGl5espW1F2qu9dgEs6hTCxmawYCRVyDJjqkx7uD10rBjCwn9thhOntxISwFDEopAsxahHsMDlteNOsTJTkCdL2YGQDqIORFmMOM+3FPlwgdzAeqB2dGIczqSr30NvwqpnUgihCVGp1w5qoXa+kZKJKBiL8eIGeNkj+On/3ej5JAQzmOa1eNWrANLxLbe4sN9Kqc3Ro6ZWap3O9DIHRdwYlqL09vOTdhX/ylkh+94s1oda8c4XWXi1LgmDah3KH5A6OmG3mbY2sYOXPqS5aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=BhmvRULt71lzNlfdmUfFLRjqdndltyCAJJ0V75nB3/U=;
 b=OfRNJMP8osnjMHer6JHInrB65m7fKLygp+Zaw4kPvI/fO2epH1i54gQoMtc/g7fcD9oCsP3R4D7x5HQrqLdVpmAjYX1fI1UZo2kgN1eJG+WzQgWenMsETr6zko5fX6OsVPba4mqTddkBLydlbQkDWEzamKI5CDfzaVKtaSIzRY9RSbKuv5DjHhaQ3Ja3mWJpxdvT4gdOv/JxTLdThDEal0FfLizU8YSyasLE6+Yebri6vKbxL5AfS3cu8gjlyHfcdXsqqbB6fv3jl7ZY4TUVG4eb5xOMbSDNyXi+wBRbChzImtDLGpmevb9ks0SJ3eQoWEXQCPq3fIHE7DyNJRxb8g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by LV8PR12MB9451.namprd12.prod.outlook.com (2603:10b6:408:206::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.16; Wed, 6 Aug
 2025 18:10:42 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.013; Wed, 6 Aug 2025
 18:10:42 +0000
Date: Wed, 6 Aug 2025 15:10:41 -0300
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
Subject: Re: [PATCH v1 02/16] iommu/dma: handle MMIO path in dma_iova_link
Message-ID: <20250806181041.GB184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <52e39cd31d8f30e54a27afac84ea35f45ae4e422.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <52e39cd31d8f30e54a27afac84ea35f45ae4e422.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: BL0PR02CA0041.namprd02.prod.outlook.com
 (2603:10b6:207:3d::18) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|LV8PR12MB9451:EE_
X-MS-Office365-Filtering-Correlation-Id: bc710f14-af91-47c0-1a00-08ddd5148e90
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?wVLnAhfU1oPkeBVGmvAU/NjH/TSeWNoRRIFzWOltqiha8M23FQAybsbpsbZ8?=
 =?us-ascii?Q?4l4viwCu5culuho8iDDBGWEwTq5CXF/Ngqk90oWIfIjUq5vAwtzT3hhe1nou?=
 =?us-ascii?Q?RfHnvfTyjNJJBuNajTKmkrOGxuljQcHezyYYeUOLG8J7e7YhoUfBKi18txfI?=
 =?us-ascii?Q?hy7/LEu5hLaURAAotyzklEoBhtCcuF7b0wjIbikh26fAB0AZcdevouc+gZJl?=
 =?us-ascii?Q?ti3ebAKulXWxzMRy1HKeWCwDMydUyj8or18L2n2kDgRFSozaD5v5MYot+TdF?=
 =?us-ascii?Q?dKxC2QBL/XGhT2R//kxm/Z1i678GXWr53qAvo6Mc8mHvDJOsshvXhzgmGGB/?=
 =?us-ascii?Q?1Y06utPzxf9qZyCI2F1LJWhLSf4aNoLYR7ieU2V2hpnKr0S2IdGAXNglv/V2?=
 =?us-ascii?Q?NbgCREZxnz6y58V3BD9Sto4B8J6D0WmOSREtfBhKzVNd+wqZQEawog1Fo6l3?=
 =?us-ascii?Q?eRHt230nua56QWjnnXCSpemvdaFAgSKyHpP2nrc0T8ngDw+BS+qk/NKK9dKv?=
 =?us-ascii?Q?2miix6/Inv7eZLR4QvFRHYlQVH8fCvteG8WevBDiAT1ifHwyS+kdJMH8MQGa?=
 =?us-ascii?Q?h2oeqnJ+pRCKKqoq3l7Xdxtc06wtRFd1swF3vJw5r9832y4wpSyaBH0ABxQZ?=
 =?us-ascii?Q?/TX07M/n/4wX45/p1sgbqJYIOsZ0f4Kln/pnJIVSKrohhzOpGyheofoWZZwr?=
 =?us-ascii?Q?zXK4lEn71gfSBgA5dXwibv+GitvdQntloKB8klvUD0TvVZmtwBJThY49DnbC?=
 =?us-ascii?Q?SaGwAetiGd0ewGNePMd0j77vgGJ3S9gqeItBg9HkWW8nbdofeXTiplfgFybO?=
 =?us-ascii?Q?lNs6BYW5LAGJmg5Pnawnlkaoh+Nu2SQBxWVZvByCSr2ZHmU6y4hzSYjah2pp?=
 =?us-ascii?Q?1GZgNFRY32XyTX6LfRGJggIvzUvpSKMuFrq/0QbyskUfTnXJtDJqF0u+r0vl?=
 =?us-ascii?Q?FHzw8sLP+mEJIfzWRclp/XpMBrRAtaUz7RJbNp49GDoGb+fHebg/sui6tJqa?=
 =?us-ascii?Q?wBts/fdjF4cWzul1birOsqA2+3Pud2Qkx8i2mJUFiA56ilpf7GZYh/4BAKqM?=
 =?us-ascii?Q?OAzISkmGBsUomFlDjgPXqH/Qtpqizg5ROAIex+09zc5Y9oC7rG28YV1LqC94?=
 =?us-ascii?Q?egOWspWxPkTJ+R+F/qXelpRIyqn/e5juK2Wy3HEjN4aUfEMGE97D0f0V/Yij?=
 =?us-ascii?Q?syps8uDsBntlosNdSlMw7fhzyzdd06tVoGAh+PdjNimZiG3526VvcP3FONDU?=
 =?us-ascii?Q?KeMnRP53LaaCcC4Lr3AycUDXY7BzbMLA+NiIjU7SYQ82Y4tbyP6+KXMLO7oR?=
 =?us-ascii?Q?KZdVJYnIwvN0wJ00oOIphNxFr25xv8l9YxKjGSH9X0lfl5uX35COldoJjmls?=
 =?us-ascii?Q?N3G+dMU9uhXhk6kUq0/AGJnwyceFZ8ROJfy6iKa44R5ANOUgva4Iwo2J4sMs?=
 =?us-ascii?Q?1Yj7dqgsMO4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?jxar6JHm676v7S2VA0b2tp/6YMZTPFXTUBggGgPT3+7w2y648Aing5nielgU?=
 =?us-ascii?Q?C8RGQR5E58Tovl/J41NfvXPwqo83HFAte/q1ThYUU8DpXUJ7xyiOtLI1agTm?=
 =?us-ascii?Q?cJCIeUGMb9nlAL6DL4HqITNVhi1xiGzDJTxsise2ikW8UjN21FJkGKqHdOUx?=
 =?us-ascii?Q?X/NlDLBiVPvSQUFkiKhqQLbU2EEshCknX1MeN/X+GTK9p7yYbr6l2wMFcY+9?=
 =?us-ascii?Q?ND2X9L4Sjj6dAZp144RnyvH9xB1EeMcQ3MsqbdVYA2Ohb6AJiP1WZuEE9jTE?=
 =?us-ascii?Q?XFged2dzreWxtqlRa6tgiGz7uZkQbLA36UuQlGNftfAreBjl1O5vF36LOuVR?=
 =?us-ascii?Q?zTHLQ2sKkyx+9cLiddBDG3UiMuXP2mRrPQ017uORc5S9zBMDpq3jpRzbWLRT?=
 =?us-ascii?Q?OVurgCMW1L9Z6zBg53ZYKRLC/qgk+o8quUk6BvWqo6W4P5Rd5IMUWHGHBi5y?=
 =?us-ascii?Q?zdrO8nCMOYop7lH+MmAFmSuLZhUg6mt/5V3y9Fp/vWWfSmLAzwsQkSU7dsgg?=
 =?us-ascii?Q?IAB3+JkLsRIpcJduXAoL+sT45A1wQHO/TB4imafngd0gcyTT8Nm5dui7KsQu?=
 =?us-ascii?Q?ZAhJZZJ3+iEN4Uo6RQYdG3oU5rGuY/gZN0+7fSIcjdEYFy8qUweayZycVBPS?=
 =?us-ascii?Q?uZTvHKGucjLJA2HHCw5BagLz7ijI619ndghyaq4NY7lrrhDyNS6MdJb9zDTh?=
 =?us-ascii?Q?2ZeuZx7xpC8KaV9ALslVxl4yBLn0WACNoPNnnl+qKNv9Ld8VGZa92JNAkL6O?=
 =?us-ascii?Q?mbSbXlRHXr/hjkElMKDR4FLunfOidt0S4xNZeK19Fuk3N2Z55CsnM5dni9n6?=
 =?us-ascii?Q?AZ728B8IPw3/FN4p5QbS/PdWs5zSXzyPNfdPLZxq9RH1sBV2zdLc3Hjj3BHu?=
 =?us-ascii?Q?8LDmyMknR3iaD0SNhgHj6TZ85GYy/Tx8lFGZAF4XQ1LGJnO5FifPUQE4QmaD?=
 =?us-ascii?Q?1kP0GIcg8w798usyvr0wYVhs4GZo5+Zpp3b4dpymUYFqmXP2hQBqYCP1bM3Y?=
 =?us-ascii?Q?h74ncSMb98quwFZXCze2mn/T7w4TnOnr/4Dcp9XX2npo95Yj4h9SYCXafZGe?=
 =?us-ascii?Q?jVL2DPa9rh+ENyPMGZLYi3KcMJWqmKkGj8Jvx5Ypzo0LsTRiHR8GsTpKDvr0?=
 =?us-ascii?Q?BTOXJuD8u1xnH5J/ttsctfR8qI0NZ50tfYg6KKv6dOO7kwrpZpsqHiCzA8M8?=
 =?us-ascii?Q?8d0LTLkulB7BiIULaMxBzFFXkXy/pUia/A51+edj5UoRdDi6Ef7h4QGrxd/Y?=
 =?us-ascii?Q?UOKnpmM9pkkJkhcM1ufy1RiOi9tFwSJhgqM8ttWgYxD0qePXUBTH3eYMoyhU?=
 =?us-ascii?Q?TUzWO08a7crrOTEWta5HWlFQ/WxCNtSamczRCSy2ZnNeSD0r77+9YRkskgZF?=
 =?us-ascii?Q?llQ6s964oNLxAP1n0oPbz6t2VSbJe+pK1mJMbHJFWwYFZ+zSofvu4kiYHzRC?=
 =?us-ascii?Q?KICyKCvRLsCxNdOToQbBeBEJNAp8AcjnYdGopdOCo1EWynuitRyDGJk/V5CM?=
 =?us-ascii?Q?VaBwfFAxVDY+usMsHxhCwVNi8gUwS3FmQuDxqFeLd4A4XIh04K0X4u7fUifG?=
 =?us-ascii?Q?zTlIkUmjnOYfRUF6+uo=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: bc710f14-af91-47c0-1a00-08ddd5148e90
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Aug 2025 18:10:42.6495
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 57xtDWWsAmS2DZ7qtHKMR4Dn5D+k0Cp1JThowypQclS3wEaF2KtlmBeaDSAVaxXY
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV8PR12MB9451
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=HPdzjbYj;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2407::620 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Aug 04, 2025 at 03:42:36PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Make sure that CPU is not synced if MMIO path is taken.

Let's elaborate..

Implement DMA_ATTR_MMIO for dma_iova_link().

This will replace the hacky use of DMA_ATTR_SKIP_CPU_SYNC to avoid
touching the possibly non-KVA MMIO memory.

Also correct the incorrect caching attribute for the IOMMU, MMIO
memory should not be cachable inside the IOMMU mapping or it can
possibly create system problems. Set IOMMU_MMIO for DMA_ATTR_MMIO.

> diff --git a/drivers/iommu/dma-iommu.c b/drivers/iommu/dma-iommu.c
> index ea2ef53bd4fef..399838c17b705 100644
> --- a/drivers/iommu/dma-iommu.c
> +++ b/drivers/iommu/dma-iommu.c
> @@ -1837,13 +1837,20 @@ static int __dma_iova_link(struct device *dev, dma_addr_t addr,
>  		phys_addr_t phys, size_t size, enum dma_data_direction dir,
>  		unsigned long attrs)
>  {
> -	bool coherent = dev_is_dma_coherent(dev);
> +	int prot;
>  
> -	if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
> -		arch_sync_dma_for_device(phys, size, dir);
> +	if (attrs & DMA_ATTR_MMIO)
> +		prot = dma_info_to_prot(dir, false, attrs) | IOMMU_MMIO;

Yeah, exactly, we need the IOPTE on ARM to have the right cachability
or some systems might go wrong.


> +	else {
> +		bool coherent = dev_is_dma_coherent(dev);
> +
> +		if (!coherent && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
> +			arch_sync_dma_for_device(phys, size, dir);
> +		prot = dma_info_to_prot(dir, coherent, attrs);
> +	}
>  
>  	return iommu_map_nosync(iommu_get_dma_domain(dev), addr, phys, size,
> -			dma_info_to_prot(dir, coherent, attrs), GFP_ATOMIC);
> +			prot, GFP_ATOMIC);
>  }

Hmm, I missed this in prior series, ideally the GFP_ATOMIC should be
passed in as a gfp_t here so we can use GFP_KERNEL in callers that are
able.

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250806181041.GB184255%40nvidia.com.
