Return-Path: <kasan-dev+bncBCN77QHK3UIBBUX2YHCQMGQEOW5XOVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 92371B3A533
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 18:01:26 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id 71dfb90a1353d-53b1736edb9sf1391265e0c.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:01:26 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756396885; cv=pass;
        d=google.com; s=arc-20240605;
        b=g/mwYKJ0ZqODBAQgMBei4B8S5iyWypgu2nq4kdCp9Ilqqg4YpGPg8WD9mmSqbR50U0
         TJT/FsmN83NUU9iEhEF+xiYObeC8S0rv7rE+V8CApt9d2mwD8S1bpG/0QP5G+IJAYeIh
         NrFrSWAtnlo7QbErWC+gSkEwpHQSa/nZ9FYCf3//Z/Xbr2qCmnIZ+tr/p6s7nC4g0sMh
         lO+b5J9ao0hK2Zj7GHucGwK+AWnguqDNWoggmQn+fXlIeP0HVCRxHqo1kZbvZu03aHfA
         1frd5fwTKCjP5DVJfT9xYy04AJauvi64va8YkD0JUTCw/FFx+3zw0fuuEImu8qIZlsDR
         KhJg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=l1eghwEJaZ6g7bH/FlYkIeobT/xCDEkXuqrlcqzvgGE=;
        fh=ZE3TTJyX/Y7xXsyDCuugyS0gdk32AEzGbgSq2aN+138=;
        b=NbCUQJsoFahsK7UrcxgJXy9Lf5sfVJua2+k9VIczbxG9mpYEJV18/lN/awYXXl6bQ6
         YUtRzuy99AOwDV4P59NbVzxmcL6wwS7v4JzNCVwutCfr8XAMSo62OFYFwSiPsC+TLCSu
         J/D+TUofOi4zMD9DQotKB6m64F/43faIcKbnfkohBU5Aps81+mmcLrLs+GoHby6DuY3F
         OSPf3Bh2NvqEfvoczFPnQkpAuf3DkhrlLAs/wyp8XwCwR0Fqhav7jWuFuo1ENFZZShRf
         6+0/+S+qVJKicC6zv6Kk9QPtTx+AWkGSjTeUSckfzdS2nktssFt9LbjwSLi4BYEUui4H
         ercA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="NK/a1uBn";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::601 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756396885; x=1757001685; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=l1eghwEJaZ6g7bH/FlYkIeobT/xCDEkXuqrlcqzvgGE=;
        b=C/+RdMgRO5TX1OI24a/QXwFTxglu1LKowUNgfhI+LrOTSF2MTbcSgdnK+6y+w2Kidy
         pNZY0QHUVlproN+X05zaakQWn3YAXoUGMnO9jqhjRkttvP591ncjjXnvTlOiCPUsCxJ9
         q3GdtuPgrf2DgMz3w16/kqPOGGcG8qrQFUbqx9hTOkMbcYI1pbhKyHTmx36uH1BqmLK2
         V6CelUNWhaM+SP4Ym3WWDqiRH9tMMnfsRTdOGuYtyymhxGaV42QkO0oG4zuMb4M3vRYa
         ++H4f7Uu3H6kKE+pw4D4PI8rgEtaGQqj8aQM2vInTcRFVYmmaMKB8kfsViZBS1rIW+B9
         clOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756396885; x=1757001685;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l1eghwEJaZ6g7bH/FlYkIeobT/xCDEkXuqrlcqzvgGE=;
        b=YQo0qo+ZCo+NAHwyOuELRF2DmRfXuK8kGtUs3+YPdXQmfY8/+Rw854oHyMvz7VuMgT
         Zl/5FDGT4Pd2Z0dRd0lThiNbSzke4hIUGPJhuMzOWSFq8yQ+6XOuKdfaa2+BdaOp3Dhi
         jjR0HtpTbmq5nl02iml/qW1WURyM/1gPUtlGOcDGNdQ51IX3gBIRGaQB1LrXKJyhDhxu
         pbb8ofcrRD/uxD40gz2g0AehDdzvHnYw+sus6soyZkRVwH9fdy1d1ZNaKLVmFMSJtHLQ
         VW7AEDA6qOChyyzitbi+F5yGuK3gmfPOOoTD2HARzBOMLCPrCwVIrgk0sOhidQtlnRYp
         9mhA==
X-Forwarded-Encrypted: i=3; AJvYcCWL0oEo3jc2wy9d5Tf6NlhGqYDowr78Q/LYTxP3uXHDnJcRjgOK+xJBVbe3kOtTnq9g88zpoQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywuk8y3DGGFZcaK+fH4xRT9jq87Pdi5KEPA2RfDjKvqfbTxtnWl
	egja/wLdQ0tZeJDbyK9MMsHwt8YLc5sqNn77WdpulS01WURx6Maq+hEW
X-Google-Smtp-Source: AGHT+IHugH8nkPKvMh8eDWAwWlVhY1DvQGWD/8V5ipye2uy+jXRPZTBh+eYnBr2BQr4Mj0f7aCgv0A==
X-Received: by 2002:a05:6122:4685:b0:542:59a2:72fb with SMTP id 71dfb90a1353d-54259a2791bmr760090e0c.9.1756396883059;
        Thu, 28 Aug 2025 09:01:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdfM2OsBwr7O39Mo2UwDSVGv71u/XrPPLDGc34bz2UzAw==
Received: by 2002:a05:6214:301b:b0:70d:e7ba:ea21 with SMTP id
 6a1803df08f44-70df04b1e47ls15833416d6.1.-pod-prod-09-us; Thu, 28 Aug 2025
 09:01:21 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUBW/8piBIOMxR+ToYPspXDwuHINi1RoSRMGJMQ5Gc+JiKsTOzRM3nk/vlinPxuEBVufstn99cZYGs=@googlegroups.com
X-Received: by 2002:a05:6122:1da5:b0:544:7057:a812 with SMTP id 71dfb90a1353d-5447057a95dmr2006405e0c.3.1756396880926;
        Thu, 28 Aug 2025 09:01:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756396880; cv=pass;
        d=google.com; s=arc-20240605;
        b=VQQc14wHP+jnk0+Jch+2wn5ogm2tBrZeLoEg3MLP0M5uwrNxqvaKYZhJIbGnybGmD+
         c0iyImIxa45WjP5iS4sogTsHWoW3zn6KPt8n3sp9ITFF4Cw2ctqtKavf3hZayWHgCzaT
         ET57kBZpPvnBBZrfWpzShwgv8E0J90of2KstKz5nETrI4vbpCYKLMtQBGBKyQ0u3gi1X
         MBz4SbsYJY7MtVkjuaYfPdA7i3ii4BIHC+6J7gP17Iu6sUV+fdemzeuA/A2HU3Tgjqrx
         C55g3d7sMf63aPNAHbpn+nS45Uuc5YLKdvfRJjM7TxuKdQxN/Sofr7+D6+vBJtQupOHt
         24jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EdstHkCHpawpiiJfH9Q2VpWGfYVCpet9NlPpEzQD2U8=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=SIVPKldMMZ2HJMFN6/z9WrvMr4qQCkc+Mlp+jKMUK3nkCa6iN0RJYZ2jzVTPn4RHmi
         8dfMt9IiVaRmRyND/wFKobm4k4muSkAiR7aI7AU+ADhUNn4zlH9MHm/y7fY4f0MzNqEK
         UFs8CaU3cOKy7oqPl4AyJbr40u7AWe72OBSOQasTUaMwFCrPOB8NwoynZLTltKOqmESW
         qPt5XOVYD7RKEt+nAxX+U0wNbZeUjhutlZVtTB6lDtLz6/qWoQbGSGAhSH5JGEOeVy81
         QRJoU/CxikD4Jb7Bx0PH4mPbLAnpbPKwnLxXLAPdKzZjnpR9361Txo91xi/kgN5U2F6s
         5aVw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="NK/a1uBn";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::601 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on20601.outbound.protection.outlook.com. [2a01:111:f403:2009::601])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5448cb57284si4817e0c.0.2025.08.28.09.01.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 09:01:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::601 as permitted sender) client-ip=2a01:111:f403:2009::601;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Om/BPnGW3ybONVhhNEzf2AuwccXH98py5hPVxqOuSAk8HTsfTTcptHZMlv6jpYYBU92ZK+PNh8ZUsKOXl40b+OE1tjbRZG3kVZQt5Bl3l8Ct8euqFGDFQqPhYNI+Wb98DKmf9vt7PclZM01wuVO66Q+CRRZFOKoIlIyrEptnCSCy6lrKRu7TNj/FyoID8j6b2VJ0tmbeE84DFMOwJhel4Z5zOmxmog2aBLvHoLnKE3k46CC9rnzWZMZ+L4JkI6u1Uxs0uZEYDOrtcqkJBZKasDFE7MkBg262FA+FYTt/34oZ0SI+utZNuFZ45UZUNM2l9G8FPMRik398ojmybHIRag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=EdstHkCHpawpiiJfH9Q2VpWGfYVCpet9NlPpEzQD2U8=;
 b=u1T5CCxCpwnppSirsnQ8EB332l2COzmGJ9dSqceybYnbMD6+MOvb1+w7vX4UvZoQ4Sq6DGTEyf3oPYEnIP9ylgzpEaonEAF2nLmEsjKRkG1sX+oep5dhagKK63dGQsq4Ec3mOLRsiIJi5lxvxoh0/MeyHHotivEEzl/FXRiQnoRjGcIDnVMrvg774MySaNpZvYsFUy3ZUYVGy0AomzyoezwyBUJMl33iYpA+zp9K7fu7ClFNZgY/ZFacz+KJqXkhhskY9Iu7vS9r3wWgUh+Hsqfs2dvQELAuY1X4iNk3kN8FQgYe3K5KI3GH+KLJN4uaQQYOn3+KuRx9mPtyrVR1cQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CH0PR12MB8550.namprd12.prod.outlook.com (2603:10b6:610:192::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.22; Thu, 28 Aug
 2025 16:01:12 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 16:01:11 +0000
Date: Thu, 28 Aug 2025 13:01:10 -0300
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
Subject: Re: [PATCH v4 11/16] dma-mapping: export new dma_*map_phys()
 interface
Message-ID: <20250828160110.GJ9469@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <bb979e4620b3bdf2878e29b998d982185beefee0.1755624249.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bb979e4620b3bdf2878e29b998d982185beefee0.1755624249.git.leon@kernel.org>
X-ClientProxiedBy: YT1PR01CA0154.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:2f::33) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CH0PR12MB8550:EE_
X-MS-Office365-Filtering-Correlation-Id: 7b90076d-92b3-4e53-369b-08dde64c1bc6
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?h5QOdmaL+pLjklwJ1hsRTUJ0TU5FA04/ChUWDKTTEIqoQR6UG8DtCAMxdfY/?=
 =?us-ascii?Q?lK3Mfl4rfLLltCVSN5mDcwgJqgbNufDwFgGtWFjs6ScwJ0jcR97gU1LEqURR?=
 =?us-ascii?Q?1Qom41k83JxNkuc1HJMc/tT3qq1nEdc6MbzoYJZpB+Q+XmgmKcVP0B1lnSeK?=
 =?us-ascii?Q?LfjDFxgyfyV7oQTjibvCwJpJW6Bxh1Ps+o93NY5EKKWKCZJD7E76EC4yOIge?=
 =?us-ascii?Q?3QOBIlsZsXdFu8+ziTPOZe4bukBIQcSmJvSgo2/vY/DbBllOJ0ndP4YhNZjx?=
 =?us-ascii?Q?m8H3Fas4GJXij5lUQChQFPTPCoPfCZr1nrGARzLf99lU2FkyTMfF0I3xuYBx?=
 =?us-ascii?Q?DwYyIyJ9csKTf4EXyEsrwKwx3qrcnWoCqII5HkuOEKG1/JefAdeVs+7v9tLF?=
 =?us-ascii?Q?6vb6T2gj7Jk2s9ttmqUF29eaGFMf6u6i/Mo3LvOwtB0WLpVNGlCGgu+tWhpm?=
 =?us-ascii?Q?04w7sZE75F/r4qldip8G91NgKjSpUYfARvDxILl1Q0yocdNf1Urkg+HcGkRv?=
 =?us-ascii?Q?7ha0KWl2DLagKMUArRKtMOT/PW7y9kiC9n4RVj9/7OG0Fdh+U/cauDu4P0n+?=
 =?us-ascii?Q?KQKskgvtRUjpeIBGNIMmc3ixSwcEIVe0Z2qhBsllZ+jUm6mjffbphwI30gAP?=
 =?us-ascii?Q?Lm1Xopxg9YnOFFGEVQGUOlZrKc8YFaWn/01NCqTS243i/o3AdHPjMoqlmgjT?=
 =?us-ascii?Q?VKZF+H0BRsjUq21SxZYirHgJanOtCxwPyt23Y27qMYBQxhynXpKBOC/pfUFt?=
 =?us-ascii?Q?RO9rGjkwIRsY0bR7Q3wzxFfyvyX6WrZJ+mxuHUdc1TX/FLT6LrjUjqAgAC9N?=
 =?us-ascii?Q?IN6p4sGFDiRFgwxAJtAsOmMg4kb4WCysg7Hi2UGE1MQXK383JCIToz1Lnd7/?=
 =?us-ascii?Q?oTXyHs0pkjAvn5u0IrS9zoTwYp5tnNnPkX1PZWrK0G5pmqD/ZUVkY0l164IE?=
 =?us-ascii?Q?erul3smld5KgOtIduhg65GNKa6Xq11iWjivCWxZEZd3pXpv2orkd9v2h1spy?=
 =?us-ascii?Q?vHKR1w6GA+KsxrE/8GDrNdUXJssFcdaPf7Grj5eGUyHwTd5bfUoBxrDhArCb?=
 =?us-ascii?Q?MX7LUIy6jzi7kRwAVK5+WIAiQg4J6zYF+LaFSpCnHde9olb2xyoS71dgDd7c?=
 =?us-ascii?Q?XzahdIlMbpPO0Ic/VN7aGTWMXaQqDDmExuWXlv/yig4nTbcUF+5OOwUh/XKH?=
 =?us-ascii?Q?hcTb4CntXjiR+6qAMQy7jVCVPgMUuipCBxyowj+VZ1YwokJstnCUYrvU4mxO?=
 =?us-ascii?Q?3N4fQrL1Gy6cvV4M1t4x1bEgwtlNyRrdh66bUr0+BOrgUGzGHV+EH0DvulVM?=
 =?us-ascii?Q?+NeQ5uqiAcAQkHind7ExXp6nD9Ik34uMRD4TyRItoXasxcWdMmG4X2bo28Lw?=
 =?us-ascii?Q?IIWn5AzUZ6A8w7GP9UsBFCuTvNd47A2xjvujqV6E55ciZoTxgq1rzRPwdpkP?=
 =?us-ascii?Q?QYK4ULd4kbs=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?emov0xpwdzd0eWxrHayyQ7BNIYV0B48ZSFkY8q+Iibu6uGJ1cqJOC//YpdY1?=
 =?us-ascii?Q?4ttE+ETLilY0wpbs3ECP6dzeOge9VxxTZfTKfaTY4Du6hNH2VFPxiWXGaHdI?=
 =?us-ascii?Q?OnjnmtgMmhIZLhwJ6BOA7+6kixnJyYYRhzUiRhZLa/EJQ4Tpmr1uyGFzzwqI?=
 =?us-ascii?Q?X3bYusGsggfolYa4h3kQq27IiMGOQchw23QUH5DBm3EppzV1bsLWwkAbKA1E?=
 =?us-ascii?Q?xwvM/3mjQlSk7VKa/GqQ/7MgtC19p8lRT5XgZpcSRvgLeu0LL8xS25kHgxRx?=
 =?us-ascii?Q?w9M5gnmrn1oF4azTs2w5dFKqlt6MZRY95P7mH3254cYanv1PR3NWxpZMWbJU?=
 =?us-ascii?Q?5at4WjuyDP3YQJ97njw8klZ9uBNoOzi1O8SjmNwbPpqEJ/c32qjajdBzJi0H?=
 =?us-ascii?Q?TX6LhgmZ9ixJ1XQX49fS0j70h1fmEN5PdLojmVrS31pbr8g3tOyMnE2fXtVJ?=
 =?us-ascii?Q?ZDAX5j2Nx6CYOIm1SLb/MIYg6VJMwVmCk5Ba9AKt9GPhAqA9KtngB1sq3+Hf?=
 =?us-ascii?Q?I3HT9y7DYyyMpuYWoBgzhi+8jhj/pgc9UBBcc6VxJx6bD6/So/FUZR/3zttA?=
 =?us-ascii?Q?q/cT3T1PL7qWwIda2n3zyjYLHCTVSuv/iCIXC2m/om2THcpzvlJgL99BV1AG?=
 =?us-ascii?Q?4tltcoIjgDSCt88uqUIn0BIZITXm78neuB9uzKtZ6pV8zWHLfnA/Jg/yUZjb?=
 =?us-ascii?Q?AZXtMiYgHSXip7KeMP2VDoSI1S2DnVfiTD2kkr8rwptPYgzxk+ChXDoziLRv?=
 =?us-ascii?Q?aICu/DMElz5cNpMQQMOjXFBt/tiRkWV3LcTOf/iWPhJVgrKxI0dMrkbqBmwn?=
 =?us-ascii?Q?zMJ6hf2tc4JGPV7pBUuUOIB0N3RWN4gH9C5h7uPkrRgF8frKhQaQ1JFkZ9Yl?=
 =?us-ascii?Q?XyWRbNtHwOeeWJyXAFB6IysmuBL6HPOKlwSSw32/1UaCk1m7nXWyPj++7TeO?=
 =?us-ascii?Q?Cwuzlstr0xgeCB5WF5xcCmlxFLhGDhKGemzZxZ4CgwyY8GM5XYXtQ7HHRAkH?=
 =?us-ascii?Q?ATGiUdAGkBQGR+2tB3caEYHXdLD7u9r+0yQ+/NmadoGnQXkNwFbMCP2HfHso?=
 =?us-ascii?Q?HWIsCB3MmK8O6rVJJASq+fD0dQqee6+fgGgtmVRHG1REhBnBJfTewWxjwpPH?=
 =?us-ascii?Q?3vFJJuTfC+AZEVd2dMWG4foAEYqa1Uxd3Dmwzt2Zu5HMTaAwXB9AsI3MTHc8?=
 =?us-ascii?Q?ku26jTqXKcIapCsE3uQeSWYxScVNsWovY0Tm4MzvLrvr6sCMO5iUZR5PxsM6?=
 =?us-ascii?Q?TAL/g66tPit46GdzWbNKlxn6ssNEBQg/D9SeF180iiEd7pDlRkmf+pSKUnVS?=
 =?us-ascii?Q?+Ye+hPdcAn82qJWXjDqLnWsXXH+fScnGLJcDOCsTAXrvRzdsqE0sBwSYUrxo?=
 =?us-ascii?Q?DmpW0gKJ+PN9QCd0/+43ejjl1wXVy/2jMVR0gwmeR+WqjDktDoxwqvlclysf?=
 =?us-ascii?Q?sFn9A2x+oErF9eyl1YK0uKVbSM+0ihycpm2qq2Az3vAT+iVMRGjDkwPkWAoy?=
 =?us-ascii?Q?ipv81rex8L8KP/jH6zKVwrsHeAR9OJkSXQJVqVhXogIJdvDYYPR4D3nUomvp?=
 =?us-ascii?Q?1Mry+PoimqGoaKlV1jE=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7b90076d-92b3-4e53-369b-08dde64c1bc6
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 16:01:11.7298
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ynsF20IHaNaMECo0lQvm8uXEaRXVaxJRSfgxp5voMi10rNTDoRaHMZISyi080voU
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR12MB8550
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="NK/a1uBn";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2009::601 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Aug 19, 2025 at 08:36:55PM +0300, Leon Romanovsky wrote:
> The old page-based API is preserved in mapping.c to ensure that existing
> code won't be affected by changing EXPORT_SYMBOL to EXPORT_SYMBOL_GPL
> variant for dma_*map_phys().
> 
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>  drivers/iommu/dma-iommu.c   | 14 --------
>  include/linux/dma-direct.h  |  2 --
>  include/linux/dma-mapping.h | 13 +++++++
>  include/linux/iommu-dma.h   |  4 ---
>  include/trace/events/dma.h  |  2 --
>  kernel/dma/debug.c          | 43 -----------------------
>  kernel/dma/debug.h          | 21 -----------
>  kernel/dma/direct.c         | 16 ---------
>  kernel/dma/mapping.c        | 69 ++++++++++++++++++++-----------------
>  9 files changed, 50 insertions(+), 134 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828160110.GJ9469%40nvidia.com.
