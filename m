Return-Path: <kasan-dev+bncBCN77QHK3UIBB5OPQXDAMGQEM6YRJZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 900EAB51643
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 13:58:47 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-32b698861d8sf6651184a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 04:58:47 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757505526; cv=pass;
        d=google.com; s=arc-20240605;
        b=E7qPxZPApsVeMJJzix7UgA1oy2cAKQ4U1dHXg/+h6/mcG7KQjLT4euqjoYf0CVEX6d
         oOJGrrZ2vvjAYqpJT3/qpCKtD5s692vt2aXvE95FOOYgn2FE2U0zYbg/aKCMn3+l19ub
         g25md+Ku9a8O5n6mQ6zy4XN2tyLK6bdJzKL1j5PfLZwYYX9pdsqkxIowMH61wWOxMZ1L
         IIf9W0sQEl6zYik5TgS81zpWf1SS/tytom9pfmgeCcO11PnLjGZzHZqyX6PmkhZHhK9h
         KOLTr+LK9lDxOEK9JD6ceQjBnpDp0LPkDsBnWVOmgil3pA1R1rfspApihSfPbiRtN5HN
         DIgw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=aBGlo0PHcqJWtswq+FPxUpu8sDcib84r4DxVDYV1DzA=;
        fh=xaNjuU0MK8Rfzhxa5cUvPJIM9tXBAry6eg1RxY9md3Q=;
        b=kJModAFLrXlVnKpiinyc2IFjzF86w2HNOX87xWfUgszKeML4qvDag+PTcGDUU3XS2e
         sWvrjrPWup1ttaOZdjjSXqA8yxma59OSFiM4VOS2wrO9qm7lpt882YzzbNatw0Mx4qpw
         N/+SSkohJTSMhFstzBIItuVyt3IV0okygwl6Ct/pEQXHrIq9O38wshgOXVgS5q4aoF7b
         1VPPYXaV0tu46DWI3/iI+pL9gDrPtoxRIhNd8Kvo7c7eYoYfZpWexsPLeyp0vluSWBOY
         TvoFYJlMBv/GXDDEtlZRKhzl98oEIBFLCR8GeZPiQAqXE/FxXWFchif//kVdqFbPzl/v
         RK9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=DCGX5i1w;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757505526; x=1758110326; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=aBGlo0PHcqJWtswq+FPxUpu8sDcib84r4DxVDYV1DzA=;
        b=Zqv5IrEQAd6Y2OtWBLazv1xgkp53X6LQ6KI9dKtG4lR06QIB3Z+lBHbXwGlgYlVvT8
         3WsmTnS9D8cteR1o1fXXyShgpzZ8Hoikiqgiaf3yz/8sSWhPnvuG1xs7PYrMwwsWlq3W
         7Y9nz9Ul0sybIH62mnAw7XPYn70c7K17y9ZS87oQ2rrw++RpDMdex+exh4teaELbUgkI
         cVv7BamKZwVro7TIkogSjZIDHHa6ncwbXO4p7Cfdk4WAyVOMux0r1n1zYE4UWpfl8LUN
         aR3mKYYFeuZu3Rpngohtn5va3yG/1qa/FmuDB1CY9Bl+nfTK0hKAjPT6qS7VsJlpMQ1A
         KYdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757505526; x=1758110326;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aBGlo0PHcqJWtswq+FPxUpu8sDcib84r4DxVDYV1DzA=;
        b=Sa81GMSdw6wkn/BI5bBD/pF3F+TUCLGwYFZue2F0E/b1VMTDOyMOSjAF/oWHLkUZBo
         xi8XTd8h0ya7iYRWQKYowJANHSSeDS5VZSv9rv7b3Yq6L/DQLHWtdw/pL59jikRwkBYg
         SET1SnUkba18Mg9OLGiuAU0fwcfRzqqDxxApVjRXDyUduSRrbFOFHQeVDMfqHkCtMoeX
         MC5eTRVTm2k3rkw3Jnu4WKtmTzEk8Pe1NsOhprCrsIt/dHkEPlY3PEXVhguFjEpuLAWZ
         03mydUmtdXi8wNZNWtCkeoFXaKdnWic9hKH0LTt8Px15t5nRV/NUcV+gYHCKrcwIBF+l
         uZWA==
X-Forwarded-Encrypted: i=3; AJvYcCXgc9DSgJrhaTV8Sw+kigfWNXWs+A2yT/4CeqzIC4ohldJs6tj9wukqkasnErD0xMhOwIvjEw==@lfdr.de
X-Gm-Message-State: AOJu0Yxl/tRkqtPkye1dPn8sZ/1F3V7fm1GwivVCE8iN1JmuOJal+ePN
	1cEYlisPCVVAa+ZugJGxBqfN8gk+2mKpxK4g6qC/y1NKg0BHUpiWKy5G
X-Google-Smtp-Source: AGHT+IEG13VMuiMzyU5/CI7It+1DfS5JZRLUNEz1I1IkfNVjhWIKzcS1wsdiUZrZWKtfJHLfW001NQ==
X-Received: by 2002:a17:90b:1fcc:b0:327:ca0a:67b4 with SMTP id 98e67ed59e1d1-32d43f00255mr23588051a91.12.1757505525724;
        Wed, 10 Sep 2025 04:58:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6CqNV9u3NS1bjPqXOlLcgmxGnOz/93Ku/bFjeg4fRlVw==
Received: by 2002:a17:90a:1181:b0:327:646f:bb64 with SMTP id
 98e67ed59e1d1-32bca93d1f9ls4119864a91.0.-pod-prod-01-us; Wed, 10 Sep 2025
 04:58:44 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXfQzpFCgywYX44dMWlVQIb1QQlDZPPwHA7YjoD52HYVGNjaLE6wAPv5ipNlZQ803ADXJ5yn05YpTU=@googlegroups.com
X-Received: by 2002:a17:90b:3141:b0:32b:6151:d1b with SMTP id 98e67ed59e1d1-32d43ee5953mr17605400a91.8.1757505524069;
        Wed, 10 Sep 2025 04:58:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757505524; cv=pass;
        d=google.com; s=arc-20240605;
        b=bytJavS+IcXN8stjmqYkEraHJxYI73moJUDVSiDQ9tRZV6zxskxA1n4f6jx1L7skcb
         cHUnL4I5d0U64f+QZBTPKq12yT3+b6IA511gi4b9ZJ0MsJFNxpQ5Zlihvm720RPljmHv
         faAIzpLxOcbyqp/UMS5VZM312J4L+O2Oryh6rrnI9/0Fer7IoABeXpEXRTt0q6K6B3xF
         t/5F1F3NRoc6Ov4ff5Tu4myqgR5JpwXA0WxbTLL18zEpc+uXTWXOrhpw9kZ/3KKKYGZl
         KAla3XHn8uUafYKUAsLIU3Nc9ojzhBw4o/9E9ePNm86qQlGUZ8BqnOnc4jSREVkC/HJh
         q9/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=M2CRGJWbvgTRAKQCpQVq3CvW0DQ/ZyYML+xgjXHDleo=;
        fh=4P1K4Q9+a0/qDcwtkx3cIgJuYWQ/kASUR/Pj3TCogyQ=;
        b=XNYKdsTpz/QqnbJN8T6HC1vUCJrURxXxaTYKNGpuc25AOexmKFU4fobOad1IPLguZL
         uMlQa4La0xOAV0Q3Nt8OmDING9+pCrKHHpm+6zBafMIYVWomJ/y1ydH0tUkQpRU0Iz+A
         PcTVP3Ehsdo4IwE0lCHeGkADDd4WHvyOGHL2zZ8+iBULTJuAT5recoCinuXfgv+cg5C7
         049No3ggx8Ebdj6rEJAk3ortmUhsvR7/BH+TsJ1gMc+Yo6VjxWWDcJaE6dmMHtyYdUwZ
         vKI5plpAOIpyWVwENok0xv1bUQWR2nKrXL4lS8GHBJGHaKqfMnWRu5nnLqRFT++Fyz0k
         CqdA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=DCGX5i1w;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on20627.outbound.protection.outlook.com. [2a01:111:f403:2009::627])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4fabd11096si672929a12.5.2025.09.10.04.58.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Sep 2025 04:58:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::627 as permitted sender) client-ip=2a01:111:f403:2009::627;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Sn3V7oELjkrT+Ex+wYuTTfJd3WsUwYgnJmnkM+tItOpmbM+J8qovkAPHYt/A7PKdAxoWGlisZ5TesXjmIXvOHKWcNXtA1O3Hg9SA6mAhfrHEezRPKmMCSHIRBmSiBgsvZgxaw6V0hH4pbdO54/Yd5q5EIYBFKZuN7d/8WIw+zLxloBetM/UCcYtcIc6GW5rH0jBKwge7a0m4jPykaBH8Y8sKHehJQWlDdKdUNpkCp2evYTZ7lvgs+TsiTWScPuI24eLlp6TrdOL+hleedbJyK+OJ4SytpZZpW4FYO/j3zVP4FD60hiKyFc9ZB4/0Ery3tfckBgfq1QXuqElNvsjftw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=M2CRGJWbvgTRAKQCpQVq3CvW0DQ/ZyYML+xgjXHDleo=;
 b=tB2vXc4aLG7Xvj/iBdZSvwn5l5BDP6C+4bz1pIRIWCRgMWFDDbhmT5qJwttomGtb8BHCznSs1U/3u4v6DHTHmWC/I6z+Xr6vluxXtIpc3nRzQiDjGvtecnGkPUr8uW7zs/hJWBGP80S7Nc1dUlCLFh9qUOu5jO987pSlHgXoT/P1w6NsT3FQBwOILLwl3So1eAjWPEjg3x9jiy8sN7xCZqAPkDZVJitbvd8ChCDhycviaJq9+sQzjix1CUYwDf9us224wMfxwnVp/LXMt9t30uAoOeFS7X2kQZFGh8Eg3ciqLaMSqi0Ur/Kgqry1mm4HqC3j/XfupYGVGiT8b2TLaA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by CH3PR12MB8709.namprd12.prod.outlook.com (2603:10b6:610:17c::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Wed, 10 Sep
 2025 11:58:41 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.021; Wed, 10 Sep 2025
 11:58:40 +0000
Date: Wed, 10 Sep 2025 08:58:39 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>, iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>, kasan-dev@googlegroups.com,
	Keith Busch <kbusch@kernel.org>, linux-block@vger.kernel.org,
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
Subject: Re: [PATCH v6 03/16] dma-debug: refactor to use physical addresses
 for page mapping
Message-ID: <20250910115839.GT789684@nvidia.com>
References: <cover.1757423202.git.leonro@nvidia.com>
 <56d1a6769b68dfcbf8b26a75a7329aeb8e3c3b6a.1757423202.git.leonro@nvidia.com>
 <20250909193748.GG341237@unreal>
 <20250910052618.GH341237@unreal>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250910052618.GH341237@unreal>
X-ClientProxiedBy: YT4PR01CA0498.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10c::6) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|CH3PR12MB8709:EE_
X-MS-Office365-Filtering-Correlation-Id: d3d1beeb-870b-4064-522c-08ddf0616235
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|1800799024|376014|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?FzIxhCTl/DFGFmaXIkSJW43QRlHeUwrObkzUBGOXZlpW5TknvixiA4gDQdO0?=
 =?us-ascii?Q?Y/Q2AqArhV3Ean+ESTnkZr/fvpBX2nkWxFKLLH4g5CA9C8G475Hr3gb3OOjv?=
 =?us-ascii?Q?6uJVbcwr9hyVssPYNNIHf4cHbHNfa1FcsJ0EkEfNXG98vrQPHF/sWCvG8QI/?=
 =?us-ascii?Q?COGsWCNfWUGpIWeBBcktY7eFttSjXnJa/fCDlR5M7SnWvVHjP09ct5kmeZoH?=
 =?us-ascii?Q?SAYNOPDNskcy46Em8ly9RRUNfqYG4XoPucVxFGwyPQt0cGYV/RAX2nuBRLnY?=
 =?us-ascii?Q?oDenFOddnolaVnUlfh0CImgVZFr/tUkfCle8aamRAftKGcs67gzyutBwvoDi?=
 =?us-ascii?Q?dNUaAWRksh0OpZeDtOzS+yUixVU6iF6zuAgdtdJ+/SJw1dzFDkGfm80wGCoH?=
 =?us-ascii?Q?pckzkDSveUd+iwi2lfDzjyPVQ9yj0CiH/xxWs9md9M1AQSc3NZiJU1hLjeKm?=
 =?us-ascii?Q?aAY8FuT7mkNTvmr+F8IaY1xbUkqwDE0/IWF1EmvaP2B2COuQ7wMj4RNUjEOc?=
 =?us-ascii?Q?O/AhbcPzLAMyP9dJTa4ojajfgOMtdCIXx/Rxry4yk0Rx2rZ2fjSA6M+C0jit?=
 =?us-ascii?Q?E4yYm3ZocgAEqqYDdafANBeHp39vXTx87t0jZIqiUkS+AeC6ISIHwD9hDxkj?=
 =?us-ascii?Q?3NKmejdUiaLbjH+sBCgqd206gGNFVcc0Zt98Oozys1GBZXwHRLMY812uQPYE?=
 =?us-ascii?Q?uyHrhpRnGAIYWFfAHefw01QVwryhLl4F/p2FxxZ5WJ2mJk8iLma6uzFa9nse?=
 =?us-ascii?Q?KDIQcCRrG9o4DskmRPMDf1PaNxx8TvwULUPJB0jwTMsE0RkZQnTZYU69eX3J?=
 =?us-ascii?Q?DTJiamg3E5I0LV9zQ7KUNLWj7+scC2fn2wUO2D+w6NK2kvcb0lvj02l6UkTc?=
 =?us-ascii?Q?X7jKgFI4/1/bAGQetuBuvx+ircaAenX1Iq6FMnRYQcgdor2MWhUDTqFKizIA?=
 =?us-ascii?Q?vJmD0Pht5I+lSm+VVTECa5eMOZE6H/UwUgnXBgFiR+SdXv8DEnEnO9a+9Ujl?=
 =?us-ascii?Q?fTzsLsC/NZI0DsiAFIBO+4w+7SMolqtyX9A00a9XgVJOp0yXxu2QqO44FHlF?=
 =?us-ascii?Q?F5kOApjBfLOwHK4UEafL48ADf1hzQpNZPMIk6R2fhwlKEIUMoSNqHn4cTPxl?=
 =?us-ascii?Q?znJlbuU5Ch+3Eejo3q7yZqrX3ozlPCo0nBxc8d/f9Cr9yddhddHSyXN4+eBq?=
 =?us-ascii?Q?1K8vM06RHw5aht/nrdIYWUbgLh/jYAL7eVKdCjw67lWNVVQn+anrn3l19WdD?=
 =?us-ascii?Q?BSnlzXwqrv/YfQoqXhsDx+EYQ9FcwydQzXtPK0D5bSt8yOGcjkm9NRk++zQ6?=
 =?us-ascii?Q?K5aUj8NJxT+OVBPsX2TS4htXjJaFpFkDZIIIo3/5K+GVBWGmqOwVOybPuki7?=
 =?us-ascii?Q?iI62pGuhOEA82Yro5WGvlkvleuez4YsUAy/C9hO+W3hCWvzy7fg3ZN0wgqkG?=
 =?us-ascii?Q?ptHYclhyF3Q=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(1800799024)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?9YO2VNtN7/AVkNY5N+N6bpbx5DVFYyJdxIshjK2kTpMeuaOdcSF5l7noHEF1?=
 =?us-ascii?Q?s+lB5UEncua+s5Drg3oPC44ZKgxdHC7EQ1mmSbi+XEq4qFKNNVBpiRWSIfc/?=
 =?us-ascii?Q?8ywQrj440x8YBHiXj4uZB0QE+J1KktuhiJc4bflyorZLYXXCNTQlvOTv371c?=
 =?us-ascii?Q?ASDGOoCEv3wTgUSySdjTbUQQGWvJC0NQpKSsq2qJNstew84LYBuDpBk3uV4o?=
 =?us-ascii?Q?vBenXfKllbuWTEDAUQSxwockvdu2HZ5HxpgplNGCWZ7znKBO2Us7KIHdhBAe?=
 =?us-ascii?Q?TCX53Fa2wFwLETR5Ho0D0sOXqpILTIZlgHisolBKChaVQ1AKIqqsvk1hmIgd?=
 =?us-ascii?Q?YE6/iB4CEGVROiDFPAO5TfADkkrbbKpGKD5A/XCbSSUrHrrkqIUnPM/LzYXQ?=
 =?us-ascii?Q?WGT0sXGTpAAVusd7OCVZF7nEWNxNPvf9OafKMixxZg+5lm9hMrGaDiXZ7U/0?=
 =?us-ascii?Q?bWiQu0xeLBXSVpmNEob1HkW8KfUJ1e3A8+quycFN8fJOn5cfpnSW3FEqOAjC?=
 =?us-ascii?Q?JgfkhIRa6APiEb2G4je21c6BWKbOX5cOHZDHFENP3jL5g+YoyyU1LJz0NoX8?=
 =?us-ascii?Q?mASc/SCKxHdg3dyOiFa2V+Xpjd+N2LutqqAwhQg4IORPN9sNWSwzKWeX8TPJ?=
 =?us-ascii?Q?OYNp+31ak76mDNFtIe0GgR/CPpX7wrNktItOo5t05HaCglof/SdPTIbMFvnQ?=
 =?us-ascii?Q?dIlVEWzu0f1mZZgQUsT1aBY9Hx24N4Kx5QcmLxuijEYIEebO87J8trQkpOC6?=
 =?us-ascii?Q?5HvTn80xxmbnBR4Z8s48Qux7dO4liJ+EP9gA8N10i8HYKFz6FU5y6aWdKBDu?=
 =?us-ascii?Q?F2nCo6aUF13uff4b9pX53OdttabCsWvQhcMi73AjQz70ijVhIZRi5rD81caI?=
 =?us-ascii?Q?qzAmnxy0fXs8ZFjYivEVLHNmcYoWZVTCFLm9h9ZlCYQajTaL3WZ2b4bBYqGY?=
 =?us-ascii?Q?mE3YlmZLwZtHu8pjWIHa8Vu9ugDe14ebg5WRs5a83zohvO7s4Sb4LfCpMic1?=
 =?us-ascii?Q?IpBv8kPo4agNFbf1H2TyXz5QyQaAkHqbPjJgR2bgQJ8ELYUjejyvmEhrmoEJ?=
 =?us-ascii?Q?cle6p7D1vIfzHtVjImdzimXsTUYCsAKTGPmt140QMNxPK7rxy96x1wl3+GfE?=
 =?us-ascii?Q?2QmAUir2xSQdsVPQXgP+rTTiGOpzo02zLXIOySsQlKBQPfcSP0MVBNdZmxpU?=
 =?us-ascii?Q?KY1LAWASYTztVwsHLEbLnBvuORa0/G0/n1GbQA1BBOj9PkqnwENbff4O7HYX?=
 =?us-ascii?Q?n/06d/f2gFt8Gr7mnZ6gme2FoyHeKWUKi0gX2Yeoawx+x9szqxzDkBmWGxM8?=
 =?us-ascii?Q?R24cd960+95kkj5RLQyuLq+qQSfIut3CnDpnavZuMCT8M7VanWjlKpxbVBmH?=
 =?us-ascii?Q?9ZdLMvbeCVO22byX6zJ/TqPCtJxTr4zQCRF5JSAHjnClMwsB+zPNa8RuDdCD?=
 =?us-ascii?Q?ozo2sXZqvbCbHoDATIse33PWDM4HV99uQGVFvcLv2sGGvcSNU4Qq3K73wuEo?=
 =?us-ascii?Q?rAyxsA9mNo4oh0K+wFkx6BNR032gCcNqav90jaUAoi5RrDp9pRWy4nuuK/ZR?=
 =?us-ascii?Q?TKRZ0lKjkgxNLtP0ngU=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: d3d1beeb-870b-4064-522c-08ddf0616235
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Sep 2025 11:58:40.8152
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: NOBo5qiUePOEw1x7YNat0KXcE5eLDbKYD5g/dL+or0XOWmfL8YpjCGLIZSmZwreP
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR12MB8709
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=DCGX5i1w;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2009::627 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Sep 10, 2025 at 08:26:18AM +0300, Leon Romanovsky wrote:
>  #define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
> -#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))
>  #define folio_test_highmem(__f)        is_highmem_idx(folio_zonenum(__f))
>  #else
>  PAGEFLAG_FALSE(HighMem, highmem)
>  #endif
> +#define PhysHighMem(__p) (PageHighMem(phys_to_page(__p)))

Yeah, that's what I imagined, and I'd make it a static inline

static inline bool PhysHighMem(phys_addr_t phys)

These existing macros are old fashioned imho.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910115839.GT789684%40nvidia.com.
