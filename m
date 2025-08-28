Return-Path: <kasan-dev+bncBCN77QHK3UIBB5F4YHCQMGQE7PKJHTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BC830B39F58
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 15:49:41 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70de52d2904sf27022396d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 06:49:41 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756388980; cv=pass;
        d=google.com; s=arc-20240605;
        b=KvMtwIFkxrDlraPWDono5hArQYcABz3jCHusijl6vXzuzlqdTdBqqNPsXmDakMWOsF
         Q9KPOp3f8XNuy1ugMMJAUDCYWRXF1XuiYJvOIouO20VbBW4YYtGhVlTuC2qgC0atPqSX
         aEFsZMxNeGF7PHeqnqzvnQqR53JvRVIJR2I1+tfC/Qk6olT/7HwdSl9wYp86nHA7IJ7u
         xKOY4qRJzZkZuStbL4I3HMgDd3c3nwAIuSuXLKupDYsb3e/bQ1wiC7X1PcfqoDc5S2Bl
         U5sBVBrJgOuu1N04To+VfHI/AFDhe0ul/byGzWcUp612i4Lm4hEc7+vPb6UdPYcmUx8o
         Q/KQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=pnIUSS6Hbgz8Lw5dy5Q67Ts7Ww3J0ClL5CtmDUf4kJ8=;
        fh=m+1Dd0g/MKfBEMc9wzfC07npRXMEJSIPG4aWJpcrbs4=;
        b=Hdw5Le5rVb3V7tcmU8zjvKSvCFIXhF/gW/wNSlz0ealOxpDYNXwsfHgcbBb2S1gDGG
         iG54KTEQ5QjBqbCpYnuJH/Jovddam8JnNpamXHruActLRPNarG7E6c9woNocx9vVF00O
         ZRhyyLI20BSjLzRb0EmLPORQlpaSBfNPpim/L2/6aaNsH27HMrBRKnjLrOdz995rjB9i
         l34QrnPhs1Msyzw8xeIttkYYhONGcI3JaS7k52jzhxN48cZl/kc763mhmKXkIAhOZrtE
         c9ozjMySZdSbbQh9bKgLcMIBEfyObEMi5PkVMNteSbvmetQD4vyMDsEHr1G/tkSzkF1K
         XgOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=aykgNITy;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::622 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756388980; x=1756993780; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=pnIUSS6Hbgz8Lw5dy5Q67Ts7Ww3J0ClL5CtmDUf4kJ8=;
        b=nKmCexv4CTwc8AJT0AxbM/W/Fmv//LiDIBlJDCBlSn373s8w1kTguPhWmXXhxk1uWJ
         7fWVGkPg3lPv9ih2NpGIL+y03PfynIf9v8NK4iiPQy4f0XX27tKsEC98JpCBNUOwjpQn
         MMizjImPb1hlO4FAIgTR+tPjAPEUdBLjkuBGpQz+YRtNjUfMwKrtfIWOZisOe2KDUmWS
         3+GvibXjpaI9hFR0npgDlEKhz+muhSiKQIlqVpLjYdjFDCETl4ODcT+7grIyOC9AN5t+
         GVgpPsVAov0fQ6dV8V3Ck6ep29ALtstX33S+7jJh0OODBnUaQ5kU/LxNDCN9GKhHaLNl
         Mp4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756388980; x=1756993780;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pnIUSS6Hbgz8Lw5dy5Q67Ts7Ww3J0ClL5CtmDUf4kJ8=;
        b=VRTSCpoq7b4JJ7Pd5gwnPjMX3vP25WM9H2Mv9RbPoFpYoV6F6gRaAtKO+D46htGco8
         pglAwQIDVljcBOZW5CKxPsgWHthxME0N5LqziEh43CSNbRqJ7SNICMyWYwpDwbHB75LD
         ZNuQfrMFWU6wUH8XbunHP77uj+zim1QARoysnjM5u60Nz/pmcBbGPgP53Va+0/NIVzMR
         89ve/oPjSLytGzrwSZViZTzjb2d6CkhNM2WCOwrn9XCLyvPSontS8JTrqNfGtlnPqPvA
         RfDqGwwcFM7bfDxGPuGLDJnciN80YVeNHdI4Pk2roVicRRkGyraZw/dM1hEhHEZd9zUL
         o31w==
X-Forwarded-Encrypted: i=3; AJvYcCVyBf4cCeaLhM145jKTc9mzlo9qZqjLZRmd4ya+p4WzraDnZwpeajVLQT4oM/xOpUgcvPiofw==@lfdr.de
X-Gm-Message-State: AOJu0Yz5QzOKp0Dcg8h7mHOM0fZ3V5UUkAXGExnyX8Ua70wNMkK1Qa0x
	I6q76tESyQRCBbuYP4+285JqvONfSPIVGMEkcCwjfUe9m4lclAIPeoRd
X-Google-Smtp-Source: AGHT+IGdzzW1E/KXdMXWhNbVOJAej/FspuvPb8nPM1WT2c4vGwS+drTUXSTHEAxGLcPMJl1i4bpgaA==
X-Received: by 2002:a05:6214:5004:b0:70d:eb6d:b7f0 with SMTP id 6a1803df08f44-70deb6dbd21mr47647386d6.10.1756388980301;
        Thu, 28 Aug 2025 06:49:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcKwUILVCh6BUo41dv4NOj4GyBxdZFGJeI0186Y1zKBfg==
Received: by 2002:a05:6214:d41:b0:70d:e355:9648 with SMTP id
 6a1803df08f44-70df00b48eals12831726d6.0.-pod-prod-06-us; Thu, 28 Aug 2025
 06:49:39 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUm0ej9m5V5R85TS0aBElA7nwFucG9mwddc0iEAlGfy/BtVPU36L/MisVFpiRblU2lUsU5uGAgAUa8=@googlegroups.com
X-Received: by 2002:a05:6214:401c:b0:70d:ae25:4e62 with SMTP id 6a1803df08f44-70dae2556e6mr205186816d6.48.1756388979259;
        Thu, 28 Aug 2025 06:49:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756388979; cv=pass;
        d=google.com; s=arc-20240605;
        b=TwSiLHekbd/d/7rbxqQZay+aB0WiHZxOFXPYQc9/00rYWK6WemmGXSZhtoh4b9iBjo
         bpM64hOlCODfPjNlr0okf9sJQN2eZUqpbEo3Mh9JjwqMrvF9XpMBZH3Va3Lpc+9+PRsO
         SVu5YBN73glqRyxcvNnOOW5FbtfRlsQba18sKQqs8POt/QflvGhNEYhjDxFaNDSi3tvn
         TklImhgaX+suXEANqRGYm4cQTprLie0pYPU8V3eltDGwQnil+tK2WC1NjcVe1SDwVjrz
         tsF7Jz/cg+VGMxys6PBMp6e/LJ7NyaSHg1/ItzPxiTReqXs64ystJv7D6fUaKybsP4My
         s+Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tmf5+3EpnHgeIhjFkX6hdDPoeYYCVpHZKSkOYrOxExM=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=eRKi4wsj1gJ2PdYaZV4mAgi8k15AOQWuEfJqKfaoiHwj5plkZ/OKJh2G0jhGsc5HER
         ry5HzToRkAU4YKGtkPqg30AX6eVLg2t2ozWUhTxvtTO/b0XkTTS9cYj2q2l9kgX2alxW
         ARJK/t2Pxp5Qcx7vcf5UqGI0UPHmTEwhjgmYjISSNH3Bq51RvHvUUgFD7YSjSQmmW0qf
         q/i1zUTfqddC4VgmehO4iunEiJZ6KZbl4mKYFSJcZZcZWJPsNXpD+z2qpbEg3SNEv9md
         vfQ77J5Z+D+6mbLmKPDQL9YFZvwmvFm9xu1flXoU6cuPXsWy1kif9xzpsMgAeo4vqOww
         g5uA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=aykgNITy;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::622 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on20622.outbound.protection.outlook.com. [2a01:111:f403:2009::622])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70df42ad314si790466d6.7.2025.08.28.06.49.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 06:49:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::622 as permitted sender) client-ip=2a01:111:f403:2009::622;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=mOyYTJbjsO9NCf8rOgy6Inz8ZGlaJmXwbgUjLmipwRKc9+8RwUUalO4/vmuNQn9F/I0tOlrhG67B/DZQndJn9k3oKOWnEz4rDTyQ23POEHnWbu8toQRA3Yd6DxHWksoIcjBBBsmnbXg7nmAcg/ClbSGZzfn6Ykx8D1tWNCYIgFb4n9BEfZRWMVvLmJR/z72ufCX5BDs7RFXlOyQK+zKvjzH2hELYS9KfN0QCuw5I5QtTsM1r2iohhAGeUgTJvRZQLHthlNlzB/FW8F2GZsIZxqMLww1+iH03v56Lqvg6kbMOP4lmQmbbLrRSnlDQU4ml63nfcn1Qb7X6yjvP3akG7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=tmf5+3EpnHgeIhjFkX6hdDPoeYYCVpHZKSkOYrOxExM=;
 b=ZZlZTyrwHmzgwzgCSCYXcsv+D/spl2cxkcuiGgwqtUzBH4BxtzFl3cnN4cDOSIcjA4ZvP6QsG8kdu+w4w6DKqaZKbOUv/H6/UJ7a0Oe+R/gpbZLe2ZSD/TTyNZbtrEDB8u3SnoHHKuNklxx2Nj23e7oEXKdBDWcJQ9ZKhK51YgDDiozBHHFp9B7s1664Jb3+MWSQ7cDDYzulWoUElteLRPoOFwQrEUWmiJw7A6HW3X3Tt303cr8V5m6pq/NldilyHOdD91SYfszt+sMG8wlX0RvwOKqBlZ0Msr2b97VESpbo+ETWD//0TGKSzDYZN1EH0c0ZZbDpAYsBbIngEvX4RQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by LV8PR12MB9336.namprd12.prod.outlook.com (2603:10b6:408:208::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 13:49:29 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 13:49:28 +0000
Date: Thu, 28 Aug 2025 10:49:27 -0300
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
Subject: Re: [PATCH v4 06/16] iommu/dma: extend iommu_dma_*map_phys API to
 handle MMIO memory
Message-ID: <20250828134927.GE9469@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <4f84639baf6d5d0e107fd2001dff91b6538ff9ae.1755624249.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4f84639baf6d5d0e107fd2001dff91b6538ff9ae.1755624249.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0489.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10c::8) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|LV8PR12MB9336:EE_
X-MS-Office365-Filtering-Correlation-Id: 10e3762c-9d9f-41d7-cb18-08dde639b556
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ho/h4y0ux9joF8qU9L34AmpmcnS+9JVoSS3ehxuqmJIPmZ10QIBkBvTZAqvV?=
 =?us-ascii?Q?hIKq/J5YNFLUw3H5lBVc1B09vk5J2Ea+EYUUlwJ07CnvdIpjL3SDHj9iSBoq?=
 =?us-ascii?Q?eTkXoWwjU5DUHZtftR/yoCL2133rJ/U4CaAnFZio4Nc/yJwHTp6Yll1Ivofl?=
 =?us-ascii?Q?QCnqx8RsPNZnzlFJu/O3i9vziusVf5l5bAXjcRQ5DEbCGOBZZTLs75rNxYi6?=
 =?us-ascii?Q?D6U2hPpRb2ctl4vsYs3JZEa7eEs1oGWyk5dbtfbhdvCFUUFjVPGYQmci3hjb?=
 =?us-ascii?Q?Px4G2d15pjehZlDSFxm+65Tm2CX8kKotwIQdqEMbUFj/PofJ4tPvxbapucF5?=
 =?us-ascii?Q?KH3LLtmjZaASk8H1LsJD6/qOFEHHxdaDvjiZqzbj3wnpfREdjLaifSYOgDbr?=
 =?us-ascii?Q?JDcilP1Th7UoPeQGU+ALwb0+v+PcBTf1sJc5i/CGel/Gk//7BU1skEv0PmWT?=
 =?us-ascii?Q?JLX2UXhuV6Sbq3I9mkeb74f9YtIp5H6VhfjYYH4K5Oc3n7JCLa2vEJlI2sz3?=
 =?us-ascii?Q?Bp9LAgJX+VolivAYMuAgheKgmUakULCM6eXqSM9ByFTbB+RLklJwVwYPB7/Y?=
 =?us-ascii?Q?T5nv6qI16UzYfSKQOVOj3Q8pIrC84M+KvyNGUIlCdqWmXepCw6vk7udUkjC+?=
 =?us-ascii?Q?2sdfbzwfgQE0hlFn04Y/h2GiXKyu8LVQqTvxX/vum44/QcSNf/waq2nUgh9u?=
 =?us-ascii?Q?s4dIM/UKqQl1Wydk7+8dr52Fn29EF1aG9HtX6Kes6fRwQ+b/NbjQCFTaumzz?=
 =?us-ascii?Q?6kJwxa1sd1dapLYVsEpMEPYMla5I9LdBYfFt6g5r5vRg8JDye+edCgNO1ac5?=
 =?us-ascii?Q?qCrXbId6DMcb3kCCmEL63qlLBlbmRusaN9MC0GK4NbTAMK/geki4HiHqIhaX?=
 =?us-ascii?Q?ZYDIUxD9UxTV3/8N8jFy/3rLuwpxz/zaZgTBotm3Go5eHYf7N4Au3ScMvPyo?=
 =?us-ascii?Q?GJtOlyD8rTSMTq6ov/HU3KLtq9QTBdyYh+mo0c6k8yBstaMFkOVfjPgx+RTQ?=
 =?us-ascii?Q?T8rjtPShvqynrDx7cej+uOiGIKz/71BRjcqLc3m9VIqZQd8g31cVtlEJ9yKF?=
 =?us-ascii?Q?Shgpj6PyiDFXICPZ+lkM+N381jIDNvESQmJkT42+Xom2LCMxJk/vrZ6+nyuj?=
 =?us-ascii?Q?XNBAS3C5soC1enzLogesRYL0wxxSm+m0v0tLrEX2kBmpB9sZq6cd4c8D2Arw?=
 =?us-ascii?Q?jfwaOQJjW0a4uE8Ub3dpTuZoJlkox9Db0ENO+AEQzpjQICsEjvw2Cy26pBp/?=
 =?us-ascii?Q?6BEeKO8nkpajz8EO1ll52RC49xW/VL/xMInGx91anXKvTnumco0wbpP6z126?=
 =?us-ascii?Q?nBEFo89b4fT8t0r0XUqF0ZEt6akuBOG06yghEYZxpgbtb7Tn2v+fw7Ug461d?=
 =?us-ascii?Q?oiR/7FI/LdRACc3DUAd2+mt7DyMIaaAChZNtx9bz2NScH+q90qG7oTdC4eyp?=
 =?us-ascii?Q?mlRVDPFKoGU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?RnwI07pU9MhS3fcj6ZjxhKBugYZeOXHf7yczQcXDk5Kxm6tSkU2JFVdCQgSf?=
 =?us-ascii?Q?poBjKBrW54ONXTEgj5vJcSLdueLOBEgoHLDUbM8D092uLdIHdWjUy32VwSyp?=
 =?us-ascii?Q?lwqpffHv5JPwiFqYYdTJ/8bGBrAqhXLfkcIEVHOdY3T92WsyQZk2adqD/ZIz?=
 =?us-ascii?Q?siknKLCQDcUAsoMn6Hcu6mam/lMrbvIhL9Q3xV9jiYVVvPaT9WOkINbLSErr?=
 =?us-ascii?Q?DAn7cj6Ke3+ARrFp60MOhkyoMUE5Y31wm7/EKyGOWv4GNkms3tUi+L+kZ9du?=
 =?us-ascii?Q?28iT4kPOFvVOXjH8aPsfL9Vz0DqBKtIEmvW3JVWGjuDUcVUt/QA7Jwrsy6GK?=
 =?us-ascii?Q?/FFxGgRsPDluK/debsNuL86P3mvlhafZTim0nbfW3+eWjit1XUk72n7Hna2n?=
 =?us-ascii?Q?PMN/STHypoiTR1UsNqcts4esOtF4xvrFmlD8QJcvv/TXymNWZ+fxlXevmVBV?=
 =?us-ascii?Q?a0HtfN3wmILiWcfhCu7SepBuDI9pXKHaJ+qH2+zqtqBWb5tIGeXMqx3uT5ME?=
 =?us-ascii?Q?ipy1xI/DjxJXMQrBoicmp1lF6lBD7BHfqR14hXwXy3Y9F/FpqinD1DZ3n7iH?=
 =?us-ascii?Q?yfZkAT+fq/RaKLZPKAKa4wPxjyzPE1kdXUSs6ueFCml6w3Po89qDduHyZcS2?=
 =?us-ascii?Q?Eh5BpE2GHDnkMRyTJbt+G3aR5ksrDMGf45eUGZkeZZZlVzhghbaqFMU2qArk?=
 =?us-ascii?Q?MpCAA0bg8TdC8PFeVu6Q+2jYebMoL/D4IjiaboXIBf/IDkaJkfIxDzAo1K0n?=
 =?us-ascii?Q?uHpjjjWQeG39f45Y9rr2E07WFfrbTzJY1bDNUXm/PFaKTJkiSzwE8M2f1fQK?=
 =?us-ascii?Q?CXxYeiREeo1yMg0ktCcpkJaYMMAg7pngvccQW0xqDfwdv6omIul/ykfvoovh?=
 =?us-ascii?Q?2VuIJ5s5sm2hx50JFkstQ+y/ppnwN9OgFLxImLg8DFIddHC8Nk9j1fpbYHYz?=
 =?us-ascii?Q?XNtJAzUE2oK9+yD0+34wOEfzoG9/OcVv8tqEz5Nzw7vipUsQ+6OG0Hv3saBS?=
 =?us-ascii?Q?lER25hBAuYh1wSkE2TPBY67aaCtRqm3j34SgnFJZJ6ZWvxGkxPpbX9fRkfwD?=
 =?us-ascii?Q?ESkioC7HMJ3dnBC5e3hhmbcAU7vx14RcEVglsgs/wN9GHYhY4zt5nRcsPcfK?=
 =?us-ascii?Q?gqmd89a3WYDRl/Qb9AP2TIfsgrCv86HmsiLgh2JhktltINwAntOtuLmRZR0r?=
 =?us-ascii?Q?7b5T11hGwVCtx1sepX3Qui1af2VlYXNppiXQYfYaw8XL9QNExZgpwUBE4OKS?=
 =?us-ascii?Q?TVG1rBdAtxDmQsO0C9uiovD5O2y9qou2ZXDL0fzmofi0Nuc2DEtm4lAvGsvu?=
 =?us-ascii?Q?fpAv7PeWh4U+/RmGaNi1/97hfeuQg+nY84qgOiNmwX6IUo7YvXi+TQL09p2y?=
 =?us-ascii?Q?qd7e+Z5B8u9UXUvGmE+ELI6bu4CD1Y4Lf97N02RDxSbqlE+0/2Y3Nr2qoHgd?=
 =?us-ascii?Q?zjIyeI72fYtKuI8QrXiG0eTi/hpTt+k1rfiBFbBo9gMfnnaeECQyUZvm1aeR?=
 =?us-ascii?Q?fVrR4C7hcO1ffd2v8PMuhgCy39AOCVI82CZFCIdR1smzs2YCUVr9xpilMHSY?=
 =?us-ascii?Q?9vdGc6Gnanm4xzcJClM=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 10e3762c-9d9f-41d7-cb18-08dde639b556
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 13:49:28.8832
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: TbARRk5NFlGpGAaiLFsgPVLVB+j1BOxQvd6Cpogz3hVgGWkgsHzBUyp4/HAjIla7
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV8PR12MB9336
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=aykgNITy;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2009::622 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Aug 19, 2025 at 08:36:50PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Combine iommu_dma_*map_phys with iommu_dma_*map_resource interfaces in
> order to allow single phys_addr_t flow.
> 
> In the following patches, the iommu_dma_map_resource() will be removed
> in favour of iommu_dma_map_phys(..., attrs | DMA_ATTR_MMIO) flow.

I would reword this a little bit

iommu/dma: implement DMA_ATTR_MMIO for iommu_dma_(un)map_phys()

Make iommu_dma_map_phys() and iommu_dma_unmap_phys() respect
DMA_ATTR_MMIO.

DMA_ATTR_MMIO makes the functions behave the same as
iommu_dma_(un)map_resource():
 - No swiotlb is possible
 - No cache flushing is done (ATTR_MMIO should not be cached memory)
 - prot for iommu_map() has IOMMU_MMIO not IOMMU_CACHE 

This is preperation for replacing iommu_dma_map_resource() callers
with iommu_dma_map_phys(DMA_ATTR_MMIO) and removing
iommu_dma_(un)map_resource().

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828134927.GE9469%40nvidia.com.
