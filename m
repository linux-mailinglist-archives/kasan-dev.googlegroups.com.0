Return-Path: <kasan-dev+bncBCN77QHK3UIBBBG42LCAMGQEKXSVCQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id A2832B1D94B
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 15:45:43 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e8e0bee7afesf1372815276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 06:45:43 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754574341; cv=pass;
        d=google.com; s=arc-20240605;
        b=IphpGxssWqQT/BMR6A3xR0Mw8i8Kk4zVch/yZNukTeC9ieReL2oWSzZiwW8fL2I1+2
         xbA1wqiCUb2uyU1DIyVEVSmTgRkvg/lofpTZIKPXTZVT8wNGd1g4ZjFr2/S06VNpL1ux
         UjqbvAlmmFpnxFU+1YakHJtm+DcVfsvlFoP8RRvGBFerO1z5RPlQ1H4dJqj8N5eGjMVY
         uSz9OWxDpHM4N8W+e9pW/A6S5sCxAg8kh0N9efuU+oHhTqU5b0vBCDUqEJRyrF4RtEfF
         BQDz1+ba4I8rctZo4rqSatNExDDGFKQxnvPOZXGd1oeKv/PaG4OsRfdoN9cJdMsSTZAF
         9uuQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=EsvFHtzmIZBJzYRi1SbNJ2ROK/q0HWEQJvqB1XcGV5s=;
        fh=VgTiJ7UvAoK4UJ3u5OGQ0GQI61ooh7BweWovC5SfA7I=;
        b=HMdE9gIPmT8c4U84oYlah3Uf/PXztTo8n6hQqGA6C/o9b7EtkCSNz7ZErHYyI0sMfj
         Ymm85P497mGEQoDacvZ+etFqWOVRinizeJqeYglLYPu29OIY8Vf+Ig/mjdKnGzQuk9DJ
         tBCsw67L4N2ffrnDaq49Ubfwj5T56ez7gNKSd4oVjTL+gfn7W0BzXJaqhnEBIWRErj/W
         sEaUkzk+hjE5weZLMi1PKQr30oc956yWB2TNq1feaEqWDfOdndnU5Ji/j8VkCyIIV3U5
         Q4aCNIbq0v/eUpIOC3z0dal22nHQNDr7i7ZFi+1Kll0ZzFsZ5QSU7TjjbHpybcWx1lvl
         HPXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=e1cuXmoH;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::609 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754574341; x=1755179141; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=EsvFHtzmIZBJzYRi1SbNJ2ROK/q0HWEQJvqB1XcGV5s=;
        b=r6R/KBrUNPLfuiI0fZ+PexBHpiEFaxUwCb5IEkwpF9RFsbjvjqeQUNXznueSHnxRIc
         PiKh3UsuC1C/k0++0NiR/o6i6YOcSfDADbnl2ajawXKeVIh/lUk/Hw9EcpZYQ0d/vZf+
         4kGoP0Rq4kTGcTgJQnRxPHoEHf51mdDbbBuPmG2ktFmnbE6JH4/OnDKKyfSjtNFZ6b78
         TeaAKL5zF4/NzsyAheV+Tn9WBFcZ9MPmGqeVH9Kfy+j/OxnVGBRkG9DGaEQsgGISeelm
         +VIGE1/kIxy0of27cvnkExgCJA9eyeqT7929Yrh9PVpGvJsB1q5lyWwdq7AFoUVh7S+Y
         BsJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754574341; x=1755179141;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EsvFHtzmIZBJzYRi1SbNJ2ROK/q0HWEQJvqB1XcGV5s=;
        b=ULHFVk/cHAeDUs+/m/ga6xhQTA+VDoQ9m7QvMZ/MVMr1A+gxvfNvSHvL13MHtpz8S/
         qp1GMxJtT6VqZ8RP0+ZINDx9Et4VfiHZBhy2tzNFJcdE4TMEYfsHH1QbGniPPcLQU1wG
         8LBUm+g9snBMloI927eYzKlY8BBCKc6lfme3lcrbo719hkUQswCCXYx41WbnUceEIhI+
         bN6QotETEuvNSV57cNZsRGOByCp4by/EO+ojW1HemeGn2rBKh9hd8i6g/JqOAVFIZ5Ap
         OaAA0UKfhnPM817iTuggn/4UKahWYVsPitMX1qWBoi13H+Ipb924nPysmoL0vKPEtXeC
         aRJA==
X-Forwarded-Encrypted: i=3; AJvYcCVGMUv9qnmD1qwLy9F8DDhjqJfjIW+Nv6zvk8VbFhtLleZEnbNu0AkO5fFp53KAAZmM/C8h9g==@lfdr.de
X-Gm-Message-State: AOJu0YyLfjJOCFpMkTgYIXfpUpKB0a0IlfZDhYGqOMuLO1ESKZZXCAH3
	F9muzoTHF9R6WYo9E04ygskQ35+HGuy8V2f1Fl+O5M/MSp6a1O0yVGhY
X-Google-Smtp-Source: AGHT+IEjowilrqM06CEH8dbRsWSY+GR4bHuAw/ynTr3xpmSM/+Grmlz9nlhAYbbR/20S8ISj15jnsA==
X-Received: by 2002:a05:6902:2b09:b0:e8f:f6d2:b706 with SMTP id 3f1490d57ef6-e9028764267mr8280934276.1.1754574340740;
        Thu, 07 Aug 2025 06:45:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf+O89ZexnEGbXt1ZWhILohNqfMpEoyI7xYU/1m72NdiA==
Received: by 2002:a25:6a87:0:b0:e8e:25ed:6b91 with SMTP id 3f1490d57ef6-e9038c99cadls1050637276.2.-pod-prod-02-us;
 Thu, 07 Aug 2025 06:45:39 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW/IBBLqWPCCBzLqaPRxdywlB6+PLrdIc0zr9h8+aUNCwhEUegHjsxFPyb0R1L5I4+zwlPsd36h9VU=@googlegroups.com
X-Received: by 2002:a05:6902:18c7:b0:e90:28eb:16db with SMTP id 3f1490d57ef6-e9028eb18b5mr7797565276.47.1754574339160;
        Thu, 07 Aug 2025 06:45:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754574339; cv=pass;
        d=google.com; s=arc-20240605;
        b=UAxihJYTrBwe80Gp5Rb0Dr1kDYJQQpGj29WVoerfdDXad5XCiqkD7u0Az3MjpnvjXP
         8ljegU0vOEPOVp8oIjC60BdLWHNhdCXXO1jrMmmfMgDXIjAJpxUN99S4EI00NHI4PMH6
         IGqBTF9tIBUsqUbEiDbX9DqxhjgyJor1B0a9qdqgDP6IseSyi1pG4C6i1Js6+C+p2P/q
         Emz7Ry67z2VhpNyyqhuut8i8FPiT91HfYSwuq5CtMGqWi/ypWDMRuZCkE2M2sA0EkmKQ
         KFO5yysrWuOUg04PYfMd8heqLDjCNeMV/42uABCvjxWT3UpMtuy+Md7i2PzYY6JQQnqc
         JJdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BqFmusTHMkkxrcuxFXcvb9JKzx3GQS2+1TQSkSQmtJ8=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=KzvKZRB5DjgLgmB/m2rpprZKsAp0kD0tlX+0RwNSALEM9G4cS3S7n+LwV4WuwLykTY
         prI4fLJTc1FpZwwEvIy+39ZHQvBq4csvFGTEs9dDpVXAOFk++BJNKr6m2yLkFfMRD5C7
         RetvPZGxr4JrlvT1kQY7iTYpz/IKOQZuF0ak5Wu8XrsNa82iFHBqZ7wbm/QUfT1oI0ds
         Vl6bXhaxJbWM++DdfmerQCcfA0WGnKZiypEH4R1W4Xc3VRbcJUBnCHMaujjHl8Q8H59Y
         6cacWPjIiz7Mj7jRfMQlnDms8Ay/qtUmiSyMPlT5lQtquEAj31wqsMwrErf44tZsJ/Pu
         ewwA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=e1cuXmoH;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::609 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-MW2-obe.outbound.protection.outlook.com (mail-mw2nam12on20609.outbound.protection.outlook.com. [2a01:111:f403:200a::609])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e902f1ebf49si134072276.1.2025.08.07.06.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 06:45:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:200a::609 as permitted sender) client-ip=2a01:111:f403:200a::609;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wyPo4KZx1mo4QWXFJhOemGlhQ0nGX1Ev42fztgGvIhBIaWQUfOWPbsaAfrZ9mUl5L5gSc0ru/bDbZs6ytMod5hKqeVSatYKWSNuPDdu+qJRHj5LV4d3ofbLFANbU+qYQmU16FYm/v9/6+oY/2SiR7c88L9uPNMOn8SmLwDiFr7TQ5vNZi1Y1my8JcJkELECA73uxCtAsQ6soCd6MBPKEkGSi2PYnPKzhDaey2I0OgVRntSR0U3TlDOM8g1+66H0aJMweX2ApsSuOuuIsoWLmq6vPfJUBDutY1O4L3jePQGc0ayAhZfEu4R5oemeGKRRZEeAAm5kuhGgPv0JD3mgBmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=BqFmusTHMkkxrcuxFXcvb9JKzx3GQS2+1TQSkSQmtJ8=;
 b=bV5NWJNRbBciaVnywm3XVzKQOdmouKrcuLgG8M2+inVQXL3Di23KJT45Yiu9wcFVbrgijTdw2JjAgRWYcVfBkXZ0AHuQQVf5tzyBRM1z6M1gNrFcncF8nxfJH4utXGj0rEMNy7CRo1Wl2jXYvWd147mNPSRdvOWjLF1NrAU9OX4CeFpRAhOomtV+9gvTASrhFd4h+SIYbOdeDpsNz56erpOvvicif1h561hizzpEWXUDsIwhGYAehDFHZcEuWXAUt9RMWA8wWSHik3zO33e//3c+iC4+erf0heO6vQtAJ8p8pQvUEj50FW8oQGCjCYON35mdvpSlCtLNSySaghXYwQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by SA0PR12MB4397.namprd12.prod.outlook.com (2603:10b6:806:93::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.13; Thu, 7 Aug
 2025 13:45:35 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.017; Thu, 7 Aug 2025
 13:45:34 +0000
Date: Thu, 7 Aug 2025 10:45:33 -0300
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
Subject: Re: [PATCH v1 16/16] nvme-pci: unmap MMIO pages with appropriate
 interface
Message-ID: <20250807134533.GM184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <5b0131f82a3d14acaa85f0d1dd608d2913af84e2.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5b0131f82a3d14acaa85f0d1dd608d2913af84e2.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0366.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:fd::11) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|SA0PR12MB4397:EE_
X-MS-Office365-Filtering-Correlation-Id: f3e4fe19-3ccc-4d01-7dae-08ddd5b8af04
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?WDXvgPGUhS8WpBtlERwsgCYjRKS8Gfx/cjnHty7Q28G4eDSzV9wvqstcw6yw?=
 =?us-ascii?Q?4jfdhirce6xAw/pUbWg3fbu6nHGHyliFkKC9QDf1/ugii2Ei2+Vt0wpphiZY?=
 =?us-ascii?Q?aj4Nrly39ao1YlPg/VaPLQfHxaEoSaTgsoJCECUBIOjPO/QRSvPnFe/dSJMm?=
 =?us-ascii?Q?2uSEY726Har14PSd94XC/dZXlhatbVDjW26+7noxHKuRbNlOSyrdph10h922?=
 =?us-ascii?Q?H49ihXeT9u7QnmflupsSg/8AA6riMyH+fnr5JF59MTFwuNPEG2KPejhDlFsW?=
 =?us-ascii?Q?UQ1ZCjbx6MtvXJf1i+q91VDYUKGmgua3T61eVEbBKmuhsRX0O9qeZyBI2cjW?=
 =?us-ascii?Q?3lXGvTAysEYtawHM6UrdwDS/RiqE9MmYcIG81xSwc7jk/3gx5SKdBpdI5M5u?=
 =?us-ascii?Q?cHFOo1xFGbehxgBp5HLJgDChohFM/uyPRjbLcCKK3Bt4a0lDD0F/UEBVci62?=
 =?us-ascii?Q?qUcWzxDznPoUFBTU2xbJRI4elzPfnEAGc7PKT5OVjO4kmVoYdevktyHVlm9X?=
 =?us-ascii?Q?R6U80lTflsE8pkcZREytNdRvWz1LeLhh+yniYjqYtrx95pMjSPxyPL9Yl8r8?=
 =?us-ascii?Q?TcZhwTLyQMTe5V1NFnq0P8+0ZypVRxN1zbrB7hQMaMTtrHoYEdJU8GNHmToZ?=
 =?us-ascii?Q?aFD9hDD7obzuiUuATRs+PgE2LocXp/6b/vqjAu+iWu5EwebEQRRlwGjiyYhv?=
 =?us-ascii?Q?ybU6OeHsPkfw5DzhD1fvbQ8PqJrV9u2a4YYQsVMMSfuCNivbhlVgEU2Y2+Gq?=
 =?us-ascii?Q?QobKltiJ5+7iWYpfX7BYBIOkQxjgWeg9B67eZmPbJyIrEsUgu6AZx+S9t5Vf?=
 =?us-ascii?Q?xlNvfRerWFyk5Jo7VztKY7NXaS2SVgztXRcfSqefmGOkPNW/Fg5a0YJ1omE4?=
 =?us-ascii?Q?C56pKQn6BgULSoa2XbBpV9Qtko6gcNXUMDNepZsirersNub1k2FQVF8g9TR+?=
 =?us-ascii?Q?EnZdk85xrW3usda8JzmhlO/7bki/ARqgj/gI8zQcRQpNvLXWqmkpL/co6TLw?=
 =?us-ascii?Q?8Emj6s7KSTJx/THFAYF/KVVCEmw/2vQ3cZMdS3UMgalseKK237M5ioEIM0KP?=
 =?us-ascii?Q?PDd/WHWoBQ+Cy7dagZxx6LToQDxTPNDU7MOsRhNoiAzT+NUgcp8b9JklDKNT?=
 =?us-ascii?Q?7XWp1bJ5QnKGVGY6gAe5q7gbj+kMgp2iJbH4zoTHVTg91gDPcdp9/NAiwg3a?=
 =?us-ascii?Q?XRIdRCbeNhPzZaFWSbIFBA/saT91G3GnZGBXU1xQbPQGwI+l5glIegQQTXmZ?=
 =?us-ascii?Q?Llw91xo+W+2hGNGQ/hMD5QTVwtuQTQ8x0J8MXzzc296wQj7bExU8jncVqvFv?=
 =?us-ascii?Q?APhndbVrMQukd7LWC9/D9icY9CA4Rq+/nTh/amGPWSdKtkdSuum5rE7FL6fY?=
 =?us-ascii?Q?Qr3bIPoStYraRAe6EktVj33PwN8klTIuDqo4Wvg7SwfW8PSfL/JKrU3pjaNI?=
 =?us-ascii?Q?LRULsD5Cvuc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?1UQX6TFMBcy6Vs+trTNtXib2FJeK9rtIhNCBceB4mjYhsDlm8RlLJE+/3YqU?=
 =?us-ascii?Q?NbEL3CVunkrrN+XY/L+YoKG47Xj+WtrQ79A6M6RaVD0SooEQp7A6DFOucKiv?=
 =?us-ascii?Q?KMe3PCuB9xxyFwSEiNP79JtO+ffkE8sN2nODlc/1eUZoszWsIn8+7zj4dfcc?=
 =?us-ascii?Q?INRXn6Bk1Ti1gpwzbhCwGWdw2IaAIFqxo1D+935OJ/3sREtvFKnd/CZgPw9X?=
 =?us-ascii?Q?cEx+tdXJFgyCVhX6Sfky+JpBeqG6aWrZ6WZoOm09ipkrCVFfIPlCGn5NNeSe?=
 =?us-ascii?Q?qSYN/KFyVtT28gPfKPtB6QT0xbLhMnBGSB+sHGrfOL0eR2LSnuMhFc8zsBFO?=
 =?us-ascii?Q?e3FIiQELp2lMet8pirel0YnwgKuIYmflzJ5t73L0KZVYii/C0APxPOck453m?=
 =?us-ascii?Q?CkdOHLWVXwizjQGIoMgXngtrShcYYwNADzjNLagLg0XeWFa2nIsJc5BqkMdq?=
 =?us-ascii?Q?EUqHMS0UXFZaVUcZa9Cb5iwFbUG0kq//aUK++pXzR2CODwXmMI5yZ1dD3UYP?=
 =?us-ascii?Q?EHrpvfaLYQHK995WzjZ8EIJ4otP/ebDucVwBjI3Ktffc1/9o8O+SNuuoWUM5?=
 =?us-ascii?Q?gHrqw4clcI4/OchmuM6aASyllQJnGRCtKHCUZFfDqAvYM2WCdP8BZCCvntck?=
 =?us-ascii?Q?Vc501vzs+o38MGfq18fXE0Gn7IwQGlGuq8kh80dVMN0jjGRjYe8OAWW7vWOE?=
 =?us-ascii?Q?6f10j64Vj31KZ6niN3FHHbPHqxrG8Oexr5dhz+/2ZLmSTaeKDs/gxB5q9HeC?=
 =?us-ascii?Q?PbZfpcmWARFDn2H03mjMoo1FbKHPVQSn78HOr+ZXdK97oi5swsKb3K9N/c1t?=
 =?us-ascii?Q?6Ojj1/QCre75J9p5ifpFyXVvTc31dY2kykDbII75dD3JyHMDn4F48V8EHlHA?=
 =?us-ascii?Q?hKakMmdO2KvfwZV2J7ZQMefKQg1MEdvWnz20raKOEtTfEnnwlqGk37Eujnpm?=
 =?us-ascii?Q?s8BTDEu547J+qOkK6B8AyuAdTNOsY+l8EZ1uOUSk+499rTVW4BH7QxrskJi9?=
 =?us-ascii?Q?3LQREu73jz7GJ3i8eRr4/OSgF0bx1uOyJuSTyCJyxvQsiyM3Q66kPMmDNOg2?=
 =?us-ascii?Q?zYQx+ezbZOABwR1PD+97X20i0ufTZp8AJaJlhb1/CGDAwSBggQsLBjAH/PL7?=
 =?us-ascii?Q?Gl2nwK+E66SH+FY6GsKqAEWTYf733qg2Orwuss2yPzEv4V/efxjNvHxFEfok?=
 =?us-ascii?Q?bLIoQPcjsJOxZCiaSX+ZMdInJENJGuCsRxG9gtieicufQqE/4QLPY9TtF9jD?=
 =?us-ascii?Q?JaPUxs6XhFDje/6mIS/2+xYzBfxNTENRN1+b028GqSc++LiOlGKTk0kucdOQ?=
 =?us-ascii?Q?i+J5mVsJgXlT6uU9fdk71HGmoH2SBDiSKrUx4FcIkR23BaV8Aa4d5m8LShgN?=
 =?us-ascii?Q?AnfrpcQ3Z+UHGUdTQV2s7BZlzl+tNG26a45wcsj1STZu8d/BeApaB3RaUX0Q?=
 =?us-ascii?Q?or3atunX0aL1YwD6kd/k8QuuBxhnDtglAopiolpH5JgiXzgo0+79zj6LmbUk?=
 =?us-ascii?Q?yKXaKol+waFIOYy1llv+zijOATP73oox90sNk6cTZrkvFotnMsv/4o/cYPiB?=
 =?us-ascii?Q?AZlMssGxT0v5NtcFpn8=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f3e4fe19-3ccc-4d01-7dae-08ddd5b8af04
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2025 13:45:34.5501
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: GQXX17i367Y+FuswGMUuSDPrOAkEDNqGpfqZ4jQggDW/X3Rs51lZS9V9SpsgjtzN
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA0PR12MB4397
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=e1cuXmoH;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:200a::609 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Aug 04, 2025 at 03:42:50PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Block layer maps MMIO memory through dma_map_phys() interface
> with help of DMA_ATTR_MMIO attribute. There is a need to unmap
> that memory with the appropriate unmap function.

Be specific, AFIACT the issue is that on dma_ops platforms the map
will call ops->map_resource for ATTR_MMIO so we must have the unmap
call ops->unmap_resournce

Maybe these patches should be swapped then, as adding ATTR_MMIO seems
like it created this issue?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807134533.GM184255%40nvidia.com.
