Return-Path: <kasan-dev+bncBD6LBUWO5UMBBBNEYLCQMGQE6ETVIIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B9D9B3A807
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 19:29:44 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-246266f9ae1sf11586605ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:29:43 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756402182; cv=pass;
        d=google.com; s=arc-20240605;
        b=L+X50wXbIrdpCtnJHVCjeDDpwEPd4GeqOXUo1Bjfxc/vuGKnd++fC9xfD8b1bipNUq
         CKpZpOG8Ih8LMJfRxWwj6Lpx6zu/zJKlIMA82kPvXvr1SJHzRo0UUM2Hkv0KBQndjcUq
         2OmnDf7GyrHgGKUvkcTj03ya/srwr9ltsd02sYZ3w89alu9tRxOrD5SnxbOIpNaKF28k
         r9bnIFLWm0nGVEZhQcbwzgy94Glazt7Okw8wTxBB8uJbVB0UNdmpkg97hiQREQ9M6XmX
         4hJjrLJqLn2S7rLWAXrj1nO59dMmvjLzTd+SlXhi9yfqiLG7dgwWbGitMWcUvSFhPkfb
         kG3Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=RDH/0nZUry68WoVe3oxcCBw88hz3qegYwT4A6EPCHZU=;
        fh=uJfvloaOgUbEuJ3+/VdJejxk8ycbbC2GvUEyVVwjqto=;
        b=hv5KegjOSbAxk4d6fzMzct9HuICeniXsaOydUl/+1ItWZbWZAZrfOPUZYJTzGnYrjp
         +RWKNWRppbR2/q/doP5Y11lccH6U8Nuhwed8mTgAhbC3vabk13Uk2QfS5WIytErz9afC
         kskPSeTZST/8Ox5iM7NCgJfT5pklwqTGTSaO79nPrcCTgPFYaYqF3JY7eH2Vo+SkkDiN
         FVwreD3s/dY1WPPcG/KLPlsAOjH1w7/BxBVe0DGfUNiYsNvTtwcv6GiIrdQS6FYhov9C
         U12J+sD6+Ejx4IpLY+SZeOq0MGiLZCkH/WXuE5rR6S4ZTjFy1uttU5SCHZL+deq7/U+I
         JFbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=JsERbD3I;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=YB+XsRZT;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756402182; x=1757006982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=RDH/0nZUry68WoVe3oxcCBw88hz3qegYwT4A6EPCHZU=;
        b=LDE+7HhFalVw0oENe4KnYQidIeFgExSVlhXO4xhubdf14yk5N5jrvhT3JZEd+7giL9
         6gn5EpdyE4D/STZK5Bc0Z5Pcn0KMyEVCaNWGUVukmgW55+LrIj2VL3K11YCke/xZrQn9
         9FuK2x2jJov073bCW/vRfOxXcMLHEztSqBjsczGXt9k2CEMBqobDwagv5or/I7VjA3LP
         IkzlV4Pj2nMQSQC0M43E/NU0VfCfmgTGP1RtwMceeaS91ZzhLdwK6UHZSny9WMvj/KFs
         w8e/87YVO7DNWYzLZwMHrYJr7VYSFTuY1kMIrPgqg5FF4aBI39n2GwXWHT9eQROfWlhg
         m9zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756402182; x=1757006982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RDH/0nZUry68WoVe3oxcCBw88hz3qegYwT4A6EPCHZU=;
        b=Co0AAfBPNP3QM5apYqqY+QgMBRolzf/d64WvBdSCiniReVKt8WIABjBx5ddmvbm1kt
         4ooJUHS2OOK84RSO5jffh/Y2y66jN4pv/zXOlkhdOjIB+pIbF997VgXBnNbV7iurGVtE
         hsYfxaZePdoRccIkW8ts2jSTEABwCJLh7OgIZzpXhsSd0EOn05NSAN2K5yESzUR3xhpS
         g0ttzqBkkG4t00HoUX3L32k5DGsrsYAeYn1y3paeYLZeG4mpPpzbKWGN6qt8zvV5c/Op
         8A1QIuoW0RH1bzCWLJFDPwg0mbXasu+76Nq6SKhdOVG4lZmDzbNjCfWRvjlDVS0l+sYE
         +eJg==
X-Forwarded-Encrypted: i=3; AJvYcCXoWAZ3lqMy1y5iApnJK5lc0WEwJFymtypjgzC9W6L2rgXhILXCobiYglYZoa1I2zAYsXpIEg==@lfdr.de
X-Gm-Message-State: AOJu0YwVwteIeOCzpRqKzPVJK1UvqOT/xDGVaj1M4byZGRQFxHBf1Y3U
	+9YpMIHQ1m56J0BnzNuB+MTKTV/xegK+Uyw4nHbZU6HrGNRtcLtW2nSF
X-Google-Smtp-Source: AGHT+IFEPdEz4+7+IMmQr6eh4Q3H2+lcQqLWaWKRYiIkWysBMCW06dDper3lAFmag5N9NYvFIOs98g==
X-Received: by 2002:a17:902:ce81:b0:246:ea6a:6ed5 with SMTP id d9443c01a7336-246ea79baf7mr178032615ad.34.1756402181546;
        Thu, 28 Aug 2025 10:29:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfcUrmFSJyt8mqoiymaZrJ6eo9BEwO+5SSx1Hygh6BmNQ==
Received: by 2002:a17:903:2845:b0:240:9e9:b889 with SMTP id
 d9443c01a7336-248d4e0a518ls7534515ad.1.-pod-prod-01-us; Thu, 28 Aug 2025
 10:29:40 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXCmumaFRcSqScOLFMv479gf8CqOhA5iyUOSZvaZbo5tsgenlM7iTSKBZ3zkexoVv7NeY0ZSmljkOE=@googlegroups.com
X-Received: by 2002:a17:903:1aed:b0:248:d84a:91df with SMTP id d9443c01a7336-248d84a94efmr49646345ad.26.1756402180148;
        Thu, 28 Aug 2025 10:29:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756402180; cv=pass;
        d=google.com; s=arc-20240605;
        b=AjFE2l4/QSU2rnS2ReXnmp8elsKmHi5v8PpDOS40h7I13mPZzi7Mz4pLhslfV478eW
         t112luNJXR+UPbjjWv37HBHhIt5N3us0gcnuk+RNmuszDcDZehveb5Kv8u+MA7IDXDz3
         xFR8J+thCvfAh9pfaVv1jBHzEnSWvJ0JgSOFqjVGY23bc0uSsqWiC/QHZYPQP5d80LiB
         d/aINsbEAgDiXK7tKzlMV4EBPrMNbEmPh8f/GUUTS7T0n6aSrU5MSsvlYonpiFkUaxHM
         9on/r+5Y7PAei8F6QJTaTyMbpzWSzOWoxSzg+V9/VVHwLijgMCXsWOnyBAt5bSmvn/7V
         Jifw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=TapbqgrrpmxfKpvaT3AtnRXyn57Ar30nmh28N+TqlhA=;
        fh=4c2x658PUxLU1tUoMuEpnwYo/1ZMAVNN0mOOGy8Hbtc=;
        b=YyHeKHlCfaNal64i+LuefZatfC0gWHR7mM/zDy4k0GkPGrd1oPTXBQBeTAsZ3TxeEV
         VvE0Cq64ghoCdDz+LehDuE73ZzY0zL9tD4SwoXxORnw7xHjziBoVmTLBE+7NsLik/y57
         pkHXyJIm4qS1Rlt28x5Ngi+mR/hREzd6JuVfi+p7amEJ5xQykFn7hRawUWWK5S7TJXTH
         188LhSFzIdoNwgRmRRycECB1Drv9mhGlAZpNoj0OCfnd5kYgep6h4Kii9ybK7XqQ6WQE
         KE+VIoGPUsx9zoWRZ9U9X6ysQQSSdllYuen6AMDFC0FJdsjwNK7lVciZ7EZOv5EeUHw1
         w84A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=JsERbD3I;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=YB+XsRZT;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f538490si187568a91.1.2025.08.28.10.29.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 10:29:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHN8F9005462;
	Thu, 28 Aug 2025 17:29:31 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q67911rc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:29:30 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHM0j7005282;
	Thu, 28 Aug 2025 17:29:29 GMT
Received: from nam04-bn8-obe.outbound.protection.outlook.com (mail-bn8nam04on2050.outbound.protection.outlook.com [40.107.100.50])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48qj8ce1cc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:29:29 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MrzV/SO4+BgQFo3FktHVwMufWBJE0ruzrTBi5qyB+NjopvuNC/CId2nwUQQ4zJXcmxGYepOhhOeswmLNjADKpFJRjYFEOaHhQqvyK2EK4q7eDX9Dzhe9PCW6mHLUzxJYSyregE2s0LQiNNYDNTmN2jZoKCS5iXxs+MQZjlffHy1/sE/Z9TdA9LOuQGs57+fi0uxh1hBliQLIe/7lnp5CVfnE03xuQBuzVqewnvnU2RS/hUfsQsmR3IcAMVjFLX/x/U/N+1E22Bk0bSvG3dsGqVARAaMj0wZPnB254WQAeAl9gXqgdYXOlmQDxauKqkLVdJkO07L1H8KdWxUEim8HQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TapbqgrrpmxfKpvaT3AtnRXyn57Ar30nmh28N+TqlhA=;
 b=WBvcKszbTR1Z3k811FmEcvmOpJcz4ODG4wpYmbNeeJ6XVbs0yh9PEAhZEX1aQaYquG4lZye2GEK69IWd8RlE1Gd9lfojxOEBF4YMXbuTK9YKS2ZzhysXIzVdy7o/Mjdr2XWszyjveZzqEBxzbBLpAeLYE9tH7Q23Fltnjr524eLfgKCSp+fpS/aRyyQDK9GFB/rEfxUn+cNy6I9RyJXCxTwrRuf2sW/K3cYovfa4wVmUnzebzoFr8JcKMvrRcaun7+Juspf55gRTkm0LZApO8pubgJybNfxufdJx4UDyTRD0A2XHV19lCNvQQv4XVnvQ5+9ErmzYCY/HmN0hdulPtA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by BY5PR10MB4388.namprd10.prod.outlook.com (2603:10b6:a03:212::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.16; Thu, 28 Aug
 2025 17:29:21 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 17:29:21 +0000
Date: Thu, 28 Aug 2025 18:29:12 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Marek Szyprowski <m.szyprowski@samsung.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 22/36] dma-remap: drop nth_page() in
 dma_common_contiguous_remap()
Message-ID: <7cfdbb15-72c1-47e7-b5e0-b8a243f2a516@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-23-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-23-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0305.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:196::22) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|BY5PR10MB4388:EE_
X-MS-Office365-Filtering-Correlation-Id: ffc4ef2d-6805-4ecf-bc8d-08dde6586cea
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?NPD79wBXeHtrfYMsCs7+Y+bvxbGES2eU0cLdHeh2xruoKvj3fpWzxdRlXrJL?=
 =?us-ascii?Q?hmGyhql9jnnzgMLR0am0vkwRoLwmXbrAy45oT42SfKWQPFPxRfbZZKvwROne?=
 =?us-ascii?Q?L14QW8JS1KWA4+jc5/OGF538wMeAKMYmQWTDsAK7iwpRRilgtiM9J11WKKHP?=
 =?us-ascii?Q?fxAaCWHh2tr69LgC3fjLmj96CkUKVfyASkVfSGp+qwBwYURdGgGWW08RMB/B?=
 =?us-ascii?Q?FKLvlYsqsGv9YQE0f+Mm80KpN0Via4LASvODgBKIZl7Yyi446Dxr0dHxJBy8?=
 =?us-ascii?Q?mM4RIYXwdZ1uaWZBZ5KxC+iWorqkXgM89+H1/QuGjeBtmdD7GpBJOZLmWSEC?=
 =?us-ascii?Q?fAZ8usTsfUg/YTSOlSRHgVYnBWRgeQ6Pc0jrUlUP3d5+pRr2epcVEpAYtAz3?=
 =?us-ascii?Q?o+m/RgP7ZGbKBD1b02S0zvFNND2LpxWJxmOIdLjym1MliDYu7SVJMtFRdRex?=
 =?us-ascii?Q?XFDJbwTwPT7iKIE7Ju1EVaSbe9ZyttfpeKok0Jwnt/aSNWkDhH6N4ApbQ/2u?=
 =?us-ascii?Q?IiksZwCPbkskkcmWwAJf1iadAVLHz5htG4WoNeHkQRb0T/tco+jCGRvrDjK9?=
 =?us-ascii?Q?GEGWT6Fp2JZEvFAag1mODEjTwxr2kGfDPBJBKqw6VnNNdBqcPoOEJbMXcFtk?=
 =?us-ascii?Q?gHciGxYqn23CF9o5rXrlgH8wjcBBVYSmbwhndJ6uaKUnBkIBtEo26IUUlSYU?=
 =?us-ascii?Q?DChq0Sgblabqc3twE2/+u+OdKea0WSGAbC+c6GCECsCrQ0MLWrBlBNwm3wkO?=
 =?us-ascii?Q?zy2SsCUHd7oOxvkwej3KbD5DbmiF+TuxHECBKXkTprdlclzxs+5J+N/VWCwB?=
 =?us-ascii?Q?TXzniuxPOeYBN/PjLS7NCaWmO8wCPgoss7Lvy2mVNlxkla9eWae5yyW8X7O+?=
 =?us-ascii?Q?Z0Gq+T+1hQjO69enDHZfYbiDe9tsKG1v7y87jBcSASKVT+QsSVC/uf469iu6?=
 =?us-ascii?Q?v7L49i/KzjN81r+I20gjHY8FpirD4z4dlao6AIimGqpR+6vd7dzIfVyKthk2?=
 =?us-ascii?Q?afqd1c9SWfTSjiEtlkuV4Zqo/sGOcSYgbR+M2pW13l3ZT8kqurr/r8PLNE1H?=
 =?us-ascii?Q?B4jC/bDejlCyBRAv5oJp3HjCFK0FjGu26V+dQrwHG9Q2qTUwkXKjeg+4+1mG?=
 =?us-ascii?Q?ULKiW4GBr08V4VUnpGFGn/I+M5qpVhQPihwLjHhddmJya0U/AVXHT8k8MnXC?=
 =?us-ascii?Q?ykkKT+zENGEYYYko+vHh74xRpWRLrUZAjnzI4JYBEhtx2Uwq2hKE9K44Zlrk?=
 =?us-ascii?Q?LmOqVfjxv8L9jXSJIR0vjFtIn/eNUzWoL+6f8rqY/8GNVJTQalDXpNkRDGSd?=
 =?us-ascii?Q?C5bFaYUg+Ji7Pmyv6/O/xy3I7rXlLq1s/Xnz5HjjAfYjTCmwee2CyHhSiCSM?=
 =?us-ascii?Q?ypXyJ+crXugKSW73M4Zg66F/Ib+DuiT0fVweBbOtQEYjr2tFXcikmLN7XSME?=
 =?us-ascii?Q?oYV3K0PH9ik=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?YTxSn/OxHzdlkn3Z9CUlLrLDCh/E3dhD8/FDv3TNvGs99HLNh1nTecZ4fXNd?=
 =?us-ascii?Q?pTS7BokIpZVQ+GMqfc8Gs+qUsFzncyHrw0M4cnpJT3s0Kelk8ZD4k3Pwxris?=
 =?us-ascii?Q?u0OM7sRCQTxUW3/T3RSQK59IIA8CWgFhuW5gwlhFZqrt3+3xXwxaObeup5mC?=
 =?us-ascii?Q?TcqABDV7eKEMkM13iE0JO+pANXuxucRqNKKZnn76FJH0PquOUsO6QZFbcfPj?=
 =?us-ascii?Q?FFZYmS+UG1NFGgGZLB/2SCCiy5iH7fhNwLcnjLvFP6yQvIKgTMh0YgodfTXa?=
 =?us-ascii?Q?U9b+isCCu6CiB/UlMryVC+1Rpe0YgekhWydfTWw/rA2hfzJi8w4wHMUWE9Wm?=
 =?us-ascii?Q?P30JDTtRJ4W9i/uZkWczzUtZFh7vLwEjaJfG7CBh38LCWPHedgFLLGyJMX2X?=
 =?us-ascii?Q?tspWE4fmg9PTFBGw6jDOdtEfvT3p5pHva/ZqQpBXO3ISCMCg+d/syOy91P1d?=
 =?us-ascii?Q?KSearcCm1Ex+/jF70NRQOU5WwAoi7aC81zC1YeRAohyz2O/MdfQtfmLm/xU3?=
 =?us-ascii?Q?B2Y9/HmlHJp8c7kIwAEyqwFDuLCbJMgJigQ9rEKpTfKyE32R9LQM3b84pLUF?=
 =?us-ascii?Q?ViqJWUYKwc4KdbGfWIxfTPBmzSLEzO5sd2JWbIlzMoHU7vUBeOfVmX50vu97?=
 =?us-ascii?Q?eC4g3AH+0RqUZFq9kQO9D+KtwWMo125yaaCezngOvnQjU8bNGjuiVlcWZ7t3?=
 =?us-ascii?Q?+eEOxmTbMIJwMmWk0lyl2nygkBmQwQGrbFC0Qt7CDAZ8uW5gWirTnyf6DSaS?=
 =?us-ascii?Q?azaf8pu+tnzE4pxZCkIc+LB3/47aG9nlwwue/rTwFptXVC9PFTMeai1jYeZ6?=
 =?us-ascii?Q?CUxaNjU/8kc3R+tK+mBczHOftwF5z6g/WY/bX+WeWo+m5tyQxxbQE0Fa6jK5?=
 =?us-ascii?Q?Dt+Ad1tJG55ejRe1tLm+ryt+mWwvFOS6TuRGX5MsgBRzNlsBlzK/Bdr+rFxM?=
 =?us-ascii?Q?4R794ETCqtx6T7sdR4zP0F0fSSTiYb3EfTolotsjjjTAVwcBfVoDzRmQCmPZ?=
 =?us-ascii?Q?NRd9zwj6lPmM1Nj4qJcqG4ah2d4mfZUcwQqx2xz1IRGfb2rZ4Xqy5u5tW1MA?=
 =?us-ascii?Q?4tJRiORvK1vcnzNAIPHIQBzGPXUbwti8HiavMSaj3b2EDdQA71yPEWdvyaJ1?=
 =?us-ascii?Q?R8ZTau6RI29ZK4I55QvGysYJrOJ/hNx8wV2OVkiNKtLVN9iknlyNHCVdW01D?=
 =?us-ascii?Q?hjcYjsNmxu8s6wlL0Q3gILoHfGZcYERcRn5JPbQAKf45qHakLHC7rL02405f?=
 =?us-ascii?Q?pi4inF4YOq93ibit7RojrV/jl0gLIbYg12vyPdsYOunainU/vJ9sMa9hYBQW?=
 =?us-ascii?Q?HBWe2RmaZFYQsMdgo1E9yZ6iQvJcyH86wxAf9cdsjvUYhTiC4ri/b9I8IVhX?=
 =?us-ascii?Q?iBKX8f51jLCRu0yXbxQxWYVOKVGHNGi2kOD1ES9gAuj6jLy4XYJi3KS302e9?=
 =?us-ascii?Q?qjkz1V+/HRhkMp9NzQ6cVHWDyF1NBrT/i1YcuHUrJy7Hhrb3ADtJmp8wHqwv?=
 =?us-ascii?Q?xZDNV7SgLrD1JPDxfhEDTFj/w2wUAREHWG/WWazseSUSw0U26uh8VFKsVcgS?=
 =?us-ascii?Q?xcAQkQzeGbJlTYfbXowryC4E/q/xWhXOR5YSPbkE8w1A7pDGQ3iH0SbSsw7Z?=
 =?us-ascii?Q?MQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: TrcL4+W+nzOLW+zrBSxMMuC94H6tqZeL1DKUv9slXVxywE2pVBrHGrwaddFnv+x5B1VHNkDd4LYb2SUBkuFCy3oGv1Remr7pOc2lJ9KyXiLyvNNjAHsjAMD/sU6masjSVTgCkWUO1ckJ0dDEod7YZ0hURTFynU3oJDtcREQSJEBs9ZEhLzi7unILCxYLlzOVP3eJ1B8BOpisxui8cwLvyGr/WN/0b/Uh5EX9cF/YeGRkCMJ0ltG16cERcGW43/kYFaO4PcZLwk/vtZWdzN8PRGQolpsSrOIB9Ez1bGR/DjntBQWN/47W6w+Xza7pOgG6qiOVd/Ihq3tIjT535IuZmhSRMdoXjjEzfpgZeA+2wp/Nmy0VmSyaDbRLW7mxjQUiQNL+fB8eIjn9mOmM9E6HKBlqZ/jiNTFLWQ47gMt/HcS+pYlVi5F2XoSXvqdZj69jrz+f9O6cTnDVq+qCej2oDRtLG8/6q1qjvutGuDYLCrORYULPe0XeJlr2RcKCTrxoi1FuA3wq11zZJPOWlKJ0FH4t7/g/sWxF/wsC1bsjA91uY6veqjBS63IHMVbtT1J47JBBZL5tp3DCJjdUeYWJJ2I76pzHAlp5feEeOIYCekw=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ffc4ef2d-6805-4ecf-bc8d-08dde6586cea
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 17:29:21.5911
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: MijRJB2MsjIHV76EsCrzinBHU6Kgrv6qDGiSPD/daKk6Tfxw6hV5eEy/ohO6UYqlifc9X6SEKxYYRoV5y+QTSrJcOfn7WoaW/BKGpu0gxYA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BY5PR10MB4388
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 suspectscore=0 spamscore=0
 phishscore=0 bulkscore=0 mlxscore=0 mlxlogscore=999 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280146
X-Proofpoint-GUID: Ts-36qijL1syMGnzqCdNQqYjf1ur9OgH
X-Proofpoint-ORIG-GUID: Ts-36qijL1syMGnzqCdNQqYjf1ur9OgH
X-Authority-Analysis: v=2.4 cv=NrLRc9dJ c=1 sm=1 tr=0 ts=68b091fb b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=hD80L64hAAAA:8 a=7CQSdrXTAAAA:8
 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8 a=7cRu4o-oBh6fblPocasA:9 a=CjuIK1q_8ugA:10
 a=a-qgeE7W1pNrGK8U0ZQC:22 cc=ntf awl=host:12068
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzNSBTYWx0ZWRfX6DCfHiWxinNh
 KTsvvKMF/z656Mo1L39S3KAr/+Y7lWMiAs0r/TqODpE4kSsXrbHCDMgABZTHPxvVKiKR/xZ3JbE
 NWR874p9rDZVrIjBDcb/ZIhrGJWlo4cWigc6vZbw3eMIIi2OwCPPLA1VqHX8bciK62DVU19zn8w
 bGBxJ8EIHaH5JHMkMbDw6hgzQ+C7PiTEU47k33IqgqXxbTNrDZpeRYwbs5YzSQehum0ouzzBbva
 gWZPG88b9ecl2TSiGgO2aDQ/kkeLN5NNX0aX//RkI8Ga1eY1bpYLoY0uDKtJpYk85Cxs24gTmqE
 /5imAiUSTCu/mJGDyKa7vKPbZXkAgCtNnM4myKkPF2szH48ak0ydLCrddV73QFpQUY16Zbmk5NC
 4LrhyaDtA2scxw1mwu2AggUHF0ZavQ==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=JsERbD3I;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=YB+XsRZT;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Thu, Aug 28, 2025 at 12:01:26AM +0200, David Hildenbrand wrote:
> dma_common_contiguous_remap() is used to remap an "allocated contiguous
> region". Within a single allocation, there is no need to use nth_page()
> anymore.
>
> Neither the buddy, nor hugetlb, nor CMA will hand out problematic page
> ranges.
>
> Acked-by: Marek Szyprowski <m.szyprowski@samsung.com>
> Cc: Marek Szyprowski <m.szyprowski@samsung.com>
> Cc: Robin Murphy <robin.murphy@arm.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Nice!

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  kernel/dma/remap.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/dma/remap.c b/kernel/dma/remap.c
> index 9e2afad1c6152..b7c1c0c92d0c8 100644
> --- a/kernel/dma/remap.c
> +++ b/kernel/dma/remap.c
> @@ -49,7 +49,7 @@ void *dma_common_contiguous_remap(struct page *page, size_t size,
>  	if (!pages)
>  		return NULL;
>  	for (i = 0; i < count; i++)
> -		pages[i] = nth_page(page, i);
> +		pages[i] = page++;
>  	vaddr = vmap(pages, count, VM_DMA_COHERENT, prot);
>  	kvfree(pages);
>
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7cfdbb15-72c1-47e7-b5e0-b8a243f2a516%40lucifer.local.
