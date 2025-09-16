Return-Path: <kasan-dev+bncBCN77QHK3UIBBS54U3DAMGQEYDX6RFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B87FB59F3B
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 19:28:45 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-26076dd11d1sf41887805ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 10:28:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758043724; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZHXVzE9/CfLO8RRUXmFj3WajovvSlrTmgcXHyUhfJo67hJwFMMEjFlRP8GVMMbMUiz
         BmUVUOILpT9NC+bzp74IH9rDSQajqu5//EscrMj+Aj8xeD+zb2Jf7ZIjUvmfmS99qzC7
         34cIHx/ON1Lzt5fZDJmzj+HBCddVh8gdxWcq+pbKZbF8q2EeCYWgRKlalYytURrsqLtO
         227f22mfhiJDWR3hhr5IMFCzl3SQnXetZNZV8fvLqYGoDRyZDWz6Fd8p2ZuaWudwJKHg
         1HO/RaIOOcbe+ZbL3wiO1ozd9dJ5jxCj0RcpfVKFAfIWFP1whj+nY1/CQPjv2D2d2sW0
         R7pg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=jF/piEtKdOQMJ0HPYAHLxAIYZawz5KVuQi9kwxzoOi8=;
        fh=PVrE/dDzOqdzKq72SfVTfGwzsALSGqer7bj9Far667U=;
        b=hGObxvQJHjyYoCLNLboz7B0Ponv2QFXlWnnw1uL5U4YAf9Nf/e1ZgSNqh7b3F/H8bH
         XCLRtIufoL5gE6JtLMohf+OmsNOSJeTI/u8C87e+VuuH56qIvGiXACh9CUDXisdZAs4j
         18fPK3TqmBDwENEqr3HblJeOhW303pMN863O6XvdnjeBd6XAjp1cnF58DHZwLxshRSPk
         LIgYYchwDQENz8suBy+YGil1CHnbvCJlj/KvLTL4pikx50kWg1un4VR/ErY04DRbeuZs
         CmNDwhTfpoFegycwcBfk/NUGFbFj71+GapioqVymatHEV7+0OMXAJRfZQqYEkjJkpHyz
         a7Cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="rc/mtPgq";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758043724; x=1758648524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=jF/piEtKdOQMJ0HPYAHLxAIYZawz5KVuQi9kwxzoOi8=;
        b=N/7mcKrJDoERJ5jPC8AaE70q6EkvNttvnYEXNqajE2GxN1e0QPwpm+rRFIpW05ayuH
         ytihGt8LObaNQlIqW0UVovR4y699ea3etHZRU25ZZQYVBhcw4Hpda+In7y7Ammq61wjJ
         MuzQ8JUd+KsVfRSRlcpGROEakSoqn3pIVG5K3m2G/RXha4Nq4E6orst/VPbdJ4moZ/l6
         dCnYvEaOLVbPug2qtrngo8B3gXcz86mqyrleZKeBdeF1zToVQe5W/vfWuZocHbMToarM
         dr/3C169PTflTAKANcBw8o4nb1DBxqBp2rxg29poWkTQ/uBmXed/IDaxj9TqkhiS7SaY
         JM1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758043724; x=1758648524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jF/piEtKdOQMJ0HPYAHLxAIYZawz5KVuQi9kwxzoOi8=;
        b=HkDHdkPOVnk0zwtwQs8eYPKMsTgGa2L+gBp8HkFVgDWO984WsRExOuic8JrEfqa/r9
         Rt5Fae+kO08wrG1zsoTwWT5YmXM5Czr5MrIy9MSDW0XGyzaJBVclQVpEX6m9ZoOo7qzF
         F8N83efEXfnh//W77WVMbhbG5Naaz5rVZVXhxwrFRPwrv9B64fxlsBNCh5WMfmSdm8j4
         6ID8xgwV+93XHSitXTMzFYzMEgkawMlS0Nh0NDgH23AxQLi1QpuUGhztcR1mXJ6j2tOj
         WDlj0KhbD2zT3Z+nZjP4tDyuLjACF+FINriAwKcw+rWNsET5Wy4MAvOyfea9vRlGPzpO
         bmEA==
X-Forwarded-Encrypted: i=3; AJvYcCW8fNP22j4OiW1EbhU5cBAF5CsPMPnLYUWT857ieeqFsQ1AjPkzjeLbF8GWWx4RhWdqs3kHHA==@lfdr.de
X-Gm-Message-State: AOJu0YyGTWivKOdZtv0vyQ9J9LoVoCf4BYPSi/EMawnUUVMF2rJM2QYl
	9Sr/2ebZwnqozMu57Ox3Ihr38RMzha5mM4kVKvxxj7VyTmKr3x+SfIft
X-Google-Smtp-Source: AGHT+IHdVNoJfiaMXPMACY/H3VLosvSnoWRCXJEYr+4nMrtSVPnR+r0LSwp5PbIe9pi3fHme06M2Zw==
X-Received: by 2002:a17:903:37c7:b0:248:f84f:fd3c with SMTP id d9443c01a7336-25d24bae624mr187461335ad.13.1758043723495;
        Tue, 16 Sep 2025 10:28:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd57uR2gYz2z9aacXsY0rxFy5JAJ5J3WRb+hDRnspfEJRQ==
Received: by 2002:a17:902:e887:b0:267:a5af:4d5b with SMTP id
 d9443c01a7336-267a5af507als18715625ad.1.-pod-prod-07-us; Tue, 16 Sep 2025
 10:28:42 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVeGm6rYdgOjz1Sb3/RNUB5L49k0XmabL2YWFNtId1CHTKOyZc88XUi7770SvdYfjB3lABX/vCGqrk=@googlegroups.com
X-Received: by 2002:a17:903:f8b:b0:246:80ef:87fc with SMTP id d9443c01a7336-25d2713424fmr188376615ad.45.1758043722176;
        Tue, 16 Sep 2025 10:28:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758043722; cv=pass;
        d=google.com; s=arc-20240605;
        b=TNB6UPCJD2GtOzUcPfzj9dkgqia+fSlKRH6KNQ2ci8AEYRawWqM9k/BtTSXCPqcIrI
         CXNLanuMAW/8AFBxVgVUDhCihnOglsZtHjHP/C2NaknnzMPGtGtZ9Ara2g/goPnIo3xG
         eQuKlhGqQjWLbnntZQjtni6+8J7DRaYmvoFNvYOis2+5YMReGEpGHqSdnIv77iTpuFKd
         QgwwHWcFoJ1+iEuWx9HIeT9pYiXs8HMmYrKMuRZ0EMRHs1zATK8fwfcSeXwZxCzXxgEh
         5DCj14PJuL4IRlWEgipMM6lxQAaVpB6Qr3q+4rPKIIxHYJZnK9SOK8Tw4Yc+e/hTIUkS
         3a9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=h7B2Dvx26EpWDjI/0jhZDqtnCxFEiRJ8IR4BdGm0584=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=WNmG/CCPPNSVI5qxT5bgcG8lBVwjsOJfcKUuRmgmbFtqkuLy/X96nMh+yp2tWC9Y6U
         J5s0cT+ANiScdytSuDPomNOi6e0EfGDwKQljYU9fn+uFGnlReCbwFbPA8SroFkm+hSD7
         1RZX8P3jJX7sCfAUkbzM37O9JoQrJyyFj3vGJbI8RCBMw56+oA9WnzLtN/fMweHl/KrN
         1U66S9T+ZxZfYR0ci6CdLDcql6L8n2kkDXM0zHHvlTapP9brnX38h27PlWkFlQeNT9gO
         u6QmzoVRcSqBVKfaj1eC3jEb/QcQRsy8N5M9TkGoBYs1qRRy4/OGogfYUPmYhhfwE5zh
         RgNQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="rc/mtPgq";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CH4PR04CU002.outbound.protection.outlook.com (mail-northcentralusazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c105::7])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25c343a2a21si1256855ad.0.2025.09.16.10.28.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 10:28:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c105::7 as permitted sender) client-ip=2a01:111:f403:c105::7;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=lgelt+GhIPZkokFW0CGSvV1pC/yv8ijl96Xw0bFGwp/rt8JfqDMQx/8ls89JD7Mnffh5kBGn2dHoKns9EDNq1juCkI/FrvT4FzRV95T6emgv/dqA1hwxkeXNM+3CAvaEFw8lr3dwFgk9motoa3AdD+0spu+eeS1VpNud1y82jKtMqme5ACp9qKfquszTdEpzRy/6TB5jIyHSEJ4O/JKQxnqkLmv4Mm7iUYfiVGvjW93Q0Amry1vzHKECsn8lYwBHu5FsDGqciSIiw8LQfxVc2jEGN7KPsqwps8qTcUhma2zwydvC3Os4YxhkBW2uHLnU4k3F15MIiyGxd+HLbSumEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=h7B2Dvx26EpWDjI/0jhZDqtnCxFEiRJ8IR4BdGm0584=;
 b=tWnhy9X10nxOUQJbiAxIPMDWXea6o7O7GQI/FX5ziI5b3nTItOEVpmyJf5vrrreS8ZnibZn4rRcBdjjdytFIgPqK/70ruI4AGno3Wj7Y7ahatZJQ8h1ZHhDmaQMd4OMT5qBNUeuHjBCcl4QJ+G0x1Lk78hZY4S7vWtgJRNhNjKdYiHopC4+XT4cMZKmoBoamLsXMe36UEi63xeUKzWB3MUSHaHe7ty+TqobOcAP3K3ay3EjY702cw89X1te9qPhuIAQo1OXhiGkUbp51yLOPNq1iLt8FYXPeP3hTieqCNYpXr7mezrbJ8mZouHu5FFi6c3W09/k3fOlIgD5ud0Gs0w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by MW6PR12MB8959.namprd12.prod.outlook.com (2603:10b6:303:23c::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.22; Tue, 16 Sep
 2025 17:28:38 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 17:28:38 +0000
Date: Tue, 16 Sep 2025 14:28:36 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	"David S . Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Dan Williams <dan.j.williams@intel.com>,
	Vishal Verma <vishal.l.verma@intel.com>,
	Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
	Muchun Song <muchun.song@linux.dev>,
	Oscar Salvador <osalvador@suse.de>,
	David Hildenbrand <david@redhat.com>,
	Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
	Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
	Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
	Reinette Chatre <reinette.chatre@intel.com>,
	Dave Martin <Dave.Martin@arm.com>,
	James Morse <james.morse@arm.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	"Liam R . Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Hugh Dickins <hughd@google.com>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
	sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
	linux-cxl@vger.kernel.org, linux-mm@kvack.org,
	ntfs3@lists.linux.dev, kexec@lists.infradead.org,
	kasan-dev@googlegroups.com, iommu@lists.linux.dev,
	Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v3 08/13] mm: add ability to take further action in
 vm_area_desc
Message-ID: <20250916172836.GQ1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <9171f81e64fcb94243703aa9a7da822b5f2ff302.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9171f81e64fcb94243703aa9a7da822b5f2ff302.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: SA1PR02CA0023.namprd02.prod.outlook.com
 (2603:10b6:806:2cf::25) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|MW6PR12MB8959:EE_
X-MS-Office365-Filtering-Correlation-Id: 7b2a3317-d2a2-4f8c-dee0-08ddf546788e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?zjck5V4WY3RJubrpNbHRlsPRMCbIgHlXg7QPqcuA1dy08IGgUVDVbwPVepOx?=
 =?us-ascii?Q?lK63fTqm1rCt6XrLZiDGRUiMT8jCALMb+yH6zCNz1D0HUKc+2QeI18mxIas2?=
 =?us-ascii?Q?SdKZjGLM6DvSron1JNI4g4Gohd0exxAnFahaJ3YqhbfKwTfmUr3g5PqptwdX?=
 =?us-ascii?Q?O8PU6sa78cqNDDK2qhghdjO+hQpdheOxHY0PN3eOFBqPRlxL/6G+/diGwfe+?=
 =?us-ascii?Q?QTfI2bCypRjOzjYRTfcHXs9HSknCvFjZmYMd6kmxVQkWfN3FVeh2kyfxh81i?=
 =?us-ascii?Q?cRdGr8FtITDDn412d7u7V/hL7vGfgOWdfPTkNhjYP+6zkKFW8Zk4EhJR3sMY?=
 =?us-ascii?Q?Pq23Asm1GUiBn9dtmKygcvZpXZl5Pu83pcdYIHJ61/DXlHm2tDDZM1L/e+zr?=
 =?us-ascii?Q?BAPVBrywFkDo+vNKuDDXaqRMgjvbcxqfYofJPgxU4BqgjNAtnjCyJjRxwyTh?=
 =?us-ascii?Q?pdGqt+j+o5JwyjJhaPYC8MGlbP7s1rowVdh2/bUEwsAs6vscmnJA0TeW09St?=
 =?us-ascii?Q?qr2qviK3v1mGCgy7hqJKgDcLxZyYr9wqPnaOzp+QfouC3QSRnIczdNCUDS9H?=
 =?us-ascii?Q?aM2hT4cUrNAUmY5d193ZrNZBMj3LKhAIjdtPlTFlg1n8UGn/vQMX8TYJSkGM?=
 =?us-ascii?Q?8ix1PCjxGVTuB2PF15Q69+Ft4j2Uqz30m+em7m3+IpG9AlvNHShGZYEwt0D6?=
 =?us-ascii?Q?uyC11boTEqlzj36QdTG8nGG7PIqGjS7Rcg7sl4KcQ+bZfSx8XBS4fOlVamXx?=
 =?us-ascii?Q?UyGMNEw8HaMnAhtzVsKpWN4MO3Z9E7y2RjLEdrTh/3RRgHQyexfXjLhsRDnj?=
 =?us-ascii?Q?3x6K4Y3Rj3Eom9jLPbS6jX4GxdSKFCm9Bh+1EutaNdOUKugPzK9JCwipRKpx?=
 =?us-ascii?Q?qB6G+NyPfUdQO7alaVjw/O2e9HY/6ipwUcc3ez1cCW1qKhmv9Iq/Ej+sTIsr?=
 =?us-ascii?Q?seZS24YIDM7u87lK9k28LPWdILdKnNBTVL2ayMpxX3SzlIEzBjtbODjC2lSO?=
 =?us-ascii?Q?o5lEo+4nrocy0sYzsn4NMAkUI065t1FyDvwFsylHAckcwqUYoj82c+ZiFuKh?=
 =?us-ascii?Q?8GVhGpdLngnKDl0yOR8gsTL/4/c13P+vwC6/HKTiQMPamDQtQSD5G1TT4A55?=
 =?us-ascii?Q?wLoTAEakQhcR/BaeezesUbRPKgnH4gHv6Q71xsc9fcQzxSKfqsvKIKobFAkz?=
 =?us-ascii?Q?Q3rsvTFoftedE0SEPIKl4Aeb7yQmSCmHuHB8W+zHgEwURK/mYQ1I//tt1ptg?=
 =?us-ascii?Q?EIuhkmznTPGi8ZfsX2HF0CtEyugm+fdyzFu7dCJXrX3sba8tJFel+6OQb94F?=
 =?us-ascii?Q?88E9YQZAZZLQNp8DHrrvQMNxdfe7EDKSVzWNCMRjOsCqdjkEmBQbJsp+1cqZ?=
 =?us-ascii?Q?FsPB5BwFmiegElhceVSpPEPBux1fo3LC2jz9yvKAfrE9Mf1OTkYVkG2DUmEy?=
 =?us-ascii?Q?qc7tXGA4RdQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?xTYPaytGpllb059ZZbp34qqdljkME9ObUwve3yfIdMS29ra2Jp+m4X2kZkPB?=
 =?us-ascii?Q?W+TysMLqwGgul5S/YMAZJV3XrzSQdYrSJW4+vAN7hhdYLbuxJbRfXZ+fcZZ2?=
 =?us-ascii?Q?zPVqPYRtNUImB7rJ15rvQTOxnOQsbcce5vUl7brO2lp2bAaoUs4nXsA0oEGg?=
 =?us-ascii?Q?ax4efsUytzWh/QhbFkmiCZK5hPXsSYkWPUOlbwDYq7aq4OxoMzw3TOKWA7ua?=
 =?us-ascii?Q?1i77uPfCgT95a+s598LesGOoWico95x8uyHin9skyANVWsuac8veHZCaTm3j?=
 =?us-ascii?Q?/SoeLGCQJkwC/HNOX371I6xEZoNN47OhNFDW+1/E+U4S7rsQklDB3d3vJ3gY?=
 =?us-ascii?Q?eTHu7bV8qeV5RfxRpVwPc/MkD9IgpMLmatIHSerGJq7U4dDln8JT0HpfOxJV?=
 =?us-ascii?Q?Uo1+VpqB9NxVwg4aHA8lHkXizO01n2+a5mLcMLgShweZZeNSk7BLgD1DU5Fa?=
 =?us-ascii?Q?FaZX2XW9vZgUavJ+mY5e1oDy8qmaujO7/ochcMa6+eIPPmeibg/lWWyPe9kO?=
 =?us-ascii?Q?80STfhFuyRXWhHCb2bYyFsUx7muFTJC7UdrC9I8bZeuH8Wz/+aDfxKjB3glR?=
 =?us-ascii?Q?NjLBDk3vsXZv24Y04916diaRGASj8BG+pcg1waBkMAtIZnsPOcKew2h89S5V?=
 =?us-ascii?Q?/MlXBbRfVrcl0c0rk6Moq0vZXQw1iUYa6sArlAxlwJ1mG3V5NSTRU+8PgvdL?=
 =?us-ascii?Q?aWSlI/AcamC9+f5paN8zNT8RlrVP0pTSf4g3ygHLulCtZgLZrP3KI0y0/oZw?=
 =?us-ascii?Q?ywwT1ltji+PrKGuj26f5gnvxT9K6CmakQGg7i53ag6gujVojHYkndw1jR0+T?=
 =?us-ascii?Q?x/NeefFPm+exEHsiR1PQzUUMIWjFvVWQumvjR3qc4yitrY3Sm+a7WBCUMREx?=
 =?us-ascii?Q?bPIO9cOrOktiX0bCwxSV1kHwbbre5eoq/7gBeRD2d2O3GMbpJ6iAWXRoXRGd?=
 =?us-ascii?Q?rtIKJuPYBQ1bPsusx0FXmx11UkQ2nUecH6VEjs6ivlFPsropDudzj2JZEAAM?=
 =?us-ascii?Q?2oTWNN6x17CLSryw84Up0xKrjg2f873RCCx7DhfxqmxCYOfDKJnGuvJynFLo?=
 =?us-ascii?Q?1Bgm0ahA9RFmwEOPItqP0sr/lSMrmctZikdQO4whwM8U3P4RBfxPUdzLzDUZ?=
 =?us-ascii?Q?5eyIbYRkqMgPedRhjSiWcUPPl7BXf6YrcNTHgU9yRH0d2s71Ym3It0kQlmvh?=
 =?us-ascii?Q?InEroVgYKmDNgwWmn5t3DjBWL+UPxvmyjowywIs90KWRxfOoBrkegrXB7I8j?=
 =?us-ascii?Q?+znuhhXXZ61bsQ8WCusHUoWn6v9reUefUhLmve43/VKSdzmspKE5MVQvT/Y7?=
 =?us-ascii?Q?bSaBOD/m1rQzg4uN2C62SL9H+HNnhwQjFJMDIpaOxrOK30UHccGEUp0+wO0+?=
 =?us-ascii?Q?Vu0P5LOrkCqEcfLprtR9sfOeQurybSJt+ZKsPK/hU+se28p0Ro2ggCrc1QYI?=
 =?us-ascii?Q?VvSQ88Tp5nPlSfSBGwjADZHgIk/yOqCPVJFiyq/xM7GKdr2BzZZEh7np3S9F?=
 =?us-ascii?Q?X5Fc1GvueZJJfJPAgRZmVFBKO7QliFbRiS2qDHISjRdXKf8CzrwIsI2O6xUW?=
 =?us-ascii?Q?lymJBqY+AYqKYzN4/uokwdLEMvax2ecCq2kQfTSR?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 7b2a3317-d2a2-4f8c-dee0-08ddf546788e
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 17:28:37.8484
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: m8sEjFK1EHT99bZeGu1DBEti1ai8vtQ0lxyhp4ZVqzdOiEQA96VGJQMp1HRzZd+q
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW6PR12MB8959
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="rc/mtPgq";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c105::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Sep 16, 2025 at 03:11:54PM +0100, Lorenzo Stoakes wrote:

> +/* What action should be taken after an .mmap_prepare call is complete? */
> +enum mmap_action_type {
> +	MMAP_NOTHING,		/* Mapping is complete, no further action. */
> +	MMAP_REMAP_PFN,		/* Remap PFN range. */

Seems like it would be a bit tider to include MMAP_IO_REMAP_PFN here
instead of having the is_io_remap bool.

> @@ -1155,15 +1155,18 @@ int __compat_vma_mmap_prepare(const struct file_operations *f_op,
>  		.vm_file = vma->vm_file,
>  		.vm_flags = vma->vm_flags,
>  		.page_prot = vma->vm_page_prot,
> +
> +		.action.type = MMAP_NOTHING, /* Default */
>  	};
>  	int err;
>  
>  	err = f_op->mmap_prepare(&desc);
>  	if (err)
>  		return err;
> -	set_vma_from_desc(vma, &desc);
>  
> -	return 0;
> +	mmap_action_prepare(&desc.action, &desc);
> +	set_vma_from_desc(vma, &desc);
> +	return mmap_action_complete(&desc.action, vma);
>  }
>  EXPORT_SYMBOL(__compat_vma_mmap_prepare);

A function called prepare that now calls complete has become a bit oddly named??

> +int mmap_action_complete(struct mmap_action *action,
> +			 struct vm_area_struct *vma)
> +{
> +	int err = 0;
> +
> +	switch (action->type) {
> +	case MMAP_NOTHING:
> +		break;
> +	case MMAP_REMAP_PFN:
> +		VM_WARN_ON_ONCE((vma->vm_flags & VM_REMAP_FLAGS) !=
> +				VM_REMAP_FLAGS);

This is checked in remap_pfn_range_complete() IIRC? Probably not
needed here as well then.

> +		if (action->remap.is_io_remap)
> +			err = io_remap_pfn_range_complete(vma, action->remap.start,
> +				action->remap.start_pfn, action->remap.size,
> +				action->remap.pgprot);
> +		else
> +			err = remap_pfn_range_complete(vma, action->remap.start,
> +				action->remap.start_pfn, action->remap.size,
> +				action->remap.pgprot);
> +		break;
> +	}
> +
> +	/*
> +	 * If an error occurs, unmap the VMA altogether and return an error. We
> +	 * only clear the newly allocated VMA, since this function is only
> +	 * invoked if we do NOT merge, so we only clean up the VMA we created.
> +	 */
> +	if (err) {
> +		const size_t len = vma_pages(vma) << PAGE_SHIFT;
> +
> +		do_munmap(current->mm, vma->vm_start, len, NULL);
> +
> +		if (action->error_hook) {
> +			/* We may want to filter the error. */
> +			err = action->error_hook(err);
> +
> +			/* The caller should not clear the error. */
> +			VM_WARN_ON_ONCE(!err);
> +		}
> +		return err;
> +	}
> +
> +	if (action->success_hook)
> +		err = action->success_hook(vma);
> +
> +	return err;

I would write this as

	if (action->success_hook)
		return action->success_hook(vma);

	return 0;

Just for emphasis this is the success path.

> +int mmap_action_complete(struct mmap_action *action,
> +			struct vm_area_struct *vma)
> +{
> +	int err = 0;
> +
> +	switch (action->type) {
> +	case MMAP_NOTHING:
> +		break;
> +	case MMAP_REMAP_PFN:
> +		WARN_ON_ONCE(1); /* nommu cannot handle this. */
> +
> +		break;
> +	}
> +
> +	/*
> +	 * If an error occurs, unmap the VMA altogether and return an error. We
> +	 * only clear the newly allocated VMA, since this function is only
> +	 * invoked if we do NOT merge, so we only clean up the VMA we created.
> +	 */
> +	if (err) {
> +		const size_t len = vma_pages(vma) << PAGE_SHIFT;
> +
> +		do_munmap(current->mm, vma->vm_start, len, NULL);
> +
> +		if (action->error_hook) {
> +			/* We may want to filter the error. */
> +			err = action->error_hook(err);
> +
> +			/* The caller should not clear the error. */
> +			VM_WARN_ON_ONCE(!err);
> +		}
> +		return err;
> +	}

err is never !0 here, so this should go to a later patch/series.

Also seems like this cleanup wants to be in a function that is not
protected by #ifdef nommu since the code is identical on both branches.

> +	if (action->success_hook)
> +		err = action->success_hook(vma);
> +
> +	return 0;

return err, though prefer to match above, and probably this sequence
should be pulled into the same shared function as above too.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916172836.GQ1086830%40nvidia.com.
