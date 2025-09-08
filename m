Return-Path: <kasan-dev+bncBCN77QHK3UIBBANM7PCQMGQEZW3NMFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id A4466B48EDD
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:11:31 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-7131866cdcesf133969136d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:11:31 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757337090; cv=pass;
        d=google.com; s=arc-20240605;
        b=WWvBzXkZgaEfyx1qfvGoZpVTyklkC0dpYFEpuz4W2AS6WvuWJJM/T6goPOiNGLSvic
         aSQzsA37NGfuGrp3LM7wn8/bYGESVhJZdOJDbSVMg0Knq+jZveQXBSK6T4mwG5aAdxSz
         ArFThevfvOSLOjuE/Hqi+eMrI9IlG7FDx0sisguKd9tlNL9lOEyRnfZVYmTQpkw84ufe
         asP9ffJK8npW1Bls+WmxFbvpdSNksbSRdCBKplfcczU/ftJ2xcdlzuaJfWf+A94e+Pd2
         fAjUc3HF94niwgfeI2MuewMgqucwWRIyHRPGKt4WYIq0XOUDt/rgJrgaIR7NuIMjoiDr
         CPlQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=wptRCL9My4QOiO9r0nEy7HAD6TXbA92e0xe7YJbBAV4=;
        fh=R0qYbxqQ5EauIfV0pX8K8HWsfrXrYvhTsUhSjBWDF7s=;
        b=GkNohGhSB+DaiPUxDXSYr3Ypv3aKv7nWuoG17oXNwvPAeuirSs2MMaPKZvHVvgvPyp
         YJn9Coi+bgT+RHPP866Xeo8bNRpOXSylHgqOfTwM86FKuMn/WUqYQw2vYav/oLkQ9F0Y
         9dQIhLPH18mGWfCbf5aSAPR17RkhSJEp3m3SV2aZrgCGTbTLgevtRa90PYtk8bA8ed2D
         QUXB1YCjw38tEuU+eSeyDfQQav5A6sLGqYU2KqYR5B4/uTUajZUkJcxahNzNUH6KqXn3
         lnm1M0Ad0gXDjVGYoqDfzmXoPH6ixKRKJ68To0n0mh9ecrZmW4cHlC2pDm7ewlXRPw6o
         9FtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=e0e3e9+Y;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::609 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757337090; x=1757941890; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=wptRCL9My4QOiO9r0nEy7HAD6TXbA92e0xe7YJbBAV4=;
        b=JyvhoiqSBjQcG2jsjER0vpwJNeeNaGZbd3hq4XMDA27BrBiBOhMggJNDDftS3HOf5e
         pulYQwrYdmnHURWdtQEZw2RkbgxSud8u9ixyspflLQ1asrK55mAhBXm9U4uPTkKxrdwa
         qNCsJYMfJzUtta6wDS8NUOLz9PNxscUsy835cf625gi4mEAUQWm5YFeg631A8oqAL5KU
         r3spkBIbBseeqj56SE76ObJOmHyhUwVkc1hxux5T/hK+8v/SMRBc9JBlrIEBXHyKSxvX
         cdr4rq0Cer92hFKAIjR9Zgme9ibxy8+1qLrzpTtjDFhGrlRAQP1JNyBxvfAb6VKYWSgR
         ttcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757337090; x=1757941890;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wptRCL9My4QOiO9r0nEy7HAD6TXbA92e0xe7YJbBAV4=;
        b=mjGgfo041u8Be+UKS/uZGNDkTJaWgn4pxGmryKXejoeRr8lgU0uVTri8UepABq2fSY
         8v6BbHQ/x0rt8pSD6y00bbRoaPJMxdnLxDTazInMiI5Bo3qXL/hgEp3oJdmsKwcm1xP2
         k+mmnaPSvvkkjA7hEnhVD1PpbTHvee9mE6DfdwQObN/AsdhNOPymtuAa2v0Lvqjq1475
         8i0Xz5Tg1K2OufbiHi93h6GtV9Lbn6ZcqVZMZFd2qrruHCQIv276kAzmueFSwX+5Vzfq
         RmmcgbbnY9AL8NHXF2DdRS1dmcGws5UwQG2yh9AjNqZYTkSXMQ6gJaNKprSq74UAubZ8
         wJtA==
X-Forwarded-Encrypted: i=3; AJvYcCVfiZgJlSFc8onLb+HqodeoKbq3NeK60e79C4ENEWMqkSn2wviL5qOR3YMXdQcbml/iUh4clg==@lfdr.de
X-Gm-Message-State: AOJu0YwcEUG4QD2tBKu5eYz7T6p7SLgXnYMgWLi0jreWLJZ5ToBhcKCf
	C7ErJlkq/DEo1pKHN9wcgeuQ91u4deG4GctRPe46nVQ4gCjEuce7Nadp
X-Google-Smtp-Source: AGHT+IHzDhnowmdYUKMgU/FM1rYmaqCMaB/MbHK8E+XNnTpQL0KQwrlIGYVYCGG1NM+Rn9bmE8twDA==
X-Received: by 2002:ad4:5be2:0:b0:72b:384c:78fd with SMTP id 6a1803df08f44-7393ec165damr97474186d6.34.1757337090221;
        Mon, 08 Sep 2025 06:11:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4JuDt+YIRlxRSog4mnW28VDeqXpe+20Q7ACGbIli2IJA==
Received: by 2002:a05:6214:20c6:b0:70f:abbb:a05c with SMTP id
 6a1803df08f44-72d3ac24c47ls55097536d6.1.-pod-prod-04-us; Mon, 08 Sep 2025
 06:11:29 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWKI/Y4im47SPTfpgiaUKCNSh7+I/j0cXlX7XgasOwvX7iVr6ciWdyCtKhs0CGMFOCK8JszfA6mLAM=@googlegroups.com
X-Received: by 2002:a67:e710:0:b0:51e:8f20:159b with SMTP id ada2fe7eead31-53d2434a92dmr2660324137.29.1757337088993;
        Mon, 08 Sep 2025 06:11:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757337088; cv=pass;
        d=google.com; s=arc-20240605;
        b=A/qnZ16gILfOHkb8fk4kX8GThsuxN0R2/tWwvABATtLINvLRXN94v8p9zqDf35z8jK
         aVjvCwsiudjlmx7ELdVJjgnJln8+PqOvBmzSZFE0ioczFGShhN8TxbIzSIuxZ0wgGDE0
         iRTSK7Qz/mRm4nLT9hhEXT7LFMlyaAemVU6Vgd9Ox2YW2wKvgdY6dE1sL1WloxMxvGNn
         eRqtNik0bAnNuFfdbv2Rfn0eqCyFuMNqqrcFqK2A2vcmGeqoXvCDETnYIUxdeLp7Tn/a
         MXOSmoTMfBG2iqhbjR9HU3wQUgKUzKHJ0SEgR/33C+TMbaacbcS0y3bHg+EedZJT/BRv
         rlnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Bz15BRQJDJr031E71fvpDtrGADfbwz04cIMxbKpzdQA=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=Lp58nyYF5fBwFZ9iUzMLR/KVBjOOVgC5aRcaimGHAHqmvUlOxyjen1bW61+lSKO5DX
         hWBxAZB7/S6klAhcFHtBhJTEsQxZQXI38RdkZ4yHvfOa9NF6/6PdOtMG2HD2of6mIQpx
         EMa50XnoYfwsCF9t/QaLXaogS4WijlvfkKNfNPbmY0YSSof9NfjFfRQvrnsRPXHW89Le
         D6oGsoJ5B16+NcrfVC+j/wBVTupr+jzz04U9MqcdNkb05h1kixpbSd2F7RRftBlgWSPi
         4RDb+gOZGyJoM4ShlnNTtBv3UY9o0zXznuLL5p/LiEl7WwpYHphgtRv/uhiCDn/yFyuf
         E5yQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=e0e3e9+Y;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::609 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on20609.outbound.protection.outlook.com. [2a01:111:f403:2009::609])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-52aef99551bsi296459137.2.2025.09.08.06.11.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:11:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2009::609 as permitted sender) client-ip=2a01:111:f403:2009::609;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wg+tvgGzPKaChDClFNQhQXYA7zY9ie7Ye2wM0NtvzOcNncDF8A7dvHYCZcGplKsMVbaiLnxffLVQVdhNjpXnGBZP5WnM7oRdi3aJfCNkhjKOrVw3heGaJbSgsTMDAf4v+CPDldGbuQFjPbs7Or9jqHey4SbifLW2jArW0kk2fWXulAeWp+aU2IOisM449HH33FFiBKiTSoqbdlRt06Wyz8CO2nHandmWOyZN2HPI++O7cpq/Y2lu6BO2CIw74YQgDG75uF3ui42lJu++2mUgEegGhEzI8Ehb1awCs5CN8jilR70awFmaL7+QwBhVlWo+XMRHR2stZbhvlC0O956l7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Bz15BRQJDJr031E71fvpDtrGADfbwz04cIMxbKpzdQA=;
 b=Cukrp6Lm5vJ/1bXU0Fylh4CgHSizjfHTlmeQcsKwmqZfwYOatcPv24ja4qKPlfKNEm33ReAjIhE7bTzuDrGTsuEdko29OfI/5NT4VQLlnoH9vZGhEgb+DMEeC76Wkp+lnyJQRuv0Fy+TMrloX1SGosaDAW8nZz9UGDxxBrw/W529Rxk+zKA2BuoLzbYru6szE+VpEfdiEy5Oqs8168yUw+hKGVWG38aLVhtBDVDuaU54DWMVbFSX3K0FrlqrwipYApMHGbTDPKAxzBlaqTRXRQOo3chm6+slaFAAYffWtA13jSmlbT9pKSSKqaEVfkmmk71d/qiT4D0LbkE5wihRTA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by IA1PR12MB8335.namprd12.prod.outlook.com (2603:10b6:208:3fa::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.19; Mon, 8 Sep
 2025 13:11:23 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9094.017; Mon, 8 Sep 2025
 13:11:23 +0000
Date: Mon, 8 Sep 2025 10:11:21 -0300
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
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 10/16] mm/hugetlb: update hugetlbfs to use mmap_prepare,
 mmap_complete
Message-ID: <20250908131121.GA616306@nvidia.com>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
 <346e2d1e768a2e5bf344c772cfbb0cd1d6f2fd15.1757329751.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <346e2d1e768a2e5bf344c772cfbb0cd1d6f2fd15.1757329751.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4PR01CA0209.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:ad::6) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|IA1PR12MB8335:EE_
X-MS-Office365-Filtering-Correlation-Id: 386a6328-7435-44da-9244-08ddeed93593
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?q8HBHKuQn1jDqfku0SHQMpqHFzJLzy9/1XphfSkkXwawrt3tflPKpRzoa9Bg?=
 =?us-ascii?Q?lJkwenNqZRJRB544dpvAAHV/f/le4z7YyBySchpJwaslvNCfmKGldeqZNbdh?=
 =?us-ascii?Q?SmIp0NTBjwzOdOSI9eFqRiKMjf3gbqJqkMTP4EZA4q61V6Lf1NYSvTiY9Trt?=
 =?us-ascii?Q?s3eldiUElHxCxvOlDVV71VTusd7WZvfPovSzZsGms/psSVD8J6VxpOA6q32q?=
 =?us-ascii?Q?9o+SlzckeUmbtIxyJ/HNeMbmhYK6+A7vpq9UQG4QDr8Ljv/SOsK0xHvLPNEe?=
 =?us-ascii?Q?kbvyNpnK7cR/zlYPjEVvmdQvVigrUi+fPzaiZ9yJSyfhXzFTSJS8+Ws3rCUm?=
 =?us-ascii?Q?VYEcscr4Z16E2Ckue5s0Ap+W1bbpG8EXQps5/aLnkTRTR7lh1Wke2NkZEwzt?=
 =?us-ascii?Q?xcElJ7fXLVn9BqMJVKzagFfxx/X4h0s44sfvHVW+zMw6HBmVoBIgSg+X91Vi?=
 =?us-ascii?Q?/FAWftaR79JeJ7B0y5g5m6pQntwqD5qtRfs+XrM5SUV7fZNZGMjBOVvSCJJm?=
 =?us-ascii?Q?RNiL1xn9jMy1CaHLJQjuqZWh3jMj6yFhTuTsFCuI5STmyn+KKH7GJx2y+g1y?=
 =?us-ascii?Q?mS3iJlPADC5t8/ULq2iUW/iA/eOPDjyr63eeVGbgXoVhkwZHKFIiU1BIQluc?=
 =?us-ascii?Q?95eNazxRfN2gBGG+HT5vakCPqgZ9BhQ9VpnDzdTk+3n/AhQh6qPexY9YUoxQ?=
 =?us-ascii?Q?r1sIBsFlV4XIsmjzAFAoyma4FGHOcaK6QUpkSKXNQAvN5GoJpHr0meh0DPJG?=
 =?us-ascii?Q?Wx/SqpUVEWZIm/4FeN+stedGIAFkkSLKVSmXm00O5y+SVjGVMk5g5GIDmL83?=
 =?us-ascii?Q?+IdMRRzE5GKi3J1s8igPZ8er5+41JxGrAHTFxeRObBna6ddXYUL7eSDMwiE+?=
 =?us-ascii?Q?CouX5Z6+YVVFb0vBalD2T5KsPol9YDuMMPvxZoggPkJ3/i0YhnaJzt3lfiJv?=
 =?us-ascii?Q?1zVNLIxQVZHKahEHBPyqOdSbPfeh9kvaWH1OaLxRv9wB6+f2928+fvRF2glG?=
 =?us-ascii?Q?Jg4UnLnffG1y8rmpVPXI6RG9BQzIKtHGgiGOPYdxE3Wxvsyg5fOzvLetIHv1?=
 =?us-ascii?Q?m/YxQ0e7HjLoFNVIei91ELcyJEZEtM/qh/1vuwahs4bFcu2n4x7m3o2H6YDZ?=
 =?us-ascii?Q?QNErhdhs+jO2AeqgG5KyMmbOlZN9a9UvGb8Mq2RPKlkzvu7ZaHGlkucdpgpU?=
 =?us-ascii?Q?HwqpLcuBuD+HXa7iwDNYGMUUvkk8mr/ppQxcOMv6fuMI2LkHGO5QRqg2fmlT?=
 =?us-ascii?Q?LLk8g6KD38fmYKAUW1VtBIj1K9imIwgjwVSZL6w79AS2LLoHPi9LCYPFnltN?=
 =?us-ascii?Q?sSdlfJMbbCkoXdz63kG7km9G+i5h8xVHFsUCJ9hDC1RzwKQQ/fhMnhAuH/pP?=
 =?us-ascii?Q?ch68fHLLEV9+j9ruyLVD7Lil/nFGVIRhTTpBYQshMJhMIuc/aM0uYyqM/kDz?=
 =?us-ascii?Q?6mihUzcux1g=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?puNHc3Z8GXMGaWZkoxhpuBbaF7Z7UWLHP/jLt/GRYUus7URhLKkcKn04AWxk?=
 =?us-ascii?Q?seGUJYpIuKkREmgF8akgId2qQQMS5jCVxmHgimKttTXEWgyccbwayIzi2aX6?=
 =?us-ascii?Q?cUIQha6HPQph72MP9j7c0GWapgYjNKovwHlMzuruWFiuYRVCDNAYd7UNibYL?=
 =?us-ascii?Q?A+0fNKhrN84gQKmecNX0p/D1Zw61Z0J1Fe1T6lSW5iVK+TVazhTtWfXNPtEa?=
 =?us-ascii?Q?9aSL3iuuJQnpoDcKb29OdLInJicV8YLGT3c4R/aolGkwa4Gdaj//QCE3TPVm?=
 =?us-ascii?Q?dkbVvu72BpVPZ7t8yzrrSK6Q94w6cfiP9kClkK5MoCJGpdWJ3DSrXrK4SJUx?=
 =?us-ascii?Q?VL8nrAH9MzStu0rX9qXoNTEBD99u70sXahdMk7j60bdLRJ5NyRwlLftinbvB?=
 =?us-ascii?Q?utrCq1nhgqHQfUp+pudwyELoApRretIhGjdgYpeVfG2yvBFKn4qVYgrDq7IC?=
 =?us-ascii?Q?FsrtkIJwtqDn+lQtBLt8tFMpO/kTtq8MYEGoPzxpYFP5GM8RAfTiTd0KQedC?=
 =?us-ascii?Q?/yGe5iNShenSCrYe3tKsKQbw3JNAOdfLeKwTY5RGgOSjVluDtCJrkAwuHGPa?=
 =?us-ascii?Q?80VSaDdd9OoVHD2cr6uCz4DlNiz8mfvVwCrsJZTwT0hL4qRvPeW/4MrrZlEx?=
 =?us-ascii?Q?2tLI/3BE6CrxrCZuIE8jEgSr6jUe93YYDqwsBgkMMi4H0jcxSOUaYYdXWjKR?=
 =?us-ascii?Q?RAWwnDhIBtcI/mWB7SJwOr7mfefmJ3tjCwopkKlDdnk1jKUlQQcrLbVYLGNn?=
 =?us-ascii?Q?AolQyIlkB7tHT700z3BlvWoNk3U1hmhJJMo6CIZvfEhMprff5Fof9/8wBg80?=
 =?us-ascii?Q?1ffQp409zG28mp7gEbzugiSTWZea4hqdB/YNKll4D+TBxhnWvNyY//ctqyKg?=
 =?us-ascii?Q?SfX5D6fHmkP4G21JvjkrdGJbtJff75guzY5vCmQ+xU1GjQ7jdj2X4DqvET6k?=
 =?us-ascii?Q?4lnJRa9nWmgikN9v+AXtT4apDWClOqO9r25krgd/Y7CIrpN/N0XWiuWMUFJ5?=
 =?us-ascii?Q?j7hmN+pw+Yj8yHawkiD/medxjZzxa4pVSssaCJ9kP0BHIpn0bsHflQ8ZxpqK?=
 =?us-ascii?Q?slCAGSx9Q9Y91MKxFaeMX+WxpjMrgKGxSukCLjKU/EJ+xambNnYOzw7fFSGd?=
 =?us-ascii?Q?ywoOG0wxhGUmeQFtxf56F0VYqeAZIxUxkLOt6IFBjX9rmqPaRjdFxHq9SVpH?=
 =?us-ascii?Q?mCtH5uVb0xG2GkRRLO+Cr/7DxevWFZQuhCk2N/VaMpZEO5Lj72M9ZwZe0x02?=
 =?us-ascii?Q?EKaIdd0x5JyTuroybGUbBjllSls+JCAWH+4HKSle4hB/FvXgseIBzaw7sp2/?=
 =?us-ascii?Q?88aYnqVmfdHAh1kbGiuLI3CAziqOFumypgeaF4ikL89c8AcrArZwaXM4Xjc8?=
 =?us-ascii?Q?Aad7smU8946SzTeEVvNCcyO9U7v8p1lvQsiFiTaCBgiv7K4LAviDOcytOmqd?=
 =?us-ascii?Q?NbG8UyI20W0xq0uccOrnJYUe3+lfCiLEVw/2CqDOqwgUbXUqCy9Ppfsw1SJb?=
 =?us-ascii?Q?uNZ4sYHZPlsYdLsxXAkmdbCHzSASMUNqjN7wNpMw1PmwLUlFhJlxF/eiAvEH?=
 =?us-ascii?Q?vVrdHqy/P75ZzvLMVxc=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 386a6328-7435-44da-9244-08ddeed93593
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 08 Sep 2025 13:11:23.3097
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: tICOvs9SHVif2QRV8+lHUpobroN8UIyUJxKgWUsntnopVcEqSChA4jmi1I7jBTlH
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR12MB8335
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=e0e3e9+Y;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2009::609 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 08, 2025 at 12:10:41PM +0100, Lorenzo Stoakes wrote:
> @@ -151,20 +123,55 @@ static int hugetlbfs_file_mmap(struct file *file, struct vm_area_struct *vma)
>  		vm_flags |= VM_NORESERVE;
>  
>  	if (hugetlb_reserve_pages(inode,
> -				vma->vm_pgoff >> huge_page_order(h),
> -				len >> huge_page_shift(h), vma,
> -				vm_flags) < 0)
> +			vma->vm_pgoff >> huge_page_order(h),
> +			len >> huge_page_shift(h), vma,
> +			vm_flags) < 0) {

It was split like this because vma is passed here right?

But hugetlb_reserve_pages() doesn't do much with the vma:

	hugetlb_vma_lock_alloc(vma);
[..]
	vma->vm_private_data = vma_lock;

Manipulates the private which should already exist in prepare:

Check non-share a few times:

	if (!vma || vma->vm_flags & VM_MAYSHARE) {
	if (vma && !(vma->vm_flags & VM_MAYSHARE) && h_cg) {
	if (!vma || vma->vm_flags & VM_MAYSHARE) {

And does this resv_map stuff:

		set_vma_resv_map(vma, resv_map);
		set_vma_resv_flags(vma, HPAGE_RESV_OWNER);
[..]
	set_vma_private_data(vma, (unsigned long)map);

Which is also just manipulating the private data.

So it looks to me like it should be refactored so that
hugetlb_reserve_pages() returns the priv pointer to set in the VMA
instead of accepting vma as an argument. Maybe just pass in the desc
instead?

Then no need to introduce complete. I think it is probably better to
try to avoid using complete except for filling PTEs..

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908131121.GA616306%40nvidia.com.
